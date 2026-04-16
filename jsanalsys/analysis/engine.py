"""
Static analysis engine.

Runs all built-in and custom patterns against JavaScript content,
deduplicates findings, assigns severity, and stores results in the DB.
"""
import re
from dataclasses import dataclass, field
from typing import Optional

from jsanalsys.analysis.patterns import ALL_PATTERNS, Pattern, SEVERITY_ORDER
from jsanalsys.core.beautifier import extract_string_literals


@dataclass
class RawFinding:
    """A finding before DB persistence."""
    finding_type: str
    category: str
    value: str
    context: str
    line_number: int
    confidence: str
    severity: str
    pattern_name: str
    asset_url: str = ""

    def dedup_key(self) -> str:
        return f"{self.finding_type}:{self.category}:{self.value}"


@dataclass
class AnalysisResult:
    asset_url: str
    findings: list[RawFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def add(self, finding: RawFinding):
        self.findings.append(finding)

    @property
    def unique_findings(self) -> list[RawFinding]:
        seen = set()
        out = []
        for f in self.findings:
            k = f.dedup_key()
            if k not in seen:
                seen.add(k)
                out.append(f)
        return out

    def by_severity(self, sev: str) -> list[RawFinding]:
        return [f for f in self.unique_findings if f.severity == sev]

    def summary(self) -> dict:
        uf = self.unique_findings
        return {
            "total": len(uf),
            "critical": len(self.by_severity("critical")),
            "high": len(self.by_severity("high")),
            "medium": len(self.by_severity("medium")),
            "low": len(self.by_severity("low")),
            "info": len(self.by_severity("info")),
        }


class AnalysisEngine:
    """
    Runs regex patterns against JS content and produces findings.
    """

    def __init__(
        self,
        extra_patterns: Optional[list[Pattern]] = None,
        enabled_categories: Optional[list[str]] = None,
        disabled_categories: Optional[list[str]] = None,
        min_severity: str = "info",
        context_lines: int = 2,
        deduplicate: bool = True,
    ):
        self.context_lines = context_lines
        self.deduplicate = deduplicate
        self.min_severity_val = SEVERITY_ORDER.get(min_severity, 4)

        # Build final pattern list
        patterns = list(ALL_PATTERNS)
        if extra_patterns:
            patterns.extend(extra_patterns)

        # Filter by category
        if enabled_categories:
            patterns = [p for p in patterns if p.category in enabled_categories]
        if disabled_categories:
            patterns = [p for p in patterns if p.category not in disabled_categories]

        # Compile regexes
        self._patterns: list[tuple[Pattern, re.Pattern]] = []
        for p in patterns:
            try:
                compiled = re.compile(p.regex, re.MULTILINE)
                self._patterns.append((p, compiled))
            except re.error as e:
                pass  # Skip invalid patterns silently

    def analyze(self, content: str, asset_url: str = "") -> AnalysisResult:
        """
        Run all patterns against JS content.
        Returns an AnalysisResult with all findings.
        """
        result = AnalysisResult(asset_url=asset_url)

        if not content or not content.strip():
            return result

        lines = content.splitlines()
        seen_keys: set[str] = set()

        for pattern, compiled in self._patterns:
            # Skip if below min severity
            if SEVERITY_ORDER.get(pattern.severity, 4) > self.min_severity_val:
                continue

            for match in compiled.finditer(content):
                # Determine matched value (group 1 if exists, else full match)
                try:
                    value = match.group(1).strip()
                except IndexError:
                    value = match.group(0).strip()

                if not value or len(value) < 3:
                    continue

                # Dedup
                dedup_key = f"{pattern.finding_type}:{pattern.category}:{value}"
                if self.deduplicate and dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                # Calculate line number
                line_num = content[:match.start()].count("\n") + 1

                # Extract context
                ctx = self._get_context(lines, line_num - 1, self.context_lines)

                finding = RawFinding(
                    finding_type=pattern.finding_type,
                    category=pattern.category,
                    value=value,
                    context=ctx,
                    line_number=line_num,
                    confidence=pattern.confidence,
                    severity=pattern.severity,
                    pattern_name=pattern.name,
                    asset_url=asset_url,
                )
                result.add(finding)

        result.stats = result.summary()
        return result

    def _get_context(self, lines: list[str], line_idx: int, n: int) -> str:
        """Return n lines before and after line_idx as context snippet."""
        start = max(0, line_idx - n)
        end = min(len(lines), line_idx + n + 1)
        return "\n".join(lines[start:end])

    def analyze_strings_only(self, content: str, asset_url: str = "") -> AnalysisResult:
        """
        Analyse only string literals extracted from JS.
        Faster for large files; misses non-string matches.
        """
        strings = extract_string_literals(content)
        combined = "\n".join(strings)
        return self.analyze(combined, asset_url=asset_url)


def analyze_for_endpoints(content: str) -> list[str]:
    """
    Fast path: extract all URL-like strings from JS content.
    Returns deduplicated list of potential endpoints/paths.
    """
    endpoints = set()

    # Absolute URLs
    for m in re.finditer(r'https?://[^\s"\'<>`,]{5,}', content):
        url = m.group(0).rstrip(".,;)'\"")
        endpoints.add(url)

    # Paths starting with /
    for m in re.finditer(r'["\'](/[a-zA-Z0-9_\-/.:{}\[\]?=&%]+)["\']', content):
        path = m.group(1)
        if len(path) >= 4 and not path.startswith(("//", "/*")):
            endpoints.add(path)

    # fetch/axios/XMLHttpRequest URLs
    for m in re.finditer(
        r'(?:fetch|axios(?:\.\w+)?|XMLHttpRequest|http(?:Client)?\.(?:get|post|put|delete|patch))\s*\(\s*["\`]([^"\'`]{4,})["\`]',
        content
    ):
        endpoints.add(m.group(1))

    return sorted(endpoints)


def analyze_for_hostnames(content: str) -> list[str]:
    """Fast path: extract domain names from JS content."""
    hostnames = set()
    for m in re.finditer(
        r'(?:^|["\'\s(=])([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})(?=["\'\s),;]|$)',
        content, re.MULTILINE
    ):
        hostname = m.group(1).lower()
        # Skip common non-interesting TLDs and generic strings
        if "." in hostname and not hostname.endswith((".js", ".css", ".png", ".jpg", ".gif")):
            hostnames.add(hostname)
    return sorted(hostnames)
