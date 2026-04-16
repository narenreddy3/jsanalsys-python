"""
Source map reversal module.

When developers accidentally expose .map files, this module:
  1. Detects sourceMappingURL comments in JS files
  2. Downloads the .map file (or data: URI embedded maps)
  3. Parses the VLQ-encoded source map
  4. Reconstructs original source files with their names and content
"""
import base64
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

from jsanalsys.core.fetcher import Fetcher


# Regex to find sourceMappingURL at end of JS file
SOURCE_MAP_COMMENT = re.compile(
    r'//[#@]\s*sourceMappingURL\s*=\s*(.+?)(?:\s*$|\*/)',
    re.MULTILINE | re.IGNORECASE,
)


@dataclass
class SourceFile:
    """A single reconstructed source file from a source map."""
    name: str        # Original filename (e.g. src/components/App.tsx)
    content: str     # Reconstructed source content
    url: Optional[str] = None   # Original source URL if available


@dataclass
class SourceMapResult:
    js_url: str
    map_url: Optional[str] = None
    source_root: str = ""
    sources: list[SourceFile] = field(default_factory=list)
    has_sources_content: bool = False
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and len(self.sources) > 0

    def get_combined_content(self) -> str:
        """Return all source files concatenated with headers."""
        parts = []
        for sf in self.sources:
            header = f"\n{'='*60}\n// Source: {sf.name}\n{'='*60}\n"
            parts.append(header + sf.content)
        return "\n".join(parts)


class SourceMapParser:
    """
    Parses V3 source maps and reconstructs original source files.
    """

    def __init__(self, fetcher: Fetcher):
        self.fetcher = fetcher

    def find_sourcemap_url(self, js_content: str, js_url: str) -> Optional[str]:
        """
        Detect sourceMappingURL in JS content.
        Returns the resolved URL of the source map (or data: URI).
        """
        m = SOURCE_MAP_COMMENT.search(js_content)
        if not m:
            return None

        raw = m.group(1).strip()

        # Inline data URI
        if raw.startswith("data:application/json"):
            return raw

        # Absolute URL
        if raw.startswith(("http://", "https://")):
            return raw

        # Relative URL — resolve against the JS file's URL
        return urljoin(js_url, raw)

    def load_map_content(self, map_url: str) -> Optional[dict]:
        """
        Download and parse a source map JSON.
        Handles both HTTP URLs and inline data: URIs.
        """
        if map_url.startswith("data:application/json"):
            # data:application/json;base64,<b64>
            # or data:application/json,<urlencoded>
            try:
                if ";base64," in map_url:
                    b64 = map_url.split(";base64,", 1)[1]
                    raw = base64.b64decode(b64).decode("utf-8")
                else:
                    raw = map_url.split(",", 1)[1]
                return json.loads(raw)
            except Exception as e:
                return None

        fetch = self.fetcher.fetch(map_url)
        if not fetch.ok:
            return None
        try:
            return json.loads(fetch.content)
        except json.JSONDecodeError:
            return None

    def parse(self, js_url: str, js_content: str) -> SourceMapResult:
        """
        Full pipeline: detect map URL → download → parse → reconstruct sources.
        """
        result = SourceMapResult(js_url=js_url)

        map_url = self.find_sourcemap_url(js_content, js_url)
        if not map_url:
            # Also try probing <js_url>.map and <js_url without .js>.map
            for candidate in self._candidate_map_urls(js_url):
                head = self.fetcher.head(candidate)
                if head.ok:
                    map_url = candidate
                    break

        if not map_url:
            result.error = "No sourceMappingURL found"
            return result

        result.map_url = map_url
        map_data = self.load_map_content(map_url)

        if not map_data:
            result.error = f"Failed to load source map from {map_url}"
            return result

        return self._extract_sources(result, map_data)

    def _extract_sources(self, result: SourceMapResult, map_data: dict) -> SourceMapResult:
        """Extract original source files from parsed source map data."""
        version = map_data.get("version", 3)
        sources = map_data.get("sources", [])
        sources_content = map_data.get("sourcesContent", [])
        source_root = map_data.get("sourceRoot", "")

        result.source_root = source_root
        result.has_sources_content = bool(sources_content)

        for i, src_path in enumerate(sources):
            # Resolve source path
            if source_root:
                if not src_path.startswith(("http://", "https://")):
                    src_path = urljoin(source_root.rstrip("/") + "/", src_path.lstrip("/"))

            # Try to get content from sourcesContent first (most common case)
            content = ""
            if sources_content and i < len(sources_content):
                content = sources_content[i] or ""

            # If no inline content, try to fetch the source
            if not content and src_path.startswith(("http://", "https://")):
                fetch = self.fetcher.fetch(src_path)
                if fetch.ok:
                    content = fetch.content

            # Clean up the source name for display
            name = self._clean_source_name(src_path)

            result.sources.append(SourceFile(
                name=name,
                content=content,
                url=src_path if src_path.startswith("http") else None,
            ))

        return result

    def _clean_source_name(self, path: str) -> str:
        """Normalize source paths for display."""
        # Remove webpack:// protocol
        path = re.sub(r'^webpack:/+', '', path)
        # Remove leading dots/slashes
        path = re.sub(r'^\.?/+', '', path)
        # Collapse ../ references
        parts = []
        for part in path.split("/"):
            if part == "..":
                if parts:
                    parts.pop()
            elif part and part != ".":
                parts.append(part)
        return "/".join(parts) if parts else path

    def _candidate_map_urls(self, js_url: str) -> list[str]:
        """Generate candidate .map URLs to probe."""
        candidates = [f"{js_url}.map"]
        if js_url.endswith(".js"):
            candidates.append(js_url[:-3] + ".map")
        return candidates

    def save_sources(self, result: SourceMapResult, output_dir: str) -> list[str]:
        """
        Save all reconstructed source files to disk.
        Returns list of written file paths.
        """
        base = Path(output_dir)
        written = []

        for sf in result.sources:
            # Build safe path
            safe_name = re.sub(r'[<>:"|?*\x00-\x1f]', '_', sf.name)
            out_path = base / safe_name

            # Ensure parent dirs exist
            out_path.parent.mkdir(parents=True, exist_ok=True)

            # Don't overwrite with empty content
            if not sf.content:
                continue

            out_path.write_text(sf.content, encoding="utf-8")
            written.append(str(out_path))

        return written
