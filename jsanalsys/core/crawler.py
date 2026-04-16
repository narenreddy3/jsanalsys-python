"""
JavaScript asset crawler.
Discovers all JS files referenced from an HTML page:
  - <script src="...">
  - <link rel="preload" as="script">
  - <link rel="modulepreload">
  - Inline <script> blocks
  - Dynamic import() references in discovered JS
  - Next.js _buildManifest.js parsing
"""
import re
from typing import Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from jsanalsys.core.fetcher import Fetcher, FetchResult, normalize_url, same_origin


# Patterns to find JS file references inside JavaScript code
_JS_IMPORT_PATTERNS = [
    # Dynamic imports: import("./chunk.js")
    re.compile(r'import\s*\(\s*["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE),
    # require("./file.js")
    re.compile(r'require\s*\(\s*["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE),
    # src: "/static/chunk.js"  (object property)
    re.compile(r'["\']src["\']\s*:\s*["\']([^"\']+\.js)["\']', re.IGNORECASE),
    # Webpack publicPath + chunkId patterns are handled by chunk_discovery.py
]

# next.js manifest pattern
_NEXT_MANIFEST_PATTERN = re.compile(
    r'__BUILD_MANIFEST\s*=\s*(\{[^;]+\})', re.DOTALL
)


class CrawlResult:
    """Result of crawling a page for JS assets."""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.js_urls: list[str] = []
        self.inline_scripts: list[str] = []
        self.html_content: str = ""
        self.errors: list[str] = []

    def add_js_url(self, url: str):
        if url and url not in self.js_urls:
            self.js_urls.append(url)

    def add_inline(self, content: str):
        content = content.strip()
        if content and content not in self.inline_scripts:
            self.inline_scripts.append(content)


class Crawler:
    """
    Crawls a target URL to discover all JavaScript assets.
    Supports scope filtering to stay within target domain.
    """

    def __init__(
        self,
        fetcher: Fetcher,
        scope_patterns: Optional[list] = None,
        follow_cross_origin: bool = False,
        extract_from_js: bool = True,
    ):
        self.fetcher = fetcher
        self.scope_patterns = [re.compile(p) for p in (scope_patterns or [])]
        self.follow_cross_origin = follow_cross_origin
        self.extract_from_js = extract_from_js

    def in_scope(self, url: str, base_url: str) -> bool:
        """Check if a URL is in scope for this crawl."""
        if self.follow_cross_origin:
            return True
        if same_origin(url, base_url):
            return True
        # Check user-defined scope patterns
        for pattern in self.scope_patterns:
            if pattern.search(url):
                return True
        return False

    def crawl_page(self, url: str) -> CrawlResult:
        """
        Fetch an HTML page and extract all JS references.
        Returns a CrawlResult with JS URLs and inline scripts.
        """
        result = CrawlResult(base_url=url)
        fetch = self.fetcher.fetch(url)

        if not fetch.ok:
            result.errors.append(f"Failed to fetch {url}: {fetch.error or fetch.status_code}")
            return result

        if not fetch.is_html:
            # Might be a direct JS URL — treat content as JS
            if fetch.is_javascript:
                result.add_inline(fetch.content)
            return result

        result.html_content = fetch.content
        soup = BeautifulSoup(fetch.content, "lxml")

        # --- <script src="..."> ---
        for tag in soup.find_all("script", src=True):
            src = tag.get("src", "").strip()
            resolved = normalize_url(fetch.final_url, src)
            if resolved and self.in_scope(resolved, url):
                result.add_js_url(resolved)

        # --- <script> inline blocks ---
        for tag in soup.find_all("script", src=False):
            content = tag.string or tag.get_text()
            if content and content.strip():
                result.add_inline(content.strip())

        # --- <link rel="preload" as="script"> ---
        for tag in soup.find_all("link", rel=True):
            rel = tag.get("rel", [])
            if isinstance(rel, list):
                rel = " ".join(rel).lower()
            as_attr = tag.get("as", "").lower()
            href = tag.get("href", "").strip()
            if ("preload" in rel or "modulepreload" in rel) and (
                as_attr == "script" or href.endswith(".js")
            ):
                resolved = normalize_url(fetch.final_url, href)
                if resolved and self.in_scope(resolved, url):
                    result.add_js_url(resolved)

        # --- Extract JS imports from inline scripts ---
        if self.extract_from_js:
            for inline in result.inline_scripts:
                for pattern in _JS_IMPORT_PATTERNS:
                    for match in pattern.finditer(inline):
                        path = match.group(1)
                        resolved = normalize_url(fetch.final_url, path)
                        if resolved and self.in_scope(resolved, url):
                            result.add_js_url(resolved)

        return result

    def crawl_js_for_imports(self, js_url: str, js_content: str, base_url: str) -> list[str]:
        """
        Scan a JS file's content for additional JS references.
        Returns list of newly discovered JS URLs.
        """
        found = []
        for pattern in _JS_IMPORT_PATTERNS:
            for match in pattern.finditer(js_content):
                path = match.group(1)
                resolved = normalize_url(js_url, path)
                if not resolved:
                    resolved = normalize_url(base_url, path)
                if resolved and self.in_scope(resolved, base_url):
                    if resolved not in found:
                        found.append(resolved)
        return found

    def parse_next_manifest(self, js_content: str, base_url: str) -> list[str]:
        """
        Parse Next.js __BUILD_MANIFEST to discover all page JS chunks.
        """
        found = []
        m = _NEXT_MANIFEST_PATTERN.search(js_content)
        if not m:
            return found
        # Extract all .js strings from the manifest blob
        js_refs = re.findall(r'["\']([^"\']*\.js)["\']', m.group(1))
        for ref in js_refs:
            # Next.js chunks are under /_next/static/
            if not ref.startswith(("http://", "https://", "//")):
                ref = "/_next/static/" + ref.lstrip("/")
            resolved = normalize_url(base_url, ref)
            if resolved and resolved not in found:
                found.append(resolved)
        return found

    def detect_framework(self, html_content: str, js_urls: list[str]) -> list[str]:
        """
        Detect bundler/framework from URL patterns and HTML content.
        Returns list of detected frameworks, e.g. ['webpack', 'nextjs']
        """
        detected = []
        combined = html_content + " ".join(js_urls)

        if "_next/" in combined or "__NEXT_DATA__" in combined:
            detected.append("nextjs")
        if "/_vite/" in combined or "vite" in combined.lower():
            detected.append("vite")
        if "webpack" in combined.lower() or "webpackChunk" in combined:
            detected.append("webpack")
        if "/__remix_manifest" in combined or "remix" in combined.lower():
            detected.append("remix")
        if "nuxt" in combined.lower():
            detected.append("nuxt")

        return detected
