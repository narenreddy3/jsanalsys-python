"""
Webpack / Vite / Next.js chunk discovery engine.

Modern SPAs lazy-load JavaScript bundles (chunks) that are not referenced
directly in HTML. This module reverse-engineers the chunk manifest embedded
in the runtime bundle to enumerate and fetch ALL chunks.

Supports:
  - Webpack 4/5 chunk enumeration
  - Vite chunked builds
  - Next.js page chunks via _buildManifest and _ssgManifest
  - Generic numeric/hash chunk ID brute-forcing
"""
import json
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urljoin

from jsanalsys.core.fetcher import Fetcher, normalize_url


# ---------------------------------------------------------------------------
# Webpack patterns
# ---------------------------------------------------------------------------

# Webpack 5 chunkId→filename map embedded in runtime:
#   ({0: "abc123", 1: "def456", ...}[e] || e) + ".chunk.js"
WP5_CHUNK_MAP = re.compile(
    r'\(\s*\{([^}]+)\}\s*\[(?:e|t|n|r|o|chunkId)\]', re.DOTALL
)

# Webpack 4 style: chunkId -> name in __webpack_require__.m
WP4_CHUNK_ID = re.compile(r'(\d+):\s*\[\s*function')

# Public path: __webpack_require__.p = "/static/js/"
WP_PUBLIC_PATH = re.compile(
    r'__webpack_require__\.p\s*=\s*["\']([^"\']+)["\']'
)

# Webpack 5 runtime chunk URL template
WP5_CHUNK_URL = re.compile(
    r'\+\s*["\.]([a-f0-9]{8,})["\.]?\s*\+\s*["\.](?:chunk\.)?js["\.]'
)

# Chunk id → hash mapping  {123: "aabbccdd"}
WP5_CHUNK_HASH_MAP = re.compile(
    r'\{(\s*(?:\d+|"[^"]+")\s*:\s*"[a-f0-9]+"\s*(?:,\s*(?:\d+|"[^"]+")\s*:\s*"[a-f0-9]+"\s*)*)\}'
)

# ---------------------------------------------------------------------------
# Vite patterns
# ---------------------------------------------------------------------------

VITE_MANIFEST_URL_PATTERN = re.compile(r'["\']([^"\']+/manifest\.json)["\']')

# ---------------------------------------------------------------------------
# Next.js patterns
# ---------------------------------------------------------------------------

NEXT_BUILD_MANIFEST = re.compile(
    r'self\.__BUILD_MANIFEST\s*=\s*(\{[\s\S]+?\})\s*,?\s*self\.__BUILD_MANIFEST_CB'
)
NEXT_SSG_MANIFEST = re.compile(
    r'self\.__SSG_MANIFEST\s*=\s*new Set\(\[([^\]]*)\]\)'
)
NEXT_STATIC_CHUNKS = re.compile(r'/_next/static/chunks/([^\s"\'<>]+\.js)')


@dataclass
class DiscoveredChunk:
    url: str
    chunk_id: Optional[str] = None
    chunk_hash: Optional[str] = None
    framework: Optional[str] = None
    source: str = "discovery"  # how it was found


@dataclass
class ChunkDiscoveryResult:
    base_url: str
    public_path: str = "/"
    framework: str = "unknown"
    chunks: list[DiscoveredChunk] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, url: str, chunk_id=None, chunk_hash=None, framework=None, source="discovery"):
        # Deduplicate
        existing = {c.url for c in self.chunks}
        if url not in existing:
            self.chunks.append(DiscoveredChunk(
                url=url,
                chunk_id=str(chunk_id) if chunk_id is not None else None,
                chunk_hash=chunk_hash,
                framework=framework or self.framework,
                source=source,
            ))


class ChunkDiscovery:
    """
    Discovers hidden JS chunks from a runtime/main bundle.
    """

    def __init__(self, fetcher: Fetcher, max_brute: int = 1000):
        self.fetcher = fetcher
        self.max_brute = max_brute  # max chunk IDs to brute-force

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def discover(
        self,
        base_url: str,
        js_content: str,
        all_js_urls: list[str],
    ) -> ChunkDiscoveryResult:
        """
        Main discovery entry point.
        Analyses the JS content to find chunk manifests, then probes for chunks.
        """
        result = ChunkDiscoveryResult(base_url=base_url)

        # Detect framework
        framework = self._detect_framework(js_content, all_js_urls)
        result.framework = framework

        if framework == "nextjs":
            self._discover_nextjs(base_url, js_content, result)
        elif framework == "vite":
            self._discover_vite(base_url, js_content, all_js_urls, result)
        else:
            # Default: try Webpack discovery
            self._discover_webpack(base_url, js_content, result)

        return result

    # ------------------------------------------------------------------
    # Framework detection
    # ------------------------------------------------------------------

    def _detect_framework(self, js_content: str, js_urls: list[str]) -> str:
        combined = js_content + " ".join(js_urls)
        if "_next/" in combined or "__NEXT_DATA__" in combined or "self.__BUILD_MANIFEST" in combined:
            return "nextjs"
        if "vite" in combined.lower() or "/@vite/" in combined:
            return "vite"
        if "webpack" in combined.lower() or "webpackChunk" in combined or "__webpack_require__" in combined:
            return "webpack"
        return "webpack"  # default assumption for bundled apps

    # ------------------------------------------------------------------
    # Next.js
    # ------------------------------------------------------------------

    def _discover_nextjs(self, base_url: str, js_content: str, result: ChunkDiscoveryResult):
        result.framework = "nextjs"
        origin = self._origin(base_url)

        # Static chunks referenced directly
        for match in NEXT_STATIC_CHUNKS.finditer(js_content):
            chunk_path = "/_next/static/chunks/" + match.group(1)
            url = origin + chunk_path
            result.add(url, framework="nextjs", source="next_static_chunks")

        # Try to fetch _buildManifest.js
        build_id = self._extract_next_build_id(js_content)
        if build_id:
            manifest_url = f"{origin}/_next/static/{build_id}/_buildManifest.js"
            fetch = self.fetcher.fetch(manifest_url)
            if fetch.ok:
                self._parse_next_build_manifest(fetch.content, origin, result)

        # Standard Next.js chunk paths to probe
        standard = [
            "/_next/static/chunks/main.js",
            "/_next/static/chunks/pages/_app.js",
            "/_next/static/chunks/pages/_error.js",
            "/_next/static/chunks/webpack.js",
            "/_next/static/chunks/framework.js",
            "/_next/static/chunks/polyfills.js",
        ]
        for path in standard:
            url = origin + path
            head = self.fetcher.head(url)
            if head.ok:
                result.add(url, framework="nextjs", source="next_standard")

    def _extract_next_build_id(self, js_content: str) -> Optional[str]:
        m = re.search(r'"buildId"\s*:\s*"([^"]+)"', js_content)
        if m:
            return m.group(1)
        m = re.search(r'/_next/static/([^/]+)/_buildManifest\.js', js_content)
        if m:
            return m.group(1)
        return None

    def _parse_next_build_manifest(self, content: str, origin: str, result: ChunkDiscoveryResult):
        # Extract all .js paths from manifest
        js_refs = re.findall(r'"([^"]+\.js)"', content)
        for ref in js_refs:
            if not ref.startswith("http"):
                ref = "/_next/static/" + ref.lstrip("/")
            url = origin + ref if ref.startswith("/") else ref
            result.add(url, framework="nextjs", source="next_build_manifest")

    # ------------------------------------------------------------------
    # Webpack
    # ------------------------------------------------------------------

    def _discover_webpack(self, base_url: str, js_content: str, result: ChunkDiscoveryResult):
        result.framework = "webpack"

        # Get public path
        public_path = self._get_webpack_public_path(js_content, base_url)
        result.public_path = public_path

        # Try to parse chunk ID → filename mappings (Webpack 5)
        chunk_map = self._parse_webpack5_chunk_map(js_content)
        if chunk_map:
            for chunk_id, filename in chunk_map.items():
                url = urljoin(public_path, filename)
                if not url.startswith("http"):
                    url = urljoin(base_url, filename)
                result.add(url, chunk_id=chunk_id, framework="webpack", source="webpack5_map")

        # Webpack 5 hash-based chunks: {chunkId: "hash", ...}
        hash_maps = self._parse_webpack5_hash_maps(js_content)
        for chunk_id, chunk_hash in hash_maps.items():
            # Try common patterns
            candidates = [
                f"{chunk_id}.{chunk_hash}.chunk.js",
                f"{chunk_id}.chunk.js",
                f"chunk.{chunk_id}.js",
                f"{chunk_hash}.chunk.js",
            ]
            for name in candidates:
                url = urljoin(public_path, name)
                head = self.fetcher.head(url)
                if head.ok:
                    result.add(url, chunk_id=chunk_id, chunk_hash=chunk_hash,
                                framework="webpack", source="webpack5_hash")
                    break

        # Fallback: numeric brute force if we found a public path
        if not result.chunks and self.max_brute > 0:
            self._brute_force_webpack(public_path, result)

    def _get_webpack_public_path(self, js_content: str, base_url: str) -> str:
        m = WP_PUBLIC_PATH.search(js_content)
        if m:
            path = m.group(1)
            if path.startswith("http"):
                return path
            return urljoin(base_url, path)

        # Vite-style __vite__base
        m = re.search(r'__vite__base\s*=\s*["\']([^"\']+)["\']', js_content)
        if m:
            return urljoin(base_url, m.group(1))

        # Infer from URL
        parsed = urlparse(base_url)
        return f"{parsed.scheme}://{parsed.netloc}/"

    def _parse_webpack5_chunk_map(self, js_content: str) -> dict:
        """Extract {chunkId: "filename"} map from Webpack 5 runtime."""
        result = {}
        for match in WP5_CHUNK_MAP.finditer(js_content):
            body = match.group(1)
            for pair in re.finditer(r'(\d+|"[^"]+"):\s*"([^"]+)"', body):
                cid = pair.group(1).strip('"')
                fname = pair.group(2)
                if fname.endswith(".js") or "." not in fname:
                    if not fname.endswith(".js"):
                        fname += ".chunk.js"
                    result[cid] = fname
        return result

    def _parse_webpack5_hash_maps(self, js_content: str) -> dict:
        """Extract {chunkId: "hash"} maps for hash-named chunks."""
        result = {}
        for match in WP5_CHUNK_HASH_MAP.finditer(js_content):
            body = match.group(1)
            for pair in re.finditer(r'(\d+):\s*"([a-f0-9]{8,})"', body):
                result[pair.group(1)] = pair.group(2)
        return result

    def _brute_force_webpack(self, public_path: str, result: ChunkDiscoveryResult):
        """
        Last-resort numeric chunk ID probing.
        Tries URLs like /static/js/0.chunk.js, /static/js/1.chunk.js, etc.
        """
        consecutive_misses = 0
        for i in range(self.max_brute):
            candidates = [
                urljoin(public_path, f"{i}.chunk.js"),
                urljoin(public_path, f"{i}.js"),
                urljoin(public_path, f"chunk.{i}.js"),
            ]
            found_one = False
            for url in candidates:
                head = self.fetcher.head(url)
                if head.ok:
                    result.add(url, chunk_id=str(i), framework="webpack",
                                source="brute_force")
                    found_one = True
                    break
            if found_one:
                consecutive_misses = 0
            else:
                consecutive_misses += 1
                # Stop after 10 consecutive misses (unlikely to find more)
                if consecutive_misses >= 10:
                    break

    # ------------------------------------------------------------------
    # Vite
    # ------------------------------------------------------------------

    def _discover_vite(
        self,
        base_url: str,
        js_content: str,
        all_js_urls: list[str],
        result: ChunkDiscoveryResult,
    ):
        result.framework = "vite"
        origin = self._origin(base_url)

        # Try to fetch manifest.json
        manifest_urls = [
            f"{origin}/.vite/manifest.json",
            f"{origin}/manifest.json",
            f"{origin}/assets/manifest.json",
        ]
        for murl in manifest_urls:
            fetch = self.fetcher.fetch(murl)
            if fetch.ok:
                try:
                    manifest = json.loads(fetch.content)
                    self._parse_vite_manifest(manifest, origin, result)
                    break
                except json.JSONDecodeError:
                    pass

        # Also scan JS content for Vite chunk references
        for match in re.finditer(r'["\']([^"\']+/assets/[^"\']+\.js)["\']', js_content):
            url = normalize_url(base_url, match.group(1))
            if url:
                result.add(url, framework="vite", source="vite_asset_ref")

    def _parse_vite_manifest(self, manifest: dict, origin: str, result: ChunkDiscoveryResult):
        for _key, entry in manifest.items():
            if isinstance(entry, dict):
                file = entry.get("file", "")
                if file.endswith(".js"):
                    url = origin + "/" + file.lstrip("/")
                    result.add(url, framework="vite", source="vite_manifest")
                for imp in entry.get("imports", []):
                    if imp.endswith(".js"):
                        url = origin + "/" + imp.lstrip("/")
                        result.add(url, framework="vite", source="vite_manifest_import")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _origin(self, url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"
