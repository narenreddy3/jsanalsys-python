"""
HTTP fetcher with session management, proxy support, retry logic, and rate limiting.
"""
import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# Default browser-like headers
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}


@dataclass
class FetchResult:
    url: str
    status_code: int
    content: str
    content_type: str
    content_length: int
    content_hash: str
    final_url: str        # After redirects
    headers: dict = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status_code < 400

    @property
    def is_javascript(self) -> bool:
        ct = self.content_type.lower()
        return (
            "javascript" in ct
            or "ecmascript" in ct
            or self.final_url.rstrip("?").endswith(".js")
        )

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type.lower()

    @property
    def is_sourcemap(self) -> bool:
        return (
            "application/json" in self.content_type.lower()
            and self.final_url.endswith(".map")
        ) or self.final_url.endswith(".map")


class Fetcher:
    """
    Thread-safe HTTP fetcher with:
    - Configurable proxy (for Burp/Caido integration)
    - Session-based connection pooling
    - Retry logic with exponential backoff
    - Rate limiting
    - Custom headers & cookies
    """

    def __init__(
        self,
        proxy: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: int = 30,
        delay: float = 0.0,
        max_retries: int = 3,
        custom_headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
    ):
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.delay = delay  # seconds between requests
        self._last_request_time: float = 0.0

        self.session = requests.Session()

        # Retry adapter
        retry = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=50)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Headers
        self.session.headers.update(DEFAULT_HEADERS)
        if custom_headers:
            self.session.headers.update(custom_headers)

        # Cookies
        if cookies:
            self.session.cookies.update(cookies)

        # Proxy config
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
            if not verify_ssl:
                self.session.verify = False

    def _rate_limit(self):
        """Enforce delay between requests."""
        if self.delay > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
        self._last_request_time = time.time()

    def fetch(self, url: str, referer: Optional[str] = None) -> FetchResult:
        """Fetch a single URL, return FetchResult."""
        self._rate_limit()
        headers = {}
        if referer:
            headers["Referer"] = referer

        try:
            resp = self.session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
                verify=self.verify_ssl,
            )
            content = ""
            try:
                content = resp.text
            except Exception:
                content = resp.content.decode("utf-8", errors="replace")

            content_hash = hashlib.sha256(content.encode()).hexdigest()
            content_type = resp.headers.get("Content-Type", "")

            return FetchResult(
                url=url,
                status_code=resp.status_code,
                content=content,
                content_type=content_type,
                content_length=len(content),
                content_hash=content_hash,
                final_url=resp.url,
                headers=dict(resp.headers),
            )
        except requests.exceptions.SSLError as e:
            return FetchResult(
                url=url, status_code=0, content="", content_type="",
                content_length=0, content_hash="", final_url=url,
                error=f"SSL Error: {e}"
            )
        except requests.exceptions.ConnectionError as e:
            return FetchResult(
                url=url, status_code=0, content="", content_type="",
                content_length=0, content_hash="", final_url=url,
                error=f"Connection Error: {e}"
            )
        except requests.exceptions.Timeout:
            return FetchResult(
                url=url, status_code=0, content="", content_type="",
                content_length=0, content_hash="", final_url=url,
                error="Timeout"
            )
        except Exception as e:
            return FetchResult(
                url=url, status_code=0, content="", content_type="",
                content_length=0, content_hash="", final_url=url,
                error=str(e)
            )

    def head(self, url: str) -> FetchResult:
        """HEAD request to check if URL exists without downloading full content."""
        self._rate_limit()
        try:
            resp = self.session.head(
                url, timeout=self.timeout, allow_redirects=True,
                verify=self.verify_ssl
            )
            return FetchResult(
                url=url,
                status_code=resp.status_code,
                content="",
                content_type=resp.headers.get("Content-Type", ""),
                content_length=int(resp.headers.get("Content-Length", 0)),
                content_hash="",
                final_url=resp.url,
                headers=dict(resp.headers),
            )
        except Exception as e:
            return FetchResult(
                url=url, status_code=0, content="", content_type="",
                content_length=0, content_hash="", final_url=url,
                error=str(e)
            )

    def close(self):
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def normalize_url(base_url: str, path: str) -> Optional[str]:
    """Resolve a relative or absolute URL against a base URL."""
    if not path:
        return None
    path = path.strip()
    if path.startswith("//"):
        parsed = urlparse(base_url)
        return f"{parsed.scheme}:{path}"
    if path.startswith(("http://", "https://")):
        return path
    return urljoin(base_url, path)


def extract_origin(url: str) -> str:
    """Return origin (scheme + host) from URL."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def same_origin(url1: str, url2: str) -> bool:
    """Check if two URLs share the same origin."""
    return extract_origin(url1) == extract_origin(url2)
