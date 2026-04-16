"""
mitmproxy integration for live traffic interception.

Usage:
  mitmdump -s jsanalsys/proxy/interceptor.py --set jsanalsys_project=myproject

This script runs as a mitmproxy addon:
  - Intercepts HTTP responses
  - Filters for JS/HTML content types
  - Saves assets to the jsanalsys database in real time
  - Runs analysis on each intercepted JS file
"""
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

# Add parent to path if running via mitmdump
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from mitmproxy import http, ctx
    HAS_MITMPROXY = True
except ImportError:
    HAS_MITMPROXY = False

from jsanalsys.db.models import init_db, Project, Asset, Finding
from jsanalsys.core.beautifier import beautify, is_minified
from jsanalsys.analysis.engine import AnalysisEngine
from jsanalsys.core.sourcemap import SourceMapParser
from jsanalsys.core.fetcher import Fetcher

import hashlib
from datetime import datetime


JS_CONTENT_TYPES = (
    "application/javascript",
    "text/javascript",
    "application/x-javascript",
    "application/ecmascript",
    "text/ecmascript",
)

HTML_CONTENT_TYPES = ("text/html",)


class JSAnalSysAddon:
    """
    mitmproxy addon that intercepts JavaScript and HTML responses,
    storing and analyzing them in the jsanalsys database.
    """

    def __init__(self):
        self.db = None
        self.session = None
        self.project = None
        self.engine = AnalysisEngine()
        self._seen_hashes: set = set()

    def load(self, loader):
        loader.add_option(
            name="jsanalsys_project",
            typespec=str,
            default="",
            help="JSAnalSys project name",
        )
        loader.add_option(
            name="jsanalsys_db",
            typespec=str,
            default="",
            help="Path to jsanalsys.db",
        )
        loader.add_option(
            name="jsanalsys_scope",
            typespec=str,
            default="",
            help="Comma-separated scope patterns",
        )

    def running(self):
        if not HAS_MITMPROXY:
            return

        db_path = ctx.options.jsanalsys_db or None
        project_name = ctx.options.jsanalsys_project or "proxy_capture"

        _, SessionLocal = init_db(db_path)
        self.session = SessionLocal()

        # Get or create project
        self.project = self.session.query(Project).filter_by(name=project_name).first()
        if not self.project:
            self.project = Project(
                name=project_name,
                target_url="(proxy capture)",
            )
            self.session.add(self.project)
            self.session.commit()

        ctx.log.info(f"[JSAnalSys] Running on project: {project_name}")

    def response(self, flow: "http.HTTPFlow"):
        if not HAS_MITMPROXY or not self.project:
            return

        resp = flow.response
        if resp is None:
            return

        content_type = resp.headers.get("Content-Type", "").lower()
        url = flow.request.pretty_url

        is_js = any(ct in content_type for ct in JS_CONTENT_TYPES)
        is_html = any(ct in content_type for ct in HTML_CONTENT_TYPES)

        if not is_js and not is_html:
            # Also capture by URL extension
            path = urlparse(url).path.lower()
            is_js = path.endswith(".js")

        if not is_js and not is_html:
            return

        try:
            content = flow.response.get_text(strict=False)
        except Exception:
            return

        if not content or not content.strip():
            return

        # Dedup by content hash
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        if content_hash in self._seen_hashes:
            return
        self._seen_hashes.add(content_hash)

        # Check if already in DB
        existing = self.session.query(Asset).filter_by(
            project_id=self.project.id, url=url
        ).first()
        if existing and existing.content_hash == content_hash:
            return

        asset_type = "javascript" if is_js else "html"

        # Beautify JS
        beautified = None
        if is_js and is_minified(content):
            try:
                beautified = beautify(content)
            except Exception:
                pass

        if existing:
            existing.content = content[:1_000_000]
            existing.beautified_content = beautified[:1_000_000] if beautified else None
            existing.content_hash = content_hash
            existing.content_length = len(content)
            existing.status_code = resp.status_code
        else:
            existing = Asset(
                project_id=self.project.id,
                url=url,
                asset_type=asset_type,
                content=content[:1_000_000],
                beautified_content=beautified[:1_000_000] if beautified else None,
                content_hash=content_hash,
                content_length=len(content),
                status_code=resp.status_code,
            )
            self.session.add(existing)
        self.session.commit()

        # Run analysis on JS files
        if is_js:
            analysis_content = beautified or content
            result = self.engine.analyze(analysis_content, asset_url=url)

            for finding in result.unique_findings:
                db_finding = Finding(
                    project_id=self.project.id,
                    asset_id=existing.id,
                    finding_type=finding.finding_type,
                    category=finding.category,
                    value=finding.value[:500],
                    context=finding.context[:1000],
                    line_number=finding.line_number,
                    confidence=finding.confidence,
                    severity=finding.severity,
                    pattern_name=finding.pattern_name,
                )
                self.session.add(db_finding)

            existing.analyzed = True
            self.session.commit()

            if result.stats.get("total", 0) > 0:
                ctx.log.info(
                    f"[JSAnalSys] {url} → "
                    f"{result.stats.get('critical',0)}C "
                    f"{result.stats.get('high',0)}H "
                    f"{result.stats.get('medium',0)}M "
                    f"{result.stats.get('info',0)}I findings"
                )

    def done(self):
        if self.session:
            self.session.close()


# mitmproxy addon entry point
if HAS_MITMPROXY:
    addons = [JSAnalSysAddon()]
