"""
Report generation — HTML and JSON outputs.
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from jsanalsys.analysis.patterns import SEVERITY_ORDER


# ---------------------------------------------------------------------------
# HTML Report Template
# ---------------------------------------------------------------------------
HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>JSAnalSys Report — {project_name}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
    --critical: #ff4d4d; --high: #ff8c42;
    --medium: #f0c040; --low: #58a6ff; --info: #8b949e;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }}
  header {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 20px 32px; display: flex; align-items: center; gap: 16px; }}
  header h1 {{ font-size: 20px; font-weight: 700; }}
  header .meta {{ color: var(--muted); font-size: 12px; margin-top: 4px; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; text-transform: uppercase; }}
  .badge.critical {{ background: rgba(255,77,77,.2); color: var(--critical); }}
  .badge.high {{ background: rgba(255,140,66,.2); color: var(--high); }}
  .badge.medium {{ background: rgba(240,192,64,.2); color: var(--medium); }}
  .badge.low {{ background: rgba(88,166,255,.2); color: var(--low); }}
  .badge.info {{ background: rgba(139,148,158,.2); color: var(--info); }}
  main {{ max-width: 1400px; margin: 0 auto; padding: 24px 32px; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 16px; margin-bottom: 32px; }}
  .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }}
  .stat-card .num {{ font-size: 32px; font-weight: 700; }}
  .stat-card .label {{ color: var(--muted); font-size: 12px; margin-top: 4px; }}
  .stat-card.critical .num {{ color: var(--critical); }}
  .stat-card.high .num {{ color: var(--high); }}
  .stat-card.medium .num {{ color: var(--medium); }}
  .stat-card.low .num {{ color: var(--low); }}
  .stat-card.info .num {{ color: var(--info); }}
  section.findings-section {{ margin-bottom: 32px; }}
  section.findings-section h2 {{ font-size: 16px; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }}
  .finding {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 12px; overflow: hidden; }}
  .finding-header {{ display: flex; align-items: center; gap: 12px; padding: 12px 16px; cursor: pointer; }}
  .finding-header .title {{ flex: 1; font-weight: 600; }}
  .finding-header .asset {{ color: var(--muted); font-size: 11px; font-family: monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 400px; }}
  .finding-body {{ padding: 12px 16px; border-top: 1px solid var(--border); display: none; }}
  .finding.open .finding-body {{ display: block; }}
  .finding-value {{ font-family: monospace; background: #010409; padding: 10px 12px; border-radius: 6px; word-break: break-all; margin-bottom: 8px; color: #79c0ff; font-size: 13px; }}
  .finding-context {{ font-family: monospace; background: #010409; padding: 10px 12px; border-radius: 6px; font-size: 12px; white-space: pre-wrap; color: var(--muted); }}
  .finding-meta {{ display: flex; gap: 16px; margin-bottom: 8px; font-size: 12px; color: var(--muted); }}
  details summary {{ cursor: pointer; }}
  .filter-bar {{ display: flex; gap: 8px; margin-bottom: 20px; flex-wrap: wrap; }}
  .filter-btn {{ background: var(--surface); border: 1px solid var(--border); color: var(--text); padding: 6px 14px; border-radius: 20px; cursor: pointer; font-size: 12px; }}
  .filter-btn.active {{ border-color: var(--accent); color: var(--accent); }}
  .assets-section {{ margin-bottom: 32px; }}
  .assets-section h2 {{ font-size: 16px; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }}
  .asset-row {{ display: flex; align-items: center; gap: 12px; padding: 10px 0; border-bottom: 1px solid var(--border); font-size: 13px; }}
  .asset-url {{ font-family: monospace; color: var(--accent); overflow: hidden; text-overflow: ellipsis; flex: 1; white-space: nowrap; }}
  .tag {{ display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 10px; background: rgba(88,166,255,.1); color: var(--low); border: 1px solid rgba(88,166,255,.3); }}
  footer {{ text-align: center; color: var(--muted); font-size: 12px; padding: 32px; border-top: 1px solid var(--border); margin-top: 32px; }}
</style>
</head>
<body>
<header>
  <div>
    <h1>JSAnalSys Security Report</h1>
    <div class="meta">Project: <strong>{project_name}</strong> &nbsp;|&nbsp; Target: {target_url} &nbsp;|&nbsp; Generated: {generated_at}</div>
  </div>
</header>
<main>
  <div class="stats-grid">
    <div class="stat-card critical"><div class="num">{count_critical}</div><div class="label">Critical</div></div>
    <div class="stat-card high"><div class="num">{count_high}</div><div class="label">High</div></div>
    <div class="stat-card medium"><div class="num">{count_medium}</div><div class="label">Medium</div></div>
    <div class="stat-card low"><div class="num">{count_low}</div><div class="label">Low</div></div>
    <div class="stat-card info"><div class="num">{count_info}</div><div class="label">Info</div></div>
    <div class="stat-card"><div class="num">{count_assets}</div><div class="label">JS Assets</div></div>
  </div>

  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterFindings('all')">All</button>
    <button class="filter-btn" onclick="filterFindings('secret')">Secrets</button>
    <button class="filter-btn" onclick="filterFindings('endpoint')">Endpoints</button>
    <button class="filter-btn" onclick="filterFindings('dom_sink')">DOM Sinks</button>
    <button class="filter-btn" onclick="filterFindings('postmessage')">postMessage</button>
    <button class="filter-btn" onclick="filterFindings('hostname')">Hostnames</button>
    <button class="filter-btn" onclick="filterFindings('storage')">Storage</button>
    <button class="filter-btn" onclick="filterFindings('prototype_pollution')">Prototype Pollution</button>
    <button class="filter-btn" onclick="filterFindings('crypto_weakness')">Crypto</button>
  </div>

  <section class="findings-section">
    <h2>Findings ({total_findings})</h2>
    {findings_html}
  </section>

  <section class="assets-section">
    <h2>Discovered Assets ({count_assets})</h2>
    {assets_html}
  </section>
</main>
<footer>Generated by JSAnalSys &mdash; JavaScript Security Analyzer for Bug Bounty Hunters</footer>
<script>
function filterFindings(type) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding').forEach(el => {{
    if (type === 'all' || el.dataset.type === type) {{
      el.style.display = '';
    }} else {{
      el.style.display = 'none';
    }}
  }});
}}
document.querySelectorAll('.finding-header').forEach(h => {{
  h.addEventListener('click', () => h.parentElement.classList.toggle('open'));
}});
</script>
</body>
</html>
"""

FINDING_HTML = """\
<div class="finding" data-type="{finding_type}" data-severity="{severity}">
  <div class="finding-header">
    <span class="badge {severity}">{severity}</span>
    <span class="title">{category} &mdash; {pattern_name}</span>
    <span class="asset">{asset_url}</span>
    <span>&#9660;</span>
  </div>
  <div class="finding-body">
    <div class="finding-meta">
      <span>Type: <strong>{finding_type}</strong></span>
      <span>Confidence: <strong>{confidence}</strong></span>
      <span>Line: <strong>{line_number}</strong></span>
    </div>
    <div class="finding-value">{value}</div>
    {context_html}
  </div>
</div>
"""


def _escape_html(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )


def generate_html_report(data: dict, output_path: str):
    """Generate an HTML report from structured data."""
    findings = data.get("findings", [])
    assets = data.get("assets", [])
    project = data.get("project", {})

    # Sort findings by severity
    findings_sorted = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "info"), 4), f.get("category", ""))
    )

    # Count by severity
    counts = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
    for f in findings_sorted:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1

    # Build findings HTML
    findings_html_parts = []
    for f in findings_sorted:
        ctx = f.get("context", "")
        ctx_html = ""
        if ctx:
            ctx_html = f'<div class="finding-context">{_escape_html(ctx)}</div>'
        findings_html_parts.append(FINDING_HTML.format(
            finding_type=_escape_html(f.get("finding_type", "")),
            severity=_escape_html(f.get("severity", "info")),
            category=_escape_html(f.get("category", "")),
            pattern_name=_escape_html(f.get("pattern_name", "")),
            asset_url=_escape_html(f.get("asset_url", "")),
            confidence=_escape_html(f.get("confidence", "")),
            line_number=f.get("line_number", 0),
            value=_escape_html(f.get("value", "")),
            context_html=ctx_html,
        ))

    # Build assets HTML
    asset_parts = []
    for a in assets:
        url = a.get("url", "")
        atype = a.get("asset_type", "javascript")
        tags = []
        if a.get("is_chunk"):
            tags.append('<span class="tag">chunk</span>')
        if a.get("has_sourcemap"):
            tags.append('<span class="tag">sourcemap</span>')
        asset_parts.append(
            f'<div class="asset-row">'
            f'<span class="asset-url">{_escape_html(url)}</span>'
            f'<span class="tag">{_escape_html(atype)}</span>'
            f'{"".join(tags)}'
            f'</div>'
        )

    html = HTML_TEMPLATE.format(
        project_name=_escape_html(project.get("name", "Unknown")),
        target_url=_escape_html(project.get("target_url", "")),
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        count_critical=counts["critical"],
        count_high=counts["high"],
        count_medium=counts["medium"],
        count_low=counts["low"],
        count_info=counts["info"],
        count_assets=len(assets),
        total_findings=len(findings_sorted),
        findings_html="\n".join(findings_html_parts) or "<p style='color:var(--muted)'>No findings.</p>",
        assets_html="\n".join(asset_parts) or "<p style='color:var(--muted)'>No assets discovered.</p>",
    )

    Path(output_path).write_text(html, encoding="utf-8")


def generate_json_report(data: dict, output_path: str):
    """Write full findings data as JSON."""
    Path(output_path).write_text(
        json.dumps(data, indent=2, default=str),
        encoding="utf-8"
    )


def build_report_data(project, assets, findings) -> dict:
    """
    Convert SQLAlchemy model instances to plain dicts for reporting.
    """
    return {
        "project": {
            "id": project.id,
            "name": project.name,
            "target_url": project.target_url,
            "created_at": str(project.created_at),
        },
        "assets": [
            {
                "id": a.id,
                "url": a.url,
                "asset_type": a.asset_type,
                "is_chunk": a.is_chunk,
                "has_sourcemap": a.has_sourcemap,
                "status_code": a.status_code,
                "content_length": a.content_length,
                "discovered_at": str(a.discovered_at),
            }
            for a in assets
        ],
        "findings": [
            {
                "id": f.id,
                "finding_type": f.finding_type,
                "category": f.category,
                "value": f.value,
                "context": f.context,
                "line_number": f.line_number,
                "confidence": f.confidence,
                "severity": f.severity,
                "pattern_name": f.pattern_name,
                "asset_url": f.asset.url if f.asset else "",
                "is_bookmarked": f.is_bookmarked,
                "notes": f.notes,
                "discovered_at": str(f.discovered_at),
            }
            for f in findings
        ],
        "generated_at": datetime.utcnow().isoformat(),
    }
