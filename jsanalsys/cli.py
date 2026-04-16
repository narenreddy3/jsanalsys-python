"""
JSAnalSys CLI — JavaScript Security Analyzer for Bug Bounty Hunters
Usage:
  jsanalsys scan <url>           # Scan a target URL
  jsanalsys project list         # List all projects
  jsanalsys project create       # Create a new project
  jsanalsys findings <project>   # View findings
  jsanalsys report <project>     # Generate HTML/JSON report
  jsanalsys analyze <file>       # Analyze a local JS file
  jsanalsys sourcemap <url>      # Fetch and reverse a source map
"""
import json
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.syntax import Syntax
from rich.text import Text
from rich import print as rprint
from rich.prompt import Prompt, Confirm

from jsanalsys.db.models import (
    get_session, init_db, Project, Asset, Finding, CustomPattern
)
from jsanalsys.core.fetcher import Fetcher
from jsanalsys.core.crawler import Crawler
from jsanalsys.core.chunk_discovery import ChunkDiscovery
from jsanalsys.core.sourcemap import SourceMapParser
from jsanalsys.core.beautifier import beautify, is_minified
from jsanalsys.analysis.engine import AnalysisEngine, analyze_for_endpoints
from jsanalsys.analysis.patterns import ALL_PATTERNS, SEVERITY_ORDER
from jsanalsys.reporting.reporter import generate_html_report, generate_json_report, build_report_data

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "bold orange1",
    "medium": "bold yellow",
    "low": "bold blue",
    "info": "dim white",
}


def _severity_badge(sev: str) -> Text:
    color = SEVERITY_COLORS.get(sev, "white")
    return Text(f" {sev.upper()} ", style=f"{color} on black")


# ---------------------------------------------------------------------------
# CLI Group
# ---------------------------------------------------------------------------
@click.group()
@click.version_option("1.0.0", prog_name="jsanalsys")
def main():
    """JSAnalSys — JavaScript Security Analyzer for Bug Bounty Hunters\n
    Discover, beautify, and analyze JavaScript to uncover hidden endpoints,
    secrets, DOM sinks, and more.
    """
    pass


# ---------------------------------------------------------------------------
# SCAN command
# ---------------------------------------------------------------------------
@main.command()
@click.argument("url")
@click.option("--project", "-p", default=None, help="Project name (creates if not exists)")
@click.option("--proxy", default=None, help="HTTP proxy (e.g. http://127.0.0.1:8080 for Burp)")
@click.option("--no-verify-ssl", is_flag=True, help="Disable SSL verification")
@click.option("--delay", default=0.0, type=float, help="Delay between requests (seconds)")
@click.option("--chunks/--no-chunks", default=True, help="Run chunk discovery")
@click.option("--sourcemaps/--no-sourcemaps", default=True, help="Download and reverse source maps")
@click.option("--beautify/--no-beautify", "do_beautify", default=True, help="Beautify minified JS")
@click.option("--min-severity", default="info", type=click.Choice(["critical","high","medium","low","info"]), help="Minimum severity to report")
@click.option("--output", "-o", default=None, help="Output directory for reports/sources")
@click.option("--cookies", default=None, help='JSON string of cookies: \'{"session":"abc"}\'')
@click.option("--headers", default=None, help='JSON string of extra headers')
@click.option("--scope", multiple=True, help="Scope regex patterns (can be repeated)")
@click.option("--cross-origin/--no-cross-origin", default=False, help="Follow cross-origin JS")
@click.option("--brute-chunks", default=0, type=int, help="Max chunk IDs to brute-force (0=disabled)")
@click.option("--save-js", is_flag=True, help="Save all JS files to output directory")
def scan(
    url, project, proxy, no_verify_ssl, delay, chunks, sourcemaps, do_beautify,
    min_severity, output, cookies, headers, scope, cross_origin, brute_chunks, save_js
):
    """Scan a target URL for JavaScript assets and analyze them."""
    console.print(Panel.fit(
        f"[bold cyan]JSAnalSys Scanner[/bold cyan]\n"
        f"Target: [bold]{url}[/bold]\n"
        f"Proxy: {proxy or 'none'}  |  SSL Verify: {not no_verify_ssl}  |  Delay: {delay}s",
        title="[bold]Starting Scan[/bold]"
    ))

    # Parse options
    extra_headers = {}
    if headers:
        try:
            extra_headers = json.loads(headers)
        except json.JSONDecodeError:
            console.print("[red]Invalid --headers JSON[/red]")
            sys.exit(1)

    cookie_dict = {}
    if cookies:
        try:
            cookie_dict = json.loads(cookies)
        except json.JSONDecodeError:
            console.print("[red]Invalid --cookies JSON[/red]")
            sys.exit(1)

    # Setup output dir
    output_dir = Path(output) if output else Path.cwd() / "jsanalsys_output"
    output_dir.mkdir(parents=True, exist_ok=True)

    # DB setup
    db_path = str(output_dir / "jsanalsys.db")
    _, SessionLocal = init_db(db_path)
    db = SessionLocal()

    # Project setup
    project_name = project or urlparse(url).netloc
    proj = db.query(Project).filter_by(name=project_name).first()
    if not proj:
        proj = Project(name=project_name, target_url=url)
        proj.scope_list = list(scope)
        db.add(proj)
        db.commit()
        console.print(f"[green]Created project:[/green] {project_name}")
    else:
        console.print(f"[cyan]Using project:[/cyan] {project_name}")

    # Fetcher
    fetcher = Fetcher(
        proxy=proxy,
        verify_ssl=not no_verify_ssl,
        delay=delay,
        custom_headers=extra_headers,
        cookies=cookie_dict,
    )

    # Crawler
    crawler = Crawler(
        fetcher=fetcher,
        scope_patterns=list(scope),
        follow_cross_origin=cross_origin,
    )

    # Analysis engine
    engine = AnalysisEngine(min_severity=min_severity)

    # Source map parser
    sm_parser = SourceMapParser(fetcher=fetcher)

    # Chunk discovery
    chunk_disc = ChunkDiscovery(fetcher=fetcher, max_brute=brute_chunks)

    # -----------------------------------------------------------------------
    # Step 1: Crawl target page
    # -----------------------------------------------------------------------
    console.print("\n[bold]Step 1:[/bold] Crawling target page...")
    crawl_result = crawler.crawl_page(url)

    for err in crawl_result.errors:
        console.print(f"  [red]Error:[/red] {err}")

    frameworks = crawler.detect_framework(crawl_result.html_content, crawl_result.js_urls)
    if frameworks:
        console.print(f"  [cyan]Detected frameworks:[/cyan] {', '.join(frameworks)}")

    console.print(f"  Found [bold]{len(crawl_result.js_urls)}[/bold] JS URLs")
    console.print(f"  Found [bold]{len(crawl_result.inline_scripts)}[/bold] inline scripts")

    # Track all JS URLs to process
    all_js_urls = list(crawl_result.js_urls)
    processed_urls: set[str] = set()

    # Save assets to DB
    for js_url in all_js_urls:
        existing = db.query(Asset).filter_by(project_id=proj.id, url=js_url).first()
        if not existing:
            asset = Asset(project_id=proj.id, url=js_url, asset_type="javascript")
            db.add(asset)
    db.commit()

    # -----------------------------------------------------------------------
    # Step 2: Fetch all JS files
    # -----------------------------------------------------------------------
    console.print(f"\n[bold]Step 2:[/bold] Fetching JS assets...")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching JS...", total=len(all_js_urls))

        for js_url in list(all_js_urls):
            if js_url in processed_urls:
                progress.advance(task)
                continue

            processed_urls.add(js_url)
            progress.update(task, description=f"Fetching {_short_url(js_url)}")

            result = fetcher.fetch(js_url, referer=url)
            if not result.ok:
                progress.advance(task)
                continue

            content = result.content

            # Check for source map
            sm_url = sm_parser.find_sourcemap_url(content, js_url)

            # Beautify if needed
            beautified = None
            if do_beautify and is_minified(content):
                try:
                    beautified = beautify(content)
                except Exception:
                    pass

            # Save JS to disk?
            if save_js:
                js_dir = output_dir / "js"
                js_dir.mkdir(exist_ok=True)
                safe_name = _safe_filename(js_url)
                (js_dir / safe_name).write_text(content, encoding="utf-8", errors="replace")

            # Update DB asset
            asset = db.query(Asset).filter_by(project_id=proj.id, url=js_url).first()
            if not asset:
                asset = Asset(project_id=proj.id, url=js_url, asset_type="javascript")
                db.add(asset)

            asset.content = content[:1_000_000]  # cap at 1MB
            asset.beautified_content = beautified[:1_000_000] if beautified else None
            asset.status_code = result.status_code
            asset.content_length = result.content_length
            asset.content_hash = result.content_hash
            asset.has_sourcemap = bool(sm_url)
            asset.sourcemap_url = sm_url
            db.commit()

            # ---------------------------------------------------------------
            # Step 2b: Chunk discovery
            # ---------------------------------------------------------------
            if chunks:
                try:
                    chunk_result = chunk_disc.discover(url, content, all_js_urls)
                    for chunk in chunk_result.chunks:
                        if chunk.url not in all_js_urls:
                            all_js_urls.append(chunk.url)
                            progress.update(task, total=len(all_js_urls))
                            # Add to DB
                            if not db.query(Asset).filter_by(project_id=proj.id, url=chunk.url).first():
                                new_asset = Asset(
                                    project_id=proj.id,
                                    url=chunk.url,
                                    asset_type="chunk",
                                    is_chunk=True,
                                    chunk_id=chunk.chunk_id,
                                    parent_url=js_url,
                                )
                                db.add(new_asset)
                    db.commit()
                except Exception:
                    pass

            progress.advance(task)

    total_assets = len(all_js_urls)
    console.print(f"  Total assets fetched: [bold]{total_assets}[/bold]")

    # -----------------------------------------------------------------------
    # Step 3: Source map reversal
    # -----------------------------------------------------------------------
    if sourcemaps:
        console.print(f"\n[bold]Step 3:[/bold] Reversing source maps...")
        sm_assets = db.query(Asset).filter_by(project_id=proj.id, has_sourcemap=True).all()

        if sm_assets:
            sm_dir = output_dir / "sourcemaps"
            sm_dir.mkdir(exist_ok=True)
            for asset in sm_assets:
                try:
                    sm_result = sm_parser.parse(asset.url, asset.content or "")
                    if sm_result.ok:
                        sm_subdir = sm_dir / _safe_filename(asset.url)
                        written = sm_parser.save_sources(sm_result, str(sm_subdir))
                        combined = sm_result.get_combined_content()
                        asset.source_mapped_content = combined[:2_000_000]
                        db.commit()
                        console.print(f"  [green]Reversed:[/green] {_short_url(asset.url)} → {len(sm_result.sources)} source files")
                except Exception as e:
                    console.print(f"  [yellow]Skipped[/yellow] {_short_url(asset.url)}: {e}")
        else:
            console.print("  No source maps found")

    # -----------------------------------------------------------------------
    # Step 4: Static analysis
    # -----------------------------------------------------------------------
    console.print(f"\n[bold]Step 4:[/bold] Running static analysis...")

    all_assets_to_analyze = db.query(Asset).filter_by(project_id=proj.id).all()
    total_findings = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing...", total=len(all_assets_to_analyze))

        for asset in all_assets_to_analyze:
            progress.update(task, description=f"Analyzing {_short_url(asset.url)}")

            # Use source-mapped content if available (richer), else beautified, else raw
            content_to_analyze = (
                asset.source_mapped_content
                or asset.beautified_content
                or asset.content
                or ""
            )

            if not content_to_analyze.strip():
                progress.advance(task)
                continue

            analysis = engine.analyze(content_to_analyze, asset_url=asset.url)

            # Also analyze inline scripts from initial crawl
            for finding in analysis.unique_findings:
                # Check for duplicates
                existing = db.query(Finding).filter_by(
                    project_id=proj.id,
                    asset_id=asset.id,
                    finding_type=finding.finding_type,
                    value=finding.value[:500],
                ).first()
                if not existing:
                    db_finding = Finding(
                        project_id=proj.id,
                        asset_id=asset.id,
                        finding_type=finding.finding_type,
                        category=finding.category,
                        value=finding.value[:500],
                        context=finding.context[:1000],
                        line_number=finding.line_number,
                        confidence=finding.confidence,
                        severity=finding.severity,
                        pattern_name=finding.pattern_name,
                    )
                    db.add(db_finding)
                    total_findings += 1

            asset.analyzed = True
            db.commit()
            progress.advance(task)

    # Also analyze inline scripts
    for i, inline in enumerate(crawl_result.inline_scripts):
        if not inline.strip():
            continue
        # Store as inline asset if not already
        inline_url = f"{url}#inline-script-{i}"
        existing_asset = db.query(Asset).filter_by(project_id=proj.id, url=inline_url).first()
        if not existing_asset:
            inline_asset = Asset(
                project_id=proj.id,
                url=inline_url,
                asset_type="inline",
                content=inline[:500_000],
                analyzed=False,
            )
            db.add(inline_asset)
            db.flush()

            analysis = engine.analyze(inline, asset_url=inline_url)
            for finding in analysis.unique_findings:
                db_finding = Finding(
                    project_id=proj.id,
                    asset_id=inline_asset.id,
                    finding_type=finding.finding_type,
                    category=finding.category,
                    value=finding.value[:500],
                    context=finding.context[:1000],
                    line_number=finding.line_number,
                    confidence=finding.confidence,
                    severity=finding.severity,
                    pattern_name=finding.pattern_name,
                )
                db.add(db_finding)
                total_findings += 1
            inline_asset.analyzed = True
            db.commit()

    console.print(f"  Total findings: [bold]{total_findings}[/bold]")

    # -----------------------------------------------------------------------
    # Step 5: Summary
    # -----------------------------------------------------------------------
    _print_findings_summary(db, proj)

    # -----------------------------------------------------------------------
    # Step 6: Generate reports
    # -----------------------------------------------------------------------
    console.print(f"\n[bold]Step 6:[/bold] Generating reports...")
    all_findings = db.query(Finding).filter_by(project_id=proj.id).all()
    all_assets_list = db.query(Asset).filter_by(project_id=proj.id).all()
    report_data = build_report_data(proj, all_assets_list, all_findings)

    html_path = output_dir / f"{project_name}_report.html"
    json_path = output_dir / f"{project_name}_report.json"

    generate_html_report(report_data, str(html_path))
    generate_json_report(report_data, str(json_path))

    console.print(f"\n[green]Reports saved:[/green]")
    console.print(f"  HTML: [cyan]{html_path}[/cyan]")
    console.print(f"  JSON: [cyan]{json_path}[/cyan]")
    console.print(f"  DB:   [cyan]{db_path}[/cyan]")

    fetcher.close()
    db.close()


# ---------------------------------------------------------------------------
# ANALYZE command (local file)
# ---------------------------------------------------------------------------
@main.command()
@click.argument("file_path")
@click.option("--min-severity", default="info", type=click.Choice(["critical","high","medium","low","info"]))
@click.option("--output", "-o", default=None, help="Save JSON findings to file")
@click.option("--beautify/--no-beautify", "do_beautify", default=True)
def analyze(file_path, min_severity, output, do_beautify):
    """Analyze a local JavaScript file."""
    path = Path(file_path)
    if not path.exists():
        console.print(f"[red]File not found:[/red] {file_path}")
        sys.exit(1)

    content = path.read_text(encoding="utf-8", errors="replace")
    console.print(f"[cyan]Analyzing:[/cyan] {file_path} ({len(content):,} bytes)")

    if do_beautify and is_minified(content):
        console.print("[dim]Beautifying minified code...[/dim]")
        try:
            content = beautify(content)
        except Exception:
            pass

    engine = AnalysisEngine(min_severity=min_severity)
    result = engine.analyze(content, asset_url=file_path)
    unique = result.unique_findings

    _print_findings_table(unique)

    if output:
        findings_data = [
            {
                "finding_type": f.finding_type,
                "category": f.category,
                "value": f.value,
                "severity": f.severity,
                "confidence": f.confidence,
                "line_number": f.line_number,
                "context": f.context,
                "pattern_name": f.pattern_name,
            }
            for f in unique
        ]
        Path(output).write_text(json.dumps(findings_data, indent=2))
        console.print(f"[green]Saved to:[/green] {output}")


# ---------------------------------------------------------------------------
# SOURCEMAP command
# ---------------------------------------------------------------------------
@main.command()
@click.argument("url")
@click.option("--output", "-o", default="./sourcemap_output", help="Output directory")
@click.option("--proxy", default=None)
@click.option("--no-verify-ssl", is_flag=True)
def sourcemap(url, output, proxy, no_verify_ssl):
    """Fetch a JS file and attempt to reverse its source map."""
    fetcher = Fetcher(proxy=proxy, verify_ssl=not no_verify_ssl)
    parser = SourceMapParser(fetcher=fetcher)

    console.print(f"[cyan]Fetching:[/cyan] {url}")
    fetch = fetcher.fetch(url)
    if not fetch.ok:
        console.print(f"[red]Failed to fetch URL:[/red] {fetch.error or fetch.status_code}")
        sys.exit(1)

    console.print(f"[cyan]Reversing source map...[/cyan]")
    result = parser.parse(url, fetch.content)

    if not result.ok:
        console.print(f"[red]Source map not found or failed:[/red] {result.error}")
        sys.exit(1)

    console.print(f"[green]Found source map:[/green] {result.map_url}")
    console.print(f"[green]Extracted {len(result.sources)} source files[/green]")

    written = parser.save_sources(result, output)
    for w in written:
        console.print(f"  [dim]Saved:[/dim] {w}")

    console.print(f"\n[green]Done! Sources saved to:[/green] {output}")
    fetcher.close()


# ---------------------------------------------------------------------------
# PROJECT commands
# ---------------------------------------------------------------------------
@main.group()
def project():
    """Manage scanning projects."""
    pass


@project.command("list")
@click.option("--db-path", default=None)
def project_list(db_path):
    """List all projects."""
    db = get_session(db_path)
    projects = db.query(Project).order_by(Project.created_at.desc()).all()

    if not projects:
        console.print("[yellow]No projects found.[/yellow]")
        return

    table = Table(title="Projects", show_header=True)
    table.add_column("ID", style="dim", width=5)
    table.add_column("Name", style="bold cyan")
    table.add_column("Target", style="blue")
    table.add_column("Assets", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Created", style="dim")

    for p in projects:
        asset_count = len(p.assets)
        finding_count = len(p.findings)
        table.add_row(
            str(p.id), p.name, p.target_url,
            str(asset_count), str(finding_count),
            p.created_at.strftime("%Y-%m-%d") if p.created_at else ""
        )

    console.print(table)
    db.close()


@project.command("create")
@click.argument("name")
@click.argument("target_url")
@click.option("--db-path", default=None)
def project_create(name, target_url, db_path):
    """Create a new project."""
    db = get_session(db_path)
    existing = db.query(Project).filter_by(name=name).first()
    if existing:
        console.print(f"[red]Project '{name}' already exists.[/red]")
        db.close()
        return

    proj = Project(name=name, target_url=target_url)
    db.add(proj)
    db.commit()
    console.print(f"[green]Created project:[/green] {name} → {target_url}")
    db.close()


@project.command("delete")
@click.argument("name")
@click.option("--db-path", default=None)
def project_delete(name, db_path):
    """Delete a project and all its data."""
    db = get_session(db_path)
    proj = db.query(Project).filter_by(name=name).first()
    if not proj:
        console.print(f"[red]Project '{name}' not found.[/red]")
        db.close()
        return
    if Confirm.ask(f"Delete project '{name}' and all findings?"):
        db.delete(proj)
        db.commit()
        console.print(f"[green]Deleted.[/green]")
    db.close()


# ---------------------------------------------------------------------------
# FINDINGS command
# ---------------------------------------------------------------------------
@main.command()
@click.argument("project_name")
@click.option("--type", "ftype", default=None, help="Filter by finding_type")
@click.option("--severity", default=None, type=click.Choice(["critical","high","medium","low","info"]))
@click.option("--category", default=None, help="Filter by category")
@click.option("--limit", default=100, type=int)
@click.option("--db-path", default=None)
@click.option("--output", "-o", default=None, help="Save to JSON file")
def findings(project_name, ftype, severity, category, limit, db_path, output):
    """View findings for a project."""
    db = get_session(db_path)
    proj = db.query(Project).filter_by(name=project_name).first()
    if not proj:
        console.print(f"[red]Project '{project_name}' not found.[/red]")
        db.close()
        return

    query = db.query(Finding).filter_by(project_id=proj.id)
    if ftype:
        query = query.filter(Finding.finding_type == ftype)
    if severity:
        query = query.filter(Finding.severity == severity)
    if category:
        query = query.filter(Finding.category == category)

    all_findings_list = query.order_by(Finding.severity).limit(limit).all()
    _print_findings_table_db(all_findings_list)

    if output:
        data = [
            {
                "id": f.id,
                "type": f.finding_type,
                "category": f.category,
                "value": f.value,
                "severity": f.severity,
                "confidence": f.confidence,
                "asset": f.asset.url if f.asset else "",
            }
            for f in all_findings_list
        ]
        Path(output).write_text(json.dumps(data, indent=2))
        console.print(f"[green]Saved to:[/green] {output}")

    db.close()


# ---------------------------------------------------------------------------
# REPORT command
# ---------------------------------------------------------------------------
@main.command()
@click.argument("project_name")
@click.option("--output", "-o", default=".", help="Output directory")
@click.option("--format", "fmt", default="both", type=click.Choice(["html", "json", "both"]))
@click.option("--db-path", default=None)
def report(project_name, output, fmt, db_path):
    """Generate HTML/JSON report for a project."""
    db = get_session(db_path)
    proj = db.query(Project).filter_by(name=project_name).first()
    if not proj:
        console.print(f"[red]Project '{project_name}' not found.[/red]")
        db.close()
        return

    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_assets = db.query(Asset).filter_by(project_id=proj.id).all()
    all_findings = db.query(Finding).filter_by(project_id=proj.id).all()
    data = build_report_data(proj, all_assets, all_findings)

    if fmt in ("html", "both"):
        html_path = out_dir / f"{project_name}_report.html"
        generate_html_report(data, str(html_path))
        console.print(f"[green]HTML report:[/green] {html_path}")

    if fmt in ("json", "both"):
        json_path = out_dir / f"{project_name}_report.json"
        generate_json_report(data, str(json_path))
        console.print(f"[green]JSON report:[/green] {json_path}")

    db.close()


# ---------------------------------------------------------------------------
# PATTERNS command
# ---------------------------------------------------------------------------
@main.command()
@click.option("--category", default=None, help="Filter by category")
@click.option("--type", "ftype", default=None, help="Filter by finding_type")
def patterns(category, ftype):
    """List all built-in analysis patterns."""
    table = Table(title="Built-in Patterns", show_header=True, show_lines=True)
    table.add_column("Name", style="bold")
    table.add_column("Type", style="cyan")
    table.add_column("Category", style="blue")
    table.add_column("Severity")
    table.add_column("Confidence")
    table.add_column("Description")

    filtered = ALL_PATTERNS
    if category:
        filtered = [p for p in filtered if p.category == category]
    if ftype:
        filtered = [p for p in filtered if p.finding_type == ftype]

    for p in filtered:
        color = SEVERITY_COLORS.get(p.severity, "white")
        table.add_row(
            p.name, p.finding_type, p.category,
            Text(p.severity, style=color),
            p.confidence, p.description
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _print_findings_summary(db, proj):
    """Print a summary table of findings by severity."""
    counts = {}
    for sev in ["critical", "high", "medium", "low", "info"]:
        counts[sev] = db.query(Finding).filter_by(
            project_id=proj.id, severity=sev
        ).count()

    table = Table(title="[bold]Findings Summary[/bold]", show_header=False)
    table.add_column("Severity", style="bold", width=12)
    table.add_column("Count", justify="right", width=8)

    for sev, count in counts.items():
        if count > 0:
            color = SEVERITY_COLORS.get(sev, "white")
            table.add_row(Text(sev.upper(), style=color), str(count))

    console.print(table)


def _print_findings_table(findings_list):
    """Print RawFinding objects."""
    if not findings_list:
        console.print("[yellow]No findings.[/yellow]")
        return

    table = Table(show_header=True, show_lines=True)
    table.add_column("Severity", width=10)
    table.add_column("Type", width=18)
    table.add_column("Category", width=20)
    table.add_column("Value", max_width=60)
    table.add_column("Line", width=6)

    sorted_f = sorted(findings_list, key=lambda f: SEVERITY_ORDER.get(f.severity, 4))
    for f in sorted_f:
        color = SEVERITY_COLORS.get(f.severity, "white")
        table.add_row(
            Text(f.severity, style=color),
            f.finding_type, f.category,
            f.value[:60] + ("..." if len(f.value) > 60 else ""),
            str(f.line_number),
        )

    console.print(table)
    console.print(f"\n[bold]Total:[/bold] {len(findings_list)} findings")


def _print_findings_table_db(findings_list):
    """Print DB Finding objects."""
    if not findings_list:
        console.print("[yellow]No findings.[/yellow]")
        return

    table = Table(show_header=True, show_lines=True)
    table.add_column("ID", width=6, style="dim")
    table.add_column("Severity", width=10)
    table.add_column("Type", width=18)
    table.add_column("Category", width=20)
    table.add_column("Value", max_width=50)
    table.add_column("Asset", max_width=40)

    sorted_f = sorted(findings_list, key=lambda f: SEVERITY_ORDER.get(f.severity, 4))
    for f in sorted_f:
        color = SEVERITY_COLORS.get(f.severity, "white")
        asset_url = f.asset.url if f.asset else ""
        table.add_row(
            str(f.id),
            Text(f.severity, style=color),
            f.finding_type, f.category,
            f.value[:50] + ("..." if len(f.value) > 50 else ""),
            _short_url(asset_url),
        )

    console.print(table)
    console.print(f"\n[bold]Total:[/bold] {len(findings_list)} findings")


def _short_url(url: str, max_len: int = 60) -> str:
    """Shorten a URL for display."""
    if len(url) <= max_len:
        return url
    parsed = urlparse(url)
    path = parsed.path
    if len(path) > max_len - 20:
        path = "..." + path[-(max_len - 23):]
    return f"{parsed.netloc}{path}"


def _safe_filename(url: str) -> str:
    """Convert a URL to a safe filesystem name."""
    import re
    name = url.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_")
    name = re.sub(r'[<>:"|*\x00-\x1f]', "_", name)
    return name[:200]


if __name__ == "__main__":
    main()
