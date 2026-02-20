#!/usr/bin/env python3
"""
Supply Chain Dependency Auditor
Scans a codebase for Python and Node dependencies, checks them against
NVD, OSV, and GitHub Advisory vulnerability databases, and generates
an interactive risk report.

Usage:
    python scan.py /path/to/project
    python scan.py /path/to/project --format html --output report.html
    python scan.py /path/to/project --format json --output results.json
"""

import argparse
import logging
import sys
import time
from pathlib import Path

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from auditor.models import Ecosystem, ScanResult, Severity
from auditor.parsers import scan_directory
from auditor.resolver import resolve_all, flatten_tree
from auditor.vulnerability import check_all_packages, _vuln_map_key
from auditor.risk import score_package, compute_overall_risk
from auditor.report import generate_html_report, generate_json_report

VERSION = "1.0.0"


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def print_banner(console) -> None:
    if HAS_RICH:
        banner = Text()
        banner.append("  Supply Chain Dependency Auditor", style="bold cyan")
        banner.append(f"  v{VERSION}\n", style="dim")
        console.print(Panel(banner, border_style="cyan", width=52))
    else:
        print(f"\n  Supply Chain Dependency Auditor v{VERSION}\n")


def severity_style(sev: Severity) -> str:
    return {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "bold yellow",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.NONE: "dim",
    }.get(sev, "dim")


def run_scan(target: str, console) -> ScanResult:
    start = time.time()
    result = ScanResult(target_path=target)

    # --- Phase 1: Parse dependency files ---
    if HAS_RICH:
        console.print("\n[bold]Phase 1:[/] Scanning dependency files...", style="cyan")
    else:
        print("\nPhase 1: Scanning dependency files...")

    python_deps, node_deps = scan_directory(target)

    if python_deps:
        result.ecosystems_found.append(Ecosystem.PYTHON)
    if node_deps:
        result.ecosystems_found.append(Ecosystem.NODE)

    if not python_deps and not node_deps:
        if HAS_RICH:
            console.print("[yellow]No dependency files found in the target directory.[/]")
        else:
            print("No dependency files found in the target directory.")
        return result

    msg = f"  Found {len(python_deps)} Python and {len(node_deps)} Node.js direct dependencies"
    if HAS_RICH:
        console.print(msg)
    else:
        print(msg)

    # --- Phase 2: Resolve dependency trees ---
    if HAS_RICH:
        console.print("\n[bold]Phase 2:[/] Resolving dependency trees...", style="cyan")
    else:
        print("\nPhase 2: Resolving dependency trees...")

    if HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30),
            console=console,
        ) as progress:
            task = progress.add_task("Resolving packages...", total=None)
            dep_trees = resolve_all(python_deps, node_deps)
            progress.update(task, completed=True)
    else:
        dep_trees = resolve_all(python_deps, node_deps)

    result.dependency_tree = dep_trees
    all_deps = flatten_tree(dep_trees)
    result.total_dependencies = len(all_deps)
    result.direct_dependencies = sum(1 for d in all_deps if d.is_direct)
    result.transitive_dependencies = result.total_dependencies - result.direct_dependencies

    msg = f"  Resolved {result.total_dependencies} total packages ({result.direct_dependencies} direct, {result.transitive_dependencies} transitive)"
    if HAS_RICH:
        console.print(msg)
    else:
        print(msg)

    # --- Phase 3: Vulnerability analysis ---
    if HAS_RICH:
        console.print("\n[bold]Phase 3:[/] Checking vulnerability databases (NVD, OSV, GitHub Advisory)...", style="cyan")
    else:
        print("\nPhase 3: Checking vulnerability databases (NVD, OSV, GitHub Advisory)...")

    def _progress_cb(done, total, name):
        if HAS_RICH:
            pass
        else:
            print(f"\r  Checking [{done}/{total}] {name[:40]:<40}", end="", flush=True)

    if HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning packages", total=len(all_deps))

            def _rich_cb(done, total, name):
                progress.update(task, completed=done, description=f"Checking {name[:32]}")

            vuln_map = check_all_packages(all_deps, max_workers=6, progress_callback=_rich_cb)
    else:
        vuln_map = check_all_packages(all_deps, max_workers=6, progress_callback=_progress_cb)
        print()

    # --- Phase 4: Risk scoring ---
    if HAS_RICH:
        console.print("\n[bold]Phase 4:[/] Calculating risk scores...", style="cyan")
    else:
        print("\nPhase 4: Calculating risk scores...")

    for dep in all_deps:
        vulns = vuln_map.get(_vuln_map_key(dep), [])
        audit = score_package(dep, vulns)
        result.audits.append(audit)

    result.audits.sort(key=lambda a: a.risk_score, reverse=True)
    compute_overall_risk(result)
    result.scan_duration = time.time() - start

    return result


def print_summary(result: ScanResult, console) -> None:
    if not HAS_RICH:
        _print_summary_plain(result)
        return

    console.print()
    table = Table(title="Scan Summary", border_style="cyan", show_header=False, pad_edge=True)
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    table.add_row("Total Packages", str(result.total_dependencies))
    table.add_row("Direct", str(result.direct_dependencies))
    table.add_row("Transitive", str(result.transitive_dependencies))
    table.add_row("Vulnerabilities Found", f"[bold red]{result.total_vulnerabilities}[/]" if result.total_vulnerabilities else "0")
    table.add_row("Critical", f"[bold red]{result.critical_count}[/]" if result.critical_count else "0")
    table.add_row("High", f"[bold yellow]{result.high_count}[/]" if result.high_count else "0")
    table.add_row("Medium", f"[yellow]{result.medium_count}[/]" if result.medium_count else "0")
    table.add_row("Low", f"[cyan]{result.low_count}[/]" if result.low_count else "0")
    table.add_row("Outdated Packages", str(result.outdated_count))
    table.add_row("Overall Risk", f"[{severity_style(result.overall_risk_level)}]{result.overall_risk_score:.1f}/10 ({result.overall_risk_level.value})[/]")
    table.add_row("Scan Duration", f"{result.scan_duration:.1f}s")
    console.print(table)

    if result.vulnerable_packages:
        console.print("\n[bold]Top Vulnerable Packages:[/]")
        vuln_table = Table(border_style="dim", show_lines=False)
        vuln_table.add_column("Package", style="cyan")
        vuln_table.add_column("Version")
        vuln_table.add_column("Risk", justify="center")
        vuln_table.add_column("Vulns", justify="center")

        for audit in result.audits[:15]:
            if not audit.vulnerabilities:
                continue
            sty = severity_style(audit.risk_level)
            vuln_table.add_row(
                audit.dependency.name,
                audit.dependency.version or "—",
                f"[{sty}]{audit.risk_score:.1f}[/]",
                f"[{sty}]{len(audit.vulnerabilities)}[/]",
            )
        console.print(vuln_table)


def _print_summary_plain(result: ScanResult) -> None:
    print(f"\n{'='*50}")
    print(f" SCAN SUMMARY")
    print(f"{'='*50}")
    print(f" Total Packages:      {result.total_dependencies}")
    print(f" Vulnerabilities:     {result.total_vulnerabilities}")
    print(f"   Critical:          {result.critical_count}")
    print(f"   High:              {result.high_count}")
    print(f"   Medium:            {result.medium_count}")
    print(f"   Low:               {result.low_count}")
    print(f" Outdated:            {result.outdated_count}")
    print(f" Overall Risk:        {result.overall_risk_score:.1f}/10 ({result.overall_risk_level.value})")
    print(f" Duration:            {result.scan_duration:.1f}s")
    print(f"{'='*50}\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="scan",
        description="Supply Chain Dependency Auditor — analyze your project's dependency risk.",
    )
    parser.add_argument("target", help="Path to the project directory to scan")
    parser.add_argument(
        "-f", "--format",
        choices=["html", "json", "both"],
        default="html",
        help="Output report format (default: html)",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output file path (default: audit_report.html or audit_report.json)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    args = parser.parse_args()
    setup_logging(args.verbose)
    console = Console() if HAS_RICH else None

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"Error: target path does not exist: {target}", file=sys.stderr)
        return 1

    print_banner(console)
    result = run_scan(str(target), console)

    if result.total_dependencies == 0:
        return 0

    print_summary(result, console)

    if args.format in ("html", "both"):
        html_path = args.output or "audit_report.html"
        if args.format == "both" and args.output:
            html_path = str(Path(args.output).with_suffix(".html"))
        out = generate_html_report(result, html_path)
        msg = f"HTML report saved to {out}"
        if HAS_RICH:
            console.print(f"\n[bold green]✓[/] {msg}")
        else:
            print(f"\n[+] {msg}")

    if args.format in ("json", "both"):
        json_path = args.output or "audit_report.json"
        if args.format == "both" and args.output:
            json_path = str(Path(args.output).with_suffix(".json"))
        out = generate_json_report(result, json_path)
        msg = f"JSON report saved to {out}"
        if HAS_RICH:
            console.print(f"[bold green]✓[/] {msg}")
        else:
            print(f"[+] {msg}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
