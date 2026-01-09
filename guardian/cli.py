#!/usr/bin/env python3
"""
SecureDev Guardian CLI

AI-powered security scanner with automated patching capabilities.
Scans your code for vulnerabilities and provides actionable fix recommendations.

Usage:
    guardian scan --base-ref main
    guardian scan --base-ref main --fail-on high
    guardian report --input report.json --format html
    guardian init
    guardian version

For more information: https://github.com/yourusername/securedev-guardian
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from guardian.config import Config
from guardian.git_utils import get_changed_files
from guardian.report import build_pr_report
from guardian.scanners.bandit_scanner import run_bandit
from guardian.scanners.semgrep_scanner import run_semgrep
from guardian.version import (
    EXIT_CONFIG_ERROR,
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_SUCCESS,
    SEVERITY_COLORS,
    SEVERITY_LEVELS,
    __app_name__,
    __description__,
    __version__,
)

# Initialize Rich console
console = Console()
err_console = Console(stderr=True)

# Create main Typer app
app = typer.Typer(
    name="guardian",
    help=f"{__app_name__} - {__description__}",
    add_completion=True,
    no_args_is_help=True,
    rich_markup_mode="rich",
)


def version_callback(value: bool) -> None:
    """Show version and exit."""
    if value:
        console.print(
            f"[bold blue]{__app_name__}[/bold blue] version [green]{__version__}[/green]"
        )
        raise typer.Exit()


def _filter_files(files: list[str]) -> tuple[list[str], list[str]]:
    """Filter files into Python and JS/TS categories."""
    py = [f for f in files if f.endswith(".py")]
    js_ts = [f for f in files if f.endswith((".js", ".ts", ".tsx", ".jsx"))]
    return py, js_ts


def _count_by_severity(findings: list[dict]) -> dict[str, int]:
    """Count findings by severity level."""
    counts = {level: 0 for level in SEVERITY_LEVELS}
    for finding in findings:
        severity = finding.get("severity", "info").lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def _should_fail(severity_counts: dict[str, int], fail_on: str | None) -> bool:
    """Check if scan should fail based on severity threshold."""
    if not fail_on:
        return False

    fail_on = fail_on.lower()
    if fail_on not in SEVERITY_LEVELS:
        return False

    fail_index = SEVERITY_LEVELS.index(fail_on)
    for i, level in enumerate(SEVERITY_LEVELS):
        if i <= fail_index and severity_counts.get(level, 0) > 0:
            return True
    return False


def _print_summary_table(py_count: int, js_count: int, findings: list[dict]) -> None:
    """Print a summary table of scan results."""
    severity_counts = _count_by_severity(findings)
    total = len(findings)

    # Create summary table
    table = Table(title="Scan Summary", show_header=True, header_style="bold cyan")
    table.add_column("Category", style="dim")
    table.add_column("Count", justify="right")

    table.add_row("Python files scanned", str(py_count))
    table.add_row("JS/TS files scanned", str(js_count))
    table.add_row("", "")
    table.add_row("[bold]Total findings[/bold]", f"[bold]{total}[/bold]")

    for level in SEVERITY_LEVELS:
        count = severity_counts.get(level, 0)
        if count > 0:
            color = SEVERITY_COLORS.get(level, "white")
            table.add_row(f"  {level.capitalize()}", f"[{color}]{count}[/{color}]")

    console.print(table)


def _print_findings(findings: list[dict], max_items: int = 10) -> None:
    """Print findings in a readable format."""
    if not findings:
        return

    console.print("\n[bold]Top Findings:[/bold]")

    for i, finding in enumerate(findings[:max_items], 1):
        severity = finding.get("severity", "info").lower()
        color = SEVERITY_COLORS.get(severity, "white")
        rule = finding.get("rule", {})
        location = finding.get("location", {})

        filepath = location.get("filepath", "unknown")
        line = location.get("start_line", "?")
        rule_id = rule.get("rule_id", "unknown")
        name = rule.get("name", "Unknown issue")

        console.print(
            f"  {i}. [{color}][{severity.upper()}][/{color}] "
            f"[cyan]{filepath}:{line}[/cyan] - {rule_id}: {name}"
        )

    if len(findings) > max_items:
        console.print(f"\n  ... and {len(findings) - max_items} more findings")


@app.command()
def scan(
    base_ref: Annotated[
        str,
        typer.Option(
            "--base-ref",
            "-b",
            help="Base branch to compare against (e.g., main, develop)",
        ),
    ] = "main",
    semgrep_config: Annotated[
        str,
        typer.Option(
            "--semgrep-config",
            "-s",
            help="Semgrep config (e.g., p/ci, p/security-audit)",
        ),
    ] = "p/ci",
    output_dir: Annotated[
        str,
        typer.Option(
            "--output-dir",
            "-o",
            help="Directory for output files",
        ),
    ] = ".",
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: md, json, or both",
        ),
    ] = "both",
    fail_on: Annotated[
        Optional[str],
        typer.Option(
            "--fail-on",
            help="Fail with exit code 1 if findings at this severity or higher",
        ),
    ] = None,
    ml_results: Annotated[
        Optional[str],
        typer.Option(
            "--ml-results",
            help="Path to ML results JSON for hybrid analysis",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show detailed output",
        ),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            "-q",
            help="Suppress all output except errors",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Output results as JSON to stdout",
        ),
    ] = False,
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-V",
            callback=version_callback,
            is_eager=True,
            help="Show version and exit",
        ),
    ] = None,
) -> None:
    """
    Scan your codebase for security vulnerabilities.

    Analyzes changed files compared to the base branch using Bandit (Python)
    and Semgrep (JavaScript/TypeScript) scanners.

    Examples:

        guardian scan --base-ref main

        guardian scan -b develop --fail-on high

        guardian scan --json > results.json
    """
    try:
        # Load config
        cfg = Config().load()

        # Apply defaults from config if not specified
        if base_ref == "main" and cfg.get("base_ref"):
            base_ref = cfg.get("base_ref")

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        artifacts_path = output_path / "artifacts"
        artifacts_path.mkdir(parents=True, exist_ok=True)

        # Get changed files
        if not quiet:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                progress.add_task("Getting changed files...", total=None)
                changed = get_changed_files(base_ref)

        else:
            changed = get_changed_files(base_ref)

        py_files, js_ts_files = _filter_files(changed)

        if not quiet and not json_output:
            console.print(
                Panel(
                    f"[bold]Files to scan:[/bold] {len(changed)} "
                    f"([cyan]Python: {len(py_files)}[/cyan], "
                    f"[yellow]JS/TS: {len(js_ts_files)}[/yellow])",
                    title="SecureDev Guardian",
                    border_style="blue",
                )
            )

        if verbose and not json_output:
            console.print("\n[dim]Changed files:[/dim]")
            for f in changed[:20]:
                console.print(f"  {f}")
            if len(changed) > 20:
                console.print(f"  ... and {len(changed) - 20} more")

        # Run scanners
        if not quiet and not json_output:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("Running Bandit scanner...", total=None)
                bandit_json = run_bandit(py_files)

                progress.update(task, description="Running Semgrep scanner...")
                semgrep_json = run_semgrep(js_ts_files, config=semgrep_config)
        else:
            bandit_json = run_bandit(py_files)
            semgrep_json = run_semgrep(js_ts_files, config=semgrep_config)

        # Build report
        report_md, report_json = build_pr_report(
            base_ref=base_ref,
            py_files=py_files,
            js_ts_files=js_ts_files,
            bandit_json=bandit_json,
            semgrep_json=semgrep_json,
            ml_results=ml_results,
        )

        findings = report_json.get("findings", [])

        # JSON output mode
        if json_output:
            print(json.dumps(report_json, indent=2))
            sys.exit(EXIT_FINDINGS if findings else EXIT_SUCCESS)

        # Write output files
        if format in ("md", "both"):
            md_path = output_path / "report.md"
            md_path.write_text(report_md, encoding="utf-8")
            if not quiet:
                console.print(f"[green]✓[/green] Wrote {md_path}")

        if format in ("json", "both"):
            json_path = output_path / "report.json"
            json_path.write_text(
                json.dumps({"bandit": bandit_json, "semgrep": semgrep_json}, indent=2),
                encoding="utf-8",
            )
            if not quiet:
                console.print(f"[green]✓[/green] Wrote {json_path}")

            pr_json_path = artifacts_path / "pr_report.json"
            pr_json_path.write_text(json.dumps(report_json, indent=2), encoding="utf-8")
            if not quiet:
                console.print(f"[green]✓[/green] Wrote {pr_json_path}")

        # Print summary
        if not quiet:
            console.print()
            _print_summary_table(len(py_files), len(js_ts_files), findings)

            if findings and verbose:
                _print_findings(findings)

            if not findings:
                console.print("\n[green]✓ No security issues found![/green]")

        # Check fail condition
        if fail_on:
            severity_counts = _count_by_severity(findings)
            if _should_fail(severity_counts, fail_on):
                if not quiet:
                    console.print(
                        f"\n[red]✗ Failing due to findings at "
                        f"{fail_on} severity or higher[/red]"
                    )
                sys.exit(EXIT_FINDINGS)

        sys.exit(EXIT_SUCCESS if not findings else EXIT_SUCCESS)

    except KeyboardInterrupt:
        err_console.print("\n[yellow]Scan cancelled by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        err_console.print(f"[red]Error:[/red] {e}")
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(EXIT_ERROR)


@app.command()
def init(
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Overwrite existing configuration",
        ),
    ] = False,
) -> None:
    """
    Initialize Guardian configuration in the current directory.

    Creates a .guardian.yaml configuration file with default settings
    that you can customize for your project.
    """
    config_path = Path.cwd() / ".guardian.yaml"

    if config_path.exists() and not force:
        console.print(
            f"[yellow]Configuration file already exists:[/yellow] {config_path}\n"
            "Use --force to overwrite."
        )
        raise typer.Exit(EXIT_CONFIG_ERROR)

    config_content = """\
# SecureDev Guardian Configuration
# https://github.com/yourusername/securedev-guardian

# Base branch for comparison
base_ref: main

# Semgrep configuration
# Options: p/ci, p/security-audit, p/owasp-top-ten, or path to custom rules
semgrep_config: p/ci

# Output directory for reports
output_dir: "."

# Artifacts directory for detailed reports
artifacts_dir: artifacts

# Report format: md, json, or both
report_format: both

# Fail CI if findings at this severity or higher
# Options: critical, high, medium, low, or null to disable
fail_on_severity: null

# Show verbose output
verbose: false

# Suppress output (errors only)
quiet: false
"""

    config_path.write_text(config_content, encoding="utf-8")
    console.print(f"[green]✓[/green] Created configuration file: {config_path}")
    console.print("\nEdit this file to customize Guardian for your project.")


@app.command(name="version")
def show_version() -> None:
    """Show version information."""
    console.print(
        Panel(
            f"[bold blue]{__app_name__}[/bold blue]\n\n"
            f"Version: [green]{__version__}[/green]\n"
            f"Python: {sys.version.split()[0]}\n\n"
            f"{__description__}",
            title="Version Info",
            border_style="blue",
        )
    )


@app.command()
def config(
    show: Annotated[
        bool,
        typer.Option(
            "--show",
            "-s",
            help="Show current configuration",
        ),
    ] = True,
) -> None:
    """Show current configuration."""
    cfg = Config().load()

    table = Table(
        title="Current Configuration", show_header=True, header_style="bold cyan"
    )
    table.add_column("Setting", style="dim")
    table.add_column("Value")
    table.add_column("Source")

    source = "default"
    if cfg.config_path:
        source = str(cfg.config_path)

    for key, value in cfg.to_dict().items():
        table.add_row(key, str(value), source if key != "color" else "auto")

    console.print(table)


@app.command()
def check(
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show detailed output",
        ),
    ] = False,
) -> None:
    """
    Check that all required tools are installed.

    Verifies that Bandit, Semgrep, and Git are available.
    """
    import subprocess

    tools = [
        ("git", ["git", "--version"]),
        ("bandit", ["bandit", "--version"]),
        ("semgrep", ["semgrep", "--version"]),
    ]

    all_ok = True

    console.print("[bold]Checking required tools...[/bold]\n")

    for name, cmd in tools:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                version = result.stdout.strip().split("\n")[0]
                console.print(f"[green]✓[/green] {name}: {version}")
            else:
                console.print(f"[red]✗[/red] {name}: not working properly")
                all_ok = False
        except FileNotFoundError:
            console.print(f"[red]✗[/red] {name}: not installed")
            if verbose:
                console.print(f"  [dim]Install with: pip install {name}[/dim]")
            all_ok = False
        except subprocess.TimeoutExpired:
            console.print(f"[yellow]?[/yellow] {name}: timed out")
            all_ok = False

    console.print()

    if all_ok:
        console.print("[green]All tools are installed and working![/green]")
        sys.exit(EXIT_SUCCESS)
    else:
        console.print("[red]Some tools are missing. Please install them first.[/red]")
        console.print("\nInstall missing tools:")
        console.print("  pip install bandit semgrep")
        sys.exit(EXIT_ERROR)


# For backwards compatibility with old --base-ref syntax
@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    base_ref: Annotated[
        Optional[str],
        typer.Option(
            "--base-ref",
            "-b",
            help="[deprecated] Use 'guardian scan --base-ref' instead",
        ),
    ] = None,
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-V",
            callback=version_callback,
            is_eager=True,
            help="Show version and exit",
        ),
    ] = None,
) -> None:
    """
    SecureDev Guardian - AI-powered security scanner.

    Scan your code for security vulnerabilities using industry-standard
    tools (Bandit, Semgrep) with optional ML-enhanced analysis.

    Quick start:

        guardian scan --base-ref main

    For more help on a command:

        guardian scan --help
    """
    # Handle legacy --base-ref at root level
    if base_ref and ctx.invoked_subcommand is None:
        # Invoke scan command with the base_ref
        ctx.invoke(scan, base_ref=base_ref)


if __name__ == "__main__":
    app()
