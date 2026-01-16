#!/usr/bin/env python3
"""
SecureDev Guardian CLI

AI-powered security scanner with automated patching capabilities.
Scans your code for vulnerabilities and provides actionable fix recommendations.

Scanners:
- Bandit: Python security analysis (ALL 60+ rules)
- Semgrep: Multi-language patterns (OWASP, secrets, etc.)
- Secrets: Hardcoded credentials and API keys (50+ patterns)
- Patterns: Dangerous code patterns (eval, exec, etc.)
- Dependencies: Known vulnerable packages (CVE database)

Usage:
    guardian scan --base-ref main
    guardian scan --base-ref main --comprehensive
    guardian scan --base-ref main --fail-on high
    guardian init
    guardian version

For more information: https://github.com/yourusername/securedev-guardian
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Annotated, Optional

# Load environment variables from .env file
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

import typer
import requests
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from guardian.config import Config
from guardian.git_utils import get_changed_files
from guardian.report import build_pr_report
from guardian.scanners.bandit_scanner import run_bandit
from guardian.scanners.dependency_scanner import run_dependency_scanner
from guardian.scanners.pattern_scanner import run_comprehensive_scan
from guardian.scanners.secrets_scanner import run_secrets_scanner
from guardian.scanners.semgrep_scanner import (
    run_semgrep,
    run_semgrep_comprehensive,
    run_semgrep_max,
)
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

# Import UI components
from guardian.ui import (
    Icons,
    Theme,
    console,
    err_console,
    print_banner,
    print_header,
    print_subheader,
    print_success,
    print_error,
    print_warning,
    print_info,
    print_muted,
    create_scan_progress,
    create_spinner_progress,
    print_scan_config,
    create_summary_dashboard,
    print_findings_table,
    print_finding_detail,
    print_patches_summary,
    print_patch_diff,
    print_scanner_status,
    print_scan_complete,
    print_analysis_complete,
    print_quick_help,
    ScanConfig,
)

# ML inference engine (lazy import for performance)
_ml_engine = None


def _get_ml_engine():
    """Lazy-load ML inference engine."""
    global _ml_engine
    if _ml_engine is None:
        try:
            from ml.inference import EnhancedInferenceEngine

            _ml_engine = EnhancedInferenceEngine()
            if not _ml_engine.is_available:
                _ml_engine = None
        except ImportError:
            _ml_engine = None
    return _ml_engine


def _enhance_findings_with_ml(findings: list):
    """Enhance findings with ML predictions."""
    try:
        from ml.inference import enhance_findings_with_ml

        return enhance_findings_with_ml(findings)
    except ImportError:
        return findings


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
        console.print(f"[bold blue]{__app_name__}[/bold blue] version [green]{__version__}[/green]")
        raise typer.Exit()


def _filter_files(files: list[str]) -> tuple[list[str], list[str]]:
    """Filter files into Python and JS/TS categories."""
    py = [f for f in files if f.endswith(".py")]
    js_ts = [f for f in files if f.endswith((".js", ".ts", ".tsx", ".jsx"))]
    return py, js_ts


def _collect_files(target: Path) -> list[str]:
    """Collect code files from a target path (full scan)."""
    if target.is_file():
        return [str(target)]
    skip_dirs = {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
        "dist",
        "build",
        ".next",
        "coverage",
    }
    files: list[str] = []
    for root, dirs, filenames in os.walk(target):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
        for filename in filenames:
            if Path(filename).suffix in {".py", ".js", ".ts", ".tsx", ".jsx"}:
                files.append(str(Path(root) / filename))
    return files


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


def _print_summary_table(
    py_count: int,
    js_count: int,
    findings: list[dict],
    scanner_stats: dict | None = None,
    scan_time_ms: int = 0,
) -> None:
    """Print a visual summary dashboard of scan results."""
    severity_counts = _count_by_severity(findings)
    total = len(findings)

    # Count patches if available
    patches = sum(1 for f in findings if f.get("patch_suggestions"))

    # Create visual dashboard
    dashboard = create_summary_dashboard(
        total_findings=total,
        critical=severity_counts.get("critical", 0),
        high=severity_counts.get("high", 0),
        medium=severity_counts.get("medium", 0),
        low=severity_counts.get("low", 0),
        info=severity_counts.get("info", 0),
        files_scanned=py_count + js_count,
        patches_generated=patches,
        scan_time_ms=scan_time_ms,
    )
    console.print(dashboard)

    # Print scanner breakdown
    if scanner_stats:
        print_scanner_status(scanner_stats)


def _print_findings(findings: list[dict], max_items: int = 10, detailed: bool = False) -> None:
    """Print findings in a readable format."""
    if not findings:
        return

    if detailed:
        # Show detailed panels for each finding
        print_subheader("Detailed Findings", Icons.BUG)
        for i, finding in enumerate(findings[:max_items], 1):
            print_finding_detail(finding, i)
    else:
        # Show table view
        print_findings_table(findings, max_items=max_items)


@app.command()
def scan(
    target: Annotated[
        Path,
        typer.Option(
            "--target",
            "-t",
            help="Target path for full scan (file or directory)",
        ),
    ] = Path("."),
    base_ref: Annotated[
        str,
        typer.Option(
            "--base-ref",
            "-b",
            help="Base branch to compare against (e.g., main, develop)",
        ),
    ] = "main",
    full: Annotated[
        bool,
        typer.Option(
            "--full",
            help="Scan the full target path (ignores git diff)",
        ),
    ] = False,
    max_files: Annotated[
        int | None,
        typer.Option(
            "--max-files",
            help="Limit the number of files scanned in full mode",
        ),
    ] = None,
    semgrep_config: Annotated[
        str,
        typer.Option(
            "--semgrep-config",
            "-s",
            help="Semgrep config (e.g., p/ci, p/security-audit, comprehensive, max)",
        ),
    ] = "max",
    semgrep_experimental: Annotated[
        bool,
        typer.Option(
            "--semgrep-experimental",
            help="Include Semgrep experimental rules (noisy but broader coverage)",
        ),
    ] = False,
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
    comprehensive: Annotated[
        bool,
        typer.Option(
            "--comprehensive",
            "-c",
            help="Run ALL scanners: Bandit, Semgrep (all rules), Secrets, Patterns, Dependencies",
        ),
    ] = False,
    scan_secrets: Annotated[
        bool,
        typer.Option(
            "--secrets",
            help="Enable secrets scanning (API keys, tokens, credentials)",
        ),
    ] = False,
    scan_patterns: Annotated[
        bool,
        typer.Option(
            "--patterns",
            help="Enable dangerous code pattern detection",
        ),
    ] = False,
    scan_deps: Annotated[
        bool,
        typer.Option(
            "--deps",
            help="Enable dependency vulnerability scanning",
        ),
    ] = False,
    ml_enhance: Annotated[
        bool,
        typer.Option(
            "--ml-enhance",
            help="Enable ML-enhanced risk scoring using trained models",
        ),
    ] = False,
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

    Analyzes changed files using multiple scanners:

    [bold]Scanners:[/bold]
    • Bandit: Python security (60+ rules)
    • Semgrep: Multi-language patterns (OWASP, security-audit)
    • Secrets: API keys, tokens, credentials (50+ patterns)
    • Patterns: Dangerous code patterns (eval, exec, pickle)
    • Dependencies: Known vulnerable packages (CVE database)

    [bold]Examples:[/bold]

        guardian scan --base-ref main

        guardian scan --comprehensive  # All scanners

        guardian scan --secrets --deps  # Secrets + Dependencies

        guardian scan --fail-on high --json
    """
    try:
        # Load config
        cfg = Config().load()

        # Apply defaults from config if not specified
        if base_ref == "main" and cfg.get("base_ref"):
            base_ref = cfg.get("base_ref")

        # Comprehensive mode enables all scanners
        if comprehensive:
            scan_secrets = True
            scan_patterns = True
            scan_deps = True
            semgrep_config = "comprehensive"  # Will use multiple rulesets

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        artifacts_path = output_path / "artifacts"
        artifacts_path.mkdir(parents=True, exist_ok=True)

        # Track timing
        start_time = time.time()

        # Get files to scan
        if full:
            if not quiet:
                with create_spinner_progress() as progress:
                    progress.add_task("Collecting files...", total=None)
                    changed = _collect_files(target)
            else:
                changed = _collect_files(target)
        else:
            if not quiet:
                with create_spinner_progress() as progress:
                    progress.add_task("Getting changed files...", total=None)
                    changed = get_changed_files(base_ref)
            else:
                changed = get_changed_files(base_ref)

        if full and max_files and len(changed) > max_files:
            changed = sorted(changed)[:max_files]
            if verbose and not json_output:
                print_warning(f"Limiting scan to first {max_files} files", Icons.WARNING)

        py_files, js_ts_files = _filter_files(changed)
        all_code_files = py_files + js_ts_files

        # Build scanner list for display
        scanners_enabled = ["Bandit", "Semgrep"]
        if scan_secrets:
            scanners_enabled.append("Secrets")
        if scan_patterns:
            scanners_enabled.append("Patterns")
        if scan_deps:
            scanners_enabled.append("Dependencies")

        if not quiet and not json_output:
            scope_label = f"full scan: {target}" if full else f"diff vs {base_ref}"
            print_banner(f"Scanning {len(changed)} files ({scope_label})")

            # Show configuration
            llm_provider = os.environ.get("PATCH_LLM_PROVIDER", "local")
            print_scan_config(
                ScanConfig(
                    targets=[str(target)] if full else ["."],
                    scanners=scanners_enabled,
                    base_ref=None if full else base_ref,
                    ml_enabled=ml_enhance,
                    rag_enabled=False,
                    llm_provider=llm_provider,
                )
            )

        if verbose and not json_output:
            print_subheader("Changed Files", Icons.FILE)
            for f in changed[:20]:
                print_muted(f"  {f}")
            if len(changed) > 20:
                print_muted(f"  ... and {len(changed) - 20} more")

        # Initialize scanner results
        bandit_json: dict = {"results": [], "errors": []}
        semgrep_json: dict = {"results": [], "errors": []}
        secrets_json: dict = {"results": [], "errors": []}
        patterns_json: dict = {"results": [], "errors": []}
        deps_json: dict = {"results": [], "errors": []}

        # Run scanners with progress
        if not quiet and not json_output:
            with create_scan_progress() as progress:
                task = progress.add_task(f"{Icons.SEARCH} Running Bandit...", total=5)
                bandit_json = run_bandit(py_files)
                progress.update(task, advance=1)

                progress.update(task, description=f"{Icons.SEARCH} Running Semgrep...")
                if semgrep_config == "comprehensive":
                    semgrep_json = run_semgrep_comprehensive(
                        all_code_files, include_experimental=semgrep_experimental
                    )
                elif semgrep_config == "max":
                    semgrep_json = run_semgrep_max(
                        all_code_files, include_experimental=semgrep_experimental
                    )
                else:
                    semgrep_targets = all_code_files if full else js_ts_files
                    semgrep_json = run_semgrep(
                        semgrep_targets,
                        config=semgrep_config,
                        include_experimental=semgrep_experimental,
                    )
                progress.update(task, advance=1)

                if scan_secrets:
                    progress.update(task, description=f"{Icons.KEY} Scanning for secrets...")
                    secrets_json = run_secrets_scanner(all_code_files)
                progress.update(task, advance=1)

                if scan_patterns:
                    progress.update(task, description=f"{Icons.WARNING} Detecting patterns...")
                    patterns_json = run_comprehensive_scan(all_code_files)
                progress.update(task, advance=1)

                if scan_deps:
                    progress.update(task, description=f"{Icons.PACKAGE} Checking dependencies...")
                    deps_json = run_dependency_scanner(directory=str(target if full else Path(".")))
                progress.update(task, advance=1, description=f"{Icons.CHECK} Complete")
        else:
            bandit_json = run_bandit(py_files)
            if semgrep_config == "comprehensive":
                semgrep_json = run_semgrep_comprehensive(
                    all_code_files, include_experimental=semgrep_experimental
                )
            elif semgrep_config == "max":
                semgrep_json = run_semgrep_max(
                    all_code_files, include_experimental=semgrep_experimental
                )
            else:
                semgrep_targets = all_code_files if full else js_ts_files
                semgrep_json = run_semgrep(
                    semgrep_targets,
                    config=semgrep_config,
                    include_experimental=semgrep_experimental,
                )

            if scan_secrets:
                secrets_json = run_secrets_scanner(all_code_files)
            if scan_patterns:
                patterns_json = run_comprehensive_scan(all_code_files)
            if scan_deps:
                deps_json = run_dependency_scanner(directory=str(target if full else Path(".")))

        # Build report
        report_md, report_json = build_pr_report(
            base_ref=base_ref if not full else "full",
            py_files=py_files,
            js_ts_files=js_ts_files,
            bandit_json=bandit_json,
            semgrep_json=semgrep_json,
            ml_results=ml_results,
            repo_root=target if full else Path("."),
        )

        # Add additional scanner results to findings
        additional_findings = []

        # Process secrets findings
        for result in secrets_json.get("results", []):
            additional_findings.append(
                {
                    "severity": result.get("extra", {}).get("severity", "high").lower(),
                    "rule": {
                        "rule_id": result.get("check_id", "secrets"),
                        "name": result.get("check_name", "Secret detected"),
                    },
                    "location": {
                        "filepath": result.get("path", ""),
                        "start_line": result.get("start", {}).get("line", 0),
                    },
                }
            )

        # Process pattern findings
        for result in patterns_json.get("results", []):
            additional_findings.append(
                {
                    "severity": result.get("extra", {}).get("severity", "medium").lower(),
                    "rule": {
                        "rule_id": result.get("check_id", "pattern"),
                        "name": result.get("check_name", "Dangerous pattern"),
                    },
                    "location": {
                        "filepath": result.get("path", ""),
                        "start_line": result.get("start", {}).get("line", 0),
                    },
                }
            )

        # Process dependency findings
        for result in deps_json.get("results", []):
            additional_findings.append(
                {
                    "severity": result.get("extra", {}).get("severity", "high").lower(),
                    "rule": {
                        "rule_id": result.get("check_id", "dependency"),
                        "name": result.get("check_name", "Vulnerable dependency"),
                    },
                    "location": {
                        "filepath": result.get("path", ""),
                        "start_line": result.get("start", {}).get("line", 0),
                    },
                }
            )

        # Combine findings
        all_findings = report_json.get("findings", []) + additional_findings

        # Apply ML enhancement if enabled
        if ml_enhance:
            engine = _get_ml_engine()
            if engine:
                if not quiet:
                    console.print("[cyan]Enhancing findings with ML...[/cyan]")
                all_findings = _enhance_findings_with_ml(all_findings)
                if verbose:
                    ml_enhanced_count = sum(
                        1 for f in all_findings if f.get("ml_risk_score") is not None
                    )
                    console.print(f"  ML enhanced {ml_enhanced_count} findings")
            elif verbose:
                console.print("[yellow]ML engine not available, skipping enhancement[/yellow]")

        # Update report_json with all findings
        report_json["findings"] = all_findings
        report_json["scanners"] = {
            "bandit": {
                "findings": len(bandit_json.get("results", [])),
                "errors": bandit_json.get("errors", []),
            },
            "semgrep": {
                "findings": len(semgrep_json.get("results", [])),
                "errors": semgrep_json.get("errors", []),
            },
            "secrets": {
                "findings": len(secrets_json.get("results", [])),
                "enabled": scan_secrets,
            },
            "patterns": {
                "findings": len(patterns_json.get("results", [])),
                "enabled": scan_patterns,
            },
            "dependencies": {
                "findings": len(deps_json.get("results", [])),
                "enabled": scan_deps,
            },
        }

        findings = all_findings

        # Calculate timing
        elapsed_ms = int((time.time() - start_time) * 1000)

        # JSON output mode
        if json_output:
            print(json.dumps(report_json, indent=2))
            sys.exit(EXIT_FINDINGS if findings else EXIT_SUCCESS)

        # Write output files
        report_path = None
        if format in ("md", "both"):
            md_path = output_path / "report.md"
            md_path.write_text(report_md, encoding="utf-8")
            report_path = str(md_path)
            if not quiet:
                print_success(f"Wrote {md_path}")

        if format in ("json", "both"):
            json_path = output_path / "report.json"
            json_path.write_text(
                json.dumps({"bandit": bandit_json, "semgrep": semgrep_json}, indent=2),
                encoding="utf-8",
            )
            if not quiet:
                print_success(f"Wrote {json_path}")

            pr_json_path = artifacts_path / "pr_report.json"
            pr_json_path.write_text(json.dumps(report_json, indent=2), encoding="utf-8")
            if not quiet:
                print_success(f"Wrote {pr_json_path}")

        # Print summary
        if not quiet:
            console.print()
            _print_summary_table(
                len(py_files),
                len(js_ts_files),
                findings,
                scanner_stats=report_json.get("scanners"),
                scan_time_ms=elapsed_ms,
            )

            if findings and verbose:
                _print_findings(findings, detailed=True)

            # Print completion message
            print_scan_complete(
                total_findings=len(findings),
                duration_ms=elapsed_ms,
                report_path=report_path,
            )

        # Check fail condition
        if fail_on:
            severity_counts = _count_by_severity(findings)
            if _should_fail(severity_counts, fail_on):
                if not quiet:
                    print_error(f"Failing due to findings at {fail_on} severity or higher")
                sys.exit(EXIT_FINDINGS)

        sys.exit(EXIT_SUCCESS if not findings else EXIT_SUCCESS)

    except KeyboardInterrupt:
        print_warning("\nScan cancelled by user")
        sys.exit(130)
    except Exception as e:
        print_error(f"Error: {e}")
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(EXIT_ERROR)


@app.command()
def ingest(
    report_path: Annotated[
        Path,
        typer.Option(
            "--report",
            "-r",
            help="Path to report.json generated by guardian scan",
        ),
    ] = Path("report.json"),
    api_url: Annotated[
        Optional[str],
        typer.Option(
            "--api-url",
            help="Backend base URL (defaults to GUARDIAN_API_URL or http://localhost:8000)",
        ),
    ] = None,
    repo: Annotated[
        Optional[str],
        typer.Option(
            "--repo",
            help="Repository identifier (e.g., org/repo or local/path)",
        ),
    ] = None,
    pr_number: Annotated[
        int,
        typer.Option(
            "--pr-number",
            help="PR number (use 0 for non-PR scans)",
        ),
    ] = 0,
    commit_sha: Annotated[
        Optional[str],
        typer.Option(
            "--commit-sha",
            help="Commit SHA (defaults to HEAD or WORKDIR)",
        ),
    ] = None,
    base_ref: Annotated[
        str,
        typer.Option(
            "--base-ref",
            help="Base reference (default: main)",
        ),
    ] = "main",
    timeout: Annotated[
        int,
        typer.Option(
            "--timeout",
            help="Request timeout in seconds",
        ),
    ] = 30,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show response body",
        ),
    ] = False,
) -> None:
    """
    Ingest a report.json into the backend API.

    This does not require the backend to be on the same machine; use --api-url.
    """
    if not report_path.exists():
        print_error(f"Report not found: {report_path}")
        sys.exit(EXIT_ERROR)

    if api_url is None:
        api_url = os.environ.get("GUARDIAN_API_URL", "http://localhost:8000")
    api_url = api_url.rstrip("/")

    if repo is None:
        repo = f"local/{Path.cwd().name}"

    if commit_sha is None:
        try:
            import subprocess

            commit_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        except Exception:
            commit_sha = "WORKDIR"

    try:
        raw = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as e:
        print_error(f"Failed to parse report JSON: {e}")
        sys.exit(EXIT_ERROR)

    payload = {
        "repo": repo,
        "pr_number": pr_number,
        "commit_sha": commit_sha,
        "base_ref": base_ref,
        "report": raw,
        "tool_versions": {},
    }

    try:
        resp = requests.post(
            f"{api_url}/api/v1/reports",
            json=payload,
            timeout=timeout,
        )
    except requests.RequestException as e:
        print_error(f"Failed to POST report: {e}")
        sys.exit(EXIT_ERROR)

    if resp.status_code >= 400:
        print_error(f"Ingest failed: {resp.status_code}")
        if verbose:
            console.print(resp.text)
        sys.exit(EXIT_ERROR)

    print_success(f"Ingested report: {resp.status_code}", Icons.CHECK)
    if verbose:
        console.print(resp.text)


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
            title=f"{Icons.SHIELD} Version Info",
            border_style="blue",
        )
    )
    print_quick_help()


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
        title=f"{Icons.GEAR} Current Configuration",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")
    table.add_column("Source", style="dim")

    source = "default"
    if cfg.config_path:
        source = str(cfg.config_path)

    for key, value in cfg.to_dict().items():
        table.add_row(key, str(value), source if key != "color" else "auto")

    console.print(table)

    # Show environment variables
    console.print()
    print_subheader("Environment Variables", Icons.KEY)
    env_vars = [
        ("PATCH_LLM_PROVIDER", os.environ.get("PATCH_LLM_PROVIDER", "local")),
        ("GUARDIAN_OPENAI_MODEL", os.environ.get("GUARDIAN_OPENAI_MODEL", "not set")),
        ("GUARDIAN_GEMINI_MODEL", os.environ.get("GUARDIAN_GEMINI_MODEL", "not set")),
        ("OPENAI_API_KEY", "✓ Set" if os.environ.get("OPENAI_API_KEY") else "not set"),
        ("GEMINI_API_KEY", "✓ Set" if os.environ.get("GEMINI_API_KEY") else "not set"),
    ]
    for name, value in env_vars:
        if "✓" in str(value):
            print_success(f"{name}: {value}", icon="")
        elif value == "not set":
            print_muted(f"  {name}: {value}")
        else:
            print_info(f"{name}: {value}", icon="")


@app.command()
def train(
    targets: Annotated[
        Optional[str],
        typer.Option(
            "--targets",
            "-t",
            help="Comma-separated paths to scan for training data",
        ),
    ] = ".",
    epochs: Annotated[
        int,
        typer.Option(
            "--epochs",
            "-e",
            help="Number of training epochs",
        ),
    ] = 10,
    batch_size: Annotated[
        int,
        typer.Option(
            "--batch-size",
            help="Training batch size",
        ),
    ] = 32,
    output_dir: Annotated[
        str,
        typer.Option(
            "--output",
            "-o",
            help="Output directory for trained models",
        ),
    ] = "artifacts/models",
    skip_scan: Annotated[
        bool,
        typer.Option(
            "--skip-scan",
            help="Skip dataset generation (use existing)",
        ),
    ] = False,
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
    Train ML models using enhanced scanner data.

    Runs the complete training pipeline:
    1. Generate enhanced dataset using all 5 scanners
    2. Train Transformer model for risk classification
    3. Train GNN model for code graph analysis
    4. Export models to artifacts directory
    5. Validate model performance

    [bold]Examples:[/bold]

        guardian train  # Train on current directory

        guardian train --targets src/,tests/ --epochs 20

        guardian train --skip-scan  # Use existing dataset
    """
    try:
        from ml.train_pipeline import TrainingPipeline

        target_list = [Path(t.strip()) for t in targets.split(",")]

        console.print(
            Panel(
                "[bold blue]SecureDev Guardian ML Training[/bold blue]\n\n"
                f"Targets: {', '.join(target_list)}\n"
                f"Epochs: {epochs}\n"
                f"Batch Size: {batch_size}\n"
                f"Output: {output_dir}",
                title="Training Configuration",
                border_style="blue",
            )
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"{Icons.GEAR} Initializing training pipeline...", total=None)

            # Create and run pipeline
            pipeline = TrainingPipeline(
                targets=target_list,
                output_dir=Path(output_dir),
                epochs=epochs,
                batch_size=batch_size,
                skip_scan=skip_scan,
            )

            progress.update(task, description=f"{Icons.BRAIN} Running training pipeline...")
            results = pipeline.run()

        # Show results
        console.print()
        print_success("Training Complete!", Icons.ROCKET)
        console.print()

        table = Table(
            title=f"{Icons.CHART} Training Results",
            show_header=True,
            header_style="bold cyan",
            border_style="green",
        )
        table.add_column("Step", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Details", style="dim")

        for step, details in results.get("steps", {}).items():
            status_icon = (
                f"[green]{Icons.CHECK}[/green]"
                if details.get("success")
                else f"[red]{Icons.CROSS}[/red]"
            )
            table.add_row(
                step.replace("_", " ").title(), status_icon, str(details.get("message", ""))[:50]
            )

        console.print(table)

        if results.get("models_exported"):
            print_success(f"Models exported to: {output_dir}", Icons.FOLDER)

        sys.exit(EXIT_SUCCESS)

    except ImportError as e:
        print_error(f"ML training modules not available: {e}")
        print_muted("Make sure PyTorch and training dependencies are installed.")
        sys.exit(EXIT_ERROR)
    except Exception as e:
        print_error(f"Training failed: {e}")
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(EXIT_ERROR)


@app.command()
def pipeline(
    repos_dir: Annotated[
        Path,
        typer.Option(
            "--repos-dir",
            help="Directory containing repositories to scan",
        ),
    ] = Path("data/repos"),
    output_dir: Annotated[
        Path,
        typer.Option(
            "--output",
            "-o",
            help="Output directory for datasets and models",
        ),
    ] = Path("artifacts/models"),
    max_samples: Annotated[
        int,
        typer.Option(
            "--max-samples",
            help="Max safe samples per repository",
        ),
    ] = 500,
    max_files: Annotated[
        int,
        typer.Option(
            "--max-files",
            help="Max files per repository to scan",
        ),
    ] = 1500,
    balance_mode: Annotated[
        str,
        typer.Option(
            "--balance-mode",
            help="Balancing strategy: ratio, downsample, none",
        ),
    ] = "ratio",
    max_safe_ratio: Annotated[
        float,
        typer.Option(
            "--max-safe-ratio",
            help="Max safe samples per vulnerable sample (ratio mode)",
        ),
    ] = 5.0,
    seed: Annotated[
        int,
        typer.Option(
            "--seed",
            help="Random seed for reproducibility",
        ),
    ] = 42,
    epochs: Annotated[
        int,
        typer.Option(
            "--epochs",
            help="Training epochs",
        ),
    ] = 10,
    batch_size: Annotated[
        int,
        typer.Option(
            "--batch-size",
            help="Training batch size",
        ),
    ] = 16,
    transformer_size: Annotated[
        str,
        typer.Option(
            "--transformer-size",
            help="Transformer size preset (tiny, small, medium)",
        ),
    ] = "small",
    gnn_hidden_dim: Annotated[
        int,
        typer.Option(
            "--gnn-hidden-dim",
            help="GNN hidden dimension",
        ),
    ] = 128,
    gnn_layers: Annotated[
        int,
        typer.Option(
            "--gnn-layers",
            help="Number of GNN layers",
        ),
    ] = 2,
    gnn_dropout: Annotated[
        float,
        typer.Option(
            "--gnn-dropout",
            help="GNN dropout",
        ),
    ] = 0.1,
    device: Annotated[
        str,
        typer.Option(
            "--device",
            help="Training device (cpu, cuda, mps)",
        ),
    ] = "cpu",
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
    End-to-end ML pipeline: scan repos -> weak/gold labels -> datasets -> train models.

    This command rebuilds datasets from scratch and trains Transformer + GNN + Ensemble.
    """
    from types import SimpleNamespace

    try:
        from ml.data_pipeline import run_pipeline as run_data_pipeline
        from ml.train_pipeline import TrainingPipeline

        datasets_dir = output_dir / "datasets"

        print_banner("End-to-End ML Pipeline (Full Rebuild)")
        print_scan_config(
            ScanConfig(
                targets=[str(repos_dir)],
                scanners=["Bandit", "Semgrep"],
                ml_enabled=True,
                rag_enabled=False,
                llm_provider=os.environ.get("PATCH_LLM_PROVIDER", "local"),
            )
        )

        # Step 1: Build datasets (weak -> gold -> splits)
        print_subheader("Step 1/2: Data Pipeline", Icons.CHART)
        args = SimpleNamespace(
            repos_dir=str(repos_dir),
            output_dir=str(datasets_dir),
            seed=seed,
            max_samples=max_samples,
            max_files=max_files,
            balance_mode=balance_mode,
            max_safe_ratio=max_safe_ratio,
            verbose=verbose,
        )
        run_data_pipeline(args)

        # Step 2: Train models
        print_subheader("Step 2/2: Training", Icons.BRAIN)
        pipeline = TrainingPipeline(
            targets=[repos_dir],
            output_dir=output_dir,
            dataset_dir=datasets_dir,
            skip_scan=True,
            epochs=epochs,
            batch_size=batch_size,
            seed=seed,
            device=device,
            transformer_size=transformer_size,
            gnn_hidden_dim=gnn_hidden_dim,
            gnn_layers=gnn_layers,
            gnn_dropout=gnn_dropout,
            verbose=verbose,
        )
        results = pipeline.run()

        if results.get("success"):
            print_success("Pipeline completed successfully.", Icons.CHECK)
        else:
            print_error(f"Pipeline failed: {results.get('error')}")
            sys.exit(EXIT_ERROR)

    except Exception as e:
        print_error(f"Pipeline failed: {e}")
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(EXIT_ERROR)


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

    print_banner("System Health Check")

    tools = [
        ("git", ["git", "--version"], "brew install git"),
        ("bandit", ["bandit", "--version"], "pip install bandit"),
        ("semgrep", ["semgrep", "--version"], "pip install semgrep"),
        ("python", ["python", "--version"], ""),
    ]

    all_ok = True

    # Create status table
    table = Table(
        title=f"{Icons.GEAR} Tool Status",
        show_header=True,
        header_style="bold",
        border_style="dim",
    )
    table.add_column("Tool", width=12)
    table.add_column("Status", justify="center", width=8)
    table.add_column("Version", width=30)
    table.add_column("Install", style="dim", width=25)

    for name, cmd, install_cmd in tools:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                version = result.stdout.strip().split("\n")[0][:28]
                table.add_row(
                    name,
                    f"[green]{Icons.CHECK}[/green]",
                    version,
                    "",
                )
            else:
                table.add_row(
                    name,
                    f"[red]{Icons.CROSS}[/red]",
                    "not working",
                    install_cmd,
                )
                all_ok = False
        except FileNotFoundError:
            table.add_row(
                name,
                f"[red]{Icons.CROSS}[/red]",
                "not installed",
                install_cmd,
            )
            all_ok = False
        except subprocess.TimeoutExpired:
            table.add_row(
                name,
                f"[yellow]{Icons.WARNING}[/yellow]",
                "timed out",
                "",
            )
            all_ok = False

    console.print(table)
    console.print()

    # Check ML components
    print_subheader("ML Components", Icons.BRAIN)
    ml_components = [
        ("PyTorch", "torch"),
        ("RAG Retriever", "rag.retriever"),
        ("ML Inference", "ml.inference"),
    ]

    for name, module in ml_components:
        try:
            __import__(module)
            print_success(f"{name}: available", icon="")
        except ImportError:
            print_muted(f"  {name}: not available")

    console.print()

    if all_ok:
        print_success("All required tools are installed and working!", Icons.SHIELD)
        sys.exit(EXIT_SUCCESS)
    else:
        print_error("Some tools are missing. Install them with the commands shown above.")
        sys.exit(EXIT_ERROR)


@app.command()
def analyze(
    targets: Annotated[
        Optional[list[Path]],
        typer.Argument(
            help="Paths to analyze (defaults to current directory)",
        ),
    ] = None,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Output file for analysis report",
        ),
    ] = None,
    format_type: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: json or markdown",
        ),
    ] = "json",
    no_patches: Annotated[
        bool,
        typer.Option(
            "--no-patches",
            help="Skip patch generation",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show detailed output",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Output JSON to stdout",
        ),
    ] = False,
) -> None:
    """
    Run integrated ML + RAG + LLM analysis on your codebase.

    This command combines:
    • ML-based vulnerability risk scoring
    • RAG-based retrieval of fix patterns
    • LLM-powered patch generation

    Examples:

        guardian analyze                    # Analyze current directory
        guardian analyze src/               # Analyze specific path
        guardian analyze --format markdown  # Get markdown report
        guardian analyze --no-patches       # Skip patch generation
    """
    try:
        from ml.integrated_pipeline import IntegratedPipeline, run_integrated_analysis
    except ImportError as e:
        print_error(f"ML components not available: {e}")
        print_muted("Make sure PyTorch and ML dependencies are installed.")
        sys.exit(EXIT_ERROR)

    targets = targets or [Path(".")]
    target_strs = [str(t) for t in targets]

    # Track timing
    start_time = time.time()

    if not json_output:
        print_banner("Integrated ML + RAG + LLM Analysis")

        llm_provider = os.environ.get("PATCH_LLM_PROVIDER", "local")
        print_scan_config(
            ScanConfig(
                targets=target_strs,
                scanners=["Bandit", "Semgrep"],
                ml_enabled=True,
                rag_enabled=True,
                llm_provider=llm_provider,
            )
        )

    try:
        with create_scan_progress() as progress:
            # Run scanners
            task = progress.add_task(f"{Icons.SEARCH} Running security scanners...", total=4)

            all_findings = []
            for target in targets:
                if target.exists():
                    # Convert to string and check if directory
                    target_str = str(target)
                    is_dir = target.is_dir()

                    # Bandit returns dict with 'results' key
                    bandit_output = run_bandit([target_str], recursive=is_dir)
                    if isinstance(bandit_output, dict):
                        bandit_findings = bandit_output.get("results", [])
                    else:
                        bandit_findings = bandit_output if isinstance(bandit_output, list) else []

                    # Semgrep returns dict with 'results' key
                    semgrep_output = run_semgrep([target])
                    if isinstance(semgrep_output, dict):
                        semgrep_findings = semgrep_output.get("results", [])
                    else:
                        semgrep_findings = (
                            semgrep_output if isinstance(semgrep_output, list) else []
                        )

                    all_findings.extend(bandit_findings)
                    all_findings.extend(semgrep_findings)

            progress.update(
                task, advance=1, description=f"{Icons.CHECK} Found {len(all_findings)} findings"
            )

            # Run integrated analysis
            progress.update(task, description=f"{Icons.BRAIN} Analyzing with ML...")

            pipeline = IntegratedPipeline()
            progress.update(task, advance=1)

            progress.update(task, description=f"{Icons.BOOK} Retrieving from knowledge base...")
            analyzed = pipeline.analyze_batch(
                all_findings,
                generate_patches=not no_patches,
            )
            progress.update(task, advance=1)

            # Generate report
            progress.update(task, description=f"{Icons.FILE} Generating report...")
            report = pipeline.generate_report(analyzed, format=format_type)
            progress.update(task, advance=1, description=f"{Icons.CHECK} Analysis complete")

        # Calculate timing
        elapsed_ms = int((time.time() - start_time) * 1000)

        # Output results
        if json_output:
            print(report)
        elif output:
            output.write_text(report)
            print_success(f"Report saved to: {output}")
        else:
            # Print summary dashboard
            import json as json_module

            data = json_module.loads(pipeline.generate_report(analyzed, format="json"))
            summary = data["summary"]

            console.print()
            dashboard = create_summary_dashboard(
                total_findings=summary["total_findings"],
                high=summary["high_risk"],
                medium=summary["medium_risk"],
                low=summary["low_risk"],
                patches_generated=summary["patches_available"],
                scan_time_ms=elapsed_ms,
            )
            console.print(dashboard)

            # Show findings table
            if analyzed:
                # Convert to dict format for display
                findings_for_display = []
                for f in sorted(analyzed, key=lambda x: -x.ml_risk_score):
                    findings_for_display.append(
                        {
                            "category": f.category,
                            "ml_risk_score": f.ml_risk_score,
                            "file_path": f.file_path,
                            "line_start": f.line_start,
                            "message": f"{f.category} - {f.ml_risk_label}",
                            "code": f.code_snippet[:100] if f.code_snippet else "",
                            "severity": "high"
                            if f.ml_risk_score > 0.7
                            else "medium"
                            if f.ml_risk_score > 0.4
                            else "low",
                            "patch_suggestions": [
                                {"source": p.source, "confidence": p.confidence}
                                for p in f.patch_suggestions
                            ]
                            if f.patch_suggestions
                            else [],
                        }
                    )

                console.print()
                print_findings_table(
                    findings_for_display, title="ML-Analyzed Findings", max_items=10
                )

                # Show patches
                patches_available = [f for f in analyzed if f.patch_suggestions]
                if patches_available:
                    console.print()
                    print_patches_summary(findings_for_display)

                if verbose:
                    # Show detailed view for top findings
                    print_header("Detailed Analysis", Icons.SEARCH)
                    for i, f in enumerate(findings_for_display[:3], 1):
                        print_finding_detail(f, i)

            # Print completion message
            print_analysis_complete(
                high_risk=summary["high_risk"],
                patches=summary["patches_available"],
            )

    except Exception as e:
        print_error(f"Analysis failed: {e}")
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(EXIT_ERROR)


@app.command()
def patch(
    findings_path: Annotated[
        Path,
        typer.Option(
            "--findings",
            "-f",
            help="Path to normalized findings JSON (e.g., artifacts/pr_report.json)",
        ),
    ] = Path("artifacts/pr_report.json"),
    repo_root: Annotated[
        Path,
        typer.Option(
            "--repo",
            "-r",
            help="Repository root to apply/validate patches",
        ),
    ] = Path("."),
    commit: Annotated[
        Optional[str],
        typer.Option(
            "--commit",
            help="Commit hash to validate against (default: HEAD)",
        ),
    ] = None,
    candidates: Annotated[
        int,
        typer.Option(
            "--candidates",
            help="Number of LLM candidates per finding",
        ),
    ] = 3,
    finding_id: Annotated[
        Optional[str],
        typer.Option(
            "--finding-id",
            help="Patch a single finding_id (optional)",
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
) -> None:
    """
    Generate validated patches from normalized findings using deterministic + LLM candidates.
    """
    try:
        from patcher.orchestrator import run_orchestrator
        from patcher.patcher import load_findings
    except ImportError as e:
        print_error(f"Patcher modules not available: {e}")
        sys.exit(EXIT_ERROR)

    if not findings_path.exists():
        print_error(f"Findings file not found: {findings_path}")
        sys.exit(EXIT_ERROR)

    if commit is None:
        try:
            import subprocess

            commit = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repo_root, text=True
            ).strip()
        except Exception as e:
            print_error(f"Failed to resolve commit hash: {e}")
            sys.exit(EXIT_ERROR)

    findings = load_findings(findings_path)
    if finding_id:
        findings = [f for f in findings if f.get("finding_id") == finding_id]
        if not findings:
            print_error(f"Finding not found: {finding_id}")
            sys.exit(EXIT_ERROR)

    print_banner("Patch Generation & Validation")
    print_scan_config(
        ScanConfig(
            targets=[str(repo_root)],
            scanners=["Deterministic", "LLM"],
            ml_enabled=True,
            rag_enabled=True,
            llm_provider=os.environ.get("PATCH_LLM_PROVIDER", "local"),
        )
    )

    result = run_orchestrator(
        repo_root=repo_root,
        commit=commit,
        findings=findings,
        candidates=candidates,
    )

    run_id = result.get("run_id", "unknown")
    print_success(f"Run ID: {run_id}")

    for item in result.get("findings", []):
        selected = item.get("selected")
        print_subheader(f"Finding {item.get('finding_id')}", Icons.FILE)
        if not selected:
            print_warning("No validated patch selected.")
            continue

        finding_dir = Path("artifacts/patch_v1") / run_id / item["finding_id"]
        candidate_path = (
            finding_dir
            / f"candidate_{'det' if selected.startswith('det') else selected.split('-')[-1]}.diff"
        )
        if not candidate_path.exists():
            print_warning(f"Selected diff not found: {candidate_path}")
            continue

        final_path = finding_dir / "selected.diff"
        final_path.write_text(candidate_path.read_text(encoding="utf-8"), encoding="utf-8")
        print_success(f"Selected patch: {final_path}")

        if verbose:
            print_patch_diff(candidate_path.read_text(encoding="utf-8"))


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
