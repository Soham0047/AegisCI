"""
Production-level CLI UI components for SecureDev Guardian.
Rich console elements, themes, and display utilities.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from rich.box import ROUNDED, HEAVY
from rich.columns import Columns
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.style import Style
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from guardian.version import __app_name__, __version__, SEVERITY_COLORS, SEVERITY_LEVELS


# ═══════════════════════════════════════════════════════════════════════════════
# THEME & STYLES
# ═══════════════════════════════════════════════════════════════════════════════

class Theme:
    """Guardian CLI color theme."""
    # Brand colors
    PRIMARY = "blue"
    SECONDARY = "cyan"
    ACCENT = "magenta"
    
    # Semantic colors
    SUCCESS = "green"
    WARNING = "yellow"
    ERROR = "red"
    MUTED = "dim"
    
    # Severity palette
    CRITICAL = "bold red"
    HIGH = "red"
    MEDIUM = "yellow"
    LOW = "blue"
    INFO = "dim"
    
    # Risk score colors
    @staticmethod
    def risk_color(score: float) -> str:
        if score >= 0.8:
            return "bold red"
        elif score >= 0.6:
            return "red"
        elif score >= 0.4:
            return "yellow"
        elif score >= 0.2:
            return "blue"
        else:
            return "green"
    
    @staticmethod
    def severity_style(severity: str) -> str:
        return SEVERITY_COLORS.get(severity.lower(), "white")


class Icons:
    """Unicode icons for CLI output."""
    # Status icons
    CHECK = "✓"
    CROSS = "✗"
    WARNING = "⚠"
    INFO = "ℹ"
    QUESTION = "?"
    
    # Category icons
    SHIELD = "🛡️"
    BUG = "🐛"
    LOCK = "🔒"
    KEY = "🔑"
    FIRE = "🔥"
    PACKAGE = "📦"
    FILE = "📄"
    FOLDER = "📁"
    SEARCH = "🔍"
    LIGHTNING = "⚡"
    GEAR = "⚙️"
    CHART = "📊"
    PATCH = "🩹"
    BRAIN = "🧠"
    BOOK = "📚"
    ROCKET = "🚀"
    CLOCK = "🕐"
    
    # Risk indicators  
    RISK_HIGH = "●"
    RISK_MED = "◐"
    RISK_LOW = "○"
    
    # Progress
    ARROW_RIGHT = "→"
    DOT = "•"


# ═══════════════════════════════════════════════════════════════════════════════
# CONSOLE FACTORY
# ═══════════════════════════════════════════════════════════════════════════════

def create_console(stderr: bool = False) -> Console:
    """Create a configured Rich console."""
    return Console(
        stderr=stderr,
        force_terminal=None,
        color_system="auto",
        highlight=True,
    )


console = create_console()
err_console = create_console(stderr=True)


# ═══════════════════════════════════════════════════════════════════════════════
# HEADER & BRANDING
# ═══════════════════════════════════════════════════════════════════════════════

def print_banner(subtitle: str = "") -> None:
    """Print the Guardian banner."""
    banner_text = Text()
    banner_text.append("╔═══════════════════════════════════════════════════════════╗\n", style="blue")
    banner_text.append("║  ", style="blue")
    banner_text.append(f"{Icons.SHIELD} SecureDev Guardian", style="bold blue")
    banner_text.append("                                  ║\n", style="blue")
    banner_text.append("║  ", style="blue")
    banner_text.append(f"v{__version__}", style="cyan")
    banner_text.append(" • AI-Powered Security Scanner", style="dim")
    banner_text.append("                  ║\n", style="blue")
    if subtitle:
        banner_text.append("║  ", style="blue")
        banner_text.append(f"{subtitle:<56}", style="white")
        banner_text.append("║\n", style="blue")
    banner_text.append("╚═══════════════════════════════════════════════════════════╝", style="blue")
    
    console.print(banner_text)
    console.print()


def print_header(title: str, icon: str = "", style: str = "bold blue") -> None:
    """Print a section header."""
    text = f"{icon} {title}" if icon else title
    console.print(Rule(text, style=style))


def print_subheader(title: str, icon: str = "") -> None:
    """Print a subsection header."""
    text = f"{icon} {title}" if icon else title
    console.print(f"\n[bold cyan]{text}[/bold cyan]")


# ═══════════════════════════════════════════════════════════════════════════════
# STATUS MESSAGES
# ═══════════════════════════════════════════════════════════════════════════════

def print_success(message: str, icon: str = Icons.CHECK) -> None:
    console.print(f"[green]{icon}[/green] {message}")


def print_error(message: str, icon: str = Icons.CROSS) -> None:
    err_console.print(f"[red]{icon}[/red] {message}")


def print_warning(message: str, icon: str = Icons.WARNING) -> None:
    console.print(f"[yellow]{icon}[/yellow] {message}")


def print_info(message: str, icon: str = Icons.INFO) -> None:
    console.print(f"[blue]{icon}[/blue] {message}")


def print_muted(message: str) -> None:
    console.print(f"[dim]{message}[/dim]")


# ═══════════════════════════════════════════════════════════════════════════════
# PROGRESS INDICATORS
# ═══════════════════════════════════════════════════════════════════════════════

def create_scan_progress() -> Progress:
    """Create progress bar for scanning operations."""
    return Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=30, complete_style="cyan", finished_style="green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


def create_spinner_progress() -> Progress:
    """Create a simple spinner progress."""
    return Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold]{task.description}"),
        console=console,
        transient=True,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# ANALYSIS DISPLAY COMPONENTS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScanConfig:
    """Configuration summary for display."""
    targets: list[str]
    scanners: list[str]
    base_ref: str | None = None
    ml_enabled: bool = False
    rag_enabled: bool = False
    llm_provider: str = "local"


def print_scan_config(config: ScanConfig) -> None:
    """Display scan configuration panel."""
    
    # Build config lines
    lines = []
    lines.append(f"[bold]Targets:[/bold]     {', '.join(config.targets) or 'current directory'}")
    lines.append(f"[bold]Scanners:[/bold]    {', '.join(config.scanners)}")
    
    if config.base_ref:
        lines.append(f"[bold]Base Ref:[/bold]    {config.base_ref}")
    
    # Feature flags
    features = []
    if config.ml_enabled:
        features.append(f"[cyan]{Icons.BRAIN} ML Scoring[/cyan]")
    if config.rag_enabled:
        features.append(f"[magenta]{Icons.BOOK} RAG[/magenta]")
    if config.llm_provider != "local":
        features.append(f"[green]{Icons.LIGHTNING} {config.llm_provider.upper()}[/green]")
    
    if features:
        lines.append(f"[bold]Features:[/bold]    {' • '.join(features)}")
    
    panel = Panel(
        "\n".join(lines),
        title=f"{Icons.GEAR} Scan Configuration",
        title_align="left",
        border_style="blue",
        padding=(0, 1),
    )
    console.print(panel)


def create_summary_dashboard(
    total_findings: int,
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    info: int = 0,
    files_scanned: int = 0,
    patches_generated: int = 0,
    scan_time_ms: int = 0,
) -> Panel:
    """Create a visual summary dashboard."""
    
    # Main metrics grid
    grid = Table.grid(padding=(0, 3))
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    
    # Top row - total and patches
    findings_box = _create_metric_box("FINDINGS", str(total_findings), "cyan" if total_findings == 0 else "yellow")
    patches_box = _create_metric_box("PATCHES", str(patches_generated), "green" if patches_generated > 0 else "dim")
    files_box = _create_metric_box("FILES", str(files_scanned), "blue")
    time_box = _create_metric_box("TIME", f"{scan_time_ms}ms", "dim")
    
    grid.add_row(findings_box, patches_box, files_box, time_box)
    
    # Severity breakdown
    severity_table = Table(
        show_header=False,
        box=None,
        padding=(0, 1),
    )
    severity_table.add_column(justify="right", width=10)
    severity_table.add_column(justify="center", width=4)
    severity_table.add_column(justify="left", width=20)
    
    if critical > 0:
        severity_table.add_row("[bold red]CRITICAL[/bold red]", f"[bold red]{critical}[/bold red]", _severity_bar(critical, total_findings, "red"))
    if high > 0:
        severity_table.add_row("[red]HIGH[/red]", f"[red]{high}[/red]", _severity_bar(high, total_findings, "red"))
    if medium > 0:
        severity_table.add_row("[yellow]MEDIUM[/yellow]", f"[yellow]{medium}[/yellow]", _severity_bar(medium, total_findings, "yellow"))
    if low > 0:
        severity_table.add_row("[blue]LOW[/blue]", f"[blue]{low}[/blue]", _severity_bar(low, total_findings, "blue"))
    if info > 0:
        severity_table.add_row("[dim]INFO[/dim]", f"[dim]{info}[/dim]", _severity_bar(info, total_findings, "dim"))
    
    content = Group(grid, "", severity_table) if total_findings > 0 else grid
    
    # Determine overall status
    if critical > 0 or high > 0:
        border_style = "red"
        title_icon = Icons.FIRE
    elif medium > 0:
        border_style = "yellow"
        title_icon = Icons.WARNING
    elif total_findings > 0:
        border_style = "blue"
        title_icon = Icons.INFO
    else:
        border_style = "green"
        title_icon = Icons.SHIELD
    
    return Panel(
        content,
        title=f"{title_icon} Security Analysis Summary",
        title_align="left",
        border_style=border_style,
        padding=(1, 2),
    )


def _create_metric_box(label: str, value: str, color: str) -> Panel:
    """Create a small metric box."""
    content = Text()
    content.append(f"{value}\n", style=f"bold {color}")
    content.append(label, style="dim")
    return Panel(content, box=ROUNDED, padding=(0, 2), border_style=color)


def _severity_bar(count: int, total: int, color: str, width: int = 20) -> str:
    """Create a severity bar visualization."""
    if total == 0:
        return ""
    ratio = min(count / total, 1.0)
    filled = int(ratio * width)
    bar = "█" * filled + "░" * (width - filled)
    return f"[{color}]{bar}[/{color}]"


# ═══════════════════════════════════════════════════════════════════════════════
# FINDINGS DISPLAY
# ═══════════════════════════════════════════════════════════════════════════════

def print_findings_table(findings: list[dict], title: str = "Security Findings", max_items: int = 15) -> None:
    """Print findings in a detailed table."""
    if not findings:
        print_success("No security issues found!", Icons.SHIELD)
        return
    
    table = Table(
        title=f"{Icons.BUG} {title}",
        title_style="bold",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        row_styles=["", "dim"],
    )
    
    table.add_column("#", justify="right", style="dim", width=3)
    table.add_column("Risk", justify="center", width=6)
    table.add_column("Category", width=12)
    table.add_column("Location", style="cyan", width=35)
    table.add_column("Description", width=40, overflow="ellipsis")
    
    for i, finding in enumerate(findings[:max_items], 1):
        # Extract fields (handle both formats)
        severity = finding.get("severity", "").lower()
        risk_score = finding.get("ml_risk_score", finding.get("risk_score"))
        
        # Handle nested rule/location or flat structure
        if "rule" in finding:
            rule = finding.get("rule", {})
            location = finding.get("location", {})
            rule_id = rule.get("rule_id", finding.get("category", "unknown"))
            description = rule.get("name", finding.get("message", ""))
            filepath = location.get("filepath", finding.get("file_path", ""))
            line = location.get("start_line", finding.get("line_start", "?"))
        else:
            rule_id = finding.get("test_id", finding.get("category", "unknown"))
            description = finding.get("issue_text", finding.get("message", ""))
            filepath = finding.get("filename", finding.get("file_path", ""))
            line = finding.get("line_number", finding.get("line_start", "?"))
        
        # Format risk indicator
        if risk_score is not None:
            risk_text = Text()
            color = Theme.risk_color(risk_score)
            icon = Icons.RISK_HIGH if risk_score >= 0.7 else Icons.RISK_MED if risk_score >= 0.4 else Icons.RISK_LOW
            risk_text.append(f"{icon} ", style=color)
            risk_text.append(f"{risk_score:.0%}", style=color)
        elif severity:
            color = Theme.severity_style(severity)
            risk_text = Text(severity.upper()[:4], style=color)
        else:
            risk_text = Text("-", style="dim")
        
        # Truncate filepath if needed
        if len(filepath) > 30:
            filepath = "..." + filepath[-27:]
        
        location_text = f"{filepath}:{line}"
        
        table.add_row(
            str(i),
            risk_text,
            rule_id,
            location_text,
            description[:40] + "..." if len(description) > 40 else description,
        )
    
    console.print(table)
    
    if len(findings) > max_items:
        print_muted(f"\n  {Icons.DOT} Showing {max_items} of {len(findings)} findings. Use --json for complete list.")


def print_finding_detail(finding: dict, index: int = 1) -> None:
    """Print detailed finding information."""
    # Extract fields
    severity = finding.get("severity", "medium").lower()
    risk_score = finding.get("ml_risk_score", finding.get("risk_score"))
    category = finding.get("test_id", finding.get("category", "unknown"))
    message = finding.get("issue_text", finding.get("message", ""))
    filepath = finding.get("filename", finding.get("file_path", ""))
    line = finding.get("line_number", finding.get("line_start", "?"))
    code = finding.get("code", finding.get("snippet", ""))
    
    # Build content
    lines = []
    lines.append(f"[bold]{category}[/bold]")
    lines.append(f"{message}")
    lines.append("")
    lines.append(f"[cyan]Location:[/cyan] {filepath}:{line}")
    
    if risk_score is not None:
        color = Theme.risk_color(risk_score)
        lines.append(f"[cyan]ML Risk Score:[/cyan] [{color}]{risk_score:.1%}[/{color}]")
    
    if code:
        lines.append("")
        lines.append("[dim]Code:[/dim]")
        lines.append(f"[dim italic]{code.strip()[:100]}[/dim italic]")
    
    color = Theme.severity_style(severity)
    panel = Panel(
        "\n".join(lines),
        title=f"[{color}]#{index} {severity.upper()}[/{color}]",
        title_align="left",
        border_style=color,
        padding=(0, 1),
    )
    console.print(panel)


# ═══════════════════════════════════════════════════════════════════════════════
# PATCH DISPLAY
# ═══════════════════════════════════════════════════════════════════════════════

def print_patches_summary(findings_with_patches: list, max_items: int = 5) -> None:
    """Print summary of available patches."""
    patches = [f for f in findings_with_patches if f.get("patch_suggestions") or hasattr(f, "patch_suggestions")]
    
    if not patches:
        print_muted(f"\n{Icons.INFO} No patches generated for current findings.")
        return
    
    console.print(f"\n[bold]{Icons.PATCH} Patch Suggestions[/bold]")
    
    table = Table(show_header=True, header_style="bold", box=ROUNDED, border_style="green")
    table.add_column("Finding", width=35)
    table.add_column("Source", width=15)
    table.add_column("Confidence", justify="center", width=12)
    
    for f in patches[:max_items]:
        # Handle both dict and object
        if hasattr(f, "patch_suggestions"):
            patch = f.patch_suggestions[0] if f.patch_suggestions else None
            location = f"{f.file_path}:{f.line_start}"
        else:
            patch = f.get("patch_suggestions", [{}])[0] if f.get("patch_suggestions") else None
            location = f"{f.get('file_path', '?')}:{f.get('line_start', '?')}"
        
        if patch:
            source = patch.source if hasattr(patch, "source") else patch.get("source", "?")
            confidence = patch.confidence if hasattr(patch, "confidence") else patch.get("confidence", 0)
            conf_color = "green" if confidence > 0.7 else "yellow" if confidence > 0.4 else "red"
            table.add_row(
                location,
                source,
                f"[{conf_color}]{confidence:.0%}[/{conf_color}]"
            )
    
    console.print(table)
    
    if len(patches) > max_items:
        print_muted(f"  {Icons.DOT} {len(patches) - max_items} more patches available.")


def print_patch_diff(patch: str, filepath: str = "", line: int = 0) -> None:
    """Print a patch diff with syntax highlighting."""
    header = f"[bold]{Icons.PATCH} Suggested Fix[/bold]"
    if filepath:
        header += f" for [cyan]{filepath}:{line}[/cyan]"
    
    console.print(header)
    
    # Colorize diff
    lines = []
    for line in patch.split("\n"):
        if line.startswith("+"):
            lines.append(f"[green]{line}[/green]")
        elif line.startswith("-"):
            lines.append(f"[red]{line}[/red]")
        elif line.startswith("@@"):
            lines.append(f"[cyan]{line}[/cyan]")
        else:
            lines.append(f"[dim]{line}[/dim]")
    
    console.print(Panel(
        "\n".join(lines),
        border_style="green",
        padding=(0, 1),
    ))


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER STATUS
# ═══════════════════════════════════════════════════════════════════════════════

def print_scanner_status(scanner_stats: dict[str, dict]) -> None:
    """Print scanner status summary."""
    table = Table(
        title=f"{Icons.SEARCH} Scanner Results",
        title_style="bold",
        show_header=True,
        header_style="bold",
        border_style="dim",
    )
    
    table.add_column("Scanner", width=15)
    table.add_column("Status", justify="center", width=8)
    table.add_column("Findings", justify="right", width=10)
    table.add_column("Notes", width=30)
    
    for scanner, stats in scanner_stats.items():
        enabled = stats.get("enabled", True)
        findings = stats.get("findings", 0)
        errors = stats.get("errors", [])
        
        if not enabled:
            status = f"[dim]{Icons.DOT} Skip[/dim]"
            notes = "Not enabled"
        elif errors:
            status = f"[yellow]{Icons.WARNING} Warn[/yellow]"
            notes = f"{len(errors)} errors"
        elif findings > 0:
            status = f"[yellow]{Icons.BUG}[/yellow]"
            notes = ""
        else:
            status = f"[green]{Icons.CHECK}[/green]"
            notes = "Clean"
        
        findings_text = str(findings) if enabled else "-"
        if findings > 0:
            findings_text = f"[yellow]{findings}[/yellow]"
        
        table.add_row(
            scanner.capitalize(),
            status,
            findings_text,
            notes,
        )
    
    console.print(table)


# ═══════════════════════════════════════════════════════════════════════════════
# HELP & DOCUMENTATION
# ═══════════════════════════════════════════════════════════════════════════════

def print_quick_help() -> None:
    """Print quick help tips."""
    tips = [
        f"{Icons.ARROW_RIGHT} Use [cyan]guardian scan --comprehensive[/cyan] for full analysis",
        f"{Icons.ARROW_RIGHT} Use [cyan]guardian analyze[/cyan] for ML + RAG + LLM analysis",
        f"{Icons.ARROW_RIGHT} Set [cyan]PATCH_LLM_PROVIDER=openai[/cyan] for AI patches",
        f"{Icons.ARROW_RIGHT} Use [cyan]--json[/cyan] for machine-readable output",
    ]
    
    panel = Panel(
        "\n".join(tips),
        title=f"{Icons.INFO} Quick Tips",
        title_align="left",
        border_style="dim",
        padding=(0, 1),
    )
    console.print(panel)


# ═══════════════════════════════════════════════════════════════════════════════
# COMPLETION MESSAGES
# ═══════════════════════════════════════════════════════════════════════════════

def print_scan_complete(
    total_findings: int,
    duration_ms: int = 0,
    report_path: str | None = None,
) -> None:
    """Print scan completion message."""
    if total_findings == 0:
        status = f"[green]{Icons.SHIELD} Scan complete - No issues found![/green]"
    else:
        status = f"[yellow]{Icons.WARNING} Scan complete - {total_findings} findings require attention[/yellow]"
    
    console.print()
    console.print(status)
    
    if duration_ms > 0:
        print_muted(f"  {Icons.CLOCK} Completed in {duration_ms}ms")
    
    if report_path:
        print_muted(f"  {Icons.FILE} Report saved to: {report_path}")


def print_analysis_complete(
    high_risk: int,
    patches: int,
) -> None:
    """Print analysis completion with recommendations."""
    console.print()
    
    if high_risk > 0:
        console.print(f"[bold red]{Icons.FIRE} {high_risk} high-risk findings require immediate attention[/bold red]")
        if patches > 0:
            console.print(f"[green]  {Icons.PATCH} {patches} patches available - review suggested fixes[/green]")
    elif patches > 0:
        console.print(f"[green]{Icons.CHECK} Analysis complete - {patches} patches ready for review[/green]")
    else:
        console.print(f"[green]{Icons.SHIELD} Analysis complete - codebase looks secure![/green]")
