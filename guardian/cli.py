import json
from pathlib import Path
from typing import List

import typer
from rich import print

from guardian.git_utils import get_changed_files
from guardian.report import build_markdown_report
from guardian.scanners.bandit_scanner import run_bandit
from guardian.scanners.semgrep_scanner import run_semgrep

app = typer.Typer(help="SecureDev Guardian CLI (baseline)")


def _filter_files(files: List[str]) -> tuple[list[str], list[str]]:
    py = [f for f in files if f.endswith(".py")]
    js_ts = [f for f in files if f.endswith((".js", ".ts", ".tsx"))]
    return py, js_ts


@app.command()
def scan(
    base_ref: str = typer.Option(..., help="Base branch name (e.g., main)"),
    semgrep_config: str = typer.Option("p/ci", help="Semgrep registry config (e.g., p/ci)"),
    out_md: str = typer.Option("report.md", help="Markdown report output path"),
    out_json: str = typer.Option("report.json", help="Raw JSON output path"),
) -> None:
    """Scan changed files vs origin/<base_ref> and write a report."""
    changed = get_changed_files(base_ref)
    py_files, js_ts_files = _filter_files(changed)

    print(f"[bold]Changed files:[/bold] {len(changed)}")
    print(f"[bold]Python:[/bold] {len(py_files)} | [bold]JS/TS:[/bold] {len(js_ts_files)}")

    bandit_json = run_bandit(py_files)
    semgrep_json = run_semgrep(js_ts_files, config=semgrep_config)

    report_md = build_markdown_report(base_ref, py_files, js_ts_files, bandit_json, semgrep_json)

    Path(out_md).write_text(report_md, encoding="utf-8")
    Path(out_json).write_text(
        json.dumps({"bandit": bandit_json, "semgrep": semgrep_json}, indent=2),
        encoding="utf-8",
    )

    print(f"[green]Wrote:[/green] {out_md} and {out_json}")


if __name__ == "__main__":
    app()
