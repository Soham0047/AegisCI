from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guardian.findings import (
    UnifiedFinding,
    merge_findings,
    normalize_bandit_finding,
    normalize_ml_finding,
    normalize_semgrep_finding,
    severity_rank,
)


@dataclass
class ReportConfig:
    max_report_chars: int = 30000
    max_finding_chars: int = 2000
    max_excerpt_lines: int = 12
    max_excerpt_chars: int = 1200
    context_lines: int = 2


def _load_ml_results(ml_results: Any) -> list[dict[str, Any]]:
    if not ml_results:
        return []
    if isinstance(ml_results, list):
        return ml_results
    if isinstance(ml_results, dict):
        if "items" in ml_results and isinstance(ml_results["items"], list):
            return ml_results["items"]
        if "results" in ml_results and isinstance(ml_results["results"], list):
            return ml_results["results"]
        return [ml_results]
    path = Path(str(ml_results))
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    data = json.loads(text)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "items" in data and isinstance(data["items"], list):
            return data["items"]
        if "results" in data and isinstance(data["results"], list):
            return data["results"]
    return []


def _get_git_sha() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return "unknown"


def _summarize_counts(findings: list[UnifiedFinding]) -> tuple[dict[str, int], dict[str, int]]:
    severity_counts = {key: 0 for key in ["critical", "high", "medium", "low", "info"]}
    source_counts = {"tool": 0, "ml": 0, "hybrid": 0}
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        if finding.source == "hybrid":
            source_counts["hybrid"] += 1
        elif finding.source in {"bandit", "semgrep"}:
            source_counts["tool"] += 1
        else:
            source_counts["ml"] += 1
    return severity_counts, source_counts


def _format_confidence(value: float) -> str:
    return f"{value:.2f}"


def _render_finding(finding: UnifiedFinding, config: ReportConfig) -> str:
    loc = finding.location
    rule = finding.rule
    title = (
        f"[{finding.severity.upper()}] {rule.rule_id} — {rule.name} "
        f"(lines {loc.start_line}-{loc.end_line})"
    )
    lines: list[str] = [f"#### {title}"]
    lines.append(f"- Source: `{finding.source}`")
    lines.append(f"- Confidence: `{_format_confidence(finding.confidence)}`")
    lines.append(f"- Location: `{loc.filepath}:{loc.start_line}-{loc.end_line}`")
    if finding.evidence.excerpt:
        lines.append("Evidence:")
        lines.append(f"```{finding.evidence.excerpt_language}")
        lines.append(finding.evidence.excerpt)
        lines.append("```")
    lines.append("Why:")
    if finding.why.tool_message:
        lines.append(f"- Tool: {finding.why.tool_message}")
    if finding.why.ml:
        ml = finding.why.ml
        calibrated = "yes" if ml.calibrated else "no"
        ml_line = (
            f"- ML: model={ml.model} risk={ml.risk_score:.2f} "
            f"category={ml.category_pred} (conf={ml.category_confidence:.2f}) "
            f"calibrated={calibrated}"
        )
        if ml.ood:
            ml_line += f" ood={ml.ood}"
        lines.append(ml_line)
    lines.append(f"- Rationale: {finding.why.rationale}")

    block = "\n".join(lines)
    if len(block) > config.max_finding_chars:
        block = block[: config.max_finding_chars - 15].rstrip() + "...(truncated)"
    return block


def _group_findings(findings: list[UnifiedFinding]) -> dict[str, list[UnifiedFinding]]:
    grouped: dict[str, list[UnifiedFinding]] = {}
    for finding in findings:
        grouped.setdefault(finding.location.filepath, []).append(finding)
    for file_findings in grouped.values():
        file_findings.sort(
            key=lambda f: (-severity_rank(f.severity), f.location.start_line, f.rule.rule_id)
        )
    return dict(sorted(grouped.items(), key=lambda item: item[0]))


def render_markdown(
    findings: list[UnifiedFinding],
    meta: dict[str, Any],
    config: ReportConfig | None = None,
) -> tuple[str, dict[str, Any]]:
    config = config or ReportConfig()
    severity_counts, source_counts = _summarize_counts(findings)
    md: list[str] = []
    md.append("## 🔐 SecureDev Guardian Report")
    md.append(f"Base branch: `{meta.get('base_ref', 'unknown')}`")
    md.append("")
    md.append("### Summary")
    md.append(f"- Total findings: **{len(findings)}**")
    md.append(
        "- By severity: "
        + ", ".join(
            f"{k}={severity_counts.get(k, 0)}"
            for k in ["critical", "high", "medium", "low", "info"]
        )
    )
    md.append(
        "- By source: "
        + ", ".join(f"{k}={source_counts.get(k, 0)}" for k in ["tool", "ml", "hybrid"])
    )
    md.append("")

    grouped = _group_findings(findings)
    md.append("### Findings by file")
    if not findings:
        md.append("")
        md.append("✅ No findings detected in changed files.")
        meta["truncated"] = False
        return "\n".join(md).rstrip() + "\n", meta

    included = 0
    for filepath, file_findings in grouped.items():
        md.append(f"#### `{filepath}`")
        for finding in file_findings:
            block = _render_finding(finding, config)
            if len("\n".join(md)) + len(block) + 2 > config.max_report_chars:
                remaining = sum(len(v) for v in grouped.values()) - included
                if remaining > 0:
                    md.append("")
                    md.append(f"... {remaining} more findings omitted due to length cap.")
                meta["truncated"] = True
                return "\n".join(md), meta
            md.append(block)
            md.append("")
            included += 1

    meta["truncated"] = False
    return "\n".join(md).rstrip() + "\n", meta


def build_markdown_report(
    base_ref: str,
    py_files: list[str],
    js_ts_files: list[str],
    bandit_json: dict[str, Any],
    semgrep_json: dict[str, Any],
    ml_results: Any | None = None,
    repo_root: Path | None = None,
    config: ReportConfig | None = None,
) -> str:
    report_md, _ = build_pr_report(
        base_ref=base_ref,
        py_files=py_files,
        js_ts_files=js_ts_files,
        bandit_json=bandit_json,
        semgrep_json=semgrep_json,
        ml_results=ml_results,
        repo_root=repo_root,
        config=config,
    )
    return report_md


def build_pr_report(
    base_ref: str,
    py_files: list[str],
    js_ts_files: list[str],
    bandit_json: dict[str, Any],
    semgrep_json: dict[str, Any],
    ml_results: Any | None = None,
    repo_root: Path | None = None,
    config: ReportConfig | None = None,
) -> tuple[str, dict[str, Any]]:
    repo_root = repo_root or Path(".")
    config = config or ReportConfig()
    file_cache: dict[str, list[str]] = {}

    bandit_items = bandit_json.get("results", []) or []
    semgrep_items = semgrep_json.get("results", []) or []
    ml_items = _load_ml_results(ml_results)

    tool_findings = [
        normalize_bandit_finding(
            item,
            repo_root=repo_root,
            file_cache=file_cache,
            context_lines=config.context_lines,
            max_lines=config.max_excerpt_lines,
            max_chars=config.max_excerpt_chars,
        )
        for item in bandit_items
    ]
    tool_findings.extend(
        normalize_semgrep_finding(
            item,
            repo_root=repo_root,
            file_cache=file_cache,
            context_lines=config.context_lines,
            max_lines=config.max_excerpt_lines,
            max_chars=config.max_excerpt_chars,
        )
        for item in semgrep_items
    )

    ml_findings = []
    for item in ml_items:
        finding = normalize_ml_finding(
            item,
            repo_root=repo_root,
            file_cache=file_cache,
            context_lines=config.context_lines,
            max_lines=config.max_excerpt_lines,
            max_chars=config.max_excerpt_chars,
        )
        if finding is not None:
            ml_findings.append(finding)

    findings = merge_findings(tool_findings, ml_findings)
    generated_at = datetime.now(timezone.utc).isoformat()
    severity_counts, source_counts = _summarize_counts(findings)
    meta = {
        "base_ref": base_ref,
        "generated_at": generated_at,
        "git_sha": _get_git_sha(),
        "python_files_scanned": len(py_files),
        "js_ts_files_scanned": len(js_ts_files),
        "severity_counts": severity_counts,
        "source_counts": source_counts,
        "total_findings": len(findings),
    }
    report_md, meta = render_markdown(findings, meta, config=config)
    report_json = {
        "meta": meta,
        "findings": [finding.to_dict() for finding in findings],
    }
    return report_md, report_json
