from __future__ import annotations

from typing import Any

from patcher.llm_client import redact_text


def render_pr_comment(
    job_id: str,
    status: str,
    summary: dict[str, int],
    findings: list[dict[str, Any]],
    diff_text: str | None,
    logs_path: str | None = None,
    max_diff_lines: int = 200,
) -> str:
    marker = f"<!-- PATCH-COPILOT:{job_id} -->"
    lines: list[str] = [marker, "## Patch Copilot", f"Status: **{status}**", ""]
    lines.append(
        f"- Findings: **{summary.get('total', 0)}** | "
        f"Patched: **{summary.get('patched', 0)}** | "
        f"Validated: **{summary.get('validated', 0)}** | "
        f"Rejected: **{summary.get('rejected', 0)}**"
    )
    if logs_path:
        lines.append(f"- Logs: `{logs_path}`")
    lines.append("")

    lines.append("### Findings")
    for item in findings:
        status_text = item.get("status", "pending")
        reason = item.get("reason")
        reason_text = f" — {reason}" if reason else ""
        lines.append(
            f"- `{item.get('finding_id')}` {item.get('rule_id')} "
            f"{item.get('filepath')}:{item.get('start_line')}-{item.get('end_line')} "
            f"**{status_text}**{reason_text}"
        )

    if status == "pending":
        lines.append("")
        lines.append("_Work in progress. Results will update when validation completes._")
        return "\n".join(lines).rstrip() + "\n"

    if diff_text:
        redacted = redact_text(diff_text)
        diff_lines = redacted.splitlines()
        truncated = len(diff_lines) > max_diff_lines
        if truncated:
            diff_lines = diff_lines[:max_diff_lines]
            diff_lines.append("...diff truncated...")
        lines.append("")
        lines.append("<details><summary>Validated patch (click to expand)</summary>")
        lines.append("")
        lines.append("```diff")
        lines.extend(diff_lines)
        lines.append("```")
        lines.append("</details>")

    return "\n".join(lines).rstrip() + "\n"
