from typing import Any, Dict, List


def _summarize_bandit(bandit_json: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    results = bandit_json.get("results", []) or []
    for r in results[:20]:
        fname = r.get("filename", "unknown")
        line = r.get("line_number", "?")
        test_id = r.get("test_id", "B???")
        sev = r.get("issue_severity", "UNKNOWN")
        conf = r.get("issue_confidence", "UNKNOWN")
        text = (r.get("issue_text") or "").strip()
        lines.append(f"- **[Bandit {test_id}]** ({sev}/{conf}) `{fname}:{line}` — {text}")
    if len(results) > 20:
        lines.append(f"- ...and {len(results) - 20} more Bandit findings")
    return lines


def _summarize_semgrep(semgrep_json: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    results = semgrep_json.get("results", []) or []
    for r in results[:20]:
        check_id = r.get("check_id", "unknown")
        path = r.get("path") or "unknown"
        start = (r.get("start") or {}).get("line", "?")
        msg = ((r.get("extra") or {}).get("message") or "").strip()
        sev = (r.get("extra") or {}).get("severity", "INFO")
        lines.append(f"- **[Semgrep {check_id}]** ({sev}) `{path}:{start}` — {msg}")
    if len(results) > 20:
        lines.append(f"- ...and {len(results) - 20} more Semgrep findings")
    return lines


def build_markdown_report(
    base_ref: str,
    py_files: List[str],
    js_ts_files: List[str],
    bandit_json: Dict[str, Any],
    semgrep_json: Dict[str, Any],
) -> str:
    bandit_findings = bandit_json.get("results", []) or []
    semgrep_findings = semgrep_json.get("results", []) or []

    md: List[str] = []
    md.append("## 🔐 SecureDev Guardian Report")
    md.append(f"Base branch: `{base_ref}`")
    md.append("")
    md.append(f"**Python files scanned:** {len(py_files)}")
    md.append(f"**JS/TS files scanned:** {len(js_ts_files)}")
    md.append("")
    md.append("### Findings summary")
    md.append(f"- Bandit findings: **{len(bandit_findings)}**")
    md.append(f"- Semgrep findings: **{len(semgrep_findings)}**")
    md.append("")

    if not bandit_findings and not semgrep_findings:
        md.append("✅ No findings detected in changed Python/JS/TS files.")
        return "\n".join(md)

    if bandit_findings:
        md.append("### Python (Bandit)")
        md.extend(_summarize_bandit(bandit_json))
        md.append("")

    if semgrep_findings:
        md.append("### JS/TS (Semgrep)")
        md.extend(_summarize_semgrep(semgrep_json))
        md.append("")

    md.append("> Baseline scanner only. Next we’ll add: patch suggestions + test-validated fixes + DL scoring.")
    return "\n".join(md)
