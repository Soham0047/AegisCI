from guardian.findings import Evidence, Location, RuleInfo, UnifiedFinding, WhyInfo
from guardian.report import ReportConfig, render_markdown


def _make_finding(filepath: str, severity: str, line: int, rule_id: str) -> UnifiedFinding:
    return UnifiedFinding(
        finding_id=f"{filepath}-{rule_id}",
        severity=severity,
        confidence=0.5,
        source="bandit",
        rule=RuleInfo(rule_id=rule_id, name=rule_id, category=rule_id),
        location=Location(filepath=filepath, start_line=line, end_line=line),
        evidence=Evidence(excerpt=">> risky()", excerpt_language="python"),
        why=WhyInfo(tool_message="Issue", ml=None, rationale="x" * 400),
    )


def test_report_caps_and_grouping() -> None:
    findings = [
        _make_finding("b/file.py", "low", 20, "BLOW"),
        _make_finding("a/file.py", "high", 5, "BHIGH"),
        _make_finding("a/file.py", "medium", 10, "BMED"),
        _make_finding("c/file.py", "low", 1, "B1"),
    ]
    config = ReportConfig(max_report_chars=900, max_finding_chars=180)
    md, meta = render_markdown(findings, {"base_ref": "main"}, config=config)

    assert "...(truncated)" in md
    assert "more findings omitted due to length cap" in md
    assert meta.get("truncated") is True

    file_order = [line for line in md.splitlines() if line.startswith("#### `")]
    assert file_order[0].endswith("`a/file.py`")
    assert file_order[1].endswith("`b/file.py`")
