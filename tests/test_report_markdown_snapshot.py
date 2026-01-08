import os
from pathlib import Path

from guardian.findings import Evidence, Location, MLWhy, RuleInfo, UnifiedFinding, WhyInfo
from guardian.report import ReportConfig, render_markdown


def _snapshot_path() -> Path:
    return Path("tests/snapshots/pr_report_example.md")


def _assert_snapshot(content: str) -> None:
    path = _snapshot_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if "UPDATE_SNAPSHOTS" in os.environ:
        path.write_text(content, encoding="utf-8")
    expected = path.read_text(encoding="utf-8")
    assert content == expected


def test_report_markdown_snapshot() -> None:
    findings = [
        UnifiedFinding(
            finding_id="f1",
            severity="high",
            confidence=0.9,
            source="hybrid",
            rule=RuleInfo(rule_id="B101", name="assert_used", category="B101"),
            location=Location(filepath="src/app.py", start_line=10, end_line=10),
            evidence=Evidence(
                excerpt=">> assert True",
                excerpt_language="python",
                highlight={"highlight_lines": [10]},
            ),
            why=WhyInfo(
                tool_message="Use of assert detected.",
                ml=MLWhy(
                    model="transformer_v3_final",
                    risk_score=0.9,
                    category_pred="injection.sql",
                    category_confidence=0.7,
                    calibrated=True,
                ),
                rationale="Tool finding supported by ML risk score.",
            ),
        ),
        UnifiedFinding(
            finding_id="f2",
            severity="medium",
            confidence=0.72,
            source="ml_ensemble",
            rule=RuleInfo(rule_id="injection.xss", name="injection.xss", category="injection.xss"),
            location=Location(filepath="src/service.ts", start_line=5, end_line=7),
            evidence=Evidence(
                excerpt=">> element.innerHTML = userInput",
                excerpt_language="ts",
                highlight={"highlight_lines": [5, 6, 7]},
            ),
            why=WhyInfo(
                tool_message=None,
                ml=MLWhy(
                    model="ensemble_v1",
                    risk_score=0.72,
                    category_pred="injection.xss",
                    category_confidence=0.68,
                    calibrated=True,
                ),
                rationale="Model flagged possible XSS pattern.",
            ),
        ),
        UnifiedFinding(
            finding_id="f3",
            severity="low",
            confidence=0.3,
            source="bandit",
            rule=RuleInfo(rule_id="B321", name="hardcoded_tmp", category="B321"),
            location=Location(filepath="src/utils.py", start_line=2, end_line=2),
            evidence=Evidence(
                excerpt=">> tempfile = '/tmp/data'",
                excerpt_language="python",
                highlight={"highlight_lines": [2]},
            ),
            why=WhyInfo(
                tool_message="Hardcoded temporary directory.",
                ml=None,
                rationale="Bandit flagged a risky temp path usage.",
            ),
        ),
    ]
    meta = {"base_ref": "main"}
    md, _ = render_markdown(findings, meta, config=ReportConfig())
    _assert_snapshot(md)
