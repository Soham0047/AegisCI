from guardian.report import build_markdown_report


def test_build_markdown_report_includes_counts_and_sections() -> None:
    bandit_json = {
        "results": [
            {
                "filename": "src/app.py",
                "line_number": 10,
                "test_id": "B101",
                "issue_severity": "HIGH",
                "issue_confidence": "MEDIUM",
                "issue_text": "Use of assert detected.",
            }
        ]
    }
    semgrep_json = {
        "results": [
            {
                "check_id": "ts.no-eval",
                "path": "src/app.ts",
                "start": {"line": 5},
                "extra": {"message": "Avoid eval", "severity": "WARNING"},
            }
        ]
    }

    md = build_markdown_report("main", ["src/app.py"], ["src/app.ts"], bandit_json, semgrep_json)

    assert "SecureDev Guardian Report" in md
    assert "Base branch: `main`" in md
    assert "### Summary" in md
    assert "### Findings by file" in md
    assert "B101" in md
    assert "ts.no-eval" in md
