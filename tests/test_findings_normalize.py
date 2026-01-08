import json
from pathlib import Path

from guardian.findings import (
    normalize_bandit_finding,
    normalize_ml_finding,
    normalize_semgrep_finding,
)


def test_bandit_normalize_redacts_excerpt(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    app = src / "app.py"
    app.write_text('token = "AKIA1234567890ABCDEF"\nassert True\n', encoding="utf-8")

    finding = normalize_bandit_finding(
        {
            "filename": str(app),
            "line_number": 2,
            "test_id": "B101",
            "issue_severity": "HIGH",
            "issue_confidence": "MEDIUM",
            "issue_text": "Use of assert detected.",
            "issue_name": "assert_used",
        },
        repo_root=tmp_path,
    )

    assert finding.severity == "high"
    assert 0.0 <= finding.confidence <= 1.0
    assert "AKIA" not in finding.evidence.excerpt
    assert "[REDACTED]" in finding.evidence.excerpt


def test_semgrep_normalize_severity_confidence(tmp_path: Path) -> None:
    app = tmp_path / "app.js"
    app.write_text("eval(userInput)\n", encoding="utf-8")

    finding = normalize_semgrep_finding(
        {
            "check_id": "js.eval",
            "path": str(app),
            "start": {"line": 1},
            "end": {"line": 1},
            "extra": {"message": "Avoid eval", "severity": "WARNING"},
        },
        repo_root=tmp_path,
    )

    assert finding.severity == "medium"
    assert 0.0 <= finding.confidence <= 1.0
    assert finding.finding_id


def test_ml_normalize_deterministic_id(tmp_path: Path) -> None:
    app = tmp_path / "app.py"
    app.write_text("def foo():\n    pass\n", encoding="utf-8")
    payload = {
        "filepath": str(app),
        "span": {"start_line": 1, "end_line": 1},
        "risk_score": 0.9,
        "top_categories": [{"category": "injection.sql", "confidence": 0.8}],
    }
    first = normalize_ml_finding(payload, repo_root=tmp_path)
    second = normalize_ml_finding(payload, repo_root=tmp_path)
    assert first is not None
    assert second is not None
    assert first.finding_id == second.finding_id


def test_normalize_from_fixtures(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "web").mkdir()
    (tmp_path / "src" / "app.py").write_text("assert True\n", encoding="utf-8")
    (tmp_path / "web" / "app.js").write_text("eval(userInput)\n", encoding="utf-8")

    bandit = json.loads(Path("tests/fixtures/bandit_sample.json").read_text())
    semgrep = json.loads(Path("tests/fixtures/semgrep_sample.json").read_text())

    bandit_finding = normalize_bandit_finding(bandit["results"][0], repo_root=tmp_path)
    semgrep_finding = normalize_semgrep_finding(semgrep["results"][0], repo_root=tmp_path)

    assert bandit_finding.location.filepath == "src/app.py"
    assert semgrep_finding.location.filepath == "web/app.js"
