from pathlib import Path

from patcher.orchestrator import ValidationResult, run_orchestrator


def test_orchestrator_selects_valid_candidate(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    path = repo / "app.py"
    path.write_text("import subprocess\nsubprocess.run(['ls'], shell=True)\n", encoding="utf-8")

    finding = {
        "finding_id": "app.py:2:B602",
        "rule": {"rule_id": "B602", "category": "B602", "name": "B602"},
        "location": {"filepath": "app.py", "start_line": 2, "end_line": 2},
        "source": "bandit",
    }

    def validator(repo_root: Path, commit: str, diff_path: Path) -> ValidationResult:
        return ValidationResult(ok=True, status="validated", report_path=None)

    result = run_orchestrator(
        repo_root=repo,
        commit="deadbeef",
        findings=[finding],
        candidates=2,
        rag_store_path=tmp_path / "rag.sqlite",
        validator=validator,
    )
    assert result["findings"][0]["selected"] in {"det-0", "llm-0", "llm-1"}
