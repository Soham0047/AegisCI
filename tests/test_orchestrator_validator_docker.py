import os
import shutil
import subprocess
from pathlib import Path

import pytest

from patcher.orchestrator import run_orchestrator


def _skip_if_no_docker() -> None:
    if os.environ.get("RUN_DOCKER_TESTS") != "1":
        pytest.skip("RUN_DOCKER_TESTS not set")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    try:
        result = subprocess.run(
            ["docker", "info"], capture_output=True, text=True, timeout=5, check=False
        )
    except Exception:
        pytest.skip("docker not accessible")
    if result.returncode != 0:
        pytest.skip("docker not accessible")


def _init_repo(repo: Path) -> str:
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    (repo / "requirements.txt").write_text("", encoding="utf-8")
    (repo / "app.py").write_text(
        "import subprocess\nsubprocess.run(['ls'], shell=True)\n", encoding="utf-8"
    )
    (repo / "tests").mkdir()
    (repo / "tests" / "test_ok.py").write_text("def test_ok():\n    assert True\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    return commit


def test_orchestrator_docker_validates(tmp_path: Path) -> None:
    _skip_if_no_docker()
    repo = tmp_path / "repo"
    repo.mkdir()
    commit = _init_repo(repo)

    finding = {
        "finding_id": "app.py:2:B602",
        "rule": {"rule_id": "B602", "category": "B602", "name": "B602"},
        "location": {"filepath": "app.py", "start_line": 2, "end_line": 2},
        "source": "bandit",
    }

    result = run_orchestrator(
        repo_root=repo,
        commit=commit,
        findings=[finding],
        candidates=1,
        rag_store_path=tmp_path / "rag.sqlite",
    )
    assert result["findings"][0]["selected"] is not None
