"""Tests for Python demo to ensure it doesn't rot."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest


def _skip_if_no_venv() -> None:
    if not Path(".venv").exists():
        pytest.skip("No .venv found")


def test_python_demo_repo_exists() -> None:
    """Verify Python demo repo structure exists."""
    demo_dir = Path("demo_pack/python_demo/demo_repo")
    assert demo_dir.exists(), "Python demo repo missing"
    assert (demo_dir / "app.py").exists(), "app.py missing"
    assert (demo_dir / "tests" / "test_app.py").exists(), "tests missing"
    assert (demo_dir / "requirements.txt").exists(), "requirements.txt missing"


def test_python_demo_report_exists() -> None:
    """Verify Python demo scan report exists and is valid JSON."""
    report_path = Path("demo_pack/python_demo/demo_report.json")
    assert report_path.exists(), "Demo report missing"
    report = json.loads(report_path.read_text())
    assert "bandit" in report, "Bandit section missing"
    results = report.get("bandit", {}).get("results", [])
    assert len(results) > 0, "No findings in report"
    assert results[0].get("test_id") == "B602", "Expected B602 finding"


def test_python_demo_vulnerable_code() -> None:
    """Verify demo repo contains the expected vulnerability."""
    app_path = Path("demo_pack/python_demo/demo_repo/app.py")
    code = app_path.read_text()
    assert "shell=True" in code, "Vulnerability (shell=True) not in demo code"
    assert "subprocess" in code, "subprocess not in demo code"


def test_python_demo_orchestrator_runs(tmp_path: Path) -> None:
    """Test that orchestrator can process the Python demo finding."""
    _skip_if_no_venv()

    # Copy demo repo to temp
    demo_repo = Path("demo_pack/python_demo/demo_repo")
    work_dir = tmp_path / "repo"
    shutil.copytree(demo_repo, work_dir)

    # Init git
    subprocess.run(["git", "init"], cwd=work_dir, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=work_dir,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=work_dir,
        check=True,
        capture_output=True,
    )
    subprocess.run(["git", "add", "."], cwd=work_dir, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=work_dir,
        check=True,
        capture_output=True,
    )
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=work_dir, text=True).strip()

    # Run orchestrator
    from patcher.orchestrator import run_orchestrator

    finding = {
        "finding_id": "app.py:8:B602",
        "rule": {"rule_id": "B602", "category": "B602", "name": "B602"},
        "location": {"filepath": "app.py", "start_line": 8, "end_line": 8},
        "source": "bandit",
    }

    result = run_orchestrator(
        repo_root=work_dir,
        commit=commit,
        findings=[finding],
        candidates=0,  # Deterministic only
        rag_store_path=tmp_path / "rag.sqlite",
    )

    assert "findings" in result
    assert len(result["findings"]) == 1

    # Check if we got a selected patch (may or may not depending on template match)
    finding_result = result["findings"][0]
    # The test passes if orchestrator ran without error
    assert "finding_id" in finding_result


def test_python_demo_tests_pass_after_manual_patch(tmp_path: Path) -> None:
    """Test that demo tests pass after applying the expected fix."""
    demo_repo = Path("demo_pack/python_demo/demo_repo")
    work_dir = tmp_path / "repo"
    shutil.copytree(demo_repo, work_dir)

    # Manually apply the expected fix
    app_path = work_dir / "app.py"
    code = app_path.read_text()
    # Simple fix: replace shell=True pattern
    fixed_code = code.replace(
        'subprocess.run(f"ls {directory}", shell=True,',
        'subprocess.run(["ls", directory], shell=False,',
    )
    app_path.write_text(fixed_code)

    # Run tests
    result = subprocess.run(
        ["python", "-m", "pytest", "tests/", "-v"],
        cwd=work_dir,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Tests failed: {result.stdout}\n{result.stderr}"
