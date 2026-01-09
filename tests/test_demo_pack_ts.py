"""Tests for TypeScript demo to ensure it doesn't rot."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


def _skip_if_no_npm() -> None:
    if shutil.which("npm") is None:
        pytest.skip("npm not available")


def _skip_unless_ts_demo_enabled() -> None:
    if os.environ.get("RUN_DEMO_TS_TESTS") != "1":
        pytest.skip("RUN_DEMO_TS_TESTS not set (TS demo tests are slow)")


def test_ts_demo_repo_exists() -> None:
    """Verify TypeScript demo repo structure exists."""
    demo_dir = Path("demo_pack/ts_demo/demo_repo")
    assert demo_dir.exists(), "TS demo repo missing"
    assert (demo_dir / "package.json").exists(), "package.json missing"
    assert (demo_dir / "tsconfig.json").exists(), "tsconfig.json missing"
    assert (demo_dir / "src" / "app.ts").exists(), "src/app.ts missing"
    assert (demo_dir / "tests" / "app.test.ts").exists(), "tests missing"


def test_ts_demo_report_exists() -> None:
    """Verify TypeScript demo scan report exists and is valid JSON."""
    report_path = Path("demo_pack/ts_demo/demo_report.json")
    assert report_path.exists(), "Demo report missing"
    report = json.loads(report_path.read_text())
    assert "semgrep" in report, "Semgrep section missing"
    results = report.get("semgrep", {}).get("results", [])
    assert len(results) >= 2, "Expected at least 2 findings"


def test_ts_demo_vulnerable_code() -> None:
    """Verify demo repo contains the expected vulnerabilities."""
    app_path = Path("demo_pack/ts_demo/demo_repo/src/app.ts")
    code = app_path.read_text()
    assert "innerHTML" in code, "innerHTML vulnerability not in demo code"
    assert "eval(" in code, "eval vulnerability not in demo code"


def test_ts_demo_package_json_valid() -> None:
    """Verify package.json is valid and has required scripts."""
    pkg_path = Path("demo_pack/ts_demo/demo_repo/package.json")
    pkg = json.loads(pkg_path.read_text())
    scripts = pkg.get("scripts", {})
    assert "build" in scripts, "build script missing"
    assert "test" in scripts, "test script missing"
    assert "lint" in scripts, "lint script missing"


@pytest.mark.slow
def test_ts_demo_npm_install(tmp_path: Path) -> None:
    """Test that npm install works for TS demo repo."""
    _skip_if_no_npm()
    _skip_unless_ts_demo_enabled()

    demo_repo = Path("demo_pack/ts_demo/demo_repo")
    work_dir = tmp_path / "repo"
    shutil.copytree(demo_repo, work_dir)

    result = subprocess.run(
        ["npm", "install"],
        cwd=work_dir,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"npm install failed: {result.stderr}"
    assert (work_dir / "node_modules").exists(), "node_modules not created"


@pytest.mark.slow
def test_ts_demo_tests_pass_after_patch(tmp_path: Path) -> None:
    """Test that TS demo tests pass after applying the expected fixes."""
    _skip_if_no_npm()
    _skip_unless_ts_demo_enabled()

    demo_repo = Path("demo_pack/ts_demo/demo_repo")
    work_dir = tmp_path / "repo"
    shutil.copytree(demo_repo, work_dir)

    # npm install
    subprocess.run(
        ["npm", "install"],
        cwd=work_dir,
        check=True,
        capture_output=True,
        timeout=120,
    )

    # Apply fixes
    app_path = work_dir / "src" / "app.ts"
    code = app_path.read_text()
    fixed_code = code.replace(".innerHTML =", ".textContent =")
    fixed_code = fixed_code.replace("return eval(jsonString)", "return JSON.parse(jsonString)")
    app_path.write_text(fixed_code)

    # Run tests
    result = subprocess.run(
        ["npm", "test"],
        cwd=work_dir,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"Tests failed: {result.stdout}\n{result.stderr}"
