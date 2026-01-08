import json
import shutil
import subprocess
from pathlib import Path

import pytest


def run_gateway_cli(command: str, payload: dict, expect_ok: bool = True) -> tuple[int, str, str]:
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available")
    tsx_module = Path("gateway/node_modules/tsx")
    if not tsx_module.exists():
        pytest.skip("tsx not installed in gateway")

    version = subprocess.run(
        [node, "--version"], capture_output=True, text=True, check=False
    ).stdout.strip()
    major = int(version.lstrip("v").split(".")[0] or 0)
    loader_flag = "--import" if major >= 20 else "--loader"
    result = subprocess.run(
        [node, loader_flag, "tsx", "scripts/gateway_cli.ts", command],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=Path("gateway"),
        check=False,
    )
    if expect_ok and result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    return result.returncode, result.stdout, result.stderr


def default_request(**overrides: object) -> dict:
    base = {
        "tool": "fs.read",
        "args": {"path": "README.md"},
        "caller": "tests",
        "correlation_id": "cid-1",
        "scope": "read",
    }
    base.update(overrides)
    return base
