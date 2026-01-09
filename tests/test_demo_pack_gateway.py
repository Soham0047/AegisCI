"""Tests for Agent Gateway demo to ensure it doesn't rot."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest


def _skip_if_no_npm() -> None:
    if shutil.which("npm") is None:
        pytest.skip("npm not available")


def _skip_if_gateway_not_built() -> None:
    # Check for compiled source files (not scripts which are separate)
    gateway_dist = Path("gateway/dist/validator.js")
    if not gateway_dist.exists():
        pytest.skip("Gateway not built (run npm install && npm run build in gateway/)")


def _get_gateway_cli() -> list[str]:
    """Get the command to run the gateway CLI."""
    # The CLI is in scripts folder, run via ts-node or npx tsx
    cli_ts = Path("gateway/scripts/gateway_cli.ts").resolve()
    if not cli_ts.exists():
        pytest.skip("Gateway CLI script not found")
    # Use npx tsx to run TypeScript directly
    return ["npx", "--yes", "tsx", str(cli_ts)]


def test_gateway_demo_inputs_exist() -> None:
    """Verify gateway demo input files exist."""
    demo_dir = Path("demo_pack/agent_gateway_demo/demo_inputs")
    assert demo_dir.exists(), "Demo inputs dir missing"
    assert (demo_dir / "allowed_request.json").exists(), "allowed_request.json missing"
    assert (demo_dir / "blocked_request.json").exists(), "blocked_request.json missing"
    assert (demo_dir / "secret_input.json").exists(), "secret_input.json missing"


def test_gateway_demo_inputs_valid_json() -> None:
    """Verify demo inputs are valid JSON."""
    demo_dir = Path("demo_pack/agent_gateway_demo/demo_inputs")

    allowed = json.loads((demo_dir / "allowed_request.json").read_text())
    assert "request" in allowed
    assert allowed["request"]["tool"] == "fs.read"

    blocked = json.loads((demo_dir / "blocked_request.json").read_text())
    assert "request" in blocked
    assert blocked["request"]["tool"] == "shell.exec"

    secrets = json.loads((demo_dir / "secret_input.json").read_text())
    assert "api_key" in secrets


def test_gateway_policy_exists() -> None:
    """Verify gateway policy.yaml exists and has expected tools."""
    policy_path = Path("gateway/policy.yaml")
    assert policy_path.exists(), "policy.yaml missing"
    content = policy_path.read_text()
    assert "fs.read" in content, "fs.read not in policy"
    assert "allowed: true" in content, "allowed: true not in policy"


def test_gateway_validate_allowed(tmp_path: Path) -> None:
    """Test that gateway allows fs.read tool call."""
    _skip_if_no_npm()
    _skip_if_gateway_not_built()

    demo_input = Path("demo_pack/agent_gateway_demo/demo_inputs/allowed_request.json")
    gateway_cmd = _get_gateway_cli()

    result = subprocess.run(
        gateway_cmd + ["validate"],
        stdin=open(demo_input),
        capture_output=True,
        text=True,
        timeout=30,
        cwd=Path("gateway"),
    )

    assert result.returncode == 0, f"Gateway CLI failed: {result.stderr}"
    decision = json.loads(result.stdout)
    assert decision.get("decision") == "allow", f"Expected decision=allow, got: {decision}"


def test_gateway_validate_blocked(tmp_path: Path) -> None:
    """Test that gateway blocks shell.exec tool call."""
    _skip_if_no_npm()
    _skip_if_gateway_not_built()

    demo_input = Path("demo_pack/agent_gateway_demo/demo_inputs/blocked_request.json")
    gateway_cmd = _get_gateway_cli()

    result = subprocess.run(
        gateway_cmd + ["validate"],
        stdin=open(demo_input),
        capture_output=True,
        text=True,
        timeout=30,
        cwd=Path("gateway"),
    )

    assert result.returncode == 0, f"Gateway CLI failed: {result.stderr}"
    decision = json.loads(result.stdout)
    assert decision.get("decision") == "deny", f"Expected decision=deny, got: {decision}"
    assert "reason" in decision, "Missing reason for denial"


def test_gateway_redact_secrets(tmp_path: Path) -> None:
    """Test that gateway redacts secrets from input."""
    _skip_if_no_npm()
    _skip_if_gateway_not_built()

    demo_input = Path("demo_pack/agent_gateway_demo/demo_inputs/secret_input.json")
    gateway_cmd = _get_gateway_cli()

    result = subprocess.run(
        gateway_cmd + ["redact"],
        stdin=open(demo_input),
        capture_output=True,
        text=True,
        timeout=30,
        cwd=Path("gateway"),
    )

    assert result.returncode == 0, f"Gateway CLI failed: {result.stderr}"
    redacted = json.loads(result.stdout)

    # Check that secrets are masked
    api_key = redacted.get("api_key", "")
    assert (
        "ghp_" not in api_key or "[REDACTED" in api_key or "***" in api_key
    ), f"API key not redacted: {api_key}"
