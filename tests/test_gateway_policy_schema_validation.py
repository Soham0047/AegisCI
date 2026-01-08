import json
from pathlib import Path

from gateway_test_utils import run_gateway_cli


def test_gateway_policy_schema_invalid(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("version: 2\ntools: []\n", encoding="utf-8")
    code, stdout, _ = run_gateway_cli(
        "validate-policy",
        {"policyPath": str(policy_path)},
        expect_ok=False,
    )
    assert code != 0
    payload = json.loads(stdout)
    assert payload["ok"] is False
    assert payload["errors"]


def test_gateway_policy_schema_valid() -> None:
    policy_path = str(Path("gateway/policy.yaml").resolve())
    code, stdout, _ = run_gateway_cli(
        "validate-policy",
        {"policyPath": policy_path},
    )
    assert code == 0
    payload = json.loads(stdout)
    assert payload["ok"] is True
