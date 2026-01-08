import json
from pathlib import Path

from gateway_test_utils import default_request, run_gateway_cli


def test_gateway_policy_unknown_tool_denied() -> None:
    policy_path = str(Path("gateway/policy.yaml").resolve())
    request = default_request(tool="unknown.tool")
    code, stdout, _ = run_gateway_cli("validate", {"request": request, "policyPath": policy_path})
    assert code == 0
    decision = json.loads(stdout)
    assert decision["decision"] == "deny"
    assert "allowlist" in decision["reason"]


def test_gateway_policy_scope_denied() -> None:
    policy_path = str(Path("gateway/policy.yaml").resolve())
    request = default_request(scope="write")
    code, stdout, _ = run_gateway_cli("validate", {"request": request, "policyPath": policy_path})
    assert code == 0
    decision = json.loads(stdout)
    assert decision["decision"] == "deny"
    assert "scope" in decision["reason"]


def test_gateway_policy_missing_args_denied() -> None:
    policy_path = str(Path("gateway/policy.yaml").resolve())
    request = default_request(args={})
    code, stdout, _ = run_gateway_cli("validate", {"request": request, "policyPath": policy_path})
    assert code == 0
    decision = json.loads(stdout)
    assert decision["decision"] == "deny"
    assert "args schema violation" in decision["reason"]


def test_gateway_policy_requires_approval() -> None:
    policy_path = str(Path("gateway/policy.yaml").resolve())
    request = default_request(
        tool="github.create_or_update_comment",
        scope="write",
        args={
            "repo": "org/repo",
            "pr_number": 1,
            "body": "hi",
            "token": "ghp_1234567890abcdef1234567890abcdef1234",
        },
    )
    code, stdout, _ = run_gateway_cli("validate", {"request": request, "policyPath": policy_path})
    assert code == 0
    decision = json.loads(stdout)
    assert decision["decision"] == "require_approval"


def test_gateway_policy_allow_with_approval() -> None:
    policy_path = str(Path("gateway/policy.yaml").resolve())
    request = default_request(
        tool="github.create_or_update_comment",
        scope="write",
        approved=True,
        args={"repo": "org/repo", "pr_number": 1, "body": "hi"},
    )
    code, stdout, _ = run_gateway_cli("validate", {"request": request, "policyPath": policy_path})
    assert code == 0
    decision = json.loads(stdout)
    assert decision["decision"] in {"allow", "mask"}
