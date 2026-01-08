import json
from pathlib import Path

from fastapi.testclient import TestClient

import backend.main as backend_main
from backend.db import GatewayEventStore
from gateway_test_utils import default_request, run_gateway_cli


def test_gateway_end_to_end(monkeypatch, tmp_path: Path) -> None:
    store = GatewayEventStore(str(tmp_path / "events.db"))
    monkeypatch.setattr(backend_main, "gateway_store", store)
    client = TestClient(backend_main.app)

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
    _, stdout_repeat, _ = run_gateway_cli(
        "validate", {"request": request, "policyPath": policy_path}
    )
    decision_repeat = json.loads(stdout_repeat)
    assert decision["args_hash"] == decision_repeat["args_hash"]

    event = {
        "correlation_id": decision["correlation_id"],
        "tool": request["tool"],
        "args_hash": decision["args_hash"],
        "decision": decision["decision"],
        "reason": decision["reason"],
        "policy_rule_id": decision.get("policy_rule_id"),
        "caller": request["caller"],
        "timestamp": decision["timestamp"],
        "sanitized_args": decision["sanitized_args"],
    }
    response = client.post("/api/v1/gateway/events", json=event)
    assert response.status_code == 200
    stored = store.get_event(response.json()["id"])
    assert stored is not None
    assert stored["decision"] == "require_approval"
    assert "ghp_1234567890abcdef" not in json.dumps(stored["sanitized_args"])
