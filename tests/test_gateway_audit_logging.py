import json
from pathlib import Path

from backend.db import GatewayEventStore


def test_gateway_event_store_redacts(tmp_path: Path) -> None:
    store = GatewayEventStore(str(tmp_path / "events.db"))
    event = {
        "correlation_id": "cid-123",
        "tool": "github.create_or_update_comment",
        "args_hash": "abc123",
        "decision": "deny",
        "reason": "secret detected",
        "policy_rule_id": "github.create_or_update_comment",
        "caller": "tests",
        "sanitized_args": {"token": "ghp_1234567890abcdef1234567890abcdef1234"},
        "metadata": {"authorization": "Bearer abc.def.ghi"},
    }
    event_id = store.create_event(event)
    stored = store.get_event(event_id)
    assert stored is not None
    payload = json.dumps(stored)
    assert "ghp_1234567890abcdef" not in payload
    assert "Bearer abc.def.ghi" not in payload
