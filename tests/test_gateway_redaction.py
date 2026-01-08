import json

from gateway_test_utils import run_gateway_cli


def test_gateway_redaction_masks_tokens() -> None:
    payload = {
        "token": "ghp_1234567890abcdef1234567890abcdef1234",
        "nested": {"authorization": "Bearer abc.def.ghi"},
    }
    code, stdout, _ = run_gateway_cli("redact", payload)
    assert code == 0
    result = json.loads(stdout)
    sanitized = result["sanitized"]
    assert "ghp_" in sanitized["token"]
    assert "***" in sanitized["token"]
    assert "***" in sanitized["nested"]["authorization"]
    assert result["findings"]
