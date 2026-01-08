import json

from gateway_test_utils import run_gateway_cli


def test_gateway_safe_output_blocks_dangerous() -> None:
    payload = {
        "output": "rm -rf /tmp/boom",
        "allow_code": False,
        "blocklist_patterns": [],
        "origin": "llm",
    }
    code, stdout, _ = run_gateway_cli("safe-output", payload)
    assert code == 0
    result = json.loads(stdout)
    assert result["output_tags"]["blocked"] is True
    assert result["output_tags"]["untrusted"] is True


def test_gateway_safe_output_allows_plain_text() -> None:
    payload = {"output": "all good", "allow_code": False, "origin": "tool"}
    code, stdout, _ = run_gateway_cli("safe-output", payload)
    assert code == 0
    result = json.loads(stdout)
    assert result["output_tags"]["blocked"] is False
    assert result["output_tags"]["trusted"] is True
