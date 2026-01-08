import json
from pathlib import Path
from typing import Any
from urllib import request as urllib_request

try:
    import requests
except Exception:  # pragma: no cover - optional dependency
    requests = None


def send_event(
    event: dict[str, Any],
    base_url: str = "http://localhost:8000",
    token: str | None = None,
    dry_run: bool = False,
    out_path: str | None = None,
) -> dict[str, Any]:
    sanitized = _redact_event(event)
    if dry_run:
        path = Path(out_path or "artifacts/gateway_events/dry_run.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(sanitized, indent=2), encoding="utf-8")
        return {"dry_run": True, "path": str(path), "payload": sanitized}

    url = f"{base_url.rstrip('/')}/api/v1/gateway/events"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if requests:
        response = requests.post(url, json=sanitized, headers=headers, timeout=10)
        return {"status_code": response.status_code, "body": response.json()}
    data = json.dumps(sanitized).encode("utf-8")
    req = urllib_request.Request(url, data=data, headers=headers, method="POST")
    with urllib_request.urlopen(req, timeout=10) as resp:
        return {"status_code": resp.status, "body": json.loads(resp.read().decode("utf-8"))}


def _redact_event(event: dict[str, Any]) -> dict[str, Any]:
    def mask(value: str) -> str:
        if len(value) < 8:
            return "***REDACTED***"
        return f"{value[:4]}***{value[-4:]}"

    redacted: dict[str, Any] = {}
    for key, value in event.items():
        if isinstance(value, str) and _is_sensitive_key(key):
            redacted[key] = mask(value)
            continue
        if isinstance(value, dict):
            redacted[key] = _redact_event(value)
            continue
        redacted[key] = value
    return redacted


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(token in lowered for token in ("token", "secret", "authorization", "apikey"))
