from pathlib import Path

from fastapi.testclient import TestClient

import backend.main as backend_main
from backend.db import ConfigStore


def test_config_org_repo_endpoints(monkeypatch, tmp_path: Path) -> None:
    config_store = ConfigStore(str(tmp_path / "config.db"))
    monkeypatch.setattr(backend_main, "config_store", config_store)
    client = TestClient(backend_main.app)

    org_resp = client.put(
        "/api/v1/config/orgs/acme",
        json={"severity_threshold": "high", "tools_enabled": ["fs.read"]},
    )
    assert org_resp.status_code == 200

    repo_resp = client.put(
        "/api/v1/config/repos/acme/repo1",
        json={"patch_auto_suggest": True},
    )
    assert repo_resp.status_code == 200

    eff = client.get("/api/v1/config/repos/acme/repo1/effective")
    assert eff.status_code == 200
    payload = eff.json()
    assert payload["effective"]["severity_threshold"] == "high"
    assert payload["effective"]["patch_auto_suggest"] is True


def test_config_invalid_policy_override(monkeypatch, tmp_path: Path) -> None:
    config_store = ConfigStore(str(tmp_path / "config.db"))
    monkeypatch.setattr(backend_main, "config_store", config_store)
    client = TestClient(backend_main.app)

    resp = client.put(
        "/api/v1/config/orgs/acme",
        json={"policy_overrides": {"tools": [{"bad": "field"}]}},
    )
    assert resp.status_code == 400
