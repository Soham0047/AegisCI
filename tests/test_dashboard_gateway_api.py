from pathlib import Path

from fastapi.testclient import TestClient

import backend.main as backend_main
from backend.dashboard import DashboardService
from backend.db import GatewayEventStore


def test_dashboard_gateway_endpoints(monkeypatch, tmp_path: Path) -> None:
    events_db = tmp_path / "events.db"
    jobs_db = tmp_path / "jobs.db"
    GatewayEventStore(str(events_db)).create_event(
        {
            "correlation_id": "c1",
            "tool": "fs.read",
            "args_hash": "abc",
            "decision": "allow",
            "reason": "allowed",
            "caller": "tests",
            "metadata": {"repo": "org/repo"},
        }
    )
    GatewayEventStore(str(events_db)).create_event(
        {
            "correlation_id": "c2",
            "tool": "github.create_or_update_comment",
            "args_hash": "def",
            "decision": "deny",
            "reason": "secret detected",
            "caller": "tests",
            "metadata": {"repo": "org/repo"},
        }
    )

    service = DashboardService(
        jobs_db_path=str(jobs_db),
        artifacts_root=tmp_path / "artifacts",
        gateway_events_db_path=str(events_db),
    )
    monkeypatch.setattr(backend_main, "dashboard_service", service)
    client = TestClient(backend_main.app)

    events = client.get("/api/v1/dashboard/gateway/events")
    assert events.status_code == 200
    assert len(events.json()) == 2

    summary = client.get("/api/v1/dashboard/gateway/summary")
    assert summary.status_code == 200
    payload = summary.json()
    assert payload["blocked"] == 1
