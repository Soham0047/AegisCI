from pathlib import Path

from fastapi.testclient import TestClient

import backend.main as backend_main
from backend.dashboard import DashboardService
from backend.db import JobStore, PatchOutcomeStore


def test_outcomes_create_and_list(monkeypatch, tmp_path: Path) -> None:
    jobs_db = tmp_path / "jobs.db"
    outcomes_db = tmp_path / "outcomes.db"
    artifacts_root = tmp_path / "artifacts" / "jobs"

    store = JobStore(str(jobs_db))
    job_id = store.create_job("report-1")
    store.update_status(job_id, "completed")
    store.set_metadata(job_id, {"repo": "org/repo", "commit": "abc123"})

    job_dir = artifacts_root / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    (job_dir / "final.diff").write_text("--- a/app.py\n+++ b/app.py\n", encoding="utf-8")

    service = DashboardService(
        jobs_db_path=str(jobs_db),
        artifacts_root=artifacts_root,
        outcomes_db_path=str(outcomes_db),
    )
    monkeypatch.setattr(backend_main, "dashboard_service", service)
    monkeypatch.setattr(backend_main, "outcome_store", PatchOutcomeStore(str(outcomes_db)))
    client = TestClient(backend_main.app)

    resp = client.post(
        "/api/v1/outcomes",
        json={
            "job_id": job_id,
            "finding_id": "f-1",
            "candidate_id": "det-0",
            "action": "accepted",
            "notes": "looks good",
        },
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["diff_hash"]
    assert payload["repo"] == "org/repo"

    resp = client.get("/api/v1/outcomes?repo=org/repo")
    assert resp.status_code == 200
    listed = resp.json()
    assert listed
    assert listed[0]["finding_id"] == "f-1"
    assert listed[0]["action"] == "accepted"
