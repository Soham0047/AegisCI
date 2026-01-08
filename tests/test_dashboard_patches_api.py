import json
from pathlib import Path

from fastapi.testclient import TestClient

import backend.main as backend_main
from backend.dashboard import DashboardService
from backend.db import JobStore


def test_dashboard_patches_list_and_detail(monkeypatch, tmp_path: Path) -> None:
    jobs_db = tmp_path / "jobs.db"
    artifacts_root = tmp_path / "artifacts" / "jobs"
    store = JobStore(str(jobs_db))
    job_id = store.create_job("report-2")
    store.update_status(job_id, "completed")
    store.set_metadata(job_id, {"repo": "org/repo", "commit": "def456"})

    job_dir = artifacts_root / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "summary": {
            "total": 2,
            "validated": 1,
            "rejected": 1,
            "patched": 1,
            "avg_validation_time": 3.1,
        },
        "findings": [
            {
                "finding_id": "f-1",
                "rule_id": "B602",
                "filepath": "app/main.py",
                "start_line": 10,
                "end_line": 12,
                "status": "validated",
                "reason": None,
                "source": "deterministic",
            }
        ],
        "run_id": "run-1",
    }
    (job_dir / "patch_summary.json").write_text(json.dumps(summary), encoding="utf-8")
    (job_dir / "final.diff").write_text("--- a/app/main.py\n+++ b/app/main.py\n", encoding="utf-8")

    service = DashboardService(jobs_db_path=str(jobs_db), artifacts_root=artifacts_root)
    monkeypatch.setattr(backend_main, "dashboard_service", service)
    client = TestClient(backend_main.app)

    resp = client.get("/api/v1/dashboard/patches")
    assert resp.status_code == 200
    data = resp.json()
    assert data
    assert data[0]["validated_count"] == 1

    detail = client.get(f"/api/v1/dashboard/patches/{job_id}")
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["diff"]
