import json
from pathlib import Path

from fastapi.testclient import TestClient

import backend.main as backend_main
from backend.dashboard import DashboardService
from backend.db import JobStore


def _write_report(artifacts_root: Path, job_id: str, findings: list[dict]) -> None:
    job_dir = artifacts_root / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    report = {"findings": findings}
    (job_dir / "unified_report.json").write_text(json.dumps(report), encoding="utf-8")


def test_dashboard_reports_list_and_detail(monkeypatch, tmp_path: Path) -> None:
    jobs_db = tmp_path / "jobs.db"
    artifacts_root = tmp_path / "artifacts" / "jobs"
    store = JobStore(str(jobs_db))
    job_id = store.create_job("report-1")
    store.update_status(job_id, "running")
    store.set_metadata(job_id, {"repo": "org/repo", "commit": "abc123"})

    findings = [
        {
            "finding_id": "f-1",
            "severity": "high",
            "source": "bandit",
            "rule": {"rule_id": "B602", "category": "unsafe.exec"},
            "location": {"filepath": "app/main.py", "start_line": 10, "end_line": 12},
            "confidence": 0.7,
            "why": {"tool_message": "shell=True"},
            "evidence": {"excerpt": ">> subprocess.run([...], shell=True)"},
        },
        {
            "finding_id": "f-2",
            "severity": "low",
            "source": "semgrep",
            "rule": {"rule_id": "SG001", "category": "misc.other"},
            "location": {"filepath": "app/utils.py", "start_line": 3, "end_line": 3},
            "confidence": 0.4,
            "why": {"tool_message": "noop"},
            "evidence": {"excerpt": ">> print('hi')"},
        },
    ]
    _write_report(artifacts_root, job_id, findings)

    service = DashboardService(jobs_db_path=str(jobs_db), artifacts_root=artifacts_root)
    monkeypatch.setattr(backend_main, "dashboard_service", service)
    client = TestClient(backend_main.app)

    resp = client.get("/api/v1/dashboard/reports")
    assert resp.status_code == 200
    data = resp.json()
    assert data
    assert data[0]["repo"] == "org/repo"
    assert data[0]["high_critical"] == 1

    detail = client.get(f"/api/v1/dashboard/reports/{job_id}")
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["summary"]["total"] == 2
    assert payload["files"]
