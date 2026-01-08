from pathlib import Path

from backend.db import JobStore


def test_job_store_crud(tmp_path: Path) -> None:
    db_path = tmp_path / "jobs.db"
    store = JobStore(str(db_path))
    job_id = store.create_job("report-1")
    assert job_id

    store.update_status(job_id, "running")
    store.append_log(job_id, "started")
    store.set_metadata(job_id, {"key": "value"})

    job = store.get_job(job_id)
    assert job is not None
    assert job["status"] == "running"
    assert job["metadata"]["key"] == "value"
    assert any("started" in entry["line"] for entry in job["logs"])
