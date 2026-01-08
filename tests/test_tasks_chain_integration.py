from pathlib import Path

from backend.celery_app import celery_app
from backend.db import JobStore
from backend.tasks import start_scan_pipeline


def test_tasks_chain_integration(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import subprocess\nsubprocess.run(['ls'], shell=True)\n", encoding="utf-8"
    )

    monkeypatch.setenv("PATCH_VALIDATOR_MODE", "mock")
    monkeypatch.setenv("GITHUB_DRY_RUN", "1")

    celery_app.conf.task_always_eager = True
    celery_app.conf.broker_url = "memory://"
    celery_app.conf.result_backend = "cache+memory://"

    report_path = Path("backend/demo_report_fixture.json")
    job_id = start_scan_pipeline(
        report_path=str(report_path),
        repo_root=str(repo),
        commit="deadbeef",
        pr_info={"repo": "org/repo", "pr_number": 1, "token": "SECRET"},
        dry_run=True,
        report_id="demo",
    )

    store = JobStore()
    job = store.get_job(job_id)
    assert job is not None
    assert job["status"] == "completed"

    final_diff = Path("artifacts/jobs") / job_id / "final.diff"
    assert final_diff.exists()
    diff_text = final_diff.read_text(encoding="utf-8")
    assert "-subprocess.run(['ls'], shell=True)" in diff_text
    assert "+subprocess.run(['ls'])" in diff_text

    dry_run_path = Path("artifacts/jobs") / job_id / "github_dry_run.json"
    assert dry_run_path.exists()
