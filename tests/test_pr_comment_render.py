from backend.rendering.pr_comment import render_pr_comment


def test_pr_comment_pending_contains_marker() -> None:
    comment = render_pr_comment(
        job_id="job123",
        status="pending",
        summary={"total": 0, "patched": 0, "validated": 0, "rejected": 0},
        findings=[],
        diff_text=None,
        logs_path="artifacts/jobs/job123",
    )
    assert "<!-- PATCH-COPILOT:job123 -->" in comment
    assert "Work in progress" in comment


def test_pr_comment_completed_includes_diff() -> None:
    comment = render_pr_comment(
        job_id="job123",
        status="completed",
        summary={"total": 1, "patched": 1, "validated": 1, "rejected": 0},
        findings=[
            {
                "finding_id": "f1",
                "rule_id": "B602",
                "filepath": "app.py",
                "start_line": 2,
                "end_line": 2,
                "status": "validated",
            }
        ],
        diff_text="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-test\n+ok\n",
        logs_path="artifacts/jobs/job123",
    )
    assert "Validated patch" in comment
    assert "```diff" in comment
