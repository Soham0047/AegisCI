from backend.rendering.pr_comment import render_pr_comment


def test_pr_update_flow_marker_consistent() -> None:
    pending = render_pr_comment(
        job_id="job-1",
        status="pending",
        summary={"total": 0, "patched": 0, "validated": 0, "rejected": 0},
        findings=[],
        diff_text=None,
    )
    final = render_pr_comment(
        job_id="job-1",
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
    )
    marker = "<!-- PATCH-COPILOT:job-1 -->"
    assert marker in pending
    assert marker in final
    assert "Validated patch" in final
    assert "Validated patch" not in pending
