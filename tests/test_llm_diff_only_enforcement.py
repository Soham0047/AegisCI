from patcher.llm_client import enforce_diff_only


def test_diff_only_accepts_unified_diff() -> None:
    diff = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-print('a')\n+print('b')\n"
    ok, reason = enforce_diff_only(diff)
    assert ok is True
    assert reason is None


def test_diff_only_rejects_fenced_output() -> None:
    text = "```diff\n--- a/app.py\n+++ b/app.py\n```\n"
    ok, reason = enforce_diff_only(text)
    assert ok is False
    assert reason == "contains code fence"


def test_diff_only_rejects_prose() -> None:
    text = "Explanation: apply the following diff"
    ok, reason = enforce_diff_only(text)
    assert ok is False
    assert reason == "contains prose"
