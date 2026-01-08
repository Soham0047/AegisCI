from patcher.ranker import Candidate, rank_candidates


def test_ranker_selects_smallest_valid_diff() -> None:
    candidates = [
        Candidate(
            candidate_id="llm-1",
            diff="--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-print('a')\n+print('b')\n",
            source="llm",
            diff_ok=True,
            validated=True,
            validation_status="validated",
        ),
        Candidate(
            candidate_id="llm-2",
            diff=(
                "--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,3 @@\n"
                "-print('a')\n+print('b')\n+print('c')\n"
            ),
            source="llm",
            diff_ok=True,
            validated=True,
            validation_status="validated",
        ),
    ]
    selected, report = rank_candidates(candidates)
    assert selected is not None
    assert selected.candidate_id == "llm-1"
    assert report["selected"] == "llm-1"


def test_ranker_never_selects_invalid() -> None:
    candidates = [
        Candidate(
            candidate_id="llm-1",
            diff="",
            source="llm",
            diff_ok=False,
            validated=False,
            validation_status="invalid",
        )
    ]
    selected, report = rank_candidates(candidates)
    assert selected is None
    assert report["selected"] is None


def test_ranker_prefers_deterministic() -> None:
    candidates = [
        Candidate(
            candidate_id="det-0",
            diff=("--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-print('a')\n+print('b')\n"),
            source="deterministic",
            diff_ok=True,
            validated=True,
            validation_status="validated",
        ),
        Candidate(
            candidate_id="llm-1",
            diff=("--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-print('a')\n+print('b')\n"),
            source="llm",
            diff_ok=True,
            validated=True,
            validation_status="validated",
        ),
    ]
    selected, _ = rank_candidates(candidates)
    assert selected is not None
    assert selected.candidate_id == "det-0"
