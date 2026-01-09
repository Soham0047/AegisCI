from pathlib import Path

from patcher.dl.patch_ranker_model import PatchRankerModel, load_ranker, save_ranker
from patcher.ranker import Candidate, rank_candidates


def test_patch_ranker_selects_smaller_diff(tmp_path: Path, monkeypatch) -> None:
    out_dir = tmp_path / "dl"
    model = PatchRankerModel(input_dim=8, hidden_dim=1)
    # Focus on lines_changed feature (index 0).
    model.net[0].weight.data.zero_()
    model.net[0].bias.data.zero_()
    model.net[0].weight.data[0, 0] = 1.0
    model.net[2].weight.data.fill_(-1.0)
    model.net[2].bias.data.zero_()
    save_ranker(
        model,
        out_dir,
        [
            "lines_changed",
            "files_changed",
            "hunks",
            "diff_chars",
            "source_is_deterministic",
            "validated",
            "lint_errors",
            "test_failures",
        ],
    )

    monkeypatch.setenv("DL_ARTIFACTS_DIR", str(out_dir))
    load_ranker.cache_clear()

    small = Candidate(
        candidate_id="det-0",
        diff="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-print('x')\n+print('y')\n",
        source="deterministic",
        diff_ok=True,
        validated=True,
        validation_status="validated",
    )
    large = Candidate(
        candidate_id="llm-0",
        diff="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-print('x')\n+print('y')\n+print('z')\n",
        source="llm",
        diff_ok=True,
        validated=True,
        validation_status="validated",
    )
    selected, report = rank_candidates([small, large])
    assert selected is not None
    assert selected.candidate_id == "det-0"
    assert report["selected"] == "det-0"
