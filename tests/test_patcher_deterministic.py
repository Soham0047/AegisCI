from pathlib import Path

from patcher.patcher import generate_patches


def test_patcher_deterministic_output(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    path.write_text("import subprocess\nsubprocess.run(['ls'], shell=True)\n", encoding="utf-8")
    finding = {
        "finding_id": "app.py:2:B602",
        "rule": {"rule_id": "B602", "category": "B602", "name": "B602"},
        "location": {"filepath": "app.py", "start_line": 2, "end_line": 2},
        "source": "bandit",
    }

    first = generate_patches(tmp_path, [finding])
    second = generate_patches(tmp_path, [finding])
    assert first.combined_diff == second.combined_diff
