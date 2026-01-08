from __future__ import annotations

import subprocess
from pathlib import Path

from patcher.diff import bundle_diffs, make_unified_diff


def test_unified_diff_applies_cleanly(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True, text=True)

    target = repo / "app.py"
    target.write_text("print('hello')\n", encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )

    old = target.read_text(encoding="utf-8")
    new = "print('hello')\nprint('world')\n"
    diff = make_unified_diff("app.py", old, new)
    diff_path = repo / "change.diff"
    diff_path.write_text(diff, encoding="utf-8")

    subprocess.run(["git", "apply", "--check", str(diff_path)], cwd=repo, check=True)
    subprocess.run(["git", "apply", str(diff_path)], cwd=repo, check=True)
    assert target.read_text(encoding="utf-8") == new


def test_bundle_diffs_orders_by_path() -> None:
    diff_a = make_unified_diff("a.txt", "a\n", "b\n")
    diff_b = make_unified_diff("b.txt", "x\n", "y\n")
    combined = bundle_diffs([diff_b, diff_a])
    assert combined.index("a.txt") < combined.index("b.txt")
