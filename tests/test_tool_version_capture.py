import json
import subprocess
from pathlib import Path

from guardian.data.weak_labeling import write_tool_outputs_for_repo


def test_tool_version_capture(monkeypatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "app.py").write_text("def foo():\n    return 1\n", encoding="utf-8")
    (repo_root / "app.ts").write_text("function bar() { return 2; }\n", encoding="utf-8")

    def fake_run(cmd, check, capture_output, text):
        if cmd[:2] == ["bandit", "--version"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="bandit 1.2.3\n", stderr="")
        if cmd[:2] == ["semgrep", "--version"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="1.88.0\n", stderr="")
        if cmd and cmd[0] == "bandit":
            return subprocess.CompletedProcess(cmd, 0, stdout='{"results": []}', stderr="")
        if cmd and cmd[0] == "semgrep":
            return subprocess.CompletedProcess(cmd, 0, stdout='{"results": []}', stderr="")
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr("guardian.data.weak_labeling.subprocess.run", fake_run)

    out_dir = tmp_path / "tool_outputs"
    meta = write_tool_outputs_for_repo(
        repo_root=repo_root,
        out_dir=out_dir,
        bandit_args=["-q", "-f", "json"],
        semgrep_args=["--json"],
        semgrep_config="p/ci",
        max_files=None,
        reuse=False,
    )

    meta_path = out_dir / repo_root.name / "meta.json"
    stored = json.loads(meta_path.read_text(encoding="utf-8"))

    assert meta["bandit"]["version"] == "1.2.3"
    assert meta["semgrep"]["version"] == "1.88.0"
    assert stored["bandit"]["args"] == ["-q", "-f", "json"]
    assert stored["semgrep"]["config"] == "p/ci"
