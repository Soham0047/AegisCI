import json
import subprocess
import sys
from pathlib import Path

from guardian.data.schema import Sample


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_build_dataset_e2e(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    repos_dir = tmp_path / "repos"
    out_dir = tmp_path / "datasets"
    repo_py = repos_dir / "repo_py"
    repo_ts = repos_dir / "repo_ts"
    repo_py.mkdir(parents=True)
    repo_ts.mkdir(parents=True)

    (repo_py / "app.py").write_text(
        "def foo():\n    return 1\n",
        encoding="utf-8",
    )
    (repo_ts / "app.ts").write_text(
        "function bar() { return 2; }\n",
        encoding="utf-8",
    )

    cmd = [
        sys.executable,
        "scripts/build_dataset.py",
        "--repos-dir",
        str(repos_dir),
        "--out-dir",
        str(out_dir),
        "--languages",
        "python,ts",
        "--context-lines",
        "1",
        "--seed",
        "1337",
        "--split",
        "0.8,0.1,0.1",
        "--commit-mode",
        "workdir",
        "--validate",
    ]
    subprocess.run(cmd, cwd=repo_root, check=True)
    first_outputs = {
        path: path.read_text(encoding="utf-8")
        for path in out_dir.rglob("*.jsonl")
        if path.name != "all.jsonl"
    }

    subprocess.run(cmd, cwd=repo_root, check=True)
    second_outputs = {
        path: path.read_text(encoding="utf-8")
        for path in out_dir.rglob("*.jsonl")
        if path.name != "all.jsonl"
    }

    assert first_outputs == second_outputs

    for lang in ("python", "ts"):
        for split_name in ("train", "val", "test"):
            path = out_dir / lang / f"{split_name}.jsonl"
            assert path.exists()
            for sample in _read_jsonl(path):
                Sample.model_validate(sample)
