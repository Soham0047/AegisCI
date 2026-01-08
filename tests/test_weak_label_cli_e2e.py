import json
import subprocess
import sys
from pathlib import Path

from guardian.data.schema import Sample, make_sample_id


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")


def test_weak_label_cli_e2e(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    repos_dir = tmp_path / "repos"
    datasets_dir = tmp_path / "datasets"
    tool_outputs = tmp_path / "tool_outputs"

    repo = repos_dir / "repo1"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text("def foo():\n    return 1\n", encoding="utf-8")
    (repo / "app.ts").write_text("function bar() { return 2; }\n", encoding="utf-8")

    py_sample = {
        "sample_id": make_sample_id("python", "local/repo1", "WORKDIR", "app.py", 1, 2),
        "language": "python",
        "repo": "local/repo1",
        "commit": "WORKDIR",
        "filepath": "app.py",
        "code_snippet": "def foo():\n    return 1",
        "function_span": {"start_line": 1, "end_line": 2, "start_col": 0, "end_col": 0},
        "context_before": "",
        "context_after": "",
        "weak_labels": [],
        "gold_labels": None,
        "metadata": {
            "file_ext": ".py",
            "n_lines": 2,
            "cyclomatic_complexity": 1,
            "dependencies": {"python": [], "npm": []},
            "tool_versions": {},
        },
    }
    ts_sample = {
        "sample_id": make_sample_id("ts", "local/repo1", "WORKDIR", "app.ts", 1, 1),
        "language": "ts",
        "repo": "local/repo1",
        "commit": "WORKDIR",
        "filepath": "app.ts",
        "code_snippet": "function bar() { return 2; }",
        "function_span": {"start_line": 1, "end_line": 1, "start_col": 0, "end_col": 0},
        "context_before": "",
        "context_after": "",
        "weak_labels": [],
        "gold_labels": None,
        "metadata": {
            "file_ext": ".ts",
            "n_lines": 1,
            "cyclomatic_complexity": None,
            "dependencies": {"python": [], "npm": []},
            "tool_versions": {},
        },
    }

    Sample.model_validate(py_sample)
    Sample.model_validate(ts_sample)

    _write_jsonl(datasets_dir / "python" / "all.jsonl", [py_sample])
    _write_jsonl(datasets_dir / "ts" / "all.jsonl", [ts_sample])

    repo_out = tool_outputs / "repo1"
    repo_out.mkdir(parents=True)
    (repo_out / "bandit.json").write_text(
        json.dumps(
            {
                "results": [
                    {
                        "filename": "app.py",
                        "line_number": 1,
                        "test_id": "B101",
                        "issue_severity": "HIGH",
                        "issue_confidence": "MEDIUM",
                        "issue_text": "Use of assert detected.",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (repo_out / "semgrep.json").write_text(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "ts.no-eval",
                        "path": "app.ts",
                        "start": {"line": 1},
                        "extra": {"message": "Avoid eval", "severity": "WARNING"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (repo_out / "meta.json").write_text(
        json.dumps(
            {
                "repo": "local/repo1",
                "bandit": {"version": "1.2.3", "args": ["-q", "-f", "json"]},
                "semgrep": {"version": "1.88.0", "args": ["--json"], "config": "p/ci"},
            }
        ),
        encoding="utf-8",
    )

    cmd = [
        sys.executable,
        "scripts/weak_label.py",
        "map",
        "--tool-outputs",
        str(tool_outputs),
        "--datasets-dir",
        str(datasets_dir),
        "--repos-dir",
        str(repos_dir),
        "--out",
        str(datasets_dir / "weak_labels.jsonl"),
    ]
    subprocess.run(cmd, cwd=repo_root, check=True)

    out_path = datasets_dir / "weak_labels.jsonl"
    rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
    assert rows
    labeled = [row for row in rows if row["weak_labels"]]
    assert labeled
    for row in labeled:
        label = row["weak_labels"][0]
        assert label["source"] in {"bandit", "semgrep"}
        assert "rule_id" in label
        assert "severity" in label
