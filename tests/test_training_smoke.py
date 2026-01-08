import json
import subprocess
import sys
from pathlib import Path

import pytest


def test_training_smoke(tmp_path: Path):
    train_path = Path("datasets/transformer/train.jsonl")
    if not train_path.exists():
        pytest.skip("transformer dataset not available")

    lines = train_path.read_text(encoding="utf-8").splitlines()[:50]
    if not lines:
        pytest.skip("transformer dataset is empty")

    tiny_train = tmp_path / "train.jsonl"
    tiny_val = tmp_path / "val.jsonl"
    tiny_train.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tiny_val.write_text("\n".join(lines[:20]) + "\n", encoding="utf-8")

    output_path = tmp_path / "transformer_v1.pt"
    metrics_path = tmp_path / "metrics.json"

    cmd = [
        sys.executable,
        "ml/train_transformer.py",
        "--train",
        str(tiny_train),
        "--val",
        str(tiny_val),
        "--epochs",
        "1",
        "--batch-size",
        "2",
        "--max-len",
        "32",
        "--model-name",
        "tiny",
        "--output",
        str(output_path),
        "--metrics-out",
        str(metrics_path),
        "--max-train-samples",
        "30",
        "--max-val-samples",
        "20",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path.cwd())
    assert result.returncode == 0, result.stderr
    assert output_path.exists()
    assert metrics_path.exists()
    data = json.loads(metrics_path.read_text(encoding="utf-8"))
    assert isinstance(data, list)
