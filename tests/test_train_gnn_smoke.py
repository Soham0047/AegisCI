import subprocess
import sys
from pathlib import Path


def test_train_gnn_smoke(tmp_path: Path):
    fixture = Path("tests/fixtures/gnn_tiny.jsonl")
    output_path = tmp_path / "gnn.pt"
    metrics_path = tmp_path / "gnn_metrics.json"

    cmd = [
        sys.executable,
        "ml/train_gnn.py",
        "--train",
        str(fixture),
        "--val",
        str(fixture),
        "--epochs",
        "1",
        "--batch-size",
        "2",
        "--max-nodes",
        "128",
        "--max-edges",
        "256",
        "--hidden-dim",
        "32",
        "--layers",
        "1",
        "--output",
        str(output_path),
        "--metrics-out",
        str(metrics_path),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path.cwd())
    assert result.returncode == 0, result.stderr
    assert output_path.exists()
    assert metrics_path.exists()
