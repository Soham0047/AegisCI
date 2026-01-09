import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from rag import embeddings
from rag.dl.dataset import build_pairs
from rag.dl.train_embeddings import train_embeddings


@pytest.mark.skipif(os.environ.get("RUN_DL_TRAIN_TESTS") != "1", reason="DL training gated")
def test_train_embeddings_smoke(tmp_path: Path, monkeypatch) -> None:
    out_dir = tmp_path / "dl"
    pairs_path = out_dir / "pairs.jsonl"
    build_pairs(pairs_path, max_pairs=10)
    args = SimpleNamespace(
        pairs=str(pairs_path),
        out_dir=str(out_dir),
        epochs=1,
        batch_size=2,
        lr=1e-3,
        seed=123,
        embed_dim=32,
        hidden_dim=48,
        max_len=32,
        vocab_size=500,
        max_pairs=10,
    )
    train_embeddings(args)
    assert (out_dir / "embeddings_model.pt").exists()
    assert (out_dir / "vocab.json").exists()

    monkeypatch.setenv("DL_ARTIFACTS_DIR", str(out_dir))
    embeddings._load_dl_model.cache_clear()
    vec1 = embeddings.embed_text("subprocess run")
    vec2 = embeddings.embed_text("subprocess run")
    assert vec1 == vec2
    assert len(vec1) == args.hidden_dim
