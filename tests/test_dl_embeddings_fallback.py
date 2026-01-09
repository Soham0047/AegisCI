from pathlib import Path

from rag import embeddings


def test_embeddings_fallback_hash(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DL_ARTIFACTS_DIR", str(tmp_path))
    embeddings._load_dl_model.cache_clear()
    vec1 = embeddings.embed_text("subprocess run")
    vec2 = embeddings.embed_text("subprocess run")
    assert vec1 == vec2
    assert len(vec1) == 256
