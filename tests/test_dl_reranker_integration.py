import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from rag.dl.reranker import load_reranker
from rag.dl.train_reranker import train_reranker
from rag.embeddings import embed_text
from rag.retriever import RAGRetriever
from rag.store.sqlite_store import Chunk, SQLiteStore


@pytest.mark.skipif(os.environ.get("RUN_DL_TRAIN_TESTS") != "1", reason="DL training gated")
def test_reranker_integration(tmp_path: Path, monkeypatch) -> None:
    out_dir = tmp_path / "dl"
    store_path = tmp_path / "rag.sqlite"

    positive_text = "Use subprocess.run with shell=False to avoid shell injection."
    negative_text = "Unrelated guidance about logging and metrics."

    store = SQLiteStore(store_path)
    store.add_chunks(
        [
            Chunk(
                chunk_id="doc1:0",
                document_id="doc1",
                chunk_index=0,
                text=positive_text,
                metadata={"title": "Fixes", "source_path": "kb"},
                embedding=embed_text(positive_text),
            ),
            Chunk(
                chunk_id="doc2:0",
                document_id="doc2",
                chunk_index=0,
                text=negative_text,
                metadata={"title": "Misc", "source_path": "kb"},
                embedding=embed_text(negative_text),
            ),
        ]
    )
    store.close()

    triples_path = out_dir / "triples.jsonl"
    triples_path.parent.mkdir(parents=True, exist_ok=True)
    triple = {
        "triple_id": "t-1",
        "query": "subprocess shell",
        "positive_text": positive_text,
        "negative_texts": [negative_text],
        "positive_chunk_id": "doc1:0",
        "metadata": {"source": "kb"},
    }
    triples_path.write_text(json.dumps(triple) + "\n", encoding="utf-8")

    monkeypatch.setenv("DL_ARTIFACTS_DIR", str(out_dir))
    args = SimpleNamespace(
        store_path=str(store_path),
        triples=str(triples_path),
        out_dir=str(out_dir),
        epochs=1,
        lr=1e-3,
        seed=123,
        hidden_dim=32,
        max_triples=1,
    )
    train_reranker(args)
    load_reranker.cache_clear()

    retriever = RAGRetriever(store_path)
    hits = retriever.retrieve("subprocess shell", top_k=2)
    assert hits
    assert hits[0].chunk_id == "doc1:0"
