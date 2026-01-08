from pathlib import Path

from rag.indexer import build_index
from rag.retriever import RAGRetriever


def test_reranker_is_deterministic(tmp_path: Path) -> None:
    store_path = tmp_path / "rag.sqlite"
    build_index([Path("rag/kb")], store_path)
    retriever = RAGRetriever(store_path)
    hits1 = retriever.retrieve("innerHTML untrusted", top_k=5)
    hits2 = retriever.retrieve("innerHTML untrusted", top_k=5)
    assert [h.chunk_id for h in hits1] == [h.chunk_id for h in hits2]
