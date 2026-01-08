from pathlib import Path

from rag.indexer import build_index
from rag.retriever import RAGRetriever


def test_rag_retrieval_shell_true(tmp_path: Path) -> None:
    store_path = tmp_path / "rag.sqlite"
    build_index([Path("rag/kb")], store_path)
    retriever = RAGRetriever(store_path)
    hits = retriever.retrieve("subprocess shell=True list args", top_k=3)
    assert hits
    assert any("shell=True" in hit.snippet for hit in hits)


def test_rag_retrieval_innerhtml(tmp_path: Path) -> None:
    store_path = tmp_path / "rag.sqlite"
    build_index([Path("rag/kb")], store_path)
    retriever = RAGRetriever(store_path)
    hits = retriever.retrieve("innerHTML tainted input", top_k=3)
    assert hits
    assert any("innerHTML" in hit.snippet for hit in hits)
