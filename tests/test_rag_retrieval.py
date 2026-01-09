from pathlib import Path

from rag.indexer import build_index
from rag.retriever import RAGRetriever


def test_rag_retrieval_shell_true(tmp_path: Path) -> None:
    """Test retrieval for subprocess shell=True vulnerability."""
    store_path = tmp_path / "rag.sqlite"
    build_index([Path("rag/kb")], store_path)
    retriever = RAGRetriever(store_path)
    hits = retriever.retrieve("subprocess shell=True list args", top_k=3)
    assert hits
    assert any("shell" in hit.snippet.lower() for hit in hits)


def test_rag_retrieval_innerhtml(tmp_path: Path) -> None:
    """Test retrieval for innerHTML XSS vulnerability."""
    store_path = tmp_path / "rag.sqlite"
    build_index([Path("rag/kb")], store_path)
    retriever = RAGRetriever(store_path)
    hits = retriever.retrieve("innerHTML tainted input", top_k=3)
    assert hits
    assert any("innerhtml" in hit.snippet.lower() for hit in hits)


def test_rag_retrieval_sql_injection(tmp_path: Path) -> None:
    """Test retrieval for SQL injection patterns."""
    store_path = tmp_path / "rag.sqlite"
    build_index([Path("rag/kb")], store_path)
    retriever = RAGRetriever(store_path)
    hits = retriever.retrieve("SQL injection parameterized query", top_k=3)
    assert hits
    assert any("sql" in hit.snippet.lower() for hit in hits)


def test_rag_retrieval_password_hashing(tmp_path: Path) -> None:
    """Test retrieval for password hashing best practices."""
    store_path = tmp_path / "rag.sqlite"
    build_index([Path("rag/kb")], store_path)
    retriever = RAGRetriever(store_path)
    hits = retriever.retrieve("password hash bcrypt", top_k=3)
    assert hits
    assert any("hash" in hit.snippet.lower() or "password" in hit.snippet.lower() for hit in hits)


def test_rag_retrieve_by_rule_bandit(tmp_path: Path) -> None:
    """Test retrieval by Bandit rule ID."""
    store_path = tmp_path / "rag.sqlite"
    build_index([Path("rag/kb")], store_path)
    retriever = RAGRetriever(store_path)
    hits = retriever.retrieve_by_rule("B602", top_k=3)
    assert hits
    # Should find subprocess-related content
    assert any(
        "shell" in hit.snippet.lower() or "subprocess" in hit.snippet.lower() for hit in hits
    )


def test_rag_retrieve_fix_pattern(tmp_path: Path) -> None:
    """Test retrieval of fix patterns for specific category/language."""
    store_path = tmp_path / "rag.sqlite"
    build_index([Path("rag/kb")], store_path)
    retriever = RAGRetriever(store_path)
    hits = retriever.retrieve_fix_pattern(
        category="command injection",
        language="Python",
        top_k=3,
    )
    assert hits


def test_rag_retrieval_owasp(tmp_path: Path) -> None:
    """Test retrieval for OWASP Top 10 references."""
    store_path = tmp_path / "rag.sqlite"
    build_index([Path("rag/kb")], store_path)
    retriever = RAGRetriever(store_path)
    hits = retriever.retrieve("OWASP injection A03", top_k=3)
    assert hits


def test_rag_retrieval_jwt_security(tmp_path: Path) -> None:
    """Test retrieval for JWT security patterns."""
    store_path = tmp_path / "rag.sqlite"
    build_index([Path("rag/kb")], store_path)
    retriever = RAGRetriever(store_path)
    hits = retriever.retrieve("JWT verify signature token", top_k=3)
    assert hits
    assert any("jwt" in hit.snippet.lower() for hit in hits)


def test_rag_metadata_extraction(tmp_path: Path) -> None:
    """Test that metadata is properly extracted during indexing."""
    store_path = tmp_path / "rag.sqlite"
    stats = build_index([Path("rag/kb")], store_path)
    # Should have indexed multiple documents
    assert stats.documents >= 2
    assert stats.chunks > 0

    retriever = RAGRetriever(store_path)
    hits = retriever.retrieve("Python security", top_k=1)
    assert hits
    # Check metadata is present
    assert hits[0].metadata is not None
