from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from rag.embeddings import embed_text, tokenize
from rag.store.sqlite_store import ChunkHit, SQLiteStore


@dataclass
class RetrievalHit:
    chunk_id: str
    document_id: str
    title: str
    source_path: str
    snippet: str
    score_embedding: float
    score_rerank: float


class RAGRetriever:
    def __init__(self, store_path: Path) -> None:
        self.store_path = store_path

    def retrieve(self, query: str, top_k: int = 5) -> list[RetrievalHit]:
        embedding = embed_text(query)
        store = SQLiteStore(self.store_path)
        hits = store.query_by_embedding(embedding, top_k=20)
        reranked = self._rerank(query, hits)
        store.close()
        return reranked[:top_k]

    def _rerank(self, query: str, hits: list[ChunkHit]) -> list[RetrievalHit]:
        query_tokens = tokenize(query)
        reranked: list[RetrievalHit] = []
        for hit in hits:
            score = _lexical_score(query_tokens, tokenize(hit.text))
            title = hit.metadata.get("title") or Path(hit.metadata.get("source_path", "")).name
            source_path = hit.metadata.get("source_path", "")
            snippet = _snippet(hit.text)
            reranked.append(
                RetrievalHit(
                    chunk_id=hit.chunk_id,
                    document_id=hit.document_id,
                    title=title,
                    source_path=source_path,
                    snippet=snippet,
                    score_embedding=hit.score,
                    score_rerank=score,
                )
            )
        reranked.sort(key=lambda h: (h.score_rerank, h.score_embedding, h.chunk_id), reverse=True)
        return reranked


def _lexical_score(query_tokens: list[str], doc_tokens: list[str]) -> float:
    if not query_tokens or not doc_tokens:
        return 0.0
    doc_counts = {}
    for token in doc_tokens:
        doc_counts[token] = doc_counts.get(token, 0) + 1
    score = 0.0
    doc_len = len(doc_tokens)
    avg_len = max(doc_len, 1)
    k1 = 1.2
    b = 0.75
    for token in query_tokens:
        tf = doc_counts.get(token, 0)
        if tf == 0:
            continue
        denom = tf + k1 * (1 - b + b * (doc_len / avg_len))
        score += (tf * (k1 + 1)) / denom
    return score


def _snippet(text: str, max_chars: int = 200) -> str:
    snippet = " ".join(text.strip().split())
    if len(snippet) <= max_chars:
        return snippet
    return snippet[: max_chars - 3].rstrip() + "..."
