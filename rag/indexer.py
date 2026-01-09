from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rag.embeddings import embed_text
from rag.store.sqlite_store import Chunk, SQLiteStore


@dataclass
class IndexStats:
    documents: int
    chunks: int


def build_index(kb_paths: Iterable[Path], store_path: Path) -> IndexStats:
    store = SQLiteStore(store_path)
    total_docs = 0
    total_chunks = 0
    for path in kb_paths:
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file():
                    total_docs, total_chunks = _index_path(store, child, total_docs, total_chunks)
        elif path.is_file():
            total_docs, total_chunks = _index_path(store, path, total_docs, total_chunks)
    store.close()
    return IndexStats(documents=total_docs, chunks=total_chunks)


def _index_path(
    store: SQLiteStore, path: Path, total_docs: int, total_chunks: int
) -> tuple[int, int]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    title = path.name
    document_id = hashlib.sha1(path.as_posix().encode("utf-8")).hexdigest()[:12]
    created_at = datetime.now(UTC).isoformat()
    store.upsert_document(
        document_id=document_id,
        title=title,
        source_path=path.as_posix(),
        created_at=created_at,
        metadata={"source_path": path.as_posix(), "title": title},
    )
    chunks = list(_chunk_text(text, max_size=800, overlap=100))
    chunk_rows = []
    for idx, chunk in enumerate(chunks):
        embedding = embed_text(chunk)
        chunk_rows.append(
            Chunk(
                chunk_id=f"{document_id}:{idx}",
                document_id=document_id,
                chunk_index=idx,
                text=chunk,
                metadata=_chunk_metadata(path, idx, title),
                embedding=embedding,
            )
        )
    store.add_chunks(chunk_rows)
    return total_docs + 1, total_chunks + len(chunk_rows)


def _chunk_text(text: str, max_size: int, overlap: int) -> Iterable[str]:
    if max_size <= 0:
        yield text
        return
    start = 0
    while start < len(text):
        end = min(len(text), start + max_size)
        chunk = text[start:end]
        yield chunk
        if end == len(text):
            break
        start = max(0, end - overlap)


def _chunk_metadata(path: Path, idx: int, title: str) -> dict[str, Any]:
    metadata = {"chunk_index": idx, "source_path": path.as_posix(), "title": title}
    if path.suffix == ".py":
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
            docstring = ast.get_docstring(tree)
            if docstring:
                metadata["docstring"] = docstring[:120]
        except SyntaxError:
            pass
    return metadata
