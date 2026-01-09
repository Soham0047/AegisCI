from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rag.embeddings import cosine_similarity


@dataclass
class Chunk:
    chunk_id: str
    document_id: str
    chunk_index: int
    text: str
    metadata: dict[str, Any]
    embedding: list[float]


@dataclass
class ChunkHit:
    chunk_id: str
    document_id: str
    text: str
    metadata: dict[str, Any]
    score: float


class SQLiteStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY,
                title TEXT,
                source_path TEXT,
                created_at TEXT,
                metadata TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS chunks (
                id TEXT PRIMARY KEY,
                document_id TEXT,
                chunk_index INTEGER,
                text TEXT,
                metadata TEXT,
                embedding TEXT
            )
            """
        )
        self.conn.commit()

    def upsert_document(
        self,
        document_id: str,
        title: str,
        source_path: str,
        created_at: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT OR REPLACE INTO documents (id, title, source_path, created_at, metadata)
            VALUES (?, ?, ?, ?, ?)
            """,
            (document_id, title, source_path, created_at, json.dumps(metadata or {})),
        )
        self.conn.commit()

    def add_chunks(self, chunks: Iterable[Chunk]) -> None:
        cur = self.conn.cursor()
        rows = []
        for chunk in chunks:
            rows.append(
                (
                    chunk.chunk_id,
                    chunk.document_id,
                    chunk.chunk_index,
                    chunk.text,
                    json.dumps(chunk.metadata),
                    json.dumps(chunk.embedding),
                )
            )
        cur.executemany(
            """
            INSERT OR REPLACE INTO chunks (id, document_id, chunk_index, text, metadata, embedding)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        self.conn.commit()

    def query_by_embedding(self, embedding: list[float], top_k: int = 5) -> list[ChunkHit]:
        cur = self.conn.cursor()
        cur.execute("SELECT id, document_id, text, metadata, embedding FROM chunks")
        hits: list[ChunkHit] = []
        for row in cur.fetchall():
            chunk_id, document_id, text, metadata_json, emb_json = row
            stored = json.loads(emb_json)
            score = cosine_similarity(embedding, stored)
            hits.append(
                ChunkHit(
                    chunk_id=chunk_id,
                    document_id=document_id,
                    text=text,
                    metadata=json.loads(metadata_json),
                    score=score,
                )
            )
        hits.sort(key=lambda h: h.score, reverse=True)
        return hits[:top_k]

    def list_chunks(self) -> list[Chunk]:
        cur = self.conn.cursor()
        cur.execute("SELECT id, document_id, chunk_index, text, metadata, embedding FROM chunks")
        chunks: list[Chunk] = []
        for row in cur.fetchall():
            chunk_id, document_id, chunk_index, text, metadata_json, emb_json = row
            chunks.append(
                Chunk(
                    chunk_id=chunk_id,
                    document_id=document_id,
                    chunk_index=int(chunk_index),
                    text=text,
                    metadata=json.loads(metadata_json),
                    embedding=json.loads(emb_json),
                )
            )
        return chunks

    def close(self) -> None:
        self.conn.close()
