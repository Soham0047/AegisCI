from __future__ import annotations

import ast
import hashlib
import re
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
                if child.is_file() and _is_indexable(child):
                    total_docs, total_chunks = _index_path(store, child, total_docs, total_chunks)
        elif path.is_file() and _is_indexable(path):
            total_docs, total_chunks = _index_path(store, path, total_docs, total_chunks)
    store.close()
    return IndexStats(documents=total_docs, chunks=total_chunks)


def _is_indexable(path: Path) -> bool:
    """Check if a file should be indexed."""
    indexable_extensions = {".md", ".txt", ".py", ".rst", ".json"}
    return path.suffix.lower() in indexable_extensions


def _index_path(
    store: SQLiteStore, path: Path, total_docs: int, total_chunks: int
) -> tuple[int, int]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    title = path.name
    document_id = hashlib.sha1(path.as_posix().encode("utf-8")).hexdigest()[:12]
    created_at = datetime.now(UTC).isoformat()

    # Extract document-level metadata
    doc_metadata = _extract_document_metadata(path, text)

    store.upsert_document(
        document_id=document_id,
        title=title,
        source_path=path.as_posix(),
        created_at=created_at,
        metadata=doc_metadata,
    )

    # Use semantic chunking for markdown files
    if path.suffix == ".md":
        chunks = list(_chunk_markdown(text))
    else:
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
                metadata=_chunk_metadata(path, idx, title, chunk),
                embedding=embedding,
            )
        )
    store.add_chunks(chunk_rows)
    return total_docs + 1, total_chunks + len(chunk_rows)


def _extract_document_metadata(path: Path, text: str) -> dict[str, Any]:
    """Extract document-level metadata."""
    metadata = {"source_path": path.as_posix(), "title": path.name}

    if path.suffix == ".md":
        # Extract title from first heading
        title_match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
        if title_match:
            metadata["title"] = title_match.group(1).strip()

        # Extract categories/tags from headings
        headings = re.findall(r"^##\s+(.+)$", text, re.MULTILINE)
        if headings:
            metadata["sections"] = headings[:10]

        # Detect document type
        if "fix pattern" in text.lower() or "- pattern:" in text.lower():
            metadata["doc_type"] = "fix_patterns"
        elif "cwe-" in text.lower():
            metadata["doc_type"] = "vulnerability_reference"
        elif "example" in text.lower() and "```" in text:
            metadata["doc_type"] = "code_examples"
        elif "bandit" in text.lower() or "semgrep" in text.lower():
            metadata["doc_type"] = "scanner_rules"
        else:
            metadata["doc_type"] = "playbook"

    return metadata


def _chunk_markdown(text: str, max_size: int = 1200) -> Iterable[str]:
    """Chunk markdown by sections for better semantic coherence."""
    # Split by level 2 and 3 headings
    sections = re.split(r"(?=^##[^#])", text, flags=re.MULTILINE)

    for section in sections:
        section = section.strip()
        if not section:
            continue

        # If section is small enough, yield it whole
        if len(section) <= max_size:
            yield section
        else:
            # Split large sections by level 3 headings
            subsections = re.split(r"(?=^###)", section, flags=re.MULTILINE)
            for subsection in subsections:
                subsection = subsection.strip()
                if not subsection:
                    continue
                if len(subsection) <= max_size:
                    yield subsection
                else:
                    # Fall back to character-based chunking
                    yield from _chunk_text(subsection, max_size=800, overlap=100)


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


def _chunk_metadata(path: Path, idx: int, title: str, chunk: str) -> dict[str, Any]:
    metadata = {"chunk_index": idx, "source_path": path.as_posix(), "title": title}

    # Extract keywords from chunk for better matching
    keywords = _extract_keywords(chunk)
    if keywords:
        metadata["keywords"] = keywords

    # Extract code language if code blocks present
    code_langs = re.findall(r"```(\w+)", chunk)
    if code_langs:
        metadata["code_languages"] = list(set(code_langs))

    # Extract CWE references
    cwes = re.findall(r"CWE-(\d+)", chunk, re.IGNORECASE)
    if cwes:
        metadata["cwe_ids"] = list(set(cwes))

    # Extract Bandit rule IDs
    bandit_rules = re.findall(r"B(\d{3})", chunk)
    if bandit_rules:
        metadata["bandit_rules"] = list(set(f"B{r}" for r in bandit_rules))

    if path.suffix == ".py":
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
            docstring = ast.get_docstring(tree)
            if docstring:
                metadata["docstring"] = docstring[:120]
        except SyntaxError:
            pass

    return metadata


def _extract_keywords(text: str) -> list[str]:
    """Extract security-relevant keywords from text."""
    security_keywords = {
        "injection",
        "xss",
        "csrf",
        "ssrf",
        "sqli",
        "rce",
        "shell",
        "subprocess",
        "eval",
        "exec",
        "pickle",
        "innerHTML",
        "textContent",
        "sanitize",
        "escape",
        "password",
        "secret",
        "token",
        "api_key",
        "credential",
        "hash",
        "encrypt",
        "bcrypt",
        "hmac",
        "md5",
        "sha1",
        "authenticate",
        "authorize",
        "session",
        "cookie",
        "path",
        "traversal",
        "directory",
        "file",
        "upload",
        "serialize",
        "deserialize",
        "yaml",
        "json",
        "xml",
        "cors",
        "origin",
        "header",
        "jwt",
        "oauth",
    }

    text_lower = text.lower()
    found = []
    for keyword in security_keywords:
        if keyword in text_lower:
            found.append(keyword)

    return found[:10]  # Limit to top 10
