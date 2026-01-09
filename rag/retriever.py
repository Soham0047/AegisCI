from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from rag.dl.reranker import score_pairs
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
    metadata: dict | None = None


class RAGRetriever:
    def __init__(self, store_path: Path) -> None:
        self.store_path = store_path

    def retrieve(
        self,
        query: str,
        top_k: int = 5,
        doc_type: str | None = None,
    ) -> list[RetrievalHit]:
        """
        Retrieve relevant chunks for a query.

        Args:
            query: The search query
            top_k: Number of results to return
            doc_type: Optional filter for document type
                      (fix_patterns, vulnerability_reference, code_examples, scanner_rules)
        """
        # Expand query with security-specific terms
        expanded_query = self._expand_query(query)
        embedding = embed_text(expanded_query)

        store = SQLiteStore(self.store_path)
        hits = store.query_by_embedding(embedding, top_k=30)

        # Filter by doc_type if specified
        if doc_type:
            hits = [
                h
                for h in hits
                if h.metadata.get("doc_type") == doc_type
                or doc_type in h.metadata.get("source_path", "")
            ]

        reranked = self._rerank(query, hits)
        store.close()
        return reranked[:top_k]

    def retrieve_by_rule(self, rule_id: str, top_k: int = 5) -> list[RetrievalHit]:
        """Retrieve chunks relevant to a specific scanner rule (e.g., B602, CWE-89)."""
        # Build a query targeting the rule
        rule_queries = {
            # Bandit rules
            "B602": "subprocess shell=True command injection Python",
            "B601": "paramiko shell command injection",
            "B608": "SQL injection string formatting Python",
            "B301": "pickle deserialization Python",
            "B324": "MD5 SHA1 weak hash Python",
            "B501": "requests verify=False SSL certificate",
            "B307": "eval code injection Python",
            # CWE categories
            "CWE-78": "OS command injection shell",
            "CWE-79": "XSS cross-site scripting",
            "CWE-89": "SQL injection",
            "CWE-502": "deserialization pickle yaml",
            "CWE-22": "path traversal directory",
        }

        query = rule_queries.get(rule_id.upper())
        if not query:
            if rule_id.startswith("B") and rule_id[1:].isdigit():
                query = f"Bandit {rule_id} Python security vulnerability fix"
            elif rule_id.lower().startswith("cwe"):
                query = f"{rule_id} vulnerability security fix pattern"
            else:
                query = f"{rule_id} security vulnerability fix"

        return self.retrieve(query, top_k=top_k)

    def retrieve_fix_pattern(
        self,
        category: str,
        language: str,
        top_k: int = 3,
    ) -> list[RetrievalHit]:
        """Retrieve fix patterns for a specific vulnerability category and language."""
        query = f"{language} {category} fix pattern secure code example"
        return self.retrieve(query, top_k=top_k, doc_type="fix_patterns")

    def _expand_query(self, query: str) -> str:
        """Expand query with related security terms."""
        expansions = {
            "shell=true": "subprocess shell command injection B602",
            "innerhtml": "innerHTML XSS DOM cross-site scripting",
            "eval": "eval code injection remote execution",
            "pickle": "pickle deserialization RCE B301",
            "sql": "SQL injection SQLi parameterized query",
            "password": "password hash bcrypt secret credential",
            "md5": "MD5 weak hash SHA256 cryptographic",
            "jwt": "JWT token verify signature authentication",
            "cors": "CORS origin header cross-origin",
            "path": "path traversal directory LFI",
            "ssrf": "SSRF server-side request forgery URL",
            "yaml": "YAML safe_load deserialization",
            "xml": "XML XXE external entity",
        }

        query_lower = query.lower()
        expanded = query

        for term, expansion in expansions.items():
            if term in query_lower and expansion not in query_lower:
                expanded = f"{expanded} {expansion}"
                break  # Only add one expansion to avoid noise

        return expanded

    def _rerank(self, query: str, hits: list[ChunkHit]) -> list[RetrievalHit]:
        query_tokens = tokenize(query)
        learned_scores = score_pairs(query, [hit.text for hit in hits])

        reranked: list[RetrievalHit] = []
        for idx, hit in enumerate(hits):
            # Base score from lexical matching
            score = _lexical_score(query_tokens, tokenize(hit.text))

            # Use learned scores if available
            if learned_scores is not None:
                score = learned_scores[idx]

            # Boost score based on metadata matches
            score = self._apply_metadata_boost(score, query, hit)

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
                    metadata=hit.metadata,
                )
            )

        reranked.sort(
            key=lambda h: (h.score_rerank, h.score_embedding, h.chunk_id),
            reverse=True,
        )
        return reranked

    def _apply_metadata_boost(
        self,
        score: float,
        query: str,
        hit: ChunkHit,
    ) -> float:
        """Apply score boosts based on metadata matches."""
        boost = 0.0
        query_lower = query.lower()

        # Boost if keywords match
        keywords = hit.metadata.get("keywords", [])
        for keyword in keywords:
            if keyword in query_lower:
                boost += 0.1

        # Boost if CWE matches
        cwe_ids = hit.metadata.get("cwe_ids", [])
        for cwe in cwe_ids:
            if f"cwe-{cwe}".lower() in query_lower or f"cwe{cwe}" in query_lower:
                boost += 0.3

        # Boost if Bandit rule matches
        bandit_rules = hit.metadata.get("bandit_rules", [])
        for rule in bandit_rules:
            if rule.lower() in query_lower:
                boost += 0.3

        # Boost fix patterns for fix-related queries
        if hit.metadata.get("doc_type") == "fix_patterns":
            if any(word in query_lower for word in ["fix", "patch", "secure", "safe"]):
                boost += 0.2

        # Boost code examples for implementation queries
        if hit.metadata.get("doc_type") == "code_examples":
            if any(word in query_lower for word in ["example", "how", "implement"]):
                boost += 0.2

        return score + boost


def _lexical_score(query_tokens: list[str], doc_tokens: list[str]) -> float:
    """BM25-style lexical scoring."""
    if not query_tokens or not doc_tokens:
        return 0.0

    doc_counts: dict[str, int] = {}
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


def _snippet(text: str, max_chars: int = 300) -> str:
    """Extract a readable snippet from text."""
    # Remove code blocks for cleaner snippets
    text_clean = re.sub(r"```[\s\S]*?```", "[code]", text)
    snippet = " ".join(text_clean.strip().split())

    if len(snippet) <= max_chars:
        return snippet

    return snippet[: max_chars - 3].rstrip() + "..."
