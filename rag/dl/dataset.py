from __future__ import annotations

import json
import random
import re
from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha1
from pathlib import Path

_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]+|\d+|[^\s]")


@dataclass
class PairExample:
    pair_id: str
    vuln_text: str
    fixed_text: str
    rule_id: str | None
    category: str | None
    metadata: dict[str, str]


@dataclass
class RetrievalTriple:
    triple_id: str
    query: str
    positive_text: str
    negative_texts: list[str]
    positive_chunk_id: str
    metadata: dict[str, str]


class Vocab:
    def __init__(self, token_to_id: dict[str, int]) -> None:
        self.token_to_id = token_to_id
        self.unk_id = token_to_id.get("<unk>", 1)
        self.pad_id = token_to_id.get("<pad>", 0)

    @classmethod
    def build(cls, texts: Iterable[str], max_size: int = 5000, min_freq: int = 1) -> Vocab:
        counts: dict[str, int] = {}
        for text in texts:
            for token in tokenize(text):
                counts[token] = counts.get(token, 0) + 1
        ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        token_to_id = {"<pad>": 0, "<unk>": 1}
        for token, freq in ranked:
            if freq < min_freq:
                continue
            if len(token_to_id) >= max_size:
                break
            token_to_id[token] = len(token_to_id)
        return cls(token_to_id)

    def encode(self, text: str, max_len: int) -> list[int]:
        ids = [self.token_to_id.get(tok, self.unk_id) for tok in tokenize(text)]
        if len(ids) >= max_len:
            return ids[:max_len]
        return ids + [self.pad_id] * (max_len - len(ids))

    def to_json(self) -> dict[str, int]:
        return dict(self.token_to_id)

    @classmethod
    def from_json(cls, payload: dict[str, int]) -> Vocab:
        return cls(dict(payload))


def tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


def build_pairs(
    output_path: Path,
    templates_root: Path = Path("patcher/templates"),
    artifacts_root: Path = Path("artifacts"),
    kb_root: Path = Path("rag/kb"),
    seed: int = 1337,
    max_pairs: int = 2000,
) -> dict[str, int]:
    rng = random.Random(seed)
    pairs: list[PairExample] = []
    pairs.extend(_template_pairs())
    pairs.extend(_diff_pairs(artifacts_root))
    pairs.extend(_kb_pairs(kb_root))
    rng.shuffle(pairs)
    if max_pairs and len(pairs) > max_pairs:
        pairs = pairs[:max_pairs]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for item in pairs:
            handle.write(json.dumps(item.__dict__) + "\n")
    return {
        "pairs": len(pairs),
        "templates": sum(1 for p in pairs if p.metadata.get("source") == "template"),
        "diffs": sum(1 for p in pairs if p.metadata.get("source") == "diff"),
        "kb": sum(1 for p in pairs if p.metadata.get("source") == "kb"),
    }


def build_retrieval_triples(
    store_path: Path,
    output_path: Path,
    seed: int = 1337,
    max_negatives: int = 3,
    max_triples: int = 1000,
) -> dict[str, int]:
    rng = random.Random(seed)
    from rag.store.sqlite_store import SQLiteStore

    store = SQLiteStore(store_path)
    chunks = sorted(store.list_chunks(), key=lambda c: c.chunk_id)
    store.close()
    triples: list[RetrievalTriple] = []
    for chunk in chunks:
        tokens = tokenize(chunk.text)[:12]
        if not tokens:
            continue
        query = " ".join(tokens)
        negatives = [c for c in chunks if c.chunk_id != chunk.chunk_id]
        rng.shuffle(negatives)
        neg_texts = [n.text for n in negatives[:max_negatives]]
        triples.append(
            RetrievalTriple(
                triple_id=_stable_id(query + chunk.chunk_id),
                query=query,
                positive_text=chunk.text,
                negative_texts=neg_texts,
                positive_chunk_id=chunk.chunk_id,
                metadata={"source": "kb", "document_id": chunk.document_id},
            )
        )
    rng.shuffle(triples)
    if max_triples and len(triples) > max_triples:
        triples = triples[:max_triples]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for item in triples:
            handle.write(json.dumps(item.__dict__) + "\n")
    return {"triples": len(triples)}


def _template_pairs() -> list[PairExample]:
    entries = [
        {
            "rule_id": "B602",
            "category": "B602",
            "vuln": "subprocess.run(['ls'], shell=True)",
            "fixed": "subprocess.run(['ls'])",
        },
        {
            "rule_id": "xss.innerhtml",
            "category": "injection.xss",
            "vuln": "element.innerHTML = userInput",
            "fixed": "element.textContent = userInput",
        },
        {
            "rule_id": "regex.dynamic",
            "category": "redos",
            "vuln": "const r = new RegExp(userInput)",
            "fixed": "const r = new RegExp(escapeRegExp(userInput))",
        },
    ]
    pairs: list[PairExample] = []
    for entry in entries:
        payload = {
            "rule_id": entry["rule_id"],
            "category": entry["category"],
            "source": "template",
        }
        pair_id = _stable_id(entry["vuln"] + entry["fixed"])
        pairs.append(
            PairExample(
                pair_id=pair_id,
                vuln_text=entry["vuln"],
                fixed_text=entry["fixed"],
                rule_id=entry["rule_id"],
                category=entry["category"],
                metadata=payload,
            )
        )
    return pairs


def _diff_pairs(artifacts_root: Path) -> list[PairExample]:
    pairs: list[PairExample] = []
    for diff_path in sorted(artifacts_root.rglob("*.diff")):
        if diff_path.name.startswith("candidate_") or diff_path.name == "final.diff":
            text = diff_path.read_text(encoding="utf-8", errors="ignore")
            pairs.extend(_pairs_from_diff(text, diff_path))
    return pairs


def _pairs_from_diff(text: str, diff_path: Path) -> list[PairExample]:
    pairs: list[PairExample] = []
    removed: list[str] = []
    added: list[str] = []
    for line in text.splitlines():
        if line.startswith("@@"):
            pairs.extend(_flush_diff_pair(removed, added, diff_path))
            removed, added = [], []
            continue
        if line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:])
        elif line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
    pairs.extend(_flush_diff_pair(removed, added, diff_path))
    return pairs


def _flush_diff_pair(removed: list[str], added: list[str], diff_path: Path) -> list[PairExample]:
    if not removed or not added:
        return []
    vuln_text = "\n".join(removed[:50]).strip()
    fixed_text = "\n".join(added[:50]).strip()
    if not vuln_text or not fixed_text:
        return []
    pair_id = _stable_id(vuln_text + fixed_text)
    return [
        PairExample(
            pair_id=pair_id,
            vuln_text=vuln_text,
            fixed_text=fixed_text,
            rule_id=None,
            category=None,
            metadata={"source": "diff", "path": diff_path.as_posix()},
        )
    ]


def _kb_pairs(kb_root: Path) -> list[PairExample]:
    pairs: list[PairExample] = []
    if not kb_root.exists():
        return pairs
    for path in sorted(kb_root.rglob("*.md")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        chunks = list(_chunk_text(text, max_size=700, overlap=120))
        for chunk in chunks:
            if not chunk.strip():
                continue
            vuln_text = f"guidance: {chunk[:200].strip()}"
            fixed_text = chunk.strip()
            pair_id = _stable_id(vuln_text + fixed_text)
            pairs.append(
                PairExample(
                    pair_id=pair_id,
                    vuln_text=vuln_text,
                    fixed_text=fixed_text,
                    rule_id=None,
                    category=None,
                    metadata={"source": "kb", "path": path.as_posix()},
                )
            )
    return pairs


def _chunk_text(text: str, max_size: int, overlap: int) -> Iterable[str]:
    start = 0
    while start < len(text):
        end = min(len(text), start + max_size)
        chunk = text[start:end]
        yield chunk
        if end == len(text):
            break
        start = max(0, end - overlap)


def _stable_id(payload: str) -> str:
    return sha1(payload.encode("utf-8")).hexdigest()[:12]
