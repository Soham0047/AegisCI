from __future__ import annotations

import json
import os
import random
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from hashlib import sha1
from pathlib import Path
from typing import Literal

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


@dataclass
class CodeSample:
    """A labeled code sample for training."""

    sample_id: str
    code: str
    label: Literal["vuln", "safe"]
    source: str
    language: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class BalancedDataset:
    """A balanced dataset with train/val/test splits."""

    train: list[CodeSample]
    val: list[CodeSample]
    test: list[CodeSample]
    stats: dict[str, int]


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


# =============================================================================
# Balanced Dataset Builder
# =============================================================================

# File extensions by language
_LANG_EXTENSIONS = {
    "python": [".py"],
    "javascript": [".js", ".jsx", ".mjs"],
    "typescript": [".ts", ".tsx"],
    "java": [".java"],
    "go": [".go"],
    "ruby": [".rb"],
    "php": [".php"],
    "c": [".c", ".h"],
    "cpp": [".cpp", ".hpp", ".cc", ".cxx"],
    "csharp": [".cs"],
}

# Vulnerable patterns (simplified heuristics)
_VULN_PATTERNS = [
    # Command injection
    (r"subprocess\.\w+\([^)]*shell\s*=\s*True", "command_injection"),
    (r"os\.system\s*\(", "command_injection"),
    (r"eval\s*\(", "code_injection"),
    (r"exec\s*\(", "code_injection"),
    # SQL injection
    (r"execute\s*\([^)]*%s|execute\s*\([^)]*\+", "sql_injection"),
    (r"cursor\.\w+\s*\([^)]*\+\s*[\"']", "sql_injection"),
    # XSS
    (r"innerHTML\s*=", "xss"),
    (r"document\.write\s*\(", "xss"),
    # Hardcoded secrets
    (r"password\s*=\s*[\"'][^\"']+[\"']", "hardcoded_secret"),
    (r"api_key\s*=\s*[\"'][^\"']+[\"']", "hardcoded_secret"),
    (r"secret\s*=\s*[\"'][^\"']+[\"']", "hardcoded_secret"),
    # Deserialization
    (r"pickle\.loads?\s*\(", "deserialization"),
    (r"yaml\.load\s*\([^)]*\)", "deserialization"),
    # Path traversal
    (r"open\s*\([^)]*\+", "path_traversal"),
]

_COMPILED_VULN_PATTERNS = [(re.compile(p, re.IGNORECASE), cat) for p, cat in _VULN_PATTERNS]


def _detect_language(path: Path) -> str | None:
    """Detect language from file extension."""
    ext = path.suffix.lower()
    for lang, extensions in _LANG_EXTENSIONS.items():
        if ext in extensions:
            return lang
    return None


def _is_vulnerable_code(code: str) -> tuple[bool, str | None]:
    """Check if code contains vulnerable patterns."""
    for pattern, category in _COMPILED_VULN_PATTERNS:
        if pattern.search(code):
            return True, category
    return False, None


def _extract_code_snippets(
    path: Path,
    max_lines: int = 50,
    min_lines: int = 5,
) -> list[tuple[str, int, int]]:
    """
    Extract code snippets from a file.

    Returns list of (snippet_text, start_line, end_line).
    """
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    lines = content.split("\n")
    if len(lines) < min_lines:
        return []

    snippets = []

    # Extract overlapping windows
    for start in range(0, len(lines), max_lines // 2):
        end = min(start + max_lines, len(lines))
        snippet = "\n".join(lines[start:end])
        if len(snippet.strip()) >= 50:  # Minimum 50 chars
            snippets.append((snippet, start + 1, end))
        if end >= len(lines):
            break

    return snippets


def scan_repos_for_samples(
    repos_root: Path,
    max_samples_per_repo: int = 100,
    seed: int = 1337,
) -> list[CodeSample]:
    """
    Scan repositories for code samples.

    Labels samples as "vuln" or "safe" based on pattern detection.
    """
    rng = random.Random(seed)
    samples: list[CodeSample] = []

    if not repos_root.exists():
        return samples

    # Find all code files
    all_files: list[Path] = []
    for lang, extensions in _LANG_EXTENSIONS.items():
        for ext in extensions:
            all_files.extend(repos_root.rglob(f"*{ext}"))

    # Group by repo
    repo_files: dict[str, list[Path]] = {}
    for file_path in all_files:
        # Get repo name (first directory under repos_root)
        try:
            rel_path = file_path.relative_to(repos_root)
            repo_name = rel_path.parts[0] if rel_path.parts else "unknown"
        except ValueError:
            repo_name = "unknown"

        if repo_name not in repo_files:
            repo_files[repo_name] = []
        repo_files[repo_name].append(file_path)

    # Process each repo
    for repo_name, files in sorted(repo_files.items()):
        repo_samples: list[CodeSample] = []
        rng.shuffle(files)

        for file_path in files:
            if len(repo_samples) >= max_samples_per_repo:
                break

            language = _detect_language(file_path)
            if not language:
                continue

            snippets = _extract_code_snippets(file_path)
            for snippet, start, end in snippets:
                if len(repo_samples) >= max_samples_per_repo:
                    break

                is_vuln, category = _is_vulnerable_code(snippet)
                label: Literal["vuln", "safe"] = "vuln" if is_vuln else "safe"

                sample_id = _stable_id(f"{repo_name}:{file_path.name}:{start}:{end}")
                repo_samples.append(
                    CodeSample(
                        sample_id=sample_id,
                        code=snippet,
                        label=label,
                        source=repo_name,
                        language=language,
                        metadata={
                            "file": file_path.name,
                            "start_line": str(start),
                            "end_line": str(end),
                            "category": category or "",
                        },
                    )
                )

        samples.extend(repo_samples)

    return samples


def balance_dataset(
    samples: list[CodeSample],
    balance_ratio: float = 0.5,
    seed: int = 1337,
    max_samples_per_class: int | None = None,
    strategy: Literal["downsample", "oversample"] = "downsample",
) -> list[CodeSample]:
    """
    Balance a dataset to achieve desired ratio.

    Args:
        samples: Input samples
        balance_ratio: Target ratio of vuln samples (0.5 = 50/50)
        seed: Random seed for determinism
        max_samples_per_class: Maximum samples per class
        strategy: "downsample" majority or "oversample" minority

    Returns:
        Balanced list of samples
    """
    rng = random.Random(seed)

    # Separate by label
    vuln_samples = [s for s in samples if s.label == "vuln"]
    safe_samples = [s for s in samples if s.label == "safe"]

    # Shuffle deterministically
    rng.shuffle(vuln_samples)
    rng.shuffle(safe_samples)

    if max_samples_per_class:
        vuln_samples = vuln_samples[:max_samples_per_class]
        safe_samples = safe_samples[:max_samples_per_class]

    n_vuln = len(vuln_samples)
    n_safe = len(safe_samples)

    if n_vuln == 0 or n_safe == 0:
        return vuln_samples + safe_samples

    # Calculate target counts based on ratio
    if strategy == "downsample":
        # Downsample majority class
        if balance_ratio == 0.5:
            target_size = min(n_vuln, n_safe)
            vuln_samples = vuln_samples[:target_size]
            safe_samples = safe_samples[:target_size]
        else:
            # ratio = vuln / (vuln + safe)
            # target_safe = vuln * (1 - ratio) / ratio
            if n_vuln > n_safe * balance_ratio / (1 - balance_ratio):
                target_vuln = int(n_safe * balance_ratio / (1 - balance_ratio))
                vuln_samples = vuln_samples[:target_vuln]
            else:
                target_safe = int(n_vuln * (1 - balance_ratio) / balance_ratio)
                safe_samples = safe_samples[:target_safe]
    else:
        # Oversample minority class with replacement
        if n_vuln < n_safe:
            target = n_safe
            while len(vuln_samples) < target:
                vuln_samples.append(rng.choice(vuln_samples[:n_vuln]))
        else:
            target = n_vuln
            while len(safe_samples) < target:
                safe_samples.append(rng.choice(safe_samples[:n_safe]))

    # Combine and shuffle
    balanced = vuln_samples + safe_samples
    rng.shuffle(balanced)

    return balanced


def split_dataset(
    samples: list[CodeSample],
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    test_ratio: float = 0.1,
    seed: int = 1337,
) -> BalancedDataset:
    """
    Split samples into train/val/test sets.

    Preserves class balance within each split.
    """
    rng = random.Random(seed)

    # Separate by label
    vuln_samples = [s for s in samples if s.label == "vuln"]
    safe_samples = [s for s in samples if s.label == "safe"]

    # Shuffle
    rng.shuffle(vuln_samples)
    rng.shuffle(safe_samples)

    def split_list(items: list) -> tuple[list, list, list]:
        n = len(items)
        n_train = int(n * train_ratio)
        n_val = int(n * val_ratio)
        return (
            items[:n_train],
            items[n_train : n_train + n_val],
            items[n_train + n_val :],
        )

    vuln_train, vuln_val, vuln_test = split_list(vuln_samples)
    safe_train, safe_val, safe_test = split_list(safe_samples)

    train = vuln_train + safe_train
    val = vuln_val + safe_val
    test = vuln_test + safe_test

    # Shuffle each split
    rng.shuffle(train)
    rng.shuffle(val)
    rng.shuffle(test)

    stats = {
        "total_samples": len(samples),
        "train_size": len(train),
        "val_size": len(val),
        "test_size": len(test),
        "train_vuln": len(vuln_train),
        "train_safe": len(safe_train),
        "val_vuln": len(vuln_val),
        "val_safe": len(safe_val),
        "test_vuln": len(vuln_test),
        "test_safe": len(safe_test),
    }

    return BalancedDataset(train=train, val=val, test=test, stats=stats)


def build_balanced_dataset(
    repos_root: Path = Path("data/repos"),
    output_dir: Path = Path("artifacts/dl/balanced"),
    balance_ratio: float = 0.5,
    max_samples_per_class: int | None = None,
    max_samples_per_repo: int = 100,
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    test_ratio: float = 0.1,
    seed: int = 1337,
    augment_k: int = 0,
) -> BalancedDataset:
    """
    Build a balanced dataset from repository code.

    Args:
        repos_root: Root directory containing repositories
        output_dir: Output directory for JSONL files
        balance_ratio: Target vuln ratio (0.5 = 50/50)
        max_samples_per_class: Cap per class
        max_samples_per_repo: Cap per repository
        train_ratio: Training set ratio
        val_ratio: Validation set ratio
        test_ratio: Test set ratio
        seed: Random seed
        augment_k: Number of augmented variants per sample (0 = no augmentation)

    Returns:
        BalancedDataset with splits
    """
    # Scan repos
    samples = scan_repos_for_samples(repos_root, max_samples_per_repo, seed)

    # Balance
    balanced = balance_dataset(
        samples,
        balance_ratio=balance_ratio,
        seed=seed,
        max_samples_per_class=max_samples_per_class,
    )

    # Apply augmentation if requested
    if augment_k > 0:
        from rag.dl.augment import generate_augmented_variants, AugmentConfig

        augmented_samples: list[CodeSample] = []
        config = AugmentConfig()

        for sample in balanced:
            # Keep original
            augmented_samples.append(sample)

            # Generate augmented variants
            variants = generate_augmented_variants(
                sample.code,
                sample.sample_id,
                k=augment_k,
                base_seed=seed,
                config=config,
            )

            for i, variant in enumerate(variants):
                if variant.augmented != sample.code:
                    aug_sample = CodeSample(
                        sample_id=f"{sample.sample_id}_aug{i}",
                        code=variant.augmented,
                        label=sample.label,
                        source=sample.source,
                        language=sample.language,
                        metadata={
                            **sample.metadata,
                            "augmented": "true",
                            "aug_index": str(i),
                            "transformations": ",".join(variant.transformations),
                        },
                    )
                    augmented_samples.append(aug_sample)

        balanced = augmented_samples

    # Split
    dataset = split_dataset(
        balanced,
        train_ratio=train_ratio,
        val_ratio=val_ratio,
        test_ratio=test_ratio,
        seed=seed,
    )

    # Save to disk
    output_dir.mkdir(parents=True, exist_ok=True)

    for split_name, split_samples in [
        ("train", dataset.train),
        ("val", dataset.val),
        ("test", dataset.test),
    ]:
        output_path = output_dir / f"{split_name}.jsonl"
        with output_path.open("w", encoding="utf-8") as f:
            for sample in split_samples:
                record = {
                    "sample_id": sample.sample_id,
                    "code": sample.code,
                    "label": sample.label,
                    "source": sample.source,
                    "language": sample.language,
                    "metadata": sample.metadata,
                }
                f.write(json.dumps(record) + "\n")

    # Save stats
    stats_path = output_dir / "stats.json"
    stats_path.write_text(json.dumps(dataset.stats, indent=2), encoding="utf-8")

    return dataset


def load_code_samples(path: Path) -> list[CodeSample]:
    """Load code samples from a JSONL file."""
    samples: list[CodeSample] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        data = json.loads(line)
        samples.append(
            CodeSample(
                sample_id=data["sample_id"],
                code=data["code"],
                label=data["label"],
                source=data.get("source", "unknown"),
                language=data.get("language", "unknown"),
                metadata=data.get("metadata", {}),
            )
        )
    return samples
