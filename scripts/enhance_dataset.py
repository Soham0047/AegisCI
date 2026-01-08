#!/usr/bin/env python3
"""
Dataset Enhancement Script for Deep Learning Phases 3 & 4
==========================================================

Enhances the gold-labeled dataset with features needed for:
- PHASE 3: Transformer classifier (CodeBERT, GraphCodeBERT)
- PHASE 4: GNN + Ensemble + OOD detection

Enhancements:
1. Code tokenization and windowing for transformers
2. AST extraction for GNN node features
3. Data flow / control flow graph edges
4. Feature engineering for ensemble models
5. Train/val/test splits with OOD holdout
6. Class balancing and augmentation
"""

from __future__ import annotations

import ast
import json
import random
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import typer

app = typer.Typer(add_completion=False)


# =============================================================================
# DATA STRUCTURES
# =============================================================================


@dataclass
class EnhancedSample:
    """Enhanced sample with all features for DL models."""

    # Core identifiers
    sample_id: str
    language: str
    repo: str
    filepath: str

    # Labels
    verdict: str  # TP, FP, UNCERTAIN
    category: str
    fix_type: str

    # Code context (for Transformers)
    code_snippet: str
    context_before: str
    context_after: str
    focal_line: int  # Line where finding occurs relative to snippet

    # Finding metadata
    rule_id: str
    severity: str
    confidence: str
    message: str

    # Tokenized representations
    tokens: list[str] = field(default_factory=list)
    token_ids: list[int] = field(default_factory=list)
    attention_mask: list[int] = field(default_factory=list)
    focal_token_positions: list[int] = field(default_factory=list)

    # AST features (for GNN)
    ast_nodes: list[dict] = field(default_factory=list)
    ast_edges: list[tuple[int, int, str]] = field(default_factory=list)
    node_types: list[str] = field(default_factory=list)

    # Engineered features (for Ensemble)
    features: dict = field(default_factory=dict)

    # Split assignment
    split: str = "train"  # train, val, test, ood_test

    # Metadata
    hardness: int = 1
    duplicate_group: str | None = None


# =============================================================================
# CODE TOKENIZATION (for Transformers)
# =============================================================================


def tokenize_code(code: str, language: str, max_length: int = 512) -> dict:
    """
    Tokenize code for transformer models.
    Returns tokens that can be used with CodeBERT/GraphCodeBERT.
    """
    # Simple tokenization (replace with actual tokenizer in training)
    # Split on whitespace, operators, and punctuation
    token_pattern = r"(\s+|[^\s\w]|\b)"
    raw_tokens = re.split(token_pattern, code)
    tokens = [t for t in raw_tokens if t.strip()]

    # Truncate to max length
    if len(tokens) > max_length:
        tokens = tokens[:max_length]

    return {
        "tokens": tokens,
        "token_count": len(tokens),
    }


def create_sliding_windows(
    code: str,
    focal_line: int,
    window_size: int = 20,
    stride: int = 10,
) -> list[dict]:
    """
    Create sliding windows around the focal line for context.
    Useful for long files that exceed transformer context limits.
    """
    lines = code.split("\n")
    windows = []

    for start in range(0, len(lines), stride):
        end = min(start + window_size, len(lines))
        window_lines = lines[start:end]

        # Check if focal line is in this window
        contains_focal = start <= focal_line < end
        focal_offset = focal_line - start if contains_focal else -1

        windows.append(
            {
                "start_line": start,
                "end_line": end,
                "code": "\n".join(window_lines),
                "contains_focal": contains_focal,
                "focal_offset": focal_offset,
            }
        )

    return windows


# =============================================================================
# AST EXTRACTION (for GNN)
# =============================================================================


def extract_python_ast(code: str) -> dict:
    """
    Extract AST nodes and edges for Python code.
    Returns graph structure for GNN training.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return {"nodes": [], "edges": [], "error": "parse_error"}

    nodes = []
    edges = []
    node_id = 0
    node_map = {}

    def visit_node(node, parent_id=None):
        nonlocal node_id
        current_id = node_id
        node_id += 1

        # Node features
        node_info = {
            "id": current_id,
            "type": node.__class__.__name__,
            "lineno": getattr(node, "lineno", None),
            "col_offset": getattr(node, "col_offset", None),
        }

        # Add node-specific features
        if isinstance(node, ast.Name):
            node_info["name"] = node.id
        elif isinstance(node, ast.FunctionDef):
            node_info["name"] = node.name
            node_info["args"] = [a.arg for a in node.args.args]
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                node_info["func_name"] = node.func.id
            elif isinstance(node.func, ast.Attribute):
                node_info["func_name"] = node.func.attr
        elif isinstance(node, ast.Str):
            node_info["value"] = node.s[:50] if len(node.s) > 50 else node.s
        elif isinstance(node, ast.Num):
            node_info["value"] = node.n

        nodes.append(node_info)
        node_map[id(node)] = current_id

        # Add edge from parent
        if parent_id is not None:
            edges.append((parent_id, current_id, "child"))

        # Visit children
        for child in ast.iter_child_nodes(node):
            visit_node(child, current_id)

    visit_node(tree)

    # Add data flow edges (simplified)
    name_definitions = {}
    for node in nodes:
        if node["type"] == "Name" and "name" in node:
            name = node["name"]
            if name in name_definitions:
                # Add data flow edge from definition to use
                edges.append((name_definitions[name], node["id"], "data_flow"))
            else:
                name_definitions[name] = node["id"]

    return {
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }


def extract_js_ast_simple(code: str) -> dict:
    """
    Simplified JS AST extraction using regex patterns.
    For full AST, use esprima/babel in Node.js.
    """
    nodes = []
    node_id = 0

    # Extract function definitions
    for match in re.finditer(r"function\s+(\w+)\s*\(([^)]*)\)", code):
        nodes.append(
            {
                "id": node_id,
                "type": "FunctionDeclaration",
                "name": match.group(1),
                "params": match.group(2),
                "lineno": code[: match.start()].count("\n") + 1,
            }
        )
        node_id += 1

    # Extract variable declarations
    for match in re.finditer(r"(const|let|var)\s+(\w+)", code):
        nodes.append(
            {
                "id": node_id,
                "type": "VariableDeclaration",
                "kind": match.group(1),
                "name": match.group(2),
                "lineno": code[: match.start()].count("\n") + 1,
            }
        )
        node_id += 1

    # Extract function calls
    for match in re.finditer(r"(\w+)\s*\(", code):
        if match.group(1) not in ("if", "for", "while", "function", "switch"):
            nodes.append(
                {
                    "id": node_id,
                    "type": "CallExpression",
                    "name": match.group(1),
                    "lineno": code[: match.start()].count("\n") + 1,
                }
            )
            node_id += 1

    return {
        "nodes": nodes,
        "edges": [],  # Would need proper parser for edges
        "node_count": len(nodes),
    }


# =============================================================================
# FEATURE ENGINEERING (for Ensemble)
# =============================================================================


def extract_features(sample: dict) -> dict:
    """
    Extract engineered features for ensemble/gradient boosting models.
    These complement the deep learning models.
    """
    code = sample.get("code_snippet", "")
    finding = sample.get("finding", {})
    filepath = sample.get("filepath", "")

    features = {}

    # === Code metrics ===
    lines = code.split("\n")
    features["code_lines"] = len(lines)
    features["code_chars"] = len(code)
    features["avg_line_length"] = len(code) / max(len(lines), 1)
    features["max_line_length"] = max(len(line) for line in lines) if lines else 0
    features["blank_line_ratio"] = sum(1 for line in lines if not line.strip()) / max(len(lines), 1)

    # === Complexity indicators ===
    features["nested_depth"] = (
        max(len(re.findall(r"^\s+", line)) // 4 for line in lines if line.strip()) if lines else 0
    )
    features["function_count"] = len(re.findall(r"\bdef\s+\w+|function\s+\w+", code))
    features["class_count"] = len(re.findall(r"\bclass\s+\w+", code))
    features["loop_count"] = len(re.findall(r"\bfor\b|\bwhile\b", code))
    features["conditional_count"] = len(re.findall(r"\bif\b|\belse\b|\belif\b", code))

    # === Security-relevant patterns ===
    features["has_eval"] = int(bool(re.search(r"\beval\s*\(", code)))
    features["has_exec"] = int(bool(re.search(r"\bexec\s*\(", code)))
    features["has_subprocess"] = int(bool(re.search(r"\bsubprocess\b", code)))
    features["has_shell_true"] = int(bool(re.search(r"shell\s*=\s*True", code)))
    features["has_sql"] = int(
        bool(re.search(r"\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b", code, re.I))
    )
    features["has_request"] = int(bool(re.search(r"request\.|req\.", code)))
    features["has_user_input"] = int(
        bool(re.search(r"input\(|argv|request\.(get|post|form|args)", code))
    )
    features["has_file_ops"] = int(bool(re.search(r"open\s*\(|read\(|write\(", code)))
    features["has_crypto"] = int(bool(re.search(r"md5|sha1|hashlib|crypto", code, re.I)))
    features["has_pickle"] = int(bool(re.search(r"pickle|marshal", code)))
    features["has_yaml_load"] = int(bool(re.search(r"yaml\.load|yaml\.unsafe", code)))
    features["has_innerhtml"] = int(bool(re.search(r"innerHTML|dangerouslySetInnerHTML", code)))

    # === String patterns ===
    features["string_concat_count"] = len(re.findall(r'\+\s*["\']|["\']\s*\+', code))
    features["fstring_count"] = len(re.findall(r'f["\']', code))
    features["format_count"] = len(re.findall(r"\.format\s*\(", code))
    features["percent_format_count"] = len(re.findall(r"%\s*\(", code))

    # === Finding metadata ===
    features["severity_score"] = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(
        finding.get("severity", "MEDIUM").upper(), 2
    )
    features["confidence_score"] = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(
        (finding.get("confidence") or "MEDIUM").upper(), 2
    )

    # === File path features ===
    features["is_test_file"] = int(bool(re.search(r"test|spec|mock|fixture", filepath, re.I)))
    features["is_vendor"] = int(bool(re.search(r"vendor|node_modules|static", filepath, re.I)))
    features["is_config"] = int(bool(re.search(r"config|settings|\.env", filepath, re.I)))
    features["path_depth"] = filepath.count("/")

    # === Rule features ===
    rule_id = finding.get("rule_id", "")
    features["is_bandit"] = int(rule_id.startswith("B"))
    features["is_semgrep"] = int("semgrep" in rule_id.lower())
    features["rule_hash"] = hash(rule_id) % 1000  # Categorical encoding

    return features


# =============================================================================
# DATA SPLITTING (with OOD holdout)
# =============================================================================


def create_splits(
    samples: list[dict],
    train_ratio: float = 0.7,
    val_ratio: float = 0.15,
    test_ratio: float = 0.10,
    ood_ratio: float = 0.05,
    ood_strategy: str = "repo",  # repo, category, or rule
    seed: int = 42,
) -> list[dict]:
    """
    Create train/val/test splits with OOD holdout.

    OOD strategies:
    - repo: Hold out entire repos for OOD
    - category: Hold out certain vulnerability categories
    - rule: Hold out certain scanner rules
    """
    random.seed(seed)

    # Group samples
    if ood_strategy == "repo":
        groups = defaultdict(list)
        for s in samples:
            groups[s.get("repo", "unknown")].append(s)
        group_key = "repo"
    elif ood_strategy == "category":
        groups = defaultdict(list)
        for s in samples:
            groups[s.get("category", "misc.other")].append(s)
        group_key = "category"
    else:  # rule
        groups = defaultdict(list)
        for s in samples:
            rule = s.get("finding", {}).get("rule_id", "unknown")
            groups[rule].append(s)
        group_key = "rule_id"

    # Select OOD groups
    group_names = list(groups.keys())
    random.shuffle(group_names)

    ood_count = max(1, int(len(group_names) * ood_ratio))
    ood_groups = set(group_names[:ood_count])
    id_groups = group_names[ood_count:]

    print(f"OOD holdout ({group_key}): {ood_groups}")

    # Assign OOD samples
    ood_samples = []
    id_samples = []

    for group_name, group_samples in groups.items():
        if group_name in ood_groups:
            for s in group_samples:
                s["split"] = "ood_test"
            ood_samples.extend(group_samples)
        else:
            id_samples.extend(group_samples)

    # Split ID samples into train/val/test
    random.shuffle(id_samples)

    n = len(id_samples)
    n_train = int(n * train_ratio / (1 - ood_ratio))
    n_val = int(n * val_ratio / (1 - ood_ratio))

    for i, s in enumerate(id_samples):
        if i < n_train:
            s["split"] = "train"
        elif i < n_train + n_val:
            s["split"] = "val"
        else:
            s["split"] = "test"

    return id_samples + ood_samples


def balance_classes(
    samples: list[dict],
    strategy: str = "oversample",  # oversample, undersample, or smote
    target_ratio: dict | None = None,
) -> list[dict]:
    """
    Balance classes for training.

    Default target: equal TP/FP (since UNCERTAIN is small)
    """
    if target_ratio is None:
        target_ratio = {"TP": 1.0, "FP": 1.0, "UNCERTAIN": 0.5}

    # Separate by class
    by_class = defaultdict(list)
    for s in samples:
        if s.get("split") == "train":
            by_class[s["verdict"]].append(s)

    if not by_class:
        return samples

    # Find target count
    max_count = max(len(v) for v in by_class.values())

    balanced = []
    for verdict, class_samples in by_class.items():
        ratio = target_ratio.get(verdict, 1.0)
        target_count = int(max_count * ratio)

        if strategy == "oversample":
            # Repeat samples to reach target
            while len(class_samples) < target_count:
                class_samples.extend(
                    random.sample(
                        class_samples, min(len(class_samples), target_count - len(class_samples))
                    )
                )
        elif strategy == "undersample":
            # Sample down to match smallest class
            min_count = min(len(v) for v in by_class.values())
            class_samples = random.sample(class_samples, min_count)

        balanced.extend(class_samples)

    # Add non-train samples
    for s in samples:
        if s.get("split") != "train":
            balanced.append(s)

    return balanced


# =============================================================================
# MAIN ENHANCEMENT PIPELINE
# =============================================================================


def enhance_sample(sample: dict) -> dict:
    """Apply all enhancements to a single sample."""
    code = sample.get("code_snippet", "")
    language = sample.get("language", "python")
    finding = sample.get("finding", {})

    enhanced = dict(sample)

    # Tokenization
    token_info = tokenize_code(code, language)
    enhanced["tokens"] = token_info["tokens"]
    enhanced["token_count"] = token_info["token_count"]

    # Sliding windows (for long code)
    focal_line = finding.get("line", 0) - sample.get("span", {}).get("start_line", 0)
    enhanced["windows"] = create_sliding_windows(code, focal_line)
    enhanced["focal_line_offset"] = focal_line

    # AST extraction
    if language == "python":
        ast_info = extract_python_ast(code)
    else:
        ast_info = extract_js_ast_simple(code)

    enhanced["ast_nodes"] = ast_info.get("nodes", [])
    enhanced["ast_edges"] = ast_info.get("edges", [])
    enhanced["ast_node_count"] = ast_info.get("node_count", 0)
    enhanced["ast_edge_count"] = ast_info.get("edge_count", 0)

    # Feature engineering
    enhanced["features"] = extract_features(sample)

    return enhanced


@app.command()
def enhance(
    input_labels: Path = typer.Option(Path("datasets/gold/gold_labels.jsonl")),
    input_items: Path = typer.Option(Path("datasets/gold/selected_items.jsonl")),
    output_dir: Path = typer.Option(Path("datasets/enhanced")),
    ood_strategy: str = typer.Option("repo", help="OOD split strategy: repo, category, or rule"),
    balance: bool = typer.Option(True, help="Balance training classes"),
    seed: int = typer.Option(42),
) -> None:
    """Enhance dataset for deep learning training."""

    output_dir.mkdir(parents=True, exist_ok=True)

    # Load data
    print("Loading data...")
    labels = {}
    with open(input_labels, encoding="utf-8") as f:
        for line in f:
            item = json.loads(line)
            labels[item["sample_id"]] = item

    samples = []
    with open(input_items, encoding="utf-8") as f:
        for line in f:
            item = json.loads(line)
            sample_id = item.get("sample_id")
            if sample_id in labels:
                # Merge labels with item data
                merged = {**item, **labels[sample_id]}
                samples.append(merged)

    print(f"Loaded {len(samples)} labeled samples")

    # Enhance samples
    print("Enhancing samples...")
    enhanced_samples = []
    for i, sample in enumerate(samples):
        enhanced = enhance_sample(sample)
        enhanced_samples.append(enhanced)
        if (i + 1) % 100 == 0:
            print(f"  Enhanced {i + 1}/{len(samples)}")

    # Create splits
    print(f"Creating splits (OOD strategy: {ood_strategy})...")
    enhanced_samples = create_splits(
        enhanced_samples,
        ood_strategy=ood_strategy,
        seed=seed,
    )

    # Balance if requested
    if balance:
        print("Balancing training classes...")
        enhanced_samples = balance_classes(enhanced_samples)

    # Compute statistics
    split_counts = Counter(s.get("split", "unknown") for s in enhanced_samples)
    verdict_counts = Counter(s.get("verdict", "unknown") for s in enhanced_samples)

    print("\n=== Split Distribution ===")
    for split, count in sorted(split_counts.items()):
        print(f"  {split}: {count}")

    print("\n=== Verdict Distribution (after balancing) ===")
    train_verdicts = Counter(s["verdict"] for s in enhanced_samples if s.get("split") == "train")
    for verdict, count in train_verdicts.most_common():
        print(f"  {verdict}: {count}")

    # Save enhanced dataset
    print("\nSaving enhanced dataset...")

    # Save by split
    for split in ["train", "val", "test", "ood_test"]:
        split_samples = [s for s in enhanced_samples if s.get("split") == split]
        if split_samples:
            split_file = output_dir / f"{split}.jsonl"
            with open(split_file, "w", encoding="utf-8") as f:
                for s in split_samples:
                    f.write(json.dumps(s, ensure_ascii=False) + "\n")
            print(f"  Saved {len(split_samples)} samples to {split_file}")

    # Save full dataset
    full_file = output_dir / "all_enhanced.jsonl"
    with open(full_file, "w", encoding="utf-8") as f:
        for s in enhanced_samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"  Saved all {len(enhanced_samples)} samples to {full_file}")

    # Save feature names for later use
    if enhanced_samples:
        feature_names = list(enhanced_samples[0].get("features", {}).keys())
        with open(output_dir / "feature_names.json", "w") as f:
            json.dump(feature_names, f, indent=2)
        print(f"  Saved {len(feature_names)} feature names")

    # Save metadata
    metadata = {
        "total_samples": len(enhanced_samples),
        "splits": dict(split_counts),
        "verdicts": dict(verdict_counts),
        "ood_strategy": ood_strategy,
        "seed": seed,
        "balanced": balance,
    }
    with open(output_dir / "metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    print("\n✅ Enhancement complete!")


@app.command()
def stats(
    input_dir: Path = typer.Option(Path("datasets/enhanced")),
) -> None:
    """Show statistics for enhanced dataset."""

    metadata_file = input_dir / "metadata.json"
    if metadata_file.exists():
        with open(metadata_file) as f:
            metadata = json.load(f)
        print("=== Dataset Metadata ===")
        for k, v in metadata.items():
            print(f"  {k}: {v}")

    # Load and analyze
    all_file = input_dir / "all_enhanced.jsonl"
    if not all_file.exists():
        print(f"No enhanced dataset found at {all_file}")
        return

    samples = []
    with open(all_file, encoding="utf-8") as f:
        for line in f:
            samples.append(json.loads(line))

    print(f"\n=== {len(samples)} Total Samples ===")

    # Token statistics
    token_counts = [s.get("token_count", 0) for s in samples]
    print(
        f"\nToken counts: min={min(token_counts)}, max={max(token_counts)}, avg={sum(token_counts)/len(token_counts):.1f}"
    )

    # AST statistics
    ast_nodes = [s.get("ast_node_count", 0) for s in samples]
    print(
        f"AST nodes: min={min(ast_nodes)}, max={max(ast_nodes)}, avg={sum(ast_nodes)/len(ast_nodes):.1f}"
    )

    # Feature statistics
    if samples and "features" in samples[0]:
        features = samples[0]["features"]
        print(f"\nEngineered features: {len(features)}")
        for name in list(features.keys())[:10]:
            print(f"  - {name}")
        if len(features) > 10:
            print(f"  ... and {len(features) - 10} more")


if __name__ == "__main__":
    app()
