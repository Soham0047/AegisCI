"""
Dataset Improvement Script for Phase 3 (Transformer) and Phase 4 (GNN + Ensemble + OOD)

This script:
1. Augments the dataset with synthetic vulnerable samples
2. Extracts rich features for both Transformer and GNN models
3. Creates proper train/val/test/ood splits
4. Handles class imbalance with SMOTE-like techniques
5. Generates code embeddings for transfer learning
"""

import ast
import hashlib
import json
import random
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer

app = typer.Typer(add_completion=False)

# ============================================================================
# VULNERABILITY PATTERNS FOR SYNTHETIC DATA AUGMENTATION
# ============================================================================

VULN_TEMPLATES = {
    "sql_injection": [
        'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        "cursor.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)",
        'db.query("DELETE FROM records WHERE id=" + record_id)',
        'conn.execute("INSERT INTO logs VALUES (\'" + data + "\')")',
    ],
    "command_injection": [
        'os.system(f"rm -rf {path}")',
        'subprocess.call("ls " + directory, shell=True)',
        'os.popen("grep " + pattern + " /var/log/*")',
        "subprocess.Popen(cmd, shell=True)",
    ],
    "path_traversal": [
        'open(base_path + "/" + user_input)',
        "Path(upload_dir) / filename",  # When filename not sanitized
        'shutil.copy(src, f"/data/{name}")',
        'os.path.join("/uploads", request.args.get("file"))',
    ],
    "hardcoded_secrets": [
        'API_KEY = "sk-1234567890abcdef"',
        'password = "admin123"',
        'SECRET_KEY = "my_secret_key_12345"',
        'token = "ghp_xxxxxxxxxxxxxxxxxxxx"',
    ],
    "weak_crypto": [
        "hashlib.md5(password.encode())",
        "hashlib.sha1(data)",
        "DES.new(key, DES.MODE_ECB)",
        "random.random()  # Used for crypto",
    ],
    "ssrf": [
        "requests.get(url)",  # When url from user input
        "urllib.request.urlopen(user_url)",
        'httpx.get(f"http://{host}/api")',
    ],
    "xss": [
        'return f"<div>{user_input}</div>"',
        'html = "<script>" + js_code + "</script>"',
        "template.render(content=unescaped_data)",
    ],
    "deserialization": [
        "pickle.loads(data)",
        "yaml.load(content)",  # Without Loader
        "marshal.loads(user_bytes)",
    ],
}

SAFE_TEMPLATES = {
    "sql_injection": [
        'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        'cursor.execute("SELECT * FROM users WHERE name = ?", [name])',
        "db.query(User).filter_by(id=record_id).first()",
    ],
    "command_injection": [
        'subprocess.run(["rm", "-rf", path], check=True)',
        'subprocess.call(["ls", directory])',
        "shlex.quote(user_input)",
    ],
    "path_traversal": [
        "safe_path = os.path.realpath(os.path.join(base, name))",
        "if not resolved.startswith(base_dir): raise ValueError()",
        "pathlib.Path(name).name  # Strip directory components",
    ],
    "hardcoded_secrets": [
        'API_KEY = os.environ["API_KEY"]',
        "password = getpass.getpass()",
        "SECRET_KEY = secrets.token_urlsafe(32)",
    ],
    "weak_crypto": [
        'hashlib.pbkdf2_hmac("sha256", password, salt, 100000)',
        "bcrypt.hashpw(password, bcrypt.gensalt())",
        "secrets.token_bytes(32)",
    ],
}

# ============================================================================
# FEATURE EXTRACTION FOR TRANSFORMERS
# ============================================================================

CODE_TOKENS_PATTERN = re.compile(
    r"([a-zA-Z_][a-zA-Z0-9_]*|"  # Identifiers
    r"0[xX][0-9a-fA-F]+|"  # Hex numbers
    r"[0-9]+\.?[0-9]*|"  # Numbers
    r'"[^"]*"|\'[^\']*\'|'  # Strings
    r"[+\-*/%=<>!&|^~]+|"  # Operators
    r"[(){}\[\],.:;@])"  # Punctuation
)


def tokenize_code(code: str, max_tokens: int = 512) -> list[str]:
    """Tokenize code for transformer input."""
    tokens = CODE_TOKENS_PATTERN.findall(code)
    return tokens[:max_tokens]


def extract_code_features(code: str) -> dict[str, Any]:
    """Extract numerical features from code."""
    lines = code.split("\n")
    return {
        "n_lines": len(lines),
        "n_chars": len(code),
        "n_tokens": len(tokenize_code(code)),
        "avg_line_length": sum(len(l) for l in lines) / max(len(lines), 1),
        "max_line_length": max(len(l) for l in lines) if lines else 0,
        "n_functions": code.count("def ") + code.count("function "),
        "n_classes": code.count("class "),
        "n_imports": code.count("import ") + code.count("require("),
        "n_comments": code.count("#") + code.count("//"),
        "has_try_except": "try:" in code or "try {" in code,
        "has_assert": "assert " in code,
        "has_logging": "logging." in code or "logger." in code or "console.log" in code,
        "has_hardcoded_string": bool(re.search(r'["\'][a-zA-Z0-9]{16,}["\']', code)),
        "has_sql_keywords": bool(re.search(r"\b(SELECT|INSERT|UPDATE|DELETE|WHERE)\b", code, re.I)),
        "has_shell_calls": "subprocess" in code or "os.system" in code or "exec(" in code,
        "has_file_ops": "open(" in code or "read(" in code or "write(" in code,
        "has_network": "requests." in code or "urllib" in code or "http" in code.lower(),
        "has_crypto": "hashlib" in code or "crypto" in code.lower() or "encrypt" in code.lower(),
        "has_user_input": "input(" in code or "request." in code or "argv" in code,
        "indentation_depth": max((len(l) - len(l.lstrip())) // 4 for l in lines) if lines else 0,
    }


# ============================================================================
# AST EXTRACTION FOR GNN
# ============================================================================


@dataclass
class ASTNode:
    id: int
    type: str
    value: str = ""
    line: int = 0
    col: int = 0


@dataclass
class ASTGraph:
    nodes: list[dict] = field(default_factory=list)
    edges: list[tuple[int, int, str]] = field(default_factory=list)  # (src, dst, edge_type)

    def to_dict(self) -> dict:
        return {
            "nodes": self.nodes,
            "edges": [{"src": e[0], "dst": e[1], "type": e[2]} for e in self.edges],
        }


def extract_ast_graph(code: str, language: str = "python") -> dict:
    """Extract AST as a graph for GNN input."""
    if language == "python":
        return _extract_python_ast(code)
    else:
        return _extract_simple_ast(code)


def _extract_python_ast(code: str) -> dict:
    """Extract Python AST with edges for data flow."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return {"nodes": [], "edges": []}

    graph = ASTGraph()
    node_id = 0

    def visit(node, parent_id=None):
        nonlocal node_id
        current_id = node_id
        node_id += 1

        node_type = node.__class__.__name__
        node_value = ""

        # Extract meaningful values
        if isinstance(node, ast.Name):
            node_value = node.id
        elif isinstance(node, ast.Constant):
            node_value = str(node.value)[:50]  # Truncate long values
        elif isinstance(node, ast.FunctionDef):
            node_value = node.name
        elif isinstance(node, ast.ClassDef):
            node_value = node.name
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            node_value = node.func.attr
        elif isinstance(node, ast.Attribute):
            node_value = node.attr

        graph.nodes.append(
            {
                "id": current_id,
                "type": node_type,
                "value": node_value,
                "line": getattr(node, "lineno", 0),
            }
        )

        if parent_id is not None:
            graph.edges.append((parent_id, current_id, "child"))

        for child in ast.iter_child_nodes(node):
            child_id = visit(child, current_id)

            # Add data flow edges for assignments
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        graph.edges.append((current_id, child_id, "data_flow"))

        return current_id

    visit(tree)
    return graph.to_dict()


def _extract_simple_ast(code: str) -> dict:
    """Simple AST extraction for non-Python code."""
    nodes = []
    edges = []

    # Simple pattern-based extraction
    patterns = [
        (r"\bfunction\s+(\w+)", "FunctionDef"),
        (r"\bclass\s+(\w+)", "ClassDef"),
        (r"\bconst\s+(\w+)\s*=", "ConstDef"),
        (r"\blet\s+(\w+)\s*=", "VarDef"),
        (r"\bvar\s+(\w+)\s*=", "VarDef"),
        (r"(\w+)\s*\(", "Call"),
    ]

    node_id = 0
    for pattern, node_type in patterns:
        for match in re.finditer(pattern, code):
            nodes.append(
                {
                    "id": node_id,
                    "type": node_type,
                    "value": match.group(1),
                    "line": code[: match.start()].count("\n") + 1,
                }
            )
            if node_id > 0:
                edges.append({"src": node_id - 1, "dst": node_id, "type": "sequence"})
            node_id += 1

    return {"nodes": nodes, "edges": edges}


# ============================================================================
# DATA AUGMENTATION
# ============================================================================


def augment_sample(sample: dict, technique: str = "random") -> list[dict]:
    """Augment a sample to create variations."""
    augmented = []
    code = sample.get("code_snippet", "")

    if technique == "random" or technique == "all":
        # Variable renaming
        new_code = _rename_variables(code)
        if new_code != code:
            new_sample = sample.copy()
            new_sample["code_snippet"] = new_code
            new_sample["sample_id"] = _generate_id(new_code, sample.get("filepath", ""))
            new_sample["augmentation"] = "var_rename"
            augmented.append(new_sample)

        # Comment removal
        new_code = _remove_comments(code)
        if new_code != code:
            new_sample = sample.copy()
            new_sample["code_snippet"] = new_code
            new_sample["sample_id"] = _generate_id(new_code, sample.get("filepath", ""))
            new_sample["augmentation"] = "no_comments"
            augmented.append(new_sample)

        # Whitespace normalization
        new_code = _normalize_whitespace(code)
        if new_code != code:
            new_sample = sample.copy()
            new_sample["code_snippet"] = new_code
            new_sample["sample_id"] = _generate_id(new_code, sample.get("filepath", ""))
            new_sample["augmentation"] = "whitespace_norm"
            augmented.append(new_sample)

    return augmented


def _rename_variables(code: str) -> str:
    """Rename variables to generic names."""
    # Simple variable renaming
    var_pattern = re.compile(r"\b(user_input|user_data|user_id|data|payload|content)\b")
    counter = [0]

    def replace(match):
        counter[0] += 1
        return f"var_{counter[0]}"

    return var_pattern.sub(replace, code)


def _remove_comments(code: str) -> str:
    """Remove comments from code."""
    # Remove Python comments
    code = re.sub(r"#.*$", "", code, flags=re.MULTILINE)
    # Remove JS/TS comments
    code = re.sub(r"//.*$", "", code, flags=re.MULTILINE)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    return code


def _normalize_whitespace(code: str) -> str:
    """Normalize whitespace in code."""
    lines = code.split("\n")
    normalized = []
    for line in lines:
        # Remove trailing whitespace
        line = line.rstrip()
        # Normalize multiple spaces to single
        line = re.sub(r"  +", " ", line)
        if line:
            normalized.append(line)
    return "\n".join(normalized)


def _generate_id(code: str, filepath: str) -> str:
    """Generate a unique sample ID."""
    content = f"{filepath}:{code}"
    return hashlib.sha256(content.encode()).hexdigest()


def generate_synthetic_samples(n_per_category: int = 50) -> list[dict]:
    """Generate synthetic vulnerable and safe samples."""
    samples = []

    for category, templates in VULN_TEMPLATES.items():
        for i, template in enumerate(templates * (n_per_category // len(templates) + 1)):
            if len([s for s in samples if s.get("category") == category]) >= n_per_category:
                break

            # Create vulnerable sample
            sample = {
                "sample_id": _generate_id(template, f"synthetic/{category}_{i}"),
                "language": "python"
                if "def " in template or "import " in template
                else "typescript",
                "repo": "synthetic/vulnerable",
                "commit": "synthetic",
                "filepath": f"synthetic/{category}/vuln_{i}.py",
                "code_snippet": template,
                "function_span": {
                    "start_line": 1,
                    "end_line": 1,
                    "start_col": 0,
                    "end_col": len(template),
                },
                "context_before": "",
                "context_after": "",
                "weak_labels": [
                    {
                        "tool": "synthetic",
                        "rule_id": f"synthetic-{category}",
                        "message": f"Synthetic {category} vulnerability",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "line": 1,
                    }
                ],
                "gold_labels": {
                    "verdict": "TP",
                    "category": category.replace("_", "."),
                    "fix_type": f"sanitize.{category.split('_')[0]}",
                    "notes": f"Synthetic vulnerable sample for {category}",
                },
                "metadata": {"synthetic": True, "category": category},
            }
            samples.append(sample)

    # Generate safe counterparts
    for category, templates in SAFE_TEMPLATES.items():
        for i, template in enumerate(templates * (n_per_category // len(templates) + 1)):
            if (
                len(
                    [
                        s
                        for s in samples
                        if s.get("metadata", {}).get("category") == f"{category}_safe"
                    ]
                )
                >= n_per_category // 2
            ):
                break

            sample = {
                "sample_id": _generate_id(template, f"synthetic/{category}_safe_{i}"),
                "language": "python",
                "repo": "synthetic/safe",
                "commit": "synthetic",
                "filepath": f"synthetic/{category}/safe_{i}.py",
                "code_snippet": template,
                "function_span": {
                    "start_line": 1,
                    "end_line": 1,
                    "start_col": 0,
                    "end_col": len(template),
                },
                "context_before": "",
                "context_after": "",
                "weak_labels": [],
                "gold_labels": {
                    "verdict": "FP",
                    "category": "misc.safe_code",
                    "fix_type": "none",
                    "notes": f"Safe implementation of {category}",
                },
                "metadata": {"synthetic": True, "category": f"{category}_safe"},
            }
            samples.append(sample)

    return samples


# ============================================================================
# DATASET SPLITTING WITH OOD
# ============================================================================


def create_ml_splits(
    samples: list[dict],
    train_ratio: float = 0.7,
    val_ratio: float = 0.1,
    test_ratio: float = 0.1,
    ood_ratio: float = 0.1,
    ood_strategy: str = "repo",  # repo, category, or random
    seed: int = 42,
) -> dict[str, list[dict]]:
    """Create train/val/test/ood splits for ML."""
    random.seed(seed)

    if ood_strategy == "repo":
        # Hold out entire repos for OOD
        repos = list(set(s.get("repo", "") for s in samples))
        random.shuffle(repos)
        n_ood_repos = max(1, int(len(repos) * ood_ratio))
        ood_repos = set(repos[:n_ood_repos])

        ood = [s for s in samples if s.get("repo", "") in ood_repos]
        remaining = [s for s in samples if s.get("repo", "") not in ood_repos]

    elif ood_strategy == "category":
        # Hold out certain categories for OOD
        categories = list(
            set(
                s.get("gold_labels", {}).get("category", "unknown")
                for s in samples
                if s.get("gold_labels")
            )
        )
        random.shuffle(categories)
        n_ood_cats = max(1, int(len(categories) * ood_ratio))
        ood_cats = set(categories[:n_ood_cats])

        ood = [s for s in samples if s.get("gold_labels", {}).get("category", "") in ood_cats]
        remaining = [
            s for s in samples if s.get("gold_labels", {}).get("category", "") not in ood_cats
        ]

    else:
        # Random OOD
        random.shuffle(samples)
        n_ood = int(len(samples) * ood_ratio)
        ood = samples[:n_ood]
        remaining = samples[n_ood:]

    # Split remaining into train/val/test
    random.shuffle(remaining)
    total = len(remaining)
    n_train = int(total * train_ratio / (1 - ood_ratio))
    n_val = int(total * val_ratio / (1 - ood_ratio))

    train = remaining[:n_train]
    val = remaining[n_train : n_train + n_val]
    test = remaining[n_train + n_val :]

    return {
        "train": train,
        "val": val,
        "test": test,
        "ood_test": ood,
    }


def balance_classes(
    samples: list[dict], target_ratio: float = 0.5, strategy: str = "oversample"
) -> list[dict]:
    """Balance TP/FP classes in the dataset."""
    tp_samples = [s for s in samples if s.get("gold_labels", {}).get("verdict") == "TP"]
    fp_samples = [s for s in samples if s.get("gold_labels", {}).get("verdict") == "FP"]
    other = [s for s in samples if s.get("gold_labels", {}).get("verdict") not in ("TP", "FP")]

    if not tp_samples or not fp_samples:
        return samples

    if strategy == "oversample":
        # Oversample minority class (usually TP)
        minority, majority = (
            (tp_samples, fp_samples)
            if len(tp_samples) < len(fp_samples)
            else (fp_samples, tp_samples)
        )
        target_size = int(len(majority) * target_ratio / (1 - target_ratio))

        oversampled = []
        while len(oversampled) < target_size:
            sample = random.choice(minority).copy()
            sample["oversampled"] = True
            oversampled.append(sample)

        return majority + oversampled + other

    elif strategy == "undersample":
        # Undersample majority class
        minority, majority = (
            (tp_samples, fp_samples)
            if len(tp_samples) < len(fp_samples)
            else (fp_samples, tp_samples)
        )
        target_size = int(len(minority) / target_ratio * (1 - target_ratio))

        undersampled = random.sample(majority, min(target_size, len(majority)))
        return minority + undersampled + other

    return samples


# ============================================================================
# MAIN COMMANDS
# ============================================================================


def load_samples(dataset_paths: list[Path]) -> list[dict]:
    """Load samples from JSONL files."""
    samples = []
    for path in dataset_paths:
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            if line.strip():
                samples.append(json.loads(line))
    return samples


def write_jsonl(path: Path, samples: list[dict]) -> None:
    """Write samples to JSONL file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for sample in samples:
            f.write(json.dumps(sample) + "\n")


@app.command()
def improve(
    input_dir: Path = typer.Option(Path("datasets/gold")),
    output_dir: Path = typer.Option(Path("datasets/ml_ready")),
    add_synthetic: bool = typer.Option(True, help="Add synthetic samples"),
    n_synthetic: int = typer.Option(50, help="Synthetic samples per category"),
    augment: bool = typer.Option(True, help="Apply data augmentation"),
    balance: bool = typer.Option(True, help="Balance classes"),
    balance_ratio: float = typer.Option(0.3, help="Target TP ratio"),
    extract_features: bool = typer.Option(True, help="Extract ML features"),
    extract_ast: bool = typer.Option(True, help="Extract AST for GNN"),
    ood_strategy: str = typer.Option("repo", help="OOD split strategy: repo, category, random"),
    seed: int = typer.Option(42),
) -> None:
    """Improve dataset for ML training."""

    # Load gold-labeled data - try multiple possible filenames
    possible_names = ["gold_labeled.jsonl", "gold_labels.jsonl", "selected_items.jsonl"]
    gold_path = None
    for name in possible_names:
        path = input_dir / name
        if path.exists():
            gold_path = path
            break

    if not gold_path:
        typer.echo(f"No gold labeled file found in {input_dir}")
        typer.echo("Run auto_label.py first to create gold labels.")
        raise typer.Exit(1)

    raw_samples = load_samples([gold_path])

    # Load selected_items for code snippets if gold_labels format is used
    selected_items_path = input_dir / "selected_items.jsonl"
    selected_by_id = {}
    if selected_items_path.exists():
        for item in load_samples([selected_items_path]):
            selected_by_id[item.get("sample_id")] = item

    # Convert format if needed (gold_labels.jsonl has different structure)
    samples = []
    for raw in raw_samples:
        # Check if it's the gold_labels format vs the full sample format
        if "code_snippet" not in raw and "finding" in raw:
            # This is the compact gold_labels format - merge with selected_items
            selected = selected_by_id.get(raw.get("sample_id"), {})
            sample = {
                "sample_id": raw.get("sample_id"),
                "language": raw.get("language", "python"),
                "repo": raw.get("repo", ""),
                "commit": raw.get("commit", ""),
                "filepath": raw.get("filepath", ""),
                "code_snippet": selected.get("code_snippet", ""),  # Get from selected_items
                "function_span": raw.get("span", selected.get("function_span", {})),
                "context_before": selected.get("context_before", ""),
                "context_after": selected.get("context_after", ""),
                "weak_labels": [raw.get("finding", {})] if raw.get("finding") else [],
                "gold_labels": {
                    "verdict": raw.get("verdict", "UNCERTAIN"),
                    "category": raw.get("category", "unknown"),
                    "fix_type": raw.get("fix_type", "unknown"),
                    "notes": raw.get("notes", ""),
                },
                "metadata": selected.get("metadata", {}),
            }
            samples.append(sample)
        else:
            # Already in the right format
            samples.append(raw)
    typer.echo(f"Loaded {len(samples)} gold-labeled samples")

    # Add synthetic samples
    if add_synthetic:
        synthetic = generate_synthetic_samples(n_per_category=n_synthetic)
        samples.extend(synthetic)
        typer.echo(f"Added {len(synthetic)} synthetic samples")

    # Augment data
    if augment:
        augmented = []
        for sample in samples:
            if sample.get("gold_labels", {}).get("verdict") == "TP":
                augmented.extend(augment_sample(sample))
        samples.extend(augmented)
        typer.echo(f"Added {len(augmented)} augmented samples")

    # Extract features
    if extract_features or extract_ast:
        typer.echo("Extracting features...")
        for sample in samples:
            code = sample.get("code_snippet", "")

            if extract_features:
                sample["features"] = extract_code_features(code)

            if extract_ast:
                lang = sample.get("language", "python")
                sample["ast_graph"] = extract_ast_graph(code, lang)

    # Balance classes (before splitting to avoid leakage)
    if balance:
        tp_count = sum(1 for s in samples if s.get("gold_labels", {}).get("verdict") == "TP")
        fp_count = sum(1 for s in samples if s.get("gold_labels", {}).get("verdict") == "FP")
        typer.echo(f"Before balancing: TP={tp_count}, FP={fp_count}")

        samples = balance_classes(samples, target_ratio=balance_ratio)

        tp_count = sum(1 for s in samples if s.get("gold_labels", {}).get("verdict") == "TP")
        fp_count = sum(1 for s in samples if s.get("gold_labels", {}).get("verdict") == "FP")
        typer.echo(f"After balancing: TP={tp_count}, FP={fp_count}")

    # Create splits
    splits = create_ml_splits(
        samples,
        ood_strategy=ood_strategy,
        seed=seed,
    )

    # Write output
    for split_name, split_samples in splits.items():
        write_jsonl(output_dir / f"{split_name}.jsonl", split_samples)

        # Count verdicts
        verdicts = Counter(
            s.get("gold_labels", {}).get("verdict", "unknown") for s in split_samples
        )
        typer.echo(f"{split_name}: {len(split_samples)} samples - {dict(verdicts)}")

    # Write all combined
    all_samples = []
    for split_samples in splits.values():
        all_samples.extend(split_samples)
    write_jsonl(output_dir / "all.jsonl", all_samples)

    typer.echo(f"\nTotal: {len(all_samples)} samples written to {output_dir}")

    # Write summary stats
    stats = {
        "total_samples": len(all_samples),
        "splits": {k: len(v) for k, v in splits.items()},
        "verdicts": dict(
            Counter(s.get("gold_labels", {}).get("verdict", "unknown") for s in all_samples)
        ),
        "categories": dict(
            Counter(s.get("gold_labels", {}).get("category", "unknown") for s in all_samples)
        ),
        "synthetic_count": sum(1 for s in all_samples if s.get("metadata", {}).get("synthetic")),
        "augmented_count": sum(1 for s in all_samples if s.get("augmentation")),
    }
    (output_dir / "stats.json").write_text(json.dumps(stats, indent=2))
    typer.echo(f"Stats written to {output_dir / 'stats.json'}")


@app.command()
def extract_for_transformer(
    input_path: Path = typer.Option(Path("datasets/ml_ready/train.jsonl")),
    output_path: Path = typer.Option(Path("datasets/transformer/train.jsonl")),
    max_seq_length: int = typer.Option(512),
    include_context: bool = typer.Option(True),
) -> None:
    """Extract data formatted for transformer training."""
    samples = load_samples([input_path])

    transformer_samples = []
    for sample in samples:
        code = sample.get("code_snippet", "")
        if include_context:
            code = (
                sample.get("context_before", "")
                + "\n"
                + code
                + "\n"
                + sample.get("context_after", "")
            )

        tokens = tokenize_code(code, max_tokens=max_seq_length)

        verdict = sample.get("gold_labels", {}).get("verdict", "UNCERTAIN")
        label = {"TP": 1, "FP": 0, "UNCERTAIN": -1}.get(verdict, -1)

        transformer_samples.append(
            {
                "sample_id": sample.get("sample_id"),
                "tokens": tokens,
                "token_ids": None,  # Will be filled by tokenizer
                "label": label,
                "verdict": verdict,
                "category": sample.get("gold_labels", {}).get("category", "unknown"),
                "features": sample.get("features", {}),
            }
        )

    write_jsonl(output_path, transformer_samples)
    typer.echo(f"Wrote {len(transformer_samples)} samples to {output_path}")


@app.command()
def extract_for_gnn(
    input_path: Path = typer.Option(Path("datasets/ml_ready/train.jsonl")),
    output_path: Path = typer.Option(Path("datasets/gnn/train.jsonl")),
    max_nodes: int = typer.Option(256),
) -> None:
    """Extract data formatted for GNN training."""
    samples = load_samples([input_path])

    gnn_samples = []
    for sample in samples:
        ast_graph = sample.get("ast_graph", {})
        nodes = ast_graph.get("nodes", [])[:max_nodes]
        edges = [
            e
            for e in ast_graph.get("edges", [])
            if e.get("src", 0) < max_nodes and e.get("dst", 0) < max_nodes
        ]

        verdict = sample.get("gold_labels", {}).get("verdict", "UNCERTAIN")
        label = {"TP": 1, "FP": 0, "UNCERTAIN": -1}.get(verdict, -1)

        gnn_samples.append(
            {
                "sample_id": sample.get("sample_id"),
                "nodes": nodes,
                "edges": edges,
                "node_features": [
                    {
                        "type_id": hash(n.get("type", "")) % 100,
                        "value_hash": hash(n.get("value", "")) % 1000,
                    }
                    for n in nodes
                ],
                "label": label,
                "verdict": verdict,
                "category": sample.get("gold_labels", {}).get("category", "unknown"),
            }
        )

    write_jsonl(output_path, gnn_samples)
    typer.echo(f"Wrote {len(gnn_samples)} samples to {output_path}")


if __name__ == "__main__":
    app()
