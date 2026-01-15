#!/usr/bin/env python3
"""
Enhanced ML Training Pipeline

Complete pipeline using all 5 enhanced scanners:
1. Generate weak labels using enhanced scanners (Bandit, Semgrep, Secrets, Patterns, Dependencies)
2. Apply consensus scoring and create gold labels
3. Prepare training datasets for Transformer and GNN
4. Train all models (Transformer, GNN, Ensemble)
5. Export and validate model artifacts

Usage:
    python scripts/enhanced_pipeline.py full --target .
    python scripts/enhanced_pipeline.py weak-labels --target .
    python scripts/enhanced_pipeline.py gold-labels
    python scripts/enhanced_pipeline.py train --epochs 10
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

# Add project root to path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

app = typer.Typer(add_completion=False)
console = Console()

# Categories for classification
CATEGORY_VOCAB = [
    "injection.sql",
    "injection.command",
    "injection.xss",
    "crypto.weak",
    "crypto.hardcoded_key",
    "auth.broken",
    "auth.session",
    "secrets.hardcoded",
    "secrets.api_key",
    "deserialization.unsafe",
    "path.traversal",
    "ssrf",
    "unsafe.exec",
    "unsafe.eval",
    "dos.regex",
    "resource.leak",
    "other",
]


@dataclass
class WeakLabel:
    """A weak label from a scanner."""
    
    sample_id: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    scanner: str
    rule_id: str
    severity: str
    confidence: str
    category: str
    message: str
    
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass 
class GoldLabel:
    """A gold label with consensus scoring."""
    
    sample_id: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    
    # Consensus info
    scanner_count: int
    scanners: list[str]
    consensus_score: float
    
    # Label
    verdict: str  # TP, FP, UNCERTAIN
    label: int  # 1=TP, 0=FP, -1=UNCERTAIN
    category: str
    severity: str
    confidence: str
    
    # Features for ML
    features: dict[str, Any]
    
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def collect_files(target_path: Path, extensions: set[str]) -> list[Path]:
    """Recursively collect files with given extensions."""
    skip_dirs = {
        ".git", ".venv", "venv", "node_modules", "__pycache__",
        ".mypy_cache", ".pytest_cache", "dist", "build", ".tox"
    }
    
    files = []
    for root, dirs, filenames in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
        for filename in filenames:
            if Path(filename).suffix in extensions:
                files.append(Path(root) / filename)
    
    return files


def read_code_snippet(file_path: str, line_start: int, line_end: int, context: int = 3) -> str:
    """Read code snippet from file with context lines."""
    try:
        path = Path(file_path)
        if not path.exists():
            return ""
        
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        
        # Adjust bounds with context
        start = max(0, line_start - context - 1)
        end = min(len(lines), line_end + context)
        
        return "\n".join(lines[start:end])
    except Exception:
        return ""


def run_enhanced_scanners(target_path: Path, verbose: bool = True) -> list[WeakLabel]:
    """Run all 5 enhanced scanners and collect weak labels."""
    from guardian.scanners.bandit_scanner import run_bandit
    from guardian.scanners.dependency_scanner import run_dependency_scanner
    from guardian.scanners.pattern_scanner import run_comprehensive_scan
    from guardian.scanners.secrets_scanner import run_secrets_scanner
    from guardian.scanners.semgrep_scanner import run_semgrep
    
    weak_labels: list[WeakLabel] = []
    
    def ensure_code_snippet(code: str, file_path: str, line_start: int, line_end: int) -> str:
        """Ensure we have a code snippet, reading from file if necessary."""
        if code and len(code.strip()) > 0:
            return code
        return read_code_snippet(file_path, line_start, line_end)
    
    # Collect files
    py_files = collect_files(target_path, {".py"})
    js_files = collect_files(target_path, {".js", ".ts", ".jsx", ".tsx"})
    all_files = py_files + js_files
    
    if verbose:
        console.print(f"\n[cyan]Found {len(py_files)} Python, {len(js_files)} JS/TS files[/cyan]")
    
    # 1. Bandit (Python)
    if py_files:
        try:
            if verbose:
                console.print("  [dim]├── Running Bandit...[/dim]")
            py_file_strs = [str(f) for f in py_files]
            result = run_bandit(py_file_strs)
            for finding in result.get("results", []):
                file_path = finding.get("filename", "")
                line_start = finding.get("line_number", 0)
                line_end = finding.get("line_range", [0])[-1] if finding.get("line_range") else line_start
                code = ensure_code_snippet(finding.get("code", ""), file_path, line_start, line_end)
                weak_labels.append(WeakLabel(
                    sample_id=_generate_id(finding),
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    code_snippet=code,
                    scanner="bandit",
                    rule_id=finding.get("test_id", ""),
                    severity=finding.get("issue_severity", "MEDIUM"),
                    confidence=finding.get("issue_confidence", "MEDIUM"),
                    category=_map_bandit_category(finding.get("test_id", "")),
                    message=finding.get("issue_text", ""),
                ))
            if verbose:
                console.print(f"      [green]Found {len(result.get('results', []))} findings[/green]")
        except Exception as e:
            if verbose:
                console.print(f"      [yellow]⚠️ Bandit error: {e}[/yellow]")
    
    # 2. Semgrep
    if all_files:
        try:
            if verbose:
                console.print("  [dim]├── Running Semgrep...[/dim]")
            file_strs = [str(f) for f in all_files]
            result = run_semgrep(file_strs, config="p/ci")
            for finding in result.get("results", []):
                file_path = finding.get("path", "")
                line_start = finding.get("start", {}).get("line", 0)
                line_end = finding.get("end", {}).get("line", 0)
                code = ensure_code_snippet(finding.get("extra", {}).get("lines", ""), file_path, line_start, line_end)
                weak_labels.append(WeakLabel(
                    sample_id=_generate_id(finding),
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    code_snippet=code,
                    scanner="semgrep",
                    rule_id=finding.get("check_id", ""),
                    severity=finding.get("extra", {}).get("severity", "WARNING"),
                    confidence="HIGH",
                    category=_map_semgrep_category(finding.get("check_id", "")),
                    message=finding.get("extra", {}).get("message", ""),
                ))
            if verbose:
                console.print(f"      [green]Found {len(result.get('results', []))} findings[/green]")
        except Exception as e:
            if verbose:
                console.print(f"      [yellow]⚠️ Semgrep error: {e}[/yellow]")
    
    # 3. Secrets Scanner
    if all_files:
        try:
            if verbose:
                console.print("  [dim]├── Running Secrets Scanner...[/dim]")
            file_strs = [str(f) for f in all_files]
            result = run_secrets_scanner(file_strs)
            for finding in result.get("results", []):
                file_path = finding.get("path", "")
                line_start = finding.get("start", {}).get("line", 0)
                line_end = finding.get("end", {}).get("line", 0)
                code = ensure_code_snippet(finding.get("extra", {}).get("lines", ""), file_path, line_start, line_end)
                weak_labels.append(WeakLabel(
                    sample_id=_generate_id(finding),
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    code_snippet=code,
                    scanner="secrets",
                    rule_id=finding.get("check_id", ""),
                    severity="HIGH",
                    confidence="HIGH",
                    category="secrets.hardcoded",
                    message=finding.get("extra", {}).get("message", "Secret detected"),
                ))
            if verbose:
                console.print(f"      [green]Found {len(result.get('results', []))} findings[/green]")
        except Exception as e:
            if verbose:
                console.print(f"      [yellow]⚠️ Secrets error: {e}[/yellow]")
    
    # 4. Pattern Scanner
    if all_files:
        try:
            if verbose:
                console.print("  [dim]├── Running Pattern Scanner...[/dim]")
            file_strs = [str(f) for f in all_files]
            result = run_comprehensive_scan(file_strs)
            for finding in result.get("results", []):
                file_path = finding.get("path", "")
                line_start = finding.get("start", {}).get("line", 0)
                line_end = finding.get("end", {}).get("line", 0)
                code = ensure_code_snippet(finding.get("extra", {}).get("lines", ""), file_path, line_start, line_end)
                weak_labels.append(WeakLabel(
                    sample_id=_generate_id(finding),
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    code_snippet=code,
                    scanner="patterns",
                    rule_id=finding.get("check_id", ""),
                    severity=finding.get("extra", {}).get("severity", "MEDIUM"),
                    confidence="MEDIUM",
                    category=_map_pattern_category(finding.get("check_id", "")),
                    message=finding.get("extra", {}).get("message", ""),
                ))
            if verbose:
                console.print(f"      [green]Found {len(result.get('results', []))} findings[/green]")
        except Exception as e:
            if verbose:
                console.print(f"      [yellow]⚠️ Pattern error: {e}[/yellow]")
    
    # 5. Dependency Scanner
    try:
        if verbose:
            console.print("  [dim]└── Running Dependency Scanner...[/dim]")
        result = run_dependency_scanner(directory=str(target_path))
        for finding in result.get("results", []):
            file_path = finding.get("path", "")
            line_start = finding.get("start", {}).get("line", 0)
            line_end = finding.get("end", {}).get("line", 0)
            code = ensure_code_snippet(finding.get("extra", {}).get("lines", ""), file_path, line_start, line_end)
            weak_labels.append(WeakLabel(
                sample_id=_generate_id(finding),
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                code_snippet=code,
                scanner="dependencies",
                rule_id=finding.get("check_id", ""),
                severity=finding.get("extra", {}).get("severity", "HIGH"),
                confidence="HIGH",
                category="other",
                message=finding.get("extra", {}).get("message", ""),
            ))
        if verbose:
            console.print(f"      [green]Found {len(result.get('results', []))} findings[/green]")
    except Exception as e:
        if verbose:
            console.print(f"      [yellow]⚠️ Dependency error: {e}[/yellow]")
    
    return weak_labels


def _generate_id(finding: dict) -> str:
    """Generate unique ID for a finding."""
    content = json.dumps(finding, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _map_bandit_category(test_id: str) -> str:
    """Map Bandit test ID to category."""
    mappings = {
        "B101": "other",  # assert
        "B102": "unsafe.exec",
        "B103": "other",  # chmod
        "B104": "other",  # hardcoded bind
        "B105": "secrets.hardcoded",
        "B106": "secrets.hardcoded",
        "B107": "secrets.hardcoded",
        "B108": "path.traversal",
        "B110": "other",  # try-except-pass
        "B112": "other",  # try-except-continue
        "B201": "unsafe.exec",
        "B301": "deserialization.unsafe",
        "B302": "deserialization.unsafe",
        "B303": "crypto.weak",
        "B304": "crypto.weak",
        "B305": "crypto.weak",
        "B306": "path.traversal",
        "B307": "unsafe.eval",
        "B308": "injection.xss",
        "B310": "ssrf",
        "B311": "crypto.weak",
        "B312": "other",
        "B313": "injection.xss",
        "B314": "injection.xss",
        "B320": "injection.xss",
        "B321": "other",
        "B323": "crypto.weak",
        "B324": "crypto.weak",
        "B501": "crypto.weak",
        "B502": "crypto.weak",
        "B503": "crypto.weak",
        "B504": "crypto.weak",
        "B505": "crypto.weak",
        "B506": "deserialization.unsafe",
        "B507": "crypto.weak",
        "B601": "injection.command",
        "B602": "injection.command",
        "B603": "injection.command",
        "B604": "injection.command",
        "B605": "injection.command",
        "B606": "injection.command",
        "B607": "injection.command",
        "B608": "injection.sql",
        "B609": "injection.command",
        "B610": "injection.command",
        "B611": "injection.command",
        "B701": "injection.xss",
        "B702": "injection.xss",
        "B703": "injection.xss",
    }
    return mappings.get(test_id, "other")


def _map_semgrep_category(check_id: str) -> str:
    """Map Semgrep check ID to category."""
    check_lower = check_id.lower()
    if "sql" in check_lower:
        return "injection.sql"
    if "xss" in check_lower:
        return "injection.xss"
    if "command" in check_lower or "shell" in check_lower:
        return "injection.command"
    if "crypto" in check_lower or "hash" in check_lower:
        return "crypto.weak"
    if "secret" in check_lower or "password" in check_lower or "api" in check_lower:
        return "secrets.hardcoded"
    if "auth" in check_lower:
        return "auth.broken"
    if "deserial" in check_lower or "pickle" in check_lower or "yaml" in check_lower:
        return "deserialization.unsafe"
    if "path" in check_lower or "traversal" in check_lower:
        return "path.traversal"
    if "ssrf" in check_lower:
        return "ssrf"
    if "eval" in check_lower:
        return "unsafe.eval"
    if "exec" in check_lower:
        return "unsafe.exec"
    return "other"


def _map_pattern_category(check_id: str) -> str:
    """Map pattern check ID to category."""
    check_lower = check_id.lower()
    if "eval" in check_lower:
        return "unsafe.eval"
    if "exec" in check_lower:
        return "unsafe.exec"
    if "pickle" in check_lower or "yaml" in check_lower:
        return "deserialization.unsafe"
    if "sql" in check_lower:
        return "injection.sql"
    if "shell" in check_lower or "command" in check_lower:
        return "injection.command"
    return "other"


def create_gold_labels(
    weak_labels: list[WeakLabel],
    min_scanners: int = 1,
    verbose: bool = True,
) -> list[GoldLabel]:
    """Create gold labels with consensus scoring from weak labels."""
    
    # Group by location (file + line range)
    location_groups: dict[str, list[WeakLabel]] = {}
    for wl in weak_labels:
        # Create location key with some tolerance
        key = f"{wl.file_path}:{wl.line_start // 3}"
        location_groups.setdefault(key, []).append(wl)
    
    gold_labels: list[GoldLabel] = []
    
    for key, group in location_groups.items():
        # Get unique scanners
        scanners = list(set(wl.scanner for wl in group))
        scanner_count = len(scanners)
        
        if scanner_count < min_scanners:
            continue
        
        # Compute consensus score (more scanners = higher confidence)
        consensus_score = min(1.0, scanner_count / 3.0)
        
        # Boost if high severity
        severities = [wl.severity.upper() for wl in group]
        if "HIGH" in severities or "CRITICAL" in severities:
            consensus_score = min(1.0, consensus_score + 0.3)
        
        # Determine verdict - more lenient for training data
        # Single scanner with high severity = TP
        # Two scanners = TP
        # Single scanner with medium severity = UNCERTAIN
        if scanner_count >= 2:
            verdict = "TP"
            label = 1
        elif "HIGH" in severities or "CRITICAL" in severities:
            verdict = "TP"
            label = 1
        elif consensus_score >= 0.5:
            verdict = "TP"
            label = 1
        else:
            verdict = "UNCERTAIN"
            label = -1
        
        # Use first finding for details
        first = group[0]
        
        # Compute features
        features = _compute_features(first.code_snippet, scanners)
        
        gold_labels.append(GoldLabel(
            sample_id=first.sample_id,
            file_path=first.file_path,
            line_start=first.line_start,
            line_end=first.line_end,
            code_snippet=first.code_snippet,
            scanner_count=scanner_count,
            scanners=scanners,
            consensus_score=consensus_score,
            verdict=verdict,
            label=label,
            category=first.category,
            severity=first.severity,
            confidence=first.confidence,
            features=features,
        ))
    
    if verbose:
        tp_count = sum(1 for g in gold_labels if g.verdict == "TP")
        uncertain_count = sum(1 for g in gold_labels if g.verdict == "UNCERTAIN")
        console.print(f"\n[cyan]Gold labels: {len(gold_labels)} total, {tp_count} TP, {uncertain_count} UNCERTAIN[/cyan]")
    
    return gold_labels


def _compute_features(code: str, scanners: list[str]) -> dict[str, Any]:
    """Compute features for ML training."""
    lines = code.split('\n')
    
    return {
        "n_lines": len(lines),
        "n_chars": len(code),
        "scanner_count": len(scanners),
        "has_bandit": "bandit" in scanners,
        "has_semgrep": "semgrep" in scanners,
        "has_secrets": "secrets" in scanners,
        "has_patterns": "patterns" in scanners,
        "has_deps": "dependencies" in scanners,
        "has_user_input": any(kw in code for kw in ["request", "input", "argv", "args"]),
        "has_dangerous_fn": any(fn in code for fn in ["eval", "exec", "system", "pickle"]),
        "has_sql": any(kw in code.upper() for kw in ["SELECT", "INSERT", "UPDATE", "DELETE"]),
    }


def prepare_training_data(
    gold_labels: list[GoldLabel],
    output_dir: Path,
    split_ratios: tuple[float, float, float] = (0.8, 0.1, 0.1),
    seed: int = 42,
    verbose: bool = True,
) -> dict[str, Path]:
    """Prepare training data from gold labels."""
    import re
    
    random.seed(seed)
    
    # Filter to only TP and FP (skip UNCERTAIN for training)
    labeled = [g for g in gold_labels if g.label in (0, 1)]
    
    if not labeled:
        if verbose:
            console.print("[yellow]No labeled samples, generating synthetic data...[/yellow]")
        labeled = _generate_synthetic_gold_labels(200)
    
    # Shuffle
    random.shuffle(labeled)
    
    # Split
    n = len(labeled)
    n_train = int(n * split_ratios[0])
    n_val = int(n * split_ratios[1])
    
    train_samples = labeled[:n_train]
    val_samples = labeled[n_train:n_train + n_val]
    test_samples = labeled[n_train + n_val:]
    
    # Ensure minimum sizes for production-quality training
    MIN_TRAIN = 200
    MIN_VAL = 50
    MIN_TEST = 50
    
    if len(train_samples) < MIN_TRAIN:
        additional = _generate_synthetic_gold_labels(MIN_TRAIN - len(train_samples))
        train_samples.extend(additional)
        if verbose:
            console.print(f"  [yellow]Added {len(additional)} synthetic training samples[/yellow]")
    
    if len(val_samples) < MIN_VAL:
        additional = _generate_synthetic_gold_labels(MIN_VAL - len(val_samples))
        val_samples.extend(additional)
        if verbose:
            console.print(f"  [yellow]Added {len(additional)} synthetic validation samples[/yellow]")
    
    if len(test_samples) < MIN_TEST:
        additional = _generate_synthetic_gold_labels(MIN_TEST - len(test_samples))
        test_samples.extend(additional)
        if verbose:
            console.print(f"  [yellow]Added {len(additional)} synthetic test samples[/yellow]")
    
    # Create output directories
    transformer_dir = output_dir / "transformer"
    gnn_dir = output_dir / "gnn"
    transformer_dir.mkdir(parents=True, exist_ok=True)
    gnn_dir.mkdir(parents=True, exist_ok=True)
    
    output_files = {}
    
    # Write transformer format
    for name, samples in [("train", train_samples), ("val", val_samples), ("test", test_samples)]:
        path = transformer_dir / f"{name}.jsonl"
        with open(path, "w") as f:
            for sample in samples:
                tokens = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*|[0-9]+|[^\s\w]', sample.code_snippet)[:256]
                record = {
                    "sample_id": sample.sample_id,
                    "tokens": tokens,
                    "categories": [sample.category],
                    "is_vulnerable": sample.label == 1,
                    "features": sample.features,
                    "consensus_score": sample.consensus_score,
                }
                f.write(json.dumps(record) + "\n")
        output_files[f"transformer_{name}"] = path
    
    # Write GNN format
    for name, samples in [("train", train_samples), ("val", val_samples), ("test", test_samples)]:
        path = gnn_dir / f"{name}.jsonl"
        with open(path, "w") as f:
            for sample in samples:
                record = {
                    "sample_id": sample.sample_id,
                    "file_path": sample.file_path,
                    "code": sample.code_snippet,
                    "categories": [sample.category],
                    "is_vulnerable": sample.label == 1,
                }
                f.write(json.dumps(record) + "\n")
        output_files[f"gnn_{name}"] = path
    
    if verbose:
        console.print(f"\n[green]Prepared datasets:[/green]")
        console.print(f"  Train: {len(train_samples)}, Val: {len(val_samples)}, Test: {len(test_samples)}")
        console.print(f"  Output: {output_dir}")
    
    return output_files


def _generate_synthetic_gold_labels(n: int) -> list[GoldLabel]:
    """Generate synthetic gold labels for training with diverse examples."""
    # Vulnerable code patterns (label=1)
    vulnerable_templates = [
        # Unsafe eval/exec
        ("eval(user_input)", "unsafe.eval"),
        ("eval(request.args.get('code'))", "unsafe.eval"),
        ("exec(command)", "unsafe.exec"),
        ("exec(compile(source, '<string>', 'exec'))", "unsafe.exec"),
        
        # Command injection
        ("os.system(cmd)", "injection.command"),
        ("os.system(f'ls {user_dir}')", "injection.command"),
        ("subprocess.call(command, shell=True)", "injection.command"),
        ("subprocess.Popen(cmd, shell=True)", "injection.command"),
        
        # SQL injection
        ("cursor.execute(f'SELECT * FROM users WHERE id={user_id}')", "injection.sql"),
        ("cursor.execute('SELECT * FROM users WHERE name=' + name)", "injection.sql"),
        ("db.query(f'DELETE FROM {table}')", "injection.sql"),
        
        # Deserialization
        ("pickle.loads(data)", "deserialization.unsafe"),
        ("yaml.load(data)", "deserialization.unsafe"),
        ("marshal.loads(user_data)", "deserialization.unsafe"),
        
        # Weak crypto
        ("hashlib.md5(password.encode())", "crypto.weak"),
        ("hashlib.sha1(data)", "crypto.weak"),
        ("DES.new(key, DES.MODE_ECB)", "crypto.weak"),
        
        # Hardcoded secrets
        ("API_KEY = 'sk-1234567890abcdef'", "secrets.hardcoded"),
        ("password = 'admin123'", "secrets.hardcoded"),
        ("SECRET_KEY = 'my-secret-key-123'", "secrets.hardcoded"),
        ("aws_access_key = 'AKIAIOSFODNN7EXAMPLE'", "secrets.api_key"),
        
        # Path traversal
        ("open(user_path + '/config.json')", "path.traversal"),
        ("shutil.copy(src, user_input)", "path.traversal"),
        
        # SSRF
        ("requests.get(url_from_user)", "ssrf"),
        ("urllib.request.urlopen(user_url)", "ssrf"),
        
        # XSS
        ("return f'<div>{user_content}</div>'", "injection.xss"),
        ("response.write(user_input)", "injection.xss"),
    ]
    
    # Safe code patterns (label=0)
    safe_templates = [
        ("result = calculate(x, y)", "other"),
        ("logger.info('Processing request')", "other"),
        ("response = requests.get(HARDCODED_URL)", "other"),
        ("data = json.loads(response.text)", "other"),
        ("config = load_config('settings.yaml')", "other"),
        ("cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))", "other"),
        ("hashlib.sha256(data.encode()).hexdigest()", "other"),
        ("password = bcrypt.hashpw(user_pass, salt)", "other"),
        ("os.makedirs(FIXED_PATH, exist_ok=True)", "other"),
        ("return render_template('page.html', data=escaped_data)", "other"),
        ("subprocess.run(['ls', '-la'], check=True)", "other"),
        ("with open(SAFE_CONFIG_PATH, 'r') as f:", "other"),
        ("encrypted = aes.encrypt(data)", "other"),
        ("token = secrets.token_urlsafe(32)", "other"),
        ("validated_path = Path(user_input).resolve().relative_to(BASE)", "other"),
    ]
    
    labels = []
    
    # Generate balanced dataset: 60% vulnerable, 40% safe
    n_vulnerable = int(n * 0.6)
    n_safe = n - n_vulnerable
    
    for i in range(n_vulnerable):
        code, category = random.choice(vulnerable_templates)
        labels.append(GoldLabel(
            sample_id=f"synthetic_vuln_{i:04d}",
            file_path=f"synthetic/vulnerable_{i % 10}.py",
            line_start=random.randint(10, 100),
            line_end=random.randint(10, 100),
            code_snippet=code,
            scanner_count=random.randint(1, 3),
            scanners=random.sample(["bandit", "semgrep", "secrets", "patterns"], k=random.randint(1, 3)),
            consensus_score=random.uniform(0.6, 1.0),
            verdict="TP",
            label=1,
            category=category,
            severity=random.choice(["HIGH", "CRITICAL", "MEDIUM"]),
            confidence="HIGH",
            features={
                "n_lines": 1,
                "n_chars": len(code),
                "scanner_count": random.randint(1, 3),
                "has_user_input": "user" in code.lower() or "request" in code.lower(),
                "has_dangerous_fn": any(fn in code for fn in ["eval", "exec", "system", "pickle"]),
            },
        ))
    
    for i in range(n_safe):
        code, category = random.choice(safe_templates)
        labels.append(GoldLabel(
            sample_id=f"synthetic_safe_{i:04d}",
            file_path=f"synthetic/safe_{i % 10}.py",
            line_start=random.randint(10, 100),
            line_end=random.randint(10, 100),
            code_snippet=code,
            scanner_count=0,
            scanners=[],
            consensus_score=random.uniform(0.0, 0.3),
            verdict="FP",
            label=0,
            category=category,
            severity="LOW",
            confidence="HIGH",
            features={
                "n_lines": 1,
                "n_chars": len(code),
                "scanner_count": 0,
                "has_user_input": False,
                "has_dangerous_fn": False,
            },
        ))
    
    random.shuffle(labels)
    return labels


def write_jsonl(path: Path, items: list) -> None:
    """Write items to JSONL file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for item in items:
            if hasattr(item, "to_dict"):
                f.write(json.dumps(item.to_dict()) + "\n")
            else:
                f.write(json.dumps(item) + "\n")


# CLI Commands

@app.command("weak-labels")
def generate_weak_labels(
    target: Path = typer.Option(Path("."), help="Target directory to scan"),
    output: Path = typer.Option(Path("datasets/weak_labels.jsonl"), help="Output file"),
) -> None:
    """Generate weak labels using all 5 enhanced scanners."""
    console.print("\n[bold blue]🔍 Generating Weak Labels with Enhanced Scanners[/bold blue]\n")
    
    weak_labels = run_enhanced_scanners(target, verbose=True)
    
    console.print(f"\n[green]Generated {len(weak_labels)} weak labels[/green]")
    
    # Write output
    write_jsonl(output, weak_labels)
    console.print(f"[green]✓ Saved to {output}[/green]")
    
    # Show summary
    scanner_counts = Counter(wl.scanner for wl in weak_labels)
    table = Table(title="Weak Labels by Scanner")
    table.add_column("Scanner")
    table.add_column("Count")
    for scanner, count in scanner_counts.most_common():
        table.add_row(scanner, str(count))
    console.print(table)


@app.command("gold-labels")
def generate_gold_labels(
    weak_labels_path: Path = typer.Option(Path("datasets/weak_labels.jsonl"), help="Input weak labels"),
    output: Path = typer.Option(Path("datasets/gold/gold_labels.jsonl"), help="Output file"),
    min_scanners: int = typer.Option(1, help="Minimum scanners for inclusion"),
) -> None:
    """Create gold labels from weak labels using consensus scoring."""
    console.print("\n[bold blue]🏅 Creating Gold Labels with Consensus Scoring[/bold blue]\n")
    
    # Load weak labels
    weak_labels = []
    with open(weak_labels_path) as f:
        for line in f:
            if line.strip():
                data = json.loads(line)
                weak_labels.append(WeakLabel(**data))
    
    console.print(f"Loaded {len(weak_labels)} weak labels")
    
    # Create gold labels
    gold_labels = create_gold_labels(weak_labels, min_scanners=min_scanners, verbose=True)
    
    # Write output
    write_jsonl(output, gold_labels)
    console.print(f"[green]✓ Saved {len(gold_labels)} gold labels to {output}[/green]")


@app.command("prepare-data")
def prepare_data(
    gold_labels_path: Path = typer.Option(Path("datasets/gold/gold_labels.jsonl"), help="Input gold labels"),
    output_dir: Path = typer.Option(Path("datasets/enhanced"), help="Output directory"),
    seed: int = typer.Option(42, help="Random seed"),
) -> None:
    """Prepare training datasets from gold labels."""
    console.print("\n[bold blue]📊 Preparing Training Datasets[/bold blue]\n")
    
    # Load gold labels
    gold_labels = []
    with open(gold_labels_path) as f:
        for line in f:
            if line.strip():
                data = json.loads(line)
                gold_labels.append(GoldLabel(**data))
    
    console.print(f"Loaded {len(gold_labels)} gold labels")
    
    # Prepare data
    output_files = prepare_training_data(gold_labels, output_dir, seed=seed, verbose=True)
    
    console.print(f"\n[green]✓ Datasets saved to {output_dir}[/green]")


@app.command("train")
def train_models(
    dataset_dir: Path = typer.Option(Path("datasets/enhanced"), help="Dataset directory"),
    output_dir: Path = typer.Option(Path("artifacts/models"), help="Output directory for models"),
    epochs: int = typer.Option(10, help="Training epochs"),
    batch_size: int = typer.Option(16, help="Batch size"),
    device: str = typer.Option("cpu", help="Device (cpu, cuda, mps)"),
) -> None:
    """Train all models (Transformer, GNN, Ensemble)."""
    console.print("\n[bold blue]🚀 Training Models[/bold blue]\n")
    
    from ml.train_pipeline import TrainingPipeline
    
    pipeline = TrainingPipeline(
        targets=[],
        output_dir=output_dir,
        dataset_dir=dataset_dir,
        skip_scan=True,
        epochs=epochs,
        batch_size=batch_size,
        device=device,
    )
    
    results = pipeline.run()
    
    if results.get("success"):
        console.print("\n[bold green]✓ Training complete![/bold green]")
    else:
        console.print(f"\n[bold red]✗ Training failed: {results.get('error')}[/bold red]")


@app.command("full")
def full_pipeline(
    target: Path = typer.Option(Path("."), help="Target directory to scan"),
    output_dir: Path = typer.Option(Path("artifacts/models"), help="Output directory"),
    epochs: int = typer.Option(10, help="Training epochs"),
    batch_size: int = typer.Option(16, help="Batch size"),
    device: str = typer.Option("cpu", help="Device (cpu, cuda, mps)"),
    seed: int = typer.Option(42, help="Random seed"),
) -> None:
    """Run the complete pipeline: scan → weak labels → gold labels → train."""
    console.print("\n[bold blue]🔄 Running Complete Enhanced Pipeline[/bold blue]\n")
    
    datasets_dir = Path("datasets")
    weak_labels_path = datasets_dir / "weak_labels.jsonl"
    gold_labels_path = datasets_dir / "gold" / "gold_labels.jsonl"
    enhanced_dir = datasets_dir / "enhanced"
    
    # Step 1: Generate weak labels
    console.print("\n[bold]Step 1/4: Generate Weak Labels[/bold]")
    weak_labels = run_enhanced_scanners(target, verbose=True)
    write_jsonl(weak_labels_path, weak_labels)
    console.print(f"[green]✓ Generated {len(weak_labels)} weak labels[/green]")
    
    # Step 2: Create gold labels
    console.print("\n[bold]Step 2/4: Create Gold Labels[/bold]")
    gold_labels = create_gold_labels(weak_labels, min_scanners=1, verbose=True)
    write_jsonl(gold_labels_path, gold_labels)
    console.print(f"[green]✓ Created {len(gold_labels)} gold labels[/green]")
    
    # Step 3: Prepare training data
    console.print("\n[bold]Step 3/4: Prepare Training Data[/bold]")
    prepare_training_data(gold_labels, enhanced_dir, seed=seed, verbose=True)
    
    # Step 4: Train models
    console.print("\n[bold]Step 4/4: Train Models[/bold]")
    from ml.train_pipeline import TrainingPipeline
    
    pipeline = TrainingPipeline(
        targets=[],
        output_dir=output_dir,
        dataset_dir=enhanced_dir,
        skip_scan=True,
        epochs=epochs,
        batch_size=batch_size,
        device=device,
    )
    
    results = pipeline.run()
    
    if results.get("success"):
        console.print("\n[bold green]✓ Full pipeline complete![/bold green]")
        console.print(f"  Models saved to: {output_dir}")
    else:
        console.print(f"\n[bold red]✗ Pipeline failed: {results.get('error')}[/bold red]")


if __name__ == "__main__":
    app()
