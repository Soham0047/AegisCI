"""
Enhanced Dataset Generator

Generates ML training datasets using all 5 security scanners:
1. Bandit - Python security analysis
2. Semgrep - Multi-language pattern matching  
3. Secrets Scanner - Hardcoded credential detection
4. Pattern Scanner - Dangerous code patterns
5. Dependency Scanner - Known CVE detection

Features:
- Multi-scanner consensus scoring
- Enhanced feature extraction
- Automatic labeling based on scanner agreement
- Export to transformer and GNN training formats
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Add project root to path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.consensus import (
    UnifiedFinding,
    compute_enhanced_features,
    compute_statistics,
    get_consensus_label,
    merge_scanner_results,
)


@dataclass
class EnhancedSample:
    """A training sample with enhanced multi-scanner features."""
    
    sample_id: str
    tokens: list[str]
    token_ids: list[int] | None
    label: int  # 1=TP, 0=FP, -1=UNCERTAIN
    verdict: str  # TP, FP, UNCERTAIN
    category: str
    features: dict[str, Any]
    
    # Enhanced fields
    scanner_sources: list[str]
    consensus_score: float
    scanner_count: int
    severity: str
    confidence: str
    
    # Source info
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "tokens": self.tokens,
            "token_ids": self.token_ids,
            "label": self.label,
            "verdict": self.verdict,
            "category": self.category,
            "features": self.features,
            "scanner_sources": self.scanner_sources,
            "consensus_score": self.consensus_score,
            "scanner_count": self.scanner_count,
            "severity": self.severity,
            "confidence": self.confidence,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "code_snippet": self.code_snippet,
        }


def tokenize_code(code: str) -> list[str]:
    """Simple tokenizer for code snippets."""
    import re
    
    # Split on whitespace and common delimiters
    tokens = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*|[0-9]+|[^\s\w]', code)
    return tokens[:512]  # Limit token count


def generate_sample_id(file_path: str, line: int, category: str) -> str:
    """Generate a unique sample ID."""
    content = f"{file_path}:{line}:{category}:{datetime.now(UTC).isoformat()}"
    return hashlib.sha256(content.encode()).hexdigest()


def compute_code_features(code: str, tokens: list[str]) -> dict[str, Any]:
    """Compute code-level features for ML training."""
    lines = code.split('\n')
    
    features = {
        # Basic metrics
        "n_lines": len(lines),
        "n_chars": len(code),
        "n_tokens": len(tokens),
        "avg_line_length": sum(len(l) for l in lines) / max(len(lines), 1),
        "max_line_length": max((len(l) for l in lines), default=0),
        
        # Code structure
        "n_functions": code.count("def ") + code.count("function "),
        "n_classes": code.count("class "),
        "n_imports": code.count("import ") + code.count("from "),
        "n_comments": code.count("#") + code.count("//") + code.count("/*"),
        
        # Control flow
        "has_try_except": "try:" in code or "try {" in code,
        "has_assert": "assert " in code,
        "has_logging": "logger." in code or "logging." in code or "console.log" in code,
        
        # Security indicators
        "has_hardcoded_string": '\"sk-' in code or '\"pk_' in code or '\"aws_' in code.lower(),
        "has_sql_keywords": any(kw in code.upper() for kw in ["SELECT", "INSERT", "UPDATE", "DELETE"]),
        "has_shell_calls": any(fn in code for fn in ["os.system", "subprocess", "shell=True", "exec("]),
        "has_file_ops": any(fn in code for fn in ["open(", ".read(", ".write(", "file"]),
        "has_network": any(fn in code for fn in ["requests.", "http", "socket", "urllib"]),
        "has_crypto": any(fn in code for fn in ["hashlib", "crypto", "encrypt", "decrypt"]),
        "has_user_input": any(fn in code for fn in ["request.", "input(", "argv", "args"]),
        
        # Indentation depth
        "indentation_depth": max((len(l) - len(l.lstrip()) for l in lines if l.strip()), default=0) // 4,
    }
    
    return features


def unified_finding_to_sample(finding: UnifiedFinding) -> EnhancedSample:
    """Convert a unified finding to a training sample."""
    tokens = tokenize_code(finding.code_snippet)
    label = get_consensus_label(finding)
    verdict = "TP" if label == 1 else "FP" if label == 0 else "UNCERTAIN"
    
    # Compute code features
    code_features = compute_code_features(finding.code_snippet, tokens)
    
    # Merge with consensus features
    all_features = {**code_features, **finding.features}
    
    return EnhancedSample(
        sample_id=generate_sample_id(finding.file_path, finding.line_start, finding.category),
        tokens=tokens,
        token_ids=None,
        label=label,
        verdict=verdict,
        category=finding.category,
        features=all_features,
        scanner_sources=finding.scanner_sources,
        consensus_score=finding.consensus_score,
        scanner_count=finding.scanner_count,
        severity=finding.severity,
        confidence=finding.confidence,
        file_path=finding.file_path,
        line_start=finding.line_start,
        line_end=finding.line_end,
        code_snippet=finding.code_snippet,
    )


def run_all_scanners(target_path: Path, verbose: bool = False) -> dict[str, list[dict[str, Any]]]:
    """Run all 5 scanners on the target path."""
    from guardian.scanners.bandit_scanner import run_bandit
    from guardian.scanners.dependency_scanner import run_dependency_scanner
    from guardian.scanners.pattern_scanner import run_comprehensive_scan
    from guardian.scanners.secrets_scanner import run_secrets_scanner
    from guardian.scanners.semgrep_scanner import run_semgrep
    
    results = {
        "bandit": [],
        "semgrep": [],
        "secrets": [],
        "patterns": [],
        "dependencies": [],
    }
    
    if verbose:
        print(f"🔍 Scanning {target_path}...")
    
    # Collect files by type
    py_files = []
    js_ts_files = []
    all_files = []
    
    if target_path.is_file():
        all_files = [str(target_path)]
        if target_path.suffix == ".py":
            py_files = [str(target_path)]
        elif target_path.suffix in (".js", ".ts", ".jsx", ".tsx"):
            js_ts_files = [str(target_path)]
    else:
        for ext in ["*.py"]:
            py_files.extend(str(f) for f in target_path.rglob(ext) if ".venv" not in str(f) and "node_modules" not in str(f))
        for ext in ["*.js", "*.ts", "*.jsx", "*.tsx"]:
            js_ts_files.extend(str(f) for f in target_path.rglob(ext) if "node_modules" not in str(f))
        all_files = py_files + js_ts_files
    
    # Run Bandit (Python only)
    try:
        if verbose:
            print("  ├── Running Bandit...")
        if py_files:
            bandit_result = run_bandit(py_files)
            if bandit_result and "results" in bandit_result:
                results["bandit"] = bandit_result["results"]
                if verbose:
                    print(f"      Found {len(results['bandit'])} findings")
        else:
            if verbose:
                print("      No Python files to scan")
    except Exception as e:
        if verbose:
            print(f"      ⚠️ Bandit failed: {e}")
    
    # Run Semgrep
    try:
        if verbose:
            print("  ├── Running Semgrep...")
        if all_files:
            semgrep_result = run_semgrep(all_files, config=["p/ci", "p/security-audit"])
            if semgrep_result and "results" in semgrep_result:
                results["semgrep"] = semgrep_result["results"]
                if verbose:
                    print(f"      Found {len(results['semgrep'])} findings")
        else:
            if verbose:
                print("      No files to scan")
    except Exception as e:
        if verbose:
            print(f"      ⚠️ Semgrep failed: {e}")
    
    # Run Secrets Scanner
    try:
        if verbose:
            print("  ├── Running Secrets Scanner...")
        if all_files:
            secrets_result = run_secrets_scanner(all_files)
            if secrets_result and "results" in secrets_result:
                results["secrets"] = secrets_result["results"]
                if verbose:
                    print(f"      Found {len(results['secrets'])} findings")
        else:
            if verbose:
                print("      No files to scan")
    except Exception as e:
        if verbose:
            print(f"      ⚠️ Secrets scanner failed: {e}")
    
    # Run Pattern Scanner
    try:
        if verbose:
            print("  ├── Running Pattern Scanner...")
        if all_files:
            pattern_result = run_comprehensive_scan(all_files)
            if pattern_result and "results" in pattern_result:
                results["patterns"] = pattern_result["results"]
                if verbose:
                    print(f"      Found {len(results['patterns'])} findings")
        else:
            if verbose:
                print("      No files to scan")
    except Exception as e:
        if verbose:
            print(f"      ⚠️ Pattern scanner failed: {e}")
    
    # Run Dependency Scanner
    try:
        if verbose:
            print("  └── Running Dependency Scanner...")
        deps_result = run_dependency_scanner(directory=str(target_path))
        if deps_result and "results" in deps_result:
            results["dependencies"] = deps_result["results"]
            if verbose:
                print(f"      Found {len(results['dependencies'])} findings")
    except Exception as e:
        if verbose:
            print(f"      ⚠️ Dependency scanner failed: {e}")
    
    return results


def generate_enhanced_dataset(
    target_paths: list[Path],
    output_dir: Path,
    split_ratios: tuple[float, float, float] = (0.8, 0.1, 0.1),
    seed: int = 42,
    verbose: bool = True,
) -> dict[str, Path]:
    """
    Generate enhanced training dataset from target paths.
    
    Args:
        target_paths: Directories to scan
        output_dir: Where to save the dataset
        split_ratios: (train, val, test) split ratios
        seed: Random seed for reproducibility
        verbose: Print progress
    
    Returns:
        Dict mapping split name to file path
    """
    import random
    random.seed(seed)
    
    if verbose:
        print("=" * 60)
        print("🚀 Enhanced Dataset Generator")
        print("=" * 60)
        print(f"Target paths: {len(target_paths)}")
        print(f"Output dir: {output_dir}")
        print()
    
    all_samples: list[EnhancedSample] = []
    
    for target_path in target_paths:
        if not target_path.exists():
            if verbose:
                print(f"⚠️ Path not found: {target_path}")
            continue
        
        # Run all scanners
        scanner_results = run_all_scanners(target_path, verbose=verbose)
        
        # Merge results with consensus
        unified_findings = merge_scanner_results(
            bandit_findings=scanner_results["bandit"],
            semgrep_findings=scanner_results["semgrep"],
            secrets_findings=scanner_results["secrets"],
            pattern_findings=scanner_results["patterns"],
            dependency_findings=scanner_results["dependencies"],
        )
        
        if verbose:
            print(f"\n📊 Merged {len(unified_findings)} unique findings")
            stats = compute_statistics(unified_findings)
            print(f"   Average consensus score: {stats.get('avg_consensus_score', 0):.2f}")
            print(f"   By severity: {stats.get('by_severity', {})}")
            print()
        
        # Convert to samples
        for finding in unified_findings:
            sample = unified_finding_to_sample(finding)
            all_samples.append(sample)
    
    if not all_samples:
        if verbose:
            print("⚠️ No samples generated. Using synthetic data...")
        all_samples = generate_synthetic_samples(100)
    
    # Shuffle and split
    random.shuffle(all_samples)
    
    n_total = len(all_samples)
    n_train = int(n_total * split_ratios[0])
    n_val = int(n_total * split_ratios[1])
    
    train_samples = all_samples[:n_train]
    val_samples = all_samples[n_train:n_train + n_val]
    test_samples = all_samples[n_train + n_val:]
    
    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save splits
    output_files = {}
    
    for split_name, samples in [("train", train_samples), ("val", val_samples), ("test", test_samples)]:
        # Save for transformer
        transformer_path = output_dir / "transformer" / f"{split_name}.jsonl"
        transformer_path.parent.mkdir(parents=True, exist_ok=True)
        with transformer_path.open("w", encoding="utf-8") as f:
            for sample in samples:
                f.write(json.dumps(sample.to_dict()) + "\n")
        output_files[f"transformer_{split_name}"] = transformer_path
        
        # Save for GNN (same format, different directory)
        gnn_path = output_dir / "gnn" / f"{split_name}.jsonl"
        gnn_path.parent.mkdir(parents=True, exist_ok=True)
        with gnn_path.open("w", encoding="utf-8") as f:
            for sample in samples:
                f.write(json.dumps(sample.to_dict()) + "\n")
        output_files[f"gnn_{split_name}"] = gnn_path
    
    if verbose:
        print("=" * 60)
        print("✅ Dataset generation complete!")
        print(f"   Train samples: {len(train_samples)}")
        print(f"   Val samples: {len(val_samples)}")
        print(f"   Test samples: {len(test_samples)}")
        print(f"   Output: {output_dir}")
        print("=" * 60)
    
    # Save metadata
    metadata = {
        "created_at": datetime.now(UTC).isoformat(),
        "target_paths": [str(p) for p in target_paths],
        "n_train": len(train_samples),
        "n_val": len(val_samples),
        "n_test": len(test_samples),
        "split_ratios": list(split_ratios),
        "seed": seed,
        "categories": list(set(s.category for s in all_samples)),
        "feature_names": list(all_samples[0].features.keys()) if all_samples else [],
    }
    metadata_path = output_dir / "metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2))
    
    return output_files


def generate_synthetic_samples(count: int = 100) -> list[EnhancedSample]:
    """Generate synthetic training samples for testing."""
    import random
    
    samples = []
    
    # Vulnerability patterns
    vuln_patterns = [
        ("sql.injection", 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")', ["bandit", "semgrep", "patterns"]),
        ("command.injection", 'os.system(f"rm -rf {path}")', ["bandit", "semgrep", "patterns"]),
        ("xss", 'return f"<div>{user_input}</div>"', ["semgrep", "patterns"]),
        ("hardcoded.secrets", 'API_KEY = "sk-1234567890abcdef"', ["secrets", "bandit", "semgrep"]),
        ("deserialization", "pickle.loads(data)", ["bandit", "patterns"]),
        ("path.traversal", 'open(f"/uploads/{filename}")', ["bandit", "semgrep", "patterns"]),
        ("crypto.weak", "hashlib.md5(password).hexdigest()", ["bandit", "semgrep"]),
        ("ssrf", 'requests.get(f"http://{user_url}")', ["semgrep", "patterns"]),
    ]
    
    # Safe patterns (for FP samples)
    safe_patterns = [
        ("misc.safe_code", 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))', ["bandit"]),
        ("misc.safe_code", 'subprocess.run(["ls", "-la"], check=True)', []),
        ("misc.safe_code", "html.escape(user_input)", []),
        ("misc.safe_code", 'secrets.token_urlsafe(32)', []),
    ]
    
    for i in range(count):
        if random.random() < 0.7:
            # True positive
            category, code, scanners = random.choice(vuln_patterns)
            label = 1
            verdict = "TP"
            scanner_count = len(scanners)
        else:
            # False positive
            category, code, scanners = random.choice(safe_patterns)
            label = 0
            verdict = "FP"
            scanner_count = len(scanners)
        
        tokens = tokenize_code(code)
        features = compute_code_features(code, tokens)
        features["scanner_count"] = scanner_count
        features["scanner_agreement_ratio"] = scanner_count / 5.0
        
        sample = EnhancedSample(
            sample_id=generate_sample_id(f"synthetic_{i}.py", i, category),
            tokens=tokens,
            token_ids=None,
            label=label,
            verdict=verdict,
            category=category,
            features=features,
            scanner_sources=scanners,
            consensus_score=0.8 if label == 1 else 0.3,
            scanner_count=scanner_count,
            severity="HIGH" if label == 1 else "LOW",
            confidence="HIGH" if scanner_count >= 2 else "MEDIUM",
            file_path=f"synthetic_{i}.py",
            line_start=i + 1,
            line_end=i + 1,
            code_snippet=code,
        )
        samples.append(sample)
    
    return samples


def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate enhanced ML training dataset")
    parser.add_argument(
        "--targets",
        nargs="+",
        type=Path,
        default=[Path(".")],
        help="Paths to scan",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("datasets/enhanced"),
        help="Output directory",
    )
    parser.add_argument(
        "--split",
        type=str,
        default="0.8,0.1,0.1",
        help="Train,val,test split ratios",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed",
    )
    parser.add_argument(
        "--synthetic",
        type=int,
        default=0,
        help="Add N synthetic samples",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce output",
    )
    
    args = parser.parse_args()
    
    split_ratios = tuple(float(x) for x in args.split.split(","))
    
    generate_enhanced_dataset(
        target_paths=args.targets,
        output_dir=args.output,
        split_ratios=split_ratios,
        seed=args.seed,
        verbose=not args.quiet,
    )


if __name__ == "__main__":
    main()
