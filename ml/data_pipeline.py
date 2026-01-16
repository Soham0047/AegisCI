#!/usr/bin/env python3
"""
Comprehensive ML Data Pipeline

This module handles the complete data pipeline:
1. Scan repositories with multiple scanners (Bandit, Semgrep, etc.)
2. Generate weak labels from scanner consensus
3. Create gold labels using heuristics and confidence thresholds
4. Build balanced train/test/val datasets for Transformer and GNN
5. Export datasets in the required format

Usage:
    python -m ml.data_pipeline --repos-dir data/repos --output artifacts/models/datasets
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import random
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Add project root to path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@dataclass
class ScanFinding:
    """A finding from a security scanner."""

    scanner: str
    file_path: str
    line_start: int
    line_end: int
    category: str
    severity: str  # HIGH, MEDIUM, LOW
    confidence: str  # HIGH, MEDIUM, LOW
    message: str
    code_snippet: str
    rule_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GoldSample:
    """A labeled sample for training."""

    sample_id: str
    code: str
    tokens: list[str]
    label: int  # 1 = vulnerable, 0 = safe
    verdict: str  # "TP" (true positive/vulnerable), "FP" (false positive/safe)
    category: str
    severity: str
    confidence: str
    scanner_sources: list[str]
    consensus_score: float
    file_path: str
    line_start: int
    line_end: int
    features: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MultiScanner:
    """Run multiple security scanners and aggregate results."""

    SCANNERS = ["bandit", "semgrep", "secrets", "patterns", "dependencies"]
    SKIP_DIRS = {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
        "dist",
        "build",
        ".next",
        "coverage",
    }

    def __init__(
        self,
        verbose: bool = True,
        semgrep_config: str = "max",
        semgrep_experimental: bool = False,
        min_confidence: str | None = None,
        rule_allowlist: set[str] | None = None,
        category_allowlist: set[str] | None = None,
    ):
        self.verbose = verbose
        self.semgrep_config = semgrep_config
        self.semgrep_experimental = semgrep_experimental
        self.min_confidence = min_confidence.upper() if min_confidence else None
        self.rule_allowlist = rule_allowlist or set()
        self.category_allowlist = category_allowlist or set()
        self._check_scanners()

    def _confidence_rank(self, value: str) -> int:
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3}.get(value.upper(), 0)

    def _matches_allowlist(self, value: str, allowlist: set[str]) -> bool:
        if not allowlist:
            return True
        for entry in allowlist:
            if entry.endswith("*"):
                if value.startswith(entry[:-1]):
                    return True
            elif value == entry:
                return True
        return False

    def _filter_findings(self, findings: list[ScanFinding]) -> list[ScanFinding]:
        if not (self.min_confidence or self.rule_allowlist or self.category_allowlist):
            return findings

        min_rank = self._confidence_rank(self.min_confidence) if self.min_confidence else 0
        filtered: list[ScanFinding] = []
        for finding in findings:
            if min_rank:
                if self._confidence_rank(finding.confidence) < min_rank:
                    continue

            if self.rule_allowlist:
                rule_value = finding.rule_id or finding.category
                if not self._matches_allowlist(rule_value, self.rule_allowlist):
                    continue

            if self.category_allowlist:
                if not self._matches_allowlist(finding.category, self.category_allowlist):
                    continue

            filtered.append(finding)
        return filtered

    def _check_scanners(self) -> None:
        """Check which scanners are available."""
        self.available_scanners = []
        cli_scanners = {"bandit", "semgrep"}
        for scanner in sorted(cli_scanners):
            try:
                result = subprocess.run(
                    [scanner, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    self.available_scanners.append(scanner)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        # Internal scanners are always available
        self.available_scanners.extend([s for s in self.SCANNERS if s not in cli_scanners])

        if self.verbose:
            print(f"Available scanners: {self.available_scanners}")

    def scan_directory(
        self,
        directory: Path,
        max_files: int | None = None,
        seed: int = 42,
    ) -> list[ScanFinding]:
        """Scan a directory with all available scanners."""
        findings: list[ScanFinding] = []
        files = self._collect_files(directory, {".py", ".js", ".ts", ".jsx", ".tsx"})
        if max_files and len(files) > max_files:
            rng = random.Random(seed)
            rng.shuffle(files)
            files = files[:max_files]

        py_files = [f for f in files if f.endswith(".py")]

        for scanner in self.available_scanners:
            if scanner == "bandit":
                findings.extend(self._run_bandit(py_files))
            elif scanner == "semgrep":
                findings.extend(self._run_semgrep(files))
            elif scanner == "secrets":
                findings.extend(self._run_secrets(files))
            elif scanner == "patterns":
                findings.extend(self._run_patterns(files))
            elif scanner == "dependencies":
                findings.extend(self._run_dependencies(directory))

        return self._filter_findings(findings)

    def _run_bandit(self, py_files: list[str]) -> list[ScanFinding]:
        """Run Bandit scanner."""
        findings = []
        try:
            from guardian.scanners.bandit_scanner import run_bandit

            if not py_files:
                return []

            for chunk in self._chunked(py_files, size=200):
                result = run_bandit(chunk)
                for r in result.get("results", []):
                    code = self._read_code_snippet(
                        Path(r["filename"]),
                        r["line_number"],
                        r.get("line_range", [r["line_number"]])[-1],
                    )
                    findings.append(
                        ScanFinding(
                            scanner="bandit",
                            file_path=r["filename"],
                            line_start=r["line_number"],
                            line_end=r.get("line_range", [r["line_number"]])[-1],
                            category=r["test_id"] + ":" + r["test_name"],
                            severity=r["issue_severity"],
                            confidence=r["issue_confidence"],
                            message=r["issue_text"],
                            code_snippet=code,
                            rule_id=r["test_id"],
                        )
                    )
        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
            if self.verbose:
                print(f"  Bandit error: {e}")

        return findings

    def _run_semgrep(self, files: list[str]) -> list[ScanFinding]:
        """Run Semgrep scanner."""
        findings = []
        try:
            from guardian.scanners.semgrep_scanner import (
                run_semgrep,
                run_semgrep_comprehensive,
                run_semgrep_max,
            )

            if not files:
                return []

            config = self.semgrep_config
            if config in {"max", "comprehensive"}:
                configs = config
            elif "," in config:
                configs = [c.strip() for c in config.split(",") if c.strip()]
            else:
                configs = config

            for chunk in self._chunked(files, size=200):
                if configs == "max":
                    result = run_semgrep_max(
                        chunk,
                        include_experimental=self.semgrep_experimental,
                    )
                elif configs == "comprehensive":
                    result = run_semgrep_comprehensive(
                        chunk,
                        include_experimental=self.semgrep_experimental,
                    )
                else:
                    result = run_semgrep(
                        chunk,
                        config=configs,
                        include_experimental=self.semgrep_experimental,
                    )
                for r in result.get("results", []):
                    code = self._read_code_snippet(
                        Path(r["path"]),
                        r["start"]["line"],
                        r["end"]["line"],
                    )
                    sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
                    severity = sev_map.get(r.get("extra", {}).get("severity", "WARNING"), "MEDIUM")

                    findings.append(
                        ScanFinding(
                            scanner="semgrep",
                            file_path=r["path"],
                            line_start=r["start"]["line"],
                            line_end=r["end"]["line"],
                            category=r.get("check_id", "unknown"),
                            severity=severity,
                            confidence="HIGH" if severity == "HIGH" else "MEDIUM",
                            message=r.get("extra", {}).get("message", ""),
                            code_snippet=code,
                            rule_id=r.get("check_id", ""),
                        )
                    )
        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
            if self.verbose:
                print(f"  Semgrep error: {e}")

        return findings

    def _run_secrets(self, files: list[str]) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        try:
            from guardian.scanners.secrets_scanner import run_secrets_scanner

            result = run_secrets_scanner(files)
            for r in result.get("results", []):
                file_path = r.get("path", "")
                line_start = r.get("start", {}).get("line", 0)
                line_end = r.get("end", {}).get("line", line_start)
                code = r.get("extra", {}).get("lines", "") or self._read_code_snippet(
                    Path(file_path), line_start, line_end
                )
                findings.append(
                    ScanFinding(
                        scanner="secrets",
                        file_path=file_path,
                        line_start=line_start,
                        line_end=line_end,
                        category="secrets.hardcoded",
                        severity="HIGH",
                        confidence="HIGH",
                        message=r.get("extra", {}).get("message", "Secret detected"),
                        code_snippet=code,
                        rule_id=r.get("check_id", ""),
                    )
                )
        except Exception as e:
            if self.verbose:
                print(f"  Secrets error: {e}")
        return findings

    def _run_patterns(self, files: list[str]) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        try:
            from guardian.scanners.pattern_scanner import run_comprehensive_scan

            result = run_comprehensive_scan(files)
            for r in result.get("results", []):
                file_path = r.get("path", "")
                line_start = r.get("start", {}).get("line", 0)
                line_end = r.get("end", {}).get("line", line_start)
                code = r.get("extra", {}).get("lines", "") or self._read_code_snippet(
                    Path(file_path), line_start, line_end
                )
                findings.append(
                    ScanFinding(
                        scanner="patterns",
                        file_path=file_path,
                        line_start=line_start,
                        line_end=line_end,
                        category=r.get("check_id", "pattern"),
                        severity=r.get("extra", {}).get("severity", "MEDIUM"),
                        confidence="MEDIUM",
                        message=r.get("extra", {}).get("message", ""),
                        code_snippet=code,
                        rule_id=r.get("check_id", ""),
                    )
                )
        except Exception as e:
            if self.verbose:
                print(f"  Pattern error: {e}")
        return findings

    def _run_dependencies(self, directory: Path) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        try:
            from guardian.scanners.dependency_scanner import run_dependency_scanner

            result = run_dependency_scanner(directory=str(directory))
            for r in result.get("results", []):
                file_path = r.get("path", "")
                line_start = r.get("start", {}).get("line", 0)
                line_end = r.get("end", {}).get("line", line_start)
                code = r.get("extra", {}).get("lines", "") or self._read_code_snippet(
                    Path(file_path), line_start, line_end
                )
                findings.append(
                    ScanFinding(
                        scanner="dependencies",
                        file_path=file_path,
                        line_start=line_start,
                        line_end=line_end,
                        category="dependency.vuln",
                        severity=r.get("extra", {}).get("severity", "HIGH"),
                        confidence="HIGH",
                        message=r.get("extra", {}).get("message", ""),
                        code_snippet=code,
                        rule_id=r.get("check_id", ""),
                    )
                )
        except Exception as e:
            if self.verbose:
                print(f"  Dependency error: {e}")
        return findings

    def _collect_files(self, directory: Path, extensions: set[str]) -> list[str]:
        files: list[str] = []
        for root, dirs, filenames in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS and not d.startswith(".")]
            for filename in filenames:
                if Path(filename).suffix in extensions:
                    files.append(str(Path(root) / filename))
        return files

    @staticmethod
    def _chunked(items: list[str], size: int) -> list[list[str]]:
        return [items[i : i + size] for i in range(0, len(items), size)]

    def _read_code_snippet(self, file_path: Path, start: int, end: int, context: int = 3) -> str:
        """Read code snippet from file (raw, without line numbers for parseability)."""
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").split("\n")
            start_idx = max(0, start - context - 1)
            end_idx = min(len(lines), end + context)
            return "\n".join(lines[start_idx:end_idx])
        except Exception:
            return ""

    def _read_code_snippet_with_lines(
        self,
        file_path: Path,
        start: int,
        end: int,
        context: int = 3,
    ) -> str:
        """Read code snippet from file with line numbers (for display)."""
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").split("\n")
            start_idx = max(0, start - context - 1)
            end_idx = min(len(lines), end + context)
            snippet_lines = []
            for i, line in enumerate(lines[start_idx:end_idx], start=start_idx + 1):
                snippet_lines.append(f"{i:4d} {line}")
            return "\n".join(snippet_lines)
        except Exception:
            return ""


class GoldLabelGenerator:
    """Generate gold labels from scanner findings using heuristics."""

    # High-confidence vulnerability patterns
    HIGH_CONFIDENCE_PATTERNS = [
        (r"subprocess\.\w+\([^)]*shell\s*=\s*True", "command_injection"),
        (r"os\.system\s*\(", "command_injection"),
        (r"eval\s*\(", "code_injection"),
        (r"exec\s*\(", "code_injection"),
        (r"pickle\.loads?\s*\(", "deserialization"),
        (r"yaml\.load\s*\([^)]*\)", "deserialization"),
        (r"cursor\.\w*execute\s*\([^)]*%|cursor\.\w*execute\s*\([^)]*\+", "sql_injection"),
        (r"innerHTML\s*=", "xss"),
        (r"document\.write\s*\(", "xss"),
    ]

    # Patterns that are often false positives
    FALSE_POSITIVE_PATTERNS = [
        r"#\s*nosec",  # Explicitly marked as safe
        r"#\s*noqa",  # Linter ignore
        r"test_\w+",  # Test files
        r"mock\.",  # Mock objects
        r"assert\s+",  # Assertions in tests
    ]

    def __init__(
        self,
        seed: int = 42,
        augment_contexts: list[int] | None = None,
        category_allowlist: set[str] | None = None,
        rule_allowlist: set[str] | None = None,
    ):
        self.seed = seed
        self.rng = random.Random(seed)
        self.augment_contexts = augment_contexts or [3]
        self.category_allowlist = category_allowlist or set()
        self.rule_allowlist = rule_allowlist or set()
        self.abstained = 0
        self._compiled_hp = [
            (re.compile(p, re.IGNORECASE), cat) for p, cat in self.HIGH_CONFIDENCE_PATTERNS
        ]
        self._compiled_fp = [re.compile(p, re.IGNORECASE) for p in self.FALSE_POSITIVE_PATTERNS]

    def _matches_allowlist(self, value: str, allowlist: set[str]) -> bool:
        if not allowlist:
            return True
        for entry in allowlist:
            if entry.endswith("*"):
                if value.startswith(entry[:-1]):
                    return True
            elif value == entry:
                return True
        return False

    def _category_allowed(self, category: str, rule_id: str | None = None) -> bool:
        if not self.category_allowlist and not self.rule_allowlist:
            return True
        candidates = {category}
        if rule_id:
            candidates.add(rule_id)
        if category and ":" in category:
            candidates.add(category.split(":", 1)[0])
        for candidate in candidates:
            if self._matches_allowlist(candidate, self.category_allowlist):
                return True
            if self._matches_allowlist(candidate, self.rule_allowlist):
                return True
        return False

    def generate_gold_labels(
        self,
        findings: list[ScanFinding],
        safe_code_samples: list[tuple[str, str, str]],  # (code, file_path, category)
    ) -> list[GoldSample]:
        """
        Generate gold-labeled samples from findings and safe code.

        Args:
            findings: Scanner findings (potentially vulnerable)
            safe_code_samples: Known safe code samples

        Returns:
            List of gold-labeled samples
        """
        samples = []

        # Process findings - determine if truly vulnerable or false positive
        finding_groups = self._group_findings(findings)

        for key, group in finding_groups.items():
            group_samples = self._create_samples_from_findings(group)
            samples.extend(group_samples)

        # Add safe code samples
        for code, file_path, category in safe_code_samples:
            sample = self._create_safe_sample(code, file_path, category)
            if sample:
                samples.append(sample)

        return samples

    def _group_findings(self, findings: list[ScanFinding]) -> dict[str, list[ScanFinding]]:
        """Group findings by file+line for consensus."""
        groups = defaultdict(list)
        for f in findings:
            key = f"{f.file_path}:{f.line_start}-{f.line_end}"
            groups[key].append(f)
        return groups

    def _read_code_snippet(self, file_path: Path, start: int, end: int, context: int) -> str:
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").split("\n")
            start_idx = max(0, start - context - 1)
            end_idx = min(len(lines), end + context)
            return "\n".join(lines[start_idx:end_idx])
        except Exception:
            return ""

    def _create_samples_from_findings(self, findings: list[ScanFinding]) -> list[GoldSample]:
        """Create labeled samples from a group of findings."""
        if not findings:
            return []

        f = findings[0]
        snippets: list[tuple[str, int]] = []
        if f.file_path:
            for ctx in sorted(set(self.augment_contexts)):
                snippet = self._read_code_snippet(
                    Path(f.file_path), f.line_start, f.line_end, context=ctx
                )
                if snippet and len(snippet.strip()) >= 10:
                    snippets.append((snippet, ctx))
        if not snippets and f.code_snippet and len(f.code_snippet.strip()) >= 10:
            snippets.append((f.code_snippet, -1))
        if not snippets:
            return []

        # Calculate consensus score
        scanner_sources = list(set(f.scanner for f in findings))
        consensus_score = len(scanner_sources) / len(MultiScanner.SCANNERS)

        # Determine severity (highest among findings)
        severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        max_severity = max(findings, key=lambda x: severity_order.get(x.severity, 0))

        # Determine if true positive or false positive
        # Determine if true positive or false positive from the first snippet
        is_tp, detected_category = self._classify_finding(snippets[0][0], findings)

        # Use detected category or scanner category (only for true positives)
        category = detected_category or f.rule_id or f.category
        if not is_tp:
            category = ""
        elif category and not self._category_allowed(category, f.rule_id):
            category = ""

        # Generate sample ID
        samples: list[GoldSample] = []
        for code, ctx in snippets:
            sample_id = hashlib.sha256(
                f"{f.file_path}:{f.line_start}:{ctx}:{code[:100]}".encode()
            ).hexdigest()
            tokens = self._tokenize(code)
            features = self._extract_features(code)
            if not is_tp and (detected_category or f.category):
                features["fp_category"] = detected_category or f.category
            samples.append(
                GoldSample(
                    sample_id=sample_id,
                    code=code,
                    tokens=tokens,
                    label=1 if is_tp else 0,
                    verdict="TP" if is_tp else "FP",
                    category=category,
                    severity=max_severity.severity,
                    confidence=max_severity.confidence,
                    scanner_sources=scanner_sources,
                    consensus_score=consensus_score,
                    file_path=f.file_path,
                    line_start=f.line_start,
                    line_end=f.line_end,
                    features=features,
                )
            )
        return samples

    def _create_safe_sample(self, code: str, file_path: str, category: str) -> GoldSample | None:
        """Create a safe (FP) sample from clean code."""
        if not code or len(code.strip()) < 10:
            return None

        sample_id = hashlib.sha256(f"safe:{file_path}:{code[:100]}".encode()).hexdigest()

        tokens = self._tokenize(code)
        features = self._extract_features(code)
        if category:
            features["safe_category"] = category

        return GoldSample(
            sample_id=sample_id,
            code=code,
            tokens=tokens,
            label=0,
            verdict="FP",
            category="",
            severity="LOW",
            confidence="HIGH",
            scanner_sources=[],
            consensus_score=0.0,
            file_path=file_path,
            line_start=1,
            line_end=code.count("\n") + 1,
            features=features,
        )

    def _classify_finding(self, code: str, findings: list[ScanFinding]) -> tuple[bool, str | None]:
        """
        Classify if a finding is a true positive.

        Returns:
            (is_true_positive, detected_category)
        """
        # Check for false positive indicators
        for pattern in self._compiled_fp:
            if pattern.search(code):
                return False, None

        # Check for high-confidence vulnerability patterns
        for pattern, category in self._compiled_hp:
            if pattern.search(code):
                return True, category

        # Use scanner consensus and severity
        scanner_count = len(set(f.scanner for f in findings))
        severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        confidence_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        max_severity = max((severity_rank.get(f.severity, 0) for f in findings), default=0)
        max_confidence = max((confidence_rank.get(f.confidence, 0) for f in findings), default=0)
        has_high_severity = max_severity >= 3
        has_medium_severity = max_severity >= 2
        has_high_confidence = max_confidence >= 3
        has_medium_confidence = max_confidence >= 2

        # Trusted scanners: treat as true positives
        for finding in findings:
            if finding.scanner in {"secrets", "dependencies"}:
                return True, finding.category or finding.rule_id

        # Allowlist-driven positives
        rule_ids = sorted({f.rule_id for f in findings if f.rule_id})
        categories = sorted({f.category for f in findings if f.category})
        for rule_id in rule_ids:
            if self._matches_allowlist(rule_id, self.rule_allowlist):
                return True, rule_id
            if self._matches_allowlist(rule_id, self.category_allowlist):
                return True, rule_id
        for category in categories:
            if self._matches_allowlist(category, self.category_allowlist):
                return True, category.split(":", 1)[0] if ":" in category else category
            if self._matches_allowlist(category, self.rule_allowlist):
                return True, category.split(":", 1)[0] if ":" in category else category

        # Multi-scanner agreement = likely true positive
        if scanner_count >= 2 and has_medium_severity:
            return True, None

        if scanner_count >= 3:
            return True, None

        # Single scanner with medium/high severity + confidence
        if has_medium_severity and has_medium_confidence:
            return True, None

        if has_high_severity and has_high_confidence:
            return True, None

        # Default to false positive for low confidence findings
        return False, None

    def _tokenize(self, code: str) -> list[str]:
        """Tokenize code."""
        return re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*|[0-9]+|[^\s\w]", code)[:512]

    def _extract_features(self, code: str) -> dict[str, Any]:
        """Extract features for the sample."""
        lines = code.split("\n")
        return {
            "n_lines": len(lines),
            "n_chars": len(code),
            "n_tokens": len(self._tokenize(code)),
            "avg_line_length": sum(len(line) for line in lines) / max(1, len(lines)),
            "has_import": "import " in code,
            "has_function_def": "def " in code,
            "has_class_def": "class " in code,
            "has_try_except": "try:" in code or "except" in code,
            "has_eval": "eval(" in code,
            "has_exec": "exec(" in code,
            "has_subprocess": "subprocess" in code,
            "has_os_system": "os.system" in code,
            "has_sql": any(
                kw in code.lower() for kw in ["select", "insert", "update", "delete", "execute"]
            ),
            "has_shell": "shell=True" in code or "shell = True" in code,
        }


class CouncilGoldLabeler(GoldLabelGenerator):
    """Precision-first labeler that abstains when evidence is ambiguous."""

    def __init__(
        self,
        seed: int = 42,
        augment_contexts: list[int] | None = None,
        category_allowlist: set[str] | None = None,
        rule_allowlist: set[str] | None = None,
        min_agreement: int = 2,
        min_scanners: int = 2,
    ):
        super().__init__(
            seed=seed,
            augment_contexts=augment_contexts,
            category_allowlist=category_allowlist,
            rule_allowlist=rule_allowlist,
        )
        self.min_agreement = max(1, min_agreement)
        self.min_scanners = max(1, min_scanners)

    def _classify_council(
        self, code: str, findings: list[ScanFinding]
    ) -> tuple[bool | None, str | None]:
        tp_votes = 0
        fp_votes = 0
        detected_category: str | None = None

        for pattern in self._compiled_fp:
            if pattern.search(code):
                fp_votes += 2

        for pattern, category in self._compiled_hp:
            if pattern.search(code):
                tp_votes += 2
                if detected_category is None:
                    detected_category = category

        for finding in findings:
            if finding.scanner in {"secrets", "dependencies"}:
                tp_votes += 2
                if detected_category is None:
                    detected_category = finding.category or finding.rule_id

        rule_ids = sorted({f.rule_id for f in findings if f.rule_id})
        categories = sorted({f.category for f in findings if f.category})
        for rule_id in rule_ids:
            if self._matches_allowlist(rule_id, self.rule_allowlist) or self._matches_allowlist(
                rule_id, self.category_allowlist
            ):
                tp_votes += 2
                if detected_category is None:
                    detected_category = rule_id
        for category in categories:
            if self._matches_allowlist(
                category, self.category_allowlist
            ) or self._matches_allowlist(category, self.rule_allowlist):
                tp_votes += 2
                if detected_category is None:
                    detected_category = category.split(":", 1)[0] if ":" in category else category

        scanner_count = len({f.scanner for f in findings})
        severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        confidence_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        max_severity = max((severity_rank.get(f.severity, 0) for f in findings), default=0)
        max_confidence = max((confidence_rank.get(f.confidence, 0) for f in findings), default=0)

        if scanner_count >= self.min_scanners and max_severity >= 2:
            tp_votes += 1
        if scanner_count >= self.min_scanners and max_confidence >= 2:
            tp_votes += 1
        if scanner_count == 1 and max_severity <= 1 and max_confidence <= 1:
            fp_votes += 1

        if tp_votes >= 2 and tp_votes >= fp_votes + 1:
            return True, detected_category
        if fp_votes >= 2 and fp_votes >= tp_votes + 1:
            return False, None
        if tp_votes >= self.min_agreement and tp_votes > fp_votes:
            return True, detected_category
        if fp_votes >= self.min_agreement and fp_votes > tp_votes:
            return False, None

        return None, None

    def _create_samples_from_findings(self, findings: list[ScanFinding]) -> list[GoldSample]:
        if not findings:
            return []

        f = findings[0]
        snippets: list[tuple[str, int]] = []
        if f.file_path:
            for ctx in sorted(set(self.augment_contexts)):
                snippet = self._read_code_snippet(
                    Path(f.file_path), f.line_start, f.line_end, context=ctx
                )
                if snippet and len(snippet.strip()) >= 10:
                    snippets.append((snippet, ctx))
        if not snippets and f.code_snippet and len(f.code_snippet.strip()) >= 10:
            snippets.append((f.code_snippet, -1))
        if not snippets:
            return []

        scanner_sources = list(set(f.scanner for f in findings))
        consensus_score = len(scanner_sources) / len(MultiScanner.SCANNERS)

        severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        max_severity = max(findings, key=lambda x: severity_order.get(x.severity, 0))

        is_tp, detected_category = self._classify_council(snippets[0][0], findings)
        if is_tp is None:
            self.abstained += 1
            return []

        category = detected_category or f.rule_id or f.category
        if is_tp:
            if category and not self._category_allowed(category, f.rule_id):
                self.abstained += 1
                return []
        else:
            if (self.category_allowlist or self.rule_allowlist) and category:
                if not self._category_allowed(category, f.rule_id):
                    self.abstained += 1
                    return []
            category = ""

        samples: list[GoldSample] = []
        for code, ctx in snippets:
            sample_id = hashlib.sha256(
                f"{f.file_path}:{f.line_start}:{ctx}:{code[:100]}".encode()
            ).hexdigest()
            tokens = self._tokenize(code)
            features = self._extract_features(code)
            if not is_tp and (detected_category or f.category):
                features["fp_category"] = detected_category or f.category
            samples.append(
                GoldSample(
                    sample_id=sample_id,
                    code=code,
                    tokens=tokens,
                    label=1 if is_tp else 0,
                    verdict="TP" if is_tp else "FP",
                    category=category,
                    severity=max_severity.severity,
                    confidence=max_severity.confidence,
                    scanner_sources=scanner_sources,
                    consensus_score=consensus_score,
                    file_path=f.file_path,
                    line_start=f.line_start,
                    line_end=f.line_end,
                    features=features,
                )
            )
        return samples


class SafeCodeExtractor:
    """Extract safe code samples from repositories."""

    EXTENSIONS = {".py", ".js", ".ts", ".java", ".go", ".rb"}

    def __init__(self, seed: int = 42, max_samples_per_repo: int = 100):
        self.seed = seed
        self.max_samples_per_repo = max_samples_per_repo
        self.rng = random.Random(seed)

    def extract_safe_samples(
        self,
        repos_dir: Path,
        exclude_files: set[str],  # Files with findings
    ) -> list[tuple[str, str, str]]:
        """
        Extract safe code samples from repositories.

        Args:
            repos_dir: Root directory containing repositories
            exclude_files: Files that have scanner findings (avoid those)

        Returns:
            List of (code, file_path, category) tuples
        """
        samples = []

        # Normalize exclude paths
        exclude_normalized = {Path(f).resolve() for f in exclude_files if f}

        for repo_dir in sorted(repos_dir.iterdir()):
            if not repo_dir.is_dir():
                continue

            repo_samples = []
            code_files = list(repo_dir.rglob("*"))
            self.rng.shuffle(code_files)

            for file_path in code_files:
                if len(repo_samples) >= self.max_samples_per_repo:
                    break

                if not file_path.is_file():
                    continue

                if file_path.suffix not in self.EXTENSIONS:
                    continue

                # Skip files with findings
                if file_path.resolve() in exclude_normalized:
                    continue

                # Skip test files
                if "test" in file_path.name.lower():
                    continue

                try:
                    code = file_path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                if len(code) < 50 or len(code) > 10000:
                    continue

                # Extract function/class snippets
                snippets = self._extract_snippets(code, str(file_path))
                for snippet, category in snippets[:5]:  # Max 5 per file
                    if len(repo_samples) < self.max_samples_per_repo:
                        repo_samples.append((snippet, str(file_path), category))

            samples.extend(repo_samples)

        return samples

    def _extract_snippets(self, code: str, file_path: str) -> list[tuple[str, str]]:
        """Extract code snippets from a file."""
        snippets = []

        # Try to parse as Python
        if file_path.endswith(".py"):
            try:
                tree = ast.parse(code)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        start = node.lineno
                        end = node.end_lineno or start + 10
                        snippet = self._extract_lines(code, start, end)
                        if snippet:
                            snippets.append((snippet, "safe_function"))
                    elif isinstance(node, ast.ClassDef):
                        start = node.lineno
                        end = min(node.lineno + 30, node.end_lineno or node.lineno + 30)
                        snippet = self._extract_lines(code, start, end)
                        if snippet:
                            snippets.append((snippet, "safe_class"))
            except SyntaxError:
                pass

        # Fallback: extract random chunks
        if not snippets:
            lines = code.split("\n")
            chunk_size = 20
            for i in range(0, len(lines) - chunk_size, chunk_size // 2):
                snippet = "\n".join(lines[i : i + chunk_size])
                if len(snippet) > 50:
                    snippets.append((snippet, "safe_code"))

        return snippets

    def _extract_lines(self, code: str, start: int, end: int) -> str:
        """Extract lines from code."""
        lines = code.split("\n")
        start_idx = max(0, start - 1)
        end_idx = min(len(lines), end)
        return "\n".join(lines[start_idx:end_idx])


class DatasetBuilder:
    """Build balanced train/test/val datasets."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        self.rng = random.Random(seed)

    def build_balanced_splits(
        self,
        samples: list[GoldSample],
        train_ratio: float = 0.8,
        val_ratio: float = 0.1,
        test_ratio: float = 0.1,
        balance_mode: str = "ratio",
        max_safe_ratio: float = 5.0,
        min_pos_per_category: int = 0,
        max_pos_per_category: int = 0,
    ) -> tuple[list[GoldSample], list[GoldSample], list[GoldSample]]:
        """
        Build balanced train/val/test splits.

        Returns:
            (train, val, test) sample lists
        """
        # Separate by label
        vulnerable = [s for s in samples if s.label == 1]
        safe = [s for s in samples if s.label == 0]

        print(f"  Raw samples: {len(vulnerable)} vulnerable, {len(safe)} safe")

        # Shuffle
        self.rng.shuffle(vulnerable)
        self.rng.shuffle(safe)

        if balance_mode == "none":
            print("  Balance mode: none (using all samples)")
        elif balance_mode == "category":
            vuln_by_category: dict[str, list[GoldSample]] = defaultdict(list)
            for sample in vulnerable:
                vuln_by_category[sample.category].append(sample)

            balanced_vulnerable: list[GoldSample] = []
            for category in sorted(vuln_by_category):
                items = vuln_by_category[category]
                self.rng.shuffle(items)
                if max_pos_per_category > 0:
                    items = items[:max_pos_per_category]
                if min_pos_per_category > 0 and items:
                    needed = min_pos_per_category - len(items)
                    if needed > 0:
                        items = items + [self.rng.choice(items) for _ in range(needed)]
                balanced_vulnerable.extend(items)

            vulnerable = balanced_vulnerable
            counts = Counter(s.category for s in vulnerable)
            top_counts = sorted(counts.items(), key=lambda x: (-x[1], x[0]))[:8]
            print(
                "  Balance mode: category "
                f"(min_pos_per_category={min_pos_per_category}, "
                f"max_pos_per_category={max_pos_per_category}) -> "
                f"{len(vulnerable)} vulnerable"
            )
            if top_counts:
                print("  Category counts (top): " + ", ".join(f"{k}={v}" for k, v in top_counts))
            if not vulnerable or not safe:
                print("  WARNING: No samples in one class!")
            else:
                max_safe = int(len(vulnerable) * max_safe_ratio)
                safe = safe[: max_safe if max_safe > 0 else len(safe)]
        elif balance_mode == "ratio":
            if not vulnerable or not safe:
                print("  WARNING: No samples in one class!")
            max_safe = int(len(vulnerable) * max_safe_ratio)
            safe = safe[: max_safe if max_safe > 0 else len(safe)]
            print(
                f"  Balance mode: ratio (max_safe_ratio={max_safe_ratio}) -> "
                f"{len(vulnerable)} vulnerable, {len(safe)} safe"
            )
        else:
            min_count = min(len(vulnerable), len(safe))
            if min_count == 0:
                print("  WARNING: No samples in one class!")
                min_count = max(len(vulnerable), len(safe))
            vulnerable = vulnerable[:min_count]
            safe = safe[:min_count]
            print(f"  Balance mode: downsample -> {len(vulnerable)} vulnerable, {len(safe)} safe")

        # Split each class proportionally
        def split_list(items: list) -> tuple[list, list, list]:
            n = len(items)
            if n == 0:
                return [], [], []
            if n == 1:
                return items[:1], [], []
            if n == 2:
                return items[:1], [], items[1:2]

            n_train = max(1, int(n * train_ratio))
            n_val = max(1, int(n * val_ratio))
            n_test = n - n_train - n_val
            if n_test <= 0:
                n_test = 1
                if n_val > 1:
                    n_val -= 1
                else:
                    n_train = max(1, n_train - 1)
            if n_train + n_val + n_test > n:
                n_train = max(1, n - n_val - n_test)

            return (
                items[:n_train],
                items[n_train : n_train + n_val],
                items[n_train + n_val : n_train + n_val + n_test],
            )

        vuln_train, vuln_val, vuln_test = split_list(vulnerable)
        safe_train, safe_val, safe_test = split_list(safe)

        # Combine and shuffle
        train = vuln_train + safe_train
        val = vuln_val + safe_val
        test = vuln_test + safe_test

        self.rng.shuffle(train)
        self.rng.shuffle(val)
        self.rng.shuffle(test)

        train, val, test = self._ensure_class_presence(train, val, test)
        self.rng.shuffle(train)
        self.rng.shuffle(val)
        self.rng.shuffle(test)

        return train, val, test

    def _ensure_class_presence(
        self,
        train: list[GoldSample],
        val: list[GoldSample],
        test: list[GoldSample],
    ) -> tuple[list[GoldSample], list[GoldSample], list[GoldSample]]:
        def _labels(items: list[GoldSample]) -> set[int]:
            return {s.label for s in items}

        def _count(items: list[GoldSample], label: int) -> int:
            return sum(1 for s in items if s.label == label)

        def _move_one(pool: list[GoldSample], label: int) -> GoldSample | None:
            for idx, sample in enumerate(pool):
                if sample.label == label:
                    return pool.pop(idx)
            return None

        def _adjust(split_name: str, split: list[GoldSample], pool: list[GoldSample]) -> None:
            labels = _labels(split)
            if len(labels) >= 2 or not split:
                return
            missing = 0 if 1 in labels else 1
            if _count(pool, missing) <= 1:
                print(
                    f"  WARNING: {split_name} missing label {missing} and train has "
                    "insufficient samples to rebalance"
                )
                return
            moved = _move_one(pool, missing)
            if moved:
                split.append(moved)
                print(f"  Adjusted {split_name}: added one sample of label {missing}")

        _adjust("val", val, train)
        _adjust("test", test, train)
        return train, val, test

    def save_datasets(
        self,
        train: list[GoldSample],
        val: list[GoldSample],
        test: list[GoldSample],
        output_dir: Path,
        dataset_name: str,
    ) -> dict[str, Path]:
        """Save datasets to JSONL files."""
        dataset_dir = output_dir / dataset_name
        dataset_dir.mkdir(parents=True, exist_ok=True)

        paths = {}
        for split_name, samples in [("train", train), ("val", val), ("test", test)]:
            path = dataset_dir / f"{split_name}.jsonl"
            with path.open("w", encoding="utf-8") as f:
                for sample in samples:
                    f.write(json.dumps(sample.to_dict()) + "\n")
            paths[split_name] = path

        # Save stats
        stats = {
            "created_at": datetime.now(UTC).isoformat(),
            "seed": self.seed,
            "train_size": len(train),
            "val_size": len(val),
            "test_size": len(test),
            "train_vulnerable": sum(1 for s in train if s.label == 1),
            "train_safe": sum(1 for s in train if s.label == 0),
            "categories": sorted({s.category for s in train if s.category}),
        }
        (dataset_dir / "stats.json").write_text(
            json.dumps(stats, indent=2),
            encoding="utf-8",
        )

        return paths


def run_pipeline(args: argparse.Namespace) -> dict[str, Any]:
    """Run the complete data pipeline."""
    results = {
        "started_at": datetime.now(UTC).isoformat(),
        "args": vars(args),
        "steps": {},
    }

    repos_dir = Path(args.repos_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("  ML Data Pipeline")
    print("=" * 70)

    # Step 1: Scan repositories
    print("\n[1/5] Scanning repositories with multiple scanners...")
    rule_allowlist = _load_allowlist(args.rule_allowlist)
    category_allowlist = _load_allowlist(args.category_allowlist)

    def _scan_with(
        min_confidence: str | None,
        rule_allowlist_override: set[str],
        category_allowlist_override: set[str],
    ) -> tuple[list[ScanFinding], set[str]]:
        scanner = MultiScanner(
            verbose=args.verbose,
            semgrep_config=args.semgrep_config,
            semgrep_experimental=args.semgrep_experimental,
            min_confidence=min_confidence,
            rule_allowlist=rule_allowlist_override,
            category_allowlist=category_allowlist_override,
        )
        findings: list[ScanFinding] = []
        finding_files: set[str] = set()
        for repo in sorted(repos_dir.iterdir()):
            if not repo.is_dir():
                continue
            if repo.name.startswith("."):
                continue
            print(f"  Scanning: {repo.name}")
            repo_findings = scanner.scan_directory(repo, max_files=args.max_files, seed=args.seed)
            findings.extend(repo_findings)
            finding_files.update(f.file_path for f in repo_findings)
            print(f"    Found {len(repo_findings)} findings")
        return findings, finding_files

    used_min_confidence = args.min_confidence
    used_rule_allowlist = set(rule_allowlist)
    used_category_allowlist = set(category_allowlist)
    relaxed_from: dict[str, Any] | None = None

    all_findings, finding_files = _scan_with(
        used_min_confidence,
        used_rule_allowlist,
        used_category_allowlist,
    )
    if not all_findings and args.auto_relax:
        relaxed_from = {
            "min_confidence": used_min_confidence,
            "rule_allowlist": sorted(used_rule_allowlist),
            "category_allowlist": sorted(used_category_allowlist),
        }
        used_min_confidence = "LOW"
        used_rule_allowlist = set()
        used_category_allowlist = set()
        print("  No findings with current filters; relaxing to LOW and clearing allowlists")
        all_findings, finding_files = _scan_with(
            used_min_confidence,
            used_rule_allowlist,
            used_category_allowlist,
        )

    results["steps"]["scan"] = {
        "total_findings": len(all_findings),
        "repos_scanned": len([d for d in repos_dir.iterdir() if d.is_dir()]),
        "files_with_findings": len(finding_files),
        "min_confidence": used_min_confidence,
        "rule_allowlist": sorted(used_rule_allowlist),
        "category_allowlist": sorted(used_category_allowlist),
        "auto_relax": args.auto_relax,
        "relaxed_from": relaxed_from,
    }
    print(f"  Total findings: {len(all_findings)}")

    if not all_findings and args.fail_on_empty:
        results["completed_at"] = datetime.now(UTC).isoformat()
        results["success"] = False
        results["failure_reason"] = "no_findings"
        results_path = output_dir / "data_pipeline_results.json"
        results_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        raise SystemExit("No findings produced; aborting due to --fail-on-empty")

    # Step 2: Extract safe code samples
    print("\n[2/5] Extracting safe code samples...")
    safe_extractor = SafeCodeExtractor(seed=args.seed, max_samples_per_repo=args.max_samples)
    safe_samples = safe_extractor.extract_safe_samples(repos_dir, finding_files)
    print(f"  Extracted {len(safe_samples)} safe samples")

    results["steps"]["safe_extraction"] = {
        "total_safe_samples": len(safe_samples),
    }

    # Step 3: Generate gold labels
    print("\n[3/5] Generating gold labels...")
    contexts = [int(c.strip()) for c in args.augment_contexts.split(",") if c.strip()]
    if args.gold_labeler == "council":
        labeler = CouncilGoldLabeler(
            seed=args.seed,
            augment_contexts=contexts,
            category_allowlist=used_category_allowlist,
            rule_allowlist=used_rule_allowlist,
            min_agreement=args.council_min_agreement,
            min_scanners=args.council_min_scanners,
        )
    else:
        labeler = GoldLabelGenerator(
            seed=args.seed,
            augment_contexts=contexts,
            category_allowlist=used_category_allowlist,
            rule_allowlist=used_rule_allowlist,
        )
    gold_samples = labeler.generate_gold_labels(all_findings, safe_samples)

    vulnerable = sum(1 for s in gold_samples if s.label == 1)
    safe = sum(1 for s in gold_samples if s.label == 0)
    print(f"  Generated {len(gold_samples)} gold samples ({vulnerable} vuln, {safe} safe)")

    categories = sorted({s.category for s in gold_samples if s.category})
    abstained = getattr(labeler, "abstained", 0)
    if abstained:
        print(f"  Council abstained on {abstained} candidates")

    results["steps"]["gold_labeling"] = {
        "total_samples": len(gold_samples),
        "vulnerable": vulnerable,
        "safe": safe,
        "augment_contexts": contexts,
        "categories": categories,
        "labeler": args.gold_labeler,
        "abstained": abstained,
    }

    if args.fail_on_empty and vulnerable == 0:
        results["completed_at"] = datetime.now(UTC).isoformat()
        results["success"] = False
        results["failure_reason"] = "no_vulnerable_samples"
        results_path = output_dir / "data_pipeline_results.json"
        results_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        raise SystemExit("No vulnerable samples generated; aborting due to --fail-on-empty")

    if args.fail_on_empty and not categories:
        results["completed_at"] = datetime.now(UTC).isoformat()
        results["success"] = False
        results["failure_reason"] = "no_categories"
        results_path = output_dir / "data_pipeline_results.json"
        results_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        raise SystemExit("No categories produced; aborting due to --fail-on-empty")

    # Step 4: Build balanced datasets
    print("\n[4/5] Building balanced train/val/test splits...")
    builder = DatasetBuilder(seed=args.seed)
    train, val, test = builder.build_balanced_splits(
        gold_samples,
        train_ratio=0.8,
        val_ratio=0.1,
        test_ratio=0.1,
        balance_mode=args.balance_mode,
        max_safe_ratio=args.max_safe_ratio,
        min_pos_per_category=args.min_pos_per_category,
        max_pos_per_category=args.max_pos_per_category,
    )

    print(f"  Train: {len(train)} ({sum(1 for s in train if s.label == 1)} vuln)")
    print(f"  Val:   {len(val)} ({sum(1 for s in val if s.label == 1)} vuln)")
    print(f"  Test:  {len(test)} ({sum(1 for s in test if s.label == 1)} vuln)")

    # Step 5: Save datasets
    print("\n[5/5] Saving datasets...")

    # Save for Transformer
    builder.save_datasets(train, val, test, output_dir, "transformer")
    print(f"  Transformer: {output_dir / 'transformer'}")

    # Save for GNN (full dataset; parseable graphs determined at training time)
    builder.save_datasets(train, val, test, output_dir, "gnn")
    print(f"  GNN: {output_dir / 'gnn'} ({len(train)} train samples)")

    results["steps"]["datasets"] = {
        "transformer": {
            "train": len(train),
            "val": len(val),
            "test": len(test),
        },
        "gnn": {
            "train": len(train),
            "val": len(val),
            "test": len(test),
        },
    }

    results["completed_at"] = datetime.now(UTC).isoformat()
    results["success"] = True

    # Save results
    results_path = output_dir / "data_pipeline_results.json"
    results_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    print("\n" + "=" * 70)
    print("  Pipeline Complete!")
    print("=" * 70)
    print(f"\n  Results: {results_path}")

    return results


def _load_allowlist(value: str | None) -> set[str]:
    if not value:
        return set()
    path = Path(value)
    if path.exists():
        entries = []
        for line in path.read_text(encoding="utf-8").splitlines():
            cleaned = line.strip()
            if not cleaned or cleaned.startswith("#"):
                continue
            entries.append(cleaned)
        return set(entries)
    return {item.strip() for item in value.split(",") if item.strip()}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ML Data Pipeline - Scan repos and generate balanced datasets"
    )
    parser.add_argument(
        "--repos-dir",
        default="data/repos",
        help="Directory containing repositories to scan",
    )
    parser.add_argument(
        "--output-dir",
        default="artifacts/models/datasets",
        help="Output directory for datasets",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=100,
        help="Max safe samples per repository",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=1500,
        help="Max files per repository to scan (bandit/semgrep)",
    )
    parser.add_argument(
        "--semgrep-config",
        default="max",
        help="Semgrep config (max, comprehensive, or comma-separated configs)",
    )
    parser.add_argument(
        "--semgrep-experimental",
        action="store_true",
        help="Include Semgrep experimental rules for broader coverage",
    )
    parser.add_argument(
        "--min-confidence",
        choices=["LOW", "MEDIUM", "HIGH"],
        default="MEDIUM",
        help="Minimum confidence to keep a finding",
    )
    parser.add_argument(
        "--auto-relax",
        action="store_true",
        help="Relax filters (LOW confidence, no allowlists) if no findings are produced",
    )
    parser.add_argument(
        "--fail-on-empty",
        action="store_true",
        help="Fail the pipeline if no findings or no vulnerable samples are produced",
    )
    parser.add_argument(
        "--rule-allowlist",
        default="",
        help="Comma-separated list or file path of allowed rule IDs (supports * suffix)",
    )
    parser.add_argument(
        "--category-allowlist",
        default="",
        help="Comma-separated list or file path of allowed categories (supports * suffix)",
    )
    parser.add_argument(
        "--balance-mode",
        choices=["ratio", "downsample", "none", "category"],
        default="ratio",
        help="Balancing strategy for train/val/test splits",
    )
    parser.add_argument(
        "--max-safe-ratio",
        type=float,
        default=5.0,
        help="Max safe samples per vulnerable sample (ratio mode)",
    )
    parser.add_argument(
        "--min-pos-per-category",
        type=int,
        default=0,
        help="Minimum positives per category (category mode)",
    )
    parser.add_argument(
        "--max-pos-per-category",
        type=int,
        default=0,
        help="Maximum positives per category (category mode)",
    )
    parser.add_argument(
        "--gold-labeler",
        choices=["heuristic", "council"],
        default="heuristic",
        help="Gold labeler strategy (heuristic or council consensus)",
    )
    parser.add_argument(
        "--council-min-agreement",
        type=int,
        default=2,
        help="Minimum council agreement for a gold label",
    )
    parser.add_argument(
        "--council-min-scanners",
        type=int,
        default=2,
        help="Minimum distinct scanners required for council labeling",
    )
    parser.add_argument(
        "--augment-contexts",
        default="3",
        help="Comma-separated context sizes for vulnerable snippet augmentation",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    run_pipeline(args)


if __name__ == "__main__":
    main()
