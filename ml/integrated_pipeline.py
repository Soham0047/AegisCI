#!/usr/bin/env python3
"""
Integrated ML + RAG + LLM Pipeline for SecureDev Guardian.

This module combines:
1. ML-based vulnerability detection and risk scoring
2. RAG-based retrieval of fix patterns and documentation
3. LLM-based patch generation with citations

The pipeline provides end-to-end vulnerability detection, analysis, and remediation.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Load environment variables from .env file
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

from ml.inference import EnhancedInferenceEngine, PredictionResult


@dataclass
class RAGCitation:
    """A citation from the RAG knowledge base."""

    chunk_id: str
    title: str
    snippet: str
    score: float
    source: str


@dataclass
class PatchSuggestion:
    """A suggested patch from the LLM."""

    diff: str
    explanation: str
    confidence: float
    citations: list[RAGCitation]
    source: str  # "deterministic", "llm", "template"


@dataclass
class IntegratedFinding:
    """A finding enriched with ML scoring, RAG context, and patch suggestions."""

    finding_id: str
    code_snippet: str
    file_path: str
    line_start: int
    line_end: int
    category: str
    severity: str

    # ML enrichment
    ml_risk_score: float
    ml_risk_label: str
    ml_confidence: float
    ml_model_source: str

    # RAG enrichment
    citations: list[RAGCitation] = field(default_factory=list)

    # LLM enrichment
    patch_suggestions: list[PatchSuggestion] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "code_snippet": self.code_snippet,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "category": self.category,
            "severity": self.severity,
            "ml_analysis": {
                "risk_score": self.ml_risk_score,
                "risk_label": self.ml_risk_label,
                "confidence": self.ml_confidence,
                "model_source": self.ml_model_source,
            },
            "citations": [
                {
                    "chunk_id": c.chunk_id,
                    "title": c.title,
                    "snippet": c.snippet[:200],
                    "score": c.score,
                }
                for c in self.citations
            ],
            "patch_suggestions": [
                {
                    "diff": p.diff,
                    "explanation": p.explanation,
                    "confidence": p.confidence,
                    "source": p.source,
                }
                for p in self.patch_suggestions
            ],
        }


class IntegratedPipeline:
    """
    Unified pipeline combining ML, RAG, and LLM for vulnerability analysis.

    Flow:
    1. Scan code with traditional scanners (Bandit, Semgrep)
    2. Score findings with ML model for risk prioritization
    3. Retrieve relevant fix patterns from RAG knowledge base
    4. Generate patch suggestions using LLM with RAG citations
    """

    def __init__(
        self,
        artifacts_dir: Path | None = None,
        rag_store_path: Path | None = None,
        llm_provider: str | None = None,
    ):
        self.artifacts_dir = artifacts_dir or Path("artifacts/dl")
        self.rag_store_path = rag_store_path or Path("artifacts/rag_store.db")
        self.llm_provider = llm_provider or os.environ.get("PATCH_LLM_PROVIDER", "local")

        # Initialize ML engine
        self._ml_engine = EnhancedInferenceEngine(artifacts_dir=self.artifacts_dir)

        # RAG retriever (lazy load)
        self._rag_retriever = None

    def _get_rag_retriever(self):
        """Lazy-load RAG retriever."""
        if self._rag_retriever is None:
            if self.rag_store_path.exists():
                from rag.retriever import RAGRetriever

                self._rag_retriever = RAGRetriever(self.rag_store_path)
            else:
                # Build index if not exists
                from rag.indexer import build_index

                kb_paths = [Path("rag/kb")]
                build_index(kb_paths, self.rag_store_path)
                from rag.retriever import RAGRetriever

                self._rag_retriever = RAGRetriever(self.rag_store_path)
        return self._rag_retriever

    def analyze_finding(
        self,
        finding: dict[str, Any],
        generate_patches: bool = True,
        top_k_citations: int = 5,
    ) -> IntegratedFinding:
        """
        Analyze a single finding with ML + RAG + LLM.

        Args:
            finding: Raw finding from scanner
            generate_patches: Whether to generate patch suggestions
            top_k_citations: Number of RAG citations to retrieve

        Returns:
            IntegratedFinding with ML scores, citations, and patch suggestions
        """
        # Extract basic info - handle both our format and bandit/semgrep format
        # Bandit format: filename, line_number, code, test_id, issue_text
        # Our format: code_snippet, file_path, line_start, category
        code_snippet = (
            finding.get("code_snippet")
            or finding.get("code")
            or finding.get("evidence", {}).get("excerpt", "")
            or ""
        )
        file_path = (
            finding.get("file_path")
            or finding.get("filename")  # Bandit
            or finding.get("location", {}).get("filepath", "")
            or finding.get("path", "")  # Semgrep
            or "unknown"
        )
        line_start = (
            finding.get("line_start")
            or finding.get("line_number")  # Bandit
            or finding.get("location", {}).get("start_line", 0)
            or finding.get("start", {}).get("line", 0)  # Semgrep
            or 0
        )
        line_end = (
            finding.get("line_end")
            or finding.get("location", {}).get("end_line", line_start)
            or finding.get("end", {}).get("line", line_start)  # Semgrep
            or line_start
        )
        category = (
            finding.get("category")
            or finding.get("test_id")  # Bandit
            or finding.get("rule", {}).get("category", "")
            or finding.get("check_id", "")  # Semgrep
            or "unknown"
        )
        severity = (
            finding.get("severity")
            or finding.get("issue_severity", "").lower()  # Bandit
            or "medium"
        )
        finding_id = (
            finding.get("finding_id") or finding.get("sample_id") or f"{file_path}:{line_start}"
        )

        # Step 1: ML Risk Scoring
        ml_result = self._ml_engine.predict_risk(
            code_snippet=code_snippet,
            category_hint=category,
            scanner_sources=finding.get("scanner_sources", []),
            consensus_score=finding.get("consensus_score"),
        )

        # Step 2: RAG Retrieval
        citations = self._retrieve_citations(category, code_snippet, top_k_citations)

        # Step 3: Create enriched finding
        enriched = IntegratedFinding(
            finding_id=finding_id,
            code_snippet=code_snippet,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            category=category,
            severity=severity,
            ml_risk_score=ml_result.risk_score,
            ml_risk_label=ml_result.risk_label,
            ml_confidence=ml_result.confidence,
            ml_model_source=ml_result.model_source,
            citations=citations,
        )

        # Step 4: Generate patch suggestions (if requested)
        if generate_patches and ml_result.risk_score > 0.3:
            patches = self._generate_patches(enriched)
            enriched.patch_suggestions = patches

        return enriched

    def analyze_batch(
        self,
        findings: list[dict[str, Any]],
        generate_patches: bool = True,
        top_k_citations: int = 5,
    ) -> list[IntegratedFinding]:
        """Analyze multiple findings."""
        return [self.analyze_finding(f, generate_patches, top_k_citations) for f in findings]

    def _retrieve_citations(
        self,
        category: str,
        code_snippet: str,
        top_k: int,
    ) -> list[RAGCitation]:
        """Retrieve relevant citations from RAG knowledge base."""
        try:
            retriever = self._get_rag_retriever()

            # Build query from category and code patterns
            query = self._build_rag_query(category, code_snippet)

            # Retrieve
            hits = retriever.retrieve(query, top_k=top_k)

            return [
                RAGCitation(
                    chunk_id=h.chunk_id,
                    title=h.title,
                    snippet=h.snippet,
                    score=h.score_rerank,
                    source=h.source_path,
                )
                for h in hits
            ]
        except Exception as e:
            # Return empty if RAG fails
            print(f"RAG retrieval failed: {e}")
            return []

    def _build_rag_query(self, category: str, code_snippet: str) -> str:
        """Build an optimized query for RAG retrieval."""
        # Extract key patterns from code
        patterns = []

        code_lower = code_snippet.lower()

        # Detect common vulnerability patterns
        if "eval(" in code_lower or "exec(" in code_lower:
            patterns.append("code injection eval exec")
        if "pickle" in code_lower:
            patterns.append("pickle deserialization RCE")
        if "shell=true" in code_lower or "subprocess" in code_lower:
            patterns.append("command injection shell subprocess")
        if "sql" in code_lower or "execute" in code_lower:
            patterns.append("SQL injection parameterized query")
        if "innerhtml" in code_lower:
            patterns.append("XSS innerHTML sanitization")
        if "md5" in code_lower or "sha1" in code_lower:
            patterns.append("weak hash MD5 SHA1 SHA256")
        if "password" in code_lower:
            patterns.append("password hash bcrypt argon2")

        # Combine category with detected patterns
        query_parts = [category.replace("_", " ").replace(":", " ")]
        query_parts.extend(patterns[:2])  # Limit to avoid noise
        query_parts.append("fix secure pattern")

        return " ".join(query_parts)

    def _generate_patches(self, finding: IntegratedFinding) -> list[PatchSuggestion]:
        """Generate patch suggestions using deterministic templates and LLM."""
        patches = []

        # Step 1: Try deterministic templates first
        det_patch = self._try_deterministic_patch(finding)
        if det_patch:
            patches.append(det_patch)

        # Step 2: Try LLM generation if enabled and high risk
        if self.llm_provider != "local" and finding.ml_risk_score > 0.5:
            llm_patch = self._try_llm_patch(finding)
            if llm_patch:
                patches.append(llm_patch)
        elif self.llm_provider == "local":
            # Use local deterministic provider
            llm_patch = self._try_local_patch(finding)
            if llm_patch:
                patches.append(llm_patch)

        return patches

    def _try_deterministic_patch(self, finding: IntegratedFinding) -> PatchSuggestion | None:
        """Try to generate patch using deterministic templates."""
        from patcher import generate_patches
        from patcher.types import NormalizedFinding

        try:
            # Convert to NormalizedFinding
            norm = NormalizedFinding(
                finding_id=finding.finding_id,
                filepath=finding.file_path,
                line_start=finding.line_start,
                line_end=finding.line_end,
                rule_id=finding.category,
                category=finding.category,
                severity=finding.severity,
                snippet=finding.code_snippet,
                message="",
            )

            bundle = generate_patches(Path("."), [norm])

            if bundle.combined_diff:
                return PatchSuggestion(
                    diff=bundle.combined_diff,
                    explanation="Deterministic template-based fix",
                    confidence=0.9,
                    citations=finding.citations[:2],
                    source="deterministic",
                )
        except Exception:
            pass

        return None

    def _try_llm_patch(self, finding: IntegratedFinding) -> PatchSuggestion | None:
        """Generate patch using LLM provider."""
        from patcher.llm_client import generate_patch

        try:
            context = {
                "finding": {
                    "id": finding.finding_id,
                    "category": finding.category,
                    "severity": finding.severity,
                    "file": finding.file_path,
                    "line": finding.line_start,
                },
                "snippet": finding.code_snippet,
                "citations": [c.snippet for c in finding.citations[:3]],
            }

            result = generate_patch(context)

            if result.ok and result.diff:
                return PatchSuggestion(
                    diff=result.diff,
                    explanation=f"LLM-generated fix using {result.provider}",
                    confidence=0.7,
                    citations=finding.citations[:3],
                    source=f"llm:{result.provider}",
                )
        except Exception as e:
            print(f"LLM patch generation failed: {e}")

        return None

    def _try_local_patch(self, finding: IntegratedFinding) -> PatchSuggestion | None:
        """Generate patch using local deterministic provider."""
        from llm.providers.local import LocalProvider

        try:
            provider = LocalProvider()
            context = {
                "snippet": finding.code_snippet,
                "finding": {
                    "category": finding.category,
                    "severity": finding.severity,
                },
            }

            diff = provider.generate_patch(context)

            if diff and "--- a/" in diff:
                return PatchSuggestion(
                    diff=diff,
                    explanation="Local deterministic fix pattern",
                    confidence=0.8,
                    citations=finding.citations[:2],
                    source="local",
                )
        except Exception:
            pass

        return None

    def generate_report(
        self,
        findings: list[IntegratedFinding],
        format: str = "json",
    ) -> str:
        """Generate a report from analyzed findings."""
        if format == "json":
            return json.dumps(
                {
                    "summary": {
                        "total_findings": len(findings),
                        "high_risk": sum(1 for f in findings if f.ml_risk_score > 0.7),
                        "medium_risk": sum(1 for f in findings if 0.4 <= f.ml_risk_score <= 0.7),
                        "low_risk": sum(1 for f in findings if f.ml_risk_score < 0.4),
                        "patches_available": sum(1 for f in findings if f.patch_suggestions),
                    },
                    "findings": [f.to_dict() for f in findings],
                },
                indent=2,
            )
        else:
            # Markdown format
            lines = [
                "# Security Analysis Report",
                "",
                "## Summary",
                f"- **Total Findings:** {len(findings)}",
                f"- **High Risk:** {sum(1 for f in findings if f.ml_risk_score > 0.7)}",
                f"- **Medium Risk:** {sum(1 for f in findings if 0.4 <= f.ml_risk_score <= 0.7)}",
                f"- **Low Risk:** {sum(1 for f in findings if f.ml_risk_score < 0.4)}",
                "",
                "## Findings",
                "",
            ]

            for f in sorted(findings, key=lambda x: -x.ml_risk_score):
                lines.append(f"### {f.finding_id}")
                lines.append(f"- **File:** `{f.file_path}:{f.line_start}`")
                lines.append(f"- **Category:** {f.category}")
                lines.append(f"- **Risk Score:** {f.ml_risk_score:.2f} ({f.ml_risk_label})")
                lines.append(f"- **ML Model:** {f.ml_model_source}")

                if f.citations:
                    lines.append("\n**Relevant Documentation:**")
                    for c in f.citations[:2]:
                        lines.append(f"- [{c.title}] {c.snippet[:100]}...")

                if f.patch_suggestions:
                    lines.append("\n**Suggested Fix:**")
                    lines.append("```diff")
                    lines.append(f.patch_suggestions[0].diff[:500])
                    lines.append("```")

                lines.append("")

            return "\n".join(lines)


def run_integrated_analysis(
    targets: list[Path] | None = None,
    output_path: Path | None = None,
    generate_patches: bool = True,
    verbose: bool = True,
) -> dict[str, Any]:
    """
    Run integrated analysis on targets.

    Args:
        targets: Paths to scan (defaults to current directory)
        output_path: Path to save report
        generate_patches: Whether to generate patches
        verbose: Show progress

    Returns:
        Analysis results dictionary
    """
    from guardian.scanners.bandit_scanner import run_bandit
    from guardian.scanners.semgrep_scanner import run_semgrep

    targets = targets or [Path(".")]

    if verbose:
        print("🔍 Running integrated ML + RAG + LLM analysis...")

    # Step 1: Run scanners
    if verbose:
        print("   1️⃣ Running scanners...")

    all_findings = []
    for target in targets:
        if target.exists():
            # Convert to string and check if directory
            target_str = str(target)
            is_dir = target.is_dir()

            # Bandit returns dict with 'results' key
            bandit_output = run_bandit([target_str], recursive=is_dir)
            if isinstance(bandit_output, dict):
                bandit_findings = bandit_output.get("results", [])
            else:
                bandit_findings = bandit_output if isinstance(bandit_output, list) else []

            # Semgrep returns dict with 'results' key
            semgrep_output = run_semgrep([target])
            if isinstance(semgrep_output, dict):
                semgrep_findings = semgrep_output.get("results", [])
            else:
                semgrep_findings = semgrep_output if isinstance(semgrep_output, list) else []

            all_findings.extend(bandit_findings)
            all_findings.extend(semgrep_findings)

    if verbose:
        print(f"      Found {len(all_findings)} findings")

    # Step 2: Analyze with integrated pipeline
    if verbose:
        print("   2️⃣ Analyzing with ML + RAG...")

    pipeline = IntegratedPipeline()
    analyzed = pipeline.analyze_batch(
        all_findings,
        generate_patches=generate_patches,
    )

    if verbose:
        high_risk = sum(1 for f in analyzed if f.ml_risk_score > 0.7)
        patches = sum(1 for f in analyzed if f.patch_suggestions)
        print(f"      High risk: {high_risk}, Patches available: {patches}")

    # Step 3: Generate report
    if verbose:
        print("   3️⃣ Generating report...")

    report = pipeline.generate_report(analyzed, format="json")

    if output_path:
        output_path.write_text(report)
        if verbose:
            print(f"      Report saved to {output_path}")

    return json.loads(report)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Integrated ML + RAG + LLM Analysis")
    parser.add_argument("targets", nargs="*", type=Path, default=[Path(".")])
    parser.add_argument("--output", "-o", type=Path, help="Output file path")
    parser.add_argument("--no-patches", action="store_true", help="Skip patch generation")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")

    args = parser.parse_args()

    result = run_integrated_analysis(
        targets=args.targets,
        output_path=args.output,
        generate_patches=not args.no_patches,
        verbose=not args.quiet,
    )

    print("\n" + "=" * 60)
    print("                    ANALYSIS COMPLETE")
    print("=" * 60)
    print(f"Total findings: {result['summary']['total_findings']}")
    print(f"High risk: {result['summary']['high_risk']}")
    print(f"Patches available: {result['summary']['patches_available']}")
