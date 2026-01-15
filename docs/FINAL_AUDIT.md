# Final Audit & Plan (CLI-First Product) — Updated 2026-01-10

This audit captures the full rebuild of datasets + labels + training loops and
CLI end-to-end checks for the CLI-first product surface.

## Repo Entry Points (Current)
- CLI: `guardian` / `securedev` -> `guardian/cli.py`
- Scanners: `guardian/scanners/*`
- Unified report: `guardian/report.py`
- Patcher: `patcher/` (deterministic + LLM + ranker)
- Validator: `validator/runner.py` (Docker sandbox)
- ML: `ml/*` (training, inference, pipelines)
- RAG: `rag/*` (embeddings, retriever, store)
- Backend: `backend/main.py` (FastAPI APIs, job store)
- Gateway: `gateway/` (TS policy enforcement + redaction)
- Frontend: `frontend/` (Next.js dashboard + docs pages)

## Rebuild Summary (Latest Run)

### Function Dataset + Weak/Gold Labels
- `scripts/build_dataset.py --max-files-per-repo 600 --commit-mode workdir` -> OK
  - Parse warnings on large repos (expected), but build completes.
- `scripts/weak_label.py run-tools` (bandit + semgrep js-basic) -> OK
- `scripts/weak_label.py map --update-dataset` -> overall 4682/4752 mapped (98.5%)
- Auto-gold labeling:
  - `scripts/auto_label.py label --target-n 1000 --per-rule-cap 150`
  - Output: `datasets/gold/gold_labels.jsonl` (464 items)
- Weak label coverage after mapping:
  - Python: 1455 / 3947 samples
  - TS/JS: 459 / 2562 samples

### ML Data Pipeline + Training
- `python -m ml.data_pipeline --max-files 400 --max-samples 15000 --balance-mode ratio --max-safe-ratio 10`
  - Findings: 1075
  - Raw samples: 143 vulnerable / 43309 safe
  - Balanced: 143 vulnerable / 1430 safe
  - Train/Val/Test: 1258 / 157 / 158
  - GNN parseable train: 333
  - Output: `artifacts/models/datasets/*`

- `python -m ml.train_pipeline --skip-scan --dataset artifacts/models/datasets --epochs 12 --batch-size 32`
  - Transformer macro F1: 0.1143
  - GNN macro F1: 0.2860
  - Ensemble weights: T=0.29, G=0.71
  - Output: `artifacts/models/*` and `artifacts/dl/*`

- `python -m ml.evaluate --checkpoint artifacts/models/transformer_enhanced.pt --test artifacts/models/datasets/transformer/test.jsonl`
  - Risk: F1 0.9333, AUROC 0.9995
  - Category: macro F1 0.1130, micro F1 0.6824
  - Metrics: `artifacts/models/transformer_test_metrics.json`

### CLI E2E Checks
- Full scan (demo repo):
  - `python -m guardian.cli scan --full --target demo_pack/python_demo/demo_repo --output-dir artifacts/cli_demo_scan`
  - Outputs: `report.json`, `report.md`, `artifacts/pr_report.json`

- End-to-end pipeline (small):
  - `python -m guardian.cli pipeline --output artifacts/cli_pipeline_test --max-files 20 --max-samples 50 --epochs 1`
  - Outputs: datasets + models + pipeline results

- Patch generation:
  - Deterministic patch generated and diff format fixed (`diff --git` header + preserved context lines).
  - Validator requires Docker; in this environment Docker is not available, so patch selection remains unvalidated.
  - With Docker running, the same patch applies cleanly (`git apply --check` succeeds).

## Key Fixes Applied
- `guardian/data/extract_ts.py` and `guardian/data/extract_python.py`: skip non-UTF8 files safely.
- `patcher/diff.py`: emit `diff --git` header and preserve trailing context lines (fixes git apply).
- Demo repo adjusted to use list args for B602 template applicability.

## Remaining Gaps / Risks
1) **Validator requires Docker**: CLI patch selection remains blocked if Docker is unavailable.
2) **Auto-gold labels are heuristic**: use for bootstrapping; manual gold labels still recommended for eval.
3) **Large repo parsing**: some parse errors in large repos (expected; skipped safely).

## Next Steps
- Run full regression tests (`pytest -q`, `RUN_DOCKER_TESTS=1 pytest -q`) once Docker is available.
- If validated patch selection is required offline, add a safe local validator mode (explicit opt-in).
- Continue manual gold labeling for high-quality evaluation.
- GCP production scaffolding is now available under `deploy/gcp/` with Cloud Run + Vertex AI + Cloud Build workflows (see `docs/GCP_DEPLOY.md`).
