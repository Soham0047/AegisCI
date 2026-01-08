# SecureDev Guardian

An **AI-powered Security Analysis Platform** for Python + JS/TS codebases with ML-based vulnerability classification, automated patch generation, and LLM security gateway.

## Features

| Phase | Component | Status |
|-------|-----------|--------|
| **Baseline** | CLI scanner (Bandit + Semgrep), GitHub Action, FastAPI backend, Next.js dashboard | ✅ |
| **Phase 3** | Transformer-based risk classifier (AUROC 99.87%) | ✅ |
| **Phase 4** | GNN + Ensemble scoring with OOD detection (AUROC 99.94%) | ✅ |
| **Phase 5** | Unified PR report generation with ML enrichment | ✅ |
| **Phase 6** | Deterministic patcher (6 templates) + Docker sandbox validator | ✅ |
| **Phase 7** | LLM Patch Copilot with RAG, provider abstraction, deterministic ranking | ✅ |
| **Phase 8** | Celery workflow orchestration + PR comment updates | ✅ |
| **Phase 9** | LLM Security Gateway with policy enforcement + audit logging | ✅ |

---

## Prerequisites

- Python 3.11+
- Node.js 20+
- Docker (for sandbox validation)
- Redis (for Celery workers)

---

## Quick Start

### 1. Install Dependencies

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .[dev]
pip install bandit semgrep
```

### 2. Run CLI Scanner

```bash
git fetch origin main
guardian scan --base-ref main
cat report.md
```

### 3. Run Backend + Dashboard

```bash
# Terminal 1: Backend
uvicorn backend.main:app --reload --port 8000

# Terminal 2: Dashboard
cd frontend && npm install && npm run dev
```

- API: http://localhost:8000/docs
- Dashboard: http://localhost:3000

### 4. Run with Docker Compose

```bash
docker-compose up -d redis worker api dashboard
```

---

## Architecture

### ML Pipeline (Phases 3-5)

```
Findings → Transformer Encoder → Risk Score (0-1)
                ↓
        GNN (code graph) → Ensemble Score
                ↓
        OOD Detection → Confidence calibration
                ↓
        Unified PR Report (Markdown + JSON)
```

**Trained Models:**
- `artifacts/transformer_final.pt` - RoBERTa-based classifier
- `artifacts/gnn_v1.pt` - GraphSAGE model

### Patch Generation (Phases 6-7)

```
Finding → Deterministic Templates (6 patterns)
              ↓ (if no match)
         LLM Provider (local/OpenAI/Gemini)
              ↓
         RAG Citations (top 5)
              ↓
         Multiple Candidates → Docker Validation
              ↓
         Deterministic Ranking → Best Patch
```

**Supported Fix Patterns:**
| Language | Pattern | Fix |
|----------|---------|-----|
| Python | `subprocess.run(..., shell=True)` | Remove `shell=True` |
| Python | `a == b` (secrets) | `hmac.compare_digest(a, b)` |
| Python | `random.choice(...)` | `secrets.choice(...)` |
| JS/TS | `.innerHTML = ...` | `.textContent = ...` |
| JS/TS | `new RegExp(userInput)` | `escapeRegExp(userInput)` |
| JS/TS | `eval('(' + x + ')')` | `JSON.parse(x)` |

### Workflow Orchestration (Phase 8)

```
Report Upload → Celery Chain:
  ├── ingest_report
  ├── run_model_inference
  ├── generate_patch_candidates
  ├── validate_patches (Docker sandbox)
  └── post_pr_update (GitHub comment)
```

### Security Gateway (Phase 9)

```
Tool Call → Policy Validation (policy.yaml)
              ├── Scope check
              ├── Arg constraints
              ├── Secret redaction
              └── Approval flow
                    ↓
              Audit Event → Backend DB
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PATCH_LLM_PROVIDER` | `local` | LLM provider: `local`, `openai`, `gemini` |
| `OPENAI_API_KEY` | - | OpenAI API key (if using openai provider) |
| `PATCH_CANDIDATES` | `3` | Number of LLM patch candidates |
| `CELERY_BROKER_URL` | `redis://localhost:6379/0` | Celery broker |
| `GITHUB_DRY_RUN` | `0` | Set to `1` to skip real GitHub API calls |
| `RUN_DOCKER_TESTS` | `0` | Set to `1` to run Docker-gated tests |

---

## Testing

```bash
# Run all tests
pytest -q

# Run with Docker tests
RUN_DOCKER_TESTS=1 pytest -q

# Run specific phase tests
pytest -k "gateway"        # Phase 9
pytest -k "orchestrator"   # Phase 7-8
pytest -k "patcher"        # Phase 6
pytest -k "transformer"    # Phase 3
```

**Test Summary:** 79 tests (all passing)

---

## Project Structure

```
├── guardian/           # CLI scanner + report generation
├── backend/            # FastAPI + Celery tasks + job store
│   ├── integrations/   # GitHub + gateway event clients
│   ├── rendering/      # PR comment formatting
│   └── tasks.py        # Celery task chain
├── frontend/           # Next.js dashboard
├── gateway/            # LLM Security Gateway (TypeScript)
│   ├── src/            # Policy engine, validator, redactor
│   └── policy.yaml     # Tool allowlist + constraints
├── patcher/            # Patch generation + orchestration
│   ├── templates/      # Deterministic fix patterns
│   └── orchestrator.py # LLM + validation pipeline
├── validator/          # Docker sandbox runner
├── rag/                # RAG knowledge base + retriever
├── llm/                # LLM provider abstraction
├── ml/                 # Transformer + GNN models
├── artifacts/          # Trained models + job logs
└── tests/              # Comprehensive test suite
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/v1/reports` | Create/upsert scan report |
| GET | `/api/v1/reports` | List reports |
| GET | `/api/v1/reports/{id}` | Get report details |
| POST | `/api/v1/gateway/events` | Store gateway audit event |

---

## License

MIT
