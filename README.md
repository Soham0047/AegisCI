# SecureDev Guardian

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An **AI-powered Security Scanner CLI** for Python + JS/TS codebases with automated vulnerability detection and patching recommendations.

## 🚀 Quick Install

```bash
# Install from source
pip install -e .

# Or install with pipx (recommended for CLI tools)
pipx install .

# Verify installation
guardian --help
```

## 📖 CLI Usage

### Basic Scan

```bash
# Scan changes compared to main branch
guardian scan --base-ref main

# Scan with a different base branch
guardian scan --base-ref develop
```

### Output Formats

```bash
# Output as JSON (for CI/CD pipelines)
guardian scan --base-ref main --json

# Generate both markdown and JSON reports
guardian scan --base-ref main --format both

# Only markdown report
guardian scan --base-ref main --format md
```

### CI/CD Integration

```bash
# Fail if high or critical severity findings exist
guardian scan --base-ref main --fail-on high

# Fail only on critical findings
guardian scan --base-ref main --fail-on critical

# Silent mode for scripts
guardian scan --base-ref main --quiet --fail-on high
```

### Comprehensive Scanning

```bash
# Run ALL scanners for maximum coverage
guardian scan --comprehensive

# Enable specific additional scanners
guardian scan --secrets              # Detect hardcoded secrets
guardian scan --patterns             # Dangerous code patterns
guardian scan --deps                 # Vulnerable dependencies
guardian scan --secrets --deps       # Combine multiple scanners
```

### Configuration

```bash
# Initialize configuration file
guardian init

# View current configuration
guardian config --show

# Check that all tools are installed
guardian check
```

### All Commands

| Command | Description |
|---------|-------------|
| `guardian scan` | Scan codebase for vulnerabilities |
| `guardian init` | Create `.guardian.yaml` config file |
| `guardian config` | Show current configuration |
| `guardian check` | Verify scanner tools are installed |
| `guardian version` | Show version information |

### Scan Options

| Option | Short | Description |
|--------|-------|-------------|
| `--base-ref` | `-b` | Base branch to compare against (default: `main`) |
| `--semgrep-config` | `-s` | Semgrep ruleset (default: `p/ci`) |
| `--comprehensive` | `-c` | Run ALL scanners for maximum coverage |
| `--secrets` | | Enable secrets scanning (API keys, tokens) |
| `--patterns` | | Enable dangerous code pattern detection |
| `--deps` | | Enable dependency vulnerability scanning |
| `--output-dir` | `-o` | Output directory for reports (default: `.`) |
| `--format` | `-f` | Output format: `md`, `json`, or `both` |
| `--fail-on` | | Fail with exit code 1 on findings at this severity |
| `--json` | | Output JSON to stdout |
| `--verbose` | `-v` | Show detailed output |
| `--quiet` | `-q` | Suppress output except errors |

## 🛡️ Security Scanners

### Bandit (Python)
Detects 60+ security issues including:
- Injection vulnerabilities (SQL, command, code)
- Hardcoded passwords and secrets
- Insecure cryptographic functions
- Dangerous deserialization
- SSL/TLS misconfigurations

### Semgrep (Multi-language)
Runs multiple security rulesets:
- `p/security-audit` - Comprehensive security audit
- `p/owasp-top-ten` - OWASP Top 10 vulnerabilities
- `p/secrets` - Hardcoded secrets detection
- `p/python`, `p/javascript`, `p/typescript` - Language-specific rules

### Secrets Scanner
Detects 50+ secret patterns:
- AWS, GCP, Azure credentials
- GitHub, GitLab, Slack tokens
- OpenAI, Anthropic API keys
- Database connection strings
- Private keys (RSA, DSA, EC)
- JWTs and Bearer tokens

### Pattern Scanner
Detects dangerous code patterns:
- `eval()`, `exec()`, `pickle.load()`
- `shell=True` in subprocess
- `innerHTML`, `document.write()`
- Insecure hash functions (MD5, SHA1)
- SQL string formatting

### Dependency Scanner
Checks for vulnerable packages:
- Python: requirements.txt, pyproject.toml
- JavaScript: package.json
- Known CVEs from vulnerability databases

## ⚙️ Configuration File

Create a `.guardian.yaml` file in your project root:

```yaml
# SecureDev Guardian Configuration
base_ref: main
semgrep_config: p/ci
output_dir: "."
report_format: both
fail_on_severity: high  # critical, high, medium, low, or null
verbose: false
quiet: false
```

## 🔧 GitHub Actions

```yaml
name: Security Scan

on:
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Guardian
        run: pip install securedev-guardian bandit semgrep

      - name: Run Security Scan
        run: guardian scan --base-ref origin/main --fail-on high --json > report.json

      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: report.json
```

## 📊 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (no findings or below threshold) |
| 1 | Findings at or above `--fail-on` severity |
| 2 | Error during scan |
| 3 | Configuration error |

---

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
