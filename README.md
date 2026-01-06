# SecureDev Guardian (Starter Baseline)

A starter baseline repo for an **AI Security** product focused on **Python + JS/TS**.

What you get in this baseline:
- ✅ `guardian` CLI: scans changed files in a PR (Bandit + Semgrep) and writes `report.md` + `report.json`
- ✅ GitHub Action: runs the CLI on pull requests and posts a PR comment
- ✅ FastAPI backend: stores scan reports + lists findings (SQLite by default)
- ✅ Next.js dashboard: shows stored findings (minimal UI)
- ✅ Optional LLM Security Gateway (Node/TS): stub server + policy loader (we'll harden later)

This is intentionally **baseline** (ship-able skeleton) before we add deep learning, patch generation, ranking, sandbox validation, and the gateway enforcement.

---

## 0) Prereqs (local)
- Git
- Python 3.11+
- Node 20+ (for dashboard + gateway)

---

## 1) Quickstart (CLI locally)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .[dev]
pip install bandit semgrep

# Example: compare your branch to origin/main
git fetch origin main
guardian scan --base-ref main
cat report.md
```

---

## 2) Quickstart (GitHub Action PR comments)
1. Push this repo to GitHub
2. Open a PR that changes a `.py` or `.js/.ts/.tsx` file
3. The workflow will comment a `SecureDev Guardian Report`

---

## 3) Quickstart (Backend + Dashboard)
### Backend
```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .[dev]
uvicorn backend.main:app --reload --port 8000
```

### Dashboard
```bash
cd frontend
npm install
npm run dev
```

Open:
- API: http://localhost:8000/docs
- Dashboard: http://localhost:3000

---

## Repo map
- `guardian/` — CLI + scanners + report formatting
- `backend/` — FastAPI service (stores reports/findings)
- `frontend/` — Next.js minimal dashboard
- `gateway/` — Node/TS stub LLM security gateway
- `.github/workflows/guardian.yml` — PR workflow

---

## Next steps (we'll do together)
1) Add patch suggestion + sandbox validation (pytest/jest/tsc)
2) Add deep learning inference service (vuln classifier + calibration)
3) Add policy enforcement + tool call auditing in gateway
4) Add org-wide dashboard metrics and alerting
