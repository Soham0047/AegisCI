"""SecureDev Guardian API - Production-ready FastAPI application."""

import hashlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from backend.config import settings
from backend.dashboard import DashboardService, default_since
from backend.db import Base, ConfigStore, GatewayEventStore, PatchOutcomeStore, SessionLocal, engine
from backend.exceptions import register_exception_handlers
from backend.logging_config import get_logger
from backend.middleware import register_middleware
from backend.models import Report
from backend.schemas import (
    FindingsCount,
    GatewayEventIn,
    GatewayEventOut,
    OrgConfigIn,
    OrgConfigOut,
    PatchOutcomeIn,
    PatchOutcomeOut,
    RepoConfigIn,
    RepoConfigOut,
    ReportIn,
    ReportListItem,
    ReportOut,
)
from backend.services import get_report_counts_by_id, upsert_report_and_findings

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan handler for startup/shutdown."""
    # Startup
    logger.info(
        "Starting SecureDev Guardian API",
        environment=settings.app_env,
        debug=settings.debug,
    )
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized")
    yield
    # Shutdown
    logger.info("Shutting down SecureDev Guardian API")


# Initialize stores
gateway_store = GatewayEventStore()
outcome_store = PatchOutcomeStore()
dashboard_service = DashboardService()
config_store = ConfigStore()

# Create FastAPI app with production settings
app = FastAPI(
    title="SecureDev Guardian API",
    description=(
        "AI-powered Security Analysis Platform with ML vulnerability classification, "
        "automated patching, and LLM security gateway"
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    openapi_url="/openapi.json" if settings.debug else None,
)

# Register exception handlers
register_exception_handlers(app)

# Register middleware
register_middleware(app)

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    """Database session dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# =============================================================================
# Health & Status Endpoints
# =============================================================================


@app.get("/health", tags=["Health"])
def health():
    """Health check endpoint for load balancers and monitoring."""
    return {"ok": True, "version": "1.0.0", "environment": settings.app_env}


@app.get("/ready", tags=["Health"])
def readiness(db: Session = Depends(get_db)):
    """Readiness check - verifies database connectivity."""
    from sqlalchemy import text

    try:
        db.execute(text("SELECT 1"))
        return {"ready": True, "database": "ok"}
    except Exception as e:
        logger.error("Readiness check failed", error=str(e))
        return Response(
            content='{"ready": false, "database": "error"}',
            status_code=503,
            media_type="application/json",
        )


# =============================================================================
# Reports Endpoints
# =============================================================================


@app.post(
    "/api/v1/reports",
    response_model=ReportOut,
    status_code=status.HTTP_201_CREATED,
    tags=["Reports"],
)
def create_report(payload: ReportIn, response: Response, db: Session = Depends(get_db)):
    report, created, counts = upsert_report_and_findings(db, payload)
    if not created:
        response.status_code = status.HTTP_200_OK
    return ReportOut(report_id=report.id, created=created, findings=FindingsCount(**counts))


@app.get("/api/v1/reports", response_model=list[ReportListItem])
def list_reports(repo: str | None = None, limit: int = 20, db: Session = Depends(get_db)):
    q = db.query(Report).order_by(Report.created_at.desc())
    if repo:
        q = q.filter(Report.repo == repo)
    reports = q.limit(min(limit, 100)).all()
    counts_by_id = get_report_counts_by_id(db, [r.id for r in reports])
    return [
        ReportListItem(
            id=r.id,
            repo=r.repo,
            pr_number=r.pr_number,
            commit_sha=r.commit_sha,
            created_at=r.created_at,
            findings=FindingsCount(
                **counts_by_id.get(r.id, {"bandit": 0, "semgrep": 0, "total": 0})
            ),
        )
        for r in reports
    ]


@app.get("/api/v1/reports/{report_id}", response_model=ReportListItem)
def get_report(report_id: int, db: Session = Depends(get_db)):
    r = db.query(Report).filter(Report.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    counts = get_report_counts_by_id(db, [r.id]).get(r.id, {"bandit": 0, "semgrep": 0, "total": 0})
    return ReportListItem(
        id=r.id,
        repo=r.repo,
        pr_number=r.pr_number,
        commit_sha=r.commit_sha,
        created_at=r.created_at,
        findings=FindingsCount(**counts),
    )


@app.post("/api/v1/gateway/events", response_model=GatewayEventOut)
def create_gateway_event(payload: GatewayEventIn):
    event_id = gateway_store.create_event(payload.model_dump())
    stored = gateway_store.get_event(event_id)
    return GatewayEventOut(**stored)


@app.post("/api/v1/outcomes", response_model=PatchOutcomeOut)
def create_patch_outcome(payload: PatchOutcomeIn):
    job = dashboard_service.job_store.get_job(payload.job_id)
    repo = job.get("metadata", {}).get("repo") if job else None
    diff_path = dashboard_service.artifacts_root / payload.job_id / "final.diff"
    diff_text = diff_path.read_text(encoding="utf-8") if diff_path.exists() else ""
    diff_hash = hashlib.sha256(diff_text.encode("utf-8")).hexdigest()
    record = outcome_store.create_outcome(
        {
            **payload.model_dump(),
            "repo": repo,
            "diff_hash": diff_hash,
        }
    )
    stored = outcome_store.list_outcomes(job_id=payload.job_id, limit=1)
    if stored:
        return PatchOutcomeOut(**stored[0])
    return PatchOutcomeOut(**record)


@app.get("/api/v1/outcomes", response_model=list[PatchOutcomeOut])
def list_patch_outcomes(
    repo: str | None = None,
    from_ts: str | None = Query(None, alias="from"),
    to_ts: str | None = Query(None, alias="to"),
    limit: int = 200,
):
    return [
        PatchOutcomeOut(**item)
        for item in outcome_store.list_outcomes(
            repo=repo,
            since=from_ts,
            until=to_ts,
            limit=min(limit, 500),
        )
    ]


@app.get("/api/v1/dashboard/reports")
def dashboard_reports(
    repo: str | None = None,
    commit: str | None = None,
    severity: str | None = None,
    from_ts: str | None = Query(None, alias="from"),
    to_ts: str | None = Query(None, alias="to"),
    limit: int = 50,
):
    since = from_ts or default_since()
    return dashboard_service.list_reports(repo, commit, severity, since, to_ts, min(limit, 200))


@app.get("/api/v1/dashboard/reports/{report_id}")
def dashboard_report_detail(
    report_id: str,
    severity: str | None = None,
):
    detail = dashboard_service.get_report_detail(report_id, severity)
    if not detail:
        raise HTTPException(status_code=404, detail="Report not found")
    return detail


@app.get("/api/v1/dashboard/patches")
def dashboard_patches(
    repo: str | None = None,
    commit: str | None = None,
    status: str | None = None,
    from_ts: str | None = Query(None, alias="from"),
    to_ts: str | None = Query(None, alias="to"),
    limit: int = 50,
):
    since = from_ts or default_since()
    return dashboard_service.list_patches(repo, commit, status, since, to_ts, min(limit, 200))


@app.get("/api/v1/dashboard/patches/{job_id}")
def dashboard_patch_detail(job_id: str):
    detail = dashboard_service.get_patch_detail(job_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Patch job not found")
    return detail


@app.get("/api/v1/dashboard/gateway/events")
def dashboard_gateway_events(
    decision: str | None = None,
    repo: str | None = None,
    from_ts: str | None = Query(None, alias="from"),
    to_ts: str | None = Query(None, alias="to"),
    limit: int = 200,
):
    since = from_ts or default_since()
    return dashboard_service.list_gateway_events(decision, repo, since, to_ts, min(limit, 500))


@app.get("/api/v1/dashboard/gateway/summary")
def dashboard_gateway_summary(
    repo: str | None = None,
    from_ts: str | None = Query(None, alias="from"),
    to_ts: str | None = Query(None, alias="to"),
):
    since = from_ts or default_since()
    return dashboard_service.gateway_summary(repo, since, to_ts)


@app.get("/api/v1/config/orgs/{org}", response_model=OrgConfigOut)
def get_org_config(org: str):
    stored = config_store.get_org(org)
    if not stored:
        return OrgConfigOut(org=org, defaults={}, created_at=None, updated_at=None)
    return OrgConfigOut(
        org=stored["org"],
        defaults=stored.get("defaults", {}),
        created_at=stored.get("created_at"),
        updated_at=stored.get("updated_at"),
    )


@app.put("/api/v1/config/orgs/{org}", response_model=OrgConfigOut)
def put_org_config(org: str, payload: OrgConfigIn):
    try:
        stored = config_store.upsert_org(org, payload.model_dump(exclude_unset=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return OrgConfigOut(
        org=stored["org"],
        defaults=stored.get("defaults", {}),
        created_at=stored.get("created_at"),
        updated_at=stored.get("updated_at"),
    )


@app.get("/api/v1/config/repos/{org}/{repo}", response_model=RepoConfigOut)
def get_repo_config(org: str, repo: str):
    stored = config_store.get_repo(org, repo)
    if not stored:
        return RepoConfigOut(org=org, repo=repo, settings={}, created_at=None, updated_at=None)
    return RepoConfigOut(
        org=stored["org"],
        repo=stored["repo"],
        settings=stored.get("settings", {}),
        created_at=stored.get("created_at"),
        updated_at=stored.get("updated_at"),
    )


@app.put("/api/v1/config/repos/{org}/{repo}", response_model=RepoConfigOut)
def put_repo_config(org: str, repo: str, payload: RepoConfigIn):
    try:
        stored = config_store.upsert_repo(org, repo, payload.model_dump(exclude_unset=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RepoConfigOut(
        org=stored["org"],
        repo=stored["repo"],
        settings=stored.get("settings", {}),
        created_at=stored.get("created_at"),
        updated_at=stored.get("updated_at"),
    )


@app.get("/api/v1/config/repos/{org}/{repo}/effective")
def get_effective_repo_config(org: str, repo: str):
    return config_store.get_effective_repo_config(org, repo)
