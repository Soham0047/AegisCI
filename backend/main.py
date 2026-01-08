from fastapi import Depends, FastAPI, HTTPException, Response, status
from sqlalchemy.orm import Session

from backend.db import Base, GatewayEventStore, SessionLocal, engine
from backend.models import Report
from backend.schemas import (
    FindingsCount,
    GatewayEventIn,
    GatewayEventOut,
    ReportIn,
    ReportListItem,
    ReportOut,
)
from backend.services import get_report_counts_by_id, upsert_report_and_findings

Base.metadata.create_all(bind=engine)
gateway_store = GatewayEventStore()

app = FastAPI(title="SecureDev Guardian API (baseline)", version="0.1.0")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/api/v1/reports", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
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
