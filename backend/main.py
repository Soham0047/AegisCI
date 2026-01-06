from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session
import json

from backend.db import Base, SessionLocal, engine
from backend.models import Report
from backend.schemas import ReportIn, ReportOut
from backend.services import flatten_findings

Base.metadata.create_all(bind=engine)

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


@app.post("/api/v1/reports", response_model=ReportOut)
def create_report(payload: ReportIn, db: Session = Depends(get_db)):
    findings = flatten_findings(payload.raw)
    report = Report(
        repo=payload.repo,
        pr_number=payload.pr_number,
        sha=payload.sha,
        raw=json.dumps(payload.raw),
        findings=findings,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return ReportOut(
        id=report.id,
        repo=report.repo,
        pr_number=report.pr_number,
        sha=report.sha,
        created_at=report.created_at,
        findings=report.findings,
    )


@app.get("/api/v1/reports", response_model=list[ReportOut])
def list_reports(repo: str | None = None, limit: int = 20, db: Session = Depends(get_db)):
    q = db.query(Report).order_by(Report.created_at.desc())
    if repo:
        q = q.filter(Report.repo == repo)
    reports = q.limit(min(limit, 100)).all()
    return [
        ReportOut(
            id=r.id,
            repo=r.repo,
            pr_number=r.pr_number,
            sha=r.sha,
            created_at=r.created_at,
            findings=r.findings,
        )
        for r in reports
    ]


@app.get("/api/v1/reports/{report_id}", response_model=ReportOut)
def get_report(report_id: int, db: Session = Depends(get_db)):
    r = db.query(Report).filter(Report.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    return ReportOut(
        id=r.id,
        repo=r.repo,
        pr_number=r.pr_number,
        sha=r.sha,
        created_at=r.created_at,
        findings=r.findings,
    )
