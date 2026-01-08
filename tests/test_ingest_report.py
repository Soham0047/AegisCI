from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.db import Base
from backend.main import app, get_db
from backend.models import Finding, Report


def test_ingest_report_idempotent(tmp_path) -> None:
    db_path = tmp_path / "test.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    payload = {
        "repo": "org/repo",
        "pr_number": 12,
        "commit_sha": "abc123",
        "base_ref": "main",
        "report": {
            "bandit": {
                "results": [
                    {
                        "test_id": "B101",
                        "issue_severity": "HIGH",
                        "issue_confidence": "MEDIUM",
                        "filename": "app.py",
                        "line_number": 10,
                        "issue_text": "Use of assert detected.",
                    }
                ]
            },
            "semgrep": {
                "results": [
                    {
                        "check_id": "ts.no-eval",
                        "path": "app.ts",
                        "start": {"line": 5},
                        "extra": {"message": "Avoid eval", "severity": "WARNING"},
                    }
                ]
            },
        },
        "tool_versions": {"bandit": "1.7.5", "semgrep": "1.0.0"},
    }

    try:
        with TestClient(app) as client:
            response = client.post("/api/v1/reports", json=payload)
            assert response.status_code == 201
            body = response.json()
            assert body["created"] is True
            assert body["findings"]["bandit"] == 1
            assert body["findings"]["semgrep"] == 1
            assert body["findings"]["total"] == 2

            response = client.post("/api/v1/reports", json=payload)
            assert response.status_code == 200
            body = response.json()
            assert body["created"] is False
    finally:
        app.dependency_overrides.clear()

    db = TestingSessionLocal()
    try:
        report_count = db.query(Report).count()
        finding_count = db.query(Finding).count()
    finally:
        db.close()

    assert report_count == 1
    assert finding_count == 2
