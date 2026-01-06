from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.db import Base


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    repo: Mapped[str] = mapped_column(String(256), index=True)
    pr_number: Mapped[int] = mapped_column(Integer, index=True)
    sha: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Store full raw report JSON (bandit + semgrep) for baseline
    raw: Mapped[str] = mapped_column(Text)

    # Convenience: flattened findings (JSON array) for dashboard queries
    findings: Mapped[dict] = mapped_column(JSON)
