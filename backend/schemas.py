from datetime import datetime
from typing import Any, Dict, List

from pydantic import BaseModel, Field


class ReportIn(BaseModel):
    repo: str = Field(..., examples=["org/repo"])
    pr_number: int = Field(..., examples=[12])
    sha: str = Field(..., examples=["abc123"])
    raw: Dict[str, Any] = Field(..., description="Raw report JSON (bandit + semgrep)")


class ReportOut(BaseModel):
    id: int
    repo: str
    pr_number: int
    sha: str
    created_at: datetime
    findings: Dict[str, Any]
