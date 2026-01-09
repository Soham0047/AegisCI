from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ReportIn(BaseModel):
    model_config = ConfigDict(extra="allow")

    repo: str = Field(..., examples=["org/repo"])
    pr_number: int = Field(..., examples=[12])
    commit_sha: str = Field(..., examples=["abc123"])
    base_ref: str = Field("main", examples=["main"])
    report: dict[str, Any] = Field(..., description="Raw report JSON (bandit + semgrep)")
    tool_versions: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _coerce_legacy_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        if "commit_sha" not in data and "sha" in data:
            data["commit_sha"] = data["sha"]
        if "report" not in data and "raw" in data:
            data["report"] = data["raw"]
        return data


class FindingsCount(BaseModel):
    bandit: int = 0
    semgrep: int = 0
    total: int = 0


class ReportOut(BaseModel):
    report_id: int
    created: bool
    findings: FindingsCount


class ReportListItem(BaseModel):
    id: int
    repo: str
    pr_number: int
    commit_sha: str
    created_at: datetime
    findings: FindingsCount


class MLCategoryPrediction(BaseModel):
    category: str
    confidence: float

    @field_validator("confidence")
    @classmethod
    def _confidence_in_range(cls, value: float) -> float:
        if not 0.0 <= value <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        return value


class MLLineAttribution(BaseModel):
    line: int
    score: float

    @field_validator("score")
    @classmethod
    def _score_in_range(cls, value: float) -> float:
        if not 0.0 <= value <= 1.0:
            raise ValueError("score must be between 0 and 1")
        return value


class MLModelOutput(BaseModel):
    risk_score: float | None = None
    top_categories: list[MLCategoryPrediction] = Field(default_factory=list)
    confidence: float | None = None
    line_attributions: list[MLLineAttribution] | None = None
    model_version: str | None = None

    @field_validator("risk_score", "confidence")
    @classmethod
    def _probability_in_range(cls, value: float | None) -> float | None:
        if value is None:
            return value
        if not 0.0 <= value <= 1.0:
            raise ValueError("value must be between 0 and 1")
        return value


class GatewayEventIn(BaseModel):
    model_config = ConfigDict(extra="allow")

    correlation_id: str
    tool: str
    args_hash: str
    decision: Literal["allow", "deny", "mask", "require_approval"]
    reason: str
    policy_rule_id: str | None = None
    caller: str | None = None
    timestamp: str | None = None
    sanitized_args: dict[str, Any] | None = None
    output_tags: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None


class GatewayEventOut(GatewayEventIn):
    id: str


class OrgConfigIn(BaseModel):
    severity_threshold: str | None = None
    tools_enabled: list[str] | None = None
    patch_auto_suggest: bool | None = None
    policy_overrides: dict[str, Any] | None = None


class OrgConfigOut(BaseModel):
    org: str
    defaults: dict[str, Any]
    created_at: str | None = None
    updated_at: str | None = None


class RepoConfigIn(BaseModel):
    severity_threshold: str | None = None
    tools_enabled: list[str] | None = None
    patch_auto_suggest: bool | None = None
    policy_overrides: dict[str, Any] | None = None


class RepoConfigOut(BaseModel):
    org: str
    repo: str
    settings: dict[str, Any]
    created_at: str | None = None
    updated_at: str | None = None


class PatchOutcomeIn(BaseModel):
    job_id: str
    finding_id: str
    candidate_id: str
    action: Literal["accepted", "rejected", "modified"]
    notes: str | None = None
    user: str | None = None


class PatchOutcomeOut(PatchOutcomeIn):
    id: str
    diff_hash: str
    timestamp: str
    repo: str | None = None
