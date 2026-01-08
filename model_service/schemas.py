from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


class ToolFinding(BaseModel):
    rule_id: str
    message: str
    severity: str
    line: int | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class InferenceRequest(BaseModel):
    language: str
    code: str
    filepath: str | None = None
    context_before: str | None = None
    context_after: str | None = None
    tool_findings: list[ToolFinding] = Field(default_factory=list)


class CategoryPrediction(BaseModel):
    category: str
    confidence: float

    @field_validator("confidence")
    @classmethod
    def _confidence_in_range(cls, value: float) -> float:
        if not 0.0 <= value <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        return value


class LineAttribution(BaseModel):
    line: int
    score: float

    @field_validator("score")
    @classmethod
    def _score_in_range(cls, value: float) -> float:
        if not 0.0 <= value <= 1.0:
            raise ValueError("score must be between 0 and 1")
        return value


class InferenceResponse(BaseModel):
    risk_score: float
    top_categories: list[CategoryPrediction]
    confidence: float
    line_attributions: list[LineAttribution] | None = None

    @field_validator("risk_score", "confidence")
    @classmethod
    def _probability_in_range(cls, value: float) -> float:
        if not 0.0 <= value <= 1.0:
            raise ValueError("value must be between 0 and 1")
        return value
