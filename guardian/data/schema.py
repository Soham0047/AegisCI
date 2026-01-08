from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class FunctionSpan(BaseModel):
    start_line: int
    end_line: int
    start_col: int
    end_col: int


class Dependencies(BaseModel):
    python: list[str] = Field(default_factory=list)
    npm: list[str] = Field(default_factory=list)


class Metadata(BaseModel):
    model_config = ConfigDict(extra="allow")

    file_ext: str
    n_lines: int
    cyclomatic_complexity: int | None
    dependencies: Dependencies
    tool_versions: dict[str, Any]


class WeakLabel(BaseModel):
    source: str
    rule_id: str
    severity: str
    confidence: str | None
    message: str
    line: int | None
    extra: dict[str, Any]


class Sample(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sample_id: str
    language: Literal["python", "ts"]
    repo: str
    commit: str
    filepath: str
    code_snippet: str
    function_span: FunctionSpan
    context_before: str
    context_after: str
    weak_labels: list[WeakLabel]
    gold_labels: dict[str, Any] | None
    metadata: Metadata


def make_sample_id(
    language: str,
    repo: str,
    commit: str,
    filepath: str,
    start_line: int,
    end_line: int,
) -> str:
    raw = f"{language}|{repo}|{commit}|{filepath}|{start_line}|{end_line}"
    return sha256(raw.encode("utf-8")).hexdigest()


def export_schema_json(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    schema = Sample.model_json_schema()
    path.write_text(json.dumps(schema, indent=2, sort_keys=True), encoding="utf-8")
