import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from backend.config import settings

Path("backend/data").mkdir(parents=True, exist_ok=True)
engine = create_engine(
    f"sqlite:///{settings.sqlite_path}", connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


class JobStore:
    def __init__(self, db_path: str | None = None) -> None:
        self.path = Path(db_path or settings.jobs_db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    report_id TEXT,
                    status TEXT,
                    logs TEXT,
                    started_at TEXT,
                    finished_at TEXT,
                    metadata TEXT
                )
                """
            )

    def create_job(self, report_id: str) -> str:
        job_id = uuid.uuid4().hex
        now = _utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO jobs (id, report_id, status, logs, started_at, finished_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (job_id, report_id, "queued", json.dumps([]), now, None, json.dumps({})),
            )
        return job_id

    def update_status(self, job_id: str, status: str) -> None:
        now = _utc_now()
        fields = {"status": status}
        if status in {"running", "pending_pr"}:
            fields["started_at"] = now
        if status in {"completed", "failed"}:
            fields["finished_at"] = now
        sets = ", ".join(f"{key} = ?" for key in fields)
        values = list(fields.values()) + [job_id]
        with self._connect() as conn:
            conn.execute(f"UPDATE jobs SET {sets} WHERE id = ?", values)

    def append_log(self, job_id: str, line: str) -> None:
        with self._connect() as conn:
            row = conn.execute("SELECT logs FROM jobs WHERE id = ?", (job_id,)).fetchone()
            logs = json.loads(row[0]) if row and row[0] else []
            logs.append({"ts": _utc_now(), "line": line})
            conn.execute(
                "UPDATE jobs SET logs = ? WHERE id = ?",
                (json.dumps(logs), job_id),
            )

    def set_metadata(self, job_id: str, metadata: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE jobs SET metadata = ? WHERE id = ?",
                (json.dumps(metadata), job_id),
            )

    def get_job(self, job_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, report_id, status, logs, started_at, finished_at, metadata "
                "FROM jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
        if not row:
            return None
        logs = json.loads(row[3]) if row[3] else []
        metadata = json.loads(row[6]) if row[6] else {}
        return {
            "id": row[0],
            "report_id": row[1],
            "status": row[2],
            "logs": logs,
            "started_at": row[4],
            "finished_at": row[5],
            "metadata": metadata,
        }


class GatewayEventStore:
    def __init__(self, db_path: str | None = None) -> None:
        self.path = Path(db_path or settings.gateway_events_db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS gateway_events (
                    id TEXT PRIMARY KEY,
                    correlation_id TEXT,
                    tool TEXT,
                    args_hash TEXT,
                    decision TEXT,
                    reason TEXT,
                    policy_rule_id TEXT,
                    caller TEXT,
                    sanitized_args TEXT,
                    output_tags TEXT,
                    metadata TEXT,
                    timestamp TEXT
                )
                """
            )

    def create_event(self, event: dict) -> str:
        event_id = event.get("id") or uuid.uuid4().hex
        timestamp = event.get("timestamp") or _utc_now()
        sanitized_args = _safe_json(_redact_sensitive(event.get("sanitized_args")))
        output_tags = _safe_json(event.get("output_tags"))
        metadata = _safe_json(_redact_sensitive(event.get("metadata")))
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO gateway_events (
                    id,
                    correlation_id,
                    tool,
                    args_hash,
                    decision,
                    reason,
                    policy_rule_id,
                    caller,
                    sanitized_args,
                    output_tags,
                    metadata,
                    timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    event.get("correlation_id"),
                    event.get("tool"),
                    event.get("args_hash"),
                    event.get("decision"),
                    event.get("reason"),
                    event.get("policy_rule_id"),
                    event.get("caller"),
                    sanitized_args,
                    output_tags,
                    metadata,
                    timestamp,
                ),
            )
        return event_id

    def get_event(self, event_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, correlation_id, tool, args_hash, decision, reason,
                       policy_rule_id, caller, sanitized_args, output_tags, metadata, timestamp
                FROM gateway_events
                WHERE id = ?
                """,
                (event_id,),
            ).fetchone()
        if not row:
            return None
        return {
            "id": row[0],
            "correlation_id": row[1],
            "tool": row[2],
            "args_hash": row[3],
            "decision": row[4],
            "reason": row[5],
            "policy_rule_id": row[6],
            "caller": row[7],
            "sanitized_args": _load_json(row[8]),
            "output_tags": _load_json(row[9]),
            "metadata": _load_json(row[10]),
            "timestamp": row[11],
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_json(value: object, max_chars: int = 4000) -> str:
    try:
        text = json.dumps(value or {})
    except TypeError:
        text = json.dumps({"_unserializable": True})
    if len(text) <= max_chars:
        return text
    return json.dumps({"_truncated": True, "preview": text[:max_chars]})


def _load_json(value: str | None) -> object:
    if not value:
        return {}
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return {"_invalid_json": True}


def _redact_sensitive(value: object) -> object:
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        for key, val in value.items():
            if _is_sensitive_key(key) and isinstance(val, str):
                redacted[key] = _mask_value(val)
            else:
                redacted[key] = _redact_sensitive(val)
        return redacted
    if isinstance(value, list):
        return [_redact_sensitive(item) for item in value]
    if isinstance(value, str) and _looks_like_secret(value):
        return _mask_value(value)
    return value


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(token in lowered for token in ("token", "secret", "authorization", "apikey"))


def _looks_like_secret(value: str) -> bool:
    return (
        value.startswith("ghp_")
        or value.startswith("github_pat_")
        or value.startswith("sk-")
        or value.startswith("Bearer ")
    )


def _mask_value(value: str) -> str:
    if len(value) <= 8:
        return "***REDACTED***"
    return f"{value[:4]}***{value[-4:]}"
