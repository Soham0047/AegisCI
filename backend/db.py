import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from backend.config import settings
from backend.policy_utils import (
    apply_policy_overrides,
    load_base_policy,
    merge_policy_overrides,
    validate_policy_overrides,
)

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

    def list_jobs(
        self,
        limit: int = 100,
        repo: str | None = None,
        commit: str | None = None,
        status: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, report_id, status, logs, started_at, finished_at, metadata FROM jobs"
            ).fetchall()
        jobs = []
        for row in rows:
            metadata = json.loads(row[6]) if row[6] else {}
            job = {
                "id": row[0],
                "report_id": row[1],
                "status": row[2],
                "logs": json.loads(row[3]) if row[3] else [],
                "started_at": row[4],
                "finished_at": row[5],
                "metadata": metadata,
            }
            if repo and metadata.get("repo") != repo:
                continue
            if commit and metadata.get("commit") != commit:
                continue
            if status and row[2] != status:
                continue
            if not _within_time(job.get("started_at"), since, until):
                continue
            jobs.append(job)
        jobs.sort(key=lambda item: _sort_ts(item.get("started_at")), reverse=True)
        return jobs[:limit]


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

    def list_events(
        self,
        limit: int = 200,
        decision: str | None = None,
        repo: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, correlation_id, tool, args_hash, decision, reason,
                       policy_rule_id, caller, sanitized_args, output_tags, metadata, timestamp
                FROM gateway_events
                """
            ).fetchall()
        events: list[dict] = []
        for row in rows:
            metadata = _load_json(row[10])
            event = {
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
                "metadata": metadata,
                "timestamp": row[11],
            }
            if decision and row[4] != decision:
                continue
            if repo and metadata.get("repo") != repo:
                continue
            if not _within_time(row[11], since, until):
                continue
            events.append(event)
        events.sort(key=lambda item: _sort_ts(item.get("timestamp")), reverse=True)
        return events[:limit]


class ConfigStore:
    def __init__(self, db_path: str | None = None) -> None:
        self.path = Path(db_path or settings.config_db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS org_configs (
                    org TEXT PRIMARY KEY,
                    defaults_json TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS repo_configs (
                    org TEXT,
                    repo TEXT,
                    settings_json TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    PRIMARY KEY (org, repo)
                )
                """
            )

    def upsert_org(self, org: str, defaults: dict) -> dict:
        _validate_policy_overrides(defaults)
        now = _utc_now()
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT created_at FROM org_configs WHERE org = ?", (org,)
            ).fetchone()
            created_at = existing[0] if existing else now
            conn.execute(
                """
                INSERT INTO org_configs (org, defaults_json, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(org) DO UPDATE SET defaults_json = excluded.defaults_json,
                updated_at = excluded.updated_at
                """,
                (org, json.dumps(defaults), created_at, now),
            )
        return {"org": org, "defaults": defaults, "created_at": created_at, "updated_at": now}

    def get_org(self, org: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT org, defaults_json, created_at, updated_at FROM org_configs WHERE org = ?",
                (org,),
            ).fetchone()
        if not row:
            return None
        return {
            "org": row[0],
            "defaults": _load_json(row[1]),
            "created_at": row[2],
            "updated_at": row[3],
        }

    def upsert_repo(self, org: str, repo: str, settings: dict) -> dict:
        _validate_policy_overrides(settings)
        now = _utc_now()
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT created_at FROM repo_configs WHERE org = ? AND repo = ?",
                (org, repo),
            ).fetchone()
            created_at = existing[0] if existing else now
            conn.execute(
                """
                INSERT INTO repo_configs (org, repo, settings_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(org, repo) DO UPDATE SET settings_json = excluded.settings_json,
                updated_at = excluded.updated_at
                """,
                (org, repo, json.dumps(settings), created_at, now),
            )
        return {
            "org": org,
            "repo": repo,
            "settings": settings,
            "created_at": created_at,
            "updated_at": now,
        }

    def get_repo(self, org: str, repo: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT org, repo, settings_json, created_at, updated_at
                FROM repo_configs
                WHERE org = ? AND repo = ?
                """,
                (org, repo),
            ).fetchone()
        if not row:
            return None
        return {
            "org": row[0],
            "repo": row[1],
            "settings": _load_json(row[2]),
            "created_at": row[3],
            "updated_at": row[4],
        }

    def get_effective_repo_config(self, org: str, repo: str) -> dict:
        org_config = self.get_org(org) or {}
        repo_config = self.get_repo(org, repo) or {}
        defaults = org_config.get("defaults", {})
        settings = repo_config.get("settings", {})
        effective = dict(defaults)
        for key, value in settings.items():
            if value is not None:
                effective[key] = value
        policy_overrides = merge_policy_overrides(
            defaults.get("policy_overrides"), settings.get("policy_overrides")
        )
        base_policy = load_base_policy()
        effective_policy = (
            apply_policy_overrides(base_policy, policy_overrides)
            if policy_overrides
            else base_policy
        )
        return {
            "org": org,
            "repo": repo,
            "effective": effective,
            "org_defaults": defaults,
            "repo_overrides": settings,
            "effective_policy": effective_policy,
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sort_ts(value: str | None) -> float:
    if not value:
        return 0.0
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return 0.0


def _within_time(value: str | None, since: str | None, until: str | None) -> bool:
    if not value:
        return True
    try:
        ts = datetime.fromisoformat(value)
    except ValueError:
        return True
    if since:
        try:
            since_ts = datetime.fromisoformat(since)
            if ts < since_ts:
                return False
        except ValueError:
            pass
    if until:
        try:
            until_ts = datetime.fromisoformat(until)
            if ts > until_ts:
                return False
        except ValueError:
            pass
    return True


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


def _validate_policy_overrides(payload: dict) -> None:
    overrides = payload.get("policy_overrides")
    if overrides is None:
        return
    errors = validate_policy_overrides(overrides)
    if errors:
        raise ValueError("; ".join(errors))
