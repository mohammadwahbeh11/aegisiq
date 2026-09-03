"""
app/storage/sqlalchemy_store.py -- the default LogStore backend.

Events live in the same relational database as the rest of the app
(DATABASE_URL — SQLite or PostgreSQL). This adapter is the tested,
behavior-preserving default: every query here is the exact query that
used to live inline in the detection rules and the log routes, moved
behind the interface unchanged. Selecting any other backend swaps only
where the EVENTS go; this file documents the canonical semantics the
other backends must reproduce.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.models.log import Log, Severity
from app.storage.base import LogStore, StoredEvent


def _to_event(row: Log) -> StoredEvent:
    return StoredEvent(
        id=row.id,
        timestamp=row.timestamp,
        event_type=row.event_type,
        severity=row.severity.value if hasattr(row.severity, "value") else row.severity,
        source_ip=row.source_ip,
        destination_ip=row.destination_ip,
        source_port=row.source_port,
        destination_port=row.destination_port,
        username=row.username,
        hostname=row.hostname,
        operating_system=row.operating_system,
        event_id=row.event_id,
        raw_log=row.raw_log,
        normalized_data=row.normalized_data,
    )


class SqlAlchemyLogStore(LogStore):
    is_relational = True
    name = "sqlalchemy"

    def __init__(self, db: Session) -> None:
        self.db = db

    # ── write ────────────────────────────────────────────────────────
    def index(self, event: dict[str, Any]) -> int:
        """Insert one event and return its new id. The caller
        (ingestion service) still owns building the Log from the
        normalized event; here we persist and flush to get the id."""
        row = event["_orm"] if "_orm" in event else Log(**{
            k: v for k, v in event.items()
            if k in Log.__table__.columns.keys()
        })
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row.id

    # ── detection primitives (verbatim from the rule modules) ─────────
    def count_events(self, event_type, source_ip, window_start, window_end) -> int:
        return (
            self.db.query(func.count(Log.id))
            .filter(
                Log.event_type == event_type,
                Log.source_ip == source_ip,
                Log.timestamp >= window_start,
                Log.timestamp <= window_end,
            )
            .scalar()
            or 0
        )

    def count_distinct_ports(self, source_ip, window_start, window_end) -> int:
        from app.ingestion.normalizer import PORT_ACCESS
        return (
            self.db.query(func.count(func.distinct(Log.destination_port)))
            .filter(
                Log.event_type == PORT_ACCESS,
                Log.source_ip == source_ip,
                Log.destination_port.isnot(None),
                Log.timestamp >= window_start,
                Log.timestamp <= window_end,
            )
            .scalar()
            or 0
        )

    def count_distinct_usernames(self, event_type, source_ip, window_start, window_end) -> int:
        return (
            self.db.query(func.count(func.distinct(Log.username)))
            .filter(
                Log.event_type == event_type,
                Log.source_ip == source_ip,
                Log.username.isnot(None),
                Log.timestamp >= window_start,
                Log.timestamp <= window_end,
            )
            .scalar()
            or 0
        )

    def count_events_by_actor(self, event_type, username, source_ip,
                              window_start, window_end) -> int:
        actor_filter = (
            Log.username == username if username else Log.source_ip == source_ip
        )
        return (
            self.db.query(func.count(Log.id))
            .filter(
                Log.event_type == event_type,
                actor_filter,
                Log.timestamp >= window_start,
                Log.timestamp <= window_end,
            )
            .scalar()
            or 0
        )

    def count_by_normalized_path(self, event_type, path, window_start, window_end) -> int:
        return (
            self.db.query(func.count(Log.id))
            .filter(
                Log.event_type == event_type,
                Log.normalized_data["path"].as_string() == path,
                Log.timestamp >= window_start,
                Log.timestamp <= window_end,
            )
            .scalar()
            or 0
        )

    # ── console read / search ─────────────────────────────────────────
    def get(self, log_id) -> StoredEvent | None:
        row = self.db.query(Log).filter(Log.id == log_id).first()
        return _to_event(row) if row else None

    def search(self, *, severity=None, event_type=None, source_ip=None,
               hostname=None, username=None, search=None, since=None,
               limit=100, offset=0) -> tuple[int, list[StoredEvent]]:
        query = self.db.query(Log)
        if severity is not None:
            query = query.filter(Log.severity == Severity(severity) if isinstance(severity, str) else Log.severity == severity)
        if event_type:
            query = query.filter(Log.event_type == event_type)
        if source_ip:
            query = query.filter(Log.source_ip == source_ip)
        if hostname:
            query = query.filter(Log.hostname == hostname)
        if username:
            query = query.filter(Log.username == username)
        if since is not None:
            query = query.filter(Log.timestamp >= since)
        if search:
            pattern = f"%{search}%"
            query = query.filter(
                or_(
                    Log.raw_log.ilike(pattern),
                    Log.username.ilike(pattern),
                    Log.hostname.ilike(pattern),
                    Log.event_type.ilike(pattern),
                )
            )
        total = query.count()
        rows = (query.order_by(Log.timestamp.desc(), Log.id.desc())
                .offset(offset).limit(limit).all())
        return total, [_to_event(r) for r in rows]

    def distinct_event_types(self) -> list[str]:
        rows = self.db.query(Log.event_type).distinct().order_by(Log.event_type).all()
        return [r[0] for r in rows]

    def related_logs(self, source_ip, event_type, window_start, window_end, limit) -> list[StoredEvent]:
        rows = (
            self.db.query(Log)
            .filter(
                Log.source_ip == source_ip,
                Log.event_type == event_type,
                Log.timestamp >= window_start,
                Log.timestamp <= window_end,
            )
            .order_by(Log.timestamp.desc())
            .limit(limit)
            .all()
        )
        return [_to_event(r) for r in rows]

    def delete(self, log_id) -> bool:
        row = self.db.query(Log).filter(Log.id == log_id).first()
        if row is None:
            return False
        self.db.delete(row)
        self.db.commit()
        return True

    def bulk_delete(self, ids) -> int:
        n = self.db.query(Log).filter(Log.id.in_(ids)).delete(synchronize_session=False)
        self.db.commit()
        return n
