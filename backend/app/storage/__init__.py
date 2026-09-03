"""
app/storage -- pluggable event store (LogStore) selection.

`get_log_store(db)` returns the backend named by `LOG_STORE`:

    sqlalchemy  -> SqlAlchemyLogStore(db)   (default; events in DATABASE_URL)
    opensearch  -> OpenSearchLogStore()     (events in an OpenSearch cluster)
    clickhouse  -> ClickHouseLogStore()     (events in ClickHouse)

The external backends are singletons (one client per process); the
SQLAlchemy backend is per-request because it wraps the request's session.
Everything else in the app talks to the returned object through the
LogStore interface, so the backend is a config choice, not a code change.

See docs/STORAGE.md.
"""
from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy.orm import Session

from app.config import get_settings
from app.storage.base import LogStore, StoredEvent  # noqa: F401 re-export
from app.storage.sqlalchemy_store import SqlAlchemyLogStore

logger = logging.getLogger(__name__)
settings = get_settings()

# Cache the external client-backed stores (they hold a network client).
_external_store: Optional[LogStore] = None


def get_log_store(db: Session | None = None) -> LogStore:
    backend = (settings.LOG_STORE or "sqlalchemy").strip().lower()

    if backend in ("sqlalchemy", "sql", "sqlite", "postgres", "postgresql"):
        if db is None:
            raise RuntimeError("SqlAlchemyLogStore requires a DB session")
        return SqlAlchemyLogStore(db)

    global _external_store
    if _external_store is not None:
        return _external_store

    if backend in ("opensearch", "elasticsearch", "elastic"):
        from app.storage.opensearch_store import OpenSearchLogStore
        _external_store = OpenSearchLogStore()
    elif backend == "clickhouse":
        from app.storage.clickhouse_store import ClickHouseLogStore
        _external_store = ClickHouseLogStore()
    else:
        logger.warning("Unknown LOG_STORE=%r; falling back to sqlalchemy", backend)
        if db is None:
            raise RuntimeError("Fallback SqlAlchemyLogStore requires a DB session")
        return SqlAlchemyLogStore(db)

    logger.info("Event store backend: %s", _external_store.name)
    return _external_store
