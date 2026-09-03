"""
SQLAlchemy setup.

Lightweight version uses SQLite (see .env DATABASE_URL). The engine is
built with a URL string only -- no SQLite-specific code leaks into the
models or routes -- so swapping DATABASE_URL to a PostgreSQL DSN later
(e.g. postgresql+psycopg://...) requires no code changes, only adding
the driver to requirements.txt.
"""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import get_settings

settings = get_settings()

connect_args = {}
_is_sqlite = settings.DATABASE_URL.startswith("sqlite")
if _is_sqlite:
    # Required for SQLite when accessed from multiple threads (FastAPI's
    # default threaded request handling).
    connect_args = {"check_same_thread": False}

# Connection pool sizing.
#
# For SQLite (the demo default) we deliberately DO NOT enlarge the pool:
# SQLite is a single-writer database, and multiple file-handle connections
# with WAL can produce spurious errors under bursty load. The dashboard's
# real fix (frontend-side coalescing + resilient allSettled loading, see
# app/frontend/src/pages/Dashboard.tsx) removes the stampede at the source.
#
# For PostgreSQL / other server databases, enlarge the pool so concurrent
# console reads during heavy ingest do not queue: pool_pre_ping drops any
# stale connection before use, pool_timeout fails fast rather than hanging.
_pool_kwargs = {}
if not _is_sqlite:
    _pool_kwargs = dict(
        pool_size=20,
        max_overflow=40,
        pool_timeout=10,
        pool_pre_ping=True,
    )

engine = create_engine(settings.DATABASE_URL, connect_args=connect_args, **_pool_kwargs)


# v2.3 — SQLite concurrency hardening.
#
# The single biggest weakness of the SQLite dev profile under load is the
# writer lock: the default rollback journal takes an exclusive lock for
# every write, so a burst of concurrent ingests raises
# "database is locked". Two PRAGMAs let the dev DB survive real bursts
# without any application-code change:
#
#   * WAL (write-ahead logging): readers no longer block the writer and
#     vice-versa — concurrent reads proceed while a write is in flight.
#   * busy_timeout: instead of failing instantly on a held lock, a
#     connection waits up to N ms for it to clear, absorbing short bursts.
#
# This is a mitigation, not a substitute for PostgreSQL at real EPS —
# see docs/GAP_ANALYSIS.md. It applies only to SQLite; PostgreSQL manages
# its own concurrency.
if _is_sqlite:
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_connection, _connection_record):  # noqa: ANN001
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")   # wait up to 5 s for a lock
            cursor.execute("PRAGMA synchronous=NORMAL")  # safe under WAL, much faster
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
