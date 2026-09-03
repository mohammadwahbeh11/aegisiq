"""
app/storage/base.py -- the LogStore abstraction (AegisIQ v2.4).

WHY THIS EXISTS
---------------
A SIEM has two very different data-shapes:

  * LOW-VOLUME, RELATIONAL, TRANSACTIONAL: users, detection rules,
    alerts, SOAR actions, the audit trail. These need joins, foreign
    keys and ACID updates — a relational DB (SQLite/PostgreSQL) is
    exactly right, and they stay there.

  * HIGH-VOLUME, APPEND-MOSTLY, SEARCH-HEAVY: the raw log/event stream.
    This is what grows to millions of rows and needs a columnar or
    search engine at scale. Production SIEMs (Splunk, Elastic, Chronicle)
    keep THIS in a purpose-built store, not a row store.

`LogStore` is the seam between the application and where the EVENT stream
lives. Everything the app does with log events — write one, count them
in a time window for a detection rule, search them for the console —
goes through this interface. Swapping SQLite → OpenSearch → ClickHouse
is then a config change (`LOG_STORE=...`), not a code change: exactly
what the SOC-readiness review asked for.

The relational tables are untouched by this abstraction; only the event
stream is pluggable.

WHAT IMPLEMENTATIONS MUST PROVIDE
---------------------------------
The six detection primitives are the queries the 8 rules actually run,
plus the write and the console read/search/delete operations. Timestamps
are timezone-aware UTC datetimes; windows are inclusive at both ends, to
match the detection engine's rolling-window convention.
"""
from __future__ import annotations

import abc
from datetime import datetime
from typing import Any


class StoredEvent:
    """A backend-neutral view of one stored log event. The SQLAlchemy
    adapter wraps a Log ORM row; the OpenSearch/ClickHouse adapters build
    this from a document/row. Only the fields the app reads are exposed,
    so a route never depends on which backend produced it."""

    __slots__ = (
        "id", "timestamp", "event_type", "severity", "source_ip",
        "destination_ip", "source_port", "destination_port", "username",
        "hostname", "operating_system", "event_id", "raw_log",
        "normalized_data",
    )

    def __init__(self, **kw: Any) -> None:
        for f in self.__slots__:
            setattr(self, f, kw.get(f))

    def as_dict(self) -> dict[str, Any]:
        return {f: getattr(self, f) for f in self.__slots__}


class LogStore(abc.ABC):
    """Pluggable event store. `is_relational` is True only for the
    SQLAlchemy backend, where the events live in the same DB as the
    alerts and an Alert.log_id foreign key is meaningful. External
    backends set it False, and the alert layer then keeps the event
    reference by id/source rather than a DB foreign key."""

    is_relational: bool = False
    name: str = "abstract"

    # ── write ────────────────────────────────────────────────────────
    @abc.abstractmethod
    def index(self, event: dict[str, Any]) -> int | str:
        """Persist one normalized event. Returns its id (int for
        relational, string/int for external). `event` carries the same
        keys as StoredEvent plus optional agent_id."""

    # ── detection query primitives (the 6 the rules use) ──────────────
    @abc.abstractmethod
    def count_events(self, event_type: str, source_ip: str,
                     window_start: datetime, window_end: datetime) -> int:
        """COUNT of events of a type from a source IP within the window.
        Used by brute_force and login_after_failure."""

    @abc.abstractmethod
    def count_distinct_ports(self, source_ip: str,
                             window_start: datetime, window_end: datetime) -> int:
        """COUNT DISTINCT destination_port for port_access events from a
        source IP within the window. Used by port_scan."""

    @abc.abstractmethod
    def count_distinct_usernames(self, event_type: str, source_ip: str,
                                 window_start: datetime, window_end: datetime) -> int:
        """COUNT DISTINCT username for events of a type from a source IP
        within the window. Used by credential_stuffing."""

    @abc.abstractmethod
    def count_events_by_actor(self, event_type: str, username: str | None,
                              source_ip: str | None,
                              window_start: datetime, window_end: datetime) -> int:
        """COUNT of events of a type by an actor (username if given, else
        source IP) within the window. Used by privilege_escalation."""

    @abc.abstractmethod
    def count_by_normalized_path(self, event_type: str, path: str,
                                 window_start: datetime, window_end: datetime) -> int:
        """COUNT of events of a type whose normalized_data.path equals
        `path` within the window. Used by file_integrity."""

    # ── console read / search ─────────────────────────────────────────
    @abc.abstractmethod
    def get(self, log_id: int | str) -> StoredEvent | None: ...

    @abc.abstractmethod
    def search(self, *, severity: str | None = None, event_type: str | None = None,
               source_ip: str | None = None, hostname: str | None = None,
               username: str | None = None, search: str | None = None,
               since: datetime | None = None,
               limit: int = 100, offset: int = 0) -> tuple[int, list[StoredEvent]]:
        """Returns (total_matching_before_paging, page_of_events),
        newest first."""

    @abc.abstractmethod
    def distinct_event_types(self) -> list[str]: ...

    @abc.abstractmethod
    def related_logs(self, source_ip: str, event_type: str,
                     window_start: datetime, window_end: datetime,
                     limit: int) -> list[StoredEvent]:
        """The other events from the same source + type in a window — the
        evidence the alert-detail view shows."""

    # ── deletion (retention / manual) ─────────────────────────────────
    @abc.abstractmethod
    def delete(self, log_id: int | str) -> bool: ...

    @abc.abstractmethod
    def bulk_delete(self, ids: list[int | str]) -> int: ...
