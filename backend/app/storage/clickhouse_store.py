"""
app/storage/clickhouse_store.py -- ClickHouse LogStore.

ClickHouse is a columnar OLAP store: it ingests millions of rows/second
and answers the count/aggregation queries the detection rules run
(COUNT, COUNT DISTINCT over a time range) extremely fast, which is
exactly the SIEM event-store shape. This adapter implements the same
LogStore interface in ClickHouse SQL.

Requires `clickhouse-connect` and a reachable server, both lazy-imported.
The table uses a MergeTree ordered by (event_type, source_ip, timestamp)
so the rule queries hit the primary index. normalized_data is stored as
JSON string and the file-integrity path is matched with JSONExtractString
— correct, and fine at SIEM scale; a materialized column on the path
would make it index-fast if that rule dominates.

Not exercised by the in-repo suite (no live server); written to the
documented ClickHouse contract. Bring one up with
`docker compose --profile clickhouse up`.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from app.config import get_settings
from app.storage.base import LogStore, StoredEvent

logger = logging.getLogger(__name__)
settings = get_settings()

_COLUMNS = [
    "id", "timestamp", "event_type", "severity", "source_ip", "destination_ip",
    "source_port", "destination_port", "username", "hostname",
    "operating_system", "event_id", "raw_log", "normalized_data",
]


class ClickHouseLogStore(LogStore):
    is_relational = False
    name = "clickhouse"

    def __init__(self) -> None:
        try:
            import clickhouse_connect  # lazy import
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                "LOG_STORE=clickhouse requires 'clickhouse-connect': "
                "pip install clickhouse-connect"
            ) from exc
        self._table = settings.CLICKHOUSE_TABLE
        self._db = settings.CLICKHOUSE_DATABASE
        self.client = clickhouse_connect.get_client(
            host=settings.CLICKHOUSE_HOST,
            port=settings.CLICKHOUSE_PORT,
            username=settings.CLICKHOUSE_USERNAME,
            password=settings.CLICKHOUSE_PASSWORD,
        )
        self._ensure_schema()

    @property
    def _fqtn(self) -> str:
        return f"{self._db}.{self._table}"

    def _ensure_schema(self) -> None:
        try:
            self.client.command(f"CREATE DATABASE IF NOT EXISTS {self._db}")
            self.client.command(f"""
                CREATE TABLE IF NOT EXISTS {self._fqtn} (
                    id UUID DEFAULT generateUUIDv4(),
                    timestamp DateTime64(3, 'UTC'),
                    event_type LowCardinality(String),
                    severity LowCardinality(String),
                    source_ip String,
                    destination_ip String,
                    source_port Nullable(Int32),
                    destination_port Nullable(Int32),
                    username String,
                    hostname String,
                    operating_system String,
                    event_id Nullable(Int32),
                    raw_log String,
                    normalized_data String
                ) ENGINE = MergeTree()
                ORDER BY (event_type, source_ip, timestamp)
            """)
        except Exception:  # noqa: BLE001
            logger.exception("ClickHouse: could not ensure schema")

    def _q(self, sql: str, params: dict) -> list:
        return self.client.query(sql, parameters=params).result_rows

    def _scalar(self, sql: str, params: dict) -> int:
        rows = self._q(sql, params)
        return int(rows[0][0]) if rows else 0

    # ── write ─────────────────────────────────────────────────────────
    def index(self, event: dict[str, Any]) -> str:
        import uuid
        rid = str(uuid.uuid4())
        ts = event.get("timestamp") or datetime.now(timezone.utc)
        row = [
            rid, ts,
            event.get("event_type") or "unparsed",
            str(event.get("severity") or "low"),
            event.get("source_ip") or "",
            event.get("destination_ip") or "",
            event.get("source_port"),
            event.get("destination_port"),
            event.get("username") or "",
            event.get("hostname") or "",
            event.get("operating_system") or "",
            event.get("event_id"),
            event.get("raw_log") or "",
            json.dumps(event.get("normalized_data") or {}, default=str),
        ]
        self.client.insert(self._fqtn, [row], column_names=_COLUMNS)
        return rid

    # ── detection primitives ──────────────────────────────────────────
    def count_events(self, event_type, source_ip, window_start, window_end) -> int:
        return self._scalar(
            f"SELECT count() FROM {self._fqtn} WHERE event_type={{et:String}} "
            f"AND source_ip={{ip:String}} AND timestamp>={{ws:DateTime64}} "
            f"AND timestamp<={{we:DateTime64}}",
            {"et": event_type, "ip": source_ip, "ws": window_start, "we": window_end},
        )

    def count_distinct_ports(self, source_ip, window_start, window_end) -> int:
        from app.ingestion.normalizer import PORT_ACCESS
        return self._scalar(
            f"SELECT uniqExact(destination_port) FROM {self._fqtn} "
            f"WHERE event_type={{et:String}} AND source_ip={{ip:String}} "
            f"AND destination_port IS NOT NULL AND timestamp>={{ws:DateTime64}} "
            f"AND timestamp<={{we:DateTime64}}",
            {"et": PORT_ACCESS, "ip": source_ip, "ws": window_start, "we": window_end},
        )

    def count_distinct_usernames(self, event_type, source_ip, window_start, window_end) -> int:
        return self._scalar(
            f"SELECT uniqExact(username) FROM {self._fqtn} WHERE event_type={{et:String}} "
            f"AND source_ip={{ip:String}} AND username != '' "
            f"AND timestamp>={{ws:DateTime64}} AND timestamp<={{we:DateTime64}}",
            {"et": event_type, "ip": source_ip, "ws": window_start, "we": window_end},
        )

    def count_events_by_actor(self, event_type, username, source_ip,
                              window_start, window_end) -> int:
        if username:
            cond, params = "username={actor:String}", {"actor": username}
        else:
            cond, params = "source_ip={actor:String}", {"actor": source_ip or ""}
        params.update({"et": event_type, "ws": window_start, "we": window_end})
        return self._scalar(
            f"SELECT count() FROM {self._fqtn} WHERE event_type={{et:String}} AND {cond} "
            f"AND timestamp>={{ws:DateTime64}} AND timestamp<={{we:DateTime64}}",
            params,
        )

    def count_by_normalized_path(self, event_type, path, window_start, window_end) -> int:
        return self._scalar(
            f"SELECT count() FROM {self._fqtn} WHERE event_type={{et:String}} "
            f"AND JSONExtractString(normalized_data, 'path')={{p:String}} "
            f"AND timestamp>={{ws:DateTime64}} AND timestamp<={{we:DateTime64}}",
            {"et": event_type, "p": path, "ws": window_start, "we": window_end},
        )

    # ── read / search ─────────────────────────────────────────────────
    def _row_to_event(self, row: list) -> StoredEvent:
        d = dict(zip(_COLUMNS, row))
        nd = d.get("normalized_data")
        try:
            nd = json.loads(nd) if isinstance(nd, str) and nd else {}
        except json.JSONDecodeError:
            nd = {}
        return StoredEvent(
            id=str(d["id"]), timestamp=d["timestamp"], event_type=d["event_type"],
            severity=d["severity"], source_ip=d["source_ip"] or None,
            destination_ip=d["destination_ip"] or None, source_port=d["source_port"],
            destination_port=d["destination_port"], username=d["username"] or None,
            hostname=d["hostname"] or None, operating_system=d["operating_system"] or None,
            event_id=d["event_id"], raw_log=d["raw_log"], normalized_data=nd,
        )

    def get(self, log_id) -> StoredEvent | None:
        cols = ", ".join(_COLUMNS)
        rows = self._q(f"SELECT {cols} FROM {self._fqtn} WHERE id={{id:String}}",
                       {"id": str(log_id)})
        return self._row_to_event(rows[0]) if rows else None

    def search(self, *, severity=None, event_type=None, source_ip=None,
               hostname=None, username=None, search=None, since=None,
               limit=100, offset=0) -> tuple[int, list[StoredEvent]]:
        clauses, params = [], {}
        for name, val in (("severity", severity), ("event_type", event_type),
                          ("source_ip", source_ip), ("hostname", hostname),
                          ("username", username)):
            if val:
                clauses.append(f"{name}={{{name}:String}}")
                params[name] = val
        if since is not None:
            clauses.append("timestamp>={since:DateTime64}")
            params["since"] = since
        if search:
            clauses.append("(positionCaseInsensitive(raw_log, {s:String})>0 "
                           "OR positionCaseInsensitive(username, {s:String})>0 "
                           "OR positionCaseInsensitive(hostname, {s:String})>0)")
            params["s"] = search
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        total = self._scalar(f"SELECT count() FROM {self._fqtn}{where}", params)
        cols = ", ".join(_COLUMNS)
        params.update({"lim": limit, "off": offset})
        rows = self._q(
            f"SELECT {cols} FROM {self._fqtn}{where} "
            f"ORDER BY timestamp DESC LIMIT {{lim:UInt32}} OFFSET {{off:UInt32}}",
            params,
        )
        return total, [self._row_to_event(r) for r in rows]

    def distinct_event_types(self) -> list[str]:
        rows = self._q(f"SELECT DISTINCT event_type FROM {self._fqtn} ORDER BY event_type", {})
        return [r[0] for r in rows]

    def related_logs(self, source_ip, event_type, window_start, window_end, limit) -> list[StoredEvent]:
        cols = ", ".join(_COLUMNS)
        rows = self._q(
            f"SELECT {cols} FROM {self._fqtn} WHERE source_ip={{ip:String}} "
            f"AND event_type={{et:String}} AND timestamp>={{ws:DateTime64}} "
            f"AND timestamp<={{we:DateTime64}} ORDER BY timestamp DESC LIMIT {{lim:UInt32}}",
            {"ip": source_ip, "et": event_type, "ws": window_start,
             "we": window_end, "lim": limit},
        )
        return [self._row_to_event(r) for r in rows]

    def delete(self, log_id) -> bool:
        self.client.command(
            f"ALTER TABLE {self._fqtn} DELETE WHERE id={{id:String}}",
            parameters={"id": str(log_id)},
        )
        return True

    def bulk_delete(self, ids) -> int:
        str_ids = [str(i) for i in ids]
        self.client.command(
            f"ALTER TABLE {self._fqtn} DELETE WHERE id IN {{ids:Array(String)}}",
            parameters={"ids": str_ids},
        )
        return len(str_ids)
