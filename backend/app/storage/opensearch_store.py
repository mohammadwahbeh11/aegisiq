"""
app/storage/opensearch_store.py -- OpenSearch/Elasticsearch LogStore.

Implements the same LogStore interface against an OpenSearch cluster, so
the event stream can scale to the volume a real SOC produces while the
detection rules and the console keep calling the identical interface.

Requires `opensearch-py` and a reachable cluster; both are lazy-imported
so the rest of the app runs without them when LOG_STORE=sqlalchemy. The
detection primitives map to OpenSearch bool filters and aggregations —
cardinality for the DISTINCT counts, term/range for the rest — which is
what makes these queries fast at scale instead of table-scanning a row
store.

Not exercised by the in-repo test suite (that has no live cluster); it
is written to the documented OpenSearch DSL contract and the shared
LogStore contract test. Bring up a cluster with
`docker compose --profile opensearch up` to run it for real.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from app.config import get_settings
from app.storage.base import LogStore, StoredEvent

logger = logging.getLogger(__name__)
settings = get_settings()

# Fields stored as keyword (exact-match/aggregatable) vs text (analyzed).
_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "timestamp": {"type": "date"},
            "event_type": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "source_ip": {"type": "keyword"},
            "destination_ip": {"type": "keyword"},
            "source_port": {"type": "integer"},
            "destination_port": {"type": "integer"},
            "username": {"type": "keyword"},
            "hostname": {"type": "keyword"},
            "operating_system": {"type": "keyword"},
            "event_id": {"type": "integer"},
            "raw_log": {"type": "text"},
            # normalized_data is a free-form object; index path as keyword
            # so file_integrity's exact-path count works.
            "normalized_data": {"type": "object", "enabled": True},
        }
    }
}


def _iso(dt: datetime) -> str:
    return dt.isoformat()


class OpenSearchLogStore(LogStore):
    is_relational = False
    name = "opensearch"

    def __init__(self) -> None:
        try:
            from opensearchpy import OpenSearch  # lazy import
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                "LOG_STORE=opensearch requires the 'opensearch-py' package: "
                "pip install opensearch-py"
            ) from exc
        self._index = settings.OPENSEARCH_INDEX
        self.client = OpenSearch(
            hosts=[settings.OPENSEARCH_URL],
            http_auth=(settings.OPENSEARCH_USERNAME, settings.OPENSEARCH_PASSWORD),
            verify_certs=settings.OPENSEARCH_VERIFY_SSL,
            ssl_show_warn=False,
        )
        self._ensure_index()

    def _ensure_index(self) -> None:
        try:
            if not self.client.indices.exists(index=self._index):
                self.client.indices.create(index=self._index, body=_INDEX_MAPPING)
        except Exception:  # noqa: BLE001
            logger.exception("OpenSearch: could not ensure index %s", self._index)

    # ── helpers ───────────────────────────────────────────────────────
    def _range(self, window_start: datetime, window_end: datetime) -> dict:
        return {"range": {"timestamp": {"gte": _iso(window_start), "lte": _iso(window_end)}}}

    def _count(self, must: list[dict]) -> int:
        body = {"query": {"bool": {"filter": must}}}
        return int(self.client.count(index=self._index, body=body).get("count", 0))

    def _cardinality(self, field: str, must: list[dict]) -> int:
        body = {
            "size": 0,
            "query": {"bool": {"filter": must}},
            "aggs": {"distinct": {"cardinality": {"field": field}}},
        }
        res = self.client.search(index=self._index, body=body)
        return int(res["aggregations"]["distinct"]["value"])

    def _doc_to_event(self, hit: dict) -> StoredEvent:
        src = hit.get("_source", hit)
        ts = src.get("timestamp")
        return StoredEvent(
            id=hit.get("_id", src.get("id")),
            timestamp=datetime.fromisoformat(ts) if isinstance(ts, str) else ts,
            event_type=src.get("event_type"),
            severity=src.get("severity"),
            source_ip=src.get("source_ip"),
            destination_ip=src.get("destination_ip"),
            source_port=src.get("source_port"),
            destination_port=src.get("destination_port"),
            username=src.get("username"),
            hostname=src.get("hostname"),
            operating_system=src.get("operating_system"),
            event_id=src.get("event_id"),
            raw_log=src.get("raw_log"),
            normalized_data=src.get("normalized_data") or {},
        )

    # ── write ─────────────────────────────────────────────────────────
    def index(self, event: dict[str, Any]) -> str:
        doc = {k: v for k, v in event.items() if k != "_orm"}
        ts = doc.get("timestamp")
        if isinstance(ts, datetime):
            doc["timestamp"] = _iso(ts)
        res = self.client.index(index=self._index, body=doc, refresh=True)
        return res["_id"]

    # ── detection primitives ──────────────────────────────────────────
    def count_events(self, event_type, source_ip, window_start, window_end) -> int:
        return self._count([
            {"term": {"event_type": event_type}},
            {"term": {"source_ip": source_ip}},
            self._range(window_start, window_end),
        ])

    def count_distinct_ports(self, source_ip, window_start, window_end) -> int:
        from app.ingestion.normalizer import PORT_ACCESS
        return self._cardinality("destination_port", [
            {"term": {"event_type": PORT_ACCESS}},
            {"term": {"source_ip": source_ip}},
            {"exists": {"field": "destination_port"}},
            self._range(window_start, window_end),
        ])

    def count_distinct_usernames(self, event_type, source_ip, window_start, window_end) -> int:
        return self._cardinality("username", [
            {"term": {"event_type": event_type}},
            {"term": {"source_ip": source_ip}},
            {"exists": {"field": "username"}},
            self._range(window_start, window_end),
        ])

    def count_events_by_actor(self, event_type, username, source_ip,
                              window_start, window_end) -> int:
        actor = ({"term": {"username": username}} if username
                 else {"term": {"source_ip": source_ip}})
        return self._count([
            {"term": {"event_type": event_type}},
            actor,
            self._range(window_start, window_end),
        ])

    def count_by_normalized_path(self, event_type, path, window_start, window_end) -> int:
        return self._count([
            {"term": {"event_type": event_type}},
            {"term": {"normalized_data.path": path}},
            self._range(window_start, window_end),
        ])

    # ── console read / search ─────────────────────────────────────────
    def get(self, log_id) -> StoredEvent | None:
        try:
            hit = self.client.get(index=self._index, id=log_id)
            return self._doc_to_event(hit)
        except Exception:  # noqa: BLE001 - not found or transport error
            return None

    def search(self, *, severity=None, event_type=None, source_ip=None,
               hostname=None, username=None, search=None, since=None,
               limit=100, offset=0) -> tuple[int, list[StoredEvent]]:
        must: list[dict] = []
        for field, val in (("severity", severity), ("event_type", event_type),
                           ("source_ip", source_ip), ("hostname", hostname),
                           ("username", username)):
            if val:
                must.append({"term": {field: val}})
        if since is not None:
            must.append({"range": {"timestamp": {"gte": _iso(since)}}})
        query: dict = {"bool": {"filter": must}}
        if search:
            query["bool"]["must"] = [{
                "query_string": {"query": f"*{search}*",
                                 "fields": ["raw_log", "username", "hostname", "event_type"]}
            }]
        body = {
            "query": query,
            "sort": [{"timestamp": "desc"}],
            "from": offset, "size": limit,
            "track_total_hits": True,
        }
        res = self.client.search(index=self._index, body=body)
        total = res["hits"]["total"]["value"]
        rows = [self._doc_to_event(h) for h in res["hits"]["hits"]]
        return total, rows

    def distinct_event_types(self) -> list[str]:
        body = {"size": 0, "aggs": {"types": {"terms": {"field": "event_type", "size": 1000}}}}
        res = self.client.search(index=self._index, body=body)
        return sorted(b["key"] for b in res["aggregations"]["types"]["buckets"])

    def related_logs(self, source_ip, event_type, window_start, window_end, limit) -> list[StoredEvent]:
        body = {
            "query": {"bool": {"filter": [
                {"term": {"source_ip": source_ip}},
                {"term": {"event_type": event_type}},
                self._range(window_start, window_end),
            ]}},
            "sort": [{"timestamp": "desc"}],
            "size": limit,
        }
        res = self.client.search(index=self._index, body=body)
        return [self._doc_to_event(h) for h in res["hits"]["hits"]]

    def delete(self, log_id) -> bool:
        try:
            self.client.delete(index=self._index, id=log_id, refresh=True)
            return True
        except Exception:  # noqa: BLE001
            return False

    def bulk_delete(self, ids) -> int:
        body = {"query": {"ids": {"values": [str(i) for i in ids]}}}
        res = self.client.delete_by_query(index=self._index, body=body, refresh=True)
        return int(res.get("deleted", 0))
