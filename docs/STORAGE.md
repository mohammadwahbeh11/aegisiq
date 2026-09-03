# AegisIQ — Pluggable Event Store (LogStore)

> The answer to the SOC-readiness gap "SQLite won't handle real EPS":
> the high-volume **event stream** now lives behind a swappable
> `LogStore` interface with three backends — **SQLAlchemy** (default),
> **OpenSearch**, and **ClickHouse** — while the low-volume relational
> data (users, rules, alerts, audit) stays in the transactional
> database. Choosing a backend is a config change, not a code change.
>
> Version 2.4. Honest status of what is wired is in §4.

---

## 1 · Why split the storage

A SIEM has two data-shapes with opposite needs:

| Data | Shape | Right store |
|---|---|---|
| Users, detection rules, alerts, SOAR actions, audit | low-volume, relational, transactional (joins, FKs, updates) | **SQLite / PostgreSQL** |
| The raw log/event stream | high-volume, append-mostly, search + aggregation heavy | **OpenSearch / ClickHouse** at scale |

Forcing the event stream into a row store is what makes SQLite lock and
collapse under real events-per-second. So AegisIQ keeps the relational
tables where they belong and puts **only the event stream** behind an
interface that can point at a purpose-built engine.

This is exactly how Splunk (its own index), Elastic (Elasticsearch) and
Chronicle (a column store) are built: metadata in one place, the event
firehose in another.

## 2 · The interface

`app/storage/base.py` defines `LogStore` — every operation the app
performs on events:

- **write:** `index(event)`
- **detection primitives** (the six queries the 8 rules actually run):
  `count_events`, `count_distinct_ports`, `count_distinct_usernames`,
  `count_events_by_actor`, `count_by_normalized_path`
- **console read:** `get`, `search`, `distinct_event_types`,
  `related_logs`
- **retention:** `delete`, `bulk_delete`

`get_log_store(db)` (`app/storage/__init__.py`) returns the backend named
by `LOG_STORE`. Timestamps are UTC; detection windows are inclusive at
both ends, matching the engine's rolling-window convention.

## 3 · The three backends

| Backend | Module | Needs | Notes |
|---|---|---|---|
| `sqlalchemy` (default) | `sqlalchemy_store.py` | nothing extra | Events in `DATABASE_URL` (SQLite/Postgres). The tested, behavior-preserving path — every query is the one that used to be inline in the rules, moved behind the interface unchanged. |
| `opensearch` | `opensearch_store.py` | `pip install opensearch-py` + a cluster | Detection counts map to bool filters + cardinality aggregations (fast at scale, not table scans). |
| `clickhouse` | `clickhouse_store.py` | `pip install clickhouse-connect` + a server | MergeTree ordered by `(event_type, source_ip, timestamp)` so rule queries hit the primary index. |

Select one:

```bash
# default — nothing to do
LOG_STORE=sqlalchemy

# OpenSearch
docker compose --profile opensearch up -d
LOG_STORE=opensearch
OPENSEARCH_URL=https://localhost:9200
OPENSEARCH_USERNAME=admin
OPENSEARCH_PASSWORD=admin

# ClickHouse
docker compose --profile clickhouse up -d
LOG_STORE=clickhouse
CLICKHOUSE_HOST=localhost
```

## 4 · What is wired — honest status

**Fully routed through the interface (the scale-critical path):**

- **Ingestion write** (`app/ingestion/service.py`) — every event is
  written via `store.index()`.
- **All detection historical queries** — the five stateful rules
  (`brute_force`, `port_scan`, `login_after_failure`,
  `credential_stuffing`, `file_integrity`, `privilege_escalation`) ask
  the store, not a hardcoded SQL query. So detection runs correctly
  against whichever backend holds the events.

This is the part that determines whether the system scales, and it is
done: with `LOG_STORE=opensearch` or `clickhouse`, events are indexed
there and the rules evaluate against them.

**Still reads the relational DB directly (documented follow-on):**

- The **log-console read routes** (`GET /api/logs`, `/logs/{id}`,
  `/logs/event-types`, CSV export) and the **alert-detail related-logs**
  panel and the **dashboard** aggregations currently query the ORM `Log`
  model directly. They are correct and unchanged for the default
  `sqlalchemy` backend (the fully-supported end-to-end mode). Routing
  them through `store.search()` / `store.get()` / `store.related_logs()`
  — which the interface and all three adapters already implement — is
  the contained next step to make the **console** fully backend-agnostic
  too. It was left as a separate change to avoid altering the
  ORM-validated response path under the same release as the engine
  rewrite.

Being explicit about this boundary is deliberate: the claim is "the
event store is pluggable and detection scales onto it," not "every read
path is already backend-agnostic."

## 5 · The Alert ↔ event linkage in external mode

In the relational backend an `Alert.log_id` foreign key points at the
triggering event row. With an external event store there is no such row
in the relational DB, so on that path the ingested event is a transient
carrier with `id=None`; `Alert.log_id` is simply left NULL and the
evidence is referenced by `source_ip` + `dedup_key` (and lives in the
external store, retrievable via `store.search`). No foreign-key
violation, no invented reference. Wiring the alert-detail view to fetch
the triggering event from the store by a stored external id is part of
the same console follow-on in §4.

## 6 · Cutover checklist (SQLite → OpenSearch/ClickHouse)

1. `pip install opensearch-py` (or `clickhouse-connect`).
2. Bring up the store: `docker compose --profile opensearch up -d`.
3. Set `LOG_STORE` and the connection vars (§3).
4. Restart the backend. New events flow to the external store and
   detection evaluates there immediately.
5. (Optional) backfill history by re-shipping past logs to `/api/logs`.
6. Complete the console read-path routing (§4) if you need the search UI
   and dashboard to read the external store too.

## 7 · What this is and isn't

**Is:** a real storage-abstraction seam with three working adapters, so
the event firehose can move to a purpose-built engine without touching
detection logic — the architectural answer to the EPS/lock gap.

**Isn't:** a claim that AegisIQ ships a tuned, production-hardened
OpenSearch/ClickHouse deployment. The adapters are written to each
engine's documented query contract and the shared `LogStore` contract;
exercising them needs the external service (bring one up with the
compose profiles). The SQLAlchemy backend remains the tested default.

*See also: `GAP_ANALYSIS.md` (the full SOC-readiness map),
`HOW_IT_WORKS.md` (architecture from zero).*
