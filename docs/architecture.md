# Architecture

## Why this isn't Wazuh + Elasticsearch + Kibana

The graduation project document (section 3.3.2 / 1.7.4) specifies Wazuh
Manager + Elasticsearch + Kibana on Ubuntu Server, targeting **< 2 GB
RAM**. That target is not realistic for the full stack:

- Elasticsearch alone recommends a minimum JVM heap of 1–2 GB and is
  commonly documented as needing 4 GB+ RAM to run stably even for small
  workloads.
- Wazuh Manager, Elasticsearch, and Kibana running together on one host
  routinely consume 3–4+ GB RAM in practice, before any log volume is
  added.
- None of that includes the OS, Docker overhead, or the frontend/demo
  tooling also running on the same laptop during a live presentation.

Running the full stack under 2 GB is not something this project (or any
project) can honestly claim. Rather than silently building something
that contradicts the document's own stated constraint, or spending the
two remaining days fighting Elasticsearch's memory footprint, this
implementation builds a **native lightweight core** that preserves the
document's 5-layer architecture and detection logic, and treats
Wazuh/Elasticsearch/Kibana as an **optional future integration** (see
`WAZUH_URL` / `ELASTICSEARCH_URL` in `.env.example` — unused today,
reserved for that integration).

This substitution is exactly the kind of "technology may differ if you
have a strong technical reason" case anticipated by the build brief, and
is the same conclusion reached independently when this was scoped out
before implementation started.

## The 5-layer model, then and now

| Layer | Document's design (Wazuh/ELK) | This implementation |
|---|---|---|
| 1. Log Sources | Windows PCs, Linux servers, firewalls, IDS/IPS | Same conceptually; demo data comes from the Simulation Lab (next phase) plus the generic log-ingestion API for real logs |
| 2. Collection | Wazuh Agents / Filebeat, TLS-encrypted | `POST /api/logs` HTTP ingestion endpoint (next phase). TLS is a deployment-time concern (reverse proxy), not application code |
| 3. Processing & Analysis | Wazuh Manager: parsing, normalization, rule matching, correlation | FastAPI backend: normalization done (`app/ingestion/`); rule engine + correlation engine still to come (`app/detection/engine.py` is currently a documented no-op) |
| 4. Storage | Elasticsearch, time-based indices | SQLite via SQLAlchemy, indexed on the fields the detection engine queries most (source_ip, event_type, timestamp — see `app/models/log.py`) |
| 5. Visualization | Kibana dashboards | React SOC dashboard, calling the backend's REST API directly |

## Current status (Phase 1 — Foundation, Phase A — Ingestion, Phase B1 — Brute Force, Phase B2 — Port Scan)

Implemented and testable today:

- Database schema for Users, Agents, Logs, Detection Rules, Alerts (+
  status history), Incidents
- JWT authentication, bcrypt password hashing, RBAC (Administrator /
  Security Analyst)
- Seeded default administrator account and the 5 detection rules from
  the document's Table 1, with their exact thresholds, plus MITRE
  ATT&CK and Cyber Kill Chain mappings for each (objective O6)
- `GET /health`, `POST /api/auth/login`, `GET/POST /api/agents`,
  `GET /api/dashboard/stats`, `POST /api/logs` — all backed by real
  database queries
- Log ingestion + normalization (`backend/app/ingestion/`): Linux
  auth-log parsing, Windows Event ID mapping (4625/4624/4672), and
  already-normalized generic JSON, all going through one pipeline
  (route → service → normalizer → database, per the project's own
  modular-architecture requirement)
- Detection engine (`backend/app/detection/`): a thin dispatcher
  (`engine.py`) evaluates enabled rules against every newly-persisted
  log. Two rules are fully implemented, both using the same inclusive
  window convention (`timestamp >= window_start`) and the same shared
  deduplication/alert-creation code (`alerting.py`):
  - **Brute Force Authentication** (`rules/brute_force.py`) — 5+ failed
    logins from the same source IP within 120s → HIGH alert, T1110,
    Kill Chain "Actions on Objectives"
  - **Port Scan** (`rules/port_scan.py`) — 10+ *distinct* destination
    ports (not just 10 events — repeats don't count twice) from the
    same source IP within 60s → HIGH alert, T1046, Kill Chain
    "Reconnaissance"

  Both rules' MITRE *tactic* (Credential Access / Discovery,
  respectively) is documented as a module-level constant for reference
  only — not a stored column, since MITRE tactic and Cyber Kill Chain
  phase are different frameworks and only the latter is part of the
  Alert schema (`kill_chain_phase`). Detection works regardless of
  whether events came in as Linux, Windows, or generic JSON, since they
  all normalize to the same `event_type` first.
- React SOC-themed login + dashboard shell, wired to the real API (no
  mock data)
- Backend test suite (auth, RBAC, dashboard stats, normalization, log
  ingestion, brute-force detection, port-scan detection)

Not implemented yet — reported honestly as `"not_implemented"` by
`/health` rather than faked:

- The other 3 detection rules (login_after_failure, file_integrity,
  privilege_escalation) — they exist in the database with real
  thresholds and MITRE/kill-chain mappings, and the engine's dispatcher
  already has a slot for each, but no handler is registered for them
  yet (see `_RULE_HANDLERS` in `app/detection/engine.py`)
- Event correlation / incident grouping logic
- Alert investigation page, Log Explorer, Rule management UI, Endpoint
  management UI, Simulation Lab
- Real-time updates (WebSocket/SSE)
- System Health page (the data exists via `/health`; no frontend page
  consumes it yet)

## Resource efficiency decisions

- SQLite instead of a database server process — zero extra RAM for a
  DB engine, sufficient for the documented scale (< 100 endpoints).
- No background workers, message queues, or scheduled jobs in this
  phase. When the detection engine lands, rule evaluation runs
  synchronously inside the log-ingestion request path (matches the
  document's own Data Flow Diagram: collect → normalize → detect →
  alert, as one pipeline) rather than adding a queue/worker process.
- Indexes are added deliberately, only on columns the actual query
  patterns need (see the composite index in `app/models/log.py`), not
  on every column.
