# Lightweight SIEM — API Reference

> Complete reference for every HTTP endpoint exposed by the backend. All examples assume the backend is reachable at `http://localhost:8000`; adjust to your deployment.

## Table of contents

1. [Authentication](#1-authentication)
2. [Health](#2-health)
3. [Log ingestion & search](#3-log-ingestion--search)
4. [Alerts](#4-alerts)
5. [Detection rules](#5-detection-rules)
6. [Agents / endpoints](#6-agents--endpoints)
7. [SOAR — automated response](#7-soar--automated-response)
8. [Retention](#8-retention)
9. [Simulation lab](#9-simulation-lab)
10. [Integrations (Wazuh)](#10-integrations-wazuh)
11. [Dashboard aggregates](#11-dashboard-aggregates)
12. [Real-time stream (WebSocket)](#12-real-time-stream-websocket)
13. [Error model](#13-error-model)

---

## 1. Authentication

All endpoints except `GET /health` and `POST /api/auth/login` require a Bearer token in the `Authorization` header. The token is a JWT (HS256), lifetime 60 minutes by default.

### `POST /api/auth/login`

Exchange username + password for a JWT.

**Request**
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"ChangeMe123!"}'
```

**Response** — `200`
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "username": "admin",
  "role": "administrator"
}
```

**Errors** — `401` for wrong password or unknown username (the API deliberately returns the same status for both — no username enumeration).

Send the token as `Authorization: Bearer <access_token>` on every subsequent call.

---

## 2. Health

### `GET /health`

Unauthenticated. Reports live status of every subsystem, computed from real state — not a hardcoded string.

**Request**
```bash
curl http://localhost:8000/health
```

**Response** — `200`
```json
{
  "api": "ok",
  "database": "ok",
  "detection_engine": "ok",
  "detection_rules_implemented": [
    "brute_force", "file_integrity", "login_after_failure",
    "port_scan", "privilege_escalation"
  ],
  "detection_rules_enabled_without_handler": [],
  "collector": "ok",
  "websocket": "ok",
  "websocket_subscribers": 2,
  "soar": "record_only",
  "wazuh": "not_configured"
}
```

- `detection_engine` = `"ok"` when every enabled rule has a handler; `"partial"` when some don't (the missing ones appear in `detection_rules_enabled_without_handler`).
- `soar` = `"record_only"` (default), `"execute_requested"`, or `"disabled"`.
- `wazuh` = `"not_configured"` until `WAZUH_URL` is set in `.env`, then `"configured"`.

---

## 3. Log ingestion & search

### `POST /api/logs`

Ingest one event. Runs normalization → persistence → detection engine → SOAR → live broadcast, all in one request.

**Request** — accepts either a raw log line, a Windows Event ID, or a fully pre-normalized event. Minimum: one of `raw_log`, `event_type`, or `event_id`.

```bash
TOKEN=$(curl -sX POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"ChangeMe123!"}' | jq -r .access_token)

# Linux auth line
curl -X POST http://localhost:8000/api/logs \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"raw_log":"Failed password for admin from 192.168.1.50 port 22 ssh2"}'

# Windows Event ID
curl -X POST http://localhost:8000/api/logs \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"event_id":4625,"source_ip":"10.0.0.5","username":"Administrator"}'

# Fully pre-normalized
curl -X POST http://localhost:8000/api/logs \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"event_type":"port_access","source_ip":"10.20.30.40","destination_port":22}'
```

**Response** — `201`
```json
{
  "id": 42,
  "status": "accepted",
  "normalized": true,
  "event_type": "authentication_failure",
  "alerts_generated": 1,
  "alert_ids": [17]
}
```

`alerts_generated` = how many rules fired on this single event.

**Errors** — `422` for invalid IP / port / severity / timestamp / empty payload. `401` unauthenticated. `404` if `agent_id` is set but unknown.

### `GET /api/logs`

Paginated search. Every query parameter is optional.

**Query**
- `severity` = `low|medium|high|critical`
- `event_type` = one of the strings the ingestion has emitted
- `source_ip`, `hostname`, `username` — exact match
- `search` — substring match across `raw_log`, `username`, `hostname`, `event_type` (max 200 chars)
- `since_hours` (1–8760)
- `limit` (1–1000, default 100), `offset` (default 0)

**Request**
```bash
curl "http://localhost:8000/api/logs?severity=high&limit=25" \
  -H "Authorization: Bearer $TOKEN"
```

**Response** — `200`
```json
{
  "total": 348,
  "items": [
    {
      "id": 42, "timestamp": "2026-08-23T12:34:56", "hostname": "web-01",
      "source_ip": "203.0.113.7", "destination_ip": null,
      "source_port": null, "destination_port": 22,
      "username": "admin", "event_type": "authentication_failure",
      "event_id": null, "severity": "medium", "source": "generic",
      "operating_system": null, "raw_log": "Failed password for admin ...",
      "normalized_data": {}, "agent_id": null
    }
  ]
}
```

`total` counts matches *before* limit/offset.

### `GET /api/logs/{id}`
Returns one log by id. `404` if not found.

### `GET /api/logs/event-types`
Returns the distinct set of `event_type` values present in the database. Used by the console's filter dropdown.

### `DELETE /api/logs/{id}`  · **admin only**
Permanently removes one log. Alerts that referenced it lose their `log_id` (set to NULL); the alerts themselves are kept — an alert is the SOC's work product, the log is the evidence chain, and losing evidence should not silently disappear the alert.

**Response** — `204` on success. `403` for non-admin. `404` if not found.

### `POST /api/logs/bulk-delete`  · **admin only**
```json
{ "ids": [1, 2, 3] }
```
Returns `{ "deleted": <count> }`. Missing ids are silently skipped.

---

## 4. Alerts

### `GET /api/alerts`

Paginated alert queue.

**Query** — `severity`, `status`, `source_ip`, `rule_id`, `since_hours`, `limit` (1–1000, default 100), `offset`.

**Response** — `200`
```json
{
  "total": 7,
  "items": [
    {
      "id": 17, "timestamp": "2026-08-23T12:34:56", "severity": "high",
      "status": "new", "source_ip": "203.0.113.7", "destination_ip": null,
      "rule_id": 1, "rule_name": "Brute Force Authentication", "rule_type": "brute_force",
      "mitre_id": "T1110", "kill_chain_phase": "Actions on Objectives",
      "description": "Brute-force authentication attack detected from 203.0.113.7: 6 failed authentication attempts within 120 seconds.",
      "log_id": 42, "incident_id": null, "created_at": "2026-08-23T12:34:57"
    }
  ]
}
```

### `GET /api/alerts/{id}`

Detail view. Same fields as above plus:

```json
{
  "rule_description": "5 or more failed login attempts...",
  "rule_threshold": 5,
  "rule_time_window_seconds": 120,
  "triggering_log": { /* AlertLogContext */ },
  "related_logs": [ /* up to 25 events in the rule's window */ ],
  "status_history": [
    { "previous_status": null, "new_status": "new",
      "changed_by": null, "changed_at": "2026-08-23T12:34:57" }
  ]
}
```

### `PATCH /api/alerts/{id}/status`

Triage. Both roles can call.
```json
{ "status": "investigating" }
```
Valid values: `new`, `investigating`, `resolved`, `false_positive`.
Records the change in `alert_status_history` (who, when, from, to). No-op if the requested status equals the current one.

### `DELETE /api/alerts/{id}`  · **admin only**
Permanently removes one alert. **Cascades:** the alert's `status_history` rows and its `SoarAction` rows are removed too — audit rows tied to a nonexistent alert would be misleading.

**Response** — `204`. `403` non-admin. `404` not found.

### `POST /api/alerts/bulk-delete`  · **admin only**
```json
{ "ids": [1, 2, 3] }
```
Returns `{ "deleted": <count> }`.

---

## 5. Detection rules

### `GET /api/rules`
List every configured rule with its live thresholds.

**Response** — `200`
```json
[
  {
    "id": 1, "name": "Brute Force Authentication",
    "description": "5 or more failed login attempts from the same source IP within 120 seconds...",
    "rule_type": "brute_force", "threshold": 5, "time_window_seconds": 120,
    "severity": "high", "mitre_id": "T1110",
    "kill_chain_phase": "Actions on Objectives",
    "parameters": null, "enabled": true,
    "created_at": "2026-08-01T00:00:00", "updated_at": "2026-08-01T00:00:00",
    "implemented": true
  }
]
```
`implemented=false` means this build has no handler for the rule's `rule_type` (the row exists but never fires).

### `PATCH /api/rules/{id}`  · **admin only**
Change threshold, window, severity, enabled, or parameters. Applies to the very next event; no restart.
```json
{ "threshold": 3, "time_window_seconds": 60, "enabled": true }
```
`threshold` must be 1–100 000; `time_window_seconds` 1–86 400.

---

## 6. Agents / endpoints

### `GET /api/agents`
Locally registered agents.

### `GET /api/agents/overview`
Merged local + Wazuh view.
```json
{
  "total": 3,
  "sources": { "local": 2, "wazuh": 1 },
  "wazuh_integration": {
    "status": "connected",
    "url": "https://192.168.100.68:55000",
    "detail": "Wazuh Manager API reachable and authenticated.",
    "agent_count": 1
  },
  "items": [
    { "source": "local", "agent_id": "…", "hostname": "web-01",
      "ip_address": "192.168.1.10", "operating_system": "Ubuntu 22.04",
      "status": "online", "last_seen": "2026-08-23T12:00:00", "version": null },
    { "source": "wazuh", "agent_id": "001", "hostname": "kali-01",
      "ip_address": "192.168.100.67", "operating_system": "Kali Linux",
      "status": "active", "last_seen": "2026-08-23T12:00:00", "version": "4.7.0" }
  ]
}
```

### `POST /api/agents`  · **admin only**
```json
{ "hostname": "ubuntu-server-01",
  "operating_system": "Ubuntu 22.04",
  "ip_address": "192.168.1.10" }
```
Returns the created row (status = `offline` until it sends its first event).

---

## 7. SOAR — automated response

### `GET /api/soar/actions`
Read-only history of containment decisions.

**Query** — `action_type`, `status` (alias `?status=`), `target`, `limit`, `offset`.

**Response**
```json
{
  "total": 12,
  "enabled": true,
  "execution_mode": "record_only",
  "items": [
    {
      "id": 5, "timestamp": "2026-08-23T12:34:57",
      "action_type": "block_ip", "target": "203.0.113.7",
      "alert_id": 17, "rule_name": "Brute Force Authentication",
      "status": "simulated",
      "detail": "Block source address 203.0.113.7 at the perimeter firewall (recorded only — not executed; see SOAR_EXECUTE in .env)",
      "execution_requested": false
    }
  ]
}
```

`execution_mode`:
- `"record_only"` — this build never runs a firewall / account command. `status` will be `simulated`.
- `"execute_requested"` — actions are marked `pending` for an external executor to consume. The shipped code never sets this — you opt in via `SOAR_EXECUTE=true` in `.env`.

**There is no POST endpoint.** Actions can only be created by the detection engine reacting to a real alert — an action with no alert behind it would break the audit chain.

---

## 8. Retention

### `GET /api/retention/config`  · **admin only**
```json
{ "log_retention_days": 30, "alert_retention_days": 90, "max_db_size_mb": 500 }
```
These are the defaults from `.env`. Purge runs on demand (no scheduler); the numbers are shown so an administrator knows what "old" means for this deployment.

### `POST /api/retention/dry-run`  · **admin only**
Compute what a purge WOULD delete without touching anything.
```json
{
  "alerts_older_than_days": 30,
  "logs_older_than_days": 14,
  "only_triaged_alerts": true,
  "min_severity_to_keep": "high"
}
```
Returns `{ "would_delete_alerts": 42, "would_delete_logs": 1180, "cutoff_alerts": "…", "cutoff_logs": "…" }`.

### `POST /api/retention/purge`  · **admin only**
Same payload; actually deletes.

**Safety rules encoded server-side:**
- Empty payload → `400`. Nothing is ever purged by accident.
- `only_triaged_alerts: true` (default) → alerts still `new` or `investigating` are preserved regardless of age. Analysts' unfinished work is never deleted.
- `min_severity_to_keep: "high"` (default) → alerts of severity ≥ HIGH are preserved regardless of age. Pass `"critical"` to allow HIGH deletions, or `null` to remove the guard.

**Response**
```json
{
  "deleted_alerts": 12,
  "deleted_logs": 380,
  "deleted_soar_actions": 15,
  "deleted_alert_status_history": 28,
  "cutoff_alerts": "2026-07-24T12:34:56",
  "cutoff_logs": "2026-08-09T12:34:56",
  "detail": "deleted 12 alert(s) older than 30 day(s); deleted 380 log(s) older than 14 day(s)"
}
```

---

## 9. Simulation lab

### `GET /api/simulation/scenarios`  · **admin only**
List canned scenarios. Each entry: `key`, `name`, `description`, `expected_rules[]`, `event_count`, `estimated_seconds`.

Available: `brute_force`, `port_scan`, `credential_compromise`, `privilege_escalation`, `file_tampering`, `full_attack_chain`.

### `POST /api/simulation/run/{scenario_key}`  · **admin only**
Fire-and-forget. Returns `202` immediately with the plan; the events stream in over the next ~30 seconds through the normal ingestion pipeline, so if the rules don't fire on this traffic, no alert appears (no fabricated data).

---

## 10. Integrations (Wazuh)

### `GET /api/integrations`
```json
{
  "wazuh": { "status": "…", "url": "…", "detail": "…", "agent_count": … },
  "soar":  { "enabled": true, "execution_mode": "record_only", "detail": "…" }
}
```

### `GET /api/integrations/wazuh/status`
Live probe of the configured Wazuh Manager. Never raises — returns a status the console can render directly:

| status | when |
|---|---|
| `not_configured` | `WAZUH_URL` blank |
| `connected` | authenticated + agents list retrieved |
| `unauthorized` | reached, but credentials rejected |
| `unreachable` | network error |
| `error` | any other failure |

---

## 11. Dashboard aggregates

### `GET /api/dashboard/stats`
```json
{
  "total_events": 12904, "events_today": 380,
  "active_alerts": 7, "critical_alerts": 2, "high_alerts": 4,
  "monitored_endpoints": 3, "online_endpoints": 2,
  "detection_rate": 87.5, "avg_detection_time_seconds": 0.12,
  "soar_actions": 12, "soar_actions_today": 5
}
```
`detection_rate` and `avg_detection_time_seconds` are `null` (not 0) until at least one alert exists — reporting 0 would look like "the engine caught nothing".

### `GET /api/dashboard/severity-distribution`
Counts of ACTIVE (new + investigating) alerts per severity. Every severity key appears even when count is 0.

### `GET /api/dashboard/timeline?hours=24`
Hourly buckets of events + alerts over the window. Empty hours are emitted explicitly.

### `GET /api/dashboard/top-sources?limit=5`
Top source IPs by alert count. Alerts with no source IP are excluded.

### `GET /api/dashboard/mitre-coverage`
Per-rule MITRE + Kill Chain mapping with the alert count each rule has raised. Rules with 0 alerts are included — "covered but never fired" is exactly what a coverage view is for.

---

## 12. Real-time stream (WebSocket)

### `WS /ws/stream?token=<jwt>`

Auth is a query-string token (browsers can't set headers on WebSocket handshake). Invalid or missing token closes with code `1008` (policy violation) so the frontend can distinguish "session expired" from "backend down".

**Message shape** — every frame:
```json
{ "seq": 42, "type": "log|alert|soar_action|hello|pong", "at": "2026-…", "data": {…} }
```

- `hello` on connect: `{ "username", "role", "subscribers", "replay": [...last 50 events...] }`
- `log`: same shape as `GET /api/logs` items
- `alert`: same shape as `GET /api/alerts` items
- `soar_action`: same shape as `GET /api/soar/actions` items
- `pong`: reply to a client-sent `"ping"` text frame

The frontend also polls `/api/alerts` every 8 seconds as a fallback, so a dropped socket does not mean a dropped alert.

---

## 13. Error model

Every error uses FastAPI's standard shape:
```json
{ "detail": "Human-readable message here" }
```

| Code | Meaning in this API |
|---|---|
| `200` | success |
| `201` | resource created (POST /api/logs, /api/agents) |
| `202` | accepted for background processing (POST /api/simulation/run/…) |
| `204` | success with no body (DELETE) |
| `400` | request violates a documented safety rule (e.g. empty purge) |
| `401` | missing / invalid / expired token |
| `403` | authenticated but the role is not permitted |
| `404` | resource id not found |
| `422` | request body failed Pydantic validation (bad IP, port, severity, missing required field, …) |
| `500` | unhandled server error — SHOULD NOT happen; open an issue with the log |

All input is validated at the schema layer before it reaches business logic — an invalid IP, an out-of-range port, a bad severity, or a request with nothing normalizable returns `422` with a JSON `detail` explaining exactly which field failed.

---

*Reference generated from the code in `backend/app/api/routes/`. Interactive docs (Swagger UI + ReDoc) are also live on the running backend at `/docs` and `/redoc`.*
