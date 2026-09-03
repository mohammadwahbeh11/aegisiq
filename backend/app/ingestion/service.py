"""
app/ingestion/service.py

Orchestrates the ingestion pipeline: resolve/validate the optional
agent -> normalize -> persist -> hand off to detection. Kept separate
from the API route (app/api/routes/logs.py) so the route stays a thin
HTTP adapter (engineering rules #5/#13: route -> service -> normalizer
-> database, not hundreds of lines in the route).
"""
import logging
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.detection import engine as detection_engine
from app.ingestion.normalizer import normalize
from app.ingestion.schemas import LogIngestRequest, LogIngestResponse
from app.models.agent import Agent, AgentStatus
from app.models.alert import Alert
from app.models.log import Log, Severity
from app.realtime.events import serialize_alert, serialize_log
from app.realtime.hub import EVENT_ALERT, EVENT_LOG, hub
from app.soar import engine as soar_engine

logger = logging.getLogger(__name__)


def ingest_log(payload: LogIngestRequest, db: Session) -> LogIngestResponse:
    agent = _resolve_agent(payload.agent_id, db)

    event = normalize(
        {
            "timestamp": payload.timestamp,
            "hostname": payload.hostname,
            "source_ip": payload.source_ip,
            "destination_ip": payload.destination_ip,
            "source_port": payload.source_port,
            "destination_port": payload.destination_port,
            "username": payload.username,
            "event_type": payload.event_type,
            "severity": payload.severity.value if payload.severity else None,
            "source": payload.source,
            "operating_system": payload.operating_system,
            "event_id": payload.event_id,
            "raw_log": payload.raw_log,
            "metadata": payload.metadata,
        }
    )

    log = Log(
        timestamp=event.timestamp,
        hostname=event.hostname or (agent.hostname if agent else None),
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        source_port=event.source_port,
        destination_port=event.destination_port,
        username=event.username,
        event_type=event.event_type,
        severity=Severity(event.severity),
        # normalize() guarantees raw_log is always a non-empty string
        # (falls back to a JSON dump of the submitted payload when no
        # literal raw log was given) -- see app/ingestion/normalizer.py.
        raw_log=event.raw_log,
        normalized_data=event.normalized_data,
        source=event.source or "generic",
        operating_system=event.operating_system,
        event_id=event.event_id,
        agent_id=agent.id if agent else None,
    )

    # v2.4 — write through the pluggable event store. For the default
    # SQLAlchemy backend this is exactly the old add/commit/refresh (the
    # Log becomes a real row and gets an int id). For an external backend
    # (OpenSearch/ClickHouse) the event is indexed there and the Log stays
    # a transient carrier with id=None, so the Alert.log_id foreign key is
    # simply left NULL — the evidence is referenced by source/dedup and
    # lives in the external store. See docs/STORAGE.md.
    from app.storage import get_log_store
    store = get_log_store(db)
    if store.is_relational:
        store.index({"_orm": log})   # add + commit + refresh → log.id set
    else:
        external_id = store.index({
            "timestamp": log.timestamp, "hostname": log.hostname,
            "source_ip": log.source_ip, "destination_ip": log.destination_ip,
            "source_port": log.source_port, "destination_port": log.destination_port,
            "username": log.username, "event_type": log.event_type,
            "severity": event.severity, "raw_log": log.raw_log,
            "normalized_data": log.normalized_data, "source": log.source,
            "operating_system": log.operating_system, "event_id": log.event_id,
        })
        log.id = None
        setattr(log, "_external_id", external_id)

    if agent is not None:
        agent.status = AgentStatus.ONLINE
        agent.last_seen = datetime.now(timezone.utc)
        db.commit()

    alert_ids = process_normalized_event(log, db, store)

    return LogIngestResponse(
        id=log.id if log.id is not None else getattr(log, "_external_id", None),
        status="accepted",
        normalized=True,
        event_type=log.event_type,
        alerts_generated=len(alert_ids),
        alert_ids=alert_ids,
    )


def process_normalized_event(log: Log, db: Session, store=None) -> list[int]:
    """
    The seam Phase B hooked into (per Phase A.11: "structure the code so
    Phase B can easily call something like process_normalized_event(event)
    without rewriting the ingestion pipeline").

    It now does three things in order, and the ORDER MATTERS:
      1. broadcast the stored log, so the console's live feed shows
         activity even when nothing is malicious about it;
      2. run the detection engine (app/detection/engine.py);
      3. for each resulting alert, broadcast it and hand it to the SOAR
         layer (app/soar/engine.py) for a recorded containment decision.

    Steps 1 and 3's broadcasts are fire-and-forget and never raise -- see
    app/realtime/hub.py. The SOAR call is wrapped defensively for the
    same reason: this function's contract to the caller is "the event was
    stored and evaluated", and a response-layer failure must not turn a
    successfully detected attack into an HTTP 500 that makes the log
    shipper retry.
    """
    hub.publish(EVENT_LOG, serialize_log(log))

    alert_ids = detection_engine.evaluate(log, db, store)

    for alert_id in alert_ids:
        alert = db.get(Alert, alert_id)
        if alert is None:  # pragma: no cover - alert was just created
            continue
        hub.publish(EVENT_ALERT, serialize_alert(alert))
        try:
            soar_engine.respond_to_alert(alert, db)
        except Exception:  # noqa: BLE001 - never fail ingestion over the response layer
            logger.exception("SOAR response failed for alert %s", alert_id)

    return alert_ids


def _resolve_agent(agent_id: str | None, db: Session) -> Agent | None:
    """Per Phase A.8/A.9: agent_id is optional and ingestion is never
    blocked by a missing one. But if one IS supplied, it must exist --
    silently accepting an unknown agent would hide a misconfigured
    log shipper instead of surfacing it."""
    if agent_id is None:
        return None
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' is not registered",
        )
    return agent
