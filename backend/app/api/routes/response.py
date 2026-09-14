"""
app/api/routes/response.py -- the real-containment surface (v3.3).

Two audiences, deliberately separated:

  ADMIN (JWT, administrator role)
    POST   /api/agents/endpoints          enrol a response agent
    GET    /api/agents/endpoints          list them with liveness
    PATCH  /api/agents/endpoints/{id}     enable / disable / relabel
    DELETE /api/agents/endpoints/{id}     remove one
    POST   /api/soar/actions/{id}/execute carry out a recorded action now
    POST   /api/soar/orders/{uid}/revoke  undo an applied order
    GET    /api/soar/orders               the order ledger

  AGENT (HMAC-signed, no JWT — an agent has no user identity)
    GET    /api/soar/agent/orders?endpoint=<id>   collect queued orders
    POST   /api/soar/agent/result                 report what it did

The agent endpoints are the ones `agent/kill_switch_agent_v2.py` has
always called and that this backend never implemented. Their auth is
HMAC-SHA256 over the body with the endpoint's own shared secret, plus a
60-second clock-skew window and per-process nonce replay rejection —
identical in both directions, so the agent verifies us exactly as we
verify it.

The shared secret is returned ONCE, at enrolment, and stored encrypted
(AES-256-GCM) thereafter: a response agent's secret is a remote-command
capability, so there is no endpoint that reads it back.
"""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.auth.dependencies import get_current_user, require_role
from app.config import get_settings
from app.models.endpoint_agent import EndpointAgent, OrderStatus, SoarOrder
from app.models.soar import SoarAction
from app.models.user import User, UserRole
from app.security import audit, crypto
from app.security.net import client_ip
from app.soar import executor

router = APIRouter(tags=["response"])
settings = get_settings()

ACT_AGENT_ENROL = "response.agent.enrol"
ACT_AGENT_UPDATE = "response.agent.update"
ACT_AGENT_DELETE = "response.agent.delete"
ACT_ORDER_ISSUED = "response.order.issued"
ACT_ORDER_REVOKED = "response.order.revoked"
ACT_ORDER_RESULT = "response.order.result"

# Nonces seen from agents in this process. Bounded inside verify_body().
_SEEN_NONCES: set[str] = set()


# ── schemas ─────────────────────────────────────────────────────────
class EnrolRequest(BaseModel):
    endpoint_id: str = Field(..., min_length=2, max_length=64,
                             pattern=r"^[A-Za-z0-9._\-]+$")
    label: str | None = Field(default=None, max_length=128)
    hostname: str | None = Field(default=None, max_length=255)
    platform: str | None = Field(default=None, max_length=32)
    note: str | None = Field(default=None, max_length=2000)


class EnrolResponse(BaseModel):
    endpoint_id: str
    shared_secret: str
    install_hint: str
    note: str


class AgentUpdate(BaseModel):
    enabled: bool | None = None
    label: str | None = Field(default=None, max_length=128)
    hostname: str | None = Field(default=None, max_length=255)
    note: str | None = Field(default=None, max_length=2000)


class AgentResultRequest(BaseModel):
    endpoint_id: str
    order_id: str
    success: bool
    output: str = ""


def _serialize_agent(agent: EndpointAgent) -> dict:
    last_seen = agent.last_seen_at
    if last_seen is not None and last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    age = None
    if last_seen is not None:
        age = int((datetime.now(timezone.utc) - last_seen).total_seconds())
    return {
        "id": agent.id,
        "endpoint_id": agent.endpoint_id,
        "label": agent.label,
        "hostname": agent.hostname,
        "platform": agent.platform,
        "enabled": agent.enabled,
        "note": agent.note,
        "last_seen_at": last_seen.isoformat() if last_seen else None,
        "last_seen_seconds_ago": age,
        # An agent that polls every 5 s and has been quiet for a minute is
        # not "registered", it is missing — say so rather than showing a
        # green row for a box that is powered off.
        "status": ("never_seen" if age is None
                   else "online" if age <= 60
                   else "stale" if age <= 600
                   else "offline"),
        "last_seen_ip": agent.last_seen_ip,
    }


def _serialize_order(order: SoarOrder) -> dict:
    return {
        "order_uid": order.order_uid,
        "endpoint_id": order.endpoint_id,
        "action": order.action,
        "target": order.target,
        "status": order.status.value,
        "alert_id": order.alert_id,
        "soar_action_id": order.soar_action_id,
        "issued_by": order.issued_by,
        "created_at": order.created_at.isoformat() if order.created_at else None,
        "delivered_at": order.delivered_at.isoformat() if order.delivered_at else None,
        "completed_at": order.completed_at.isoformat() if order.completed_at else None,
        "output": order.output,
        "revocable": (order.status is OrderStatus.SUCCEEDED
                      and order.action in executor.INVERSE_ACTION),
    }


# ── admin: the endpoint registry ────────────────────────────────────
@router.post("/api/agents/endpoints", status_code=status.HTTP_201_CREATED,
             response_model=EnrolResponse)
def enrol_endpoint(payload: EnrolRequest, request: Request,
                   db: Session = Depends(get_db),
                   user: User = Depends(require_role(UserRole.ADMINISTRATOR))):
    """Register a response agent and mint its shared secret.

    The secret is shown once, here. It is stored encrypted and never
    returned again — a secret that can be read back from an API is a
    remote-command capability behind one stolen session.
    """
    existing = (db.query(EndpointAgent)
                .filter(EndpointAgent.endpoint_id == payload.endpoint_id).first())
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"Endpoint {payload.endpoint_id!r} is already enrolled.")

    if not crypto.is_enabled():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=("DATA_ENCRYPTION_KEY is not set, so the agent secret could not "
                    "be stored encrypted. Set it before enrolling a response agent."),
        )

    secret = secrets.token_urlsafe(32)
    agent = EndpointAgent(
        endpoint_id=payload.endpoint_id,
        label=payload.label,
        hostname=payload.hostname,
        platform=payload.platform,
        note=payload.note,
        secret_enc=crypto.encrypt(secret),
    )
    db.add(agent)
    db.commit()

    audit.record(db, action=ACT_AGENT_ENROL, outcome="success",
                 username=user.username, source_ip=client_ip(request),
                 target=payload.endpoint_id,
                 details={"hostname": payload.hostname, "platform": payload.platform})

    return EnrolResponse(
        endpoint_id=payload.endpoint_id,
        shared_secret=secret,
        install_hint=(
            "sudo AEGIS_ENDPOINT_ID={eid} AEGIS_SHARED_SECRET=<the secret above> "
            "AEGIS_SIEM_URL=<this API's base URL> python3 /opt/aegisiq/kill_switch_agent_v2.py"
        ).format(eid=payload.endpoint_id),
        note=("Copy the secret now — it is stored encrypted and is never shown "
              "again. Re-enrol the endpoint to rotate it."),
    )


@router.get("/api/agents/endpoints")
def list_endpoints(db: Session = Depends(get_db),
                   _user: User = Depends(get_current_user)):
    agents = db.query(EndpointAgent).order_by(EndpointAgent.created_at.desc()).all()
    return {
        "items": [_serialize_agent(a) for a in agents],
        "execution_enabled": settings.SOAR_EXECUTE,
        "note": (
            "SOAR_EXECUTE is on: qualifying containment is dispatched to these "
            "agents." if settings.SOAR_EXECUTE else
            "SOAR_EXECUTE is off: containment is recorded and shown, never sent."
        ),
    }


@router.patch("/api/agents/endpoints/{endpoint_id}")
def update_endpoint(endpoint_id: str, payload: AgentUpdate, request: Request,
                    db: Session = Depends(get_db),
                    user: User = Depends(require_role(UserRole.ADMINISTRATOR))):
    agent = (db.query(EndpointAgent)
             .filter(EndpointAgent.endpoint_id == endpoint_id).first())
    if agent is None:
        raise HTTPException(status_code=404, detail="No such endpoint.")
    for field_name in ("enabled", "label", "hostname", "note"):
        value = getattr(payload, field_name)
        if value is not None:
            setattr(agent, field_name, value)
    db.commit()
    audit.record(db, action=ACT_AGENT_UPDATE, outcome="success",
                 username=user.username, source_ip=client_ip(request),
                 target=endpoint_id,
                 details=payload.model_dump(exclude_none=True))
    return _serialize_agent(agent)


@router.delete("/api/agents/endpoints/{endpoint_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_endpoint(endpoint_id: str, request: Request,
                    db: Session = Depends(get_db),
                    user: User = Depends(require_role(UserRole.ADMINISTRATOR))):
    agent = (db.query(EndpointAgent)
             .filter(EndpointAgent.endpoint_id == endpoint_id).first())
    if agent is None:
        raise HTTPException(status_code=404, detail="No such endpoint.")
    db.delete(agent)
    db.commit()
    audit.record(db, action=ACT_AGENT_DELETE, outcome="success",
                 username=user.username, source_ip=client_ip(request),
                 target=endpoint_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── admin: execute / revoke ─────────────────────────────────────────
@router.post("/api/soar/actions/{action_id}/execute")
def execute_now(action_id: int, request: Request,
                db: Session = Depends(get_db),
                user: User = Depends(require_role(UserRole.ADMINISTRATOR))):
    """Carry out a recorded containment decision on demand — the
    analyst-in-the-loop path, available whether or not SOAR_EXECUTE is
    on. The same guard rails apply as for automatic dispatch."""
    action = db.query(SoarAction).filter(SoarAction.id == action_id).first()
    if action is None:
        raise HTTPException(status_code=404, detail="No such SOAR action.")

    verdict = executor.execute_action(db, action, issued_by=user.username)
    audit.record(db, action=ACT_ORDER_ISSUED,
                 outcome="success" if verdict["executed"] else "failure",
                 username=user.username, source_ip=client_ip(request),
                 target=action.target, details=verdict)
    if not verdict["executed"]:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=verdict["reason"])
    return verdict


@router.post("/api/soar/orders/{order_uid}/revoke")
def revoke_order(order_uid: str, request: Request,
                 db: Session = Depends(get_db),
                 user: User = Depends(require_role(UserRole.ADMINISTRATOR))):
    """Undo an applied order by queueing its inverse (unblock / enable)."""
    order = db.query(SoarOrder).filter(SoarOrder.order_uid == order_uid).first()
    if order is None:
        raise HTTPException(status_code=404, detail="No such order.")
    inverse = executor.revoke(db, order, issued_by=user.username)
    if inverse is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"{order.action} cannot be reversed automatically.")
    audit.record(db, action=ACT_ORDER_REVOKED, outcome="success",
                 username=user.username, source_ip=client_ip(request),
                 target=order.target,
                 details={"original": order.order_uid, "inverse": inverse.order_uid})
    return _serialize_order(inverse)


@router.get("/api/soar/orders")
def list_orders(db: Session = Depends(get_db),
                _user: User = Depends(get_current_user),
                limit: int = Query(default=50, ge=1, le=500),
                offset: int = Query(default=0, ge=0)):
    query = db.query(SoarOrder).order_by(SoarOrder.created_at.desc())
    total = query.count()
    rows = query.offset(offset).limit(limit).all()
    return {"total": total, "items": [_serialize_order(o) for o in rows]}


# ── agent-facing: HMAC only, no user session ────────────────────────
@router.get("/api/soar/agent/orders")
def agent_orders(request: Request, endpoint: str = Query(..., max_length=64),
                 db: Session = Depends(get_db)):
    """The agent's poll. The RESPONSE is signed with the endpoint's
    secret, so an agent never applies an order it cannot attribute to
    this SIEM — that signature is the only thing standing between a
    protected host and anyone who can answer its HTTP request."""
    agent, orders = executor.collect_orders(db, endpoint, client_ip(request))
    if agent is None:
        # Same body for "unknown endpoint" as for "nothing to do": an
        # unauthenticated caller must not be able to enumerate which
        # endpoints are enrolled.
        return Response(content=json.dumps({"orders": []}),
                        media_type="application/json")

    body = json.dumps({"orders": orders}).encode("utf-8")
    signature = executor.sign_body(executor.agent_secret(agent), body)
    return Response(content=body, media_type="application/json",
                    headers={"X-AegisIQ-Signature": signature})


@router.post("/api/soar/agent/result")
async def agent_result(request: Request, db: Session = Depends(get_db)):
    """The agent reports what happened. Verified by HMAC over the raw
    body — the request is parsed only after the signature checks out."""
    raw = await request.body()
    try:
        payload = AgentResultRequest(**json.loads(raw or b"{}"))
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Malformed result body.")

    agent = (db.query(EndpointAgent)
             .filter(EndpointAgent.endpoint_id == payload.endpoint_id).first())
    if agent is None or not agent.enabled:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Unknown or disabled endpoint.")

    signature = request.headers.get("x-aegisiq-signature", "")
    if not executor.verify_body(executor.agent_secret(agent), raw, signature, _SEEN_NONCES):
        audit.record(db, action=ACT_ORDER_RESULT, outcome="failure",
                     username=f"agent:{payload.endpoint_id}",
                     source_ip=client_ip(request),
                     details={"reason": "signature_invalid_or_replayed"})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid or replayed signature.")

    order = executor.record_result(db, payload.endpoint_id, payload.order_id,
                                   payload.success, payload.output)
    if order is None:
        raise HTTPException(status_code=404, detail="No such order for this endpoint.")

    audit.record(db, action=ACT_ORDER_RESULT,
                 outcome="success" if payload.success else "failure",
                 username=f"agent:{payload.endpoint_id}",
                 source_ip=client_ip(request), target=order.target,
                 details={"order": order.order_uid, "action": order.action,
                          "output": (payload.output or "")[:500]})
    return {"ok": True, "order": _serialize_order(order)}
