"""
app/soar/executor.py -- real containment: turning a recorded SOAR
decision into a signed order a response agent will actually apply
(v3.3).

The scope note that stood at the top of `app/soar/engine.py` for three
releases — "this module decides and records; nothing is executed" — was
honest but it left the product one component short of the thing it
describes. The component is here, and it is deliberately narrow:

* **The SIEM never connects into the estate.** Agents poll
  (`GET /api/soar/agent/orders`); this module only writes rows. So there
  is no inbound port to open on a protected host, nothing to expose, and
  no credential to the estate held by the SIEM.
* **Only registered endpoints.** An order is addressed to an
  `EndpointAgent` row that an administrator created, with a shared secret
  only that host knows. An alert about a host with no agent records the
  decision and says plainly that it was not executed.
* **Guard rails that cannot be argued with** (`_refuse_reason`): the SIEM
  will not block a loopback, link-local or multicast address, will not
  block its own configured console origins, will not disable a protected
  account (the administrator who would have to undo it), and will not act
  on a target it cannot parse. Every refusal is recorded on the action.
* **Everything expires.** An order not collected within
  `SOAR_ORDER_TTL_SECONDS` is dead, and the agent itself auto-expires a
  block after its own `MAX_BLOCK_MINUTES`. Containment that outlives the
  incident is an outage with a security explanation.
* **Reversible.** `revoke()` queues the inverse action (unblock_ip /
  enable_user), so the console can undo a containment in one click.

Controls: NIST SP 800-53 IR-4(2) (automated incident response), AC-3,
AU-2 (every order is audited), SC-13 (HMAC-SHA256 signing), SI-4(7).
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.alert import Alert
from app.models.endpoint_agent import EndpointAgent, OrderStatus, SoarOrder
from app.models.soar import SoarAction, SoarActionStatus, SoarActionType
from app.security import crypto

logger = logging.getLogger(__name__)
settings = get_settings()

# SOAR action type -> the verb the agent understands, and its inverse.
ACTION_TO_AGENT: dict[SoarActionType, str] = {
    SoarActionType.BLOCK_IP: "block_ip",
    SoarActionType.DISABLE_ACCOUNT: "disable_user",
}
INVERSE_ACTION = {
    "block_ip": "unblock_ip",
    "disable_user": "enable_user",
}

# Accounts the SIEM will never disable automatically. Disabling the
# account that would have to re-enable it is how an automated response
# becomes the incident.
_PROTECTED_ACCOUNTS = {"root", "administrator", "admin", "system"}

MAX_CLOCK_SKEW_SECONDS = 60


# ── signing (matches agent/kill_switch_agent_v2.py exactly) ─────────
def sign_body(secret: bytes, body: bytes) -> str:
    """``t=<epoch>,n=<nonce>,v1=<hex>`` over ``f"{t}.{n}." + body``."""
    ts = str(int(time.time()))
    nonce = hashlib.sha256(os.urandom(16)).hexdigest()[:16]
    mac = hmac.new(secret, f"{ts}.{nonce}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={ts},n={nonce},v1={mac}"


def verify_body(secret: bytes, body: bytes, header: str, seen_nonces: set[str]) -> bool:
    """Verify an agent's signed result. Same scheme, same skew window,
    same replay rejection as the agent applies to us."""
    if not header:
        return False
    try:
        parts = dict(kv.split("=", 1) for kv in header.split(",") if "=" in kv)
    except ValueError:
        return False
    ts, nonce, mac = parts.get("t"), parts.get("n"), parts.get("v1")
    if not (ts and nonce and mac):
        return False
    try:
        ts_int = int(ts)
    except ValueError:
        return False
    if abs(int(time.time()) - ts_int) > MAX_CLOCK_SKEW_SECONDS:
        return False
    if nonce in seen_nonces:
        return False
    expected = hmac.new(secret, f"{ts}.{nonce}.".encode() + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, mac):
        return False
    seen_nonces.add(nonce)
    if len(seen_nonces) > 10_000:
        seen_nonces.clear()
        seen_nonces.add(nonce)
    return True


# ── guard rails ─────────────────────────────────────────────────────
def _console_hosts() -> set[str]:
    hosts = set()
    for origin in settings.cors_origins_list:
        host = origin.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        if host:
            hosts.add(host)
    return hosts


def _refuse_reason(agent_action: str, target: str) -> str | None:
    """Why this order must NOT be issued, or None when it is allowed."""
    if not target or not target.strip():
        return "no target to act on"

    if agent_action in ("block_ip", "unblock_ip"):
        try:
            ip = ipaddress.ip_address(target.strip())
        except ValueError:
            return f"{target!r} is not an IP address"
        if ip.is_loopback:
            return "refusing to block a loopback address"
        if ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return "refusing to block a link-local, multicast or reserved address"
        if str(ip) in _console_hosts():
            return "refusing to block the console's own origin"
        if settings.SOAR_BLOCK_PRIVATE_RANGES is False and ip.is_private:
            return ("refusing to block a private address "
                    "(set SOAR_BLOCK_PRIVATE_RANGES=true for a lab network)")

    if agent_action in ("disable_user", "enable_user"):
        if target.strip().lower() in _PROTECTED_ACCOUNTS:
            return f"refusing to disable the protected account {target!r}"
        protected = {
            a.strip().lower()
            for a in (settings.SOAR_PROTECTED_ACCOUNTS or "").split(",")
            if a.strip()
        }
        if target.strip().lower() in protected:
            return f"{target!r} is on SOAR_PROTECTED_ACCOUNTS"

    return None


def _agent_for(db: Session, hostname: str | None) -> EndpointAgent | None:
    """The enabled agent that should carry out an action for this host.

    A host-scoped action (disable an account) goes to that host's agent.
    A network action (block an IP) goes to the host the event came from,
    falling back to the single enabled agent when there is exactly one —
    the lab case, where "the perimeter" is that one box.
    """
    query = db.query(EndpointAgent).filter(EndpointAgent.enabled.is_(True))
    if hostname:
        match = query.filter(EndpointAgent.hostname == hostname).first()
        if match:
            return match
        match = query.filter(EndpointAgent.endpoint_id == hostname).first()
        if match:
            return match
    agents = query.all()
    return agents[0] if len(agents) == 1 else None


# ── issuing orders ──────────────────────────────────────────────────
def queue_order(
    db: Session,
    *,
    agent: EndpointAgent,
    agent_action: str,
    target: str,
    soar_action: SoarAction | None = None,
    alert: Alert | None = None,
    issued_by: str = "soar",
) -> SoarOrder:
    order = SoarOrder(
        order_uid=secrets.token_urlsafe(18),
        endpoint_id=agent.endpoint_id,
        action=agent_action,
        target=target,
        status=OrderStatus.QUEUED,
        soar_action_id=soar_action.id if soar_action else None,
        alert_id=alert.id if alert else (soar_action.alert_id if soar_action else None),
        issued_by=issued_by,
        expires_at=datetime.now(timezone.utc) + timedelta(
            seconds=settings.SOAR_ORDER_TTL_SECONDS),
    )
    db.add(order)
    db.commit()
    db.refresh(order)
    logger.info("queued %s %s for %s (order %s)",
                agent_action, target, agent.endpoint_id, order.order_uid)
    return order


def execute_action(db: Session, action: SoarAction, *, issued_by: str = "soar") -> dict:
    """Try to turn one recorded SOAR action into a real order.

    Always returns a verdict dict and never raises into the caller: the
    ingestion path must not fail because containment could not be
    dispatched. The reason is written onto the action's own detail, so
    the console shows *why* something was not executed instead of
    leaving an operator to guess.
    """
    verdict = {"executed": False, "reason": None, "order_uid": None}

    agent_action = ACTION_TO_AGENT.get(action.action_type)
    if agent_action is None:
        verdict["reason"] = (f"{action.action_type.value} has no agent verb — "
                             "recorded for a human to carry out")
        return verdict

    refusal = _refuse_reason(agent_action, action.target or "")
    if refusal:
        verdict["reason"] = refusal
        _mark(db, action, SoarActionStatus.SIMULATED, f"NOT executed: {refusal}")
        return verdict

    hostname = None
    alert = action.alert if hasattr(action, "alert") else None
    if alert is not None and getattr(alert, "log", None) is not None:
        hostname = alert.log.hostname
    if agent_action in ("disable_user", "enable_user") and not hostname:
        hostname = None  # fall through to the single-agent case

    agent = _agent_for(db, hostname)
    if agent is None:
        verdict["reason"] = ("no response agent registered for this target — "
                             "decision recorded only")
        _mark(db, action, SoarActionStatus.SIMULATED,
              f"NOT executed: {verdict['reason']}")
        return verdict

    try:
        order = queue_order(db, agent=agent, agent_action=agent_action,
                            target=action.target, soar_action=action,
                            issued_by=issued_by)
    except Exception:  # noqa: BLE001 - containment must never break ingestion
        logger.exception("could not queue a containment order")
        verdict["reason"] = "internal error queueing the order (see server log)"
        return verdict

    _mark(db, action, SoarActionStatus.PENDING,
          f"Order {order.order_uid} queued for {agent.endpoint_id} "
          f"({agent_action} {action.target}); awaiting the agent.")
    verdict.update(executed=True, order_uid=order.order_uid,
                   endpoint_id=agent.endpoint_id)
    return verdict


def revoke(db: Session, order: SoarOrder, *, issued_by: str) -> SoarOrder | None:
    """Queue the inverse of an applied order — the undo the console needs
    when containment turns out to have hit the wrong target."""
    inverse = INVERSE_ACTION.get(order.action)
    if inverse is None:
        return None
    agent = (db.query(EndpointAgent)
             .filter(EndpointAgent.endpoint_id == order.endpoint_id).first())
    if agent is None:
        return None
    return queue_order(db, agent=agent, agent_action=inverse, target=order.target,
                       issued_by=issued_by)


def _mark(db: Session, action: SoarAction, status: SoarActionStatus, detail: str) -> None:
    try:
        action.status = status
        action.detail = detail
        db.commit()
    except Exception:  # noqa: BLE001
        logger.exception("could not update SOAR action %s", action.id)
        db.rollback()


# ── the agent-facing side ───────────────────────────────────────────
def collect_orders(db: Session, endpoint_id: str, source_ip: str | None) -> tuple[EndpointAgent | None, list[dict]]:
    """Hand an agent its queued orders and mark them delivered.

    Expired orders are retired here rather than delivered: the agent is
    the only thing that polls, so this is the one place that reliably
    runs.
    """
    agent = (db.query(EndpointAgent)
             .filter(EndpointAgent.endpoint_id == endpoint_id).first())
    if agent is None or not agent.enabled:
        return agent, []

    now = datetime.now(timezone.utc)
    agent.last_seen_at = now
    agent.last_seen_ip = source_ip

    pending = (db.query(SoarOrder)
               .filter(SoarOrder.endpoint_id == endpoint_id,
                       SoarOrder.status == OrderStatus.QUEUED)
               .order_by(SoarOrder.created_at.asc())
               .limit(50).all())

    payload: list[dict] = []
    for order in pending:
        expires = order.expires_at
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires is not None and expires < now:
            order.status = OrderStatus.EXPIRED
            order.completed_at = now
            order.output = "not collected before the order expired"
            continue
        order.status = OrderStatus.DELIVERED
        order.delivered_at = now
        payload.append({
            "id": order.order_uid,
            "action": order.action,
            "target": order.target,
            "alert_id": order.alert_id,
            "issued_at": order.created_at.isoformat() if order.created_at else None,
        })

    db.commit()
    return agent, payload


def record_result(db: Session, endpoint_id: str, order_uid: str,
                  success: bool, output: str) -> SoarOrder | None:
    """Write back what the agent actually did, and reflect it on the SOAR
    action so the console's response history shows reality rather than
    intent."""
    order = (db.query(SoarOrder)
             .filter(SoarOrder.order_uid == order_uid,
                     SoarOrder.endpoint_id == endpoint_id).first())
    if order is None:
        return None

    order.status = OrderStatus.SUCCEEDED if success else OrderStatus.FAILED
    order.completed_at = datetime.now(timezone.utc)
    order.output = (output or "")[:2048]

    if order.soar_action_id:
        action = db.query(SoarAction).filter(SoarAction.id == order.soar_action_id).first()
        if action is not None:
            action.status = (SoarActionStatus.EXECUTED if success
                             else SoarActionStatus.FAILED)
            action.detail = (
                f"{'Applied' if success else 'FAILED'} on {endpoint_id}: "
                f"{order.action} {order.target} — {order.output or 'no output'}"
            )
    db.commit()
    db.refresh(order)
    return order


def agent_secret(agent: EndpointAgent) -> bytes:
    """Decrypt the shared secret for signing/verification."""
    value = crypto.decrypt(agent.secret_enc) or ""
    return value.encode("utf-8")
