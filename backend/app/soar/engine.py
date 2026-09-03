"""
app/soar/engine.py -- the automated-response (SOAR) layer.

Scope, stated plainly because this is the part of a SIEM demo most often
overclaimed: this module DECIDES and RECORDS a containment action for
qualifying alerts. It does not execute anything. There is no code path
in this project that runs `iptables`, disables an account, or touches a
remote host, and `SOAR_EXECUTE=true` does not create one -- it only
marks recorded actions as intended-for-execution (status PENDING instead
of SIMULATED) so that a real executor could be added later without
changing the schema or the console.

That is a deliberate scope decision, not an omission: a graduation
project that ships a self-triggering remote-firewall changer on a lab
network is a liability, and "the SOC console shows exactly what response
would have been taken, for which alert, and why" demonstrates the same
design.

Playbook selection (which action for which alert) is driven by the
alert's own severity and rule type, so it stays consistent with the
detection engine instead of being a second, separately-tuned policy:

    CRITICAL, credential/privilege rules -> DISABLE_ACCOUNT + BLOCK_IP
    CRITICAL, host-integrity rules        -> ISOLATE_ENDPOINT
    HIGH, network-borne rules             -> BLOCK_IP
    anything else                         -> NOTIFY_ANALYST

Every action is broadcast on the realtime hub as it is recorded, so the
console shows containment happening in the same live feed as the alert
that triggered it.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.alert import Alert
from app.models.log import Severity
from app.models.soar import SoarAction, SoarActionStatus, SoarActionType
from app.realtime.hub import EVENT_SOAR, hub

settings = get_settings()

# rule_type -> the containment actions that rule's alerts warrant.
_PLAYBOOKS: dict[str, list[SoarActionType]] = {
    "brute_force": [SoarActionType.BLOCK_IP],
    "port_scan": [SoarActionType.BLOCK_IP],
    "login_after_failure": [SoarActionType.DISABLE_ACCOUNT, SoarActionType.BLOCK_IP],
    "privilege_escalation": [SoarActionType.DISABLE_ACCOUNT],
    "file_integrity": [SoarActionType.ISOLATE_ENDPOINT],
}

# Below this severity, the response is to tell a human rather than to
# contain automatically -- automated containment on low-confidence
# signals is how a SOAR deployment ends up disabling the CEO's account.
_MIN_SEVERITY_FOR_CONTAINMENT = {Severity.HIGH, Severity.CRITICAL}


def _target_for(action_type: SoarActionType, alert: Alert) -> str | None:
    """What this action would be applied to. Returns None when the alert
    doesn't carry the necessary identifier -- e.g. a DISABLE_ACCOUNT
    action for an alert with no associated username -- in which case the
    action is skipped rather than recorded against a made-up target."""
    log = alert.log
    if action_type in (SoarActionType.BLOCK_IP,):
        return alert.source_ip
    if action_type is SoarActionType.DISABLE_ACCOUNT:
        return (log.username if log else None) or alert.dedup_key
    if action_type is SoarActionType.ISOLATE_ENDPOINT:
        return (log.hostname if log else None) or alert.dedup_key
    if action_type is SoarActionType.NOTIFY_ANALYST:
        return alert.dedup_key or alert.source_ip or "unspecified"
    return None


_ACTION_PHRASING = {
    SoarActionType.BLOCK_IP: "Block source address {target} at the perimeter firewall",
    SoarActionType.ISOLATE_ENDPOINT: "Isolate endpoint {target} from the network",
    SoarActionType.DISABLE_ACCOUNT: "Disable account {target} pending investigation",
    SoarActionType.NOTIFY_ANALYST: "Notify the on-duty analyst about {target}",
}


def respond_to_alert(alert: Alert, db: Session) -> list[SoarAction]:
    """Records the containment actions an alert warrants. Returns the
    created rows (empty when SOAR is disabled or the alert warrants no
    action). Never raises into the ingestion path: a response-layer
    problem must not prevent the alert itself from being stored."""
    if not settings.SOAR_ENABLED:
        return []

    rule_type = alert.rule.rule_type if alert.rule else None
    rule_name = alert.rule.name if alert.rule else None

    if alert.severity in _MIN_SEVERITY_FOR_CONTAINMENT:
        action_types = _PLAYBOOKS.get(rule_type, [SoarActionType.NOTIFY_ANALYST])
    else:
        action_types = [SoarActionType.NOTIFY_ANALYST]

    status = SoarActionStatus.PENDING if settings.SOAR_EXECUTE else SoarActionStatus.SIMULATED

    created: list[SoarAction] = []
    for action_type in action_types:
        target = _target_for(action_type, alert)
        if not target:
            continue  # no identifier to act on -- skip rather than invent one

        detail = _ACTION_PHRASING[action_type].format(target=target)
        if status is SoarActionStatus.SIMULATED:
            detail += " (recorded only -- not executed; see SOAR_EXECUTE in .env)"

        action = SoarAction(
            timestamp=alert.timestamp,
            action_type=action_type,
            target=target,
            alert_id=alert.id,
            rule_name=rule_name,
            status=status,
            detail=detail,
            execution_requested=settings.SOAR_EXECUTE,
        )
        db.add(action)
        created.append(action)

    if not created:
        return []

    db.commit()
    for action in created:
        db.refresh(action)
        payload = serialize_action(action)
        hub.publish(EVENT_SOAR, payload)
        # v2.3 — hand the action to an external automation platform
        # (Shuffle/Cortex/n8n) when a webhook is configured. Fire-and-
        # forget; a dead receiver never delays or fails ingestion.
        try:
            from app.soar import webhook
            webhook.dispatch(payload)
        except Exception:  # noqa: BLE001 - defensive, never break ingestion
            pass

    return created


def serialize_action(action: SoarAction) -> dict:
    """One place that decides the wire shape of a SOAR action, shared by
    the REST route and the realtime broadcast so the console never has to
    handle two different shapes for the same thing."""
    return {
        "id": action.id,
        "timestamp": action.timestamp.isoformat() if action.timestamp else None,
        "action_type": action.action_type.value,
        "target": action.target,
        "alert_id": action.alert_id,
        "rule_name": action.rule_name,
        "status": action.status.value,
        "detail": action.detail,
        "execution_requested": action.execution_requested,
    }
