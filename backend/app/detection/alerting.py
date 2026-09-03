"""
app/detection/alerting.py -- the "Alert Service" layer (Step 18's
architecture: Rules -> Alert Service -> Database).

Originally, deduplication and Alert-row creation were implemented
inline inside app/detection/rules/brute_force.py (Phase B1). Extracted
here so every rule shares the exact same dedup/creation behavior
instead of each rule reimplementing its own copy (Phase B2 Step 11:
"Reuse the existing B1 deduplication pattern... do NOT create a second
independent deduplication architecture").

Phase C update: the dedup discriminator is now an explicit `dedup_key`
argument (stored on Alert.dedup_key) rather than the source IP column.
brute_force and port_scan pass their source IP and so behave exactly as
before; file_integrity and privilege_escalation operate on events that
often carry NO source IP at all, and would otherwise all collapse into
a single "source_ip IS NULL" bucket -- one tampered file suppressing
the alert for every other tampered file.
"""
from datetime import datetime

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertStatus
from app.models.log import Log
from app.models.rule import DetectionRule


def has_active_alert(rule_id: int, dedup_key: str, window_start: datetime, db: Session) -> bool:
    """
    Deduplication / cooldown, shared by every rule. For the same rule +
    dedup key, a new alert is suppressed if an existing alert is either:

      (a) still OPEN (status NEW or INVESTIGATING) -- don't pile on
          duplicate alerts while an analyst hasn't triaged the first
          one yet, regardless of how long ago it fired; or
      (b) RECENT -- created within the current detection window, using
          the same inclusive boundary as the detection window itself
          (timestamp >= window_start) -- so events #11, #12, #13 right
          after a rule fires don't each spawn their own alert.

    A genuinely new attack from the same source after the previous alert
    has been resolved/marked false positive AND the window has elapsed
    creates a new alert normally -- a source is not muted forever.
    """
    return (
        db.query(Alert.id)
        .filter(
            Alert.rule_id == rule_id,
            Alert.dedup_key == dedup_key,
            or_(
                Alert.status.in_([AlertStatus.NEW, AlertStatus.INVESTIGATING]),
                Alert.timestamp >= window_start,
            ),
        )
        .first()
        is not None
    )


def create_alert(
    rule: DetectionRule,
    log: Log,
    description: str,
    db: Session,
    dedup_key: str | None = None,
) -> Alert:
    """Persists a new Alert row for a fired rule. Does not itself check
    deduplication -- callers check has_active_alert() first.

    dedup_key defaults to the log's source IP so the two network rules
    keep their original behavior without passing it explicitly."""
    alert = Alert(
        timestamp=log.timestamp,
        severity=rule.severity,
        source_ip=log.source_ip,
        destination_ip=log.destination_ip,
        rule_id=rule.id,
        mitre_id=rule.mitre_id,
        kill_chain_phase=rule.kill_chain_phase,
        description=description,
        status=AlertStatus.NEW,
        dedup_key=dedup_key if dedup_key is not None else log.source_ip,
        log_id=log.id,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert
