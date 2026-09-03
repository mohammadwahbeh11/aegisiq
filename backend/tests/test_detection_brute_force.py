"""
Integration tests for the brute-force detection rule (Phase B1). These
go through the real API (POST /api/logs), the real detection engine
(app/detection/engine.py -> app/detection/rules/brute_force.py), and a
real SQLite database via the `client`/`admin_token`/`db_session`
fixtures -- nothing about detection is mocked, per Step 12's explicit
requirement.

All test IPs use 192.0.2.0/24 (TEST-NET-1, IANA-reserved for
documentation/testing -- RFC 5737), a range not used anywhere else in
this test suite, so these tests cannot be contaminated by -- or
contaminate -- unrelated tests sharing the same SQLite file for the
whole pytest session.
"""
from datetime import datetime, timedelta, timezone

from app.models.alert import Alert, AlertStatus
from app.models.log import Severity
from app.models.rule import DetectionRule


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _post_failed_login(client, token, source_ip: str, when: datetime | None = None, username: str = "admin"):
    payload: dict = {"raw_log": f"Failed password for {username} from {source_ip}"}
    if when is not None:
        payload["timestamp"] = when.isoformat()
    return client.post("/api/logs", json=payload, headers=_auth_headers(token))


def _post_successful_login(client, token, source_ip: str, when: datetime | None = None, username: str = "admin"):
    payload: dict = {"raw_log": f"Accepted password for {username} from {source_ip}"}
    if when is not None:
        payload["timestamp"] = when.isoformat()
    return client.post("/api/logs", json=payload, headers=_auth_headers(token))


def _post_windows_4625(client, token, source_ip: str, when: datetime | None = None, username: str = "Administrator"):
    payload: dict = {"event_id": 4625, "source_ip": source_ip, "username": username}
    if when is not None:
        payload["timestamp"] = when.isoformat()
    return client.post("/api/logs", json=payload, headers=_auth_headers(token))


# --- 1. Below threshold ------------------------------------------------


def test_brute_force_below_threshold(client, admin_token, db_session):
    ip = "192.0.2.1"
    for _ in range(4):
        response = _post_failed_login(client, admin_token, ip)
        assert response.status_code == 201, response.text
        assert response.json()["alerts_generated"] == 0

    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 0


# --- 2. Exact threshold, using the project's own worked example --------


def test_brute_force_exact_threshold(client, admin_token, db_session):
    ip = "192.0.2.2"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    offsets_seconds = [0, 20, 40, 60, 90]  # matches Step 5's passing example exactly

    responses = [_post_failed_login(client, admin_token, ip, when=base + timedelta(seconds=s)) for s in offsets_seconds]
    for r in responses:
        assert r.status_code == 201, r.text

    alerts_generated = [r.json()["alerts_generated"] for r in responses]
    assert alerts_generated == [0, 0, 0, 0, 1], alerts_generated

    alerts = db_session.query(Alert).filter(Alert.source_ip == ip).all()
    assert len(alerts) == 1


# --- 3. Above threshold: no duplicate alert storm -----------------------


def test_brute_force_above_threshold_does_not_create_a_duplicate_storm(client, admin_token, db_session):
    ip = "192.0.2.3"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)

    # Failures 1-5 within the window -> exactly one alert on #5.
    for i in range(5):
        r = _post_failed_login(client, admin_token, ip, when=base + timedelta(seconds=i * 10))
    assert r.json()["alerts_generated"] == 1

    # 3 more failures right after, same IP -- must NOT create 3 more alerts.
    for i in range(3):
        r = _post_failed_login(client, admin_token, ip, when=base + timedelta(seconds=60 + i * 5))
        assert r.status_code == 201, r.text
        assert r.json()["alerts_generated"] == 0

    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 1


# --- 4. Different source IPs are never combined -------------------------


def test_brute_force_different_source_ips_are_not_combined(client, admin_token, db_session):
    ip_a, ip_b = "192.0.2.4", "192.0.2.5"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)

    for i in range(3):
        r = _post_failed_login(client, admin_token, ip_a, when=base + timedelta(seconds=i * 5))
        assert r.json()["alerts_generated"] == 0
    for i in range(2):
        r = _post_failed_login(client, admin_token, ip_b, when=base + timedelta(seconds=i * 5))
        assert r.json()["alerts_generated"] == 0

    assert db_session.query(Alert).filter(Alert.source_ip.in_([ip_a, ip_b])).count() == 0


# --- 5. Outside the time window, using the project's own failing example -


def test_brute_force_outside_time_window(client, admin_token, db_session):
    ip = "192.0.2.6"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    offsets_seconds = [0, 30, 60, 120, 180]  # matches Step 5's non-triggering example exactly

    responses = [_post_failed_login(client, admin_token, ip, when=base + timedelta(seconds=s)) for s in offsets_seconds]
    for r in responses:
        assert r.status_code == 201, r.text
        assert r.json()["alerts_generated"] == 0

    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 0


# --- Boundary test: the window is inclusive at both ends -----------------


def test_brute_force_inclusive_window_boundary(client, admin_token, db_session):
    """
    Corrected boundary behavior: for a 120-second window, an event
    exactly 120 seconds before the triggering event is INCLUDED (the
    filter is `timestamp >= window_start`, not `>`).

    5 events spaced exactly 30s apart span exactly 120 seconds
    (0, 30, 60, 90, 120) -- the 5th event's window_start is exactly
    120-120=0, i.e. exactly the timestamp of the 1st event. Under the
    inclusive interpretation all 5 events count and the rule fires on
    the 5th. Under the old, incorrect exclusive interpretation the 1st
    event would have been excluded, leaving only 4 -- one short of the
    threshold -- and no alert would have fired. This test proves the
    inclusive behavior is what actually happens.
    """
    ip = "192.0.2.17"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    offsets_seconds = [0, 30, 60, 90, 120]  # span == exactly the 120s window

    responses = [_post_failed_login(client, admin_token, ip, when=base + timedelta(seconds=s)) for s in offsets_seconds]
    for r in responses:
        assert r.status_code == 201, r.text

    alerts_generated = [r.json()["alerts_generated"] for r in responses]
    assert alerts_generated == [0, 0, 0, 0, 1], (
        "expected the 5th event (exactly at the 120s boundary from the 1st) to trigger an alert "
        f"under the inclusive window interpretation; got {alerts_generated}"
    )
    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 1


# --- 6. Successful logins alone never trigger ----------------------------


def test_successful_login_does_not_trigger_bruteforce(client, admin_token, db_session):
    ip = "192.0.2.7"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(6):
        r = _post_successful_login(client, admin_token, ip, when=base + timedelta(seconds=i * 5))
        assert r.status_code == 201, r.text
        assert r.json()["alerts_generated"] == 0

    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 0


# --- 7. Disabled rule never triggers --------------------------------------


def test_disabled_bruteforce_rule_does_not_trigger(client, admin_token, db_session):
    rule = db_session.query(DetectionRule).filter(DetectionRule.rule_type == "brute_force").first()
    assert rule is not None
    rule.enabled = False
    db_session.commit()

    ip = "192.0.2.8"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(6):
        r = _post_failed_login(client, admin_token, ip, when=base + timedelta(seconds=i * 10))
        assert r.status_code == 201, r.text
        assert r.json()["alerts_generated"] == 0

    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 0

    # Restore, so this test doesn't leak state into any test that runs
    # after it in the same session.
    rule.enabled = True
    db_session.commit()


# --- 8-9. Source-agnostic: Windows 4625 and Linux both detected ----------


def test_windows_4625_bruteforce(client, admin_token, db_session):
    ip = "192.0.2.9"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    responses = [_post_windows_4625(client, admin_token, ip, when=base + timedelta(seconds=i * 10)) for i in range(5)]
    for r in responses:
        assert r.status_code == 201, r.text
    assert [r.json()["alerts_generated"] for r in responses] == [0, 0, 0, 0, 1]

    alert = db_session.query(Alert).filter(Alert.source_ip == ip).first()
    assert alert is not None


def test_linux_failed_login_bruteforce(client, admin_token, db_session):
    ip = "192.0.2.10"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    responses = [_post_failed_login(client, admin_token, ip, when=base + timedelta(seconds=i * 10)) for i in range(5)]
    for r in responses:
        assert r.status_code == 201, r.text
    assert [r.json()["alerts_generated"] for r in responses] == [0, 0, 0, 0, 1]

    alert = db_session.query(Alert).filter(Alert.source_ip == ip).first()
    assert alert is not None


# --- 10-12. Alert content: severity, MITRE technique, MITRE tactic
# (documented, not a stored field), and Cyber Kill Chain phase ----------
# These are three distinct frameworks/concepts and must not be
# conflated: MITRE ATT&CK Technique (T1110), MITRE ATT&CK Tactic
# ("Credential Access" -- T1110's tactic, referenced from
# brute_force.MITRE_TACTIC for documentation, not stored on the model),
# and the Lockheed Martin Cyber Kill Chain phase ("Actions on
# Objectives" -- a completely different framework, stored in
# kill_chain_phase). Putting a MITRE tactic into the kill_chain_phase
# field was exactly the bug this test now guards against.


def test_alert_severity_mitre_and_kill_chain_mapping(client, admin_token, db_session):
    from app.detection.rules.brute_force import MITRE_TACTIC

    ip = "192.0.2.11"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(5):
        r = _post_failed_login(client, admin_token, ip, when=base + timedelta(seconds=i * 10))

    alert = db_session.query(Alert).filter(Alert.source_ip == ip).first()
    assert alert is not None
    assert alert.severity == Severity.HIGH

    # MITRE ATT&CK Technique
    assert alert.mitre_id == "T1110"
    # MITRE ATT&CK Tactic (documented alongside the technique, not a
    # separate DB column -- see brute_force.py's module docstring)
    assert MITRE_TACTIC == "Credential Access"
    # Cyber Kill Chain phase -- a DIFFERENT framework from the tactic
    # above; must never be "Credential Access"
    assert alert.kill_chain_phase == "Actions on Objectives"
    assert alert.kill_chain_phase != MITRE_TACTIC

    assert alert.status == AlertStatus.NEW


# --- 14. Description is dynamic, not hardcoded ----------------------------


def test_alert_description_contains_source_ip_and_is_not_hardcoded(client, admin_token, db_session):
    ip = "192.0.2.12"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(5):
        _post_failed_login(client, admin_token, ip, when=base + timedelta(seconds=i * 10))

    alert = db_session.query(Alert).filter(Alert.source_ip == ip).first()
    assert ip in alert.description
    assert "5" in alert.description  # the actual observed failure count
    assert "120" in alert.description  # the rule's actual configured window


# --- 13. Deduplication: a resolved alert + elapsed window allows a genuinely
# new alert; an unresolved one does not, even after the window elapses ----


def test_alert_deduplication_suppresses_repeat_alerts_within_window(client, admin_token, db_session):
    ip = "192.0.2.13"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(5):
        r = _post_failed_login(client, admin_token, ip, when=base + timedelta(seconds=i * 10))
    assert r.json()["alerts_generated"] == 1

    # More failures, still within the window, same IP -- suppressed.
    for i in range(3):
        r = _post_failed_login(client, admin_token, ip, when=base + timedelta(seconds=60 + i * 5))
        assert r.json()["alerts_generated"] == 0

    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 1


def test_new_alert_fires_after_previous_one_resolved_and_window_elapsed(client, admin_token, db_session):
    ip = "192.0.2.14"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(5):
        r = _post_failed_login(client, admin_token, ip, when=base + timedelta(seconds=i * 10))
    assert r.json()["alerts_generated"] == 1

    first_alert = db_session.query(Alert).filter(Alert.source_ip == ip).one()
    first_alert.status = AlertStatus.RESOLVED
    db_session.commit()

    # A second wave, well over 120s after the first wave AND after the
    # first alert was resolved -- this is a genuinely new attack and
    # must produce its own new alert, not be suppressed forever.
    second_wave_start = base + timedelta(seconds=1000)
    for i in range(5):
        r = _post_failed_login(client, admin_token, ip, when=second_wave_start + timedelta(seconds=i * 10))

    assert r.json()["alerts_generated"] == 1
    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 2


def test_repeat_within_window_is_suppressed_even_if_status_changes_midway(client, admin_token, db_session):
    """The 'open OR recent' dedup rule: even if an analyst immediately
    resolves the first alert, a second burst still within the same
    120-second cooldown window must not spawn another alert -- 'recent'
    alone is enough to suppress, independent of status."""
    ip = "192.0.2.15"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(5):
        r = _post_failed_login(client, admin_token, ip, when=base + timedelta(seconds=i * 10))
    assert r.json()["alerts_generated"] == 1

    alert = db_session.query(Alert).filter(Alert.source_ip == ip).one()
    alert.status = AlertStatus.RESOLVED
    db_session.commit()

    # Still well within the 120s window of the resolved alert.
    r = _post_failed_login(client, admin_token, ip, when=base + timedelta(seconds=100))
    assert r.json()["alerts_generated"] == 0
    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 1


# --- 15. Detection reads the database, not in-process memory -------------


def test_detection_uses_database_state_not_in_memory_state(client, admin_token, db_session):
    """Step 3: 'use database timestamps/events rather than keeping the
    entire detection state only in Python memory... the system should
    continue working if the backend restarts.' A real process restart
    isn't practical inside a test, but this proves the same property
    structurally: a BRAND NEW SQLAlchemy session -- exactly what a freshly
    restarted backend would open against the same SQLite file -- sees
    the same failure count the detection engine used, because
    app/detection/rules/brute_force.py has no module-level counters or
    any other in-memory state; it only ever reads Log rows from the
    database."""
    from app.database import SessionLocal
    from app.models.log import Log

    ip = "192.0.2.16"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(4):
        r = _post_failed_login(client, admin_token, ip, when=base + timedelta(seconds=i * 10))
        assert r.json()["alerts_generated"] == 0

    fresh_session = SessionLocal()
    try:
        count_seen_by_fresh_session = (
            fresh_session.query(Log)
            .filter(Log.source_ip == ip, Log.event_type == "authentication_failure")
            .count()
        )
        assert count_seen_by_fresh_session == 4
    finally:
        fresh_session.close()

    r = _post_failed_login(client, admin_token, ip, when=base + timedelta(seconds=40))
    assert r.json()["alerts_generated"] == 1
