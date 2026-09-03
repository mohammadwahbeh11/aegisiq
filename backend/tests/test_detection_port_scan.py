"""
Integration tests for the port-scan detection rule (Phase B2). Real API
(POST /api/logs), real detection engine, real SQLite database via the
`client`/`admin_token`/`db_session` fixtures -- nothing mocked, per
Step 13's requirement (matching B1's own test file).

All test IPs use 192.0.2.0/24 (TEST-NET-1, RFC 5737), the same range
used by test_detection_brute_force.py, but with distinct octets (.20
and up) so this file cannot collide with brute-force tests OR with each
other: port-scan tests only ever match on event_type == "port_access",
which brute-force tests never generate, so there's no cross-event-type
collision risk even on a shared subnet -- distinct octets are just
extra insurance for readability.
"""
from datetime import datetime, timedelta, timezone

from app.models.alert import Alert, AlertStatus
from app.models.log import Severity
from app.models.rule import DetectionRule


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _post_port_access(client, token, source_ip: str, port: int, when: datetime):
    payload = {
        "raw_log": f"Connection attempt from {source_ip} to port {port}",
        "timestamp": when.isoformat(),
    }
    return client.post("/api/logs", json=payload, headers=_auth_headers(token))


def _post_failed_login(client, token, source_ip: str, when: datetime):
    payload = {"raw_log": f"Failed password for admin from {source_ip}", "timestamp": when.isoformat()}
    return client.post("/api/logs", json=payload, headers=_auth_headers(token))


def _post_successful_login(client, token, source_ip: str, when: datetime):
    payload = {"raw_log": f"Accepted password for admin from {source_ip}", "timestamp": when.isoformat()}
    return client.post("/api/logs", json=payload, headers=_auth_headers(token))


# --- 1. Below threshold ---------------------------------------------------


def test_port_scan_below_threshold(client, admin_token, db_session):
    ip = "192.0.2.20"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    ports = [22, 23, 25, 53, 80, 110, 135, 139, 443]  # 9 distinct
    for i, port in enumerate(ports):
        r = _post_port_access(client, admin_token, ip, port, base + timedelta(seconds=i * 3))
        assert r.status_code == 201, r.text
        assert r.json()["alerts_generated"] == 0

    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 0


# --- 2. Exact threshold ----------------------------------------------------


def test_port_scan_exact_threshold(client, admin_token, db_session):
    ip = "192.0.2.21"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    ports = [22, 23, 25, 53, 80, 110, 135, 139, 443, 445]  # 10 distinct
    responses = [
        _post_port_access(client, admin_token, ip, port, base + timedelta(seconds=i * 3))
        for i, port in enumerate(ports)
    ]
    for r in responses:
        assert r.status_code == 201, r.text

    alerts_generated = [r.json()["alerts_generated"] for r in responses]
    assert alerts_generated == [0, 0, 0, 0, 0, 0, 0, 0, 0, 1], alerts_generated
    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 1


# --- 3. Above threshold: no alert storm ------------------------------------


def test_port_scan_above_threshold_does_not_create_a_duplicate_storm(client, admin_token, db_session):
    ip = "192.0.2.22"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    ports = [22, 23, 25, 53, 80, 110, 135, 139, 443, 445]
    for i, port in enumerate(ports):
        r = _post_port_access(client, admin_token, ip, port, base + timedelta(seconds=i * 3))
    assert r.json()["alerts_generated"] == 1

    for i, port in enumerate([446, 447, 448]):
        r = _post_port_access(client, admin_token, ip, port, base + timedelta(seconds=35 + i))
        assert r.status_code == 201, r.text
        assert r.json()["alerts_generated"] == 0

    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 1


# --- 4. Duplicate ports count once -----------------------------------------


def test_port_scan_duplicate_ports_count_once(client, admin_token, db_session):
    """22,22,22,23,25,53,80,110,135,139 -- 10 events, only 8 distinct ports."""
    ip = "192.0.2.23"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    ports = [22, 22, 22, 23, 25, 53, 80, 110, 135, 139]
    for i, port in enumerate(ports):
        r = _post_port_access(client, admin_token, ip, port, base + timedelta(seconds=i * 2))
        assert r.status_code == 201, r.text
        assert r.json()["alerts_generated"] == 0

    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 0


# --- 5. Different source IPs are never combined -----------------------------


def test_port_scan_different_source_ips_are_not_combined(client, admin_token, db_session):
    ip_a, ip_b = "192.0.2.24", "192.0.2.25"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    for i, port in enumerate([22, 23, 25, 53, 80]):
        r = _post_port_access(client, admin_token, ip_a, port, base + timedelta(seconds=i * 2))
        assert r.json()["alerts_generated"] == 0
    for i, port in enumerate([110, 135, 139, 443, 445]):
        r = _post_port_access(client, admin_token, ip_b, port, base + timedelta(seconds=i * 2))
        assert r.json()["alerts_generated"] == 0

    assert db_session.query(Alert).filter(Alert.source_ip.in_([ip_a, ip_b])).count() == 0


# --- 6. Outside the time window ---------------------------------------------


def test_port_scan_outside_time_window(client, admin_token, db_session):
    ip = "192.0.2.26"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    offsets = [0, 10, 20, 30, 40, 50, 65, 75, 85, 95]  # last 4 land >60s after the first
    ports = [22, 23, 25, 53, 80, 110, 135, 139, 443, 445]
    for s, port in zip(offsets, ports):
        r = _post_port_access(client, admin_token, ip, port, base + timedelta(seconds=s))
        assert r.status_code == 201, r.text
        assert r.json()["alerts_generated"] == 0

    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 0


# --- 7. Exact 60-second boundary (same inclusive convention as B1) ---------


def test_port_scan_exact_time_boundary(client, admin_token, db_session):
    """
    Mirrors test_detection_brute_force.py::test_brute_force_inclusive_window_boundary.
    10 events spanning exactly 60 seconds (0..60) -- the 10th event's
    window_start is exactly 60-60=0, i.e. exactly the 1st event's own
    timestamp. Under the project's inclusive convention
    (timestamp >= window_start), that 1st event counts and the rule
    fires on the 10th. An exclusive boundary would have excluded it,
    leaving only 9 -- one short -- and never fired.
    """
    ip = "192.0.2.27"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    offsets = [0, 6, 12, 18, 24, 30, 36, 42, 48, 60]
    ports = [22, 23, 25, 53, 80, 110, 135, 139, 443, 445]

    responses = [
        _post_port_access(client, admin_token, ip, port, base + timedelta(seconds=s))
        for s, port in zip(offsets, ports)
    ]
    for r in responses:
        assert r.status_code == 201, r.text

    alerts_generated = [r.json()["alerts_generated"] for r in responses]
    assert alerts_generated == [0, 0, 0, 0, 0, 0, 0, 0, 0, 1], (
        f"expected the 10th event (exactly at the 60s boundary from the 1st) to trigger; got {alerts_generated}"
    )
    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 1


# --- 8. Missing destination_port --------------------------------------------


def test_port_scan_missing_destination_port(client, admin_token, db_session):
    """A generic event with event_type=port_access but no destination_port
    must not contribute to (or crash) port-scan detection."""
    ip = "192.0.2.28"
    response = client.post(
        "/api/logs",
        json={"event_type": "port_access", "source_ip": ip},
        headers=_auth_headers(admin_token),
    )
    assert response.status_code == 201, response.text
    assert response.json()["alerts_generated"] == 0
    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 0


# --- 9. Invalid destination_port --------------------------------------------


def test_port_scan_invalid_destination_port_rejected_at_ingestion(client, admin_token):
    """The ingestion schema itself rejects an out-of-range port (Phase A
    validation) -- this proves invalid port data can't even reach the
    database in the first place."""
    response = client.post(
        "/api/logs",
        json={"event_type": "port_access", "source_ip": "192.0.2.29", "destination_port": 99999},
        headers=_auth_headers(admin_token),
    )
    assert response.status_code == 422


def test_port_scan_detector_defensive_against_out_of_range_port(db_session):
    """Belt-and-suspenders (Step 9: "the detector itself should remain
    defensive"): even if an out-of-range port somehow reached the
    detector directly, evaluate() must not crash and must not count it.
    Exercises app/detection/rules/port_scan.py's own guard clause
    directly, independent of the ingestion schema's validation."""
    from datetime import timezone as tz

    from app.detection.rules import port_scan
    from app.models.log import Log

    rule = db_session.query(DetectionRule).filter(DetectionRule.rule_type == "port_scan").first()
    assert rule is not None

    bad_log = Log(
        timestamp=datetime(2026, 1, 1, 10, 0, 0, tzinfo=tz.utc),
        source_ip="192.0.2.30",
        event_type="port_access",
        destination_port=-1,  # invalid, out of range
        severity=Severity.LOW,
        raw_log="synthetic test row",
        source="generic",
    )
    result = port_scan.evaluate(bad_log, rule, db_session)
    assert result is None


# --- 10. Disabled rule -------------------------------------------------------


def test_disabled_port_scan_rule_does_not_trigger(client, admin_token, db_session):
    rule = db_session.query(DetectionRule).filter(DetectionRule.rule_type == "port_scan").first()
    assert rule is not None
    rule.enabled = False
    db_session.commit()

    ip = "192.0.2.31"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    ports = [22, 23, 25, 53, 80, 110, 135, 139, 443, 445]
    for i, port in enumerate(ports):
        r = _post_port_access(client, admin_token, ip, port, base + timedelta(seconds=i * 2))
        assert r.status_code == 201, r.text
        assert r.json()["alerts_generated"] == 0

    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 0

    rule.enabled = True
    db_session.commit()


# --- 11-14. Alert content: severity, MITRE technique/tactic, kill chain ----


def test_port_scan_alert_severity_mitre_and_kill_chain_mapping(client, admin_token, db_session):
    from app.detection.rules.port_scan import MITRE_TACTIC

    ip = "192.0.2.32"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    ports = [22, 23, 25, 53, 80, 110, 135, 139, 443, 445]
    for i, port in enumerate(ports):
        _post_port_access(client, admin_token, ip, port, base + timedelta(seconds=i * 2))

    alert = db_session.query(Alert).filter(Alert.source_ip == ip).first()
    assert alert is not None

    assert alert.severity == Severity.HIGH
    assert alert.mitre_id == "T1046"
    assert MITRE_TACTIC == "Discovery"
    assert alert.kill_chain_phase == "Reconnaissance"
    assert alert.kill_chain_phase != MITRE_TACTIC
    assert alert.status == AlertStatus.NEW


# --- 15. Description is dynamic ---------------------------------------------


def test_port_scan_alert_description_contains_source_ip(client, admin_token, db_session):
    ip = "192.0.2.33"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    ports = [22, 23, 25, 53, 80, 110, 135, 139, 443, 445]
    for i, port in enumerate(ports):
        _post_port_access(client, admin_token, ip, port, base + timedelta(seconds=i * 2))

    alert = db_session.query(Alert).filter(Alert.source_ip == ip).first()
    assert ip in alert.description
    assert "10" in alert.description
    assert "60" in alert.description


# --- 16. Deduplication -------------------------------------------------------


def test_port_scan_alert_deduplication(client, admin_token, db_session):
    ip = "192.0.2.34"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    ports = [22, 23, 25, 53, 80, 110, 135, 139, 443, 445]
    for i, port in enumerate(ports):
        r = _post_port_access(client, admin_token, ip, port, base + timedelta(seconds=i * 2))
    assert r.json()["alerts_generated"] == 1

    for i, port in enumerate([446, 447, 448]):
        r = _post_port_access(client, admin_token, ip, port, base + timedelta(seconds=25 + i))
        assert r.json()["alerts_generated"] == 0

    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 1


def test_new_port_scan_alert_fires_after_previous_one_resolved_and_window_elapsed(client, admin_token, db_session):
    ip = "192.0.2.35"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    ports = [22, 23, 25, 53, 80, 110, 135, 139, 443, 445]
    for i, port in enumerate(ports):
        r = _post_port_access(client, admin_token, ip, port, base + timedelta(seconds=i * 2))
    assert r.json()["alerts_generated"] == 1

    first_alert = db_session.query(Alert).filter(Alert.source_ip == ip).one()
    first_alert.status = AlertStatus.RESOLVED
    db_session.commit()

    second_wave_start = base + timedelta(seconds=500)  # well past the 60s window
    second_ports = [8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009]
    for i, port in enumerate(second_ports):
        r = _post_port_access(client, admin_token, ip, port, second_wave_start + timedelta(seconds=i * 2))

    assert r.json()["alerts_generated"] == 1
    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 2


# --- 17. Detected regardless of how the port_access events were produced ---


def test_generic_json_port_scan_detection(client, admin_token, db_session):
    """Uses the normalized event format directly (already-normalized
    generic JSON, per Phase A.6), rather than relying on raw_log
    parsing -- proving detection works on the normalized event_type
    itself, not on any particular log source's text format."""
    ip = "192.0.2.36"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    ports = [22, 23, 25, 53, 80, 110, 135, 139, 443, 445]
    responses = []
    for i, port in enumerate(ports):
        r = client.post(
            "/api/logs",
            json={
                "event_type": "port_access",
                "source_ip": ip,
                "destination_port": port,
                "timestamp": (base + timedelta(seconds=i * 2)).isoformat(),
            },
            headers=_auth_headers(admin_token),
        )
        assert r.status_code == 201, r.text
        responses.append(r)

    assert [r.json()["alerts_generated"] for r in responses] == [0] * 9 + [1]


# --- 18. B1 brute-force regression check ------------------------------------


def test_phase_b1_bruteforce_still_works_after_port_scan_changes(client, admin_token, db_session):
    """Confirms the alerting.py extraction (shared by both rules as of
    B2) didn't change brute-force's behavior."""
    ip = "192.0.2.37"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    responses = [_post_failed_login(client, admin_token, ip, base + timedelta(seconds=i * 10)) for i in range(5)]
    for r in responses:
        assert r.status_code == 201, r.text
    assert [r.json()["alerts_generated"] for r in responses] == [0, 0, 0, 0, 1]

    alert = db_session.query(Alert).filter(Alert.source_ip == ip).first()
    assert alert is not None
    assert alert.mitre_id == "T1110"
    assert alert.kill_chain_phase == "Actions on Objectives"


# --- Benign events: successful logins and unrelated event types ------------


def test_successful_logins_never_trigger_port_scan(client, admin_token, db_session):
    ip = "192.0.2.38"
    base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(12):
        r = _post_successful_login(client, admin_token, ip, base + timedelta(seconds=i * 2))
        assert r.status_code == 201, r.text
        assert r.json()["alerts_generated"] == 0

    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 0
