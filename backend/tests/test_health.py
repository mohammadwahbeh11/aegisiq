"""
/health must report what is actually true of the running build, not a
string somebody remembered to update. These tests assert that the
reported status is DERIVED -- the detection status is computed from the
rule registry versus the enabled rule rows, so disabling every handler
would flip it without anyone editing the endpoint.
"""
from app.detection.engine import implemented_rule_types


def test_health_check_reports_ok_api_and_database(client):
    response = client.get("/health")
    assert response.status_code == 200

    body = response.json()
    assert body["api"] == "ok"
    assert body["database"] == "ok"
    # collector has been real since Phase A (POST /api/logs)
    assert body["collector"] == "ok"
    # All five rules from the project document are implemented, so no
    # enabled rule is left without a handler.
    assert body["detection_engine"] == "ok"
    assert body["detection_rules_enabled_without_handler"] == []
    assert set(body["detection_rules_implemented"]) == implemented_rule_types()
    # The live stream exists (app/api/routes/stream.py); no client is
    # connected during a plain REST test, hence zero subscribers.
    assert body["websocket"] == "ok"
    assert body["websocket_subscribers"] == 0


def test_health_reports_soar_as_record_only_not_as_executing(client):
    """The SOAR layer records containment decisions and does not execute
    them. /health says so explicitly, because "SOAR: ok" would read as a
    claim that hosts are being acted on."""
    body = client.get("/health").json()
    assert body["soar"] == "record_only"


def test_health_reports_wazuh_as_not_configured_by_default(client):
    """No WAZUH_URL in the test environment, so the honest answer is
    "not_configured" -- never a decorative "connected"."""
    body = client.get("/health").json()
    assert body["wazuh"] == "not_configured"


def test_health_detection_status_is_derived_not_hardcoded(client, db_session):
    """Adding an enabled rule row whose type this build cannot execute
    must flip the reported status to "partial" and name the offender."""
    from app.models.log import Severity
    from app.models.rule import DetectionRule

    unsupported = DetectionRule(
        name="Beaconing Detection (not implemented in this build)",
        description="Placeholder rule type with no handler registered.",
        rule_type="c2_beaconing",
        threshold=3,
        time_window_seconds=300,
        severity=Severity.HIGH,
        enabled=True,
    )
    db_session.add(unsupported)
    db_session.commit()
    try:
        body = client.get("/health").json()
        assert body["detection_engine"] == "partial"
        assert body["detection_rules_enabled_without_handler"] == ["c2_beaconing"]
    finally:
        db_session.delete(unsupported)
        db_session.commit()
