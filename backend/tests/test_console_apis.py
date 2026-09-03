"""
Integration tests for the endpoints the SOC console is built on: alert
querying and triage, log search, rule editing, SOAR history, and the
live WebSocket stream. Real API, real database, nothing mocked --
matching the approach of the detection test files.

Source addresses use 203.0.113.0/24 (TEST-NET-3, RFC 5737), distinct
from the ranges the detection test files use, because every test in the
suite shares one SQLite database.
"""
from datetime import datetime, timedelta, timezone

import pytest

from app.models.alert import AlertStatus
from app.models.log import Severity


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _raise_brute_force(client, token, ip: str, base: datetime, count: int = 6) -> None:
    for i in range(count):
        response = client.post(
            "/api/logs",
            json={
                "raw_log": f"Failed password for admin from {ip}",
                "timestamp": (base + timedelta(seconds=i)).isoformat(),
            },
            headers=_headers(token),
        )
        assert response.status_code == 201, response.text


# ===========================================================================
# Alerts
# ===========================================================================


def test_alert_list_filters_and_reports_total_before_paging(client, admin_token):
    ip = "203.0.113.10"
    base = datetime(2026, 2, 1, 10, 0, 0, tzinfo=timezone.utc)
    _raise_brute_force(client, admin_token, ip, base)

    response = client.get("/api/alerts", params={"source_ip": ip}, headers=_headers(admin_token))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 1
    assert len(body["items"]) == 1

    alert = body["items"][0]
    # The rule's name/type are denormalized onto the row so the table can
    # render without a request per alert.
    assert alert["rule_name"] == "Brute Force Authentication"
    assert alert["rule_type"] == "brute_force"
    assert alert["severity"] == Severity.HIGH.value
    assert alert["status"] == AlertStatus.NEW.value

    # A filter that cannot match returns an honest empty result, not
    # everything.
    empty = client.get(
        "/api/alerts",
        params={"source_ip": ip, "severity": Severity.LOW.value},
        headers=_headers(admin_token),
    ).json()
    assert empty["total"] == 0
    assert empty["items"] == []


def test_alert_detail_includes_triggering_log_and_supporting_evidence(client, admin_token):
    ip = "203.0.113.11"
    base = datetime(2026, 2, 1, 11, 0, 0, tzinfo=timezone.utc)
    _raise_brute_force(client, admin_token, ip, base)

    alert_id = client.get(
        "/api/alerts", params={"source_ip": ip}, headers=_headers(admin_token)
    ).json()["items"][0]["id"]

    detail = client.get(f"/api/alerts/{alert_id}", headers=_headers(admin_token)).json()

    # The rule's configured thresholds, so the analyst can see WHY this
    # fired without opening the Rules page.
    assert detail["rule_threshold"] == 5
    assert detail["rule_time_window_seconds"] == 120

    # The original log line, verbatim -- a false-positive judgement needs
    # the raw evidence, not only our parse of it.
    assert detail["triggering_log"] is not None
    assert ip in detail["triggering_log"]["raw_log"]

    # Five failures are pulled in as supporting evidence -- the ones up
    # to and including the event that tripped the rule. The sixth failure
    # arrived AFTER the alert was raised and is deliberately not shown as
    # evidence for it: the investigation view has to reflect what the
    # engine actually saw at decision time, not everything that happened
    # afterwards.
    assert len(detail["related_logs"]) == 5
    assert all(log["source_ip"] == ip for log in detail["related_logs"])
    assert all(
        log["timestamp"] <= detail["triggering_log"]["timestamp"]
        for log in detail["related_logs"]
    )


def test_alert_detail_404_for_unknown_id(client, admin_token):
    assert client.get("/api/alerts/999999", headers=_headers(admin_token)).status_code == 404


def test_alert_status_change_is_recorded_in_the_audit_trail(client, admin_token):
    ip = "203.0.113.12"
    base = datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc)
    _raise_brute_force(client, admin_token, ip, base)
    alert_id = client.get(
        "/api/alerts", params={"source_ip": ip}, headers=_headers(admin_token)
    ).json()["items"][0]["id"]

    response = client.patch(
        f"/api/alerts/{alert_id}/status",
        json={"status": AlertStatus.INVESTIGATING.value},
        headers=_headers(admin_token),
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == AlertStatus.INVESTIGATING.value

    client.patch(
        f"/api/alerts/{alert_id}/status",
        json={"status": AlertStatus.FALSE_POSITIVE.value},
        headers=_headers(admin_token),
    )

    history = client.get(f"/api/alerts/{alert_id}", headers=_headers(admin_token)).json()[
        "status_history"
    ]
    assert [(h["previous_status"], h["new_status"]) for h in history] == [
        (AlertStatus.NEW.value, AlertStatus.INVESTIGATING.value),
        (AlertStatus.INVESTIGATING.value, AlertStatus.FALSE_POSITIVE.value),
    ]
    # The verdict is attributable to whoever made it.
    assert all(entry["changed_by"] == "admin" for entry in history)


def test_setting_the_same_status_twice_adds_no_audit_noise(client, admin_token):
    ip = "203.0.113.13"
    base = datetime(2026, 2, 1, 13, 0, 0, tzinfo=timezone.utc)
    _raise_brute_force(client, admin_token, ip, base)
    alert_id = client.get(
        "/api/alerts", params={"source_ip": ip}, headers=_headers(admin_token)
    ).json()["items"][0]["id"]

    for _ in range(3):
        response = client.patch(
            f"/api/alerts/{alert_id}/status",
            json={"status": AlertStatus.RESOLVED.value},
            headers=_headers(admin_token),
        )
        assert response.status_code == 200

    history = client.get(f"/api/alerts/{alert_id}", headers=_headers(admin_token)).json()[
        "status_history"
    ]
    assert len(history) == 1


def test_alert_endpoints_require_authentication(client):
    assert client.get("/api/alerts").status_code == 401
    assert client.get("/api/alerts/1").status_code == 401
    assert client.patch("/api/alerts/1/status", json={"status": "resolved"}).status_code == 401


# ===========================================================================
# Logs
# ===========================================================================


def test_log_search_matches_raw_line_and_reports_true_total(client, admin_token):
    ip = "203.0.113.20"
    base = datetime(2026, 2, 2, 9, 0, 0, tzinfo=timezone.utc)
    for i in range(4):
        client.post(
            "/api/logs",
            json={
                "raw_log": f"Failed password for searchtarget from {ip}",
                "timestamp": (base + timedelta(seconds=i)).isoformat(),
            },
            headers=_headers(admin_token),
        )

    body = client.get(
        "/api/logs", params={"search": "searchtarget", "limit": 2}, headers=_headers(admin_token)
    ).json()
    # total counts every match; items honours the page size.
    assert body["total"] == 4
    assert len(body["items"]) == 2
    assert all("searchtarget" in item["raw_log"] for item in body["items"])
    # Newest first.
    timestamps = [item["timestamp"] for item in body["items"]]
    assert timestamps == sorted(timestamps, reverse=True)


def test_log_event_types_are_derived_from_stored_data(client, admin_token):
    client.post(
        "/api/logs",
        json={"raw_log": "Connection attempt from 203.0.113.21 to port 8080"},
        headers=_headers(admin_token),
    )
    types = client.get("/api/logs/event-types", headers=_headers(admin_token)).json()
    assert "port_access" in types
    assert "authentication_failure" in types


def test_log_detail_route_does_not_shadow_event_types_route(client, admin_token):
    """/api/logs/event-types must not be parsed as /api/logs/{log_id}.
    Declaration order in the router is what prevents that, and nothing
    else would catch it if the routes were ever reordered."""
    response = client.get("/api/logs/event-types", headers=_headers(admin_token))
    assert response.status_code == 200
    assert isinstance(response.json(), list)


# ===========================================================================
# Rules
# ===========================================================================


def test_rules_list_marks_every_seeded_rule_as_implemented(client, admin_token):
    rules = client.get("/api/rules", headers=_headers(admin_token)).json()
    assert len(rules) >= 5
    seeded = {rule["rule_type"] for rule in rules}
    assert {
        "brute_force",
        "port_scan",
        "login_after_failure",
        "file_integrity",
        "privilege_escalation",
    } <= seeded
    assert all(rule["implemented"] for rule in rules if rule["rule_type"] in seeded)


def test_editing_a_rule_threshold_changes_real_detection_behaviour(client, admin_token):
    """The point of storing thresholds in the database: a PATCH here must
    change what the engine does on the very next event, with no restart."""
    rules = client.get("/api/rules", headers=_headers(admin_token)).json()
    brute_force = next(r for r in rules if r["rule_type"] == "brute_force")
    original_threshold = brute_force["threshold"]

    response = client.patch(
        f"/api/rules/{brute_force['id']}",
        json={"threshold": 3},
        headers=_headers(admin_token),
    )
    assert response.status_code == 200, response.text
    assert response.json()["threshold"] == 3
    # A PATCH of one field must not reset the others.
    assert response.json()["time_window_seconds"] == brute_force["time_window_seconds"]

    try:
        ip = "203.0.113.30"
        base = datetime(2026, 2, 3, 10, 0, 0, tzinfo=timezone.utc)
        # Only 3 failures -- under the original threshold of 5, at the new one.
        _raise_brute_force(client, admin_token, ip, base, count=3)
        alerts = client.get(
            "/api/alerts", params={"source_ip": ip}, headers=_headers(admin_token)
        ).json()
        assert alerts["total"] == 1
    finally:
        client.patch(
            f"/api/rules/{brute_force['id']}",
            json={"threshold": original_threshold},
            headers=_headers(admin_token),
        )


def test_rule_threshold_of_zero_is_rejected(client, admin_token):
    rules = client.get("/api/rules", headers=_headers(admin_token)).json()
    response = client.patch(
        f"/api/rules/{rules[0]['id']}", json={"threshold": 0}, headers=_headers(admin_token)
    )
    assert response.status_code == 422


def test_rule_editing_requires_administrator(client, admin_token, db_session):
    """An analyst triages alerts; an administrator decides what the
    system alerts on (project RBAC matrix)."""
    from app.auth.security import hash_password
    from app.models.user import User, UserRole

    analyst = User(
        username="analyst-rules-test",
        password_hash=hash_password("AnalystPass123!"),
        role=UserRole.SECURITY_ANALYST,
    )
    db_session.add(analyst)
    db_session.commit()
    try:
        token = client.post(
            "/api/auth/login",
            json={"username": "analyst-rules-test", "password": "AnalystPass123!"},
        ).json()["access_token"]

        rules = client.get("/api/rules", headers=_headers(token)).json()
        assert rules  # reading is allowed

        forbidden = client.patch(
            f"/api/rules/{rules[0]['id']}", json={"enabled": False}, headers=_headers(token)
        )
        assert forbidden.status_code == 403
    finally:
        db_session.delete(analyst)
        db_session.commit()


# ===========================================================================
# SOAR
# ===========================================================================


def test_soar_records_a_containment_action_for_a_high_severity_alert(client, admin_token):
    ip = "203.0.113.40"
    base = datetime(2026, 2, 4, 10, 0, 0, tzinfo=timezone.utc)
    _raise_brute_force(client, admin_token, ip, base)

    body = client.get("/api/soar/actions", params={"target": ip}, headers=_headers(admin_token)).json()
    assert body["total"] == 1
    action = body["items"][0]
    assert action["action_type"] == "block_ip"
    assert action["target"] == ip
    assert action["rule_name"] == "Brute Force Authentication"


def test_soar_reports_record_only_and_never_claims_execution(client, admin_token):
    """The honesty check: with SOAR_EXECUTE unset, every action must be
    labelled simulated and the response must say so at the top level."""
    body = client.get("/api/soar/actions", headers=_headers(admin_token)).json()
    assert body["enabled"] is True
    assert body["execution_mode"] == "record_only"
    assert all(item["status"] == "simulated" for item in body["items"])
    assert all(item["execution_requested"] is False for item in body["items"])


# ===========================================================================
# Dashboard analytics
# ===========================================================================


def test_severity_distribution_includes_every_severity_even_at_zero(client, admin_token):
    body = client.get("/api/dashboard/severity-distribution", headers=_headers(admin_token)).json()
    assert set(body["counts"]) == {s.value for s in Severity}
    assert body["total"] == sum(body["counts"].values())


def test_timeline_emits_a_bucket_for_every_hour_including_empty_ones(client, admin_token):
    body = client.get(
        "/api/dashboard/timeline", params={"hours": 6}, headers=_headers(admin_token)
    ).json()
    assert body["hours"] == 6
    assert len(body["buckets"]) == 6
    hours = [bucket["hour"] for bucket in body["buckets"]]
    assert hours == sorted(hours)


def test_mitre_coverage_lists_every_rule_with_its_framework_mapping(client, admin_token):
    coverage = client.get("/api/dashboard/mitre-coverage", headers=_headers(admin_token)).json()
    by_type = {row["rule_type"]: row for row in coverage}
    assert by_type["brute_force"]["mitre_id"] == "T1110"
    assert by_type["port_scan"]["mitre_id"] == "T1046"
    # MITRE tactic and Kill Chain phase are different frameworks; the
    # stored phase must be a real Kill Chain phase, never "Credential
    # Access" (which is a MITRE tactic).
    assert by_type["brute_force"]["kill_chain_phase"] == "Actions on Objectives"
    assert all(row["kill_chain_phase"] != "Credential Access" for row in coverage)


# ===========================================================================
# Integrations
# ===========================================================================


def test_wazuh_status_is_not_configured_rather_than_pretending(client, admin_token):
    body = client.get("/api/integrations/wazuh/status", headers=_headers(admin_token)).json()
    assert body["status"] == "not_configured"
    assert body["agent_count"] is None
    assert "WAZUH_URL" in body["detail"]


def test_agents_overview_reports_which_sources_contributed(client, admin_token):
    body = client.get("/api/agents/overview", headers=_headers(admin_token)).json()
    assert body["sources"]["wazuh"] == 0
    assert body["wazuh_integration"]["status"] == "not_configured"
    assert body["total"] == len(body["items"])


# ===========================================================================
# Realtime stream
# ===========================================================================


def test_websocket_rejects_a_missing_token(client):
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/ws/stream") as websocket:
            websocket.receive_json()
    assert excinfo.value.code == 1008


def test_websocket_rejects_a_forged_token(client):
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/ws/stream?token=not-a-real-jwt") as websocket:
            websocket.receive_json()
    assert excinfo.value.code == 1008


def test_websocket_greets_an_authenticated_client(client, admin_token):
    with client.websocket_connect(f"/ws/stream?token={admin_token}") as websocket:
        hello = websocket.receive_json()
        assert hello["type"] == "hello"
        assert hello["data"]["username"] == "admin"
        assert hello["data"]["role"] == "administrator"
        assert "replay" in hello["data"]


def test_websocket_answers_a_ping(client, admin_token):
    with client.websocket_connect(f"/ws/stream?token={admin_token}") as websocket:
        websocket.receive_json()  # hello
        websocket.send_text("ping")
        assert websocket.receive_json()["type"] == "pong"
