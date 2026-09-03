"""
Integration tests for POST /api/logs -- these exercise the real FastAPI
app, real auth, and a real (temp file) SQLite database via the existing
`client`/`admin_token` fixtures in tests/conftest.py, per Phase A.10's
requirement that tests "exercise the real API and database behavior",
not just call the normalizer function directly (see
test_normalization.py for that lower-level coverage).
"""


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# --- 1. Accepts a valid generic (already-normalized) log ------------------


def test_ingest_generic_already_normalized_log(client, admin_token):
    response = client.post(
        "/api/logs",
        json={
            "source_ip": "198.51.100.7",
            "username": "svc-backup",
            "event_type": "authentication_failure",
            "severity": "medium",
            "hostname": "web-01",
        },
        headers=_auth_headers(admin_token),
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "accepted"
    assert body["normalized"] is True
    assert body["event_type"] == "authentication_failure"
    assert isinstance(body["id"], int)


# --- 2. Rejects invalid input ----------------------------------------------


def test_ingest_log_with_nothing_to_normalize_is_rejected(client, admin_token):
    """No raw_log, no event_type, no event_id -- nothing for the
    normalizer to work with."""
    response = client.post("/api/logs", json={"hostname": "web-01"}, headers=_auth_headers(admin_token))
    assert response.status_code == 422


def test_ingest_log_with_invalid_ip_is_rejected(client, admin_token):
    response = client.post(
        "/api/logs",
        json={"event_type": "authentication_failure", "source_ip": "not-an-ip"},
        headers=_auth_headers(admin_token),
    )
    assert response.status_code == 422


def test_ingest_log_with_invalid_port_is_rejected(client, admin_token):
    response = client.post(
        "/api/logs",
        json={"event_type": "port_access", "destination_port": 99999},
        headers=_auth_headers(admin_token),
    )
    assert response.status_code == 422


def test_ingest_log_with_invalid_severity_is_rejected(client, admin_token):
    response = client.post(
        "/api/logs",
        json={"event_type": "authentication_failure", "severity": "apocalyptic"},
        headers=_auth_headers(admin_token),
    )
    assert response.status_code == 422


def test_ingest_log_with_invalid_timestamp_is_rejected(client, admin_token):
    response = client.post(
        "/api/logs",
        json={"event_type": "authentication_failure", "timestamp": "not-a-real-timestamp"},
        headers=_auth_headers(admin_token),
    )
    assert response.status_code == 422


def test_ingest_log_with_malformed_field_type_is_rejected(client, admin_token):
    """destination_port must be an integer -- a non-numeric string is a
    malformed payload, not just an out-of-range value."""
    response = client.post(
        "/api/logs",
        json={"event_type": "port_access", "destination_port": "not-a-port"},
        headers=_auth_headers(admin_token),
    )
    assert response.status_code == 422


# --- 3-8. Linux and Windows normalization, exercised through the real API --


def test_ingest_linux_failed_login(client, admin_token):
    response = client.post(
        "/api/logs",
        json={"raw_log": "Failed password for admin from 192.168.1.50"},
        headers=_auth_headers(admin_token),
    )
    assert response.status_code == 201, response.text
    assert response.json()["event_type"] == "authentication_failure"


def test_ingest_linux_successful_login(client, admin_token):
    response = client.post(
        "/api/logs",
        json={"raw_log": "Accepted password for admin from 192.168.1.50"},
        headers=_auth_headers(admin_token),
    )
    assert response.status_code == 201, response.text
    assert response.json()["event_type"] == "authentication_success"


def test_ingest_linux_sudo_privileged_event(client, admin_token):
    response = client.post(
        "/api/logs",
        json={"raw_log": "sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash"},
        headers=_auth_headers(admin_token),
    )
    assert response.status_code == 201, response.text
    assert response.json()["event_type"] == "privilege_related"


def test_ingest_linux_pam_style_authentication_failure(client, admin_token):
    response = client.post(
        "/api/logs",
        json={
            "raw_log": (
                "authentication failure; logname= uid=0 euid=0 tty=ssh "
                "ruser= rhost=203.0.113.9 user=root"
            )
        },
        headers=_auth_headers(admin_token),
    )
    assert response.status_code == 201, response.text
    assert response.json()["event_type"] == "authentication_failure"


def test_ingest_linux_file_integrity_change(client, admin_token):
    response = client.post(
        "/api/logs",
        json={"raw_log": "File integrity violation: /etc/shadow modified by root"},
        headers=_auth_headers(admin_token),
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["event_type"] == "file_integrity_change"
    # Task 3/9: critical-looking event, still no alert in Phase A.
    assert body["alerts_generated"] == 0


def test_ingest_windows_4625_failed_authentication(client, admin_token):
    response = client.post(
        "/api/logs",
        json={"event_id": 4625, "hostname": "WIN-PC01", "source_ip": "10.0.0.5", "username": "Administrator"},
        headers=_auth_headers(admin_token),
    )
    assert response.status_code == 201, response.text
    assert response.json()["event_type"] == "authentication_failure"


def test_ingest_windows_4624_successful_authentication(client, admin_token):
    response = client.post(
        "/api/logs",
        json={"event_id": 4624, "username": "Administrator"},
        headers=_auth_headers(admin_token),
    )
    assert response.status_code == 201, response.text
    assert response.json()["event_type"] == "authentication_success"


def test_ingest_windows_4672_privileged_logon(client, admin_token):
    response = client.post(
        "/api/logs",
        json={"event_id": 4672, "username": "Administrator"},
        headers=_auth_headers(admin_token),
    )
    assert response.status_code == 201, response.text
    assert response.json()["event_type"] == "privilege_related"


# --- 9. Generic already-normalized event is not re-derived ----------------


def test_generic_already_normalized_event_type_is_trusted(client, admin_token):
    response = client.post(
        "/api/logs",
        json={
            "event_type": "authentication_failure",
            "source_ip": "10.0.0.10",
            "username": "admin",
            "raw_log": "Accepted password for admin from 192.168.1.50",  # would parse as SUCCESS if used
        },
        headers=_auth_headers(admin_token),
    )
    assert response.status_code == 201, response.text
    assert response.json()["event_type"] == "authentication_failure"


# --- 10-11. Raw log preserved, normalized fields actually stored in DB ----
# Task 2 (verification pass): these query the SQLAlchemy Log table
# directly via db_session, rather than only checking the API response or
# an aggregate dashboard count, to prove the actual database record is
# correct -- not just that the API claimed success.


def test_ingested_log_is_correctly_persisted_in_the_database(client, admin_token, db_session):
    from app.models.log import Log, Severity

    payload = {
        "timestamp": "2026-08-18T18:00:00+00:00",
        "hostname": "ubuntu-server",
        "source_ip": "192.168.1.50",
        "destination_ip": "10.0.0.1",
        "source_port": 51742,
        "destination_port": 22,
        "username": "admin",
        "event_type": "authentication_failure",
        "severity": "medium",
        "source": "linux_auth",
        "operating_system": "linux",
        "raw_log": "Failed password for admin from 192.168.1.50",
        "metadata": {"custom_field": "custom_value"},
    }
    response = client.post("/api/logs", json=payload, headers=_auth_headers(admin_token))
    assert response.status_code == 201, response.text
    log_id = response.json()["id"]

    log = db_session.query(Log).filter(Log.id == log_id).first()
    assert log is not None, "ingested log was not found in the database"

    assert log.raw_log == payload["raw_log"]
    # Compared field-by-field rather than with strict datetime equality,
    # to avoid false failures from SQLite's naive-vs-aware storage
    # behavior -- the values that matter are what actually persisted.
    assert (log.timestamp.year, log.timestamp.month, log.timestamp.day, log.timestamp.hour, log.timestamp.minute) == (
        2026,
        8,
        18,
        18,
        0,
    )
    assert log.hostname == "ubuntu-server"
    assert log.source_ip == "192.168.1.50"
    assert log.destination_ip == "10.0.0.1"
    assert log.source_port == 51742
    assert log.destination_port == 22
    assert log.username == "admin"
    assert log.event_type == "authentication_failure"
    assert log.severity == Severity.MEDIUM
    assert log.source == "linux_auth"
    assert log.operating_system == "linux"
    assert log.agent_id is None  # not supplied in this request
    assert log.event_id is None  # not applicable -- no Windows Event ID supplied
    assert log.normalized_data == {"custom_field": "custom_value"}


def test_agent_id_is_persisted_as_the_correct_foreign_key(client, admin_token, db_session):
    from app.models.agent import Agent
    from app.models.log import Log

    agent_response = client.post(
        "/api/agents",
        json={"hostname": "ubuntu-server-02", "operating_system": "Ubuntu 22.04", "ip_address": "192.168.1.11"},
        headers=_auth_headers(admin_token),
    )
    assert agent_response.status_code == 201, agent_response.text
    external_agent_id = agent_response.json()["agent_id"]

    log_response = client.post(
        "/api/logs",
        json={"raw_log": "Accepted password for admin from 192.168.1.50", "agent_id": external_agent_id},
        headers=_auth_headers(admin_token),
    )
    assert log_response.status_code == 201, log_response.text
    log_id = log_response.json()["id"]

    log = db_session.query(Log).filter(Log.id == log_id).first()
    assert log is not None
    assert log.agent_id is not None

    linked_agent = db_session.query(Agent).filter(Agent.id == log.agent_id).first()
    assert linked_agent is not None
    assert linked_agent.agent_id == external_agent_id
    assert linked_agent.hostname == "ubuntu-server-02"


def test_windows_event_id_and_raw_payload_are_persisted(client, admin_token, db_session):
    import json

    from app.models.log import Log

    windows_payload = {
        "event_id": 4625,
        "hostname": "WIN-PC01",
        "source_ip": "10.0.0.5",
        "username": "Administrator",
        "raw_log": json.dumps({"EventID": 4625, "IpAddress": "10.0.0.5", "TargetUserName": "Administrator"}),
    }
    response = client.post("/api/logs", json=windows_payload, headers=_auth_headers(admin_token))
    assert response.status_code == 201, response.text
    log_id = response.json()["id"]

    log = db_session.query(Log).filter(Log.id == log_id).first()
    assert log is not None
    assert log.event_id == 4625
    assert log.event_type == "authentication_failure"
    assert log.raw_log == windows_payload["raw_log"]
    assert json.loads(log.raw_log)["EventID"] == 4625


# --- 12-13. Agent association ----------------------------------------------


def test_ingest_log_with_valid_agent_id_associates_it_and_marks_online(client, admin_token):
    agent_response = client.post(
        "/api/agents",
        json={"hostname": "ubuntu-server-01", "operating_system": "Ubuntu 22.04", "ip_address": "192.168.1.10"},
        headers=_auth_headers(admin_token),
    )
    assert agent_response.status_code == 201, agent_response.text
    agent_id = agent_response.json()["agent_id"]

    log_response = client.post(
        "/api/logs",
        json={"raw_log": "Accepted password for admin from 192.168.1.50", "agent_id": agent_id},
        headers=_auth_headers(admin_token),
    )
    assert log_response.status_code == 201, log_response.text

    agents_after = client.get("/api/agents", headers=_auth_headers(admin_token)).json()
    updated = next(a for a in agents_after if a["agent_id"] == agent_id)
    assert updated["status"] == "online"
    assert updated["last_seen"] is not None


def test_ingest_log_with_nonexistent_agent_id_is_rejected(client, admin_token):
    response = client.post(
        "/api/logs",
        json={"raw_log": "Accepted password for admin from 192.168.1.50", "agent_id": "does-not-exist"},
        headers=_auth_headers(admin_token),
    )
    assert response.status_code == 404


def test_ingest_log_without_agent_id_still_succeeds(client, admin_token):
    """Per Phase A.8: agent registration is never a blocker for basic
    log ingestion."""
    response = client.post(
        "/api/logs",
        json={"raw_log": "Accepted password for admin from 192.168.1.50"},
        headers=_auth_headers(admin_token),
    )
    assert response.status_code == 201, response.text


# --- 14. Unauthorized request -----------------------------------------------


def test_ingest_log_without_authentication_is_rejected(client):
    response = client.post("/api/logs", json={"event_type": "authentication_failure"}, headers={})
    assert response.status_code == 401


# --- Phase A.11 / Task 9: detection must NOT run yet, even under a
# burst of clearly attack-shaped traffic. Checked both via the API
# response AND by querying the `alerts` table directly -- an empty
# response field could theoretically lie; an empty table can't.


def test_no_alerts_are_generated_in_phase_a_even_for_suspicious_looking_events(client, admin_token):
    response = client.post(
        "/api/logs",
        json={"raw_log": "File integrity violation: /etc/shadow modified by root"},
        headers=_auth_headers(admin_token),
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["alerts_generated"] == 0
    assert body["alert_ids"] == []


def test_sub_threshold_attack_shaped_traffic_generates_no_alerts(client, admin_token, db_session):
    """
    Attack-SHAPED traffic that stays under every rule's threshold must
    stay silent. This is the false-positive guard for the ingestion
    pipeline: getting more sensitive over time is the failure mode that
    makes a SIEM unusable, so each live rule is exercised deliberately
    one step below where it is supposed to fire.

    History: this test used to assert that rules which were not yet
    implemented stayed quiet. All five rules from the project document
    are implemented now, so the premise changed -- what is still worth
    guarding is the threshold boundary itself.

    Note the assertions are scoped to the traffic this test generated
    (its own source IP / actor), not to a global `Alert.count() == 0`:
    every test in the suite shares one SQLite database, so a global
    count also counts alerts raised by the dedicated detection test
    files and would fail for reasons that have nothing to do with this
    test's subject.
    """
    from app.models.alert import Alert

    headers = _auth_headers(admin_token)
    ip = "203.0.113.51"  # distinct from the IPs used in the detection test files
    actor = "ingestion-test-operator"

    # 4 failed logins -- ONE BELOW brute_force's threshold of 5. No
    # successful login follows, so login_after_failure has nothing to
    # trigger on either.
    for _ in range(4):
        response = client.post(
            "/api/logs",
            json={"raw_log": f"Failed password for admin from {ip}"},
            headers=headers,
        )
        assert response.status_code == 201, response.text
        assert response.json()["alerts_generated"] == 0

    # 9 distinct destination ports -- ONE BELOW port_scan's threshold of
    # 10 (see test_detection_port_scan.py for the firing case).
    for port in range(1, 10):
        response = client.post(
            "/api/logs",
            json={"raw_log": f"Connection attempt from {ip} to port {port}"},
            headers=headers,
        )
        assert response.status_code == 201, response.text
        assert response.json()["alerts_generated"] == 0

    # A privileged action that is ROUTINE administration rather than
    # escalation: privilege_escalation deliberately does not fire on
    # every sudo (see its module docstring).
    response = client.post(
        "/api/logs",
        json={
            "raw_log": (
                f"sudo: {actor} : TTY=pts/0 ; PWD=/home/{actor} ; USER=root ; "
                "COMMAND=/usr/bin/systemctl restart nginx"
            )
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text
    assert response.json()["alerts_generated"] == 0

    # A change to a file that is not on file_integrity's watch list.
    response = client.post(
        "/api/logs",
        json={"raw_log": f"File integrity violation: /var/tmp/scratch.txt modified by {actor}"},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    assert response.json()["alerts_generated"] == 0

    # The stronger check: the alerts table itself holds nothing traceable
    # to this test's traffic, regardless of what any response claimed.
    assert db_session.query(Alert).filter(Alert.dedup_key.in_([ip, actor])).count() == 0
    assert db_session.query(Alert).filter(Alert.source_ip == ip).count() == 0
