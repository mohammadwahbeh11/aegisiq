"""
Integration tests for the three detection rules added in Phase C:
login_after_failure, file_integrity and privilege_escalation. Real API
(POST /api/logs), real detection engine, real SQLite database via the
`client`/`admin_token`/`db_session` fixtures -- nothing mocked, matching
the approach in test_detection_brute_force.py and
test_detection_port_scan.py.

IP addressing convention (continuing the existing files'): all test IPs
are in 192.0.2.0/24 (TEST-NET-1, RFC 5737). The brute-force tests use
.1-.19 and the port-scan tests .20+, so this file uses .40+ to stay
clear of both -- the tests share one database within a session.
"""
from datetime import datetime, timedelta, timezone

from app.models.alert import Alert, AlertStatus
from app.models.log import Severity
from app.models.rule import DetectionRule


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _post(client, token, payload: dict):
    return client.post("/api/logs", json=payload, headers=_auth_headers(token))


def _post_failed_login(client, token, source_ip: str, when: datetime, user: str = "admin"):
    return _post(
        client,
        token,
        {"raw_log": f"Failed password for {user} from {source_ip}", "timestamp": when.isoformat()},
    )


def _post_successful_login(client, token, source_ip: str, when: datetime, user: str = "admin"):
    return _post(
        client,
        token,
        {"raw_log": f"Accepted password for {user} from {source_ip}", "timestamp": when.isoformat()},
    )


def _post_file_change(client, token, path: str, when: datetime, user: str = "eve"):
    return _post(
        client,
        token,
        {
            "raw_log": f"File integrity violation: {path} modified by {user}",
            "timestamp": when.isoformat(),
        },
    )


def _post_sudo(client, token, user: str, command: str, when: datetime):
    return _post(
        client,
        token,
        {
            "raw_log": f"sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}",
            "timestamp": when.isoformat(),
        },
    )


def _rule(db_session, rule_type: str) -> DetectionRule:
    return db_session.query(DetectionRule).filter(DetectionRule.rule_type == rule_type).one()


def _alerts_for(db_session, rule_type: str, dedup_key: str) -> list[Alert]:
    rule = _rule(db_session, rule_type)
    return (
        db_session.query(Alert)
        .filter(Alert.rule_id == rule.id, Alert.dedup_key == dedup_key)
        .all()
    )


# ===========================================================================
# login_after_failure
# ===========================================================================


def test_login_after_failure_fires_on_success_following_enough_failures(
    client, admin_token, db_session
):
    ip = "192.0.2.40"
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    # 5 failures = the seeded threshold. This also crosses brute_force's
    # own threshold of 5, so the 5th failure raises a brute_force alert --
    # that is correct and intentional (two different rules, two different
    # meanings), and is asserted explicitly below rather than being
    # allowed to silently pollute this test.
    for i in range(5):
        assert _post_failed_login(client, admin_token, ip, base + timedelta(seconds=i)).status_code == 201

    response = _post_successful_login(client, admin_token, ip, base + timedelta(seconds=30))
    assert response.status_code == 201, response.text
    assert response.json()["alerts_generated"] == 1

    alerts = _alerts_for(db_session, "login_after_failure", ip)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.severity == Severity.CRITICAL
    assert alert.mitre_id == "T1078"
    assert alert.kill_chain_phase == "Exploitation"
    assert alert.status == AlertStatus.NEW
    assert alert.source_ip == ip
    assert "admin" in alert.description
    assert "5 failed" in alert.description

    # The companion brute_force alert exists too -- proof the two rules
    # coexist rather than one suppressing the other.
    assert len(_alerts_for(db_session, "brute_force", ip)) == 1


def test_login_after_failure_below_threshold_does_not_fire(client, admin_token, db_session):
    ip = "192.0.2.41"
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    for i in range(4):  # one below the threshold of 5
        assert _post_failed_login(client, admin_token, ip, base + timedelta(seconds=i)).status_code == 201

    response = _post_successful_login(client, admin_token, ip, base + timedelta(seconds=10))
    assert response.status_code == 201
    assert response.json()["alerts_generated"] == 0
    assert _alerts_for(db_session, "login_after_failure", ip) == []


def test_login_after_failure_ignores_failures_outside_the_window(client, admin_token, db_session):
    """The failures are real, but old. By the time the login succeeds,
    they are no longer evidence that THIS login was guessed."""
    ip = "192.0.2.42"
    rule = _rule(db_session, "login_after_failure")
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    for i in range(5):
        assert _post_failed_login(client, admin_token, ip, base + timedelta(seconds=i)).status_code == 201

    # One second past the far edge of the rule's window, measured
    # backwards from the successful login.
    success_at = base + timedelta(seconds=rule.time_window_seconds + 5)
    response = _post_successful_login(client, admin_token, ip, success_at)
    assert response.status_code == 201
    assert _alerts_for(db_session, "login_after_failure", ip) == []


def test_login_after_failure_counts_only_the_same_source_ip(client, admin_token, db_session):
    """Failures from other addresses must not incriminate this login --
    otherwise a busy server would flag every legitimate login."""
    victim_ip = "192.0.2.43"
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    for i in range(5):
        other_ip = f"192.0.2.{60 + i}"
        assert _post_failed_login(client, admin_token, other_ip, base + timedelta(seconds=i)).status_code == 201

    response = _post_successful_login(client, admin_token, victim_ip, base + timedelta(seconds=20))
    assert response.status_code == 201
    assert response.json()["alerts_generated"] == 0
    assert _alerts_for(db_session, "login_after_failure", victim_ip) == []


def test_login_after_failure_deduplicates_while_alert_is_open(client, admin_token, db_session):
    ip = "192.0.2.44"
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    for i in range(5):
        assert _post_failed_login(client, admin_token, ip, base + timedelta(seconds=i)).status_code == 201
    assert _post_successful_login(client, admin_token, ip, base + timedelta(seconds=10)).status_code == 201

    # A second successful login moments later is the same ongoing
    # incident, not a new one.
    for i in range(5):
        _post_failed_login(client, admin_token, ip, base + timedelta(seconds=20 + i))
    assert _post_successful_login(client, admin_token, ip, base + timedelta(seconds=30)).status_code == 201

    assert len(_alerts_for(db_session, "login_after_failure", ip)) == 1


# ===========================================================================
# file_integrity
# ===========================================================================


def test_file_integrity_fires_on_watched_path(client, admin_token, db_session):
    when = datetime(2026, 1, 2, 9, 0, 0, tzinfo=timezone.utc)
    response = _post_file_change(client, admin_token, "/etc/shadow", when)
    assert response.status_code == 201, response.text
    assert response.json()["alerts_generated"] == 1

    alerts = _alerts_for(db_session, "file_integrity", "/etc/shadow")
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.severity == Severity.CRITICAL
    assert alert.mitre_id == "T1098"
    assert alert.kill_chain_phase == "Installation"
    assert "/etc/shadow" in alert.description
    assert "eve" in alert.description


def test_file_integrity_ignores_unwatched_path(client, admin_token, db_session):
    """A change to an ordinary file is stored as a log but is not an
    alert -- the rule watches critical files, not every file."""
    when = datetime(2026, 1, 2, 9, 5, 0, tzinfo=timezone.utc)
    response = _post_file_change(client, admin_token, "/home/eve/notes.txt", when)
    assert response.status_code == 201
    assert response.json()["alerts_generated"] == 0
    assert _alerts_for(db_session, "file_integrity", "/home/eve/notes.txt") == []


def test_file_integrity_matches_directory_prefix_entries(client, admin_token, db_session):
    """/etc/sudoers.d/ is watched as a directory, so any file dropped
    inside it counts -- that is how sudoers rules are actually added."""
    when = datetime(2026, 1, 2, 9, 10, 0, tzinfo=timezone.utc)
    path = "/etc/sudoers.d/99-backdoor"
    response = _post_file_change(client, admin_token, path, when)
    assert response.status_code == 201
    assert response.json()["alerts_generated"] == 1
    assert len(_alerts_for(db_session, "file_integrity", path)) == 1


def test_file_integrity_deduplicates_per_path_not_globally(client, admin_token, db_session):
    """The regression this rule's dedup_key exists to prevent: file
    integrity events carry no source IP, so keying deduplication on
    source_ip would let the /etc/passwd alert swallow the /etc/shadow
    one. Two different critical files must produce two alerts."""
    when = datetime(2026, 1, 2, 9, 20, 0, tzinfo=timezone.utc)
    assert _post_file_change(client, admin_token, "/etc/passwd", when).json()["alerts_generated"] == 1
    assert (
        _post_file_change(client, admin_token, "/etc/ssh/sshd_config", when + timedelta(seconds=1))
        .json()["alerts_generated"]
        == 1
    )

    assert len(_alerts_for(db_session, "file_integrity", "/etc/passwd")) == 1
    assert len(_alerts_for(db_session, "file_integrity", "/etc/ssh/sshd_config")) == 1

    # ...while a repeat change to the SAME file is deduplicated.
    assert (
        _post_file_change(client, admin_token, "/etc/passwd", when + timedelta(seconds=2))
        .json()["alerts_generated"]
        == 0
    )
    assert len(_alerts_for(db_session, "file_integrity", "/etc/passwd")) == 1


def test_file_integrity_respects_rule_parameters(client, admin_token, db_session):
    """The watched set is data, not code: narrowing parameters on the
    rule row changes what the running engine alerts on."""
    rule = _rule(db_session, "file_integrity")
    original = rule.parameters
    rule.parameters = {"critical_paths": ["/etc/nginx/nginx.conf"]}
    db_session.commit()
    try:
        when = datetime(2026, 1, 2, 9, 30, 0, tzinfo=timezone.utc)
        # Now watched, though it is not in the built-in defaults.
        assert (
            _post_file_change(client, admin_token, "/etc/nginx/nginx.conf", when)
            .json()["alerts_generated"]
            == 1
        )
        # No longer watched, though it IS in the built-in defaults.
        assert (
            _post_file_change(client, admin_token, "/etc/sudoers", when + timedelta(seconds=1))
            .json()["alerts_generated"]
            == 0
        )
    finally:
        rule.parameters = original
        db_session.commit()


# ===========================================================================
# privilege_escalation
# ===========================================================================


def test_privilege_escalation_fires_on_root_shell(client, admin_token, db_session):
    when = datetime(2026, 1, 3, 8, 0, 0, tzinfo=timezone.utc)
    response = _post_sudo(client, admin_token, "mallory", "/bin/bash", when)
    assert response.status_code == 201, response.text
    assert response.json()["alerts_generated"] == 1

    alerts = _alerts_for(db_session, "privilege_escalation", "mallory")
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.severity == Severity.CRITICAL
    assert alert.mitre_id == "T1548"
    assert alert.kill_chain_phase == "Actions on Objectives"
    assert "/bin/bash" in alert.description


def test_privilege_escalation_ignores_routine_sudo(client, admin_token, db_session):
    """`sudo systemctl restart nginx` is administration, not escalation.
    Alerting on it would bury the analyst in false positives."""
    when = datetime(2026, 1, 3, 8, 10, 0, tzinfo=timezone.utc)
    response = _post_sudo(client, admin_token, "ops-carol", "/usr/bin/systemctl restart nginx", when)
    assert response.status_code == 201
    assert response.json()["alerts_generated"] == 0
    assert _alerts_for(db_session, "privilege_escalation", "ops-carol") == []


def test_privilege_escalation_fires_on_windows_event_4672(client, admin_token, db_session):
    """A Windows special-privileges assignment has no command string --
    the event id itself is the signal. The normalizer deliberately does
    not call 4672 an escalation; this rule is the layer that judges."""
    when = datetime(2026, 1, 3, 8, 20, 0, tzinfo=timezone.utc)
    response = _post(
        client,
        admin_token,
        {
            "event_id": 4672,
            "username": "WIN-SVC-ADMIN",
            "hostname": "DC-01",
            "operating_system": "Windows Server 2022",
            "timestamp": when.isoformat(),
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["alerts_generated"] == 1

    alerts = _alerts_for(db_session, "privilege_escalation", "WIN-SVC-ADMIN")
    assert len(alerts) == 1
    assert "4672" in alerts[0].description


def test_privilege_escalation_deduplicates_per_actor(client, admin_token, db_session):
    """Two different users escalating are two incidents; the same user
    escalating twice in the window is one."""
    when = datetime(2026, 1, 3, 8, 30, 0, tzinfo=timezone.utc)
    assert _post_sudo(client, admin_token, "dave", "/bin/sh", when).json()["alerts_generated"] == 1
    assert (
        _post_sudo(client, admin_token, "erin", "/usr/sbin/visudo", when + timedelta(seconds=1))
        .json()["alerts_generated"]
        == 1
    )
    assert (
        _post_sudo(client, admin_token, "dave", "/bin/bash", when + timedelta(seconds=2))
        .json()["alerts_generated"]
        == 0
    )

    assert len(_alerts_for(db_session, "privilege_escalation", "dave")) == 1
    assert len(_alerts_for(db_session, "privilege_escalation", "erin")) == 1


def test_privilege_escalation_respects_rule_parameters(client, admin_token, db_session):
    rule = _rule(db_session, "privilege_escalation")
    original = rule.parameters
    rule.parameters = {"suspicious_commands": ["docker run --privileged"]}
    db_session.commit()
    try:
        when = datetime(2026, 1, 3, 8, 40, 0, tzinfo=timezone.utc)
        assert (
            _post_sudo(client, admin_token, "frank", "docker run --privileged -it alpine", when)
            .json()["alerts_generated"]
            == 1
        )
        # /bin/bash is a built-in default but is not in the narrowed set.
        assert (
            _post_sudo(client, admin_token, "grace", "/bin/bash", when + timedelta(seconds=1))
            .json()["alerts_generated"]
            == 0
        )
    finally:
        rule.parameters = original
        db_session.commit()


def test_disabled_rule_is_not_evaluated(client, admin_token, db_session):
    """Toggling a rule off from the Rules page must actually stop it
    firing, not merely hide it in the UI."""
    rule = _rule(db_session, "privilege_escalation")
    rule.enabled = False
    db_session.commit()
    try:
        when = datetime(2026, 1, 3, 8, 50, 0, tzinfo=timezone.utc)
        response = _post_sudo(client, admin_token, "heidi", "/bin/bash", when)
        assert response.status_code == 201
        assert response.json()["alerts_generated"] == 0
        assert _alerts_for(db_session, "privilege_escalation", "heidi") == []
    finally:
        rule.enabled = True
        db_session.commit()
