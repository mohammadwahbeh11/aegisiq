"""
Direct tests of app/ingestion/normalizer.py -- no FastAPI app, no
database, no auth, no Pydantic. These were run for real during
development (python3 executing this exact logic, not just reviewed) to
verify parsing correctness independent of whether the web framework is
installed; this file is the permanent, pytest-runnable version of those
checks. See tests/test_log_ingestion.py for the API/DB-level tests that
exercise the real endpoint end to end (required by Phase A.10 -- "must
exercise the real API and database behavior", which unit tests of the
parser alone do not satisfy on their own).
"""
from app.ingestion.normalizer import (
    AUTH_FAILURE,
    AUTH_SUCCESS,
    FILE_INTEGRITY_CHANGE,
    PRIVILEGE_RELATED,
    UNPARSED,
    normalize,
)


def test_linux_failed_login_matches_project_example():
    e = normalize({"raw_log": "Failed password for admin from 192.168.1.50"})
    assert e.event_type == AUTH_FAILURE
    assert e.username == "admin"
    assert e.source_ip == "192.168.1.50"


def test_linux_successful_login_matches_project_example():
    e = normalize({"raw_log": "Accepted password for admin from 192.168.1.50"})
    assert e.event_type == AUTH_SUCCESS
    assert e.username == "admin"


def test_linux_sudo_is_privilege_related_not_escalation():
    """Phase A does not judge maliciousness -- that's Phase B's job."""
    e = normalize({"raw_log": "sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash"})
    assert e.event_type == PRIVILEGE_RELATED
    assert e.username == "admin"


def test_linux_pam_style_authentication_failure():
    e = normalize(
        {"raw_log": "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9 user=root"}
    )
    assert e.event_type == AUTH_FAILURE
    assert e.source_ip == "203.0.113.9"
    assert e.username == "root"


def test_linux_file_integrity_change():
    e = normalize({"raw_log": "File integrity violation: /etc/shadow modified by root"})
    assert e.event_type == FILE_INTEGRITY_CHANGE
    assert e.normalized_data["path"] == "/etc/shadow"


def test_windows_4625_is_authentication_failure():
    e = normalize({"event_id": 4625, "hostname": "WIN-PC01", "source_ip": "10.0.0.5", "username": "Administrator"})
    assert e.event_type == AUTH_FAILURE
    assert e.event_id == 4625


def test_windows_4624_is_authentication_success():
    e = normalize({"event_id": 4624, "username": "Administrator"})
    assert e.event_type == AUTH_SUCCESS


def test_windows_4672_is_privilege_related():
    e = normalize({"event_id": 4672, "username": "Administrator"})
    assert e.event_type == PRIVILEGE_RELATED


def test_already_normalized_event_is_not_overwritten():
    e = normalize(
        {
            "event_type": "authentication_failure",
            "source_ip": "10.0.0.10",
            "username": "admin",
            "raw_log": "Accepted password for admin from 192.168.1.50",  # would parse as SUCCESS if it were used
        }
    )
    assert e.event_type == "authentication_failure"
    assert e.source_ip == "10.0.0.10"


def test_raw_log_is_always_preserved_verbatim():
    raw = "Failed password for admin from 192.168.1.50 port 51742 ssh2"
    assert normalize({"raw_log": raw}).raw_log == raw


def test_unrecognized_line_is_honestly_unparsed_not_guessed():
    raw = "totally unrecognized nonsense line"
    e = normalize({"raw_log": raw})
    assert e.event_type == UNPARSED
    assert e.raw_log == raw


def test_client_supplied_metadata_wins_over_parsed_extras():
    e = normalize(
        {
            "raw_log": "sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash",
            "metadata": {"command": "client-override"},
        }
    )
    assert e.normalized_data["command"] == "client-override"


def test_destination_port_is_parsed_into_its_own_field():
    e = normalize({"raw_log": "Failed password for admin from 192.168.1.50 port 51742 ssh2"})
    assert e.destination_port == 51742


def test_missing_raw_log_falls_back_to_json_of_the_submitted_fields():
    """A fully pre-normalized event with no literal raw_log must still
    end up with SOMETHING preserved for forensic review -- never an
    empty string."""
    import json

    e = normalize({"event_type": "authentication_failure", "source_ip": "10.0.0.10", "username": "admin"})
    assert e.raw_log  # not empty, not None
    parsed_back = json.loads(e.raw_log)
    assert parsed_back["event_type"] == "authentication_failure"
    assert parsed_back["source_ip"] == "10.0.0.10"
