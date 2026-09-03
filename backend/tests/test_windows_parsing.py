"""
tests/test_windows_parsing.py — v2.3 Windows Event parsing + context.

Locks in the fixes from report #16:
  * Windows Security Event rows parse into real event types (not
    "unparsed").
  * The TARGET account is extracted (ASUS on a 4625), not the SYSTEM
    subject that reported the event.
  * Service/built-in accounts are flagged so the engine can treat their
    privilege/logon activity as routine.
"""
from app.ingestion import normalizer as norm


def test_4672_system_is_parsed_as_service_account():
    raw = ("Event ID=4672 | Special privileges assigned to new logon.\r\n"
           "Subject:\r\n\tAccount Name:\t\tSYSTEM\r\n\tAccount Domain:\tNT AUTHORITY")
    ev = norm.normalize({"raw_log": raw})
    assert ev.event_type == "privilege_related"
    assert ev.event_id == 4672
    assert ev.username == "SYSTEM"
    assert ev.normalized_data.get("is_service_account") is True


def test_4625_extracts_target_account_not_subject():
    raw = ("Event ID=4625 | An account failed to log on.\r\n"
           "Subject:\r\n\tAccount Name:\t\tDESKTOP-T8744J5$\r\n"
           "Logon Type:\t\t2\r\n"
           "Account For Which Logon Failed:\r\n\tAccount Name:\t\tASUS\r\n"
           "\tAccount Domain:\tDESKTOP-T8744J5")
    ev = norm.normalize({"raw_log": raw})
    assert ev.event_type == "authentication_failure"
    assert ev.event_id == 4625
    # The meaningful account is the target, not the SYSTEM subject.
    assert ev.username == "ASUS"
    assert ev.normalized_data.get("is_service_account") is False
    assert ev.normalized_data.get("logon_type") == 2


def test_4624_machine_account_is_service():
    raw = ("Event ID=4624 | An account was successfully logged on.\r\n"
           "Subject:\r\n\tAccount Name:\t\tDESKTOP-T8744J5$\r\n"
           "Logon Information:\r\n\tLogon Type:\t\t5")
    ev = norm.normalize({"raw_log": raw})
    assert ev.event_type == "authentication_success"
    assert ev.normalized_data.get("is_service_account") is True   # machine account ($)
    assert ev.normalized_data.get("logon_type") == 5


def test_non_windows_line_is_unaffected():
    raw = "Failed password for admin from 203.0.113.7 port 22 ssh2"
    ev = norm.normalize({"raw_log": raw})
    assert ev.event_type == "authentication_failure"
    assert ev.source_ip == "203.0.113.7"
    # No Windows metadata leaked onto a Linux line.
    assert "is_service_account" not in ev.normalized_data


def test_windows_datetime_parses_arabic_meridiem():
    raw = ("Date and Time=25/08/2026 02:01:52 م | Event ID=4625 | "
           "An account failed to log on.\r\nAccount For Which Logon Failed:\r\n"
           "\tAccount Name:\t\tASUS")
    ev = norm.normalize({"raw_log": raw})
    # 02:01:52 PM on 25 Aug 2026
    assert ev.timestamp.year == 2026 and ev.timestamp.month == 8 and ev.timestamp.day == 25
    assert ev.timestamp.hour == 14
