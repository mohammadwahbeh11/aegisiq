"""
tests/test_sigma.py — v2.3 Sigma rule engine.

Verifies the practical Sigma subset: field equality, modifiers
(endswith/contains), keyword lists, and the boolean condition evaluator
(and/or/not, parentheses). Uses inline rules so it doesn't depend on the
shipped sigma_rules/ directory.
"""
import textwrap

import pytest

yaml = pytest.importorskip("yaml")  # Sigma needs PyYAML

from app.detection import sigma


def _rule(yaml_text: str) -> sigma.SigmaRule:
    doc = yaml.safe_load(textwrap.dedent(yaml_text))
    r = sigma._build_rule(doc, "inline")
    assert r is not None
    return r


def test_simple_eventid_equality():
    r = _rule("""
        title: Audit log cleared
        tags: [attack.defense_evasion, attack.t1070.001]
        detection:
          selection:
            EventID: 1102
          condition: selection
        level: critical
    """)
    assert r.severity == "critical"
    assert r.mitre == "T1070.001"
    assert sigma.rule_matches(r, {"event_id": 1102, "normalized_data": {}}, "Event ID=1102")
    assert not sigma.rule_matches(r, {"event_id": 4624, "normalized_data": {}}, "Event ID=4624")


def test_endswith_and_contains_with_condition():
    r = _rule("""
        title: Encoded PowerShell
        detection:
          selection_img:
            Image|endswith: '\\powershell.exe'
          selection_flags:
            CommandLine|contains: ' -enc '
          condition: selection_img and selection_flags
        level: high
    """)
    ev = {"normalized_data": {"Image": "C:\\Windows\\System32\\powershell.exe",
                              "CommandLine": "powershell.exe -enc ABCD"}}
    assert sigma.rule_matches(r, ev, "powershell.exe -enc ABCD")
    # Missing the flag → condition fails
    ev2 = {"normalized_data": {"Image": "C:\\Windows\\System32\\powershell.exe",
                               "CommandLine": "powershell.exe Get-Process"}}
    assert not sigma.rule_matches(r, ev2, "powershell.exe Get-Process")


def test_keyword_list_or():
    r = _rule("""
        title: Mimikatz keywords
        detection:
          keywords:
            - sekurlsa::logonpasswords
            - lsadump::sam
          condition: keywords
        level: critical
    """)
    assert sigma.rule_matches(r, {"normalized_data": {}}, "invoke sekurlsa::logonpasswords now")
    assert not sigma.rule_matches(r, {"normalized_data": {}}, "nothing suspicious here")


def test_not_condition():
    r = _rule("""
        title: Logon not by SYSTEM
        detection:
          selection:
            EventID: 4624
          filter:
            TargetUserName: SYSTEM
          condition: selection and not filter
        level: low
    """)
    # 4624 by a real user → matches (not filtered)
    assert sigma.rule_matches(r, {"event_id": 4624, "username": "alice", "normalized_data": {}},
                              "Event ID=4624 Account Name: alice")
    # 4624 by SYSTEM → filtered out
    assert not sigma.rule_matches(r, {"event_id": 4624, "username": "SYSTEM", "normalized_data": {}},
                                  "Event ID=4624 Account Name: SYSTEM")


def test_aggregation_rule_is_skipped():
    doc = yaml.safe_load(textwrap.dedent("""
        title: Count-based rule
        detection:
          selection:
            EventID: 4625
          condition: selection | count() by TargetUserName > 5
        level: high
    """))
    assert sigma._build_rule(doc, "inline") is None  # unsupported → skipped, not mis-evaluated
