"""
Startup initialization: create tables, seed a default administrator
account, and seed the detection rules exactly as specified in the
graduation project document (section 3.6 / Table 1 - Features of the
Detection Engine), so the Rules page is never empty and the detection
engine (next phase) has real configured rules to execute.

Design decisions, documented rather than hidden:
- The document defines 5 detection features (failed_login_count,
  port_access_count, login_after_failure, file_integrity_change,
  privilege_escalation). Each is seeded as one rule below with the exact
  thresholds given in the document (5 failed logins / 120s, 10 ports /
  60s). Where the document does not give a specific number
  (login_after_failure's "configurable period", privilege_escalation),
  a sensible default is chosen and called out in each rule's description
  so it's obviously a default, not a hidden assumption.
- MITRE ATT&CK technique IDs are standard mappings for each attack
  pattern (T1110 Brute Force, T1046 Network Service Scanning, T1078
  Valid Accounts, T1098 Account Manipulation, T1548 Abuse Elevation
  Control Mechanism), satisfying objective O6.
"""
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth.security import hash_password
from app.config import get_settings
from app.database import Base, engine, SessionLocal
# Imported for their default parameter sets, so the seeded rule rows and
# the rule modules' own fallbacks can never drift apart.
from app.detection.rules import (
    file_integrity, privilege_escalation, suspicious_user_agent, web_attack,
)
from app.models.alert import Alert
from app.models.log import Severity
from app.models.rule import DetectionRule
from app.models.user import User, UserRole

# Import models package so every table is registered on Base.metadata.
import app.models  # noqa: F401
# v2.0 — audit table lives under app.security; import so create_all sees it.
from app.security.audit import AuditEntry  # noqa: F401
# v2.1 — analysis-report table (premium feature).
from app.models.analysis import AnalysisReport  # noqa: F401

settings = get_settings()

DEFAULT_RULES = [
    dict(
        name="Brute Force Authentication",
        description=(
            "5 or more failed login attempts from the same source IP within "
            "120 seconds (project Table 1: failed_login_count threshold)."
        ),
        rule_type="brute_force",
        threshold=5,
        time_window_seconds=120,
        severity=Severity.HIGH,
        mitre_id="T1110",
        # "Credential Access" is T1110's MITRE ATT&CK TACTIC, not a
        # Cyber Kill Chain phase -- those are two different frameworks
        # (objective O6 asks for both). The actual Kill Chain phase for
        # repeated credential-guessing against this target is "Actions
        # on Objectives".
        kill_chain_phase="Actions on Objectives",
    ),
    dict(
        name="Port Scanning",
        description=(
            "10 or more distinct destination ports accessed by the same "
            "source IP within 60 seconds (project Table 1: port_access_count)."
        ),
        rule_type="port_scan",
        threshold=10,
        time_window_seconds=60,
        severity=Severity.HIGH,
        mitre_id="T1046",
        kill_chain_phase="Reconnaissance",
    ),
    dict(
        name="Login After Repeated Failures",
        description=(
            "A successful login from a source IP that had 5+ failed attempts "
            "in the preceding 300 seconds (project: login_after_failure). "
            "300s default is not specified in the document as an exact "
            "number ('a configurable period') -- adjust via this rule's "
            "time window."
        ),
        rule_type="login_after_failure",
        threshold=5,
        time_window_seconds=300,
        severity=Severity.CRITICAL,
        mitre_id="T1078",
        # Same category error as brute_force originally had -- "Credential
        # Access" is a MITRE tactic, not a Kill Chain phase. Not explicitly
        # requested for this rule, but it's the identical mistake on the
        # same seed table being fixed in this pass, so corrected here too
        # rather than left inconsistent. A successful login immediately
        # after repeated failures is the moment the credential attack
        # actually succeeds -- "Exploitation" in Kill Chain terms.
        kill_chain_phase="Exploitation",
    ),
    dict(
        name="Critical File Integrity Change",
        description=(
            "Modification of a critical system file (/etc/passwd or "
            "/etc/shadow). Any single change triggers this rule "
            "(project: file_integrity_change)."
        ),
        rule_type="file_integrity",
        threshold=1,
        time_window_seconds=60,
        severity=Severity.CRITICAL,
        mitre_id="T1098",
        kill_chain_phase="Installation",
        # Which files this rule watches. Editable per-deployment without
        # a code change; the rule falls back to
        # file_integrity.DEFAULT_CRITICAL_PATHS if this is ever cleared.
        parameters={
            "critical_paths": list(file_integrity.DEFAULT_CRITICAL_PATHS),
        },
    ),
    dict(
        name="Privilege Escalation",
        description=(
            "A suspicious sudo/administrative action is detected. Any "
            "single matching event triggers this rule by default "
            "(project: privilege_escalation); raise the threshold to "
            "require repeated attempts if this is too noisy in practice."
        ),
        rule_type="privilege_escalation",
        threshold=1,
        time_window_seconds=60,
        severity=Severity.CRITICAL,
        mitre_id="T1548",
        kill_chain_phase="Actions on Objectives",
        # What counts as "suspicious" for this rule -- see the module
        # docstring in app/detection/rules/privilege_escalation.py for
        # why it is not simply "every sudo invocation".
        parameters={
            "suspicious_commands": list(privilege_escalation.DEFAULT_SUSPICIOUS_COMMANDS),
        },
    ),
    # ─── v2.0 rules ──────────────────────────────────────────────────
    dict(
        name="Web Application Attack",
        description=(
            "HTTP request whose URL, body, or User-Agent matches an "
            "attack-tool signature: SQL injection, XSS, path traversal, "
            "OS command injection, SSTI, or Log4Shell. Single match "
            "triggers the rule; edit rule.parameters['patterns'] to "
            "add or refine signatures (AegisIQ v2.0)."
        ),
        rule_type="web_attack",
        threshold=1,
        time_window_seconds=60,
        severity=Severity.HIGH,
        mitre_id="T1190",
        kill_chain_phase="Exploitation",
        parameters={
            "patterns": [
                {"name": name, "regex": regex}
                for name, regex in web_attack._DEFAULT_PATTERNS
            ],
        },
    ),
    dict(
        name="Credential Stuffing",
        description=(
            "Failed logins across N or more DISTINCT usernames from the "
            "same source IP within 120 seconds. Distinct from brute_force, "
            "which counts many attempts against one account; credential "
            "stuffing is many attempts across many accounts and signals "
            "the attacker holds a leaked credential dump (AegisIQ v2.0)."
        ),
        rule_type="credential_stuffing",
        threshold=5,
        time_window_seconds=120,
        severity=Severity.CRITICAL,
        mitre_id="T1110.004",
        kill_chain_phase="Credential Access",
    ),
    dict(
        name="Suspicious User-Agent",
        description=(
            "HTTP request whose User-Agent matches a known attacker-tool "
            "signature (sqlmap, nikto, nmap NSE, metasploit, wpscan, "
            "dirbuster, gobuster, hydra, ffuf, burp, acunetix, nuclei, "
            "masscan, zaproxy). Catches automated / unskilled scanning; "
            "skilled attackers spoof the UA, so severity is MEDIUM by "
            "design (AegisIQ v2.0)."
        ),
        rule_type="suspicious_user_agent",
        threshold=1,
        time_window_seconds=120,
        severity=Severity.MEDIUM,
        mitre_id="T1595.002",
        kill_chain_phase="Reconnaissance",
        parameters={
            "ua_signatures": [
                {"name": name, "needle": needle}
                for name, needle in suspicious_user_agent.DEFAULT_UA_SIGNATURES
            ],
        },
    ),
]


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    _ensure_log_table_columns()
    _ensure_columns("detection_rules", {"kill_chain_phase": "VARCHAR(64)", "parameters": "JSON"})
    _ensure_columns("alerts", {"kill_chain_phase": "VARCHAR(64)", "dedup_key": "VARCHAR(255)"})

    db: Session = SessionLocal()
    try:
        _seed_admin(db)
        _seed_rules(db)
        _backfill_rule_kill_chain_phases(db)
        _backfill_rule_parameters(db)
        _backfill_alert_dedup_keys(db)
        _correct_stale_kill_chain_phases(db)
        db.commit()
    finally:
        db.close()


def _ensure_log_table_columns() -> None:
    """
    Small, honest, SQLite-only 'migration' for columns added to the Log
    model in the ingestion phase (source_port, destination_port,
    operating_system, event_id). Base.metadata.create_all() only creates
    tables that don't exist yet -- it will NOT add columns to a `logs`
    table that a previous run of this project already created, which
    would otherwise force deleting local demo data on every schema
    change.

    This project intentionally has no Alembic (see docs/architecture.md
    "resource efficiency" -- avoiding unnecessary dependencies for a
    lightweight app). If the schema keeps evolving, or once PostgreSQL
    is adopted, Alembic (or an equivalent) should replace this. For now
    this is a deliberately narrow, documented stand-in, not a general
    migration framework.
    """
    _ensure_columns(
        "logs",
        {
            "source_port": "INTEGER",
            "destination_port": "INTEGER",
            "operating_system": "VARCHAR(64)",
            "event_id": "INTEGER",
        },
    )
    if engine.dialect.name == "sqlite":
        with engine.connect() as conn:
            # destination_port is indexed on the model (the brute-force/
            # port-scan rules query it); ALTER TABLE ADD COLUMN doesn't
            # create that index, so it's added explicitly, matching
            # SQLAlchemy's default naming convention (ix_<table>_<column>).
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_logs_destination_port ON logs (destination_port)"))
            conn.commit()


def _ensure_columns(table_name: str, required_columns: dict[str, str]) -> None:
    """Generalized version of the same small SQLite-only 'migration'
    described above -- adds any of `required_columns` that are missing
    from an already-existing table, without touching existing rows."""
    if engine.dialect.name != "sqlite":
        return

    with engine.connect() as conn:
        existing = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table_name})"))}
        if not existing:
            return  # table doesn't exist yet -- create_all() just made it with every column already
        for column, sql_type in required_columns.items():
            if column not in existing:
                conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column} {sql_type}"))
        conn.commit()


def _seed_admin(db: Session) -> None:
    if db.query(User).count() > 0:
        return
    admin = User(
        username=settings.DEFAULT_ADMIN_USERNAME,
        password_hash=hash_password(settings.DEFAULT_ADMIN_PASSWORD),
        role=UserRole.ADMINISTRATOR,
    )
    db.add(admin)


def _seed_rules(db: Session) -> None:
    existing = {r.rule_type for r in db.query(DetectionRule.rule_type).all()}
    for rule_data in DEFAULT_RULES:
        if rule_data["rule_type"] not in existing:
            db.add(DetectionRule(**rule_data))


def _backfill_rule_kill_chain_phases(db: Session) -> None:
    """kill_chain_phase was added after rules may already have been
    seeded by an earlier run (Phase A). _seed_rules only inserts rules
    that don't exist yet by rule_type, so an existing rule row would
    otherwise keep kill_chain_phase=NULL forever. This fills it in from
    DEFAULT_RULES without touching any other field an administrator may
    have already customized (threshold, time_window_seconds, enabled)."""
    phase_by_rule_type = {r["rule_type"]: r["kill_chain_phase"] for r in DEFAULT_RULES}
    rules_missing_phase = db.query(DetectionRule).filter(DetectionRule.kill_chain_phase.is_(None)).all()
    for rule in rules_missing_phase:
        phase = phase_by_rule_type.get(rule.rule_type)
        if phase is not None:
            rule.kill_chain_phase = phase


def _backfill_rule_parameters(db: Session) -> None:
    """parameters (see app/models/rule.py) was added after rules may
    already have been seeded by an earlier run, and _seed_rules only
    inserts rules that don't exist yet by rule_type. This fills in the
    default parameters for rule rows that have none, without overwriting
    a set an administrator has already customized."""
    params_by_rule_type = {
        r["rule_type"]: r.get("parameters") for r in DEFAULT_RULES if r.get("parameters")
    }
    if not params_by_rule_type:
        return
    rules_missing_params = db.query(DetectionRule).filter(DetectionRule.parameters.is_(None)).all()
    for rule in rules_missing_params:
        defaults = params_by_rule_type.get(rule.rule_type)
        if defaults is not None:
            rule.parameters = defaults


def _backfill_alert_dedup_keys(db: Session) -> None:
    """Alert.dedup_key replaced source_ip as the deduplication
    discriminator (see app/detection/alerting.py). Alerts created before
    that change have dedup_key=NULL, which would make the dedup lookup
    miss them and let a duplicate alert fire once immediately after the
    upgrade. Backfilling from source_ip reproduces exactly the old
    behavior for those historical rows."""
    db.query(Alert).filter(
        Alert.dedup_key.is_(None),
        Alert.source_ip.isnot(None),
    ).update({"dedup_key": Alert.source_ip}, synchronize_session=False)


# One-time correction, keyed by rule_type: an earlier pass of this
# project seeded "Credential Access" -- a MITRE ATT&CK TACTIC -- into
# the kill_chain_phase field for these two rules. That's a category
# error (tactic != Kill Chain phase); this maps the old, wrong value to
# the corrected Kill Chain phase name.
_KILL_CHAIN_PHASE_CORRECTIONS = {
    "brute_force": "Actions on Objectives",
    "login_after_failure": "Exploitation",
}
_STALE_KILL_CHAIN_PHASE_VALUE = "Credential Access"


def _correct_stale_kill_chain_phases(db: Session) -> None:
    """Fixes rule rows (and any alerts already generated from them)
    still carrying the erroneous "Credential Access" kill_chain_phase
    value from before this correction. Only touches rows that still
    have exactly that stale value -- a rule an administrator has since
    edited to something else deliberately is left alone. This runs
    every startup but is a no-op once corrected (idempotent)."""
    for rule_type, corrected_phase in _KILL_CHAIN_PHASE_CORRECTIONS.items():
        rule = (
            db.query(DetectionRule)
            .filter(
                DetectionRule.rule_type == rule_type,
                DetectionRule.kill_chain_phase == _STALE_KILL_CHAIN_PHASE_VALUE,
            )
            .first()
        )
        if rule is None:
            continue
        rule.kill_chain_phase = corrected_phase
        # Alerts already generated from this rule inherited the same
        # wrong value at creation time -- correct those too, so
        # historical alerts match the corrected framework mapping.
        db.query(Alert).filter(
            Alert.rule_id == rule.id,
            Alert.kill_chain_phase == _STALE_KILL_CHAIN_PHASE_VALUE,
        ).update({"kill_chain_phase": corrected_phase})
