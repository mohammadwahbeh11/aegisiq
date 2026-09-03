"""
app/api/routes/simulation.py -- the Simulation Lab.

Purpose: demonstrate the whole pipeline end to end, live, in one click.
A scenario replays a realistic attack as a sequence of RAW LOG LINES fed
through the ordinary POST-ingestion path (app/ingestion/service.py), so
what the console shows is produced by the same normalizer, the same
detection rules, the same SOAR layer and the same WebSocket broadcast
that real traffic from a Kali box would exercise. Nothing is inserted
straight into the alerts table, and no alert is fabricated: if a rule
does not actually fire on this traffic, no alert appears, which is the
only way a demo is worth anything.

Why events are spaced out over several seconds rather than inserted in
one burst: the point of the lab is to watch detection happen. A burst
would produce a finished alert list before the analyst's eye reaches the
screen; a trickle shows events arriving, the counter climbing, and the
alert popping the moment the threshold is crossed.

The work runs in a background task and the endpoint returns immediately
with the plan it is about to execute, so the browser is never blocked
holding a request open for the length of the scenario.

Restricted to administrators: it writes real rows into the real
database, which is a system-changing action even though the content is
synthetic. Every generated log is tagged source="simulation" and carries
`simulated: true` in normalized_data, so lab traffic can always be told
apart from genuine events afterwards.
"""
from __future__ import annotations

import itertools
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status

from app.auth.dependencies import require_role
from app.database import SessionLocal
from app.ingestion.schemas import LogIngestRequest
from app.ingestion.service import ingest_log
from app.models.user import UserRole

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/simulation", tags=["simulation"])

# Seconds between generated events. Slow enough to watch, fast enough
# that a full scenario finishes while someone is still looking at it.
STEP_DELAY_SECONDS = 0.4

# Simulated attackers live in 198.51.100.0/24 (TEST-NET-2, RFC 5737):
# documentation addresses that can never belong to a real host, so lab
# traffic is never confused with -- or attributed to -- a real machine on
# the network. The exact host octet is chosen per run, see _run_context.
SIMULATED_ATTACKER_SUBNET = "198.51.100"
TARGET_HOST = "ubuntu-web-01"


@dataclass
class Scenario:
    key: str
    name: str
    description: str
    expected_rules: list[str]
    # Each entry is one raw log line submitted as one ingestion request.
    # Lines are templates: {attacker}, {attacker2} and {user} are filled
    # in per run (see _run_context) so that running the same scenario
    # twice represents two DIFFERENT attackers and therefore raises fresh
    # alerts, instead of the second run being correctly -- but
    # unhelpfully, mid-demo -- swallowed by rule deduplication.
    lines: list[str]

    @property
    def event_count(self) -> int:
        return len(self.lines)


def _brute_force_lines(placeholder: str = "{attacker}", count: int = 7) -> list[str]:
    return [
        f"Failed password for invalid user admin from {placeholder} port 22 ssh2"
        for _ in range(count)
    ]


# Cycles the host octet so consecutive runs look like distinct attackers.
# Bounded to .10-.249 to stay inside 198.51.100.0/24 and away from the
# network/broadcast addresses.
_run_counter = itertools.count()


def _run_context() -> dict[str, str]:
    run = next(_run_counter)
    octet = 10 + (run * 7) % 240
    second_octet = 10 + ((run * 7) + 3) % 240
    return {
        "attacker": f"{SIMULATED_ATTACKER_SUBNET}.{octet}",
        "attacker2": f"{SIMULATED_ATTACKER_SUBNET}.{second_octet}",
        "user": f"webadmin{run % 100}",
    }


SCENARIOS: dict[str, Scenario] = {
    "brute_force": Scenario(
        key="brute_force",
        name="SSH brute-force attack",
        description=(
            "Seven failed SSH logins from one address in a few seconds. Crosses the "
            "Brute Force Authentication rule's threshold of 5 within 120 seconds."
        ),
        expected_rules=["brute_force"],
        lines=_brute_force_lines(),
    ),
    "port_scan": Scenario(
        key="port_scan",
        name="Network port scan",
        description=(
            "Connection attempts to twelve distinct ports from one address -- the "
            "traffic an nmap sweep produces. Crosses the Port Scanning rule's "
            "threshold of 10 distinct ports within 60 seconds."
        ),
        expected_rules=["port_scan"],
        lines=[
            "Connection attempt from {attacker} to port %d" % port
            for port in (21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389)
        ],
    ),
    "credential_compromise": Scenario(
        key="credential_compromise",
        name="Credential compromise (guessed password works)",
        description=(
            "Six failed logins followed by a SUCCESSFUL one from the same address. "
            "Raises the HIGH brute-force alert and then the CRITICAL "
            "'Login After Repeated Failures' alert -- the difference between "
            "someone knocking and someone getting in."
        ),
        expected_rules=["brute_force", "login_after_failure"],
        lines=_brute_force_lines("{attacker2}", 6)
        + ["Accepted password for admin from {attacker2} port 22 ssh2"],
    ),
    "privilege_escalation": Scenario(
        key="privilege_escalation",
        name="Privilege escalation via sudo",
        description=(
            "A compromised account runs a routine administrative command (which is "
            "correctly ignored), then spawns an interactive root shell and edits the "
            "sudoers file -- which is not ignored."
        ),
        expected_rules=["privilege_escalation"],
        lines=[
            "sudo: {user} : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/systemctl status nginx",
            "sudo: {user} : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash",
            "sudo: {user} : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/usr/sbin/visudo",
        ],
    ),
    "file_tampering": Scenario(
        key="file_tampering",
        name="Critical file tampering",
        description=(
            "Modifications to a harmless file (ignored), then to /etc/passwd and "
            "/etc/shadow (two separate CRITICAL alerts -- one per file). Note: unlike "
            "the other scenarios, re-running this one raises no new alerts while the "
            "first pair is still untriaged -- the watched paths are fixed, so rule "
            "deduplication correctly treats it as the same ongoing incident. Resolve "
            "the alerts, or wait out the rule's window, to see it fire again."
        ),
        expected_rules=["file_integrity"],
        lines=[
            "File integrity violation: /var/tmp/session.cache modified by {user}",
            "File integrity violation: /etc/passwd modified by {user}",
            "File integrity violation: /etc/shadow modified by {user}",
        ],
    ),
}

# The full chain runs the individual scenarios back to back, in the order
# a real intrusion unfolds: reconnaissance, then credential access, then
# escalation, then persistence.
_CHAIN_ORDER = ["port_scan", "credential_compromise", "privilege_escalation", "file_tampering"]

SCENARIOS["full_attack_chain"] = Scenario(
    key="full_attack_chain",
    name="Full attack chain",
    description=(
        "Reconnaissance -> credential access -> privilege escalation -> persistence, "
        "replayed in order. Exercises every implemented detection rule and shows the "
        "Cyber Kill Chain phases filling in as the intrusion progresses."
    ),
    expected_rules=[
        "port_scan",
        "brute_force",
        "login_after_failure",
        "privilege_escalation",
        "file_integrity",
    ],
    lines=[line for key in _CHAIN_ORDER for line in SCENARIOS[key].lines],
)


def _run_scenario(scenario: Scenario) -> None:
    """Executed in a background worker thread. Owns its own database
    session: the request's session is closed as soon as the response is
    returned, long before this finishes."""
    context = _run_context()
    db = SessionLocal()
    try:
        for index, template in enumerate(scenario.lines):
            line = template.format(**context)
            payload = LogIngestRequest(
                raw_log=line,
                hostname=TARGET_HOST,
                source="simulation",
                operating_system="Ubuntu 22.04",
                timestamp=datetime.now(timezone.utc),
                metadata={"simulated": True, "scenario": scenario.key, "step": index + 1},
            )
            try:
                ingest_log(payload, db)
            except Exception:  # noqa: BLE001 - one bad step must not abort the scenario
                logger.exception("Simulation step %s failed for scenario %s", index + 1, scenario.key)
                db.rollback()
            time.sleep(STEP_DELAY_SECONDS)
    finally:
        db.close()


@router.get("/scenarios")
def list_scenarios(_user=Depends(require_role(UserRole.ADMINISTRATOR))):
    return [
        {
            "key": scenario.key,
            "name": scenario.name,
            "description": scenario.description,
            "expected_rules": scenario.expected_rules,
            "event_count": scenario.event_count,
            "estimated_seconds": round(scenario.event_count * STEP_DELAY_SECONDS, 1),
        }
        for scenario in SCENARIOS.values()
    ]


@router.post("/run/{scenario_key}", status_code=status.HTTP_202_ACCEPTED)
def run_scenario(
    scenario_key: str,
    background_tasks: BackgroundTasks,
    _user=Depends(require_role(UserRole.ADMINISTRATOR)),
):
    scenario = SCENARIOS.get(scenario_key)
    if scenario is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown scenario '{scenario_key}'. See GET /api/simulation/scenarios.",
        )

    background_tasks.add_task(_run_scenario, scenario)

    return {
        "status": "started",
        "scenario": scenario.key,
        "name": scenario.name,
        "event_count": scenario.event_count,
        "estimated_seconds": round(scenario.event_count * STEP_DELAY_SECONDS, 1),
        # Which rules SHOULD fire -- stated up front so the demo can be
        # checked against it rather than judged by whatever appears.
        "expected_rules": scenario.expected_rules,
        "detail": "Events are streaming into the live feed now.",
    }
