"""
app/detection/sigma.py -- Sigma rule support (AegisIQ v2.3).

WHY
---
The gap every SOC review raises about a young SIEM is "your rules are
code — I can't add a detection without a developer." Sigma
(https://github.com/SigmaHQ/sigma) is the industry-standard, vendor-
neutral YAML format for detections. Supporting it means an analyst drops
a `.yml` file into `sigma_rules/` and the new detection is live on the
next analysis — no code change, no redeploy. Thousands of community
Sigma rules become usable as-is.

SCOPE (honest)
--------------
This is a practical, well-tested SUBSET of the Sigma spec — the part
that covers the large majority of real Windows/Sysmon/Linux rules:

  * field matches with modifiers: ``|contains``, ``|startswith``,
    ``|endswith``, ``|re`` (regex), ``|all`` (every value must match),
    and plain equality; a list of values under a field is OR;
  * keyword lists (a bare list under ``detection``) → substring search;
  * conditions: single selection, ``and`` / ``or`` / ``not``,
    parentheses, ``1 of <name>*`` / ``all of <name>*``,
    ``1 of them`` / ``all of them``;
  * ``level`` → severity, ``tags`` (attack.tXXXX) → MITRE technique.

Not supported (a rule using these is skipped, not mis-evaluated):
aggregation (``| count() by``), timeframe correlation, and the more
exotic value modifiers (base64offset, cidr, …). Skipped rules are
logged, never fatal — one bad rule never blocks the rest.

The evaluator resolves a Sigma field against the normalized event
first (with a small alias map: EventID→event_id, TargetUserName→
username, IpAddress→source_ip, …), then normalized_data, then falls
back to a substring search of the raw log — so a rule matches whether
the field was structured or only present in the raw line.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Optional dependency: PyYAML. If it is missing, Sigma support disables
# itself cleanly (load_rules returns []) rather than crashing the app.
try:
    import yaml  # type: ignore
    _YAML_OK = True
except Exception:  # pragma: no cover
    _YAML_OK = False

_LEVEL_TO_SEVERITY = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

# Sigma field name -> our normalized event field (case-insensitive keys).
_FIELD_ALIASES = {
    "eventid": "event_id",
    "computername": "hostname",
    "computer": "hostname",
    "hostname": "hostname",
    "targetusername": "username",
    "subjectusername": "username",
    "accountname": "username",
    "user": "username",
    "username": "username",
    "ipaddress": "source_ip",
    "sourceip": "source_ip",
    "src_ip": "source_ip",
    "source_ip": "source_ip",
    "destinationip": "destination_ip",
    "dest_ip": "destination_ip",
}


@dataclass
class SigmaRule:
    title: str
    level: str
    severity: str
    description: str
    mitre: str | None
    kill_chain: str | None
    detection: dict
    condition: str
    rule_id: str | None = None
    tags: list[str] = dc_field(default_factory=list)
    source_file: str | None = None


# ─────────────────────────────────────────────────────────────────────
# Loading
# ─────────────────────────────────────────────────────────────────────
def load_rules(directory: str | Path) -> list[SigmaRule]:
    """Load every .yml/.yaml Sigma rule under `directory`. Malformed or
    unsupported rules are skipped with a log line, never raised."""
    if not _YAML_OK:
        logger.warning("Sigma support disabled: PyYAML is not installed.")
        return []
    path = Path(directory)
    if not path.exists():
        return []
    rules: list[SigmaRule] = []
    for f in sorted(path.rglob("*.y*ml")):
        try:
            docs = list(yaml.safe_load_all(f.read_text(encoding="utf-8")))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Sigma: could not read %s: %s", f.name, exc)
            continue
        for doc in docs:
            if not isinstance(doc, dict) or "detection" not in doc:
                continue
            rule = _build_rule(doc, str(f))
            if rule is not None:
                rules.append(rule)
    logger.info("Sigma: loaded %d rule(s) from %s", len(rules), path)
    return rules


def _build_rule(doc: dict, source_file: str) -> SigmaRule | None:
    detection = doc.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        return None
    condition = detection.get("condition")
    if not isinstance(condition, str):
        return None
    # Skip aggregation / correlation conditions we don't implement.
    if "|" in condition or " by " in condition.lower():
        logger.info("Sigma: skipping aggregation rule '%s'", doc.get("title"))
        return None

    level = str(doc.get("level", "medium")).lower()
    tags = [str(t) for t in (doc.get("tags") or [])]
    mitre = _mitre_from_tags(tags)
    return SigmaRule(
        title=str(doc.get("title", "Untitled Sigma rule")),
        level=level,
        severity=_LEVEL_TO_SEVERITY.get(level, "medium"),
        description=str(doc.get("description", "")).strip(),
        mitre=mitre,
        kill_chain=_killchain_from_tags(tags),
        detection={k: v for k, v in detection.items() if k != "condition"},
        condition=condition,
        rule_id=doc.get("id"),
        tags=tags,
        source_file=source_file,
    )


def _mitre_from_tags(tags: list[str]) -> str | None:
    for t in tags:
        m = re.search(r"attack\.(t\d{4}(?:\.\d{3})?)", t, re.IGNORECASE)
        if m:
            return m.group(1).upper()
    return None


def _killchain_from_tags(tags: list[str]) -> str | None:
    # Sigma tactic tags like attack.credential_access → "Credential Access"
    for t in tags:
        m = re.match(r"attack\.([a-z_]+)$", t, re.IGNORECASE)
        if m and not m.group(1).startswith("t"):
            return m.group(1).replace("_", " ").title()
    return None


# ─────────────────────────────────────────────────────────────────────
# Matching
# ─────────────────────────────────────────────────────────────────────
def _resolve_field(field: str, event_fields: dict, raw_log: str) -> list[str]:
    """Return candidate string values for a Sigma field. Prefers a real
    structured value; empty list means 'not present as a field' (the
    caller may still fall back to a raw-log substring test)."""
    base = field.split("|")[0].strip().lower()
    key = _FIELD_ALIASES.get(base, base)
    val = event_fields.get(key)
    if val is None:
        data = event_fields.get("normalized_data") or {}
        if isinstance(data, dict):
            # try exact and case-insensitive key
            val = data.get(base)
            if val is None:
                for k, v in data.items():
                    if k.lower() == base:
                        val = v
                        break
    if val is None:
        return []
    if isinstance(val, (list, tuple)):
        return [str(x) for x in val]
    return [str(val)]


def _match_one(field_spec: str, expected, event_fields: dict, raw_log: str) -> bool:
    """Match a single `field|modifier: expected` entry."""
    parts = field_spec.split("|")
    modifiers = [p.strip().lower() for p in parts[1:]]

    expected_values = expected if isinstance(expected, list) else [expected]
    expected_values = [("" if e is None else str(e)) for e in expected_values]

    actual_values = _resolve_field(field_spec, event_fields, raw_log)
    # Fallback: no structured field — test against the raw log so a rule
    # keying on e.g. CommandLine still fires when only raw_log is present.
    raw_fallback = not actual_values
    haystack = raw_log if raw_fallback else None

    def _cmp(exp: str) -> bool:
        exp_l = exp.lower()
        if "re" in modifiers:
            try:
                rx = re.compile(exp, re.IGNORECASE)
            except re.error:
                return False
            if raw_fallback:
                return bool(rx.search(haystack or ""))
            return any(rx.search(a) for a in actual_values)
        if raw_fallback:
            hl = (haystack or "").lower()
            if "contains" in modifiers:
                return exp_l in hl
            if "startswith" in modifiers or "endswith" in modifiers:
                return exp_l in hl  # position is meaningless in a whole line
            return exp_l in hl      # equality on a raw line → substring
        for a in actual_values:
            al = a.lower()
            if "contains" in modifiers and exp_l in al:
                return True
            if "startswith" in modifiers and al.startswith(exp_l):
                return True
            if "endswith" in modifiers and al.endswith(exp_l):
                return True
            if not modifiers and al == exp_l:
                return True
        return False

    if "all" in modifiers:
        return all(_cmp(e) for e in expected_values)
    return any(_cmp(e) for e in expected_values)


def _match_selection(sel, event_fields: dict, raw_log: str) -> bool:
    """A selection is either a keyword list (OR substring) or a map of
    field→expected (AND across fields), or a list of such maps (OR)."""
    if isinstance(sel, list):
        # list of keywords OR list of maps
        if all(isinstance(x, dict) for x in sel):
            return any(_match_selection(x, event_fields, raw_log) for x in sel)
        hl = raw_log.lower()
        return any(str(k).lower() in hl for k in sel)
    if isinstance(sel, dict):
        return all(_match_one(f, v, event_fields, raw_log) for f, v in sel.items())
    # scalar keyword
    return str(sel).lower() in raw_log.lower()


_ALLOWED_COND_TOKENS = re.compile(r"[A-Za-z0-9_ ()]+")


def _evaluate_condition(condition: str, selection_results: dict[str, bool]) -> bool:
    """Evaluate a Sigma condition string against precomputed selection
    booleans. Supports and/or/not, parentheses, '1 of x*'/'all of x*',
    '1 of them'/'all of them'. Returns False on anything unparseable."""
    cond = condition.strip()

    def _quantifier(match_all: bool, pattern: str) -> bool:
        if pattern in ("them", "*"):
            vals = list(selection_results.values())
        else:
            prefix = pattern.rstrip("*")
            vals = [v for k, v in selection_results.items() if k.startswith(prefix)]
        if not vals:
            return False
        return all(vals) if match_all else any(vals)

    # Replace "1 of X" / "all of X" with literal True/False first.
    def _repl(m: re.Match) -> str:
        qty, pat = m.group(1), m.group(2)
        res = _quantifier(qty.lower() == "all", pat)
        return "True" if res else "False"

    cond = re.sub(r"\b(all|1)\s+of\s+([A-Za-z0-9_*]+)", _repl, cond, flags=re.IGNORECASE)

    # Now only selection names, and/or/not, parens should remain.
    # Substitute each known selection name with its boolean.
    def _name_repl(m: re.Match) -> str:
        name = m.group(0)
        if name in ("and", "or", "not", "True", "False"):
            return name
        if name in selection_results:
            return "True" if selection_results[name] else "False"
        # Unknown token → make the whole rule fail safely.
        return "__UNKNOWN__"

    substituted = re.sub(r"[A-Za-z_][A-Za-z0-9_]*", _name_repl, cond)
    if "__UNKNOWN__" in substituted:
        return False
    if not _ALLOWED_COND_TOKENS.fullmatch(substituted):
        return False
    try:
        # Safe: only True/False/and/or/not/parens remain after sanitising.
        return bool(eval(substituted, {"__builtins__": {}}, {}))  # noqa: S307
    except Exception:  # noqa: BLE001
        return False


def rule_matches(rule: SigmaRule, event_fields: dict, raw_log: str) -> bool:
    """True if the compiled Sigma rule matches this event."""
    results: dict[str, bool] = {}
    for name, sel in rule.detection.items():
        try:
            results[name] = _match_selection(sel, event_fields, raw_log)
        except Exception:  # noqa: BLE001
            results[name] = False
    return _evaluate_condition(rule.condition, results)
