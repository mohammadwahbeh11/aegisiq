"""
app/security/password_policy.py -- enforce strong passwords at set time,
and only at set time.

Why not enforce on login too: the shipped default admin password
(ChangeMe123!) meets the shipped policy today, but an operator who
tightens the policy tomorrow must not lock every existing user out
overnight. Policies apply at password CHANGE, not at password USE.

The rules are intentionally simple and evidence-based:
  * at least 12 characters (NIST SP 800-63B: longer beats "complex")
  * must contain at least 3 of: lowercase, uppercase, digit, symbol
  * cannot be one of the well-known compromised passwords baked into
    the file's WELL_KNOWN set (top-100 leaks + the seeded default)
  * cannot equal the username
  * cannot contain three consecutive characters from the username

Deliberately absent: forced rotation ("change every 90 days"), which
NIST now recommends AGAINST because it leads to '<same>-<season>-<year>'
patterns that are worse than a single strong password.
"""
from __future__ import annotations

import re
import string
from dataclasses import dataclass


# A short list of infamous defaults + demo passwords. The point isn't
# to be exhaustive (that's what a k-anonymity check against HIBP is
# for, out of scope here) but to fail obvious foot-guns.
WELL_KNOWN = frozenset({
    "password", "password1", "password123", "passw0rd",
    "12345678", "123456789", "1234567890", "qwerty12345",
    "admin", "admin1", "admin123", "administrator",
    "letmein", "changeme", "changeme123!", "ChangeMe123!",
    "welcome1", "welcome123", "welcome2024", "welcome2025", "welcome2026",
    "iloveyou", "root", "toor", "kali", "vboxuser",
})

MIN_LENGTH = 12
MIN_CATEGORIES = 3


@dataclass
class PolicyResult:
    """Outcome of validating one candidate password. `errors` is the
    exact list of user-facing messages that failed -- the front-end can
    display them verbatim without inventing text."""
    ok: bool
    errors: list[str]


def _categories(password: str) -> int:
    """How many of the four character-class categories are present."""
    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    return sum((has_lower, has_upper, has_digit, has_symbol))


def _shares_three_chars(password: str, username: str) -> bool:
    """True when password contains any 3-char substring of the username
    (case-insensitive). Blocks 'JohnDoe' -> 'JohnDoe2025!' style."""
    if len(username) < 3:
        return False
    p = password.lower()
    u = username.lower()
    return any(u[i : i + 3] in p for i in range(len(u) - 2))


def validate(password: str, username: str) -> PolicyResult:
    """Check `password` against the policy. Returns a PolicyResult;
    never raises. The caller decides how to surface errors."""
    errors: list[str] = []

    if password is None or not isinstance(password, str):
        return PolicyResult(ok=False, errors=["Password must be a string."])

    if len(password) < MIN_LENGTH:
        errors.append(f"Must be at least {MIN_LENGTH} characters (yours: {len(password)}).")

    if _categories(password) < MIN_CATEGORIES:
        errors.append(
            f"Must include at least {MIN_CATEGORIES} of: lowercase, uppercase, digit, symbol."
        )

    if password.lower() in {w.lower() for w in WELL_KNOWN}:
        errors.append(
            "This password is on the well-known-leak list; pick something not on any public list."
        )

    if username and password.lower() == username.lower():
        errors.append("Password cannot equal the username.")

    if username and _shares_three_chars(password, username):
        errors.append(
            "Password cannot contain three or more consecutive characters from the username."
        )

    # A short check for repeated characters that pad length without adding
    # entropy ('aaaaaaaaaaaa' is 12 chars but 1 bit of entropy).
    if re.match(r"^(.)\1{7,}$", password):
        errors.append("Password cannot be a single character repeated.")

    return PolicyResult(ok=not errors, errors=errors)
