"""
app/security/totp.py -- RFC 6238 TOTP + RFC 4226 HOTP, pure standard
library (AegisIQ v2.3 multi-factor authentication).

Why implemented from the standard library rather than a dependency
-----------------------------------------------------------------
The project's design principle is minimal dependencies for a
"lightweight" SIEM (see docs/architecture.md). TOTP is ~40 lines of
`hmac` + `struct` and is fully specified by two short RFCs, so pulling
in a third-party package would add supply-chain surface for no benefit.
The implementation is validated against the official RFC 6238
Appendix-B test vectors in tests/test_totp.py — so we know it
interoperates with Google Authenticator, Authy, 1Password, Microsoft
Authenticator, and every other standard TOTP app.

Algorithm choices
------------------
* **HMAC-SHA1, 6 digits, 30-second period.** These are the de-facto
  defaults every authenticator app assumes when it scans a bare
  ``otpauth://`` URI. RFC 6238 permits SHA-256/SHA-512 and other digit
  counts, but almost no consumer app supports them, so using the
  defaults maximises interoperability. SHA-1 here is a MAC, not a
  collision-sensitive hash, so its collision weaknesses do not apply.
* **Base32 secret, 160 bits.** RFC 4648 base32 is what the otpauth URI
  and every authenticator expects. 160 bits (20 bytes) matches the
  HMAC-SHA1 block relationship and the RFC test vectors.
* **Verification window ±1 step (configurable).** Accepts the code for
  the previous, current, and next 30-second step to tolerate clock
  drift between the server and the phone — the RFC 6238 §5.2
  recommendation.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
import urllib.parse

_DIGITS = 6
_PERIOD = 30
_SECRET_BYTES = 20  # 160-bit, per RFC 4226 / 6238 test vectors


def generate_secret() -> str:
    """A fresh random base32 secret (no padding) for a new enrolment."""
    return base64.b32encode(os.urandom(_SECRET_BYTES)).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int, digits: int = _DIGITS) -> str:
    """RFC 4226 HOTP — the primitive TOTP is built on."""
    # base32 decode is case-insensitive and needs padding to a multiple of 8.
    padded = secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded)
    msg = struct.pack(">Q", counter)                      # 8-byte big-endian counter
    digest = hmac.new(key, msg, hashlib.sha1).digest()    # HMAC-SHA1
    offset = digest[-1] & 0x0F                             # dynamic truncation
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10 ** digits)).zfill(digits)


def now_code(secret_b32: str, at: float | None = None) -> str:
    """The TOTP code valid right now (or at a given epoch time)."""
    t = int((at if at is not None else time.time()) // _PERIOD)
    return _hotp(secret_b32, t)


def verify(secret_b32: str, code: str, window: int = 1, at: float | None = None) -> bool:
    """True if `code` matches any step within ±`window` of now.

    Uses hmac.compare_digest for the final comparison so a matching
    attempt is not distinguishable from a non-matching one by timing.
    """
    if not code or not code.strip().isdigit():
        return False
    code = code.strip()
    t = int((at if at is not None else time.time()) // _PERIOD)
    for drift in range(-window, window + 1):
        candidate = _hotp(secret_b32, t + drift)
        if hmac.compare_digest(candidate, code):
            return True
    return False


def provisioning_uri(secret_b32: str, account_name: str, issuer: str) -> str:
    """Build the ``otpauth://totp/...`` URI an authenticator app scans
    (or that a password manager accepts pasted). Format per the Key Uri
    spec used by Google Authenticator."""
    label = urllib.parse.quote(f"{issuer}:{account_name}")
    params = urllib.parse.urlencode({
        "secret": secret_b32,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": _DIGITS,
        "period": _PERIOD,
    })
    return f"otpauth://totp/{label}?{params}"


# ─────────────────────────────────────────────────────────────────────
# Backup / recovery codes
# ─────────────────────────────────────────────────────────────────────
def generate_backup_codes(count: int = 10) -> list[str]:
    """One-time recovery codes for when the phone is lost. Formatted
    xxxx-xxxx from a URL-safe alphabet, easy to read and type."""
    codes: list[str] = []
    for _ in range(count):
        raw = base64.b32encode(os.urandom(5)).decode("ascii").rstrip("=").lower()[:8]
        codes.append(f"{raw[:4]}-{raw[4:8]}")
    return codes
