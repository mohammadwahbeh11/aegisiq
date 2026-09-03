"""
app/security/crypto.py -- AES-256-GCM envelope encryption for
data-at-rest (AegisIQ v2.3).

Why this design
---------------
* **AES-256-GCM** is an AEAD cipher: it encrypts AND authenticates in
  one pass, so a tampered ciphertext fails to decrypt rather than
  silently returning garbage. This is the NIST SP 800-38D recommended
  mode and is FIPS-approved. (We do not claim FIPS *validation* — see
  docs/COMPLIANCE.md — only that the algorithm is the approved one.)
* **Per-value random 96-bit nonce.** GCM's security collapses if a
  (key, nonce) pair is ever reused, so every encryption draws a fresh
  12-byte nonce from `os.urandom` and stores it alongside the
  ciphertext. 96 bits is the size GCM is optimised for (SP 800-38D §5.2.1.1).
* **Key derivation with scrypt.** The operator supplies a master secret
  in the `DATA_ENCRYPTION_KEY` environment variable (any length /
  entropy). We stretch it to a 32-byte AES key with scrypt
  (N=2^15, r=8, p=1) — memory-hard, so a leaked env value is far more
  expensive to brute-force than a bare SHA-256 would be. The salt is
  fixed and application-scoped so the same env value always derives the
  same key (deterministic — required for a database that must decrypt
  what a previous process wrote). Rotating the env value re-keys the
  data set; a migration helper would re-encrypt in place.
* **Versioned wire format.** Stored blobs are
  ``v1:<base64(nonce||ciphertext||tag)>``. The ``v1:`` prefix lets a
  future algorithm change coexist with old rows, and lets the decrypt
  path recognise "this value is not encrypted" (legacy plaintext rows
  written before encryption was enabled) and pass them through instead
  of throwing.

What it is used for
-------------------
* Always-on: TOTP/MFA secrets and backup-code hashes (never searched,
  so transparent encryption is free of downside) — see app/models/mfa.py.
* Optional (config ENCRYPT_LOG_PAYLOAD): the log `raw_log` and
  `normalized_data` columns. OFF by default because encrypting them
  breaks the SQL ``LIKE`` search the console relies on; when ON, search
  falls back to decrypt-then-filter in Python (documented, slower). For
  full log-store confidentiality at rest most deployments should instead
  use SQLCipher (SQLite) or PostgreSQL TDE / a LUKS volume — documented
  in docs/SECURITY.md.

Fail-safe
---------
If `DATA_ENCRYPTION_KEY` is unset, the module runs in a clearly-labelled
"no-encryption" mode: `encrypt()` returns the plaintext unchanged and
`is_enabled()` is False, so the app still boots in a dev/lab setting
without a key. Production is expected to set the key; a startup log
warns when it is absent.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
from functools import lru_cache

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import get_settings

logger = logging.getLogger(__name__)

_PREFIX = "v1:"
_NONCE_BYTES = 12  # 96-bit nonce — GCM-optimal (NIST SP 800-38D §5.2.1.1)
_KEY_BYTES = 32    # AES-256

# Application-scoped scrypt salt. Fixed on purpose: key derivation must be
# deterministic so a value encrypted by one process decrypts in the next.
# The master secret in the env var is the actual secret; this salt only
# domain-separates AegisIQ's KDF from any other use of the same passphrase.
_KDF_SALT = b"AegisIQ/v1/data-at-rest/scrypt"


@lru_cache(maxsize=1)
def _derive_key() -> bytes | None:
    """Stretch DATA_ENCRYPTION_KEY to a 32-byte AES key with scrypt, or
    return None when no key is configured (no-encryption mode)."""
    settings = get_settings()
    master = (getattr(settings, "DATA_ENCRYPTION_KEY", "") or "").encode("utf-8")
    if not master:
        return None
    # N=2^15 (32768), r=8, p=1 — OWASP-recommended interactive scrypt
    # parameters; ~30 ms and ~32 MB per derivation, done once per process.
    # maxmem must be raised above OpenSSL's ~32 MB default ceiling, which
    # these parameters (128*N*r ≈ 32 MB) sit right at — 64 MB gives head-room.
    return hashlib.scrypt(
        master, salt=_KDF_SALT, n=32768, r=8, p=1,
        dklen=_KEY_BYTES, maxmem=64 * 1024 * 1024,
    )


def is_enabled() -> bool:
    """True when a DATA_ENCRYPTION_KEY is configured and encryption is
    active. False = the app boots in plaintext dev/lab mode."""
    return _derive_key() is not None


def encrypt(plaintext: str | None) -> str | None:
    """Encrypt a string for storage. Returns the ``v1:...`` token, or the
    input unchanged when encryption is disabled or the value is None/empty.

    Idempotent-safe: an already-encrypted value (``v1:`` prefix) is
    returned as-is rather than double-encrypted."""
    if plaintext is None or plaintext == "":
        return plaintext
    if plaintext.startswith(_PREFIX):
        return plaintext  # already encrypted
    key = _derive_key()
    if key is None:
        return plaintext  # no-encryption mode
    nonce = os.urandom(_NONCE_BYTES)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    blob = base64.b64encode(nonce + ct).decode("ascii")
    return _PREFIX + blob


def decrypt(stored: str | None) -> str | None:
    """Inverse of encrypt(). A value without the ``v1:`` prefix is treated
    as legacy plaintext and returned unchanged, so enabling encryption on
    a database that already has plaintext rows never breaks reads.

    A ``v1:`` value that fails authentication (wrong key, tampering)
    raises ValueError — callers that must not hard-fail should catch it."""
    if stored is None or stored == "":
        return stored
    if not stored.startswith(_PREFIX):
        return stored  # legacy plaintext row
    key = _derive_key()
    if key is None:
        # A v1: value exists but no key is configured — cannot read it.
        raise ValueError(
            "Encrypted value found but DATA_ENCRYPTION_KEY is not set. "
            "Set the same key that was used to write this data."
        )
    try:
        raw = base64.b64decode(stored[len(_PREFIX):].encode("ascii"))
        nonce, ct = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]
        return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
    except Exception as exc:  # noqa: BLE001 - re-raise as a clean error
        raise ValueError(f"Failed to decrypt value: {exc}") from exc


def hash_lookup(value: str) -> str:
    """A deterministic, non-reversible SHA-256 hex digest of a value,
    salted with the derived key when available. Used for equality lookup
    on encrypted columns (e.g. "does this backup code match?") without
    storing the plaintext. NOT used for passwords — those use bcrypt."""
    key = _derive_key() or b""
    return hashlib.sha256(key + value.encode("utf-8")).hexdigest()


# ─────────────────────────────────────────────────────────────────────
# SQLAlchemy TypeDecorator — transparent column encryption
# ─────────────────────────────────────────────────────────────────────
try:
    from sqlalchemy.types import String, TypeDecorator

    class EncryptedString(TypeDecorator):
        """A String column whose value is AES-256-GCM encrypted on the way
        into the database and decrypted on the way out — transparently to
        the ORM. Use for small, never-searched sensitive fields (secrets,
        tokens). Do NOT use for columns you run ``LIKE`` / ``ilike`` on:
        the stored form is ciphertext, so substring search won't match.

        When DATA_ENCRYPTION_KEY is unset the column stores plaintext, so
        the app still works in dev; enabling the key later transparently
        starts encrypting new writes while old plaintext rows still read
        (decrypt() passes non-prefixed values through)."""

        impl = String
        cache_ok = True

        def process_bind_param(self, value, dialect):
            return encrypt(value)

        def process_result_value(self, value, dialect):
            try:
                return decrypt(value)
            except ValueError:
                logger.exception("EncryptedString: failed to decrypt a column value")
                return None

except Exception:  # pragma: no cover - SQLAlchemy always present in app
    EncryptedString = None  # type: ignore
