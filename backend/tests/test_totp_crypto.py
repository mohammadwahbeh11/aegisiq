"""
tests/test_totp_crypto.py -- v2.3 security primitives.

Two things must be provably correct because everything else trusts them:
  1. TOTP interoperates with real authenticator apps  → validate against
     the official RFC 6238 Appendix-B test vectors.
  2. AES-256-GCM encryption round-trips and rejects tampering.

These tests use no database and no FastAPI, so they run even in a
minimal environment.
"""
import base64
import importlib
import os

import pytest


# ─── TOTP (RFC 6238) ─────────────────────────────────────────────────
from app.security import totp


# RFC 6238 Appendix B publishes 8-digit SHA-1 codes for the ASCII seed
# "12345678901234567890". Authenticator apps use 6 digits, which is the
# last 6 of the published value.
_RFC_SEED_B32 = base64.b32encode(b"12345678901234567890").decode()
_RFC_VECTORS = [
    (59,          "287082"),
    (1111111109,  "081804"),
    (1111111111,  "050471"),
    (1234567890,  "005924"),
    (2000000000,  "279037"),
    (20000000000, "353130"),
]


@pytest.mark.parametrize("t,expected", _RFC_VECTORS)
def test_totp_matches_rfc6238_vectors(t, expected):
    assert totp.now_code(_RFC_SEED_B32, at=t) == expected


def test_totp_verify_accepts_current_and_drift():
    at = 1111111109
    code = totp.now_code(_RFC_SEED_B32, at=at)
    assert totp.verify(_RFC_SEED_B32, code, window=1, at=at)
    # previous step still accepted within window=1
    prev = totp.now_code(_RFC_SEED_B32, at=at - 30)
    assert totp.verify(_RFC_SEED_B32, prev, window=1, at=at)


def test_totp_verify_rejects_wrong_and_out_of_window():
    at = 1111111109
    assert totp.verify(_RFC_SEED_B32, "000000", at=at) is False
    far = totp.now_code(_RFC_SEED_B32, at=at - 300)   # 10 steps ago
    assert totp.verify(_RFC_SEED_B32, far, window=1, at=at) is False


def test_secret_and_backup_codes_shapes():
    assert len(totp.generate_secret()) >= 16
    codes = totp.generate_backup_codes(10)
    assert len(codes) == 10
    assert all("-" in c and len(c) == 9 for c in codes)


def test_provisioning_uri_is_scannable():
    uri = totp.provisioning_uri(_RFC_SEED_B32, "admin", "AegisIQ")
    assert uri.startswith("otpauth://totp/AegisIQ")
    assert "secret=" in uri and "issuer=AegisIQ" in uri


# ─── AES-256-GCM at rest ─────────────────────────────────────────────
def _fresh_crypto(monkeypatch, key: str):
    """Reload the crypto module with a given DATA_ENCRYPTION_KEY so the
    lru_cache on the derived key is rebuilt for each scenario."""
    from app.config import get_settings
    get_settings.cache_clear()
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", key)
    from app.security import crypto as crypto_mod
    importlib.reload(crypto_mod)
    return crypto_mod


def test_encrypt_roundtrip(monkeypatch):
    crypto = _fresh_crypto(monkeypatch, "unit-test-master-key")
    assert crypto.is_enabled() is True
    token = crypto.encrypt("JBSWY3DPEHPK3PXP")
    assert token.startswith("v1:")
    assert crypto.decrypt(token) == "JBSWY3DPEHPK3PXP"


def test_encrypt_is_idempotent_and_handles_empty(monkeypatch):
    crypto = _fresh_crypto(monkeypatch, "unit-test-master-key")
    tok = crypto.encrypt("secret")
    assert crypto.encrypt(tok) == tok            # already-encrypted passthrough
    assert crypto.encrypt("") == ""
    assert crypto.encrypt(None) is None


def test_legacy_plaintext_passthrough(monkeypatch):
    crypto = _fresh_crypto(monkeypatch, "unit-test-master-key")
    # A value written before encryption was enabled has no v1: prefix.
    assert crypto.decrypt("plain-old-value") == "plain-old-value"


def test_tamper_is_rejected(monkeypatch):
    crypto = _fresh_crypto(monkeypatch, "unit-test-master-key")
    forged = "v1:" + base64.b64encode(os.urandom(40)).decode()
    with pytest.raises(ValueError):
        crypto.decrypt(forged)


def test_no_key_mode_is_plaintext(monkeypatch):
    crypto = _fresh_crypto(monkeypatch, "")
    assert crypto.is_enabled() is False
    assert crypto.encrypt("x") == "x"            # dev/lab: no encryption
