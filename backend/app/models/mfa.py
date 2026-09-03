"""
app/models/mfa.py -- per-user multi-factor authentication state
(AegisIQ v2.3).

Kept in its own table (1:1 with users) rather than columns on `users`
so that:
  * the sensitive secret + backup codes live together and are easy to
    wipe on MFA reset without touching the user row;
  * a user with no MFA simply has no row (NULL-free model);
  * the encryption applies to a small, well-scoped table.

The TOTP secret and the backup-code hashes are stored with
EncryptedString → AES-256-GCM at rest (app/security/crypto.py). Backup
codes are additionally only ever stored HASHED (sha256 via
crypto.hash_lookup) — the plaintext is shown to the user exactly once at
enrolment and never persisted, so a database dump can neither replay
TOTP nor use a backup code.
"""
from __future__ import annotations

import enum
import json
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base
from app.security.crypto import EncryptedString


class MfaStatus(str, enum.Enum):
    DISABLED = "disabled"     # no MFA configured
    PENDING = "pending"       # secret issued, first code not yet confirmed
    ACTIVE = "active"         # confirmed and enforced at login


class UserMFA(Base):
    __tablename__ = "user_mfa"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False, index=True)

    status = Column(Enum(MfaStatus), nullable=False, default=MfaStatus.DISABLED)

    # AES-256-GCM encrypted at rest. String(512) leaves head-room for the
    # v1:<base64> envelope around a 32-char base32 secret.
    secret_enc = Column(EncryptedString(512), nullable=True)

    # JSON array of sha256 hashes of the remaining (unused) backup codes,
    # itself encrypted at rest. We store hashes, not the codes.
    backup_codes_enc = Column(EncryptedString(4096), nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    confirmed_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)

    user = relationship("User")

    # ── helpers for the backup-code list (stored as a JSON array) ──────
    def load_backup_hashes(self) -> list[str]:
        if not self.backup_codes_enc:
            return []
        try:
            data = json.loads(self.backup_codes_enc)
            return data if isinstance(data, list) else []
        except (json.JSONDecodeError, TypeError):
            return []

    def store_backup_hashes(self, hashes: list[str]) -> None:
        self.backup_codes_enc = json.dumps(hashes)
