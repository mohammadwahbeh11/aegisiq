"""
Central configuration for the Lightweight SIEM backend.

All values are overridable via environment variables (see .env.example).
No secrets are hardcoded here -- defaults exist only so the app can boot
in a fresh dev environment, and DEFAULT_ADMIN_PASSWORD must be changed
after first login (see README "Default administrator account").
"""
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Repository root (backend/app/config.py -> backend/app -> backend -> root).
# Used to anchor the default SQLite path and the .env location so the app
# behaves identically no matter which directory uvicorn is launched from,
# and no matter which machine the project was copied onto.
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SQLITE_PATH = REPO_ROOT / "data" / "siem.db"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(REPO_ROOT / ".env"), extra="ignore")

    # General — v2.0 branding
    PROJECT_NAME: str = "AegisIQ"                          # commercial name
    PROJECT_TAGLINE: str = "Intelligent Shield SIEM & SOAR"
    PROJECT_VERSION: str = "2.4.2"
    ENV: str = "development"

    # Database. Absolute by default (see REPO_ROOT above) rather than the
    # old relative "sqlite:///./data/siem.db", which silently created a
    # second, empty database whenever the server was started from a
    # different working directory.
    DATABASE_URL: str = f"sqlite:///{DEFAULT_SQLITE_PATH.as_posix()}"

    # Auth / JWT
    SECRET_KEY: str = "dev-secret-key-change-me"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Default administrator account (created on first startup if no users exist)
    DEFAULT_ADMIN_USERNAME: str = "admin"
    DEFAULT_ADMIN_PASSWORD: str = "ChangeMe123!"

    # CORS - comma separated list of allowed origins. A single "*" allows
    # any origin, which is convenient on a lab network where the analyst
    # browses the console from a Kali VM whose IP changes between runs.
    CORS_ORIGINS: str = (
        "http://localhost:5173,http://127.0.0.1:5173,"
        "https://localhost:5173,https://127.0.0.1:5173"
    )

    # Resource / retention settings (used by later phases; declared now so
    # they are configurable from day one instead of hardcoded later)
    LOG_RETENTION_DAYS: int = 30
    ALERT_RETENTION_DAYS: int = 90
    MAX_DB_SIZE_MB: int = 500

    # --- v2.0 security controls ---
    # Rate limit on /api/auth/login (per source IP). Tuned for a lab:
    # a real analyst typing carefully never hits it; a script hammering
    # the endpoint does within seconds.
    RATE_LIMIT_AUTH_PER_MINUTE: int = 10
    RATE_LIMIT_AUTH_BURST: int = 5
    # Auto-logout on idle (seconds). The frontend enforces this
    # client-side; the JWT lifetime is the enforceable server ceiling.
    IDLE_TIMEOUT_SECONDS: int = 900
    # Whether the /api/audit endpoint is exposed. Off in environments
    # where audit data itself is sensitive; the row is still written to
    # the audit_log table either way.
    AUDIT_API_ENABLED: bool = True

    # --- v2.1 premium license (Log Analysis Report) ---
    # AEGIS-EDUC-6M9N-4W7X-C1AV is a demo educational key ideal for the
    # graduation panel — see docs/PREMIUM.md. Any admin can activate a
    # different key at runtime via PATCH /api/license/activate.
    PREMIUM_LICENSE_KEY: str = ""

    # --- v2.3 data-at-rest encryption (AES-256-GCM) ---
    # Master secret stretched with scrypt to a 32-byte AES key (see
    # app/security/crypto.py). MFA secrets and backup-code hashes are
    # ALWAYS encrypted with this. Left blank in dev => the app boots in
    # plaintext mode (a startup warning is logged). Set a strong random
    # value in production, e.g.  DATA_ENCRYPTION_KEY=$(openssl rand -hex 32)
    DATA_ENCRYPTION_KEY: str = ""
    # Note on log payloads: the raw_log column is deliberately NOT
    # field-encrypted, because the console's substring search
    # (LIKE/ilike) and the offline analysis both need it in the clear,
    # and the detection rules read normalized_data via SQL json_extract.
    # For whole-log-store confidentiality at rest, encrypt the storage
    # layer instead — SQLCipher for SQLite, or PostgreSQL TDE / a LUKS
    # volume. This is the same approach Splunk/Elastic use (encrypt the
    # index, keep search working). See docs/SECURITY.md § Encryption.

    # --- v2.4 pluggable event store (LogStore) ---
    # Where the high-volume LOG/EVENT stream lives. The relational tables
    # (users, rules, alerts, audit) always stay in DATABASE_URL; only the
    # event stream is pluggable, so it can scale independently.
    #   sqlalchemy  -> events in DATABASE_URL (default; the tested path)
    #   opensearch  -> events in OpenSearch (needs opensearch-py + a cluster)
    #   clickhouse  -> events in ClickHouse (needs clickhouse-connect + a server)
    # See docs/STORAGE.md for the trade-offs and the cutover checklist.
    LOG_STORE: str = "sqlalchemy"

    # OpenSearch backend
    OPENSEARCH_URL: str = "https://localhost:9200"
    OPENSEARCH_USERNAME: str = "admin"
    OPENSEARCH_PASSWORD: str = "admin"
    OPENSEARCH_INDEX: str = "aegisiq-logs"
    OPENSEARCH_VERIFY_SSL: bool = False

    # ClickHouse backend
    CLICKHOUSE_HOST: str = "localhost"
    CLICKHOUSE_PORT: int = 8123
    CLICKHOUSE_USERNAME: str = "default"
    CLICKHOUSE_PASSWORD: str = ""
    CLICKHOUSE_DATABASE: str = "aegisiq"
    CLICKHOUSE_TABLE: str = "logs"

    # --- v2.3 Sigma rule support ---
    # Directory of Sigma YAML rules. Drop community or custom .yml rules
    # here and they take effect on the next analysis — detections become
    # config, not code. Default resolves to <repo>/sigma_rules.
    SIGMA_RULES_DIR: str = str(REPO_ROOT / "sigma_rules")
    SIGMA_ENABLED: bool = True

    # --- v2.3 SOAR outbound webhook (Shuffle / Cortex / n8n) ---
    # When set, each recorded SOAR action is also POSTed to this webhook
    # so an external automation platform can run a real playbook. Blank =
    # off (record-only, as before). Signed with SOAR_WEBHOOK_SECRET via
    # HMAC-SHA256 in the X-AegisIQ-Signature header if the secret is set.
    SOAR_WEBHOOK_URL: str = ""
    SOAR_WEBHOOK_SECRET: str = ""
    SOAR_WEBHOOK_TIMEOUT_SECONDS: float = 4.0

    # --- v2.3 multi-factor authentication (TOTP, RFC 6238) ---
    # When true, users who have enrolled a TOTP authenticator must supply
    # a 6-digit code (or a backup code) at login. Users who have not yet
    # enrolled can still log in with password alone unless MFA_REQUIRED.
    MFA_ENABLED: bool = True
    # When true, EVERY user must have MFA enrolled — password-only logins
    # are refused with a "must enrol MFA" challenge. Off by default so the
    # first admin can log in and set MFA up.
    MFA_REQUIRED: bool = False
    # Issuer label shown in the authenticator app (Google Authenticator,
    # Authy, 1Password, …) next to the account.
    MFA_ISSUER: str = "AegisIQ"
    # Accepted clock drift: how many 30-second steps before/after now a
    # code is still valid. 1 => ±30 s, the RFC 6238 recommended window.
    MFA_TOTP_WINDOW: int = 1

    # --- SOAR (automated response) ---
    # When enabled, high/critical alerts record a containment action.
    # SOAR_EXECUTE=false means actions are RECORDED but never actually
    # executed against a host -- see app/soar/engine.py. There is no code
    # path in this project that runs a real firewall command; setting
    # SOAR_EXECUTE=true only marks actions as intended-for-execution so a
    # real executor can be plugged in later without changing the schema.
    SOAR_ENABLED: bool = True
    SOAR_EXECUTE: bool = False

    # --- Optional Wazuh integration ---
    # Left blank => the integration reports "not_configured" instead of
    # pretending a manager is connected (app/integrations/wazuh.py).
    WAZUH_URL: str = ""
    WAZUH_USERNAME: str = ""
    WAZUH_PASSWORD: str = ""
    WAZUH_VERIFY_SSL: bool = False
    WAZUH_TIMEOUT_SECONDS: float = 5.0

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @property
    def wazuh_configured(self) -> bool:
        return bool(self.WAZUH_URL.strip())

    @property
    def is_production(self) -> bool:
        return self.ENV.strip().lower() in ("production", "prod")


# Insecure defaults that are fine for a local demo but must never survive
# into a networked/production deployment.
_INSECURE_SECRET_KEYS = {"dev-secret-key-change-me", "", "changeme", "secret"}
_INSECURE_ADMIN_PASSWORDS = {"ChangeMe123!", "", "admin", "password", "changeme"}


def validate_production_security(settings: "Settings") -> list[str]:
    """Return a list of fatal misconfigurations for a production boot.

    Empty list = safe to start. This is the guardrail that stops the app
    shipping to a network with the demo SECRET_KEY / admin password /
    wide-open CORS still in place — the classic way a lab tool becomes an
    incident. Only enforced when ENV=production; dev/lab boots freely.
    """
    problems: list[str] = []
    if not settings.is_production:
        return problems

    if settings.SECRET_KEY.strip() in _INSECURE_SECRET_KEYS or len(settings.SECRET_KEY) < 32:
        problems.append(
            "SECRET_KEY is the demo default or too short (<32 chars). "
            "Generate one: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
        )
    if settings.DEFAULT_ADMIN_PASSWORD.strip() in _INSECURE_ADMIN_PASSWORDS:
        problems.append(
            "DEFAULT_ADMIN_PASSWORD is the demo default. Set a strong "
            "DEFAULT_ADMIN_PASSWORD before first boot (and change it after login)."
        )
    if not settings.DATA_ENCRYPTION_KEY.strip():
        problems.append(
            "DATA_ENCRYPTION_KEY is not set — MFA secrets would be stored in "
            "plaintext. Set it: DATA_ENCRYPTION_KEY=$(openssl rand -hex 32)"
        )
    if "*" in settings.CORS_ORIGINS:
        problems.append(
            "CORS_ORIGINS contains '*' (any origin). Pin it to the console's "
            "exact origin(s) in production."
        )
    if settings.MFA_ENABLED and not settings.MFA_REQUIRED:
        # Not fatal, but strongly recommended — surfaced as a warning by
        # the caller, not a hard stop.
        pass
    return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()
