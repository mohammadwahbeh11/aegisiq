-- ============================================================================
-- AegisIQ — Supabase Postgres schema (v1.0).
--
-- Idempotent: run once, or run again on a fresh Supabase project without
-- destroying data (uses IF NOT EXISTS + `create_if_needed` patterns).
--
-- Paste this whole file into Supabase Studio -> SQL Editor -> Run.
-- Then swap DATABASE_URL on Render for the Supabase connection string.
-- ============================================================================

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ----------------------------------------------------------------------------
-- Users
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id                   SERIAL PRIMARY KEY,
    username             VARCHAR(64) NOT NULL UNIQUE,
    email                VARCHAR(255) UNIQUE,
    hashed_password      TEXT NOT NULL,
    role                 VARCHAR(32) NOT NULL DEFAULT 'security_analyst',
    is_active            BOOLEAN NOT NULL DEFAULT TRUE,
    mfa_enabled          BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret_encrypted TEXT,
    backup_codes_encrypted TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at        TIMESTAMPTZ,
    CONSTRAINT users_role_check CHECK (role IN ('administrator', 'security_analyst'))
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);

-- ----------------------------------------------------------------------------
-- Detection rules
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS detection_rules (
    id              SERIAL PRIMARY KEY,
    key             VARCHAR(128) NOT NULL UNIQUE,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    severity        VARCHAR(16) NOT NULL,
    threshold_count INTEGER,
    time_window_s   INTEGER,
    mitre_id        VARCHAR(32),
    kill_chain_phase VARCHAR(64),
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    source          VARCHAR(32) NOT NULL DEFAULT 'core',
    sigma_yaml      TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT rules_severity_check CHECK (severity IN ('low', 'medium', 'high', 'critical', 'informational'))
);

-- ----------------------------------------------------------------------------
-- Log events (the high-volume table; consider partitioning past 10M rows)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS log_events (
    id            BIGSERIAL PRIMARY KEY,
    event_type    VARCHAR(64) NOT NULL,
    severity      VARCHAR(16) NOT NULL DEFAULT 'low',
    hostname      VARCHAR(255),
    source_ip     INET,
    dest_ip       INET,
    dest_port     INTEGER,
    username      VARCHAR(255),
    process       VARCHAR(255),
    raw_log       TEXT,
    normalized_data JSONB,
    collector     VARCHAR(64) DEFAULT 'agent',
    ingested_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_at      TIMESTAMPTZ,
    CONSTRAINT events_severity_check CHECK (severity IN ('low', 'medium', 'high', 'critical', 'informational'))
);
CREATE INDEX IF NOT EXISTS idx_events_ingested ON log_events (ingested_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON log_events (source_ip) WHERE source_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_severity ON log_events (severity, ingested_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_type ON log_events (event_type, ingested_at DESC);
-- Full-text-adjacent index for `LIKE '%pattern%'` on raw_log
CREATE INDEX IF NOT EXISTS idx_events_raw_trgm ON log_events USING gin (raw_log gin_trgm_ops);
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ----------------------------------------------------------------------------
-- Alerts
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id            SERIAL PRIMARY KEY,
    rule_id       INTEGER REFERENCES detection_rules (id) ON DELETE SET NULL,
    rule_name     VARCHAR(255),
    severity      VARCHAR(16) NOT NULL,
    status        VARCHAR(32) NOT NULL DEFAULT 'new',
    description   TEXT,
    source_ip     INET,
    hostname      VARCHAR(255),
    username      VARCHAR(255),
    mitre_id      VARCHAR(32),
    kill_chain_phase VARCHAR(64),
    dedup_key     VARCHAR(255),
    context       JSONB,
    raised_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at   TIMESTAMPTZ,
    resolved_by_user_id INTEGER REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT alerts_severity_check CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT alerts_status_check CHECK (status IN ('new', 'investigating', 'resolved', 'false_positive'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status, raised_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity, raised_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts (dedup_key) WHERE dedup_key IS NOT NULL;

-- ----------------------------------------------------------------------------
-- SOAR actions
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS soar_actions (
    id            SERIAL PRIMARY KEY,
    alert_id      INTEGER REFERENCES alerts (id) ON DELETE SET NULL,
    action        VARCHAR(64) NOT NULL,
    target        VARCHAR(255) NOT NULL,
    executed      BOOLEAN NOT NULL DEFAULT FALSE,
    success       BOOLEAN,
    output        TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    executed_at   TIMESTAMPTZ
);

-- ----------------------------------------------------------------------------
-- Audit log
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id           SERIAL PRIMARY KEY,
    user_id      INTEGER REFERENCES users (id) ON DELETE SET NULL,
    username     VARCHAR(64),
    action       VARCHAR(128) NOT NULL,
    target       VARCHAR(255),
    outcome      VARCHAR(32),
    source_ip    INET,
    context      JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log (user_id, created_at DESC);

-- ----------------------------------------------------------------------------
-- Row-Level Security recommendation:
-- If exposing Supabase directly to the client (bypassing FastAPI), enable RLS.
-- With FastAPI as the only client, RLS is unnecessary — Postgres role
-- authentication is enough.
-- ----------------------------------------------------------------------------
-- ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY tenant_isolation ON alerts USING (workspace_id = current_setting('app.workspace_id')::int);
