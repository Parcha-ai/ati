-- Initial schema for ATI persistence layer.
--
-- Four tables:
--   ati_keys          — virtual keys with scopes + TTL
--   ati_deleted_keys  — soft-delete archive of revoked keys (snapshot as JSONB)
--   ati_call_log      — per-request audit row (proxy-side)
--   ati_audit_log     — admin mutations (key.create / key.revoke / etc.)
--
-- All tables are optional: if ATI_DB_URL is unset, the proxy never touches them.
-- Migrations are versioned by the timestamp prefix on the filename and tracked
-- in the `_sqlx_migrations` table that sqlx::migrate! creates automatically.
--
-- Minimum supported PostgreSQL version: 13. We rely on the built-in
-- `gen_random_uuid()` (in pg_catalog as of 13), which avoids the pgcrypto
-- extension — managed Postgres services like RDS / Cloud SQL won't grant the
-- application user `CREATE EXTENSION` privileges. If we ever need pre-13
-- support, run `CREATE EXTENSION pgcrypto` out-of-band as a superuser before
-- applying this migration.

CREATE TABLE IF NOT EXISTS ati_keys (
    token_hash      TEXT PRIMARY KEY,
    key_alias       TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    blocked         BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at      TIMESTAMPTZ,
    tools           TEXT[] NOT NULL DEFAULT '{}',
    providers       TEXT[] NOT NULL DEFAULT '{}',
    categories      TEXT[] NOT NULL DEFAULT '{}',
    skills          TEXT[] NOT NULL DEFAULT '{}',
    request_count   BIGINT NOT NULL DEFAULT 0,
    error_count     BIGINT NOT NULL DEFAULT 0,
    last_used_at    TIMESTAMPTZ,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      TEXT,
    -- One alias per user; orchestrators key job-scoped issuance off this so a
    -- second `issue` for the same alias must intentionally rotate, not
    -- silently duplicate.
    UNIQUE (user_id, key_alias)
);

CREATE INDEX IF NOT EXISTS idx_ati_keys_user
    ON ati_keys(user_id);

CREATE INDEX IF NOT EXISTS idx_ati_keys_active_expiring
    ON ati_keys(expires_at)
    WHERE blocked = FALSE AND expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS ati_deleted_keys (
    token_hash      TEXT PRIMARY KEY,
    snapshot        JSONB NOT NULL,
    deleted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_by      TEXT
);

CREATE TABLE IF NOT EXISTS ati_call_log (
    request_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at      TIMESTAMPTZ NOT NULL,
    ended_at        TIMESTAMPTZ NOT NULL,
    -- BIGINT not INTEGER: a hung upstream (LLM streaming, slow network) can
    -- exceed INT4_MAX milliseconds (24 days) before the request actually
    -- closes; better to never overflow the audit row.
    latency_ms      BIGINT NOT NULL,
    token_hash      TEXT,
    user_id         TEXT,
    session_id      TEXT,
    endpoint        TEXT NOT NULL,
    tool_name       TEXT,
    provider        TEXT,
    handler         TEXT,
    status          TEXT NOT NULL,
    upstream_status INTEGER,
    error_class     TEXT,
    error_message   TEXT,
    request_args    JSONB,
    response_size   INTEGER,
    requester_ip    INET,
    user_agent      TEXT
);

CREATE INDEX IF NOT EXISTS idx_call_log_started_at
    ON ati_call_log(started_at DESC);

CREATE INDEX IF NOT EXISTS idx_call_log_token
    ON ati_call_log(token_hash, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_call_log_tool
    ON ati_call_log(tool_name, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_call_log_failures
    ON ati_call_log(status, started_at DESC)
    WHERE status <> 'success';

CREATE TABLE IF NOT EXISTS ati_audit_log (
    id              BIGSERIAL PRIMARY KEY,
    happened_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor           TEXT NOT NULL,
    action          TEXT NOT NULL,
    target_table    TEXT NOT NULL,
    target_id       TEXT NOT NULL,
    before_value    JSONB,
    after_value     JSONB
);

CREATE INDEX IF NOT EXISTS idx_audit_log_target
    ON ati_audit_log(target_table, target_id, happened_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_log_actor
    ON ati_audit_log(actor, happened_at DESC);
