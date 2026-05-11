-- Control plane schema for ATI — the second migration after the initial
-- persistence layer in 20260501000001. Adds seven tables that turn the proxy
-- from "configured by TOML files on disk" into "configured by Postgres, with
-- per-tenant overrides, encrypted secrets, and an admin surface for the UI".
--
-- Layout summary:
--   ati_customers                    — tenants (Parcha customers)
--   ati_providers                    — provider manifests (shared OR per-customer)
--   ati_provider_credentials         — static API keys, envelope-encrypted
--   ati_oauth_clients                — DCR results (RFC 7591)
--   ati_oauth_tokens                 — OAuth access + refresh, envelope-encrypted
--   ati_pending_oauth_flows          — state + PKCE held across the AS redirect
--   ati_customer_provider_overrides  — per-customer non-credential overrides
--   ALTER ati_keys ADD COLUMN customer_id  — virtual keys inherit a tenant
--
-- Tenancy model: every credential / token / provider table has a nullable
-- `customer_id`. NULL means "shared / Parcha-owned"; a non-null value means
-- "scoped to this customer". A pair of partial unique indexes per table
-- enforces "one shared row per (provider, key)" and "one per-customer row per
-- (customer, provider, key)" without doubling the table count. The resolver
-- (PR #3 in the stack) uses ORDER BY customer_id NULLS LAST to do
-- customer-wins-shared-fallback in a single round-trip.
--
-- Envelope encryption: ciphertext + nonce + wrapped_dek + kek_id columns
-- match the EnvelopeBlob shape from core::secrets (PR #91). Plaintext never
-- lands here.
--
-- Soft delete: every table carries deleted_at TIMESTAMPTZ. Hard-delete is
-- operator-only and flows through a confirmation step in PR #4.

-- ---------------------------------------------------------------------------
-- ati_customers — tenants
-- ---------------------------------------------------------------------------
-- A row per Parcha customer. parcha_org_id is the optional foreign-key into
-- parcha-backend's org table; metadata JSONB holds operator-defined fields
-- (contact email, plan tier, …) without forcing a schema change every time.

CREATE TABLE IF NOT EXISTS ati_customers (
    id              TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL,
    parcha_org_id   TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    -- Customer ids should be filesystem-safe identifiers. Operator-pickable.
    CONSTRAINT ati_customers_id_chk CHECK (id ~ '^[a-z][a-z0-9_-]*$')
);

CREATE INDEX IF NOT EXISTS idx_ati_customers_active
    ON ati_customers(id) WHERE deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- ati_providers — manifest source-of-truth
-- ---------------------------------------------------------------------------
-- Hot fields the proxy queries on every request (name, handler, auth_type,
-- enabled) are typed columns and indexed. Cold fields (mcp_args,
-- openapi_overrides, oauth_scopes, oauth_resource, extra_headers,
-- auth_generator, …) ride in config JSONB so adding a new Provider field
-- doesn't need a migration.
--
-- `source` distinguishes 'toml' rows (created by the one-time bootstrap on
-- first DB connect) from 'admin' rows (created via the UI / admin API).
-- Bootstrap uses ON CONFLICT DO NOTHING so it's idempotent and never
-- overwrites operator edits.

CREATE TABLE IF NOT EXISTS ati_providers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id     TEXT REFERENCES ati_customers(id),  -- NULL = shared
    name            TEXT NOT NULL,
    handler         TEXT NOT NULL,                       -- http|mcp|openapi|cli|file_manager
    description     TEXT NOT NULL,
    base_url        TEXT NOT NULL DEFAULT '',
    auth_type       TEXT NOT NULL DEFAULT 'none',
    category        TEXT,
    internal        BOOLEAN NOT NULL DEFAULT FALSE,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    config          JSONB NOT NULL DEFAULT '{}',
    source          TEXT NOT NULL DEFAULT 'admin',       -- 'toml' for bootstrap
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    -- Provider names map to filesystem-friendly identifiers; same constraint
    -- as the existing TOML manifest filenames.
    CONSTRAINT ati_providers_name_chk CHECK (name ~ '^[a-z][a-z0-9_-]*$')
);

-- Shared row: exactly one per name when not soft-deleted.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ati_providers_shared_name
    ON ati_providers(name)
    WHERE customer_id IS NULL AND deleted_at IS NULL;

-- Per-customer row: exactly one per (customer, name) when not soft-deleted.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ati_providers_customer_name
    ON ati_providers(customer_id, name)
    WHERE customer_id IS NOT NULL AND deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_ati_providers_handler
    ON ati_providers(handler) WHERE deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- ati_provider_credentials — static API keys, envelope-encrypted
-- ---------------------------------------------------------------------------
-- Replaces ~/.ati/keyring.enc entries. One row per (customer?, provider, key).
-- ciphertext/nonce/wrapped_dek/kek_id match core::secrets::EnvelopeBlob.
-- suffix4 is the last 4 chars of the original plaintext, kept for UI display
-- ("...abc7"). Plaintext is never stored.

CREATE TABLE IF NOT EXISTS ati_provider_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id     TEXT REFERENCES ati_customers(id),  -- NULL = shared
    provider_name   TEXT NOT NULL,
    key_name        TEXT NOT NULL,                       -- "particle_api_key"
    ciphertext      BYTEA NOT NULL,
    nonce           BYTEA NOT NULL,
    wrapped_dek     BYTEA NOT NULL,
    kek_id          TEXT NOT NULL,
    suffix4         TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at      TIMESTAMPTZ,
    deleted_at      TIMESTAMPTZ,
    created_by      TEXT,
    -- Defensive sanity checks: the resolver's single-query cascade depends
    -- on these always being present.
    CONSTRAINT ati_provider_credentials_nonce_len CHECK (octet_length(nonce) = 12),
    CONSTRAINT ati_provider_credentials_wrap_len CHECK (octet_length(wrapped_dek) = 40)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_creds_shared
    ON ati_provider_credentials(provider_name, key_name)
    WHERE customer_id IS NULL AND deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_creds_customer
    ON ati_provider_credentials(customer_id, provider_name, key_name)
    WHERE customer_id IS NOT NULL AND deleted_at IS NULL;

-- Hot-path lookup: covers the resolver's cascade query (provider+customer or NULL).
CREATE INDEX IF NOT EXISTS idx_creds_lookup
    ON ati_provider_credentials(provider_name, customer_id)
    WHERE deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- ati_oauth_clients — RFC 7591 Dynamic Client Registration results
-- ---------------------------------------------------------------------------
-- One row per (customer?, provider). Most MCP servers issue public clients
-- (no client_secret) per the 2025-06-18 MCP authorization spec; we store the
-- secret encrypted when one is issued so the rare confidential-client case
-- still works.

CREATE TABLE IF NOT EXISTS ati_oauth_clients (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id                 TEXT REFERENCES ati_customers(id),
    provider_name               TEXT NOT NULL,
    client_id                   TEXT NOT NULL,
    wrapped_secret              BYTEA,
    secret_nonce                BYTEA,
    secret_wrapped_dek          BYTEA,
    secret_kek_id               TEXT,
    redirect_uri                TEXT NOT NULL,
    token_endpoint_auth_method  TEXT,
    registration_endpoint       TEXT,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at                  TIMESTAMPTZ,
    -- All-or-nothing for the encrypted-secret tuple — partial state shouldn't
    -- be possible. If wrapped_secret is set, all four columns must be.
    CONSTRAINT ati_oauth_clients_secret_consistency CHECK (
        (wrapped_secret IS NULL AND secret_nonce IS NULL AND secret_wrapped_dek IS NULL AND secret_kek_id IS NULL)
        OR
        (wrapped_secret IS NOT NULL AND secret_nonce IS NOT NULL AND secret_wrapped_dek IS NOT NULL AND secret_kek_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_clients_shared
    ON ati_oauth_clients(provider_name)
    WHERE customer_id IS NULL AND deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_clients_customer
    ON ati_oauth_clients(customer_id, provider_name)
    WHERE customer_id IS NOT NULL AND deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- ati_oauth_tokens — OAuth access + refresh, envelope-encrypted
-- ---------------------------------------------------------------------------
-- Mirrors core::oauth_store::ProviderTokens from PR #89 plus tenancy +
-- envelope encryption + the `version BIGINT` optimistic-locking column.
--
-- The version column is the cross-pod refresh story: every refresh does
--     UPDATE ati_oauth_tokens SET ... version = version + 1
--      WHERE id = $1 AND version = $2 RETURNING version
-- If RETURNING is empty, a peer beat us; the loser reloads and returns the
-- winner's already-rotated access_token. No double-refresh, no burned
-- refresh token, works across an unlimited number of replicas.
--
-- Access + refresh tokens are stored together in one JSON ciphertext blob:
-- {"access":"…","refresh":"…"}. Single unwrap covers both reads.

CREATE TABLE IF NOT EXISTS ati_oauth_tokens (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id              TEXT REFERENCES ati_customers(id),
    provider_name            TEXT NOT NULL,
    client_id                TEXT NOT NULL,
    redirect_uri             TEXT NOT NULL,
    ciphertext               BYTEA NOT NULL,
    nonce                    BYTEA NOT NULL,
    wrapped_dek              BYTEA NOT NULL,
    kek_id                   TEXT NOT NULL,
    access_token_expires_at  TIMESTAMPTZ NOT NULL,
    scopes                   TEXT[] NOT NULL DEFAULT '{}',
    resource                 TEXT NOT NULL,
    token_endpoint           TEXT NOT NULL,
    revocation_endpoint      TEXT,
    authorized_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    version                  BIGINT NOT NULL DEFAULT 0,
    deleted_at               TIMESTAMPTZ,
    CONSTRAINT ati_oauth_tokens_nonce_len CHECK (octet_length(nonce) = 12),
    CONSTRAINT ati_oauth_tokens_wrap_len CHECK (octet_length(wrapped_dek) = 40)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_tokens_shared
    ON ati_oauth_tokens(provider_name)
    WHERE customer_id IS NULL AND deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_tokens_customer
    ON ati_oauth_tokens(customer_id, provider_name)
    WHERE customer_id IS NOT NULL AND deleted_at IS NULL;

-- Hot-path lookup matching the resolver cascade.
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_lookup
    ON ati_oauth_tokens(provider_name, customer_id)
    WHERE deleted_at IS NULL;

-- Admin "what's expiring soon" view.
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_expiring
    ON ati_oauth_tokens(access_token_expires_at)
    WHERE deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- ati_pending_oauth_flows — short-lived flow state for /admin/oauth/callback
-- ---------------------------------------------------------------------------
-- The proxy holds the PKCE verifier + state across the redirect to the
-- authorization server and back. Rows are inserted in
-- POST /admin/providers/{name}/authorize and deleted by the callback handler
-- (single-use). Anything older than 10 minutes is presumed abandoned.
-- A scheduled GC task in PR #4 will hard-delete rows older than 1 day.

CREATE TABLE IF NOT EXISTS ati_pending_oauth_flows (
    state                    TEXT PRIMARY KEY,
    customer_id              TEXT REFERENCES ati_customers(id),
    provider_name            TEXT NOT NULL,
    pkce_verifier            TEXT NOT NULL,                  -- never logged
    pkce_method              TEXT NOT NULL DEFAULT 'S256',
    client_id                TEXT NOT NULL,
    token_endpoint           TEXT NOT NULL,
    authorization_endpoint   TEXT NOT NULL,
    revocation_endpoint      TEXT,
    resource                 TEXT NOT NULL,
    redirect_uri             TEXT NOT NULL,
    scopes                   TEXT[] NOT NULL DEFAULT '{}',
    actor                    TEXT NOT NULL,                  -- admin sub
    return_url               TEXT,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at               TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pending_oauth_expiring
    ON ati_pending_oauth_flows(expires_at);

-- ---------------------------------------------------------------------------
-- ati_customer_provider_overrides — per-customer non-credential overrides
-- ---------------------------------------------------------------------------
-- Sparse JSONB. Lets an operator say "customer X uses Particle but with a
-- different base_url" or "customer Y has a tighter rate cap on web_search"
-- without creating a duplicate provider row. The resolver in PR #3 will
-- merge this JSONB over the matched provider config at resolve time.

CREATE TABLE IF NOT EXISTS ati_customer_provider_overrides (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id     TEXT NOT NULL REFERENCES ati_customers(id),
    provider_name   TEXT NOT NULL,
    overrides       JSONB NOT NULL DEFAULT '{}',
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    UNIQUE (customer_id, provider_name)
);

-- ---------------------------------------------------------------------------
-- ati_keys — extend the PR #88 virtual-keys table with customer scoping
-- ---------------------------------------------------------------------------
-- Virtual keys (one-shot bearer tokens issued by the orchestrator at job
-- start) inherit a tenant the same way sandbox JWTs do. The resolver reads
-- this column when constructing synthetic TokenClaims from a virtual-key
-- row, so a job_id pinned to "cust_alpha" automatically gets cust_alpha's
-- provider config.
--
-- ADD COLUMN IF NOT EXISTS lets this migration apply cleanly even when
-- PR #88's ati_keys was created by a separate migration in the same DB.

ALTER TABLE ati_keys ADD COLUMN IF NOT EXISTS customer_id TEXT REFERENCES ati_customers(id);

CREATE INDEX IF NOT EXISTS idx_ati_keys_customer
    ON ati_keys(customer_id) WHERE blocked = FALSE;
