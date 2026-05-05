# ATI Persistence Layer

> **Status (PR 1/3):** schema + connection plumbing only. The tables exist but
> nothing writes to them yet. Per-call audit (PR 2) and ephemeral virtual keys
> (PR 3) layer on top. This doc will grow as those land.

ATI's persistence layer is **optional**. If you don't set `ATI_DB_URL`, the
proxy works exactly as before — no DB connection, no schema, no behavior change.
That's the default.

When you do enable it, ATI gets:

- **Per-call audit log** (PR 2) — one row per request showing who called what,
  with what args, latency, status, and error class. Lets you answer
  "which tools are failing?" and "what did user X do today?"
- **Ephemeral virtual keys** (PR 3) — issue a key when a job starts, revoke
  when it ends. Each key carries scopes (tools/providers/categories/skills)
  identical to today's JWT model, but is DB-backed so revocation is immediate
  and survives orchestrator restarts.

---

## Quick start

### 1. Provision Postgres

ATI needs **PostgreSQL 13+** (we use the built-in `gen_random_uuid()`,
not the `pgcrypto` extension — see [Why no pgcrypto?](#why-no-pgcrypto) below).

Any Postgres works: managed (RDS, Cloud SQL, Azure Flexible, Neon, Supabase,
Northflank addon) or self-hosted. Create a database and an application user
with full DML privileges on that database — no superuser needed.

```sql
-- As the DB superuser, once per ATI deployment:
CREATE DATABASE ati;
CREATE USER ati_app WITH PASSWORD '<strong-random-secret>';
GRANT ALL PRIVILEGES ON DATABASE ati TO ati_app;
\c ati
GRANT ALL PRIVILEGES ON SCHEMA public TO ati_app;
```

### 2. Build ATI with the `db` feature

The Postgres driver is **opt-in at compile time** so default builds stay tiny
and dependency-free. Three ways to get a build with the feature:

```bash
# From source
cargo build --release --features db --target x86_64-unknown-linux-musl

# Pre-built binary — released artifacts include both variants
curl -fsSL https://github.com/Parcha-ai/ati/releases/latest/download/ati-x86_64-unknown-linux-musl-db.tar.gz \
  | tar xz && sudo mv ati /usr/local/bin/
# (the `-db` suffix marks the variant with the db feature compiled in)

# Docker — the stock image will gain a `db`-tagged variant alongside `latest`
docker pull parcha/ati:db-latest
```

Verify the build supports it:

```bash
ati proxy --help | grep -A1 migrate
#       --migrate
#           Apply pending database migrations on startup ...
```

If the `--migrate` flag is missing, you have a build without the feature.

### 3. Run migrations

ATI ships its migrations embedded in the binary. To apply them, run the proxy
once with `--migrate`:

```bash
export ATI_DB_URL="postgres://ati_app:<password>@db.example.com:5432/ati"
ati proxy --port 8090 --bind 0.0.0.0 --migrate
```

You'll see in the structured logs:

```json
{"level":"INFO","message":"applied database migrations"}
{"level":"INFO","message":"ATI proxy server starting","db":"connected", ...}
```

`--migrate` is **idempotent**. Running it on every deploy is safe — sqlx
tracks applied migrations in a `_sqlx_migrations` table and skips ones already
present. In production you can either:

- Leave `--migrate` in the startup command (simplest, recommended for single-pod deployments).
- Or run a one-shot migration job out-of-band (`ati proxy --migrate` then exit
  via `--health-and-quit` — TBD in a later PR), then run the long-lived
  proxy without the flag (preferred for multi-pod deployments where you want
  exactly-once migration semantics).

### 4. Verify

```bash
curl -s http://localhost:8090/health | jq
# {
#   "status": "ok",
#   "version": "0.7.10",
#   "tools": 104,
#   "providers": 10,
#   "skills": 0,
#   "auth": "jwt",
#   "db": "connected"     ← was "disabled" before
# }
```

The `db: connected` field is the operator's at-a-glance signal that the
persistence layer is live.

---

## Schema

PR 1 lands four tables. **None of them are written to yet** — that's PRs 2/3.
They're declared now so subsequent PRs are pure code, not schema-change
migrations that need a multi-step deploy.

| Table | Purpose | Rows from |
|---|---|---|
| `ati_keys` | Virtual keys with scope arrays + counters | PR 3 |
| `ati_deleted_keys` | Soft-delete archive of revoked keys (JSONB snapshot) | PR 3 |
| `ati_call_log` | Per-request audit row | PR 2 |
| `ati_audit_log` | Admin mutations (key.create / key.revoke / etc.) | PR 3 |

### `ati_keys`

```sql
CREATE TABLE ati_keys (
    token_hash      TEXT PRIMARY KEY,        -- sha256(raw_key) hex
    key_alias       TEXT NOT NULL,            -- human label, often `job-<uuid>`
    user_id         TEXT NOT NULL,
    blocked         BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at      TIMESTAMPTZ,
    -- scope arrays — mirror the existing JWT scope cascade
    tools           TEXT[] NOT NULL DEFAULT '{}',
    providers       TEXT[] NOT NULL DEFAULT '{}',
    categories      TEXT[] NOT NULL DEFAULT '{}',
    skills          TEXT[] NOT NULL DEFAULT '{}',
    -- counters (updated async, eventual-consistency)
    request_count   BIGINT NOT NULL DEFAULT 0,
    error_count     BIGINT NOT NULL DEFAULT 0,
    last_used_at    TIMESTAMPTZ,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      TEXT,
    UNIQUE (user_id, key_alias)               -- one alias per user
);
```

The raw key (`ati-key_…`) is **never stored** — only its sha256 hash. Operators
must save the raw key at issuance time; there's no decrypt-and-show path.

### `ati_deleted_keys`

```sql
CREATE TABLE ati_deleted_keys (
    token_hash      TEXT PRIMARY KEY,
    snapshot        JSONB NOT NULL,          -- full ati_keys row at deletion
    deleted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_by      TEXT
);
```

Revocation **moves** rows here rather than DELETE-ing — preserves audit trail
linkage from `ati_call_log.token_hash` to the key that made the call, even
after revocation. There's no FK between the two tables on purpose: the soft-
delete archive must outlive the source row.

### `ati_call_log`

```sql
CREATE TABLE ati_call_log (
    request_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at      TIMESTAMPTZ NOT NULL,
    ended_at        TIMESTAMPTZ NOT NULL,
    latency_ms      BIGINT NOT NULL,         -- BIGINT not INT4 — no 24-day overflow
    -- who
    token_hash      TEXT,                     -- nullable: master key has none
    user_id         TEXT,
    session_id      TEXT,                     -- groups multi-call agent runs
    -- what
    endpoint        TEXT NOT NULL,            -- '/call' | '/mcp' | '/help'
    tool_name       TEXT,                     -- e.g. 'parallel:web_search'
    provider        TEXT,
    handler         TEXT,                     -- 'http' | 'mcp' | 'openapi'
    -- outcome
    status          TEXT NOT NULL,            -- 'success' | 'tool_error' | ...
    upstream_status INTEGER,                  -- HTTP status from upstream
    error_class     TEXT,
    error_message   TEXT,
    -- payload (truncated, secrets redacted)
    request_args    JSONB,
    response_size   INTEGER,
    requester_ip    INET,
    user_agent      TEXT
);
```

Indexed on `(started_at DESC)`, `(token_hash, started_at DESC)`,
`(tool_name, started_at DESC)`, plus a partial index on
`(status, started_at DESC) WHERE status <> 'success'` so error dashboards
stay cheap.

### `ati_audit_log`

```sql
CREATE TABLE ati_audit_log (
    id              BIGSERIAL PRIMARY KEY,
    happened_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor           TEXT NOT NULL,            -- 'admin' or user_id
    action          TEXT NOT NULL,            -- 'key.create' | 'key.revoke' | ...
    target_table    TEXT NOT NULL,
    target_id       TEXT NOT NULL,
    before_value    JSONB,
    after_value     JSONB
);
```

Independent retention from `ati_call_log` — admin mutations are low-volume and
high-value, per-call rows are high-volume and short-lived.

---

## Configuration reference

| Variable | Purpose | Default |
|---|---|---|
| `ATI_DB_URL` | Postgres connection string. Empty or unset → persistence disabled. | unset |

### CLI flags

| Flag | Purpose |
|---|---|
| `--migrate` | Apply embedded migrations on startup. No-op if `ATI_DB_URL` is unset. |

### `/health` reporting

The `db` field in the `/health` JSON has two values:

- `"disabled"` — `ATI_DB_URL` unset, or build lacks the `db` feature
- `"connected"` — pool is up

> **Caveat (PR 1):** `db: connected` reflects the pool's *configured* state, not
> a live liveness probe. If Postgres dies after the proxy starts, `/health`
> still reports `connected` until the next restart. PR 2 will revisit this once
> per-request DB writes start mattering. For now, monitor your Postgres
> directly, not through `/health`.

---

## Failure semantics

### At startup

- **`ATI_DB_URL` unset / empty** → proxy starts cleanly, `db: disabled`. Default.
- **`ATI_DB_URL` set, build has `db` feature, DB reachable** → proxy starts, `db: connected`.
- **`ATI_DB_URL` set, DB unreachable / bad creds** → proxy **fails to start**
  with a structured ERROR log + non-zero exit. Operators can't accidentally
  miss a misconfigured DB.
- **`ATI_DB_URL` set, build lacks `db` feature** → proxy **fails to start** with
  `ATI built without `db` feature; rebuild with --features db to use ATI_DB_URL`.
  Prevents silently ignoring an operator's intent.

### Once running (PR 2/3 territory, sketched here for future-proofing)

- DB outage → proxy keeps serving requests. Audit writes go to a bounded
  in-memory queue; if the queue is full and the DB stays down, oldest entries
  drop with a `tracing::warn!`. Requests are never blocked or dropped on a
  DB error.
- DB reachable but slow → audit writes batch with timeout, never starve the
  request path.

This matches LiteLLM's design lesson learned at scale: the request path must
not depend on the DB being healthy.

---

## Operations

### Backup

`ati_call_log` is the high-volume table. Plan retention based on row volume
(rough rule: at 100 calls/sec, ~1 row × ~2 KB ≈ 200 KB/sec ≈ 17 GB/day).
A `pg_dump` daily + WAL archiving covers most needs. Retention beyond
30-90 days is rarely worth it — pre-aggregate into rollup tables once volumes
demand it (we don't have those yet; they'll come if and when we need them).

### Migrations on rolling deploys

On Northflank / Kubernetes with multiple pods:

- Avoid having every pod run `--migrate` simultaneously. sqlx is safe under
  concurrent migration attempts (advisory lock), but the log noise is
  confusing.
- Recommended: use a one-shot pre-deploy job that runs `--migrate` and exits,
  then the long-lived proxies run without the flag.
- Acceptable: one of the pods runs `--migrate`, others race-but-skip via the
  advisory lock. This is what most small deployments do.

### Schema drift

The migration filename pattern (`YYYYMMDDHHMMSS_<name>.sql`) is recorded in
`_sqlx_migrations(version, description, success, checksum)`. If you edit a
migration after it's applied, the checksum will mismatch on the next startup
and `--migrate` will refuse to proceed. **Never edit applied migrations** —
add a new one.

If you need to reset a dev DB:

```bash
psql "$ATI_DB_URL" -c "DROP TABLE _sqlx_migrations CASCADE;
                        DROP TABLE ati_keys CASCADE;
                        DROP TABLE ati_deleted_keys CASCADE;
                        DROP TABLE ati_call_log CASCADE;
                        DROP TABLE ati_audit_log CASCADE;"
ati proxy --migrate ...   # re-applies from scratch
```

---

## Why no pgcrypto?

The earlier draft of this migration created the `pgcrypto` extension to get
`gen_random_uuid()`. We removed it because **managed Postgres services don't
grant `CREATE EXTENSION` to application users** — RDS, Cloud SQL, Azure
Flexible Server all reject the call with `permission denied to create extension`.

PostgreSQL 13+ ships `gen_random_uuid()` as a built-in in `pg_catalog`, no
extension required. We declare PG 13 as the minimum supported version and
get the same UUID generation everywhere.

If you absolutely need PG 12 support, run `CREATE EXTENSION pgcrypto;` once
out-of-band as the DB superuser before applying ATI's migration. We don't
test this configuration.

---

## Why a Cargo feature flag?

The persistence layer pulls in sqlx (~30 transitive dependencies, ~15s extra
compile time, larger binary). Most ATI users don't need it — they run the CLI
or a single-node proxy with JWT auth and no DB.

Gating behind `--features db` keeps the default build identical to ATI 0.7.x
in size and behavior. Operators who want the persistence layer opt in
explicitly when building or by pulling the `-db` release artifact.

The runtime check on `ATI_DB_URL` is a second gate: even with the feature
compiled in, the DB code path is dead unless the env var is set.

---

## Roadmap

- **PR 2** — Per-call audit writer. Async write queue, secret redaction,
  bounded memory, never blocks requests. New admin endpoint to query the log.
- **PR 3** — Ephemeral virtual keys. `POST /admin/keys/issue` returns a
  one-shot `ati-key_…` for a job; `DELETE /admin/keys/{hash}` revokes it.
  Scope cascade matches today's JWT model. Compatible with the existing JWT
  auth — keys are additive, not a replacement.

PR 1 (this one) lands the foundation so PRs 2/3 ship as pure code without
needing schema-change migrations that complicate rolling deploys.
