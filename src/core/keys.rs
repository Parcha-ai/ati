//! Ephemeral virtual keys backed by `ati_keys`.
//!
//! Orchestrators issue a one-shot `ati-key_<random>` per agent job at start
//! time, the sandbox uses it as `Authorization: Ati-Key <raw>` instead of (or
//! alongside) a JWT, and the orchestrator revokes it at job end. Revocation
//! is immediate via `LISTEN/NOTIFY` and survives orchestrator restarts —
//! that's the point compared to the JWT path, where revocation requires an
//! external blocklist.
//!
//! Three invariants:
//!
//!   1. **Raw key never leaves process memory.** `KeyStore::issue` returns
//!      it once in `IssuedKey`. The DB only ever stores `sha256(raw)` hex.
//!      Operators must capture the raw key at issuance.
//!   2. **Auth lookup is cache-first.** Hot path is in-memory `moka` with a
//!      30s TTL; cache miss falls back to a `SELECT * FROM ati_keys WHERE
//!      token_hash = $1`. `LISTEN ati_key_revoked` invalidates other pods'
//!      caches within roundtrip latency.
//!   3. **Revocation is a soft delete.** Rows move to `ati_deleted_keys` so
//!      `ati_call_log.token_hash` references stay resolvable for forensics
//!      after the fact.
//!
//! The entire module is gated behind `#[cfg(feature = "db")]` because sqlx
//! is itself optional.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use chrono::{DateTime, Utc};
use moka::future::Cache;
use sqlx::postgres::PgListener;
use sqlx::PgPool;
use thiserror::Error;
use tokio::task::JoinHandle;

/// Prefix on the wire so operators can spot the credential in logs.
pub const KEY_PREFIX: &str = "ati-key_";

/// Postgres `LISTEN/NOTIFY` channel for cross-pod cache invalidation.
pub const NOTIFY_CHANNEL: &str = "ati_key_revoked";

/// Cache TTL for positive and negative `lookup` results.
pub const CACHE_TTL: Duration = Duration::from_secs(30);

/// Cache size cap. ~50k keys × ~1 KB row ≈ 50 MB worst case.
pub const CACHE_CAPACITY: u64 = 50_000;

#[derive(Debug, Error)]
pub enum KeyStoreError {
    #[error("invalid issue parameters: {0}")]
    InvalidParams(&'static str),
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
}

/// One row from `ati_keys`. Mirrors the migration in PR 1.
#[derive(Debug, Clone)]
pub struct AtiKey {
    pub token_hash: String,
    pub key_alias: String,
    pub user_id: String,
    pub blocked: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub tools: Vec<String>,
    pub providers: Vec<String>,
    pub categories: Vec<String>,
    pub skills: Vec<String>,
    pub request_count: i64,
    pub error_count: i64,
    pub last_used_at: Option<DateTime<Utc>>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<String>,
}

impl AtiKey {
    /// True when the row is still usable: not blocked AND (no expiry OR
    /// expiry in the future).
    pub fn is_active(&self) -> bool {
        if self.blocked {
            return false;
        }
        match self.expires_at {
            Some(when) => when > Utc::now(),
            None => true,
        }
    }

    /// Build a synthetic `TokenClaims` from this key's scope arrays. Lets
    /// `auth_middleware` insert the same extension type as the JWT path so
    /// `scopes_for_request` and every handler keep working unchanged.
    pub fn to_synthetic_claims(&self) -> crate::core::jwt::TokenClaims {
        let mut scopes: Vec<String> = Vec::new();
        for t in &self.tools {
            scopes.push(format!("tool:{t}"));
        }
        for p in &self.providers {
            scopes.push(format!("tool:{p}:*"));
        }
        for s in &self.skills {
            scopes.push(format!("skill:{s}"));
        }
        for c in &self.categories {
            scopes.push(format!("category:{c}"));
        }
        // 0 sentinel preserves "no expiry" semantics — ScopeConfig treats it
        // identically to a JWT without an exp claim.
        let exp = self
            .expires_at
            .map(|d| d.timestamp().max(0) as u64)
            .unwrap_or(0);
        crate::core::jwt::TokenClaims {
            iss: None,
            sub: self.user_id.clone(),
            aud: String::new(),
            iat: self.created_at.timestamp().max(0) as u64,
            exp,
            jti: Some(self.token_hash.clone()),
            scope: scopes.join(" "),
            ati: None,
            job_id: None,
            sandbox_id: None,
        }
    }
}

/// Inputs to `KeyStore::issue`. Required: `user_id`, `key_alias`. The scope
/// arrays may be empty (resulting in a key with no tool access — useful for
/// admin shells that should only ever hit /help).
#[derive(Debug, Clone)]
pub struct IssueParams {
    pub user_id: String,
    pub key_alias: String,
    pub tools: Vec<String>,
    pub providers: Vec<String>,
    pub categories: Vec<String>,
    pub skills: Vec<String>,
    pub expires_in: Option<Duration>,
    pub metadata: serde_json::Value,
    pub created_by: Option<String>,
}

impl IssueParams {
    fn validate(&self) -> Result<(), KeyStoreError> {
        if self.user_id.trim().is_empty() {
            return Err(KeyStoreError::InvalidParams("user_id is required"));
        }
        if self.key_alias.trim().is_empty() {
            return Err(KeyStoreError::InvalidParams("key_alias is required"));
        }
        Ok(())
    }
}

/// What `KeyStore::issue` returns. The `raw_key` is the only place the raw
/// credential ever leaves process memory — operators must capture it.
#[derive(Debug, Clone)]
pub struct IssuedKey {
    pub raw_key: String,
    pub hash: String,
    pub alias: String,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Filter for `KeyStore::bulk_revoke`. Fields combine with AND. At least one
/// non-empty filter must be present so we don't accidentally revoke every
/// key in the database.
#[derive(Debug, Default, Clone)]
pub struct BulkRevokeFilter {
    pub user_id: Option<String>,
    pub alias_prefix: Option<String>,
    pub hashes: Option<Vec<String>>,
}

impl BulkRevokeFilter {
    /// True when no field would meaningfully constrain the WHERE clause:
    /// every field is None, an empty string, or an empty hash list. Used as
    /// a guard inside `bulk_revoke` so we never accidentally revoke every
    /// row in `ati_keys`.
    fn is_empty(&self) -> bool {
        let user_empty = self.user_id.as_ref().is_none_or(|s| s.trim().is_empty());
        let prefix_empty = self
            .alias_prefix
            .as_ref()
            .is_none_or(|s| s.trim().is_empty());
        let hashes_empty = self.hashes.as_ref().is_none_or(|h| h.is_empty());
        user_empty && prefix_empty && hashes_empty
    }
}

/// Escape `%` and `_` (LIKE wildcards) in an alias_prefix so a caller can't
/// match every row by passing `"%"` or `"_"`. Pairs with an explicit
/// `LIKE … ESCAPE '\'` clause in the query.
fn escape_like(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch == '%' || ch == '_' || ch == '\\' {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Cache-fronted key store. Cheap to clone (interior `Arc`s).
pub struct KeyStore {
    pool: PgPool,
    cache: Cache<String, Option<AtiKey>>,
    /// Held just to keep the listener task alive for the lifetime of the
    /// store. Tasks are aborted on drop, which closes the standalone
    /// listener connection.
    _listener_handle: JoinHandle<()>,
}

impl KeyStore {
    /// Build a new store and spawn the LISTEN task. Connects an extra DB
    /// connection (separate from the pool) for the listener — pool
    /// connections can't be held idle on `LISTEN` indefinitely.
    pub async fn new(pool: PgPool) -> Result<Arc<Self>, sqlx::Error> {
        let cache = Cache::builder()
            .time_to_live(CACHE_TTL)
            .max_capacity(CACHE_CAPACITY)
            .build();
        let listener_handle = spawn_listener(pool.clone(), cache.clone());
        Ok(Arc::new(KeyStore {
            pool,
            cache,
            _listener_handle: listener_handle,
        }))
    }

    /// Insert a new row + audit log entry, return the raw key (one shot).
    /// Atomic: either both rows land or neither. Cache populated immediately.
    pub async fn issue(&self, params: IssueParams) -> Result<IssuedKey, KeyStoreError> {
        params.validate()?;

        let raw_key = generate_raw_key();
        let hash = crate::core::keys::sha256_hex(raw_key.as_bytes());
        let expires_at = params
            .expires_in
            .and_then(|d| chrono::Duration::from_std(d).ok())
            .map(|d| Utc::now() + d);

        let mut tx = self.pool.begin().await?;
        let row = sqlx::query_as::<_, AtiKeyRow>(
            r#"
            INSERT INTO ati_keys (
                token_hash, key_alias, user_id, expires_at,
                tools, providers, categories, skills,
                metadata, created_by
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING token_hash, key_alias, user_id, blocked, expires_at,
                tools, providers, categories, skills,
                request_count, error_count, last_used_at,
                metadata, created_at, created_by
            "#,
        )
        .bind(&hash)
        .bind(&params.key_alias)
        .bind(&params.user_id)
        .bind(expires_at)
        .bind(&params.tools)
        .bind(&params.providers)
        .bind(&params.categories)
        .bind(&params.skills)
        .bind(&params.metadata)
        .bind(&params.created_by)
        .fetch_one(&mut *tx)
        .await?;

        let after_value = serde_json::json!({
            "alias": params.key_alias,
            "user_id": params.user_id,
            "tools": params.tools,
            "providers": params.providers,
            "categories": params.categories,
            "skills": params.skills,
            "expires_at": expires_at,
        });
        sqlx::query(
            r#"
            INSERT INTO ati_audit_log (actor, action, target_table, target_id, after_value)
            VALUES ($1, 'key.issue', 'ati_keys', $2, $3)
            "#,
        )
        .bind(params.created_by.as_deref().unwrap_or("admin"))
        .bind(&hash)
        .bind(&after_value)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        let key: AtiKey = row.into();
        // Pre-warm the cache with the fresh row.
        self.cache.insert(hash.clone(), Some(key.clone())).await;

        Ok(IssuedKey {
            raw_key,
            hash,
            alias: key.key_alias,
            expires_at: key.expires_at,
        })
    }

    /// Look up a key by hash. Cache-first; on miss, query `ati_keys`. Stores
    /// `None` for missing rows so a hash flood doesn't hammer the DB.
    pub async fn lookup(&self, hash: &str) -> Result<Option<AtiKey>, KeyStoreError> {
        if let Some(cached) = self.cache.get(hash).await {
            return Ok(cached);
        }
        let row: Option<AtiKeyRow> = sqlx::query_as(
            r#"
            SELECT token_hash, key_alias, user_id, blocked, expires_at,
                tools, providers, categories, skills,
                request_count, error_count, last_used_at,
                metadata, created_at, created_by
            FROM ati_keys WHERE token_hash = $1
            "#,
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await?;
        let key = row.map(AtiKey::from);
        self.cache.insert(hash.to_string(), key.clone()).await;
        Ok(key)
    }

    /// Soft-delete: copy row to `ati_deleted_keys`, delete from `ati_keys`,
    /// fire `pg_notify(ati_key_revoked, hash)` for cross-pod invalidation,
    /// purge local cache. Returns true if a row existed to revoke.
    pub async fn revoke(&self, hash: &str, by: Option<&str>) -> Result<bool, KeyStoreError> {
        let mut tx = self.pool.begin().await?;

        let snapshot: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(ati_keys.*) FROM ati_keys WHERE token_hash = $1")
                .bind(hash)
                .fetch_optional(&mut *tx)
                .await?;

        let Some(snapshot) = snapshot else {
            return Ok(false);
        };

        sqlx::query(
            r#"
            INSERT INTO ati_deleted_keys (token_hash, snapshot, deleted_by)
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(hash)
        .bind(&snapshot)
        .bind(by)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM ati_keys WHERE token_hash = $1")
            .bind(hash)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            r#"
            INSERT INTO ati_audit_log (actor, action, target_table, target_id, before_value)
            VALUES ($1, 'key.revoke', 'ati_keys', $2, $3)
            "#,
        )
        .bind(by.unwrap_or("admin"))
        .bind(hash)
        .bind(&snapshot)
        .execute(&mut *tx)
        .await?;

        // pg_notify in the same transaction so subscribers see it precisely
        // when the DELETE commits, never before.
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(NOTIFY_CHANNEL)
            .bind(hash)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        self.cache.invalidate(hash).await;
        Ok(true)
    }

    /// Revoke all rows matching the filter in one transaction. Filter fields
    /// AND together; passing all-empty fails fast rather than wiping the
    /// table.
    pub async fn bulk_revoke(
        &self,
        filter: BulkRevokeFilter,
        by: Option<&str>,
    ) -> Result<u64, KeyStoreError> {
        if filter.is_empty() {
            return Err(KeyStoreError::InvalidParams(
                "bulk_revoke requires at least one filter field",
            ));
        }

        let mut tx = self.pool.begin().await?;

        // Build the WHERE clause once and reuse for the single DELETE …
        // RETURNING. This is the atomic alternative to SELECT-then-DELETE,
        // which under READ COMMITTED can hard-delete rows inserted between
        // the two queries with no snapshot, no audit row, and no NOTIFY —
        // breaking the soft-delete invariant.
        let mut where_clauses: Vec<String> = Vec::new();
        let mut bind_idx = 1usize;
        if filter
            .user_id
            .as_ref()
            .is_some_and(|s| !s.trim().is_empty())
        {
            where_clauses.push(format!("user_id = ${bind_idx}"));
            bind_idx += 1;
        }
        if filter
            .alias_prefix
            .as_ref()
            .is_some_and(|s| !s.trim().is_empty())
        {
            // ESCAPE '\\' so a caller passing `%` or `_` matches literally
            // instead of as a SQL LIKE wildcard. Without this, `alias_prefix
            // = "%"` would match every row and silently revoke the table.
            where_clauses.push(format!("key_alias LIKE ${bind_idx} ESCAPE '\\'"));
            bind_idx += 1;
        }
        if filter.hashes.as_ref().is_some_and(|h| !h.is_empty()) {
            where_clauses.push(format!("token_hash = ANY(${bind_idx})"));
        }
        let where_sql = where_clauses.join(" AND ");

        // DELETE … RETURNING gives us atomic snapshot+removal: any concurrent
        // INSERT either misses this DELETE entirely or appears in the
        // returned rows. No silent hard-delete window.
        let delete_sql = format!(
            "DELETE FROM ati_keys WHERE {where_sql} \
             RETURNING token_hash, to_jsonb(ati_keys.*) AS snap"
        );
        let mut delete = sqlx::query_as::<_, (String, serde_json::Value)>(&delete_sql);
        if let Some(ref u) = filter.user_id {
            if !u.trim().is_empty() {
                delete = delete.bind(u);
            }
        }
        if let Some(ref p) = filter.alias_prefix {
            if !p.trim().is_empty() {
                delete = delete.bind(format!("{}%", escape_like(p)));
            }
        }
        if let Some(ref h) = filter.hashes {
            if !h.is_empty() {
                delete = delete.bind(h);
            }
        }
        let rows: Vec<(String, serde_json::Value)> = delete.fetch_all(&mut *tx).await?;

        if rows.is_empty() {
            tx.commit().await?;
            return Ok(0);
        }

        // Per-row snapshot + audit + NOTIFY. All inside the same transaction
        // as the DELETE, so subscribers see the NOTIFYs precisely when the
        // commit lands — never before.
        for (hash, snap) in &rows {
            sqlx::query(
                "INSERT INTO ati_deleted_keys (token_hash, snapshot, deleted_by) VALUES ($1, $2, $3)",
            )
            .bind(hash)
            .bind(snap)
            .bind(by)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                r#"
                INSERT INTO ati_audit_log (actor, action, target_table, target_id, before_value)
                VALUES ($1, 'key.bulk_revoke', 'ati_keys', $2, $3)
                "#,
            )
            .bind(by.unwrap_or("admin"))
            .bind(hash)
            .bind(snap)
            .execute(&mut *tx)
            .await?;
            sqlx::query("SELECT pg_notify($1, $2)")
                .bind(NOTIFY_CHANNEL)
                .bind(hash)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;

        // Purge cache for every revoked hash.
        for (hash, _) in &rows {
            self.cache.invalidate(hash).await;
        }

        Ok(rows.len() as u64)
    }

    /// List active rows for a user. Used by the `ati admin keys list-sessions`
    /// CLI for break-glass inspection. Returns at most 100 rows.
    pub async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<AtiKey>, KeyStoreError> {
        let rows: Vec<AtiKeyRow> = sqlx::query_as(
            r#"
            SELECT token_hash, key_alias, user_id, blocked, expires_at,
                tools, providers, categories, skills,
                request_count, error_count, last_used_at,
                metadata, created_at, created_by
            FROM ati_keys WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT 100
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(AtiKey::from).collect())
    }
}

/// Generate a fresh `ati-key_<base64-url-no-pad>` from 16 random bytes.
/// Mirrors the `ring::rand::SystemRandom` precedent in `cli/token.rs`.
pub fn generate_raw_key() -> String {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("system RNG must succeed");
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    format!("{KEY_PREFIX}{b64}")
}

/// SHA-256 hex of arbitrary bytes. Local copy of the helper from the proxy
/// module — re-exported there but accessible here without depending on the
/// proxy crate path.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

// --- Internal: row decoder ------------------------------------------------

#[derive(sqlx::FromRow)]
struct AtiKeyRow {
    token_hash: String,
    key_alias: String,
    user_id: String,
    blocked: bool,
    expires_at: Option<DateTime<Utc>>,
    tools: Vec<String>,
    providers: Vec<String>,
    categories: Vec<String>,
    skills: Vec<String>,
    request_count: i64,
    error_count: i64,
    last_used_at: Option<DateTime<Utc>>,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
    created_by: Option<String>,
}

impl From<AtiKeyRow> for AtiKey {
    fn from(r: AtiKeyRow) -> Self {
        AtiKey {
            token_hash: r.token_hash,
            key_alias: r.key_alias,
            user_id: r.user_id,
            blocked: r.blocked,
            expires_at: r.expires_at,
            tools: r.tools,
            providers: r.providers,
            categories: r.categories,
            skills: r.skills,
            request_count: r.request_count,
            error_count: r.error_count,
            last_used_at: r.last_used_at,
            metadata: r.metadata,
            created_at: r.created_at,
            created_by: r.created_by,
        }
    }
}

// --- LISTEN task ----------------------------------------------------------

fn spawn_listener(pool: PgPool, cache: Cache<String, Option<AtiKey>>) -> JoinHandle<()> {
    tokio::spawn(async move {
        const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
        const MAX_BACKOFF: Duration = Duration::from_secs(30);
        let mut backoff = INITIAL_BACKOFF;
        let mut warned_once = false;
        loop {
            // listen_loop resets backoff to INITIAL_BACKOFF on first successful
            // notification — that proves the new connection is live and a
            // subsequent disconnect should retry quickly, not at the cap.
            match listen_loop(&pool, &cache, &mut backoff).await {
                Ok(()) => {
                    // listen_loop only returns Ok on graceful shutdown; we
                    // drop the channel below to break the outer loop.
                    break;
                }
                Err(err) => {
                    if !warned_once {
                        tracing::warn!(error = %err, "ati_key_revoked listener disconnected; reconnecting");
                        warned_once = true;
                    } else {
                        tracing::debug!(error = %err, "listener reconnect");
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    })
}

async fn listen_loop(
    pool: &PgPool,
    cache: &Cache<String, Option<AtiKey>>,
    backoff: &mut Duration,
) -> Result<(), sqlx::Error> {
    let mut listener = PgListener::connect_with(pool).await?;
    listener.listen(NOTIFY_CHANNEL).await?;
    // Connection is good — reset backoff so a *future* disconnect retries
    // quickly. Without this, a brief outage after a long-stable session
    // would wait the cap (30s) instead of the intended 1s.
    *backoff = Duration::from_secs(1);
    loop {
        let notification = listener.recv().await?;
        let hash = notification.payload();
        cache.invalidate(hash).await;
        tracing::debug!(hash, "ati_key cache invalidated by NOTIFY");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_have_prefix_and_decode() {
        let key = generate_raw_key();
        assert!(key.starts_with(KEY_PREFIX));
        let body = key.strip_prefix(KEY_PREFIX).unwrap();
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .expect("base64-url-no-pad");
        assert_eq!(decoded.len(), 16);
    }

    #[test]
    fn generated_keys_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(generate_raw_key()));
        }
    }

    #[test]
    fn issue_params_validate_rejects_empty_user_id() {
        let p = IssueParams {
            user_id: "".into(),
            key_alias: "x".into(),
            tools: vec![],
            providers: vec![],
            categories: vec![],
            skills: vec![],
            expires_in: None,
            metadata: serde_json::Value::Null,
            created_by: None,
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn issue_params_validate_rejects_empty_alias() {
        let p = IssueParams {
            user_id: "u".into(),
            key_alias: "  ".into(),
            tools: vec![],
            providers: vec![],
            categories: vec![],
            skills: vec![],
            expires_in: None,
            metadata: serde_json::Value::Null,
            created_by: None,
        };
        assert!(p.validate().is_err());
    }

    fn dummy_key() -> AtiKey {
        AtiKey {
            token_hash: "h".into(),
            key_alias: "a".into(),
            user_id: "u".into(),
            blocked: false,
            expires_at: None,
            tools: vec!["clinicaltrials:searchStudies".into()],
            providers: vec!["finnhub".into()],
            categories: vec!["finance".into()],
            skills: vec!["sanctions".into()],
            request_count: 0,
            error_count: 0,
            last_used_at: None,
            metadata: serde_json::Value::Null,
            created_at: Utc::now(),
            created_by: None,
        }
    }

    #[test]
    fn is_active_no_expiry_unblocked() {
        let key = dummy_key();
        assert!(key.is_active());
    }

    #[test]
    fn is_active_blocked_returns_false() {
        let mut key = dummy_key();
        key.blocked = true;
        assert!(!key.is_active());
    }

    #[test]
    fn is_active_future_expiry() {
        let mut key = dummy_key();
        key.expires_at = Some(Utc::now() + chrono::Duration::hours(1));
        assert!(key.is_active());
    }

    #[test]
    fn is_active_past_expiry() {
        let mut key = dummy_key();
        key.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(!key.is_active());
    }

    #[test]
    fn synthetic_claims_map_each_scope_array() {
        let key = dummy_key();
        let claims = key.to_synthetic_claims();
        assert_eq!(claims.sub, "u");
        let scopes: Vec<&str> = claims.scope.split_whitespace().collect();
        assert!(scopes.contains(&"tool:clinicaltrials:searchStudies"));
        assert!(scopes.contains(&"tool:finnhub:*"));
        assert!(scopes.contains(&"skill:sanctions"));
        assert!(scopes.contains(&"category:finance"));
    }

    #[test]
    fn synthetic_claims_no_expiry_uses_zero() {
        let key = dummy_key();
        let claims = key.to_synthetic_claims();
        assert_eq!(claims.exp, 0);
    }

    #[test]
    fn synthetic_claims_preserve_expiry() {
        let mut key = dummy_key();
        let when = Utc::now() + chrono::Duration::hours(2);
        key.expires_at = Some(when);
        let claims = key.to_synthetic_claims();
        assert_eq!(claims.exp, when.timestamp() as u64);
    }

    #[test]
    fn bulk_revoke_filter_is_empty() {
        let f = BulkRevokeFilter::default();
        assert!(f.is_empty());
        let f = BulkRevokeFilter {
            user_id: Some("u".into()),
            ..Default::default()
        };
        assert!(!f.is_empty());
        let f = BulkRevokeFilter {
            hashes: Some(vec![]),
            ..Default::default()
        };
        assert!(f.is_empty());
    }

    #[test]
    fn bulk_revoke_filter_treats_whitespace_as_empty() {
        // Whitespace-only fields would previously sneak past the table-wipe
        // guard. They must be treated as effectively None.
        let f = BulkRevokeFilter {
            user_id: Some("   ".into()),
            ..Default::default()
        };
        assert!(f.is_empty());
        let f = BulkRevokeFilter {
            alias_prefix: Some("\t\n".into()),
            ..Default::default()
        };
        assert!(f.is_empty());
        let f = BulkRevokeFilter {
            user_id: Some("".into()),
            alias_prefix: Some("".into()),
            hashes: Some(vec![]),
        };
        assert!(f.is_empty());
    }

    #[test]
    fn escape_like_escapes_wildcards_and_backslash() {
        assert_eq!(escape_like(""), "");
        assert_eq!(escape_like("plain"), "plain");
        assert_eq!(escape_like("100%"), "100\\%");
        assert_eq!(escape_like("a_b"), "a\\_b");
        assert_eq!(escape_like("c:\\path"), "c:\\\\path");
        // The most adversarial case: passing `%` alone must not match every
        // row when concatenated with `%` to form the LIKE pattern.
        assert_eq!(escape_like("%"), "\\%");
        // Multi-char prefix with mixed wildcards.
        assert_eq!(escape_like("foo_%bar"), "foo\\_\\%bar");
    }

    #[test]
    fn constant_time_eq_basics() {
        // Local copy of the proxy helper for unit testing.
        fn ct_eq(a: &[u8], b: &[u8]) -> bool {
            let mut diff: u8 = (a.len() ^ b.len()) as u8 | ((a.len() ^ b.len()) >> 8) as u8;
            let n = a.len();
            for i in 0..n {
                let bi = if b.is_empty() { 0u8 } else { b[i % b.len()] };
                diff |= a[i] ^ bi;
            }
            diff == 0
        }
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab")); // shorter
        assert!(!ct_eq(b"ab", b"abc")); // longer
        assert!(!ct_eq(b"abc", b"")); // empty mismatch
        assert!(!ct_eq(b"", b"abc"));
    }
}
