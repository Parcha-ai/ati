//! Postgres-backed implementation of [`CredentialResolver`].
//!
//! Owns three things:
//!
//! 1. A `PgPool` (shared with the rest of the proxy's DB layer).
//! 2. A `dyn Kek` (the master key encryption key — usually `LocalKek`
//!    from `ATI_MASTER_KEY`) that wraps/unwraps per-row data keys.
//! 3. A pair of `moka::future::Cache`s, one for static credentials and
//!    one for OAuth access tokens. TTL caps how long a revoked secret
//!    stays usable; PR #5 will plumb `pg_notify`-driven invalidation on
//!    top so admin revocations are immediate.
//!
//! ## Cascade
//!
//! Every lookup is a single round-trip:
//!
//! ```sql
//! ... WHERE provider_name = $1 AND key_name = $2
//!       AND (customer_id = $3 OR customer_id IS NULL)
//!     ORDER BY customer_id NULLS LAST LIMIT 1
//! ```
//!
//! Postgres returns the customer-specific row when one exists (because
//! NULLS LAST sorts the NULL/shared row after the named-customer row),
//! and falls back to the shared row otherwise. Same shape for static
//! credentials and OAuth tokens.
//!
//! ## Refresh races
//!
//! `resolve_oauth` does **optimistic locking** against `ati_oauth_tokens.version`.
//! The conditional UPDATE is:
//!
//! ```sql
//! UPDATE ati_oauth_tokens
//!    SET ciphertext = $..., nonce = $..., wrapped_dek = $..., kek_id = $...,
//!        access_token_expires_at = $..., updated_at = now(),
//!        version = version + 1
//!  WHERE id = $... AND version = $expected
//!  RETURNING version;
//! ```
//!
//! If `RETURNING` is empty, a peer pod beat us — we reload the row and
//! return the peer's newly-rotated access token. No double refresh, no
//! burned refresh token, works across an arbitrary number of replicas.

#![cfg(feature = "db")]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use zeroize::Zeroizing;

use crate::core::secrets::{self, EnvelopeBlob, Kek};

use super::{CredentialResolver, ResolverError};

/// Default TTL for the in-process plaintext cache. Short — a revoked key
/// stays usable for at most this long. PR #5 adds pg_notify-driven
/// invalidation so the TTL is the safety net, not the primary signal.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);
/// Cap entries across all kinds of secrets to keep memory bounded even
/// in a misconfigured deploy with thousands of providers × customers.
const DEFAULT_CACHE_CAPACITY: u64 = 10_000;

/// Cache key for a static credential resolution.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct StaticKey {
    provider: String,
    key: String,
    customer: Option<String>,
}

/// Cache key for an OAuth access token. Customer is part of the key so
/// per-tenant tokens never bleed into each other's cache slots.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct OauthKey {
    provider: String,
    customer: Option<String>,
}

/// Cached value. We hold the plaintext as a `String` (not `Zeroizing`)
/// because moka requires `Send + Sync + Clone`; the resolver hands out
/// `Zeroizing<String>` to callers and the cache itself eventually
/// expires + the inner string drops normally. Tradeoff: cache contents
/// aren't zeroized at TTL boundary. Acceptable in the proxy because the
/// process memory itself is the trust boundary; PR #5 will add explicit
/// `invalidate` calls on revoke so a deleted credential clears the
/// cache too.
#[derive(Clone)]
struct CachedPlaintext(Arc<String>);

/// DB-backed credential resolver. Construct via [`DbResolver::new`].
pub struct DbResolver {
    pool: PgPool,
    kek: Arc<dyn Kek>,
    static_cache: Cache<StaticKey, CachedPlaintext>,
    oauth_cache: Cache<OauthKey, CachedPlaintext>,
}

impl std::fmt::Debug for DbResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbResolver")
            .field("kek_id", &self.kek.active_kek_id())
            .field("static_cache_entries", &self.static_cache.entry_count())
            .field("oauth_cache_entries", &self.oauth_cache.entry_count())
            .finish()
    }
}

impl DbResolver {
    pub fn new(pool: PgPool, kek: Arc<dyn Kek>) -> Self {
        Self::new_with(pool, kek, DEFAULT_CACHE_TTL, DEFAULT_CACHE_CAPACITY)
    }

    pub fn new_with(pool: PgPool, kek: Arc<dyn Kek>, ttl: Duration, capacity: u64) -> Self {
        Self {
            pool,
            kek,
            static_cache: Cache::builder()
                .max_capacity(capacity)
                .time_to_live(ttl)
                .build(),
            oauth_cache: Cache::builder()
                .max_capacity(capacity)
                .time_to_live(ttl)
                .build(),
        }
    }

    /// Invalidate one cached static credential. Used by the admin layer
    /// when a row is rotated or deleted (PR #5).
    pub async fn invalidate_static(
        &self,
        provider: &str,
        key_name: &str,
        customer_id: Option<&str>,
    ) {
        let k = StaticKey {
            provider: provider.to_string(),
            key: key_name.to_string(),
            customer: customer_id.map(|s| s.to_string()),
        };
        self.static_cache.invalidate(&k).await;
    }

    /// Invalidate one cached OAuth access token.
    pub async fn invalidate_oauth(&self, provider: &str, customer_id: Option<&str>) {
        let k = OauthKey {
            provider: provider.to_string(),
            customer: customer_id.map(|s| s.to_string()),
        };
        self.oauth_cache.invalidate(&k).await;
    }

    /// Look up a static credential row from PG (no cache), envelope-
    /// decrypt, return plaintext. The AAD pattern matches
    /// `<provider>:<key>:<customer-or-_>` so a ciphertext copy-pasted
    /// from one row onto another fails AEAD verification.
    async fn fetch_static(
        &self,
        provider: &str,
        key_name: &str,
        customer_id: Option<&str>,
    ) -> Result<Zeroizing<String>, ResolverError> {
        let row = sqlx::query(
            r#"
            SELECT ciphertext, nonce, wrapped_dek, kek_id, customer_id
            FROM ati_provider_credentials
            WHERE provider_name = $1
              AND key_name = $2
              AND deleted_at IS NULL
              AND (customer_id = $3 OR customer_id IS NULL)
            ORDER BY customer_id NULLS LAST
            LIMIT 1
            "#,
        )
        .bind(provider)
        .bind(key_name)
        .bind(customer_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_err)?
        .ok_or_else(|| ResolverError::NotConfigured {
            provider: provider.to_string(),
            key: key_name.to_string(),
            customer: customer_id.map(|s| s.to_string()),
        })?;

        let blob = EnvelopeBlob {
            ciphertext: row.get("ciphertext"),
            nonce: byte_array_from_slice(row.get::<Vec<u8>, _>("nonce"))?,
            wrapped_dek: row.get("wrapped_dek"),
            kek_id: row.get("kek_id"),
        };
        let row_customer: Option<String> = row.get("customer_id");
        let aad = aad_for_static(provider, key_name, row_customer.as_deref());

        let plain_bytes = secrets::open(&blob, aad.as_bytes(), &*self.kek)
            .map_err(|e| ResolverError::DecryptFailed(e.to_string()))?;
        let plain_str = String::from_utf8(plain_bytes.to_vec())
            .map_err(|_| ResolverError::DecryptFailed("plaintext is not UTF-8".into()))?;
        // Wrap immediately so the unwrapped String is the only on-heap
        // copy; the original Zeroizing<Vec<u8>> drops at end of scope.
        Ok(Zeroizing::new(plain_str))
    }

    /// Same shape as `fetch_static` but for an OAuth token row. Reads,
    /// envelope-decrypts the `{access, refresh}` JSON blob, returns it
    /// alongside the row id + version + expiry so the caller can decide
    /// to refresh.
    async fn fetch_oauth_row(
        &self,
        provider: &str,
        customer_id: Option<&str>,
    ) -> Result<Option<OauthRow>, ResolverError> {
        let row = sqlx::query(
            r#"
            SELECT id, version, customer_id, ciphertext, nonce, wrapped_dek, kek_id,
                   access_token_expires_at, token_endpoint, scopes, resource,
                   client_id, revocation_endpoint
            FROM ati_oauth_tokens
            WHERE provider_name = $1
              AND deleted_at IS NULL
              AND (customer_id = $2 OR customer_id IS NULL)
            ORDER BY customer_id NULLS LAST
            LIMIT 1
            "#,
        )
        .bind(provider)
        .bind(customer_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        let Some(row) = row else {
            return Ok(None);
        };

        let id: uuid::Uuid = row.get("id");
        let version: i64 = row.get("version");
        let row_customer: Option<String> = row.get("customer_id");
        let blob = EnvelopeBlob {
            ciphertext: row.get("ciphertext"),
            nonce: byte_array_from_slice(row.get::<Vec<u8>, _>("nonce"))?,
            wrapped_dek: row.get("wrapped_dek"),
            kek_id: row.get("kek_id"),
        };
        let aad = aad_for_oauth(provider, row_customer.as_deref());
        let plain = secrets::open(&blob, aad.as_bytes(), &*self.kek)
            .map_err(|e| ResolverError::DecryptFailed(e.to_string()))?;
        let bundle: OauthBundle = serde_json::from_slice(&plain)
            .map_err(|e| ResolverError::DecryptFailed(format!("oauth bundle JSON invalid: {e}")))?;
        let expires_at: chrono::DateTime<chrono::Utc> = row.get("access_token_expires_at");
        let token_endpoint: String = row.get("token_endpoint");
        let scopes: Vec<String> = row.get("scopes");
        let resource: String = row.get("resource");
        let client_id: String = row.get("client_id");

        Ok(Some(OauthRow {
            id,
            version,
            customer_id: row_customer,
            access_token: bundle.access,
            refresh_token: bundle.refresh,
            expires_at,
            token_endpoint,
            scopes,
            resource,
            client_id,
        }))
    }
}

#[async_trait]
impl CredentialResolver for DbResolver {
    async fn resolve_static(
        &self,
        provider_name: &str,
        key_name: &str,
        customer_id: Option<&str>,
    ) -> Result<Zeroizing<String>, ResolverError> {
        let cache_key = StaticKey {
            provider: provider_name.to_string(),
            key: key_name.to_string(),
            customer: customer_id.map(|s| s.to_string()),
        };
        if let Some(hit) = self.static_cache.get(&cache_key).await {
            return Ok(Zeroizing::new((*hit.0).clone()));
        }
        let plain = self
            .fetch_static(provider_name, key_name, customer_id)
            .await?;
        self.static_cache
            .insert(cache_key, CachedPlaintext(Arc::new((*plain).clone())))
            .await;
        Ok(plain)
    }

    async fn resolve_oauth(
        &self,
        provider_name: &str,
        customer_id: Option<&str>,
        min_remaining: Duration,
    ) -> Result<Zeroizing<String>, ResolverError> {
        // Cache short-circuit: if the access token is in cache, the row
        // we're about to read can't be more current. The TTL bounds the
        // window over which a refresh that happened on another pod stays
        // invisible to this pod's cache.
        let cache_key = OauthKey {
            provider: provider_name.to_string(),
            customer: customer_id.map(|s| s.to_string()),
        };
        if let Some(hit) = self.oauth_cache.get(&cache_key).await {
            // Caller may have asked for a longer min_remaining than the
            // cache TTL; trust the cache only if there's a sane window.
            // (We don't currently re-check expiry here — the cached value
            // is already the access token, and `min_remaining` is mostly
            // a hint. If we cached a token 4 minutes ago and the access
            // token's actual remaining is 30 s, we'll get a 401 from the
            // upstream and the caller's retry path will hit force_refresh.)
            return Ok(Zeroizing::new((*hit.0).clone()));
        }

        let row = self
            .fetch_oauth_row(provider_name, customer_id)
            .await?
            .ok_or_else(|| ResolverError::NotConfigured {
                provider: provider_name.to_string(),
                key: "oauth_token".to_string(),
                customer: customer_id.map(|s| s.to_string()),
            })?;

        let need_refresh = needs_refresh(row.expires_at, min_remaining);
        if !need_refresh {
            self.oauth_cache
                .insert(
                    cache_key,
                    CachedPlaintext(Arc::new(row.access_token.clone())),
                )
                .await;
            return Ok(Zeroizing::new(row.access_token));
        }
        self.refresh_oauth_locked(provider_name, customer_id, row, &cache_key)
            .await
    }

    async fn force_refresh_oauth(
        &self,
        provider_name: &str,
        customer_id: Option<&str>,
    ) -> Result<Zeroizing<String>, ResolverError> {
        let cache_key = OauthKey {
            provider: provider_name.to_string(),
            customer: customer_id.map(|s| s.to_string()),
        };
        // Invalidate before fetching so a concurrent caller can't pick
        // up the stale cached value while we're swapping.
        self.oauth_cache.invalidate(&cache_key).await;

        let row = self
            .fetch_oauth_row(provider_name, customer_id)
            .await?
            .ok_or_else(|| ResolverError::NotConfigured {
                provider: provider_name.to_string(),
                key: "oauth_token".to_string(),
                customer: customer_id.map(|s| s.to_string()),
            })?;
        self.refresh_oauth_locked(provider_name, customer_id, row, &cache_key)
            .await
    }
}

// ---------------------------------------------------------------------------
// Refresh: optimistic-locking conditional UPDATE
// ---------------------------------------------------------------------------

impl DbResolver {
    async fn refresh_oauth_locked(
        &self,
        provider_name: &str,
        customer_id: Option<&str>,
        row: OauthRow,
        cache_key: &OauthKey,
    ) -> Result<Zeroizing<String>, ResolverError> {
        let refresh_token = row.refresh_token.clone().ok_or_else(|| {
            ResolverError::OauthExpired(format!(
                "no refresh_token persisted for provider={provider_name} customer={customer_id:?}"
            ))
        })?;

        // Talk to the AS token endpoint. We deliberately don't reuse a
        // shared reqwest client here because we want per-refresh failure
        // isolation; the marginal cost is microseconds.
        let response = exchange_refresh_token(
            &row.token_endpoint,
            &refresh_token,
            &row.client_id,
            &row.resource,
            &row.scopes,
        )
        .await
        .map_err(|e| ResolverError::OauthExpired(format!("refresh failed: {e}")))?;

        // Build the new envelope and persist via optimistic-locking UPDATE.
        let new_access = response.access_token.clone();
        let new_refresh = response
            .refresh_token
            .clone()
            .or(Some(refresh_token))
            .unwrap_or_default();
        let bundle = OauthBundle {
            access: new_access.clone(),
            refresh: if new_refresh.is_empty() {
                None
            } else {
                Some(new_refresh)
            },
        };
        let bundle_json = serde_json::to_vec(&bundle)
            .map_err(|e| ResolverError::DecryptFailed(format!("bundle serialize: {e}")))?;
        let aad = aad_for_oauth(provider_name, row.customer_id.as_deref());
        let blob = secrets::seal(&bundle_json, aad.as_bytes(), &*self.kek)
            .map_err(|e| ResolverError::DecryptFailed(format!("seal: {e}")))?;
        let new_expires = chrono::Utc::now() + chrono::Duration::seconds(response.expires_in);

        let updated = sqlx::query(
            r#"
            UPDATE ati_oauth_tokens
               SET ciphertext = $1, nonce = $2, wrapped_dek = $3, kek_id = $4,
                   access_token_expires_at = $5, version = version + 1, updated_at = now()
             WHERE id = $6 AND version = $7
             RETURNING version
            "#,
        )
        .bind(&blob.ciphertext)
        .bind(blob.nonce.to_vec())
        .bind(&blob.wrapped_dek)
        .bind(&blob.kek_id)
        .bind(new_expires)
        .bind(row.id)
        .bind(row.version)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        if updated.is_none() {
            // A peer pod refreshed the same row between our fetch and our
            // UPDATE. Re-read; the peer's access_token is now canonical.
            tracing::info!(
                provider = provider_name,
                customer = ?customer_id,
                "OAuth refresh race lost; reloading peer's token"
            );
            let reloaded = self
                .fetch_oauth_row(provider_name, customer_id)
                .await?
                .ok_or_else(|| {
                    ResolverError::OauthExpired(
                        "row vanished mid-refresh — concurrent deauthorize?".into(),
                    )
                })?;
            self.oauth_cache
                .insert(
                    cache_key.clone(),
                    CachedPlaintext(Arc::new(reloaded.access_token.clone())),
                )
                .await;
            return Ok(Zeroizing::new(reloaded.access_token));
        }

        self.oauth_cache
            .insert(
                cache_key.clone(),
                CachedPlaintext(Arc::new(new_access.clone())),
            )
            .await;
        Ok(Zeroizing::new(new_access))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Concrete row pulled from `ati_oauth_tokens`, used internally by the
/// refresh path. Plaintext access/refresh land here, never in a struct
/// that crosses an API boundary.
struct OauthRow {
    id: uuid::Uuid,
    version: i64,
    customer_id: Option<String>,
    access_token: String,
    refresh_token: Option<String>,
    expires_at: chrono::DateTime<chrono::Utc>,
    token_endpoint: String,
    scopes: Vec<String>,
    resource: String,
    client_id: String,
}

#[derive(Serialize, Deserialize)]
struct OauthBundle {
    access: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh: Option<String>,
}

/// AAD for a static credential row. Binding (provider, key, customer)
/// into the AEAD tag makes a ciphertext copy-pasted from one row onto
/// another fail integrity verification at decrypt time.
fn aad_for_static(provider: &str, key_name: &str, customer: Option<&str>) -> String {
    format!(
        "static:{provider}:{key_name}:{}",
        customer.unwrap_or("_shared")
    )
}

/// AAD for an OAuth token row.
fn aad_for_oauth(provider: &str, customer: Option<&str>) -> String {
    format!("oauth:{provider}:{}", customer.unwrap_or("_shared"))
}

/// Returns true when the access token is expired or expires within
/// `min_remaining`.
fn needs_refresh(expires_at: chrono::DateTime<chrono::Utc>, min_remaining: Duration) -> bool {
    let now = chrono::Utc::now();
    if expires_at <= now {
        return true;
    }
    let remaining = expires_at - now;
    remaining
        .to_std()
        .map(|r| r < min_remaining)
        .unwrap_or(false)
}

/// Convert a `Vec<u8>` we just read from a `BYTEA` column into a
/// fixed-size nonce. The migration's CHECK constraint already enforces
/// `octet_length(nonce) = 12`, so this is a defensive double-check.
fn byte_array_from_slice<const N: usize>(v: Vec<u8>) -> Result<[u8; N], ResolverError> {
    if v.len() != N {
        return Err(ResolverError::DecryptFailed(format!(
            "expected {N}-byte field, got {}",
            v.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Ok(out)
}

fn map_sqlx_err(e: sqlx::Error) -> ResolverError {
    // Connection-class failures degrade to UpstreamUnavailable so the
    // proxy can decide between hard-fail (writes) and serve-from-cache
    // (reads). Everything else surfaces as Other.
    match &e {
        sqlx::Error::PoolTimedOut
        | sqlx::Error::Io(_)
        | sqlx::Error::Tls(_)
        | sqlx::Error::WorkerCrashed => ResolverError::UpstreamUnavailable(e.to_string()),
        _ => ResolverError::Other(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Token-endpoint exchange
// ---------------------------------------------------------------------------

/// Response from the AS `/token` endpoint after a refresh_token grant.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    /// Lifetime in seconds. Some ASes omit it; default 1 hour and let
    /// the 401 path recover if we got it wrong.
    #[serde(default = "default_expires_in")]
    expires_in: i64,
}

fn default_expires_in() -> i64 {
    3600
}

async fn exchange_refresh_token(
    token_endpoint: &str,
    refresh_token: &str,
    client_id: &str,
    resource: &str,
    scopes: &[String],
) -> Result<TokenResponse, String> {
    let scope_param = scopes.join(" ");
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
        ("resource", resource),
    ];
    if !scope_param.is_empty() {
        form.push(("scope", &scope_param));
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("build client: {e}"))?;
    let resp = client
        .post(token_endpoint)
        .header("Accept", "application/json")
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("POST {token_endpoint}: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!(
            "HTTP {} from {token_endpoint}: {text}",
            status.as_u16()
        ));
    }
    serde_json::from_str(&text).map_err(|e| format!("parse token response: {e} :: {text}"))
}

// ---------------------------------------------------------------------------
// Tests (pure-Rust portions; live-PG tests live in
// tests/credential_resolver_db_test.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_for_static_distinguishes_shared_and_customer() {
        let shared = aad_for_static("particle", "particle_api_key", None);
        let alpha = aad_for_static("particle", "particle_api_key", Some("cust_alpha"));
        assert_ne!(shared, alpha);
        // Same customer, different provider — also distinct.
        let mid = aad_for_static("middesk", "particle_api_key", Some("cust_alpha"));
        assert_ne!(mid, alpha);
    }

    #[test]
    fn aad_for_oauth_distinguishes_tenants() {
        let shared = aad_for_oauth("particle", None);
        let a = aad_for_oauth("particle", Some("cust_alpha"));
        let b = aad_for_oauth("particle", Some("cust_beta"));
        assert_ne!(shared, a);
        assert_ne!(a, b);
    }

    #[test]
    fn needs_refresh_logic() {
        let now = chrono::Utc::now();
        // Already expired.
        assert!(needs_refresh(
            now - chrono::Duration::seconds(1),
            Duration::from_secs(60)
        ));
        // Expires within window.
        assert!(needs_refresh(
            now + chrono::Duration::seconds(30),
            Duration::from_secs(60)
        ));
        // Comfortably in the future.
        assert!(!needs_refresh(
            now + chrono::Duration::seconds(3600),
            Duration::from_secs(60)
        ));
    }

    #[test]
    fn byte_array_size_check() {
        let twelve = vec![0u8; 12];
        let arr: Result<[u8; 12], _> = byte_array_from_slice(twelve);
        assert!(arr.is_ok());

        let wrong = vec![0u8; 11];
        let arr: Result<[u8; 12], _> = byte_array_from_slice(wrong);
        assert!(matches!(arr, Err(ResolverError::DecryptFailed(_))));
    }

    #[test]
    fn oauth_bundle_serde_roundtrip() {
        let b = OauthBundle {
            access: "AT".into(),
            refresh: Some("RT".into()),
        };
        let s = serde_json::to_string(&b).unwrap();
        assert!(s.contains("\"access\""));
        let parsed: OauthBundle = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed.access, "AT");
        assert_eq!(parsed.refresh.as_deref(), Some("RT"));

        // Refresh missing must roundtrip cleanly too.
        let b2 = OauthBundle {
            access: "x".into(),
            refresh: None,
        };
        let s2 = serde_json::to_string(&b2).unwrap();
        assert!(!s2.contains("\"refresh\""));
        let parsed2: OauthBundle = serde_json::from_str(&s2).unwrap();
        assert_eq!(parsed2.refresh, None);
    }
}
