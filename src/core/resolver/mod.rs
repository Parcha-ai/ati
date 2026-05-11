//! Credential resolution: the seam between "where do tools live" (manifests)
//! and "where do their secrets live" (keyring on disk, or `ati_provider_*`
//! tables in Postgres).
//!
//! ## Why a trait
//!
//! Today every static-API-key call site reaches into a process-local
//! `Keyring` via `keyring.get(name)`. That works for the single-tenant
//! single-host CLI, but the control-plane work needs three more things:
//!
//! 1. **Per-customer credentials.** The same `provider_name` + `key_name`
//!    can map to different secrets depending on which Parcha customer the
//!    JWT carries. The resolver cascades `customer_id → shared` in a
//!    single PG query so the call path doesn't grow a branch.
//! 2. **Encrypted at rest.** Plaintext lives only in `Zeroizing<String>`
//!    in process memory and only for as long as the cache TTL says.
//! 3. **Cross-pod refresh races.** Two proxy replicas asked to refresh the
//!    same OAuth token at the same time must end up with the same rotated
//!    refresh token. That's the `version BIGINT` optimistic-locking dance.
//!
//! ## Two implementations
//!
//! - [`KeyringResolver`] — wraps the existing `core::keyring::Keyring` and
//!   `core::oauth_store` (when PR #89 lands; for now, returns `NotConfigured`
//!   for OAuth). Customer scoping is ignored — always returns shared rows.
//!   Used by the local-mode CLI and by the proxy when no `ATI_DB_URL` /
//!   `ATI_MASTER_KEY` is configured.
//! - [`DbResolver`] (PR #4 of the stack) — Postgres-backed, envelope-
//!   decrypts each row, refreshes OAuth tokens via row-version optimistic
//!   locking. Selected at startup when DB + KEK are both present.
//!
//! Either way the call site sees the same async trait, so handlers stay
//! unchanged across the cutover.
//!
//! ## Caching
//!
//! Both implementations may cache plaintexts. The cache key is
//! `(provider_name, key_name, customer_id)`. TTL is 5 minutes — short
//! enough that revocation has a bounded blast radius, long enough that a
//! healthy proxy doesn't decrypt on every `/call`. Invalidation on writes
//! (the admin UI revoking a key) goes through `pg_notify` once the admin
//! layer lands; until then the TTL is your only safety net.

use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::core::keyring::Keyring;

#[derive(Debug, Error)]
pub enum ResolverError {
    /// The caller asked for a key/provider that simply isn't configured —
    /// no shared row, no per-customer row. Maps to `auth.missing_key` in
    /// the error classifier.
    #[error("resolver.not_configured: no credential for provider='{provider}' key='{key}' customer={customer:?}")]
    NotConfigured {
        provider: String,
        key: String,
        customer: Option<String>,
    },
    /// The on-disk keyring or DB row exists but the envelope can't be
    /// opened (master key gone, ciphertext tampered, wrong kek_id). This
    /// is a hard failure — we won't return a stale or guessed value.
    #[error("resolver.decrypt_failed: {0}")]
    DecryptFailed(String),
    /// A required upstream (PG, OAuth token endpoint) is unreachable.
    /// Reads might still succeed from cache; writes (refresh persistence)
    /// hard-fail.
    #[error("resolver.upstream_unavailable: {0}")]
    UpstreamUnavailable(String),
    /// OAuth token bundle exists but has expired and can't be refreshed
    /// (no refresh_token persisted, or the AS rejected the rotation).
    /// Maps to `auth.expired` in the error classifier.
    #[error("resolver.oauth_expired: {0}")]
    OauthExpired(String),
    /// Whatever the underlying store reported. Use sparingly — prefer the
    /// typed variants above so the proxy can map to a sane HTTP status.
    #[error("resolver.other: {0}")]
    Other(String),
}

/// Resolve credentials needed to authenticate an upstream request.
///
/// All methods take an optional `customer_id`. `None` means "no tenant" —
/// the resolver only matches shared (Parcha-owned) rows. A non-`None`
/// value tries the per-customer row first and falls back to the shared
/// row in a single round-trip.
#[async_trait]
pub trait CredentialResolver: Send + Sync + std::fmt::Debug {
    /// Fetch a static credential by name. Plaintext-out is zeroized on drop.
    ///
    /// `Ok(plaintext)` if a row matched. `Err(NotConfigured)` if neither
    /// the customer nor the shared scope has the key — handlers should
    /// surface that as `auth.missing_key`.
    async fn resolve_static(
        &self,
        provider_name: &str,
        key_name: &str,
        customer_id: Option<&str>,
    ) -> Result<Zeroizing<String>, ResolverError>;

    /// Fetch an OAuth access token for a provider, refreshing if it's
    /// within `min_remaining` of expiry.
    ///
    /// Implementations that talk to a DB use the `version BIGINT`
    /// optimistic-locking column to coordinate refreshes across replicas:
    /// the conditional UPDATE either succeeds (the local pod won the
    /// race) or returns 0 rows (a peer won — reload and use their
    /// rotated token).
    async fn resolve_oauth(
        &self,
        provider_name: &str,
        customer_id: Option<&str>,
        min_remaining: std::time::Duration,
    ) -> Result<Zeroizing<String>, ResolverError>;

    /// Force a refresh round-trip regardless of expiry, used by the
    /// 401-retry path. Returns the new access token.
    async fn force_refresh_oauth(
        &self,
        provider_name: &str,
        customer_id: Option<&str>,
    ) -> Result<Zeroizing<String>, ResolverError>;
}

// ---------------------------------------------------------------------------
// KeyringResolver — local-mode + bridge while DB callers ramp up
// ---------------------------------------------------------------------------

/// Local-mode resolver. Wraps an in-process `Keyring` for static lookups.
///
/// OAuth resolution is not yet wired here — local-mode OAuth flows through
/// `core::oauth_refresh::ensure_fresh_token` directly today. Once PR #89
/// (OAuth 2.1 + PKCE) lands on main we'll route the local-mode OAuth path
/// through this resolver too. Until then `resolve_oauth` returns
/// `NotConfigured` with a clear error message and the legacy code path
/// stays in place.
#[derive(Clone)]
pub struct KeyringResolver {
    keyring: Arc<Keyring>,
}

impl KeyringResolver {
    pub fn new(keyring: Keyring) -> Self {
        Self {
            keyring: Arc::new(keyring),
        }
    }

    pub fn from_arc(keyring: Arc<Keyring>) -> Self {
        Self { keyring }
    }

    /// Convenience for handlers that need raw keyring access while we're
    /// still mid-migration. Once every call site routes through
    /// `resolve_static`, this can be deleted.
    pub fn keyring(&self) -> &Keyring {
        &self.keyring
    }
}

impl std::fmt::Debug for KeyringResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the keyring's contents.
        f.debug_struct("KeyringResolver")
            .field("key_count", &self.keyring.key_names().len())
            .finish()
    }
}

#[async_trait]
impl CredentialResolver for KeyringResolver {
    async fn resolve_static(
        &self,
        provider_name: &str,
        key_name: &str,
        _customer_id: Option<&str>,
    ) -> Result<Zeroizing<String>, ResolverError> {
        // The local Keyring is global to the process and has no notion of
        // tenancy — every caller sees the same shared keys. That's the
        // right behavior for the CLI and for the proxy in pre-DB mode;
        // the DbResolver is where per-customer scoping comes online.
        match self.keyring.get(key_name) {
            Some(plain) => Ok(Zeroizing::new(plain.to_string())),
            None => Err(ResolverError::NotConfigured {
                provider: provider_name.to_string(),
                key: key_name.to_string(),
                customer: None,
            }),
        }
    }

    async fn resolve_oauth(
        &self,
        provider_name: &str,
        _customer_id: Option<&str>,
        _min_remaining: std::time::Duration,
    ) -> Result<Zeroizing<String>, ResolverError> {
        // Local-mode OAuth currently flows through core::oauth_refresh,
        // which is unrelated to this resolver. Once PR #89 lands we'll
        // route through here too. Until then, anything asking the
        // resolver for an OAuth token explicitly is a programming error.
        Err(ResolverError::NotConfigured {
            provider: provider_name.to_string(),
            key: "oauth_token".to_string(),
            customer: None,
        })
    }

    async fn force_refresh_oauth(
        &self,
        provider_name: &str,
        _customer_id: Option<&str>,
    ) -> Result<Zeroizing<String>, ResolverError> {
        Err(ResolverError::NotConfigured {
            provider: provider_name.to_string(),
            key: "oauth_token".to_string(),
            customer: None,
        })
    }
}

// ---------------------------------------------------------------------------
// DbResolver — Postgres-backed implementation (db feature only)
// ---------------------------------------------------------------------------

#[cfg(feature = "db")]
mod db_resolver;

#[cfg(feature = "db")]
pub use db_resolver::DbResolver;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_keyring(entries: &[(&str, &str)]) -> Keyring {
        let mut m = HashMap::new();
        for (k, v) in entries {
            m.insert((*k).to_string(), (*v).to_string());
        }
        Keyring::from_map(m)
    }

    #[tokio::test]
    async fn keyring_resolver_returns_shared_when_no_customer() {
        let kr = test_keyring(&[("particle_api_key", "secret-xyz")]);
        let r = KeyringResolver::new(kr);
        let got = r
            .resolve_static("particle", "particle_api_key", None)
            .await
            .unwrap();
        assert_eq!(&*got, "secret-xyz");
    }

    #[tokio::test]
    async fn keyring_resolver_ignores_customer_id() {
        // KeyringResolver is for local-mode / pre-DB proxies. customer_id
        // is intentionally non-functional here — handlers should still be
        // able to pass one through without the resolver erroring.
        let kr = test_keyring(&[("particle_api_key", "the-one-shared-key")]);
        let r = KeyringResolver::new(kr);
        let got_alpha = r
            .resolve_static("particle", "particle_api_key", Some("cust_alpha"))
            .await
            .unwrap();
        let got_none = r
            .resolve_static("particle", "particle_api_key", None)
            .await
            .unwrap();
        assert_eq!(&*got_alpha, "the-one-shared-key");
        assert_eq!(&*got_none, "the-one-shared-key");
    }

    #[tokio::test]
    async fn keyring_resolver_not_configured_when_key_missing() {
        let r = KeyringResolver::new(test_keyring(&[]));
        let err = r
            .resolve_static("particle", "particle_api_key", None)
            .await
            .unwrap_err();
        match err {
            ResolverError::NotConfigured {
                provider,
                key,
                customer,
            } => {
                assert_eq!(provider, "particle");
                assert_eq!(key, "particle_api_key");
                assert_eq!(customer, None);
            }
            other => panic!("expected NotConfigured, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn keyring_resolver_oauth_unsupported_in_local_mode() {
        let r = KeyringResolver::new(test_keyring(&[]));
        let err = r
            .resolve_oauth("particle", None, std::time::Duration::from_secs(60))
            .await
            .unwrap_err();
        assert!(matches!(err, ResolverError::NotConfigured { .. }));
    }

    #[test]
    fn keyring_resolver_debug_redacts_keys() {
        let kr = test_keyring(&[("sk_live_super_secret", "xxx"), ("another_key", "yyy")]);
        let r = KeyringResolver::new(kr);
        let s = format!("{r:?}");
        assert!(s.contains("KeyringResolver"));
        assert!(s.contains("key_count"));
        // Key names themselves are not secrets but values are — make sure
        // neither value nor name leaks via the dyn-Debug formatter.
        assert!(!s.contains("xxx"));
        assert!(!s.contains("yyy"));
        assert!(!s.contains("sk_live_super_secret"));
    }
}
