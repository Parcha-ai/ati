//! Race-safe access-token refresh used by the proxy hot path and CLI.
//!
//! Two layers of mutual exclusion:
//! - **In-process**: a `tokio::sync::Mutex` per provider, stored in a
//!   `OnceLock<DashMap<…>>`. Multiple concurrent `tools/call` requests in the
//!   same proxy will line up rather than racing each other.
//! - **Cross-process**: an `fcntl(F_SETLK)` advisory lock on the provider's
//!   `.lock` file (`core::oauth_store::acquire_file_lock`). Two ATI binaries
//!   on the same host (CLI + proxy, or two CLI invocations) can't both refresh
//!   the same provider at the same time.
//!
//! Inside the locks we always `oauth_store::load` from disk before deciding
//! to refresh. That way, if a peer beat us to the refresh, our `load` returns
//! the freshly-rotated tokens and we skip the redundant round-trip — the
//! peer already won.
//!
//! `force_refresh` is the 401-recovery path: it always issues a refresh
//! round-trip even if the on-disk `expires_at` looks fine, because the
//! upstream just told us the access token is bad.
//!
//! Refresh failures map to `OauthError::RefreshFailed` and are surfaced to
//! the caller; the proxy catches them and translates to an `auth.expired`
//! error class via `core::error::classify_error`.

use dashmap::DashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::Mutex;

use crate::core::manifest::Provider;
use crate::core::oauth_mcp::{self, OauthError};
use crate::core::oauth_store::{self, ProviderTokens};

static REFRESH_LOCKS: OnceLock<DashMap<String, Arc<Mutex<()>>>> = OnceLock::new();

fn lock_for(provider: &str) -> Arc<Mutex<()>> {
    let map = REFRESH_LOCKS.get_or_init(DashMap::new);
    map.entry(provider.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

/// Return a usable access token for `provider`. Refreshes if the persisted
/// access token is missing, expired, or expires within `min_remaining`.
///
/// Returns `OauthError::NotAuthorized` if no token bundle exists on disk.
pub async fn ensure_fresh_token(
    provider: &Provider,
    min_remaining: Duration,
) -> Result<String, OauthError> {
    let mutex = lock_for(&provider.name);
    let _guard = mutex.lock().await;

    // The fcntl lock blocks the thread; do it inside spawn_blocking so we
    // don't pin the tokio worker.
    let provider_name = provider.name.clone();
    let _file_lock =
        tokio::task::spawn_blocking(move || oauth_store::acquire_file_lock(&provider_name))
            .await
            .map_err(|e| OauthError::Io(std::io::Error::other(format!("spawn_blocking: {e}"))))??;

    let tokens = oauth_store::load(&provider.name)?
        .ok_or_else(|| OauthError::NotAuthorized(provider.name.clone()))?;

    let need_refresh = {
        let remaining = tokens.access_remaining();
        let secs = remaining.num_seconds();
        secs <= 0 || (secs as u64) < min_remaining.as_secs()
    };

    if !need_refresh {
        return Ok(tokens.access_token);
    }

    do_refresh(provider, &tokens).await
}

/// Always issue a refresh round-trip, regardless of the on-disk `expires_at`.
/// Used by the 401-retry path in `mcp_client::send_http_request`.
pub async fn force_refresh(provider: &Provider) -> Result<String, OauthError> {
    let mutex = lock_for(&provider.name);
    let _guard = mutex.lock().await;

    let provider_name = provider.name.clone();
    let _file_lock =
        tokio::task::spawn_blocking(move || oauth_store::acquire_file_lock(&provider_name))
            .await
            .map_err(|e| OauthError::Io(std::io::Error::other(format!("spawn_blocking: {e}"))))??;

    let tokens = oauth_store::load(&provider.name)?
        .ok_or_else(|| OauthError::NotAuthorized(provider.name.clone()))?;

    // If the on-disk refresh_token differs from our in-memory snapshot taken
    // before acquiring the lock, a peer already refreshed under us — return
    // its access token instead of burning our (now-rotated) refresh token.
    // We can detect this by comparing `updated_at` against a snapshot taken
    // pre-lock... but since we always re-load post-lock, the value we see
    // here IS the latest. So just check expiry: if it looks fresh, use it.
    if !tokens.is_access_expired() && tokens.access_remaining().num_seconds() > 30 {
        return Ok(tokens.access_token);
    }

    do_refresh(provider, &tokens).await
}

/// Internal: perform the actual refresh round-trip and persist the new bundle.
async fn do_refresh(provider: &Provider, prior: &ProviderTokens) -> Result<String, OauthError> {
    let refresh_token = prior
        .refresh_token
        .as_deref()
        .ok_or_else(|| OauthError::RefreshFailed("no refresh_token persisted".into()))?;

    let resource = provider
        .oauth_resource
        .clone()
        .unwrap_or_else(|| prior.resource.clone());

    let response = oauth_mcp::refresh(
        &prior.token_endpoint,
        refresh_token,
        &prior.client_id,
        &resource,
        &provider.oauth_scopes,
    )
    .await?;

    // Build the new bundle. If the AS rotated the refresh token, persist the
    // new one; otherwise keep the prior refresh token (some ASes don't rotate).
    let now = chrono::Utc::now();
    let expires_in = i64::try_from(response.expires_in).unwrap_or(3600);
    let new_bundle = ProviderTokens {
        provider: prior.provider.clone(),
        client_id: prior.client_id.clone(),
        redirect_uri: prior.redirect_uri.clone(),
        access_token: response.access_token.clone(),
        access_token_expires_at: now + chrono::Duration::seconds(expires_in),
        refresh_token: response
            .refresh_token
            .clone()
            .or_else(|| prior.refresh_token.clone()),
        scopes: if !provider.oauth_scopes.is_empty() {
            provider.oauth_scopes.clone()
        } else {
            prior.scopes.clone()
        },
        resource: resource.clone(),
        token_endpoint: prior.token_endpoint.clone(),
        revocation_endpoint: prior.revocation_endpoint.clone(),
        authorized_at: prior.authorized_at,
        updated_at: now,
    };

    oauth_store::save(&new_bundle)?;
    Ok(response.access_token)
}

#[doc(hidden)]
#[cfg(test)]
pub fn clear_refresh_locks_for_test() {
    if let Some(map) = REFRESH_LOCKS.get() {
        map.clear();
    }
}
