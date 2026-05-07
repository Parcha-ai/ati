//! OAuth 2.1 + PKCE protocol primitives for MCP servers.
//!
//! Implements the discovery cascade and token endpoints used by MCP servers
//! that follow the [Model Context Protocol authorization spec][mcp-spec]:
//!
//! 1. **Discovery** — `mcp_url` → [RFC 9728] protected-resource metadata →
//!    [RFC 8414] authorization-server metadata.
//! 2. **Dynamic Client Registration** — [RFC 7591] anonymous `POST /register`.
//!    MCP servers commonly issue public clients (no `client_secret`,
//!    `token_endpoint_auth_method = "none"`).
//! 3. **Authorization request** — [RFC 7636] PKCE `S256` + [RFC 8707] resource
//!    indicator. The `state` param is generated and validated by the caller
//!    (see `core::cli::provider::authorize`).
//! 4. **Token exchange and refresh** — `application/x-www-form-urlencoded`
//!    POST to the AS `/token` endpoint with `client_id` always in the body
//!    (Basic auth is not used for public clients).
//! 5. **Revocation** — best-effort [RFC 7009] for `ati provider deauthorize`.
//!
//! Discovery results are cached for 5 minutes per `mcp_url` to avoid hitting
//! the protected-resource and AS metadata endpoints on every connect — refresh
//! and exchange paths reuse already-discovered URLs from the persisted token
//! file (`core::oauth_store::ProviderTokens::token_endpoint`).
//!
//! All outbound URLs run through `core::http::validate_url_not_private` for
//! SSRF protection.
//!
//! [mcp-spec]: https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
//! [RFC 9728]: https://www.rfc-editor.org/rfc/rfc9728.html
//! [RFC 8414]: https://www.rfc-editor.org/rfc/rfc8414
//! [RFC 7591]: https://www.rfc-editor.org/rfc/rfc7591
//! [RFC 7636]: https://www.rfc-editor.org/rfc/rfc7636
//! [RFC 8707]: https://www.rfc-editor.org/rfc/rfc8707
//! [RFC 7009]: https://www.rfc-editor.org/rfc/rfc7009

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Path appended to `mcp_url` origin to fetch the protected-resource metadata.
pub const PROTECTED_RESOURCE_PATH: &str = "/.well-known/oauth-protected-resource";
/// Path appended to the authorization server origin to fetch AS metadata.
pub const AS_METADATA_PATH: &str = "/.well-known/oauth-authorization-server";

/// In-memory TTL for discovery results, per `mcp_url`.
const DISCOVERY_CACHE_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Error)]
pub enum OauthError {
    #[error("oauth.discovery_failed: {0}")]
    DiscoveryFailed(String),
    #[error("oauth.dcr_failed: {0}")]
    DcrFailed(String),
    #[error("oauth.exchange_failed: {0}")]
    ExchangeFailed(String),
    #[error("oauth.refresh_failed: {0}")]
    RefreshFailed(String),
    #[error("oauth.revoke_failed: {0}")]
    RevokeFailed(String),
    #[error("oauth.not_authorized: run `ati provider authorize {0}`")]
    NotAuthorized(String),
    #[error("oauth.http: {0}")]
    Http(String),
    #[error("oauth.io: {0}")]
    Io(#[from] std::io::Error),
    #[error("oauth.parse: {0}")]
    Parse(String),
    #[error("oauth.config: {0}")]
    Config(String),
}

impl From<reqwest::Error> for OauthError {
    fn from(e: reqwest::Error) -> Self {
        OauthError::Http(e.to_string())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    #[serde(default)]
    pub bearer_methods_supported: Vec<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AsMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    pub protected: ProtectedResourceMetadata,
    pub as_meta: AsMetadata,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default = "default_token_type")]
    pub token_type: String,
    /// Lifetime in seconds. Some servers omit this; we default to 1 hour and
    /// rely on 401-driven refresh to recover.
    #[serde(default = "default_expires_in")]
    pub expires_in: u64,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
}

fn default_token_type() -> String {
    "Bearer".to_string()
}

fn default_expires_in() -> u64 {
    3600
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DcrResponse {
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

static DISCOVERY_CACHE: LazyLock<Mutex<HashMap<String, (DiscoveryResult, Instant)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Discover the protected-resource and authorization-server metadata for an MCP URL.
///
/// Cascade:
/// 1. `GET {mcp_url_origin}/.well-known/oauth-protected-resource`
/// 2. Fetch AS metadata from the first entry of `authorization_servers`.
///
/// Cached for 5 minutes per `mcp_url`.
pub async fn discover(mcp_url: &str) -> Result<DiscoveryResult, OauthError> {
    {
        let cache = DISCOVERY_CACHE.lock().unwrap();
        if let Some((result, fetched_at)) = cache.get(mcp_url) {
            if fetched_at.elapsed() < DISCOVERY_CACHE_TTL {
                return Ok(result.clone());
            }
        }
    }

    let result = discover_uncached(mcp_url).await?;

    let mut cache = DISCOVERY_CACHE.lock().unwrap();
    cache.insert(mcp_url.to_string(), (result.clone(), Instant::now()));
    Ok(result)
}

async fn discover_uncached(mcp_url: &str) -> Result<DiscoveryResult, OauthError> {
    crate::core::http::validate_url_not_private(mcp_url)
        .map_err(|e| OauthError::DiscoveryFailed(format!("ssrf guard: {e}")))?;

    let origin = origin_of(mcp_url)?;
    let prm_url = format!("{origin}{PROTECTED_RESOURCE_PATH}");
    crate::core::http::validate_url_not_private(&prm_url)
        .map_err(|e| OauthError::DiscoveryFailed(format!("ssrf guard: {e}")))?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(OauthError::from)?;

    let prm_resp = client
        .get(&prm_url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| OauthError::DiscoveryFailed(format!("GET {prm_url}: {e}")))?;
    if !prm_resp.status().is_success() {
        return Err(OauthError::DiscoveryFailed(format!(
            "GET {prm_url} returned HTTP {}",
            prm_resp.status().as_u16()
        )));
    }
    let prm_text = prm_resp
        .text()
        .await
        .map_err(|e| OauthError::DiscoveryFailed(format!("read {prm_url}: {e}")))?;
    let protected: ProtectedResourceMetadata = serde_json::from_str(&prm_text).map_err(|e| {
        OauthError::DiscoveryFailed(format!("parse protected-resource doc: {e} :: {prm_text}"))
    })?;

    let as_url = protected
        .authorization_servers
        .first()
        .ok_or_else(|| OauthError::DiscoveryFailed("authorization_servers is empty".into()))?
        .clone();

    let as_meta_url = if as_url.contains("/.well-known/") {
        as_url.clone()
    } else {
        format!("{}{AS_METADATA_PATH}", as_url.trim_end_matches('/'))
    };

    crate::core::http::validate_url_not_private(&as_meta_url)
        .map_err(|e| OauthError::DiscoveryFailed(format!("ssrf guard: {e}")))?;

    let as_resp = client
        .get(&as_meta_url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| OauthError::DiscoveryFailed(format!("GET {as_meta_url}: {e}")))?;
    if !as_resp.status().is_success() {
        return Err(OauthError::DiscoveryFailed(format!(
            "GET {as_meta_url} returned HTTP {}",
            as_resp.status().as_u16()
        )));
    }
    let as_text = as_resp
        .text()
        .await
        .map_err(|e| OauthError::DiscoveryFailed(format!("read {as_meta_url}: {e}")))?;
    let as_meta: AsMetadata = serde_json::from_str(&as_text)
        .map_err(|e| OauthError::DiscoveryFailed(format!("parse AS metadata: {e} :: {as_text}")))?;

    Ok(DiscoveryResult { protected, as_meta })
}

fn origin_of(url: &str) -> Result<String, OauthError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| OauthError::Parse(format!("invalid URL '{url}': {e}")))?;
    let scheme = parsed.scheme();
    let host = parsed
        .host_str()
        .ok_or_else(|| OauthError::Parse(format!("URL missing host: {url}")))?;
    let port = match parsed.port() {
        Some(p) => format!(":{p}"),
        None => String::new(),
    };
    Ok(format!("{scheme}://{host}{port}"))
}

/// Clear the in-memory discovery cache (used by tests).
#[doc(hidden)]
pub fn clear_discovery_cache_for_test() {
    DISCOVERY_CACHE.lock().unwrap().clear();
}

// ---------------------------------------------------------------------------
// Dynamic Client Registration (RFC 7591)
// ---------------------------------------------------------------------------

/// Anonymous DCR. Returns `client_id`. MCP servers usually issue public
/// clients, so we don't expect a `client_secret` and ignore it if returned.
pub async fn register_client(
    registration_endpoint: &str,
    redirect_uri: &str,
    client_name: &str,
) -> Result<String, OauthError> {
    crate::core::http::validate_url_not_private(registration_endpoint)
        .map_err(|e| OauthError::DcrFailed(format!("ssrf guard: {e}")))?;

    let body = serde_json::json!({
        "client_name": client_name,
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "application_type": "native",
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let resp = client
        .post(registration_endpoint)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| OauthError::DcrFailed(format!("POST {registration_endpoint}: {e}")))?;

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(OauthError::DcrFailed(format!(
            "HTTP {} from {registration_endpoint}: {text}",
            status.as_u16()
        )));
    }
    let dcr: DcrResponse = serde_json::from_str(&text)
        .map_err(|e| OauthError::DcrFailed(format!("parse DCR response: {e} :: {text}")))?;
    Ok(dcr.client_id)
}

// ---------------------------------------------------------------------------
// PKCE (RFC 7636) and state generation
// ---------------------------------------------------------------------------

/// Generate a PKCE verifier/challenge pair using `S256`.
///
/// Returns `(code_verifier, code_challenge)` where:
/// - `code_verifier` is 43 chars, URL-safe base64 of 32 random bytes.
/// - `code_challenge` is `BASE64URL(SHA256(code_verifier))`, no padding.
pub fn make_pkce_pair() -> (String, String) {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes).expect("ring SystemRandom fill");
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let digest = hasher.finalize();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);

    (verifier, challenge)
}

/// 32 random bytes, URL-safe base64 — used for the OAuth `state` parameter.
pub fn make_state() -> String {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes).expect("ring SystemRandom fill");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Constant-time compare for the `state` value returned in the OAuth callback.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Token exchange + refresh
// ---------------------------------------------------------------------------

/// Exchange an authorization code for an access+refresh token pair.
///
/// Sends RFC 8707 `resource` indicator + RFC 7636 `code_verifier`. Public
/// clients put `client_id` in the body, no Basic auth.
#[allow(clippy::too_many_arguments)]
pub async fn exchange_code(
    token_endpoint: &str,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
    client_id: &str,
    resource: &str,
) -> Result<TokenResponse, OauthError> {
    crate::core::http::validate_url_not_private(token_endpoint)
        .map_err(|e| OauthError::ExchangeFailed(format!("ssrf guard: {e}")))?;

    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", code_verifier),
        ("resource", resource),
    ];

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let resp = client
        .post(token_endpoint)
        .header("Accept", "application/json")
        .form(&form)
        .send()
        .await
        .map_err(|e| OauthError::ExchangeFailed(format!("POST {token_endpoint}: {e}")))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(OauthError::ExchangeFailed(format!(
            "HTTP {} from {token_endpoint}: {text}",
            status.as_u16()
        )));
    }
    let tr: TokenResponse = serde_json::from_str(&text)
        .map_err(|e| OauthError::ExchangeFailed(format!("parse token response: {e} :: {text}")))?;
    Ok(tr)
}

/// Refresh an access token using a stored refresh token.
pub async fn refresh(
    token_endpoint: &str,
    refresh_token: &str,
    client_id: &str,
    resource: &str,
    scopes: &[String],
) -> Result<TokenResponse, OauthError> {
    crate::core::http::validate_url_not_private(token_endpoint)
        .map_err(|e| OauthError::RefreshFailed(format!("ssrf guard: {e}")))?;

    let scope_joined = scopes.join(" ");

    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
        ("resource", resource),
    ];
    if !scope_joined.is_empty() {
        form.push(("scope", scope_joined.as_str()));
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let resp = client
        .post(token_endpoint)
        .header("Accept", "application/json")
        .form(&form)
        .send()
        .await
        .map_err(|e| OauthError::RefreshFailed(format!("POST {token_endpoint}: {e}")))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(OauthError::RefreshFailed(format!(
            "HTTP {} from {token_endpoint}: {text}",
            status.as_u16()
        )));
    }
    let tr: TokenResponse = serde_json::from_str(&text)
        .map_err(|e| OauthError::RefreshFailed(format!("parse refresh response: {e} :: {text}")))?;
    Ok(tr)
}

/// Revoke a token at the AS revocation endpoint (best-effort).
pub async fn revoke(
    revocation_endpoint: &str,
    token: &str,
    client_id: &str,
    token_type_hint: Option<&str>,
) -> Result<(), OauthError> {
    crate::core::http::validate_url_not_private(revocation_endpoint)
        .map_err(|e| OauthError::RevokeFailed(format!("ssrf guard: {e}")))?;

    let mut form: Vec<(&str, &str)> = vec![("token", token), ("client_id", client_id)];
    if let Some(hint) = token_type_hint {
        form.push(("token_type_hint", hint));
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let resp = client
        .post(revocation_endpoint)
        .header("Accept", "application/json")
        .form(&form)
        .send()
        .await
        .map_err(|e| OauthError::RevokeFailed(format!("POST {revocation_endpoint}: {e}")))?;

    // RFC 7009: 200 on success. Most ASes also return 200 for unknown tokens.
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(OauthError::RevokeFailed(format!(
            "HTTP {} from {revocation_endpoint}: {text}",
            status.as_u16()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Authorize URL builder
// ---------------------------------------------------------------------------

/// Build the `/authorize` URL the operator's browser is redirected to.
#[allow(clippy::too_many_arguments)]
pub fn build_authorize_url(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
    resource: &str,
    scopes: &[String],
) -> Result<String, OauthError> {
    let mut url = reqwest::Url::parse(authorization_endpoint)
        .map_err(|e| OauthError::Parse(format!("invalid authorization_endpoint: {e}")))?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", client_id);
        q.append_pair("redirect_uri", redirect_uri);
        q.append_pair("state", state);
        q.append_pair("code_challenge", code_challenge);
        q.append_pair("code_challenge_method", "S256");
        q.append_pair("resource", resource);
        if !scopes.is_empty() {
            q.append_pair("scope", &scopes.join(" "));
        }
    }
    Ok(url.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_pair_shape() {
        let (verifier, challenge) = make_pkce_pair();
        // 32 bytes -> 43 chars URL-safe base64 no-pad
        assert_eq!(verifier.len(), 43, "verifier should be 43 chars");
        assert_eq!(challenge.len(), 43, "challenge should be 43 chars");
        assert!(!verifier.contains('='));
        assert!(!verifier.contains('+'));
        assert!(!verifier.contains('/'));

        // Recompute the challenge and ensure it matches.
        let mut h = Sha256::new();
        h.update(verifier.as_bytes());
        let digest = h.finalize();
        let recomputed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        assert_eq!(recomputed, challenge);
    }

    #[test]
    fn pkce_known_vector() {
        // RFC 7636 Appendix B example
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let mut h = Sha256::new();
        h.update(verifier.as_bytes());
        let digest = h.finalize();
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn state_uniqueness() {
        let a = make_state();
        let b = make_state();
        assert_ne!(a, b, "state collisions are astronomically unlikely");
        assert_eq!(a.len(), 43);
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(!constant_time_eq("", "x"));
    }

    #[test]
    fn origin_of_strips_path() {
        assert_eq!(
            origin_of("https://mcp.example.com/some/path?x=1").unwrap(),
            "https://mcp.example.com"
        );
        assert_eq!(
            origin_of("https://mcp.example.com:8443/foo").unwrap(),
            "https://mcp.example.com:8443"
        );
    }

    #[test]
    fn build_authorize_url_includes_all_params() {
        let url = build_authorize_url(
            "https://as.example.com/authorize",
            "oc_abc",
            "http://127.0.0.1:9876/callback",
            "STATE",
            "CHAL",
            "https://mcp.example.com",
            &["mcp:read".to_string(), "mcp:write".to_string()],
        )
        .unwrap();
        assert!(url.starts_with("https://as.example.com/authorize?"));
        for fragment in [
            "response_type=code",
            "client_id=oc_abc",
            "redirect_uri=http%3A%2F%2F127.0.0.1%3A9876%2Fcallback",
            "state=STATE",
            "code_challenge=CHAL",
            "code_challenge_method=S256",
            "resource=https%3A%2F%2Fmcp.example.com",
            "scope=mcp%3Aread+mcp%3Awrite",
        ] {
            assert!(url.contains(fragment), "missing {fragment} in {url}");
        }
    }
}
