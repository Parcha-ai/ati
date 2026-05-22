//! JWT-based authentication for ATI.
//!
//! ES256-signed JWTs carry identity + scopes + expiry in a single tamper-proof
//! credential. The orchestrator signs with a private key; the proxy validates
//! with the corresponding public key (served via JWKS).
//!
//! Supports ES256 (recommended) and HS256 (simpler, for single-machine setups).

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum JwtError {
    #[error("JWT encoding failed: {0}")]
    Encode(#[from] jsonwebtoken::errors::Error),
    #[error("Invalid PEM key: {0}")]
    InvalidKey(String),
    #[error("No encoding key configured (private key required for issuance)")]
    NoEncodingKey,
    #[error("No decoding key configured (public key required for validation)")]
    NoDecodingKey,
    #[error("Base64 decode error: {0}")]
    Base64(String),
}

/// Configuration for JWT validation and (optionally) issuance.
#[derive(Clone)]
pub struct JwtConfig {
    /// Public key for validation.
    pub decoding_key: DecodingKey,
    /// Private key for issuance (only on orchestrator).
    pub encoding_key: Option<EncodingKey>,
    /// Signing algorithm (ES256 or HS256).
    pub algorithm: Algorithm,
    /// Expected `iss` claim (optional — skipped if None).
    pub required_issuer: Option<String>,
    /// Accepted `aud` claim values. A token whose `aud` matches **any** entry
    /// in this list passes audience validation; the per-tool scope check
    /// downstream still gates the actual call.
    ///
    /// Single-element vec preserves v0.7.x single-audience behaviour. For
    /// multi-audience deployments (e.g. proxy accepting both `ati-proxy` and
    /// per-MCP-audience tokens — see issue #121), populate from
    /// `ATI_JWT_ACCEPTED_AUDIENCES` (CSV env var).
    pub accepted_audiences: Vec<String>,
    /// Clock skew tolerance in seconds.
    pub leeway_secs: u64,
    /// Raw public key PEM bytes (for JWKS endpoint).
    pub public_key_pem: Option<Vec<u8>>,
}

impl std::fmt::Debug for JwtConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtConfig")
            .field("algorithm", &self.algorithm)
            .field("required_issuer", &self.required_issuer)
            .field("accepted_audiences", &self.accepted_audiences)
            .field("leeway_secs", &self.leeway_secs)
            .field("has_encoding_key", &self.encoding_key.is_some())
            .finish()
    }
}

/// ATI-specific namespace in JWT claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtiNamespace {
    /// Claims schema version.
    pub v: u8,
    /// Per-tool-pattern rate limits (e.g. {"tool:github:*": "10/hour"}).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub rate: HashMap<String, String>,
}

/// JWT claims per RFC 9068.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Issuer (who signed this token).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Subject (agent identity).
    pub sub: String,
    /// Audience (target service, e.g. "ati-proxy").
    pub aud: String,
    /// Issued-at timestamp (Unix seconds).
    pub iat: u64,
    /// Expiry timestamp (Unix seconds).
    pub exp: u64,
    /// Unique token ID (UUID) for replay detection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Space-delimited scopes per RFC 9068 §2.2.3.
    pub scope: String,
    /// ATI-specific claims namespace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ati: Option<AtiNamespace>,
    /// Job identifier (set by orchestrator provisioner).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    /// Sandbox identifier (set by orchestrator provisioner).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,
}

impl TokenClaims {
    /// Parse the space-delimited scope string into a Vec.
    pub fn scopes(&self) -> Vec<String> {
        self.scope.split_whitespace().map(String::from).collect()
    }
}

/// Validate a JWT token string and return the claims.
///
/// A token whose `aud` claim matches **any** entry in
/// `config.accepted_audiences` passes. Per-tool authorization (scope check)
/// is done separately by callers via `ScopeConfig`.
pub fn validate(token: &str, config: &JwtConfig) -> Result<TokenClaims, JwtError> {
    let mut validation = Validation::new(config.algorithm);
    // jsonwebtoken's set_audience uses "any-match" semantics: token.aud is
    // accepted iff it matches at least one entry. Passing a slice of &str
    // borrows from the Vec<String> without allocating an intermediate owned
    // collection.
    let auds: Vec<&str> = config
        .accepted_audiences
        .iter()
        .map(String::as_str)
        .collect();
    validation.set_audience(&auds);
    validation.leeway = config.leeway_secs;

    if let Some(ref issuer) = config.required_issuer {
        validation.set_issuer(&[issuer]);
    } else {
        // Don't require issuer validation if not configured
        validation.set_required_spec_claims(&["exp", "sub", "aud"]);
    }

    let token_data: TokenData<TokenClaims> =
        jsonwebtoken::decode(token, &config.decoding_key, &validation)?;

    Ok(token_data.claims)
}

/// Issue (sign) a JWT token from claims.
pub fn issue(claims: &TokenClaims, config: &JwtConfig) -> Result<String, JwtError> {
    let encoding_key = config
        .encoding_key
        .as_ref()
        .ok_or(JwtError::NoEncodingKey)?;

    let header = Header::new(config.algorithm);
    let token = jsonwebtoken::encode(&header, claims, encoding_key)?;
    Ok(token)
}

/// Decode a JWT without verifying the signature (for inspection only).
pub fn inspect(token: &str) -> Result<TokenClaims, JwtError> {
    let mut validation = Validation::default();
    validation.insecure_disable_signature_validation();
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.set_required_spec_claims::<&str>(&[]);

    // Use a dummy key since we're not validating
    let key = DecodingKey::from_secret(b"unused");
    let token_data: TokenData<TokenClaims> = jsonwebtoken::decode(token, &key, &validation)?;

    Ok(token_data.claims)
}

/// Load an ES256 or RS256 public key from PEM bytes.
pub fn load_public_key_pem(pem: &[u8], alg: Algorithm) -> Result<DecodingKey, JwtError> {
    match alg {
        Algorithm::ES256 | Algorithm::ES384 => {
            DecodingKey::from_ec_pem(pem).map_err(|e| JwtError::InvalidKey(e.to_string()))
        }
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            DecodingKey::from_rsa_pem(pem).map_err(|e| JwtError::InvalidKey(e.to_string()))
        }
        _ => Err(JwtError::InvalidKey(format!(
            "Unsupported algorithm for PEM: {alg:?}"
        ))),
    }
}

/// Load an ES256 or RS256 private key from PEM bytes.
pub fn load_private_key_pem(pem: &[u8], alg: Algorithm) -> Result<EncodingKey, JwtError> {
    match alg {
        Algorithm::ES256 | Algorithm::ES384 => {
            EncodingKey::from_ec_pem(pem).map_err(|e| JwtError::InvalidKey(e.to_string()))
        }
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            EncodingKey::from_rsa_pem(pem).map_err(|e| JwtError::InvalidKey(e.to_string()))
        }
        _ => Err(JwtError::InvalidKey(format!(
            "Unsupported algorithm for PEM: {alg:?}"
        ))),
    }
}

/// Create a JwtConfig from an HS256 shared secret.
///
/// `audiences` is the allowlist of acceptable `aud` claim values; a token
/// matches if its `aud` equals any entry. Single-element vec for the
/// common single-audience case. **Empty vec is an error in v0.7.x callers
/// that hit it indirectly — every config-creation path normalises empty to
/// `["ati-proxy"]` (the historical default) so the proxy fails loud rather
/// than accepting any aud silently.** See `parse_audiences_env`.
pub fn config_from_secret(
    secret: &[u8],
    issuer: Option<String>,
    audiences: Vec<String>,
) -> JwtConfig {
    JwtConfig {
        decoding_key: DecodingKey::from_secret(secret),
        encoding_key: Some(EncodingKey::from_secret(secret)),
        algorithm: Algorithm::HS256,
        required_issuer: issuer,
        accepted_audiences: audiences,
        leeway_secs: 60,
        public_key_pem: None,
    }
}

/// Create a JwtConfig from PEM key files. See [`config_from_secret`] for
/// the `audiences` contract.
pub fn config_from_pem(
    public_pem: &[u8],
    private_pem: Option<&[u8]>,
    alg: Algorithm,
    issuer: Option<String>,
    audiences: Vec<String>,
) -> Result<JwtConfig, JwtError> {
    let decoding_key = load_public_key_pem(public_pem, alg)?;
    let encoding_key = match private_pem {
        Some(pem) => Some(load_private_key_pem(pem, alg)?),
        None => None,
    };

    Ok(JwtConfig {
        decoding_key,
        encoding_key,
        algorithm: alg,
        required_issuer: issuer,
        accepted_audiences: audiences,
        leeway_secs: 60,
        public_key_pem: Some(public_pem.to_vec()),
    })
}

/// Generate a JWKS JSON object from a public key PEM.
/// Returns the JWKS `keys` array suitable for `/.well-known/jwks.json`.
pub fn public_key_to_jwks(
    pem: &[u8],
    alg: Algorithm,
    kid: &str,
) -> Result<serde_json::Value, JwtError> {
    // Parse the PEM to extract the raw key bytes
    let pem_str = std::str::from_utf8(pem).map_err(|e| JwtError::InvalidKey(e.to_string()))?;

    // Extract base64 content between PEM headers
    let key_type = match alg {
        Algorithm::ES256 | Algorithm::ES384 => "EC",
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => "RSA",
        _ => {
            return Err(JwtError::InvalidKey(
                "Unsupported algorithm for JWKS".into(),
            ))
        }
    };

    let alg_str = match alg {
        Algorithm::ES256 => "ES256",
        Algorithm::ES384 => "ES384",
        Algorithm::RS256 => "RS256",
        Algorithm::RS384 => "RS384",
        Algorithm::RS512 => "RS512",
        _ => "unknown",
    };

    // For JWKS, we encode the full DER of the public key as x5c or use raw coordinates.
    // Simpler approach: encode the entire PEM-decoded DER as a base64url x5c entry.
    let der_b64: String = pem_str
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");

    let jwk = serde_json::json!({
        "kty": key_type,
        "use": "sig",
        "alg": alg_str,
        "kid": kid,
        "x5c": [der_b64],
    });

    Ok(serde_json::json!({
        "keys": [jwk]
    }))
}

/// Resolve the accepted-audience allowlist from environment.
///
/// Priority (first source wins):
/// 1. `ATI_JWT_ACCEPTED_AUDIENCES` (CSV) — operator declares an allowlist,
///    e.g. `"ati-proxy,parcha-custom-tools"`. Used when the proxy accepts
///    multiple aud values for per-provider audience separation (#121).
/// 2. `ATI_JWT_AUDIENCE` (singular) — back-compat with v0.7.x single-aud
///    deployments; wrapped in a one-element vec.
/// 3. Default: `["ati-proxy"]` — preserves v0.7.x behaviour when nothing
///    is set.
///
/// Empty/whitespace-only CSV entries are dropped. An empty list falls
/// through to the singular env / default rather than producing
/// `Vec::new()` (which `validate()` would interpret as "accept any aud").
pub fn parse_audiences_env() -> Vec<String> {
    if let Ok(csv) = std::env::var("ATI_JWT_ACCEPTED_AUDIENCES") {
        let v: Vec<String> = csv
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !v.is_empty() {
            return v;
        }
    }
    let single = std::env::var("ATI_JWT_AUDIENCE").unwrap_or_else(|_| "ati-proxy".to_string());
    vec![single]
}

/// Build a JwtConfig from environment variables.
///
/// Priority:
/// 1. `ATI_JWT_PUBLIC_KEY` (PEM file) → ES256
/// 2. `ATI_JWT_SECRET` (hex string) → HS256
/// 3. Neither → None (JWT disabled)
///
/// The audience allowlist is sourced via [`parse_audiences_env`] —
/// `ATI_JWT_ACCEPTED_AUDIENCES` (CSV) > `ATI_JWT_AUDIENCE` (singular) >
/// `["ati-proxy"]` default.
pub fn config_from_env() -> Result<Option<JwtConfig>, JwtError> {
    let issuer = std::env::var("ATI_JWT_ISSUER").ok();
    let audiences = parse_audiences_env();

    // Try ES256 first
    if let Ok(pub_key_path) = std::env::var("ATI_JWT_PUBLIC_KEY") {
        let public_pem = std::fs::read(&pub_key_path)
            .map_err(|e| JwtError::InvalidKey(format!("Cannot read {pub_key_path}: {e}")))?;

        let private_pem = std::env::var("ATI_JWT_PRIVATE_KEY")
            .ok()
            .and_then(|path| std::fs::read(&path).ok());

        let mut config = config_from_pem(
            &public_pem,
            private_pem.as_deref(),
            Algorithm::ES256,
            issuer,
            audiences,
        )?;

        // Store raw PEM for JWKS endpoint
        config.public_key_pem = Some(public_pem);

        return Ok(Some(config));
    }

    // Try HS256 fallback
    if let Ok(secret_hex) = std::env::var("ATI_JWT_SECRET") {
        let secret_bytes = hex::decode(&secret_hex)
            .map_err(|e| JwtError::InvalidKey(format!("ATI_JWT_SECRET is not valid hex: {e}")))?;

        return Ok(Some(config_from_secret(&secret_bytes, issuer, audiences)));
    }

    Ok(None)
}

/// Get the current Unix timestamp.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hs256_config() -> JwtConfig {
        config_from_secret(
            b"test-secret-key-32-bytes-long!!!",
            None,
            vec!["ati-proxy".into()],
        )
    }

    fn hs256_config_with_issuer() -> JwtConfig {
        config_from_secret(
            b"test-secret-key-32-bytes-long!!!",
            Some("ati-orchestrator".into()),
            vec!["ati-proxy".into()],
        )
    }

    fn make_claims(scope: &str) -> TokenClaims {
        let now = now_secs();
        TokenClaims {
            iss: Some("ati-orchestrator".into()),
            sub: "agent-7".into(),
            aud: "ati-proxy".into(),
            iat: now,
            exp: now + 1800,
            jti: Some(uuid::Uuid::new_v4().to_string()),
            scope: scope.into(),
            ati: Some(AtiNamespace {
                v: 1,
                rate: HashMap::new(),
            }),
            job_id: None,
            sandbox_id: None,
        }
    }

    #[test]
    fn test_hs256_round_trip() {
        let config = hs256_config();
        let claims = make_claims("tool:web_search tool:github:*");

        let token = issue(&claims, &config).unwrap();
        let decoded = validate(&token, &config).unwrap();

        assert_eq!(decoded.sub, "agent-7");
        assert_eq!(decoded.aud, "ati-proxy");
        assert_eq!(decoded.scope, "tool:web_search tool:github:*");
        assert_eq!(decoded.scopes(), vec!["tool:web_search", "tool:github:*"]);
        assert_eq!(decoded.iss, Some("ati-orchestrator".into()));
    }

    #[test]
    fn test_expired_token_rejected() {
        let config = hs256_config();
        let mut claims = make_claims("tool:web_search");
        claims.exp = 1; // Expired long ago

        let token = issue(&claims, &config).unwrap();
        let result = validate(&token, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_secret_rejected() {
        let config1 = hs256_config();
        let config2 = config_from_secret(
            b"different-secret-key-32-bytes!!",
            None,
            vec!["ati-proxy".into()],
        );

        let claims = make_claims("tool:web_search");
        let token = issue(&claims, &config1).unwrap();
        let result = validate(&token, &config2);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_audience_rejected() {
        let config = hs256_config();
        let mut claims = make_claims("tool:web_search");
        claims.aud = "wrong-audience".into();

        let token = issue(&claims, &config).unwrap();
        let result = validate(&token, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_issuer_rejected() {
        let config = hs256_config_with_issuer();
        let mut claims = make_claims("tool:web_search");
        claims.iss = Some("evil-orchestrator".into());

        let token = issue(&claims, &config).unwrap();
        let result = validate(&token, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_payload_rejected() {
        let config = hs256_config();
        let claims = make_claims("tool:web_search");
        let token = issue(&claims, &config).unwrap();

        // Tamper with the payload: change a character in the middle section
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let mut tampered_payload = parts[1].to_string();
        // Flip a character
        if tampered_payload.ends_with('A') {
            tampered_payload.push('B');
        } else {
            tampered_payload.push('A');
        }
        let tampered = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

        let result = validate(&tampered, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_malformed_token_rejected() {
        let config = hs256_config();
        let result = validate("not.a.jwt.token.at.all", &config);
        assert!(result.is_err());

        let result = validate("", &config);
        assert!(result.is_err());

        let result = validate("just-a-string", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_inspect_decodes_without_key() {
        let config = hs256_config();
        let claims = make_claims("tool:web_search skill:research-*");
        let token = issue(&claims, &config).unwrap();

        let decoded = inspect(&token).unwrap();
        assert_eq!(decoded.sub, "agent-7");
        assert_eq!(decoded.scope, "tool:web_search skill:research-*");
    }

    #[test]
    fn test_scope_parsing() {
        let claims = make_claims("tool:web_search tool:github:* skill:research-* help");
        let scopes = claims.scopes();
        assert_eq!(
            scopes,
            vec![
                "tool:web_search",
                "tool:github:*",
                "skill:research-*",
                "help"
            ]
        );
    }

    #[test]
    fn test_empty_scope() {
        let claims = make_claims("");
        assert!(claims.scopes().is_empty());
    }

    #[test]
    fn test_single_scope() {
        let claims = make_claims("*");
        assert_eq!(claims.scopes(), vec!["*"]);
    }

    #[test]
    fn test_no_encoding_key_fails() {
        let config = JwtConfig {
            decoding_key: DecodingKey::from_secret(b"test"),
            encoding_key: None,
            algorithm: Algorithm::HS256,
            required_issuer: None,
            accepted_audiences: vec!["ati-proxy".into()],
            leeway_secs: 60,
            public_key_pem: None,
        };

        let claims = make_claims("tool:web_search");
        let result = issue(&claims, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_issuer_not_required_when_none() {
        let config = hs256_config(); // No required_issuer
        let mut claims = make_claims("tool:web_search");
        claims.iss = None;

        let token = issue(&claims, &config).unwrap();
        let decoded = validate(&token, &config).unwrap();
        assert_eq!(decoded.iss, None);
    }

    #[test]
    fn test_jti_preserved() {
        let config = hs256_config();
        let claims = make_claims("tool:web_search");
        let jti = claims.jti.clone();

        let token = issue(&claims, &config).unwrap();
        let decoded = validate(&token, &config).unwrap();
        assert_eq!(decoded.jti, jti);
    }

    #[test]
    fn test_ati_namespace_preserved() {
        let config = hs256_config();
        let claims = make_claims("tool:web_search");

        let token = issue(&claims, &config).unwrap();
        let decoded = validate(&token, &config).unwrap();
        assert!(decoded.ati.is_some());
        assert_eq!(decoded.ati.unwrap().v, 1);
    }

    // -------------------------------------------------------------------------
    // Multi-audience validation (issue #121).
    //
    // The proxy needs to accept JWTs minted for different downstream services
    // (each with their own `aud` claim) so the sandbox can forward a
    // per-provider-scoped token without re-minting at the proxy boundary.
    //
    // jsonwebtoken's `Validation::set_audience` is natively any-match across
    // the slice, so the change is one-line. Tests here lock in the behaviour
    // so a future refactor can't regress to single-audience matching.
    // -------------------------------------------------------------------------

    fn hs256_config_multi(audiences: Vec<String>) -> JwtConfig {
        config_from_secret(b"test-secret-key-32-bytes-long!!!", None, audiences)
    }

    #[test]
    fn test_multi_audience_accepts_first() {
        let config = hs256_config_multi(vec!["ati-proxy".into(), "parcha-tools".into()]);
        let mut claims = make_claims("tool:web_search");
        claims.aud = "ati-proxy".into();

        let token = issue(&claims, &config).unwrap();
        let decoded = validate(&token, &config).expect("aud=ati-proxy should pass");
        assert_eq!(decoded.aud, "ati-proxy");
    }

    #[test]
    fn test_multi_audience_accepts_second() {
        let config = hs256_config_multi(vec!["ati-proxy".into(), "parcha-tools".into()]);
        let mut claims = make_claims("tool:web_search");
        claims.aud = "parcha-tools".into();

        let token = issue(&claims, &config).unwrap();
        let decoded = validate(&token, &config).expect("aud=parcha-tools should pass");
        assert_eq!(decoded.aud, "parcha-tools");
    }

    #[test]
    fn test_multi_audience_rejects_out_of_list() {
        let config = hs256_config_multi(vec!["ati-proxy".into(), "parcha-tools".into()]);
        let mut claims = make_claims("tool:web_search");
        claims.aud = "evil-aud".into();

        let token = issue(&claims, &config).unwrap();
        let result = validate(&token, &config);
        assert!(result.is_err(), "aud not in allowlist must be rejected");
    }

    #[test]
    fn test_single_audience_back_compat() {
        // A one-element vec must behave exactly as the v0.7.x single-aud
        // String case did — same tokens accepted, same tokens rejected.
        let config = hs256_config_multi(vec!["ati-proxy".into()]);
        let mut claims = make_claims("tool:web_search");

        claims.aud = "ati-proxy".into();
        let token = issue(&claims, &config).unwrap();
        assert!(validate(&token, &config).is_ok());

        claims.aud = "wrong".into();
        let token = issue(&claims, &config).unwrap();
        assert!(validate(&token, &config).is_err());
    }

    // -------------------------------------------------------------------------
    // parse_audiences_env (issue #121).
    //
    // Test using env vars requires serializing across tests; reuse the same
    // Mutex pattern as core::token::tests::ENV_LOCK rather than re-rolling.
    // -------------------------------------------------------------------------

    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        prev: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn set(pairs: &[(&'static str, Option<&str>)]) -> Self {
            let mut prev = Vec::new();
            for (k, v) in pairs {
                prev.push((*k, std::env::var(k).ok()));
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
            Self { prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.prev {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    fn test_parse_audiences_env_csv_wins() {
        let _g = ENV_LOCK.lock().unwrap();
        let _e = EnvGuard::set(&[
            ("ATI_JWT_ACCEPTED_AUDIENCES", Some("a, b ,c")),
            ("ATI_JWT_AUDIENCE", Some("ignored-singular")),
        ]);
        assert_eq!(parse_audiences_env(), vec!["a", "b", "c"]);
    }

    #[test]
    fn test_parse_audiences_env_falls_back_to_singular() {
        let _g = ENV_LOCK.lock().unwrap();
        let _e = EnvGuard::set(&[
            ("ATI_JWT_ACCEPTED_AUDIENCES", None),
            ("ATI_JWT_AUDIENCE", Some("custom-aud")),
        ]);
        assert_eq!(parse_audiences_env(), vec!["custom-aud"]);
    }

    #[test]
    fn test_parse_audiences_env_default_is_ati_proxy() {
        let _g = ENV_LOCK.lock().unwrap();
        let _e = EnvGuard::set(&[
            ("ATI_JWT_ACCEPTED_AUDIENCES", None),
            ("ATI_JWT_AUDIENCE", None),
        ]);
        assert_eq!(parse_audiences_env(), vec!["ati-proxy"]);
    }

    #[test]
    fn test_parse_audiences_env_csv_all_empty_falls_back() {
        // Pathological config: "ATI_JWT_ACCEPTED_AUDIENCES=  ,  ,  ". If we
        // honoured the empty list we'd silently accept any aud — instead
        // fall through to the singular env / default. validate()'s contract
        // is that the allowlist is never empty.
        let _g = ENV_LOCK.lock().unwrap();
        let _e = EnvGuard::set(&[
            ("ATI_JWT_ACCEPTED_AUDIENCES", Some("  ,  ,  ")),
            ("ATI_JWT_AUDIENCE", Some("fallback-aud")),
        ]);
        assert_eq!(parse_audiences_env(), vec!["fallback-aud"]);
    }
}
