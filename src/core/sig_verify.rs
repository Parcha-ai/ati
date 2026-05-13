//! HMAC sandbox-signature verification middleware.
//!
//! Ports `parcha-proxy/verify/server.py` to a native axum middleware. The
//! sandbox runner signs every outbound request with an HMAC-SHA256 of
//! `{ts}.{method}.{path}` using a shared secret. The proxy verifies the
//! signature here, with three modes:
//!
//! - `log`     — always allow; log validity + reason. Pre-rollout default.
//! - `warn`    — always allow; add `X-Signature-Status` response header.
//! - `enforce` — reject invalid/missing with `403 Forbidden`.
//!
//! The signing secret is loaded from the keyring at startup and stored in an
//! `ArcSwapOption` so a SIGHUP-driven keyring reload can swap it in place
//! without restarting the proxy.
//!
//! Exempt paths (defaults: `/healthz`, `/health`, `/root/*`, `/npm/*`,
//! `/otel/*`, `/.well-known/jwks.json`) bypass the check — these are the
//! routes Caddy didn't `forward_auth` either, plus ATI's own health/JWKS
//! endpoints. The exempt list is operator-configurable via
//! `--sig-exempt-paths`.

use arc_swap::ArcSwapOption;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use axum::middleware::Next;
use clap::ValueEnum;
use globset::{Glob, GlobSet, GlobSetBuilder};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

use crate::core::keyring::Keyring;

type HmacSha256 = Hmac<Sha256>;

/// Header name carrying the signature, e.g. `X-Sandbox-Signature: t=...,s=...`.
pub const SIGNATURE_HEADER: &str = "x-sandbox-signature";

/// Optional debug header carrying the sandbox job id. Only used for logging
/// — verification doesn't depend on it.
pub const JOB_ID_HEADER: &str = "x-sandbox-job-id";

/// Response header inserted by `warn` mode so the client can observe sig
/// validity without being blocked. Mirrors verify.py.
pub const STATUS_HEADER: &str = "x-signature-status";

/// Keyring entry name where the shared HMAC secret lives.
pub const SECRET_KEY_NAME: &str = "sandbox_signing_shared_secret";

/// Default exempt globs. Verbatim from Caddyfile.prod-with-verify + ATI's
/// public endpoints.
pub const DEFAULT_EXEMPT_PATHS: &[&str] = &[
    "/healthz",
    "/health",
    "/root/*",
    "/root/**",
    "/npm/*",
    "/npm/**",
    "/otel/*",
    "/otel/**",
    "/.well-known/jwks.json",
];

/// Verification mode — picked by the operator at startup via
/// `--sig-verify-mode`. `log` is the safe default for rollout: requests
/// flow regardless of signature validity, but the structured log makes the
/// state observable in real traffic before enforcement is flipped on.
#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq, Default)]
#[clap(rename_all = "lower")]
pub enum SigVerifyMode {
    /// Always allow; log validity + reason. Safe default for rollout.
    #[default]
    Log,
    /// Always allow; insert `X-Signature-Status: valid|<reason>` on the response.
    Warn,
    /// Reject invalid/missing with `403 Forbidden`.
    Enforce,
}

/// Runtime config for the middleware. Held in `ProxyState` as an `Arc<_>` so
/// the hot path doesn't pay a clone. `secret` is `ArcSwapOption` so SIGHUP
/// can hot-reload the keyring without process restart.
pub struct SigVerifyConfig {
    pub mode: SigVerifyMode,
    pub drift_seconds: i64,
    pub exempt: GlobSet,
    /// HMAC key. `None` = secret not configured. In `enforce` mode this
    /// causes every request to fail-closed; in `log`/`warn` the requests
    /// pass with `reason = no_signing_secret_configured`.
    pub secret: ArcSwapOption<Vec<u8>>,
}

impl SigVerifyConfig {
    /// Build a config given operator flags and a keyring to read the secret
    /// from. Compiles the exempt-glob set once. Returns an error if any
    /// exempt pattern is invalid.
    pub fn build(
        mode: SigVerifyMode,
        drift_seconds: i64,
        exempt_paths: &[&str],
        keyring: &Keyring,
    ) -> Result<Self, SigVerifyError> {
        let exempt = build_globset(exempt_paths)?;
        let cfg = Self {
            mode,
            drift_seconds,
            exempt,
            secret: ArcSwapOption::from(None),
        };
        cfg.reload(keyring);
        Ok(cfg)
    }

    /// Reload the secret from the keyring. Called at startup and on every
    /// SIGHUP. Tries hex-decode first, falls back to raw UTF-8 bytes —
    /// matches verify.py:109-112.
    pub fn reload(&self, keyring: &Keyring) {
        match keyring.get(SECRET_KEY_NAME) {
            Some(raw) => {
                let bytes = match hex::decode(raw) {
                    Ok(b) => b,
                    Err(_) => raw.as_bytes().to_vec(),
                };
                self.secret.store(Some(Arc::new(bytes)));
                tracing::info!(
                    secret_bytes = self.secret.load().as_ref().map(|s| s.len()).unwrap_or(0),
                    "sandbox signing secret loaded"
                );
            }
            None => {
                self.secret.store(None);
                tracing::warn!(
                    "sandbox signing secret '{SECRET_KEY_NAME}' not present in keyring \
                     — all signatures will fail verification"
                );
            }
        }
    }

    /// True iff a signature secret is currently loaded.
    pub fn has_secret(&self) -> bool {
        self.secret.load().is_some()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SigVerifyError {
    #[error("bad exempt path pattern '{0}': {1}")]
    BadExemptGlob(String, String),
}

fn build_globset(patterns: &[&str]) -> Result<GlobSet, SigVerifyError> {
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        let glob = Glob::new(p)
            .map_err(|e| SigVerifyError::BadExemptGlob(p.to_string(), e.to_string()))?;
        builder.add(glob);
    }
    builder
        .build()
        .map_err(|e| SigVerifyError::BadExemptGlob(String::new(), e.to_string()))
}

/// Verification result for a single request. `Valid` ⇒ HMAC matched. All
/// other variants carry a `&'static str` reason that mirrors verify.py's
/// log strings byte-for-byte for downstream log parsers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Valid,
    MissingSignature,
    MalformedSignature,
    InvalidTimestamp,
    ExpiredTimestamp(i64), // drift in seconds
    NoSecretConfigured,
    HmacMismatch,
}

impl Verdict {
    pub fn is_valid(self) -> bool {
        matches!(self, Verdict::Valid)
    }

    pub fn reason(self) -> String {
        match self {
            Verdict::Valid => "valid".to_string(),
            Verdict::MissingSignature => "missing_signature".to_string(),
            Verdict::MalformedSignature => "malformed_signature".to_string(),
            Verdict::InvalidTimestamp => "invalid_timestamp".to_string(),
            Verdict::ExpiredTimestamp(drift) => format!("expired_timestamp_drift={drift}s"),
            Verdict::NoSecretConfigured => "no_signing_secret_configured".to_string(),
            Verdict::HmacMismatch => "hmac_mismatch".to_string(),
        }
    }
}

/// Parse `t=<ts>,s=<hex>` header → `(timestamp_str, sig_hex)`. Returns
/// `None` on malformed input. Tolerates extra k=v pairs (forward-compat).
fn parse_signature_header(header: &str) -> Option<(&str, &str)> {
    let mut ts = None;
    let mut sig = None;
    for segment in header.split(',') {
        let mut kv = segment.trim().splitn(2, '=');
        let k = kv.next()?.trim();
        let v = kv.next()?.trim();
        match k {
            "t" => ts = Some(v),
            "s" => sig = Some(v),
            _ => {} // ignore unknown segments
        }
    }
    Some((ts?, sig?))
}

/// Pure verification. Separate from the middleware so it's directly testable.
/// `now_unix` is injected to make drift tests deterministic.
pub fn verify(
    cfg: &SigVerifyConfig,
    method: &str,
    path: &str,
    sig_header: Option<&str>,
    now_unix: i64,
) -> Verdict {
    let sig_header = match sig_header {
        Some(h) if !h.is_empty() => h,
        _ => return Verdict::MissingSignature,
    };
    let (ts_str, sig_hex) = match parse_signature_header(sig_header) {
        Some(parts) => parts,
        None => return Verdict::MalformedSignature,
    };
    if ts_str.is_empty() || sig_hex.is_empty() {
        return Verdict::MalformedSignature;
    }
    let ts: i64 = match ts_str.parse() {
        Ok(n) => n,
        Err(_) => return Verdict::InvalidTimestamp,
    };
    let drift = (now_unix - ts).abs();
    if drift > cfg.drift_seconds {
        return Verdict::ExpiredTimestamp(drift);
    }
    let secret_arc = cfg.secret.load();
    let secret = match &*secret_arc {
        Some(s) => s.clone(),
        None => return Verdict::NoSecretConfigured,
    };
    let message = format!("{ts_str}.{method}.{path}");
    let mut mac = match HmacSha256::new_from_slice(&secret) {
        Ok(m) => m,
        Err(_) => return Verdict::NoSecretConfigured, // zero-length key
    };
    mac.update(message.as_bytes());
    let expected = mac.finalize().into_bytes();
    // Decode the hex signature provided by the client. Constant-time compare.
    let provided = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return Verdict::MalformedSignature,
    };
    if expected.len() != provided.len() {
        return Verdict::HmacMismatch;
    }
    if bool::from(expected.as_slice().ct_eq(&provided)) {
        Verdict::Valid
    } else {
        Verdict::HmacMismatch
    }
}

/// axum middleware. Extracts the request method + path + signature header,
/// runs `verify`, then mode-routes:
/// - `Log`     → pass through; structured log only.
/// - `Warn`    → pass through; insert `X-Signature-Status` on response.
/// - `Enforce` → 403 with the reason as body if invalid.
pub async fn sig_verify_middleware(
    State(state): State<Arc<crate::proxy::server::ProxyState>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    let cfg = &state.sig_verify;

    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();

    // Exempt-path bypass — no verification, no logging at info level.
    if cfg.exempt.is_match(&path) {
        return Ok(next.run(req).await);
    }

    let sig_header = req
        .headers()
        .get(SIGNATURE_HEADER)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let job_id = req
        .headers()
        .get(JOB_ID_HEADER)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("none")
        .to_string();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let verdict = verify(cfg, &method, &path, sig_header.as_deref(), now);

    tracing::info!(
        mode = ?cfg.mode,
        valid = verdict.is_valid(),
        reason = %verdict.reason(),
        job_id = %job_id,
        method = %method,
        path = %path,
        "sig_verify"
    );

    match cfg.mode {
        SigVerifyMode::Log => Ok(next.run(req).await),
        SigVerifyMode::Warn => {
            let mut resp = next.run(req).await;
            if let Ok(v) = axum::http::HeaderValue::from_str(&verdict.reason()) {
                resp.headers_mut().insert(STATUS_HEADER, v);
            }
            Ok(resp)
        }
        SigVerifyMode::Enforce => {
            if verdict.is_valid() {
                Ok(next.run(req).await)
            } else {
                Ok(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::from(verdict.reason()))
                    .unwrap_or_else(|_| {
                        Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::empty())
                            .expect("403 fallback")
                    }))
            }
        }
    }
}

/// Parse a comma-separated CLI value into `&'static str`-style refs via an
/// owned `Vec<String>`. Helper for the `--sig-exempt-paths` flag.
pub fn parse_exempt_paths(csv: &str) -> Vec<String> {
    csv.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::encode as hex_encode;

    fn cfg_with_secret(mode: SigVerifyMode, secret_bytes: Option<&[u8]>) -> SigVerifyConfig {
        let exempt = build_globset(DEFAULT_EXEMPT_PATHS).unwrap();
        let cfg = SigVerifyConfig {
            mode,
            drift_seconds: 60,
            exempt,
            secret: ArcSwapOption::from(None),
        };
        if let Some(b) = secret_bytes {
            cfg.secret.store(Some(Arc::new(b.to_vec())));
        }
        cfg
    }

    fn sign(ts: i64, method: &str, path: &str, secret: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(format!("{ts}.{method}.{path}").as_bytes());
        hex_encode(mac.finalize().into_bytes())
    }

    #[test]
    fn valid_signature_passes() {
        let cfg = cfg_with_secret(SigVerifyMode::Enforce, Some(b"shh-its-a-secret"));
        let ts = 1_700_000_000;
        let sig = sign(ts, "POST", "/v1/chat", b"shh-its-a-secret");
        let header = format!("t={ts},s={sig}");
        assert_eq!(
            verify(&cfg, "POST", "/v1/chat", Some(&header), ts + 5),
            Verdict::Valid
        );
    }

    #[test]
    fn missing_signature_fails() {
        let cfg = cfg_with_secret(SigVerifyMode::Enforce, Some(b"k"));
        assert_eq!(
            verify(&cfg, "GET", "/x", None, 0),
            Verdict::MissingSignature
        );
        assert_eq!(
            verify(&cfg, "GET", "/x", Some(""), 0),
            Verdict::MissingSignature
        );
    }

    #[test]
    fn malformed_header_fails() {
        let cfg = cfg_with_secret(SigVerifyMode::Enforce, Some(b"k"));
        // No `t=`/`s=` pair
        assert_eq!(
            verify(&cfg, "GET", "/x", Some("garbage"), 0),
            Verdict::MalformedSignature
        );
        // Only t, missing s
        assert_eq!(
            verify(&cfg, "GET", "/x", Some("t=1"), 0),
            Verdict::MalformedSignature
        );
        // Empty values
        assert_eq!(
            verify(&cfg, "GET", "/x", Some("t=,s="), 0),
            Verdict::MalformedSignature
        );
        // s value not hex
        let header = "t=100,s=not-hex-at-all";
        assert_eq!(
            verify(&cfg, "GET", "/x", Some(header), 100),
            Verdict::MalformedSignature
        );
    }

    #[test]
    fn non_numeric_timestamp_fails() {
        let cfg = cfg_with_secret(SigVerifyMode::Enforce, Some(b"k"));
        assert_eq!(
            verify(&cfg, "GET", "/x", Some("t=abc,s=deadbeef"), 0),
            Verdict::InvalidTimestamp
        );
    }

    #[test]
    fn expired_timestamp_returns_drift() {
        let cfg = cfg_with_secret(SigVerifyMode::Enforce, Some(b"k"));
        let ts = 1_000_000;
        let sig = sign(ts, "GET", "/x", b"k");
        let header = format!("t={ts},s={sig}");
        let now = ts + 120; // 120s drift, default cfg cap is 60
        match verify(&cfg, "GET", "/x", Some(&header), now) {
            Verdict::ExpiredTimestamp(drift) => assert_eq!(drift, 120),
            other => panic!("expected ExpiredTimestamp, got {other:?}"),
        }
    }

    #[test]
    fn drift_within_window_passes() {
        let cfg = cfg_with_secret(SigVerifyMode::Enforce, Some(b"k"));
        let ts = 1_000_000;
        let sig = sign(ts, "GET", "/x", b"k");
        let header = format!("t={ts},s={sig}");
        // 59s of drift — boundary inside the default 60s window
        assert_eq!(
            verify(&cfg, "GET", "/x", Some(&header), ts + 59),
            Verdict::Valid
        );
        // backwards drift also accepted
        assert_eq!(
            verify(&cfg, "GET", "/x", Some(&header), ts - 30),
            Verdict::Valid
        );
    }

    #[test]
    fn no_secret_configured_fails_closed() {
        let cfg = cfg_with_secret(SigVerifyMode::Enforce, None);
        let header = "t=100,s=deadbeef";
        assert_eq!(
            verify(&cfg, "GET", "/x", Some(header), 100),
            Verdict::NoSecretConfigured
        );
    }

    #[test]
    fn wrong_secret_fails_hmac() {
        let cfg = cfg_with_secret(SigVerifyMode::Enforce, Some(b"server-secret"));
        let ts = 100;
        // Client signs with a different key
        let sig = sign(ts, "GET", "/x", b"client-thinks-this-is-the-key");
        let header = format!("t={ts},s={sig}");
        assert_eq!(
            verify(&cfg, "GET", "/x", Some(&header), ts),
            Verdict::HmacMismatch
        );
    }

    #[test]
    fn method_or_path_tampering_fails_hmac() {
        let cfg = cfg_with_secret(SigVerifyMode::Enforce, Some(b"k"));
        let ts = 100;
        // Sign for POST /a but verify against GET /a
        let sig = sign(ts, "POST", "/a", b"k");
        let header = format!("t={ts},s={sig}");
        assert_eq!(
            verify(&cfg, "GET", "/a", Some(&header), ts),
            Verdict::HmacMismatch
        );
        // Sign for /a but verify against /b
        let sig = sign(ts, "POST", "/a", b"k");
        let header = format!("t={ts},s={sig}");
        assert_eq!(
            verify(&cfg, "POST", "/b", Some(&header), ts),
            Verdict::HmacMismatch
        );
    }

    #[test]
    fn signature_with_wrong_byte_length_fails() {
        let cfg = cfg_with_secret(SigVerifyMode::Enforce, Some(b"k"));
        // Truncated hex → decodes to a shorter byte string than expected.
        let header = "t=100,s=deadbeef"; // 4 bytes vs HMAC-SHA256's 32
        assert_eq!(
            verify(&cfg, "GET", "/x", Some(header), 100),
            Verdict::HmacMismatch
        );
    }

    #[test]
    fn extra_header_segments_tolerated() {
        // Forward-compat: clients may add k=v pairs we don't recognize.
        let cfg = cfg_with_secret(SigVerifyMode::Enforce, Some(b"k"));
        let ts = 100;
        let sig = sign(ts, "GET", "/x", b"k");
        let header = format!("t={ts},s={sig},v=1");
        assert_eq!(verify(&cfg, "GET", "/x", Some(&header), ts), Verdict::Valid);
    }

    #[test]
    fn arcswap_secret_reload_takes_effect() {
        let cfg = cfg_with_secret(SigVerifyMode::Enforce, Some(b"old-secret"));
        let ts = 100;

        // Old secret signs ok
        let old_sig = sign(ts, "GET", "/x", b"old-secret");
        assert!(verify(&cfg, "GET", "/x", Some(&format!("t={ts},s={old_sig}")), ts).is_valid());

        // Rotate to a new secret — equivalent of a SIGHUP after `ati edge rotate-keyring`.
        cfg.secret.store(Some(Arc::new(b"new-secret".to_vec())));

        // Old signature now fails
        assert_eq!(
            verify(&cfg, "GET", "/x", Some(&format!("t={ts},s={old_sig}")), ts),
            Verdict::HmacMismatch
        );
        // New signature works
        let new_sig = sign(ts, "GET", "/x", b"new-secret");
        assert!(verify(&cfg, "GET", "/x", Some(&format!("t={ts},s={new_sig}")), ts).is_valid());
    }

    #[test]
    fn keyring_secret_hex_decode_preferred_with_utf8_fallback() {
        use crate::core::keyring::Keyring;
        // First case: pure hex string in keyring → decoded as bytes.
        let key_hex = "abcd1234";
        let env_var = format!("ATI_KEY_{}", SECRET_KEY_NAME.to_uppercase());
        std::env::set_var(&env_var, key_hex);
        let kr = Keyring::from_env();
        std::env::remove_var(&env_var);

        let cfg =
            SigVerifyConfig::build(SigVerifyMode::Enforce, 60, DEFAULT_EXEMPT_PATHS, &kr).unwrap();
        let stored = cfg.secret.load();
        let bytes = stored.as_ref().unwrap();
        assert_eq!(&**bytes, &[0xab, 0xcd, 0x12, 0x34]);

        // Second case: non-hex string → raw bytes fallback.
        std::env::set_var(&env_var, "not-hex-string!");
        let kr = Keyring::from_env();
        std::env::remove_var(&env_var);
        let cfg =
            SigVerifyConfig::build(SigVerifyMode::Enforce, 60, DEFAULT_EXEMPT_PATHS, &kr).unwrap();
        let stored = cfg.secret.load();
        let bytes = stored.as_ref().unwrap();
        assert_eq!(&**bytes, b"not-hex-string!".as_ref());
    }

    #[test]
    fn verdict_reason_strings_match_verify_py() {
        // These reason strings are parsed by downstream log scrapers
        // (parcha-backend metrics). Pin them.
        assert_eq!(Verdict::Valid.reason(), "valid");
        assert_eq!(Verdict::MissingSignature.reason(), "missing_signature");
        assert_eq!(Verdict::MalformedSignature.reason(), "malformed_signature");
        assert_eq!(Verdict::InvalidTimestamp.reason(), "invalid_timestamp");
        assert_eq!(
            Verdict::ExpiredTimestamp(120).reason(),
            "expired_timestamp_drift=120s"
        );
        assert_eq!(
            Verdict::NoSecretConfigured.reason(),
            "no_signing_secret_configured"
        );
        assert_eq!(Verdict::HmacMismatch.reason(), "hmac_mismatch");
    }

    #[test]
    fn default_exempt_paths_match_caddyfile_set() {
        let set = build_globset(DEFAULT_EXEMPT_PATHS).unwrap();
        for p in &[
            "/health",
            "/healthz",
            "/root/foo",
            "/root/a/b",
            "/npm/anything",
            "/npm/a/b/c",
            "/otel/v1/traces",
            "/.well-known/jwks.json",
        ] {
            assert!(set.is_match(p), "expected {p} to be exempt");
        }
        for p in &["/v1/chat", "/litellm/v1/chat", "/call", "/random"] {
            assert!(!set.is_match(p), "expected {p} to NOT be exempt");
        }
    }

    #[test]
    fn parse_exempt_paths_handles_whitespace_and_empty_segments() {
        assert_eq!(
            parse_exempt_paths("/healthz, /root/*, , /npm/* "),
            vec!["/healthz", "/root/*", "/npm/*"]
        );
        assert!(parse_exempt_paths("").is_empty());
    }
}
