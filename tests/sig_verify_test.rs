//! Integration tests for the HMAC sig-verify middleware (PR 2 of #94).
//!
//! Builds the axum router in-process and exercises the full middleware
//! stack — sig_verify wraps every non-exempt route, and in `enforce` mode
//! a request without a valid signature must be rejected *before* hitting
//! the named-route handlers (`/call`, etc.) or the passthrough fallback.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;
use wiremock::matchers::method as wm_method;
use wiremock::matchers::path as wm_path;
use wiremock::{Mock, MockServer, ResponseTemplate};

use ati::core::auth_generator::AuthCache;
use ati::core::keyring::Keyring;
use ati::core::manifest::ManifestRegistry;
use ati::core::passthrough::PassthroughRouter;
use ati::core::sig_verify::{
    SigVerifyConfig, SigVerifyMode, DEFAULT_EXEMPT_PATHS, JOB_ID_HEADER, SECRET_KEY_NAME,
    SIGNATURE_HEADER, STATUS_HEADER,
};
use ati::core::skill::SkillRegistry;
use ati::proxy::server::{build_router, ProxyState};

/// Process-wide mutex for ATI_KEY_* env-var manipulation. Same pattern as
/// the PR 1 passthrough tests.
fn env_mutex() -> &'static std::sync::Mutex<()> {
    static M: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    M.get_or_init(|| std::sync::Mutex::new(()))
}

/// Build an ATI router with sig-verify mode + an optional secret + a single
/// passthrough manifest pointing at the supplied upstream URL. Used to
/// verify that the middleware gates real traffic at the right point.
fn build_app(
    mode: SigVerifyMode,
    secret: Option<&[u8]>,
    upstream_url: Option<&str>,
) -> (axum::Router, TempDir) {
    let dir = TempDir::new().unwrap();
    let manifests = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests).unwrap();

    // If an upstream is supplied, mount it as a passthrough route at /api/*.
    let registry = if let Some(upstream) = upstream_url {
        std::fs::write(
            manifests.join("test.toml"),
            format!(
                r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{upstream}"
path_prefix = "/api"
"#
            ),
        )
        .unwrap();
        ManifestRegistry::load(&manifests).expect("load manifests")
    } else {
        ManifestRegistry::load(&manifests).expect("load empty manifests")
    };

    // Keyring with the sig-verify secret (under the canonical name).
    let keyring = {
        let _guard = env_mutex().lock().unwrap_or_else(|p| p.into_inner());
        let var = format!("ATI_KEY_{}", SECRET_KEY_NAME.to_uppercase());
        if let Some(bytes) = secret {
            // store as hex so hex-decode path is exercised
            std::env::set_var(&var, hex::encode(bytes));
        }
        let kr = Keyring::from_env();
        std::env::remove_var(&var);
        kr
    };

    let sig_verify = Arc::new(
        SigVerifyConfig::build(mode, 60, DEFAULT_EXEMPT_PATHS, &keyring).expect("sig-verify cfg"),
    );

    let passthrough = if upstream_url.is_some() {
        Some(Arc::new(
            PassthroughRouter::build(&registry, &keyring).expect("passthrough"),
        ))
    } else {
        None
    };

    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring,
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
        db: ati::core::db::DbState::Disabled,
        passthrough,
        sig_verify,
    });
    (build_router(state), dir)
}

fn sign(ts: i64, method: &str, path: &str, secret: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(format!("{ts}.{method}.{path}").as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn body_text(b: Body) -> String {
    String::from_utf8(b.collect().await.unwrap().to_bytes().to_vec()).unwrap()
}

// --- Enforce mode ---------------------------------------------------------

#[tokio::test]
async fn enforce_rejects_unsigned_request_at_passthrough() {
    let upstream = MockServer::start().await;
    Mock::given(wm_method("GET"))
        .and(wm_path("/v1/anything"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .mount(&upstream)
        .await;

    let (app, _dir) = build_app(
        SigVerifyMode::Enforce,
        Some(b"sekret"),
        Some(&upstream.uri()),
    );
    let req = Request::builder()
        .uri("/api/v1/anything")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_text(resp.into_body()).await;
    assert_eq!(body, "missing_signature");
    // Upstream must NOT have been hit — sig-verify wraps the fallback.
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn enforce_accepts_valid_signature() {
    let upstream = MockServer::start().await;
    Mock::given(wm_method("GET"))
        .and(wm_path("/v1/ok"))
        .respond_with(ResponseTemplate::new(200).set_body_string("UPSTREAM_OK"))
        .mount(&upstream)
        .await;

    let secret = b"sekret-bytes";
    let (app, _dir) = build_app(SigVerifyMode::Enforce, Some(secret), Some(&upstream.uri()));
    let ts = now_unix();
    let sig = sign(ts, "GET", "/api/v1/ok", secret);
    let req = Request::builder()
        .uri("/api/v1/ok")
        .header(SIGNATURE_HEADER, format!("t={ts},s={sig}"))
        .header(JOB_ID_HEADER, "job-test-123")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_text(resp.into_body()).await, "UPSTREAM_OK");
}

#[tokio::test]
async fn enforce_rejects_wrong_signature() {
    let upstream = MockServer::start().await;
    let (app, _dir) = build_app(
        SigVerifyMode::Enforce,
        Some(b"server-key"),
        Some(&upstream.uri()),
    );
    let ts = now_unix();
    // Client signs with a different key
    let sig = sign(ts, "GET", "/api/v1", b"client-thinks-different");
    let req = Request::builder()
        .uri("/api/v1")
        .header(SIGNATURE_HEADER, format!("t={ts},s={sig}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_text(resp.into_body()).await, "hmac_mismatch");
}

#[tokio::test]
async fn enforce_rejects_expired_timestamp_with_drift() {
    let upstream = MockServer::start().await;
    let (app, _dir) = build_app(SigVerifyMode::Enforce, Some(b"k"), Some(&upstream.uri()));
    // Sign with a stale timestamp 5 minutes in the past — well outside the
    // 60s drift window.
    let ts = now_unix() - 300;
    let sig = sign(ts, "GET", "/api/x", b"k");
    let req = Request::builder()
        .uri("/api/x")
        .header(SIGNATURE_HEADER, format!("t={ts},s={sig}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_text(resp.into_body()).await;
    assert!(
        body.starts_with("expired_timestamp_drift="),
        "expected drift reason, got: {body}"
    );
}

// --- Log mode -------------------------------------------------------------

#[tokio::test]
async fn log_mode_always_allows_even_when_invalid() {
    let upstream = MockServer::start().await;
    Mock::given(wm_method("GET"))
        .and(wm_path("/v1/x"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .mount(&upstream)
        .await;

    // Log mode + WRONG signature should still pass through.
    let (app, _dir) = build_app(
        SigVerifyMode::Log,
        Some(b"server-secret"),
        Some(&upstream.uri()),
    );
    let req = Request::builder()
        .uri("/api/v1/x")
        .header(SIGNATURE_HEADER, "t=100,s=deadbeef")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn log_mode_allows_unsigned_request() {
    let upstream = MockServer::start().await;
    Mock::given(wm_method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    let (app, _dir) = build_app(SigVerifyMode::Log, Some(b"k"), Some(&upstream.uri()));
    let req = Request::builder()
        .uri("/api/anything")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// --- Warn mode ------------------------------------------------------------

#[tokio::test]
async fn warn_mode_adds_status_header_invalid() {
    let upstream = MockServer::start().await;
    Mock::given(wm_method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    let (app, _dir) = build_app(SigVerifyMode::Warn, Some(b"k"), Some(&upstream.uri()));
    let req = Request::builder()
        .uri("/api/x")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let status = resp
        .headers()
        .get(STATUS_HEADER)
        .and_then(|v| v.to_str().ok())
        .expect("X-Signature-Status header");
    assert_eq!(status, "missing_signature");
}

#[tokio::test]
async fn warn_mode_adds_status_header_valid() {
    let upstream = MockServer::start().await;
    Mock::given(wm_method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    let secret = b"k";
    let (app, _dir) = build_app(SigVerifyMode::Warn, Some(secret), Some(&upstream.uri()));
    let ts = now_unix();
    let sig = sign(ts, "GET", "/api/x", secret);
    let req = Request::builder()
        .uri("/api/x")
        .header(SIGNATURE_HEADER, format!("t={ts},s={sig}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let status = resp
        .headers()
        .get(STATUS_HEADER)
        .and_then(|v| v.to_str().ok())
        .expect("X-Signature-Status header");
    assert_eq!(status, "valid");
}

// --- Exempt paths --------------------------------------------------------

#[tokio::test]
async fn exempt_path_bypasses_verify_even_in_enforce_mode() {
    // /health is a default exempt — must not 403 even when sig-verify is
    // strict and no signature is supplied.
    let (app, _dir) = build_app(SigVerifyMode::Enforce, Some(b"k"), None);
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwks_path_is_exempt_in_enforce_mode() {
    let (app, _dir) = build_app(SigVerifyMode::Enforce, Some(b"k"), None);
    let req = Request::builder()
        .uri("/.well-known/jwks.json")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // /.well-known/jwks.json returns 200 with JWKS or 404 if not configured;
    // either way it's NOT a 403 — the exempt path bypasses sig-verify.
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}

// --- Method / path are part of the HMAC message --------------------------

#[tokio::test]
async fn enforce_rejects_when_path_tampered() {
    let upstream = MockServer::start().await;
    Mock::given(wm_method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    let secret = b"k";
    let (app, _dir) = build_app(SigVerifyMode::Enforce, Some(secret), Some(&upstream.uri()));
    let ts = now_unix();
    // Sign for /api/A but send to /api/B
    let sig = sign(ts, "GET", "/api/A", secret);
    let req = Request::builder()
        .uri("/api/B")
        .header(SIGNATURE_HEADER, format!("t={ts},s={sig}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_text(resp.into_body()).await, "hmac_mismatch");
}

#[tokio::test]
async fn enforce_rejects_when_method_tampered() {
    let upstream = MockServer::start().await;
    Mock::given(wm_method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    let secret = b"k";
    let (app, _dir) = build_app(SigVerifyMode::Enforce, Some(secret), Some(&upstream.uri()));
    let ts = now_unix();
    // Sign for GET but send POST
    let sig = sign(ts, "GET", "/api/x", secret);
    let req = Request::builder()
        .method("POST")
        .uri("/api/x")
        .header(SIGNATURE_HEADER, format!("t={ts},s={sig}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
