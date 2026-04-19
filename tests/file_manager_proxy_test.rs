//! End-to-end tests for `file_manager:download` through the proxy axum router.
//!
//! Builds the router in-process, mounts a wiremock server as the upstream,
//! and verifies that a POST /call with `tool_name = "file_manager:download"`
//! returns the expected base64 payload + metadata.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ati::core::auth_generator::AuthCache;
use ati::core::keyring::Keyring;
use ati::core::manifest::ManifestRegistry;
use ati::core::skill::SkillRegistry;
use ati::proxy::server::{build_router, ProxyState};

/// Serialize tests that mutate process-wide env vars (ATI_DOWNLOAD_ALLOWLIST,
/// ATI_UPLOAD_BUCKET). All tests in this file take this lock to keep the env
/// stable across the assertion window.
fn env_mutex() -> &'static tokio::sync::Mutex<()> {
    static M: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    M.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn clear_file_manager_env() {
    std::env::remove_var("ATI_DOWNLOAD_ALLOWLIST");
    std::env::remove_var("ATI_UPLOAD_BUCKET");
    std::env::remove_var("ATI_UPLOAD_PREFIX");
}

fn build_app() -> axum::Router {
    // Empty registry — file_manager is auto-registered.
    let registry = ManifestRegistry::empty();
    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring: Keyring::empty(),
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
    });
    build_router(state)
}

async fn body_json(body: Body) -> Value {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn proxy_dispatches_file_manager_download_happy_path() {
    let _g = env_mutex().lock().await;
    clear_file_manager_env();
    let upstream = MockServer::start().await;
    let payload = b"the quick brown fox".to_vec();
    Mock::given(method("GET"))
        .and(path("/sample.bin"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/octet-stream")
                .set_body_bytes(payload.clone()),
        )
        .mount(&upstream)
        .await;

    let app = build_app();

    let body = json!({
        "tool_name": "file_manager:download",
        "args": {"url": format!("{}/sample.bin", upstream.uri())},
    });
    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    let result = &json["result"];
    assert_eq!(result["success"], true);
    assert_eq!(result["size_bytes"], payload.len());
    assert_eq!(result["content_type"], "application/octet-stream");
    let b64 = result["content_base64"].as_str().unwrap();
    assert_eq!(B64.decode(b64).unwrap(), payload);
}

#[tokio::test]
async fn proxy_returns_payload_too_large_when_size_cap_exceeded() {
    let _g = env_mutex().lock().await;
    clear_file_manager_env();
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/big.bin"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/octet-stream")
                .set_body_bytes(vec![0u8; 4096]),
        )
        .mount(&upstream)
        .await;

    let app = build_app();
    let body = json!({
        "tool_name": "file_manager:download",
        "args": {
            "url": format!("{}/big.bin", upstream.uri()),
            "max_bytes": 100,
        },
    });
    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let json = body_json(resp.into_body()).await;
    let err = json["error"].as_str().unwrap();
    assert!(err.contains("max-bytes"), "unexpected error message: {err}");
}

#[tokio::test]
async fn proxy_propagates_upstream_404_status() {
    let _g = env_mutex().lock().await;
    clear_file_manager_env();
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_string("nope"))
        .mount(&upstream)
        .await;

    let app = build_app();
    let body = json!({
        "tool_name": "file_manager:download",
        "args": {"url": format!("{}/missing", upstream.uri())},
    });
    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // Status should be 404 (passed through from upstream) — but proxy clamps
    // it to a real HTTP status if the upstream gave a 4xx.
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let json = body_json(resp.into_body()).await;
    assert!(json["error"].as_str().unwrap_or("").contains("404"));
}

#[tokio::test]
async fn proxy_rejects_missing_url_with_bad_request() {
    let _g = env_mutex().lock().await;
    clear_file_manager_env();
    let app = build_app();
    let body = json!({
        "tool_name": "file_manager:download",
        "args": {},
    });
    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn proxy_returns_forbidden_when_host_not_in_allowlist() {
    let _g = env_mutex().lock().await;
    clear_file_manager_env();
    std::env::set_var("ATI_DOWNLOAD_ALLOWLIST", "only.allowed.test");
    let app = build_app();

    let body = json!({
        "tool_name": "file_manager:download",
        "args": {"url": "https://this-is-not-allowed.test/x"},
    });
    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp.into_body()).await;
    let err = json["error"].as_str().unwrap_or("");
    assert!(
        err.contains("not in the download allowlist"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn proxy_upload_without_bucket_returns_503() {
    let _g = env_mutex().lock().await;
    clear_file_manager_env();
    let app = build_app();

    let body = json!({
        "tool_name": "file_manager:upload",
        "args": {
            "filename": "x.txt",
            "content_type": "text/plain",
            "content_base64": B64.encode(b"hello"),
        },
    });
    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let json = body_json(resp.into_body()).await;
    let err = json["error"].as_str().unwrap_or("");
    assert!(err.contains("ATI_UPLOAD_BUCKET"), "unexpected error: {err}");
}
