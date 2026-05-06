//! End-to-end integration tests for `handler = "passthrough"` providers.
//!
//! Builds the axum router in-process (no TCP binding), points a passthrough
//! manifest at a `wiremock` upstream, and drives the whole pipeline via
//! `tower::ServiceExt::oneshot`. Every test here exercises the *full*
//! middleware stack: auth-bypass detection, fallback dispatch, header
//! filtering, body streaming, and per-route limits.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ati::core::auth_generator::AuthCache;
use ati::core::keyring::Keyring;
use ati::core::manifest::ManifestRegistry;
use ati::core::passthrough::PassthroughRouter;
use ati::core::skill::SkillRegistry;
use ati::proxy::server::{build_router, ProxyState};

/// Process-wide mutex around env-var manipulation. `Keyring::from_env` scans
/// the process environment, so two concurrent tests setting `ATI_KEY_*` would
/// race. Use this guard whenever a test populates env vars to construct a
/// keyring.
fn env_mutex() -> &'static std::sync::Mutex<()> {
    static M: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    M.get_or_init(|| std::sync::Mutex::new(()))
}

// --- Test rig --------------------------------------------------------------

/// Build an ATI router with a passthrough manifest pointing at `upstream_url`.
/// Uses the in-memory keyring populated from `keys` (key_name → value).
fn build_passthrough_app(manifest_toml: &str, keys: &[(&str, &str)]) -> (axum::Router, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap();
    std::fs::write(manifests_dir.join("test.toml"), manifest_toml).unwrap();

    let registry = ManifestRegistry::load(&manifests_dir).expect("load test manifest");

    // Build the keyring via ATI_KEY_* env vars so we don't reach into private
    // internals. The Keyring::from_env path is the same one production uses.
    // Hold env_mutex for the whole set/build/clear cycle: scanning the env is
    // not concurrency-safe.
    let keyring = {
        let _guard = env_mutex().lock().unwrap_or_else(|p| p.into_inner());
        let mut to_clear: Vec<String> = Vec::new();
        for (k, v) in keys {
            let env_key = format!("ATI_KEY_{}", k.to_uppercase());
            std::env::set_var(&env_key, v);
            to_clear.push(env_key);
        }
        let kr = Keyring::from_env();
        for k in to_clear {
            std::env::remove_var(k);
        }
        kr
    };

    let passthrough = PassthroughRouter::build(&registry, &keyring).expect("build router");
    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring,
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
        db: ati::core::db::DbState::Disabled,
        passthrough: Some(Arc::new(passthrough)),
        sig_verify: std::sync::Arc::new(
            ati::core::sig_verify::SigVerifyConfig::build(
                ati::core::sig_verify::SigVerifyMode::Log,
                60,
                ati::core::sig_verify::DEFAULT_EXEMPT_PATHS,
                &ati::core::keyring::Keyring::empty(),
            )
            .unwrap(),
        ),
        key_store: None,
        admin_token: None,
    });
    let app = build_router(state);
    (app, dir)
}

/// Build an ATI router with passthrough explicitly DISABLED (the fallback
/// then 404s every request). Used to assert the gating works.
fn build_disabled_app(manifest_toml: &str) -> (axum::Router, TempDir) {
    let dir = TempDir::new().unwrap();
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap();
    std::fs::write(manifests_dir.join("test.toml"), manifest_toml).unwrap();

    let registry = ManifestRegistry::load(&manifests_dir).expect("load test manifest");
    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring: Keyring::empty(),
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
        db: ati::core::db::DbState::Disabled,
        passthrough: None,
        sig_verify: std::sync::Arc::new(
            ati::core::sig_verify::SigVerifyConfig::build(
                ati::core::sig_verify::SigVerifyMode::Log,
                60,
                ati::core::sig_verify::DEFAULT_EXEMPT_PATHS,
                &ati::core::keyring::Keyring::empty(),
            )
            .unwrap(),
        ),
        key_store: None,
        admin_token: None,
    });
    let app = build_router(state);
    (app, dir)
}

async fn body_bytes(body: Body) -> Vec<u8> {
    body.collect().await.unwrap().to_bytes().to_vec()
}

async fn body_text(body: Body) -> String {
    String::from_utf8(body_bytes(body).await).unwrap()
}

// --- Basic forwarding ------------------------------------------------------

#[tokio::test]
async fn passthrough_forwards_get_request_and_returns_body() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/foo"))
        .respond_with(ResponseTemplate::new(200).set_body_string("hello from upstream"))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "test passthrough"
handler = "passthrough"
base_url = "{}"
path_prefix = "/test"
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[]);

    let req = Request::builder()
        .method("GET")
        .uri("/test/v1/foo")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp.into_body()).await;
    assert_eq!(body, "hello from upstream");
}

#[tokio::test]
async fn passthrough_strips_prefix_by_default() {
    let upstream = MockServer::start().await;
    // Upstream must see /v1/chat — NOT /test/v1/chat.
    Mock::given(method("GET"))
        .and(path("/v1/chat"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/test"
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[]);
    let req = Request::builder()
        .uri("/test/v1/chat")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn passthrough_keeps_prefix_when_strip_prefix_false() {
    let upstream = MockServer::start().await;
    // strip_prefix=false → upstream sees /root/something untouched.
    Mock::given(method("GET"))
        .and(path("/root/something"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "devpi"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/root"
strip_prefix = false
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[]);
    let req = Request::builder()
        .uri("/root/something")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn passthrough_applies_path_replace() {
    let upstream = MockServer::start().await;
    // Incoming: /otel/v1/traces → strip /otel → /v1/traces → replace / with /otlp/ → /otlp/v1/traces
    Mock::given(method("POST"))
        .and(path("/otlp/v1/traces"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "otel"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/otel"
path_replace = ["/", "/otlp/"]
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[]);
    let req = Request::builder()
        .method("POST")
        .uri("/otel/v1/traces")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn passthrough_preserves_query_string() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(wiremock::matchers::query_param("q", "rust"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/api"
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[]);
    let req = Request::builder()
        .uri("/api/search?q=rust")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// --- Method round-trip + body --------------------------------------------

#[tokio::test]
async fn passthrough_forwards_post_with_body() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/echo"))
        .and(wiremock::matchers::body_string("payload-body"))
        .respond_with(ResponseTemplate::new(201).set_body_string("created"))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/api"
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[]);
    let req = Request::builder()
        .method("POST")
        .uri("/api/echo")
        .header("content-type", "text/plain")
        .body(Body::from("payload-body"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(body_text(resp.into_body()).await, "created");
}

// --- Auth injection -------------------------------------------------------

#[tokio::test]
async fn passthrough_injects_bearer_token() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .and(header("authorization", "Bearer SUPERSECRET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/api"
auth_type = "bearer"
auth_key_name = "my_token"
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[("my_token", "SUPERSECRET")]);
    let req = Request::builder()
        .uri("/api/me")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn passthrough_injects_custom_auth_header() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1"))
        .and(header("x-bb-api-key", "BB123"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/bb"
auth_type = "header"
auth_header_name = "x-bb-api-key"
auth_key_name = "bb_key"
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[("bb_key", "BB123")]);
    let req = Request::builder()
        .uri("/bb/v1")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn passthrough_extra_headers_expand_keyring_vars() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ingest"))
        .and(header("authorization", "Basic dGVzdC1jcmVk"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/otel"
[provider.extra_headers]
Authorization = "Basic ${{otlp_creds}}"
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[("otlp_creds", "dGVzdC1jcmVk")]);
    let req = Request::builder()
        .uri("/otel/ingest")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn passthrough_strips_inbound_authorization() {
    // The sandbox-side Authorization header (a JWT) must NOT leak upstream —
    // upstream auth comes from the manifest. We assert by configuring the
    // upstream to reject Bearer tokens it doesn't recognize.
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1"))
        .and(header("authorization", "Bearer UPSTREAM_TOKEN"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/api"
auth_type = "bearer"
auth_key_name = "upstream_tok"
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[("upstream_tok", "UPSTREAM_TOKEN")]);
    // Send a *different* Authorization on the way in.
    let req = Request::builder()
        .uri("/api/v1")
        .header("authorization", "Bearer SANDBOX_JWT_SHOULD_BE_STRIPPED")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Upstream only matched because the sandbox token was stripped and replaced.
    assert_eq!(resp.status(), StatusCode::OK);
}

// --- Hop-by-hop header filtering -----------------------------------------

#[tokio::test]
async fn passthrough_strips_hop_by_hop_request_headers() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/x"))
        // Verify connection header didn't leak upstream by asserting it's absent.
        // wiremock's matchers don't have a "header-absent" directly, but we can
        // verify by accepting + checking the request log.
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/api"
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[]);
    let req = Request::builder()
        .uri("/api/x")
        .header("connection", "keep-alive, upgrade")
        .header("upgrade", "websocket")
        .header("x-keep-me", "yes")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Inspect the upstream's received request log.
    let received = upstream.received_requests().await.unwrap();
    let r = received.last().unwrap();
    // Hop-by-hop headers must NOT have been forwarded.
    assert!(
        r.headers.get("connection").is_none(),
        "connection header leaked upstream"
    );
    assert!(
        r.headers.get("upgrade").is_none(),
        "upgrade header leaked upstream"
    );
    // Non-hop-by-hop headers MUST be forwarded.
    assert_eq!(
        r.headers.get("x-keep-me").map(|v| v.to_str().unwrap()),
        Some("yes")
    );
}

#[tokio::test]
async fn passthrough_strips_sandbox_signature_headers() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/api"
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[]);
    let req = Request::builder()
        .uri("/api/anything")
        .header("x-sandbox-signature", "t=1,s=deadbeef")
        .header("x-sandbox-job-id", "job-123")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let received = upstream.received_requests().await.unwrap();
    let r = received.last().unwrap();
    assert!(r.headers.get("x-sandbox-signature").is_none());
    assert!(r.headers.get("x-sandbox-job-id").is_none());
}

#[tokio::test]
async fn passthrough_strips_all_x_sandbox_prefix_headers_end_to_end() {
    // Greptile flagged that the original strip list named only two specific
    // x-sandbox-* headers. The fix broadens to a prefix match. This test
    // exercises that round-trip through the real handler.
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/api"
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[]);
    let req = Request::builder()
        .uri("/api/anything")
        .header("x-sandbox-signature", "t=1,s=deadbeef")
        .header("x-sandbox-job-id", "job-123")
        .header("x-sandbox-trace-id", "tr-xyz")
        .header("x-sandbox-attempt", "2")
        .header("x-sandbox-custom-future-header", "value")
        .header("x-not-sandbox", "keep-me")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let received = upstream.received_requests().await.unwrap();
    let r = received.last().unwrap();
    for h in &[
        "x-sandbox-signature",
        "x-sandbox-job-id",
        "x-sandbox-trace-id",
        "x-sandbox-attempt",
        "x-sandbox-custom-future-header",
    ] {
        assert!(
            r.headers.get(*h).is_none(),
            "expected {h} to be stripped from upstream request"
        );
    }
    // Headers that don't start with x-sandbox- must pass through.
    assert_eq!(
        r.headers.get("x-not-sandbox").map(|v| v.to_str().unwrap()),
        Some("keep-me")
    );
}

#[tokio::test]
async fn passthrough_strips_content_length_when_response_cap_active() {
    // Greptile P1: when MaxBytesStream may truncate the body mid-stream, the
    // upstream's Content-Length is a lie. Strip it so the downstream client
    // frames the response via chunked transfer-encoding instead.
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blob"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-length", "1000")
                .set_body_bytes(vec![b'A'; 1000]),
        )
        .mount(&upstream)
        .await;

    // max_response_bytes > 0 → cap_active is true → Content-Length must be stripped.
    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/api"
max_response_bytes = 10000
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[]);
    let req = Request::builder()
        .uri("/api/blob")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get("content-length").is_none(),
        "content-length must be stripped when response cap is active; got {:?}",
        resp.headers().get("content-length")
    );
}

#[tokio::test]
async fn passthrough_keeps_content_length_when_cap_disabled() {
    // max_response_bytes = 0 → unlimited → no truncation risk → keep CL.
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blob"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-length", "5")
                .set_body_bytes(b"hello".to_vec()),
        )
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/api"
max_response_bytes = 0
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[]);
    let req = Request::builder()
        .uri("/api/blob")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-length")
            .map(|v| v.to_str().unwrap()),
        Some("5"),
        "content-length must be preserved when no response cap is active"
    );
}

#[tokio::test]
async fn passthrough_strips_host_header_uses_override() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/api"
host_override = "api.upstream.example"
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[]);
    let req = Request::builder()
        .uri("/api/x")
        .header("host", "proxy.greppy3.parcha.dev")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let received = upstream.received_requests().await.unwrap();
    let r = received.last().unwrap();
    // Upstream sees the override, not the inbound host.
    assert_eq!(
        r.headers.get("host").map(|v| v.to_str().unwrap()),
        Some("api.upstream.example")
    );
}

// --- deny_paths -----------------------------------------------------------

#[tokio::test]
async fn passthrough_deny_paths_returns_403_without_upstream_call() {
    let upstream = MockServer::start().await;
    // No mock — if upstream is ever called, the test fails because wiremock
    // returns 404 by default.

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/litellm"
deny_paths = ["/config/*", "/model/*"]
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[]);
    let req = Request::builder()
        .uri("/litellm/config/secret")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_text(resp.into_body()).await;
    assert!(
        body.contains("forbidden"),
        "expected forbidden body, got: {body}"
    );

    // Upstream must not have received the request.
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn passthrough_deny_paths_block_nested_subpaths() {
    // Greptile review #2 P1: deny_paths `/config/*` must block `/config/a/b`
    // too — globset's `*` doesn't cross `/`. Without the expansion helper,
    // a sandbox could escape the LiteLLM admin denylist with a sub-segment.
    let upstream = MockServer::start().await;
    // No mock — if the request leaks to upstream, wiremock will 404, but
    // the test asserts 403 directly so we'd catch it either way.

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/litellm"
deny_paths = ["/config/*", "/model/*"]
"#,
        upstream.uri()
    );
    let (app, _dir) = build_passthrough_app(&manifest, &[]);

    // Each of these must return 403 — previously /config/a/b silently
    // skipped the denylist.
    for forbidden_path in &[
        "/litellm/config/x",
        "/litellm/config/x/y",
        "/litellm/config/deeply/nested/secret",
        "/litellm/model/list/all",
    ] {
        let req = Request::builder()
            .uri(*forbidden_path)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "expected 403 for {forbidden_path}; got {}",
            resp.status()
        );
    }

    // Upstream must NEVER have been called.
    assert!(
        upstream.received_requests().await.unwrap().is_empty(),
        "denied requests must not reach upstream"
    );
}

#[tokio::test]
async fn passthrough_returns_redirects_to_client_unchanged() {
    // Greptile review #2 P1: passthrough must NOT follow redirects internally.
    // Following them would forward keyring-derived `extra_headers` to whatever
    // host the upstream redirects to. The fix is `redirect::Policy::none()`.
    // This test verifies a 3xx upstream response propagates verbatim.
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "https://attacker.example/steal"),
        )
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/api"

[provider.extra_headers]
X-Secret-Token = "should-not-leak"
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[]);
    let req = Request::builder()
        .uri("/api/start")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // The 302 must be returned to the client, not followed.
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        resp.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("https://attacker.example/steal"),
        "Location header must propagate verbatim"
    );
    // Upstream should have received exactly ONE request — no automatic
    // follow-the-redirect call to attacker.example.
    let received = upstream.received_requests().await.unwrap();
    assert_eq!(received.len(), 1, "passthrough must not follow redirects");
}

#[tokio::test]
async fn passthrough_deny_paths_does_not_block_unrelated_routes() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/litellm"
deny_paths = ["/config/*", "/model/*"]
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[]);
    let req = Request::builder()
        .method("POST")
        .uri("/litellm/v1/chat/completions")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// --- Body size caps -------------------------------------------------------

#[tokio::test]
async fn passthrough_request_content_length_over_cap_returns_413() {
    let upstream = MockServer::start().await;
    // No mock body — upstream must not be hit.

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/api"
max_request_bytes = 100
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[]);
    let big_payload = vec![0u8; 500];
    let req = Request::builder()
        .method("POST")
        .uri("/api/upload")
        .header("content-length", "500")
        .body(Body::from(big_payload))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // Upstream must not have been called.
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

// --- Hostname routing -----------------------------------------------------

#[tokio::test]
async fn passthrough_host_match_routes_correctly() {
    let bb_upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sessions"))
        .respond_with(ResponseTemplate::new(200).set_body_string("from-bb"))
        .mount(&bb_upstream)
        .await;

    let default_upstream = MockServer::start().await;
    // strip_prefix=true on "/sessions" → upstream sees "/" (root).
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("from-default"))
        .mount(&default_upstream)
        .await;

    let dir = TempDir::new().unwrap();
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap();

    std::fs::write(
        manifests_dir.join("bb.toml"),
        format!(
            r#"
[provider]
name = "browserbase"
description = "t"
handler = "passthrough"
base_url = "{}"
host_match = "bb.greppy.example"
"#,
            bb_upstream.uri()
        ),
    )
    .unwrap();
    std::fs::write(
        manifests_dir.join("default.toml"),
        format!(
            r#"
[provider]
name = "default"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/sessions"
"#,
            default_upstream.uri()
        ),
    )
    .unwrap();

    let registry = ManifestRegistry::load(&manifests_dir).unwrap();
    let keyring = Keyring::empty();
    let passthrough = PassthroughRouter::build(&registry, &keyring).unwrap();
    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring,
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
        db: ati::core::db::DbState::Disabled,
        passthrough: Some(Arc::new(passthrough)),
        sig_verify: std::sync::Arc::new(
            ati::core::sig_verify::SigVerifyConfig::build(
                ati::core::sig_verify::SigVerifyMode::Log,
                60,
                ati::core::sig_verify::DEFAULT_EXEMPT_PATHS,
                &ati::core::keyring::Keyring::empty(),
            )
            .unwrap(),
        ),
        key_store: None,
        admin_token: None,
    });
    let app = build_router(state);

    // Hit bb.greppy.example — should route to bb_upstream.
    let req = Request::builder()
        .uri("/sessions")
        .header("host", "bb.greppy.example")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_text(resp.into_body()).await, "from-bb");

    // Hit default host — should route to default_upstream.
    let req = Request::builder()
        .uri("/sessions")
        .header("host", "other.example")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_text(resp.into_body()).await, "from-default");
}

// --- Disabled + no-match behavior ----------------------------------------

#[tokio::test]
async fn fallback_returns_404_when_passthrough_disabled() {
    let manifest = r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "http://127.0.0.1:1"
path_prefix = "/api"
"#;
    let (app, _dir) = build_disabled_app(manifest);
    let req = Request::builder()
        .uri("/api/anything")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = body_text(resp.into_body()).await;
    assert!(body.contains("passthrough disabled"));
}

#[tokio::test]
async fn fallback_returns_404_when_no_route_matches() {
    let upstream = MockServer::start().await;
    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/api"
"#,
        upstream.uri()
    );
    let (app, _dir) = build_passthrough_app(&manifest, &[]);
    let req = Request::builder()
        .uri("/unknown/path")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn named_routes_still_win_over_fallback() {
    // Even with passthrough enabled, /health must serve the named handler.
    let upstream = MockServer::start().await;
    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/"
"#,
        upstream.uri()
    );
    let (app, _dir) = build_passthrough_app(&manifest, &[]);
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Health endpoint returns JSON; passthrough would return upstream's response.
    // Asserting on body's shape proves which handler ran.
    let body = body_text(resp.into_body()).await;
    assert!(
        body.contains("\"status\""),
        "expected health JSON, got: {body}"
    );
}

// --- Bad gateway on upstream failure -------------------------------------

#[tokio::test]
async fn passthrough_returns_502_on_upstream_connection_failure() {
    // base_url points at a port nothing is listening on.
    let manifest = r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "http://127.0.0.1:1"
path_prefix = "/api"
connect_timeout_seconds = 1
"#;

    let (app, _dir) = build_passthrough_app(manifest, &[]);
    let req = Request::builder()
        .uri("/api/x")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

// --- Manifest-load-time validation ---------------------------------------

#[tokio::test]
async fn passthrough_accepts_forward_websockets_with_http_base_url() {
    // PR 5 enables WebSocket support. `forward_websockets = true` paired
    // with an http(s):// base_url must load successfully — the proxy
    // derives ws/wss from the URL scheme automatically.
    let dir = TempDir::new().unwrap();
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap();
    std::fs::write(
        manifests_dir.join("ws.toml"),
        r#"
[provider]
name = "ws"
description = "t"
handler = "passthrough"
base_url = "https://api.example.com"
path_prefix = "/ws"
forward_websockets = true
"#,
    )
    .unwrap();
    ManifestRegistry::load(&manifests_dir).expect("must load");
}

#[tokio::test]
async fn passthrough_rejects_forward_websockets_with_non_http_base_url() {
    let dir = TempDir::new().unwrap();
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap();
    std::fs::write(
        manifests_dir.join("ws.toml"),
        r#"
[provider]
name = "ws"
description = "t"
handler = "passthrough"
base_url = "ftp://example.com"
path_prefix = "/ws"
forward_websockets = true
"#,
    )
    .unwrap();
    let err = match ManifestRegistry::load(&manifests_dir) {
        Ok(_) => panic!("expected load to fail"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(msg.contains("forward_websockets"), "got: {msg}");
    assert!(
        msg.contains("http://") || msg.contains("https://"),
        "got: {msg}"
    );
}

#[tokio::test]
async fn passthrough_rejects_missing_host_and_prefix_at_load() {
    let dir = TempDir::new().unwrap();
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap();
    std::fs::write(
        manifests_dir.join("bad.toml"),
        r#"
[provider]
name = "bad"
description = "t"
handler = "passthrough"
base_url = "http://x"
"#,
    )
    .unwrap();

    let err = match ManifestRegistry::load(&manifests_dir) {
        Ok(_) => panic!("expected load to fail"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(msg.contains("host_match or path_prefix"), "got: {msg}");
}

#[tokio::test]
async fn passthrough_rejects_empty_base_url_at_load() {
    let dir = TempDir::new().unwrap();
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap();
    std::fs::write(
        manifests_dir.join("bad.toml"),
        r#"
[provider]
name = "bad"
description = "t"
handler = "passthrough"
path_prefix = "/x"
"#,
    )
    .unwrap();

    let err = match ManifestRegistry::load(&manifests_dir) {
        Ok(_) => panic!("expected load to fail"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(msg.contains("base_url"), "got: {msg}");
}

#[tokio::test]
async fn passthrough_rejects_path_prefix_without_leading_slash() {
    let dir = TempDir::new().unwrap();
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap();
    std::fs::write(
        manifests_dir.join("bad.toml"),
        r#"
[provider]
name = "bad"
description = "t"
handler = "passthrough"
base_url = "http://x"
path_prefix = "no-leading-slash"
"#,
    )
    .unwrap();

    let err = match ManifestRegistry::load(&manifests_dir) {
        Ok(_) => panic!("expected load to fail"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(msg.contains("start with '/'"), "got: {msg}");
}

#[tokio::test]
async fn passthrough_normalizes_trailing_slash_on_prefix() {
    // `/litellm/` should load successfully and behave like `/litellm`.
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/x"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/litellm/"
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[]);
    let req = Request::builder()
        .uri("/litellm/x")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// --- Streaming a large response (body cap) -------------------------------

#[tokio::test]
async fn passthrough_response_within_cap_streams_through() {
    let upstream = MockServer::start().await;
    let big = vec![b'A'; 50_000];
    Mock::given(method("GET"))
        .and(path("/big"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(big.clone()))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/api"
max_response_bytes = 1000000
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[]);
    let req = Request::builder()
        .uri("/api/big")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_bytes(resp.into_body()).await;
    assert_eq!(bytes.len(), 50_000);
}

// --- Startup gate: enforce mode requires a sig-verify secret -----------

#[test]
fn ati_proxy_refuses_enforce_mode_when_secret_missing() {
    // PR 2 ships HMAC sig-verify. In --sig-verify-mode enforce, if the
    // keyring entry is missing, every signed request would fail closed —
    // a startup misconfiguration that should be loud, not silent. The
    // proxy refuses to start in that combination.
    let dir = TempDir::new().unwrap();
    let manifests = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests).unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("ati").unwrap();
    let output = cmd
        .arg("proxy")
        .arg("--port")
        .arg("0")
        .arg("--ati-dir")
        .arg(dir.path())
        .arg("--sig-verify-mode")
        .arg("enforce")
        .timeout(std::time::Duration::from_secs(10))
        .output()
        .expect("run ati");
    assert!(
        !output.status.success(),
        "ati proxy --sig-verify-mode enforce without a secret should refuse to start"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("sandbox_signing_shared_secret"),
        "stderr should name the missing keyring entry; got: {stderr}"
    );
    assert!(
        stderr.contains("enforce"),
        "stderr should mention enforce mode; got: {stderr}"
    );
}

#[test]
fn ati_proxy_starts_in_log_mode_without_secret() {
    // Conversely, --sig-verify-mode log (the default) must NOT refuse to
    // start when the secret is missing. Log mode is the safe-rollout
    // posture — it logs validity but never blocks. The proxy emits a
    // warning at startup, then continues binding.
    //
    // Verified by polling for the proxy's "ATI proxy server starting"
    // log line on stderr (rather than a fixed sleep — Greptile #96 P2
    // flagged the original 2s sleep as flake-prone under CI load). We
    // wait up to 30s for the line; if it appears the proxy is healthy.
    use assert_cmd::cargo::CommandCargoExt;
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let dir = TempDir::new().unwrap();
    let manifests = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests).unwrap();

    let mut child = Command::cargo_bin("ati")
        .unwrap()
        .args([
            "proxy",
            "--port",
            "0",
            "--ati-dir",
            dir.path().to_str().unwrap(),
            // sig-verify defaults to log → no startup refusal expected
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("RUST_LOG", "info")
        .spawn()
        .expect("spawn ati");

    // Stream stderr (where tracing-subscriber emits in proxy mode by default)
    // into a channel; bail when we see the startup marker, or when the
    // process exits.
    let stderr = child.stderr.take().expect("stderr pipe");
    let (tx, rx) = mpsc::channel::<String>();
    let reader_handle = thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut saw_startup = false;
    let mut buffered = Vec::new();
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(line) => {
                if line.contains("ATI proxy server starting") {
                    saw_startup = true;
                    break;
                }
                buffered.push(line);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Some(exit) = child.try_wait().expect("wait") {
                    let _ = reader_handle.join();
                    panic!(
                        "proxy exited (code={exit:?}) before logging startup marker; stderr so far:\n{}",
                        buffered.join("\n")
                    );
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = reader_handle.join();

    assert!(
        saw_startup,
        "log mode without secret should reach the startup log line"
    );
}

// --- Sanity: `ati_dir`-based bootstrap parses our manifests --------------

#[tokio::test]
async fn manifest_loads_from_disk_with_all_passthrough_fields() {
    // Smoke test that a "full" passthrough manifest with every option set
    // parses successfully — sanity check for serde defaults.
    let dir = TempDir::new().unwrap();
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap();
    std::fs::write(
        manifests_dir.join("full.toml"),
        r#"
[provider]
name = "full"
description = "every field set"
handler = "passthrough"
base_url = "https://api.example.com"
host_match = "api.example.com"
host_override = "internal.example.com"
path_prefix = "/v1"
strip_prefix = true
path_replace = ["/", "/api/"]
forward_websockets = false
deny_paths = ["/admin/*", "/internal/*"]
connect_timeout_seconds = 5
read_timeout_seconds = 60
idle_timeout_seconds = 30
max_request_bytes = 10485760
max_response_bytes = 52428800
auth_type = "header"
auth_header_name = "x-api-key"
auth_key_name = "example_key"

[provider.extra_headers]
X-Custom = "value"
X-Templated = "Bearer ${example_token}"
"#,
    )
    .unwrap();

    let _ = PathBuf::from(&manifests_dir);
    let registry = ManifestRegistry::load(&manifests_dir).expect("should load");
    assert_eq!(
        registry.list_providers().len(),
        1 + 1 /* file_manager virtual */
    );
}

// --- forward_authorization_paths (issue #107) ----------------------------

/// LiteLLM virtual-key flow: a path inside `forward_authorization_paths`
/// must forward the sandbox's inbound Authorization and NOT inject the
/// manifest-defined master key.
#[tokio::test]
async fn passthrough_forwards_authorization_on_matched_path() {
    let upstream = MockServer::start().await;
    // Upstream only accepts the SANDBOX's virtual key, never the master.
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("authorization", "Bearer sk-virtual-xxx"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "litellm"
description = "LiteLLM-style virtual-key passthrough"
handler = "passthrough"
base_url = "{}"
path_prefix = "/litellm"
auth_type = "bearer"
auth_key_name = "litellm_master_key"
forward_authorization_paths = ["/v1/*"]
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(
        &manifest,
        &[("litellm_master_key", "sk-master-MUST-NOT-LEAK")],
    );

    let req = Request::builder()
        .method("POST")
        .uri("/litellm/v1/chat/completions")
        .header("authorization", "Bearer sk-virtual-xxx")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "upstream only matches when the virtual key (not the master) is forwarded"
    );
}

/// Inverse test: a path OUTSIDE `forward_authorization_paths` keeps the
/// today's strip+inject behaviour — sandbox Authorization is stripped,
/// manifest master key is injected.
#[tokio::test]
async fn passthrough_strips_authorization_on_unmatched_path() {
    let upstream = MockServer::start().await;
    // /key/generate is an admin endpoint — it must see the MASTER key.
    Mock::given(method("POST"))
        .and(path("/key/generate"))
        .and(header("authorization", "Bearer sk-master-MUST-LEAK-HERE"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "litellm"
description = "LiteLLM-style virtual-key passthrough"
handler = "passthrough"
base_url = "{}"
path_prefix = "/litellm"
auth_type = "bearer"
auth_key_name = "litellm_master_key"
forward_authorization_paths = ["/v1/*"]
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(
        &manifest,
        &[("litellm_master_key", "sk-master-MUST-LEAK-HERE")],
    );

    let req = Request::builder()
        .method("POST")
        // /key/generate is NOT in forward_authorization_paths.
        .uri("/litellm/key/generate")
        // Sandbox tries to assert its own creds — must be stripped.
        .header("authorization", "Bearer sk-sandbox-tried-to-impersonate")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "admin path must inject master key and strip the sandbox's Authorization"
    );
}

/// Recursive glob expansion: `/v1/*` also matches `/v1/a/b/c` (same
/// behaviour as deny_paths — `*` doesn't cross `/` so the loader
/// auto-adds the `**` twin).
#[tokio::test]
async fn passthrough_forward_auth_glob_is_recursive() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/embeddings/openai/text-embedding-3-small"))
        .and(header("authorization", "Bearer sk-virtual-deep"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "litellm"
description = "LiteLLM-style virtual-key passthrough"
handler = "passthrough"
base_url = "{}"
path_prefix = "/litellm"
auth_type = "bearer"
auth_key_name = "litellm_master_key"
forward_authorization_paths = ["/v1/*"]
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[("litellm_master_key", "sk-master")]);

    let req = Request::builder()
        .uri("/litellm/v1/embeddings/openai/text-embedding-3-small")
        .header("authorization", "Bearer sk-virtual-deep")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "deeply-nested path under /v1/* must still get forward-auth treatment"
    );
}

// --- auth_key_name miss handling (issue #108) ----------------------------

/// When `auth_key_name` points at a key that isn't in the keyring, the old
/// behaviour silently injected `Authorization: Bearer ` (empty value),
/// producing cryptic upstream 401s. The fix logs a warning and skips
/// injection entirely — so the upstream sees NO Authorization header, and
/// the operator gets a clear log line to diagnose.
#[tokio::test]
async fn passthrough_skips_auth_when_keyring_missing_the_key() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/anything"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/api"
auth_type = "bearer"
auth_key_name = "absent_key"
"#,
        upstream.uri()
    );

    // Empty keyring — `absent_key` is not present.
    let (app, _dir) = build_passthrough_app(&manifest, &[]);
    let req = Request::builder()
        .uri("/api/v1/anything")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Critical assertion: NO Authorization header reached upstream, not even
    // an empty "Bearer ". Old behaviour would have leaked `Bearer ` here.
    let received = upstream.received_requests().await.unwrap();
    let r = received.last().expect("upstream got at least one request");
    assert!(
        r.headers.get("authorization").is_none(),
        "auth_key_name miss must skip injection — no Authorization header should be sent upstream"
    );
}

/// `auth_key_name` is normalised to lowercase before keyring lookup so that
/// manifests written as `LITELLM_MASTER_KEY` resolve against `ATI_KEY_*`
/// entries (which the keyring stores lowercase by convention).
#[tokio::test]
async fn passthrough_resolves_auth_key_name_case_insensitively() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/x"))
        .and(header("authorization", "Bearer SECRET-VALUE"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let manifest = format!(
        r#"
[provider]
name = "test"
description = "t"
handler = "passthrough"
base_url = "{}"
path_prefix = "/api"
auth_type = "bearer"
# Manifest names the key in uppercase; keyring loader stored it lowercase
# (ATI_KEY_LITELLM_MASTER_KEY → "litellm_master_key"). Must still resolve.
auth_key_name = "LITELLM_MASTER_KEY"
"#,
        upstream.uri()
    );

    let (app, _dir) = build_passthrough_app(&manifest, &[("litellm_master_key", "SECRET-VALUE")]);
    let req = Request::builder()
        .uri("/api/v1/x")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "uppercase auth_key_name must resolve against lowercase keyring entry"
    );
}
