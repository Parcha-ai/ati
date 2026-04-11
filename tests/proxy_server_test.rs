/// Integration tests for the ATI proxy server (axum handlers).
///
/// These tests build the axum Router in-process (no TCP binding) and use
/// `tower::ServiceExt::oneshot` to send requests directly.
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ati::core::auth_generator::AuthCache;
use ati::core::jwt::{self, AtiNamespace, JwtConfig, TokenClaims};
use ati::core::keyring::Keyring;
use ati::core::manifest::ManifestRegistry;
use ati::core::skill::SkillRegistry;
use ati::proxy::server::{build_router, ProxyState};

/// Single global lock held by every test that mutates process-wide env vars
/// (e.g. `ATI_SKILL_REGISTRY`, `ATI_PROXY_URL`). Cargo runs tests in parallel
/// threads of a single process, so env mutation leaks across tests unless
/// serialized.
///
/// Uses `tokio::sync::Mutex` so the guard can be held across `.await` points
/// without tripping clippy's `await_holding_lock` lint.
fn env_mutex() -> &'static tokio::sync::Mutex<()> {
    static M: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    M.get_or_init(|| tokio::sync::Mutex::new(()))
}

struct EnvGuard {
    key: &'static str,
    original: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: Option<&str>) -> Self {
        let original = std::env::var(key).ok();
        if let Some(v) = value {
            std::env::set_var(key, v);
        } else {
            std::env::remove_var(key);
        }
        Self { key, original }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(val) = &self.original {
            std::env::set_var(self.key, val);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

// --- Helpers ---

/// Create a temp directory with a single manifest pointing at the given upstream base_url.
fn create_test_manifests(base_url: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    let manifest = format!(
        r#"
[provider]
name = "test_provider"
description = "Test provider for integration tests"
base_url = "{base_url}"
auth_type = "bearer"
auth_key_name = "test_api_key"

[[tools]]
name = "test_search"
description = "A test search tool"
endpoint = "/search"
method = "GET"
scope = "tool:test_search"

[tools.input_schema]
type = "object"
required = ["query"]

[tools.input_schema.properties.query]
type = "string"
description = "Search query"

[[tools]]
name = "test_create"
description = "A test POST tool"
endpoint = "/create"
method = "POST"

[tools.input_schema]
type = "object"
required = ["title"]

[tools.input_schema.properties.title]
type = "string"
description = "Title to create"

[[tools]]
name = "test_api:get_data"
description = "A tool with colon-separated provider:name format"
endpoint = "/data"
method = "GET"
scope = "tool:test_api:get_data"

[tools.input_schema]
type = "object"

[tools.input_schema.properties.id]
type = "string"
description = "Data ID"
"#
    );

    std::fs::write(manifests_dir.join("test.toml"), manifest).expect("write manifest");
    dir
}

/// Create an HS256 JWT config for testing.
fn test_jwt_config() -> JwtConfig {
    jwt::config_from_secret(
        b"test-secret-key-32-bytes-long!!!",
        None,
        "ati-proxy".into(),
    )
}

/// Issue a test JWT with given scopes.
fn issue_test_token(scope: &str) -> String {
    let config = test_jwt_config();
    let now = jwt::now_secs();
    let claims = TokenClaims {
        iss: None,
        sub: "test-agent".into(),
        aud: "ati-proxy".into(),
        iat: now,
        exp: now + 3600,
        jti: None,
        scope: scope.into(),
        ati: Some(AtiNamespace {
            v: 1,
            rate: std::collections::HashMap::new(),
        }),
        job_id: None,
        sandbox_id: None,
    };
    jwt::issue(&claims, &config).unwrap()
}

/// Build a test Router with manifests pointing at the given upstream, no auth.
fn build_test_app(upstream_url: &str) -> axum::Router {
    let dir = create_test_manifests(upstream_url);
    let manifests_dir = dir.path().join("manifests");
    let registry = ManifestRegistry::load(&manifests_dir).expect("load test manifests");
    std::mem::forget(dir);

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

/// Build a test app with JWT auth configured.
fn build_test_app_with_jwt(upstream_url: &str) -> axum::Router {
    let dir = create_test_manifests(upstream_url);
    let manifests_dir = dir.path().join("manifests");
    let registry = ManifestRegistry::load(&manifests_dir).expect("load test manifests");
    std::mem::forget(dir);

    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();

    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring: Keyring::empty(),
        jwt_config: Some(test_jwt_config()),
        jwks_json: None,
        auth_cache: AuthCache::new(),
    });

    build_router(state)
}

/// Helper to read response body as JSON.
async fn body_json(body: Body) -> Value {
    let bytes = body.collect().await.expect("collect body").to_bytes();
    serde_json::from_slice(&bytes).expect("parse body as JSON")
}

// --- Tests ---

/// /health returns 200 with tool and provider counts.
#[tokio::test]
async fn test_health_endpoint() {
    let app = build_test_app("http://unused.test");

    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    assert_eq!(json["status"], "ok");
    assert_eq!(json["tools"], 3); // test_search + test_create + test_api:get_data
    assert_eq!(json["providers"], 1);
    assert!(json["version"].as_str().is_some());
}

/// /call with an unknown tool returns 404 with error message.
#[tokio::test]
async fn test_call_unknown_tool_returns_404() {
    let app = build_test_app("http://unused.test");

    let body = serde_json::json!({
        "tool_name": "nonexistent_tool",
        "args": {}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let json = body_json(resp.into_body()).await;
    assert!(json["error"].as_str().unwrap().contains("Unknown tool"));
    assert!(json["error"].as_str().unwrap().contains("nonexistent_tool"));
}

/// /call routes to the upstream API and returns the response.
#[tokio::test]
async fn test_call_routes_to_upstream() {
    let upstream = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("query", "hello"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": [{"title": "Hello World"}],
            "total": 1
        })))
        .mount(&upstream)
        .await;

    let app = build_test_app(&upstream.uri());

    let body = serde_json::json!({
        "tool_name": "test_search",
        "args": {"query": "hello"}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");

    // The tool requires auth_type=bearer but keyring is empty, so we expect 502.
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

    let json = body_json(resp.into_body()).await;
    assert!(json["error"].as_str().unwrap().contains("test_api_key"));
}

/// /call with upstream returning an error propagates as 502.
#[tokio::test]
async fn test_call_upstream_error_returns_502() {
    let upstream = MockServer::start().await;

    let dir = tempfile::tempdir().expect("create tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    let manifest = format!(
        r#"
[provider]
name = "noauth_provider"
description = "Provider with no auth"
base_url = "{}"
auth_type = "none"

[[tools]]
name = "noauth_search"
description = "Search without auth"
endpoint = "/search"
method = "GET"

[tools.input_schema]
type = "object"
required = ["q"]

[tools.input_schema.properties.q]
type = "string"
description = "Query"
"#,
        upstream.uri()
    );

    std::fs::write(manifests_dir.join("noauth.toml"), manifest).expect("write manifest");

    let registry = ManifestRegistry::load(&manifests_dir).expect("load manifests");

    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&upstream)
        .await;

    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring: Keyring::empty(),
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
    });
    let app = build_router(state);

    let body = serde_json::json!({
        "tool_name": "noauth_search",
        "args": {"q": "test"}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

    let json = body_json(resp.into_body()).await;
    assert!(json["error"]
        .as_str()
        .unwrap()
        .contains("Upstream API error"));
}

/// /call with auth_type=none + successful upstream returns 200 with result.
#[tokio::test]
async fn test_call_noauth_tool_success() {
    let upstream = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "found": true,
            "name": "Test Entity"
        })))
        .mount(&upstream)
        .await;

    let dir = tempfile::tempdir().expect("create tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    let manifest = format!(
        r#"
[provider]
name = "open_provider"
description = "No auth required"
base_url = "{}"
auth_type = "none"

[[tools]]
name = "open_lookup"
description = "Public lookup"
endpoint = "/lookup"
method = "GET"

[tools.input_schema]
type = "object"

[tools.input_schema.properties.id]
type = "string"
description = "ID to look up"
"#,
        upstream.uri()
    );

    std::fs::write(manifests_dir.join("open.toml"), manifest).expect("write manifest");

    let registry = ManifestRegistry::load(&manifests_dir).expect("load manifests");
    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring: Keyring::empty(),
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
    });
    let app = build_router(state);

    let body = serde_json::json!({
        "tool_name": "open_lookup",
        "args": {"id": "123"}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    assert_eq!(json["result"]["found"], true);
    assert_eq!(json["result"]["name"], "Test Entity");
    assert!(json["error"].is_null() || json.get("error").is_none());
}

/// POST tool with auth_type=none succeeds.
#[tokio::test]
async fn test_call_post_tool_success() {
    let upstream = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/create"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "new-456",
            "created": true
        })))
        .mount(&upstream)
        .await;

    let dir = tempfile::tempdir().expect("create tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    let manifest = format!(
        r#"
[provider]
name = "post_provider"
description = "Post provider"
base_url = "{}"
auth_type = "none"

[[tools]]
name = "post_create"
description = "Create something"
endpoint = "/create"
method = "POST"

[tools.input_schema]
type = "object"
required = ["title"]

[tools.input_schema.properties.title]
type = "string"
description = "Title"
"#,
        upstream.uri()
    );

    std::fs::write(manifests_dir.join("post.toml"), manifest).expect("write manifest");

    let registry = ManifestRegistry::load(&manifests_dir).expect("load manifests");
    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring: Keyring::empty(),
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
    });
    let app = build_router(state);

    let body = serde_json::json!({
        "tool_name": "post_create",
        "args": {"title": "My Document"}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    assert_eq!(json["result"]["id"], "new-456");
    assert_eq!(json["result"]["created"], true);
}

/// /help without an _llm.toml manifest returns 503.
#[tokio::test]
async fn test_help_without_llm_returns_503() {
    let app = build_test_app("http://unused.test");

    let body = serde_json::json!({
        "query": "how do I search?"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/help")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let json = body_json(resp.into_body()).await;
    assert!(json["error"].as_str().unwrap().contains("_llm.toml"));
}

/// /call with invalid JSON body returns 400.
#[tokio::test]
async fn test_call_invalid_json_returns_error() {
    let app = build_test_app("http://unused.test");

    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from("this is not json"))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    // Now we parse manually so we get 422 for invalid JSON
    assert!(
        resp.status() == StatusCode::UNPROCESSABLE_ENTITY
            || resp.status() == StatusCode::BAD_REQUEST
    );
}

/// /call with missing required fields returns 422.
#[tokio::test]
async fn test_call_missing_fields_returns_error() {
    let app = build_test_app("http://unused.test");

    let body = serde_json::json!({
        "args": {"query": "test"}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

/// GET /call returns 405 Method Not Allowed (only POST is accepted).
#[tokio::test]
async fn test_call_get_method_not_allowed() {
    let app = build_test_app("http://unused.test");

    let req = Request::builder().uri("/call").body(Body::empty()).unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

/// Bearer auth is injected when keyring has the key.
#[tokio::test]
async fn test_call_with_keyring_injects_auth() {
    let upstream = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/search"))
        .and(header("Authorization", "Bearer secret-key-value"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "auth_verified": true,
            "data": "secure result"
        })))
        .mount(&upstream)
        .await;

    let dir = tempfile::tempdir().expect("create tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    let manifest = format!(
        r#"
[provider]
name = "secure_provider"
description = "Requires bearer auth"
base_url = "{}"
auth_type = "bearer"
auth_key_name = "secure_api_key"

[[tools]]
name = "secure_search"
description = "Search with auth"
endpoint = "/search"
method = "GET"

[tools.input_schema]
type = "object"

[tools.input_schema.properties.query]
type = "string"
description = "Query"
"#,
        upstream.uri()
    );

    std::fs::write(manifests_dir.join("secure.toml"), manifest).expect("write manifest");

    let registry = ManifestRegistry::load(&manifests_dir).expect("load manifests");

    let session_key = ati::core::keyring::generate_session_key();
    let keyring_json = serde_json::json!({"secure_api_key": "secret-key-value"});
    let plaintext = serde_json::to_vec(&keyring_json).unwrap();
    let encrypted = ati::core::keyring::encrypt_keyring(&session_key, &plaintext).unwrap();

    let keyring_path = dir.path().join("keyring.enc");
    std::fs::write(&keyring_path, &encrypted).expect("write keyring");

    let keyring = Keyring::load_with_key(&keyring_path, &session_key).expect("load keyring");

    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring,
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
    });
    let app = build_router(state);

    let body = serde_json::json!({
        "tool_name": "secure_search",
        "args": {"query": "test"}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    assert_eq!(json["result"]["auth_verified"], true);
    assert_eq!(json["result"]["data"], "secure result");
}

// --- JWT Auth middleware tests ---

/// Requests without token are rejected when JWT auth is configured.
#[tokio::test]
async fn test_jwt_auth_rejects_missing_token() {
    let app = build_test_app_with_jwt("http://unused.test");

    let body = serde_json::json!({
        "tool_name": "test_search",
        "args": {"query": "hello"}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Requests with invalid JWT are rejected.
#[tokio::test]
async fn test_jwt_auth_rejects_invalid_token() {
    let app = build_test_app_with_jwt("http://unused.test");

    let body = serde_json::json!({
        "tool_name": "test_search",
        "args": {"query": "hello"}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .header("authorization", "Bearer not-a-valid-jwt")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Requests with wrong secret JWT are rejected.
#[tokio::test]
async fn test_jwt_auth_rejects_wrong_secret() {
    let app = build_test_app_with_jwt("http://unused.test");

    // Issue token with a different secret
    let wrong_config = jwt::config_from_secret(
        b"wrong-secret-key-32-bytes-long!!",
        None,
        "ati-proxy".into(),
    );
    let now = jwt::now_secs();
    let claims = TokenClaims {
        iss: None,
        sub: "test-agent".into(),
        aud: "ati-proxy".into(),
        iat: now,
        exp: now + 3600,
        jti: None,
        scope: "*".into(),
        ati: None,
        job_id: None,
        sandbox_id: None,
    };
    let bad_token = jwt::issue(&claims, &wrong_config).unwrap();

    let body = serde_json::json!({
        "tool_name": "test_search",
        "args": {"query": "hello"}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {bad_token}"))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Requests with valid JWT are accepted and scopes enforced.
#[tokio::test]
async fn test_jwt_auth_accepts_valid_token() {
    let app = build_test_app_with_jwt("http://unused.test");
    let token = issue_test_token("tool:test_search tool:test_create");

    let body = serde_json::json!({
        "tool_name": "nonexistent_tool",
        "args": {}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    // 404 means middleware passed and handler ran (tool not found)
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// JWT with insufficient scopes returns 403.
#[tokio::test]
async fn test_jwt_scope_enforcement_denies_access() {
    let app = build_test_app_with_jwt("http://unused.test");
    // Issue token with scope that doesn't include test_search
    let token = issue_test_token("tool:other_tool");

    let body = serde_json::json!({
        "tool_name": "test_search",
        "args": {"query": "hello"}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// JWT-scoped /tools only exposes visible tools.
#[tokio::test]
async fn test_jwt_scopes_filter_tools_endpoint() {
    let app = build_test_app_with_jwt("http://unused.test");
    let token = issue_test_token("tool:test_search");

    let req = Request::builder()
        .uri("/tools")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    let tools = json.as_array().unwrap();
    assert!(tools.iter().any(|tool| tool["name"] == "test_search"));
    // test_create has auto-assigned scope "tool:test_create" — not in this JWT
    assert!(!tools.iter().any(|tool| tool["name"] == "test_create"));
    assert!(!tools.iter().any(|tool| tool["name"] == "test_api:get_data"));
}

/// JWT-scoped MCP tools/list only exposes visible tools.
#[tokio::test]
async fn test_jwt_scopes_filter_mcp_tools_list() {
    let app = build_test_app_with_jwt("http://unused.test");
    let token = issue_test_token("tool:test_search");
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    let tools = json["result"]["tools"].as_array().unwrap();
    assert!(tools.iter().any(|tool| tool["name"] == "test_search"));
    // test_create has auto-assigned scope "tool:test_create" — not in this JWT
    assert!(!tools.iter().any(|tool| tool["name"] == "test_create"));
    assert!(!tools.iter().any(|tool| tool["name"] == "test_api:get_data"));
}

/// JWT-scoped MCP tools/call enforces the same scopes as /call.
#[tokio::test]
async fn test_jwt_scope_enforcement_denies_mcp_tools_call() {
    let app = build_test_app_with_jwt("http://unused.test");
    let token = issue_test_token("tool:test_search");
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "test_api:get_data",
            "arguments": {"id": "123"}
        }
    });

    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    assert_eq!(json["error"]["code"], -32001);
    assert!(json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Access denied"));
}

/// JWT with wildcard scope allows access to any tool.
#[tokio::test]
async fn test_jwt_wildcard_scope_allows_all() {
    let app = build_test_app_with_jwt("http://unused.test");
    let token = issue_test_token("*");

    let body = serde_json::json!({
        "tool_name": "test_search",
        "args": {"query": "hello"}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    // 502 means auth passed, scope passed, tool found, but keyring is empty
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

/// Expired JWT is rejected.
#[tokio::test]
async fn test_jwt_expired_token_rejected() {
    let app = build_test_app_with_jwt("http://unused.test");

    let config = test_jwt_config();
    let claims = TokenClaims {
        iss: None,
        sub: "test-agent".into(),
        aud: "ati-proxy".into(),
        iat: 1000000,
        exp: 1000001, // Expired long ago
        jti: None,
        scope: "*".into(),
        ati: None,
        job_id: None,
        sandbox_id: None,
    };
    let expired_token = jwt::issue(&claims, &config).unwrap();

    let body = serde_json::json!({
        "tool_name": "test_search",
        "args": {"query": "hello"}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {expired_token}"))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// /health is exempt from JWT auth.
#[tokio::test]
async fn test_health_bypasses_jwt_auth() {
    let app = build_test_app_with_jwt("http://unused.test");

    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    assert_eq!(json["status"], "ok");
    assert_eq!(json["auth"], "jwt");
}

/// /.well-known/jwks.json is exempt from JWT auth.
#[tokio::test]
async fn test_jwks_bypasses_jwt_auth() {
    let app = build_test_app_with_jwt("http://unused.test");

    let req = Request::builder()
        .uri("/.well-known/jwks.json")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    // 404 because no JWKS configured (HS256 doesn't have JWKS), but auth was bypassed
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// When no JWT config is set, all requests pass through (dev mode).
#[tokio::test]
async fn test_no_jwt_config_allows_all() {
    let app = build_test_app("http://unused.test");

    let body = serde_json::json!({
        "tool_name": "nonexistent_tool",
        "args": {}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    // 404 means the middleware passed through and handler ran
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// --- Auth Generator through Proxy tests ---

/// Auth generator with bearer token flows through the proxy /call endpoint.
#[tokio::test]
async fn test_call_with_auth_generator_through_proxy() {
    let upstream = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/gen-endpoint"))
        .and(header("authorization", "Bearer generated-proxy-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "proxy_gen": "success"
        })))
        .mount(&upstream)
        .await;

    let dir = tempfile::tempdir().expect("create tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    let manifest = format!(
        r#"
[provider]
name = "gen_proxy_provider"
description = "Provider with auth_generator for proxy test"
base_url = "{}"
auth_type = "bearer"

[provider.auth_generator]
type = "command"
command = "echo"
args = ["generated-proxy-token"]
cache_ttl_secs = 0
output_format = "text"
timeout_secs = 5

[[tools]]
name = "gen_proxy_search"
description = "Search via auth generator"
endpoint = "/gen-endpoint"
method = "GET"

[tools.input_schema]
type = "object"

[tools.input_schema.properties.q]
type = "string"
description = "Query"
"#,
        upstream.uri()
    );

    std::fs::write(manifests_dir.join("gen_proxy.toml"), manifest).expect("write manifest");
    let registry = ManifestRegistry::load(&manifests_dir).expect("load manifests");

    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring: Keyring::empty(),
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
    });
    let app = build_router(state);

    let body = serde_json::json!({
        "tool_name": "gen_proxy_search",
        "args": {"q": "test"}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    assert_eq!(json["result"]["proxy_gen"], "success");
}

/// Auth generator with JSON output + inject map through the proxy.
#[tokio::test]
async fn test_call_with_auth_generator_json_inject_through_proxy() {
    let upstream = MockServer::start().await;

    // Upstream requires both bearer token and custom header
    Mock::given(method("POST"))
        .and(path("/gen-secure"))
        .and(header("authorization", "Bearer proxy-session-tok"))
        .and(header("X-Custom-Key", "PROXY-KEY-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "proxy_inject": "verified"
        })))
        .mount(&upstream)
        .await;

    let dir = tempfile::tempdir().expect("create tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    let manifest = format!(
        r#"
[provider]
name = "gen_inject_provider"
description = "Provider with JSON inject auth_generator"
base_url = "{}"
auth_type = "bearer"

[provider.auth_generator]
type = "command"
command = "echo"
args = ['{{"token":"proxy-session-tok","api_key":"PROXY-KEY-123"}}']
cache_ttl_secs = 0
output_format = "json"
timeout_secs = 5

[provider.auth_generator.inject.token]
type = "primary"
name = "token"

[provider.auth_generator.inject."api_key"]
type = "header"
name = "X-Custom-Key"

[[tools]]
name = "gen_inject_tool"
description = "Tool with JSON inject"
endpoint = "/gen-secure"
method = "POST"

[tools.input_schema]
type = "object"

[tools.input_schema.properties.data]
type = "string"
description = "Data"
"#,
        upstream.uri()
    );

    std::fs::write(manifests_dir.join("gen_inject.toml"), manifest).expect("write manifest");
    let registry = ManifestRegistry::load(&manifests_dir).expect("load manifests");

    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring: Keyring::empty(),
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
    });
    let app = build_router(state);

    let body = serde_json::json!({
        "tool_name": "gen_inject_tool",
        "args": {"data": "hello"}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    assert_eq!(json["result"]["proxy_inject"], "verified");
}

// --- Tool endpoint tests ---

/// GET /tools returns all tools.
#[tokio::test]
async fn test_tools_list_returns_tools() {
    let app = build_test_app("http://unused.test");

    let req = Request::builder()
        .uri("/tools")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    let tools = json.as_array().expect("should be array");
    assert!(!tools.is_empty(), "should have at least one tool");

    // Each tool should have name, description, provider
    let first = &tools[0];
    assert!(first.get("name").is_some());
    assert!(first.get("description").is_some());
    assert!(first.get("provider").is_some());
}

/// GET /tools?provider=X filters by provider.
#[tokio::test]
async fn test_tools_list_filter_by_provider() {
    let app = build_test_app("http://unused.test");

    let req = Request::builder()
        .uri("/tools?provider=test_api")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    let tools = json.as_array().expect("should be array");
    for tool in tools {
        assert_eq!(tool["provider"], "test_api");
    }
}

/// GET /tools/:name returns tool info.
#[tokio::test]
async fn test_tool_info_returns_metadata() {
    let app = build_test_app("http://unused.test");

    let req = Request::builder()
        .uri("/tools/test_search")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    assert_eq!(json["name"], "test_search");
    assert_eq!(json["provider"], "test_provider");
    assert!(json.get("input_schema").is_some());
}

/// GET /tools/:name returns 404 for unknown tool.
#[tokio::test]
async fn test_tool_info_not_found() {
    let app = build_test_app("http://unused.test");

    let req = Request::builder()
        .uri("/tools/nonexistent_tool_xyz")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// --- Underscore → colon tool name resolution tests (issue #24) ---

/// POST /call with underscore tool name resolves to colon format.
/// Note: 502 is acceptable — it means the tool was FOUND (not 404) but upstream failed.
#[tokio::test]
async fn test_call_underscore_tool_name_resolves() {
    let app = build_test_app("http://unused.test");

    // "test_api_get_data" should resolve to "test_api:get_data" (not 404)
    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"tool_name": "test_api_get_data", "args": {}}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_ne!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "underscore tool name should resolve (not 404)"
    );
}

/// POST /call with colon tool name still works.
#[tokio::test]
async fn test_call_colon_tool_name_works() {
    let app = build_test_app("http://unused.test");

    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"tool_name": "test_api:get_data", "args": {}}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_ne!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "colon tool name should be found (not 404)"
    );
}

/// Scope check accepts underscore format in JWT when tool uses colon format.
#[tokio::test]
async fn test_call_underscore_scope_matches_colon_tool() {
    let app = build_test_app_with_jwt("http://unused.test");

    // JWT scope uses underscore: tool:test_api_get_data
    // Tool's scope uses colon: tool:test_api:get_data
    let claims = TokenClaims {
        sub: "test-agent".into(),
        aud: "ati-proxy".into(),
        scope: "tool:test_api_get_data".into(),
        exp: jwt::now_secs() + 3600,
        iat: jwt::now_secs(),
        iss: None,
        jti: None,
        ati: None,
        job_id: None,
        sandbox_id: None,
    };
    let token = jwt::issue(&claims, &test_jwt_config()).unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::json!({"tool_name": "test_api:get_data", "args": {}}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    // Should NOT be 403 (scope denied) — underscore scope should match colon tool
    assert_ne!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "underscore scope should match colon-format tool (not 403)"
    );
    // Should also NOT be 404
    assert_ne!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn skillati_catalog_without_registry_returns_503() {
    let _lock = env_mutex().lock().await;
    let _reg = EnvGuard::set("ATI_SKILL_REGISTRY", None);
    let _url = EnvGuard::set("ATI_PROXY_URL", None);
    let app = build_test_app("http://unused.test");

    let req = Request::builder()
        .method("GET")
        .uri("/skillati/catalog")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn skillati_resources_without_registry_returns_503() {
    let _lock = env_mutex().lock().await;
    let _reg = EnvGuard::set("ATI_SKILL_REGISTRY", None);
    let _url = EnvGuard::set("ATI_PROXY_URL", None);
    let app = build_test_app("http://unused.test");

    let req = Request::builder()
        .method("GET")
        .uri("/skillati/demo/resources")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn skillati_file_without_registry_returns_503() {
    let _lock = env_mutex().lock().await;
    let _reg = EnvGuard::set("ATI_SKILL_REGISTRY", None);
    let _url = EnvGuard::set("ATI_PROXY_URL", None);
    let app = build_test_app("http://unused.test");

    let req = Request::builder()
        .method("GET")
        .uri("/skillati/demo/file?path=SKILL.md")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// Legacy underscore JWT scopes still expose colon-namespaced tools in discovery.
#[tokio::test]
async fn test_tools_list_legacy_underscore_scope_includes_colon_tool() {
    let app = build_test_app_with_jwt("http://unused.test");
    let token = issue_test_token("tool:test_api_get_data");

    let req = Request::builder()
        .uri("/tools")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    let tools = json.as_array().unwrap();
    assert!(tools.iter().any(|tool| tool["name"] == "test_api:get_data"));
}

/// Legacy underscore JWT scopes still expose colon-namespaced tools in MCP tools/list.
#[tokio::test]
async fn test_mcp_tools_list_legacy_underscore_scope_includes_colon_tool() {
    let app = build_test_app_with_jwt("http://unused.test");
    let token = issue_test_token("tool:test_api_get_data");
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    let tools = json["result"]["tools"].as_array().unwrap();
    assert!(tools.iter().any(|tool| tool["name"] == "test_api:get_data"));
}

/// Legacy underscore JWT scopes are accepted by MCP tools/call just like /call.
#[tokio::test]
async fn test_mcp_tools_call_legacy_underscore_scope_matches_colon_tool() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/data"))
        .and(query_param("id", "123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "123",
            "ok": true
        })))
        .mount(&mock_server)
        .await;

    let app = build_test_app_with_jwt(&mock_server.uri());
    let token = issue_test_token("tool:test_api_get_data");
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "test_api:get_data",
            "arguments": {"id": "123"}
        }
    });

    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    assert!(json.get("error").is_none(), "unexpected MCP error: {json}");
    assert!(
        json["result"].is_object(),
        "expected MCP result object after auth passes: {json}"
    );
}

// --- Regression tests for issue #59 ---
//
// Before the fix, proxies running with `ATI_SKILL_REGISTRY=gcs://...` and an
// empty local `~/.ati/skills/` directory returned 404 for every remote skill,
// because `visible_skill_names` only consulted the (empty) local registry.
// These tests exercise all 6 /skillati/* handlers with a wiremock "upstream
// proxy" standing in for the remote catalog, and assert that:
//
//   (a) an explicit `skill:X` scope makes remote skill X visible
//   (b) a `tool:Y` scope makes remote skills that cover tool Y visible
//   (c) a `*` wildcard scope makes every remote skill visible
//   (d) a scope that grants nothing still 404s (scope enforcement preserved)
//
// The empty local `skill_registry` is the whole point — it reproduces the
// production deployment shape where skills live only in GCS.

/// Stand up a wiremock server acting as an upstream SkillATI proxy. Serves
/// `/skillati/catalog` with the given entries, plus a generic
/// `/skillati/:name/resources` → `{"resources": []}` so read_skill's
/// list_resources call doesn't 502.
async fn serve_remote_catalog_mock(entries: Vec<serde_json::Value>) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/skillati/catalog"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "skills": entries,
        })))
        .mount(&server)
        .await;
    // Resources endpoint is hit by read_skill → list_resources → list_all_resources.
    // Match via regex on the path prefix.
    Mock::given(method("GET"))
        .and(wiremock::matchers::path_regex(
            r"^/skillati/[^/]+/resources$",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "",
            "prefix": null,
            "resources": [],
        })))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn skillati_read_remote_skill_visible_via_explicit_skill_scope() {
    let _lock = env_mutex().lock().await;
    // Upstream "real" registry exposes one remote skill.
    let upstream = serve_remote_catalog_mock(vec![serde_json::json!({
        "name": "slidedeck-production",
        "description": "Remote skill",
        "skill_directory": "slidedeck-production",
    })])
    .await;
    // Serve the skill activation payload so the handler's read_skill path
    // completes. proxy_read_skill_md expects a JSON body with a `content`
    // field (the SKILL.md text).
    Mock::given(method("GET"))
        .and(path("/skillati/slidedeck-production"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "slidedeck-production",
            "skill_directory": "slidedeck-production",
            "content": "---\nname: slidedeck-production\ndescription: Remote skill\n---\nhello",
            "resources": [],
        })))
        .mount(&upstream)
        .await;

    let _reg = EnvGuard::set("ATI_SKILL_REGISTRY", Some("proxy"));
    let _url = EnvGuard::set("ATI_PROXY_URL", Some(&upstream.uri()));

    let app = build_test_app_with_jwt("http://unused.test");
    let token = issue_test_token("skill:slidedeck-production");

    let req = Request::builder()
        .method("GET")
        .uri("/skillati/slidedeck-production")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "remote skill with explicit skill: scope must be visible even when local skill registry is empty"
    );

    let body = body_json(resp.into_body()).await;
    // Level-2 shape (post-0.7.5): description is surfaced, resource
    // manifest is dropped so agents have to pull files on demand.
    assert_eq!(
        body["description"].as_str(),
        Some("Remote skill"),
        "activation must include description sourced from the catalog entry: {body}"
    );
    assert!(
        body.get("resources").is_none(),
        "activation must NOT include a resources manifest \
         (Level-3 is pulled on demand via `ati skill fetch resources`): {body}"
    );
}

#[tokio::test]
async fn skillati_catalog_includes_remote_skills_under_wildcard_scope() {
    let _lock = env_mutex().lock().await;
    let upstream = serve_remote_catalog_mock(vec![
        serde_json::json!({
            "name": "slidedeck-production",
            "description": "",
            "skill_directory": "slidedeck-production",
        }),
        serde_json::json!({
            "name": "html-app-architecture",
            "description": "",
            "skill_directory": "html-app-architecture",
        }),
    ])
    .await;

    let _reg = EnvGuard::set("ATI_SKILL_REGISTRY", Some("proxy"));
    let _url = EnvGuard::set("ATI_PROXY_URL", Some(&upstream.uri()));

    let app = build_test_app_with_jwt("http://unused.test");
    let token = issue_test_token("*");

    let req = Request::builder()
        .method("GET")
        .uri("/skillati/catalog")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_json(resp.into_body()).await;
    let skills = body
        .get("skills")
        .and_then(|s| s.as_array())
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        skills.len(),
        2,
        "wildcard scope must surface every remote skill, got: {body}"
    );
}

#[tokio::test]
async fn skillati_read_remote_skill_denied_when_scope_lacks_access() {
    let _lock = env_mutex().lock().await;
    // Catalog has the skill, but the caller's scope does not grant it.
    let upstream = serve_remote_catalog_mock(vec![serde_json::json!({
        "name": "slidedeck-production",
        "description": "",
        "skill_directory": "slidedeck-production",
    })])
    .await;

    let _reg = EnvGuard::set("ATI_SKILL_REGISTRY", Some("proxy"));
    let _url = EnvGuard::set("ATI_PROXY_URL", Some(&upstream.uri()));

    let app = build_test_app_with_jwt("http://unused.test");
    // `help` scope alone grants no skills.
    let token = issue_test_token("help");

    let req = Request::builder()
        .method("GET")
        .uri("/skillati/slidedeck-production")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "scope without access to a remote skill must still 404 (scope enforcement preserved)"
    );
}

#[tokio::test]
async fn skillati_read_remote_skill_visible_via_tool_scope_cascade() {
    let _lock = env_mutex().lock().await;
    // Remote skill `slidedeck-production` binds tool `test_search`; a token
    // with `tool:test_search` should make the skill visible via the cascade.
    let upstream = serve_remote_catalog_mock(vec![serde_json::json!({
        "name": "slidedeck-production",
        "description": "",
        "skill_directory": "slidedeck-production",
        "tools": ["test_search"],
    })])
    .await;
    Mock::given(method("GET"))
        .and(path("/skillati/slidedeck-production"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "slidedeck-production",
            "skill_directory": "slidedeck-production",
            "content": "---\nname: slidedeck-production\n---\nhello",
            "resources": [],
        })))
        .mount(&upstream)
        .await;

    let _reg = EnvGuard::set("ATI_SKILL_REGISTRY", Some("proxy"));
    let _url = EnvGuard::set("ATI_PROXY_URL", Some(&upstream.uri()));

    let app = build_test_app_with_jwt("http://unused.test");
    let token = issue_test_token("tool:test_search");

    let req = Request::builder()
        .method("GET")
        .uri("/skillati/slidedeck-production")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let body = body_json(resp.into_body()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "tool: scope should cascade to remote skills that cover that tool — body: {body}"
    );
}

/// The other four skillati handlers (resources, file, refs, ref) all use
/// the same `visible_skill_names_with_remote` helper and are therefore
/// structurally fixed by this PR, but left untested by the per-handler tests
/// above, only `read` and `catalog` had direct coverage.
///
/// This test fires a request at each of the four remaining handlers against
/// a proxy with an empty local SkillRegistry and a remote catalog that only
/// grants visibility through the scope gate. Before the fix all four returned
/// 404; after the fix all four return 200.
#[tokio::test]
async fn skillati_remaining_handlers_visible_for_remote_only_skill() {
    let _lock = env_mutex().lock().await;
    let upstream = serve_remote_catalog_mock(vec![serde_json::json!({
        "name": "slidedeck-production",
        "description": "",
        "skill_directory": "slidedeck-production",
    })])
    .await;
    // /skillati/:name/file → FileDataResp (tagged enum, `kind: "text"`).
    // Same endpoint also serves read_reference(name, ref) calls, which hit
    // ?path=references/<ref>.
    Mock::given(method("GET"))
        .and(wiremock::matchers::path_regex(r"^/skillati/[^/]+/file$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "kind": "text",
            "content": "file body",
        })))
        .mount(&upstream)
        .await;

    let _reg = EnvGuard::set("ATI_SKILL_REGISTRY", Some("proxy"));
    let _url = EnvGuard::set("ATI_PROXY_URL", Some(&upstream.uri()));

    let app = build_test_app_with_jwt("http://unused.test");
    let token = issue_test_token("skill:slidedeck-production");

    // Exercise each of the four remaining /skillati/* handlers. Any of them
    // returning 404 is a regression of the fix — they all share the same
    // visibility helper.
    // Use a non-SKILL.md path for file since SKILL.md triggers the read_skill_md
    // path which has different error handling.
    let endpoints: &[(&str, &str)] = &[
        ("resources", "/skillati/slidedeck-production/resources"),
        (
            "file",
            "/skillati/slidedeck-production/file?path=assets/foo.txt",
        ),
        ("refs", "/skillati/slidedeck-production/refs"),
        ("ref", "/skillati/slidedeck-production/ref/example"),
    ];

    for (label, uri) in endpoints {
        let req = Request::builder()
            .method("GET")
            .uri(*uri)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        let status = resp.status();
        let body = body_json(resp.into_body()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "handler `{label}` at {uri} must return 200 for a remote-only skill with the correct scope — body: {body}"
        );
    }
}

/// `read_skill` substitutes `${ATI_SKILL_DIR}` and `${CLAUDE_SKILL_DIR}` in
/// SKILL.md bodies to the skill's `skillati://<name>` URI. Mirrors Claude
/// Code's `${CLAUDE_SKILL_DIR}` substitution at
/// `~/cc/src/skills/loadSkillsDir.ts:362`. Supporting both variable names
/// means skill content authored for Claude Code works unchanged here, and
/// vice versa.
#[tokio::test]
async fn skillati_read_substitutes_skill_dir_variables() {
    let _lock = env_mutex().lock().await;
    let upstream = serve_remote_catalog_mock(vec![serde_json::json!({
        "name": "slidedeck-production",
        "description": "Zero-dep HTML presentations",
        "skill_directory": "slidedeck-production",
    })])
    .await;
    // SKILL.md body contains both variable forms in a single content block.
    Mock::given(method("GET"))
        .and(path("/skillati/slidedeck-production"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "slidedeck-production",
            "skill_directory": "slidedeck-production",
            "content": "---\nname: slidedeck-production\n---\n\
                Run ${ATI_SKILL_DIR}/scripts/generate.sh before building.\n\
                Also see ${CLAUDE_SKILL_DIR}/references/theme-guide.md.\n",
            "resources": [],
        })))
        .mount(&upstream)
        .await;

    let _reg = EnvGuard::set("ATI_SKILL_REGISTRY", Some("proxy"));
    let _url = EnvGuard::set("ATI_PROXY_URL", Some(&upstream.uri()));

    let app = build_test_app_with_jwt("http://unused.test");
    let token = issue_test_token("skill:slidedeck-production");
    let req = Request::builder()
        .method("GET")
        .uri("/skillati/slidedeck-production")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    let content = body["content"].as_str().unwrap_or_default().to_string();

    assert!(
        !content.contains("${ATI_SKILL_DIR}"),
        "${{ATI_SKILL_DIR}} should have been substituted away: {content}"
    );
    assert!(
        !content.contains("${CLAUDE_SKILL_DIR}"),
        "${{CLAUDE_SKILL_DIR}} should have been substituted away: {content}"
    );
    assert!(
        content.contains("skillati://slidedeck-production/scripts/generate.sh"),
        "ATI_SKILL_DIR should resolve to skillati://<name>: {content}"
    );
    assert!(
        content.contains("skillati://slidedeck-production/references/theme-guide.md"),
        "CLAUDE_SKILL_DIR should resolve to the same skillati://<name>: {content}"
    );
}

/// `read_skill` rewrites `.claude/skills/<other-skill>/…` directory
/// references to `skillati://<other-skill>/…` so skill bodies authored
/// against Claude Code's filesystem layout resolve correctly through the
/// ATI runtime. Guarded by `is_anthropic_valid_name` — prose mentions
/// like "the .claude/skills/ directory" are left unchanged.
#[tokio::test]
async fn skillati_read_rewrites_cross_skill_filesystem_refs() {
    let _lock = env_mutex().lock().await;
    let upstream = serve_remote_catalog_mock(vec![serde_json::json!({
        "name": "html-app-architecture",
        "description": "HTML app patterns",
        "skill_directory": "html-app-architecture",
    })])
    .await;
    Mock::given(method("GET"))
        .and(path("/skillati/html-app-architecture"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "html-app-architecture",
            "skill_directory": "html-app-architecture",
            // Real-world body: explicit path reference + a prose mention.
            // Only the explicit directory-form reference should be rewritten.
            "content": "---\nname: html-app-architecture\n---\n\
                Before building, read `.claude/skills/anti-slop-design/SKILL.md`\n\
                and follow the Selection Protocol. Skills live under the\n\
                .claude/skills/ directory on Claude Code.\n",
            "resources": [],
        })))
        .mount(&upstream)
        .await;

    let _reg = EnvGuard::set("ATI_SKILL_REGISTRY", Some("proxy"));
    let _url = EnvGuard::set("ATI_PROXY_URL", Some(&upstream.uri()));

    let app = build_test_app_with_jwt("http://unused.test");
    let token = issue_test_token("skill:html-app-architecture");
    let req = Request::builder()
        .method("GET")
        .uri("/skillati/html-app-architecture")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    let content = body["content"].as_str().unwrap_or_default().to_string();

    assert!(
        content.contains("skillati://anti-slop-design/SKILL.md"),
        "directory-form `.claude/skills/<name>/…` must be rewritten to skillati://<name>/…: {content}"
    );
    assert!(
        !content.contains(".claude/skills/anti-slop-design"),
        "original filesystem path must be fully replaced: {content}"
    );
    // Prose mention with non-name-char after the anchor is preserved.
    assert!(
        content.contains(".claude/skills/ directory"),
        "prose mention of `.claude/skills/ directory` must not be rewritten: {content}"
    );
}
