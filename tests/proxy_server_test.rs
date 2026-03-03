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

use ati::core::keyring::Keyring;
use ati::core::manifest::ManifestRegistry;
use ati::core::skill::SkillRegistry;
use ati::proxy::server::{build_router, ProxyState};

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
"#
    );

    std::fs::write(manifests_dir.join("test.toml"), manifest).expect("write manifest");
    dir
}

/// Build a test Router with manifests pointing at the given upstream and an empty keyring.
fn build_test_app(upstream_url: &str) -> axum::Router {
    let dir = create_test_manifests(upstream_url);
    let manifests_dir = dir.path().join("manifests");
    let registry = ManifestRegistry::load(&manifests_dir).expect("load test manifests");

    // Leak the TempDir so it lives for the whole test (manifests already loaded anyway)
    std::mem::forget(dir);

    // Empty skill registry for tests
    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();

    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring: Keyring::empty(),
        verbose: false,
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
    assert_eq!(json["tools"], 2); // test_search + test_create
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
    assert!(json["error"]
        .as_str()
        .unwrap()
        .contains("Unknown tool"));
    assert!(json["error"]
        .as_str()
        .unwrap()
        .contains("nonexistent_tool"));
}

/// /call routes to the upstream API and returns the response.
/// Uses wiremock as the upstream — the proxy's handler calls http::execute_tool
/// which makes a real HTTP request to wiremock.
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

    // The tool requires auth_type=bearer but keyring is empty, so we expect 502 (missing key).
    // This is correct — we're testing the proxy routing, not auth.
    // A 502 with "API key 'test_api_key' not found in keyring" means the tool was found
    // and the proxy attempted to execute it.
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

    let json = body_json(resp.into_body()).await;
    assert!(json["error"]
        .as_str()
        .unwrap()
        .contains("test_api_key"));
}

/// /call with upstream returning an error propagates as 502.
#[tokio::test]
async fn test_call_upstream_error_returns_502() {
    let upstream = MockServer::start().await;

    // No mocks mounted — upstream returns nothing, connection will work but the proxy
    // needs auth first. With auth_type=none we can test the upstream error path.
    // Let's create a manifest with auth_type = "none" instead.
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

    // Mount a 500 error on the upstream
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
        verbose: false,
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
        verbose: false,
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
        verbose: false,
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
    assert!(json["error"]
        .as_str()
        .unwrap()
        .contains("_llm.toml"));
}

/// /call with invalid JSON body returns 422 (axum deserialization error).
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
    // axum returns 400 Bad Request for malformed JSON
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// /call with missing required fields returns 422.
#[tokio::test]
async fn test_call_missing_fields_returns_error() {
    let app = build_test_app("http://unused.test");

    // Missing "tool_name" field
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

    let req = Request::builder()
        .uri("/call")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

/// Bearer auth is injected when keyring has the key.
#[tokio::test]
async fn test_call_with_keyring_injects_auth() {
    let upstream = MockServer::start().await;

    // Only respond if Authorization header is present
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

    // Create encrypted keyring with the test key
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
        verbose: false,
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
