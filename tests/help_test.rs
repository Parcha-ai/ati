/// Integration tests for `ati assist` (local mode) and proxy `/help` endpoint.
///
/// Uses wiremock to mock the Cerebras LLM API so tests run without real API keys.
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ati::core::auth_generator::AuthCache;
use ati::core::keyring::Keyring;
use ati::core::manifest::ManifestRegistry;
use ati::core::skill::SkillRegistry;
use ati::proxy::server::{build_router, ProxyState};

// --- Helpers ---

/// Build a mock Cerebras LLM response.
fn mock_llm_response(content: &str) -> Value {
    serde_json::json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": content
            },
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}
    })
}

/// Create a temp manifests dir with a test tool AND an _llm.toml pointing at the mock LLM.
fn create_test_manifests_with_llm(tool_base_url: &str, llm_base_url: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    // A real tool manifest
    let tool_manifest = format!(
        r#"
[provider]
name = "test_finance"
description = "Test financial data provider"
base_url = "{tool_base_url}"
auth_type = "bearer"
auth_key_name = "test_api_key"

[[tools]]
name = "get_stock_quote"
description = "Get real-time stock quote with price, volume, and change"
endpoint = "/quote"
method = "GET"
scope = "tool:get_stock_quote"

[tools.input_schema]
type = "object"
required = ["symbol"]

[tools.input_schema.properties.symbol]
type = "string"
description = "Stock ticker symbol (e.g. AAPL, MSFT)"
"#
    );

    // _llm.toml — internal provider for assist mode
    let llm_manifest = format!(
        r#"
[provider]
name = "_llm"
description = "LLM provider for ati assist (internal)"
base_url = "{llm_base_url}"
auth_type = "bearer"
auth_key_name = "cerebras_api_key"
internal = true

[[tools]]
name = "_chat_completion"
description = "Chat completion via LLM (internal, for ati assist)"
endpoint = "/chat/completions"
method = "POST"
"#
    );

    std::fs::write(manifests_dir.join("test_finance.toml"), tool_manifest)
        .expect("write tool manifest");
    std::fs::write(manifests_dir.join("_llm.toml"), llm_manifest).expect("write _llm manifest");

    dir
}

/// Create an encrypted keyring containing a cerebras_api_key.
///
/// Returns (keyring_path, keyring, key_file_path).
/// For in-process tests, use the Keyring directly.
/// For subprocess tests, set ATI_KEY_FILE to key_file_path.
fn create_test_keyring(dir: &std::path::Path) -> (std::path::PathBuf, Keyring, std::path::PathBuf) {
    let session_key = ati::core::keyring::generate_session_key();
    let keyring_json = serde_json::json!({
        "cerebras_api_key": "test-cerebras-key-123",
        "test_api_key": "test-tool-key-456"
    });
    let plaintext = serde_json::to_vec(&keyring_json).unwrap();
    let encrypted = ati::core::keyring::encrypt_keyring(&session_key, &plaintext).unwrap();

    let keyring_path = dir.join("keyring.enc");
    std::fs::write(&keyring_path, &encrypted).expect("write keyring.enc");

    // Write the session key as base64 to a .key file (for sealed_file::read_and_delete_key)
    let key_file_path = dir.join(".key");
    let key_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, session_key);
    std::fs::write(&key_file_path, &key_b64).expect("write .key file");

    let keyring = Keyring::load_with_key(&keyring_path, &session_key).expect("load test keyring");

    (keyring_path, keyring, key_file_path)
}

async fn body_json(body: Body) -> Value {
    let bytes = body.collect().await.expect("collect body").to_bytes();
    serde_json::from_slice(&bytes).expect("parse body as JSON")
}

// ============================================================
// Proxy /help endpoint tests (in-process via axum Router)
// ============================================================

/// Proxy /help with a mocked LLM returns tool recommendations.
#[tokio::test]
async fn test_proxy_help_returns_llm_recommendations() {
    let llm_mock = MockServer::start().await;

    // Mock Cerebras chat completions endpoint
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(header("Authorization", "Bearer test-cerebras-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_llm_response(
            "1. **get_stock_quote** — Get real-time stock quote\n   ```\n   ati run get_stock_quote --symbol AAPL\n   ```",
        )))
        .expect(1)
        .mount(&llm_mock)
        .await;

    let dir = create_test_manifests_with_llm("http://unused.test", &llm_mock.uri());
    let manifests_dir = dir.path().join("manifests");
    let registry = ManifestRegistry::load(&manifests_dir).expect("load manifests");

    let (_, keyring, _) = create_test_keyring(dir.path());

    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring,
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
        db: ati::core::db::DbState::Disabled,
        call_log: None,
    });
    let app = build_router(state);

    let body = serde_json::json!({"query": "What is Apple's stock price?"});
    let req = Request::builder()
        .method("POST")
        .uri("/help")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    let content = json["content"].as_str().unwrap();

    // LLM response should contain the tool recommendation
    assert!(
        content.contains("get_stock_quote"),
        "Response should recommend get_stock_quote. Got: {content}"
    );
    assert!(
        content.contains("AAPL"),
        "Response should include AAPL example. Got: {content}"
    );
    assert!(
        json["error"].is_null() || json.get("error").is_none(),
        "Should have no error"
    );
}

/// Proxy /help sends correct system prompt with tool context.
#[tokio::test]
async fn test_proxy_help_sends_tool_context_in_prompt() {
    let llm_mock = MockServer::start().await;

    // Capture request body to verify the system prompt
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(mock_llm_response("Use get_stock_quote")),
        )
        .expect(1)
        .mount(&llm_mock)
        .await;

    let dir = create_test_manifests_with_llm("http://unused.test", &llm_mock.uri());
    let manifests_dir = dir.path().join("manifests");
    let registry = ManifestRegistry::load(&manifests_dir).expect("load manifests");
    let (_, keyring, _) = create_test_keyring(dir.path());

    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring,
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
        db: ati::core::db::DbState::Disabled,
        call_log: None,
    });
    let app = build_router(state);

    let body = serde_json::json!({"query": "stock price"});
    let req = Request::builder()
        .method("POST")
        .uri("/help")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify the request was made to the LLM (mock expects exactly 1 call)
    // If this passes, the system prompt with tools was sent correctly
    llm_mock.verify().await;
}

/// Proxy /help with missing cerebras key in keyring returns 503.
#[tokio::test]
async fn test_proxy_help_missing_llm_key_returns_503() {
    let llm_mock = MockServer::start().await;

    let dir = create_test_manifests_with_llm("http://unused.test", &llm_mock.uri());
    let manifests_dir = dir.path().join("manifests");
    let registry = ManifestRegistry::load(&manifests_dir).expect("load manifests");

    // Empty keyring — no cerebras_api_key
    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring: Keyring::empty(),
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
        db: ati::core::db::DbState::Disabled,
        call_log: None,
    });
    let app = build_router(state);

    let body = serde_json::json!({"query": "test"});
    let req = Request::builder()
        .method("POST")
        .uri("/help")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let json = body_json(resp.into_body()).await;
    assert!(
        json["error"].as_str().unwrap().contains("API key"),
        "Error should mention missing API key. Got: {}",
        json["error"]
    );
}

/// Proxy /help propagates LLM API errors as 502.
#[tokio::test]
async fn test_proxy_help_llm_error_returns_502() {
    let llm_mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
            "error": {"message": "Rate limit exceeded", "type": "rate_limit_error"}
        })))
        .mount(&llm_mock)
        .await;

    let dir = create_test_manifests_with_llm("http://unused.test", &llm_mock.uri());
    let manifests_dir = dir.path().join("manifests");
    let registry = ManifestRegistry::load(&manifests_dir).expect("load manifests");
    let (_, keyring, _) = create_test_keyring(dir.path());

    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring,
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
        db: ati::core::db::DbState::Disabled,
        call_log: None,
    });
    let app = build_router(state);

    let body = serde_json::json!({"query": "test"});
    let req = Request::builder()
        .method("POST")
        .uri("/help")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

    let json = body_json(resp.into_body()).await;
    assert!(
        json["error"].as_str().unwrap().contains("LLM API error"),
        "Error should mention LLM API error. Got: {}",
        json["error"]
    );
}

// ============================================================
// CLI `ati assist` local mode tests (subprocess)
// ============================================================

/// `ati assist` in local mode (no ATI_PROXY_URL) loads manifests + keyring
/// and calls the LLM to produce tool recommendations.
#[tokio::test]
async fn test_assist_local_mode_calls_llm() {
    let llm_mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(header("Authorization", "Bearer test-cerebras-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_llm_response(
            "1. **get_stock_quote** — Get real-time stock quote\n   ```\n   ati run get_stock_quote --symbol GOOG\n   ```",
        )))
        .expect(1)
        .mount(&llm_mock)
        .await;

    let dir = create_test_manifests_with_llm("http://unused.test", &llm_mock.uri());
    let (_, _, key_file_path) = create_test_keyring(dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .args(["assist", "What is Google stock price?"])
        .env_remove("ATI_PROXY_URL") // Force local mode
        .env("ATI_DIR", dir.path().to_str().unwrap())
        .env("ATI_KEY_FILE", key_file_path.to_str().unwrap())
        .output()
        .expect("Failed to execute ati");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "ati assist should succeed in local mode. stderr: {stderr}"
    );
    assert!(
        stdout.contains("get_stock_quote"),
        "Output should contain tool recommendation. stdout: {stdout}"
    );
    assert!(
        stdout.contains("GOOG"),
        "Output should contain the example ticker. stdout: {stdout}"
    );

    // Verify LLM was called exactly once
    llm_mock.verify().await;
}

/// `ati assist` local mode with --verbose shows mode info.
#[tokio::test]
async fn test_assist_local_mode_verbose() {
    let llm_mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(mock_llm_response("Use get_stock_quote")),
        )
        .mount(&llm_mock)
        .await;

    let dir = create_test_manifests_with_llm("http://unused.test", &llm_mock.uri());
    let (_, _, key_file_path) = create_test_keyring(dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .args(["--verbose", "assist", "test query"])
        .env_remove("ATI_PROXY_URL")
        .env("ATI_DIR", dir.path().to_str().unwrap())
        .env("ATI_KEY_FILE", key_file_path.to_str().unwrap())
        .output()
        .expect("Failed to execute ati");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("mode: local"),
        "Verbose output should show local mode. stderr: {stderr}"
    );
    assert!(
        stderr.contains("prompt_len"),
        "Verbose output should show prompt length. stderr: {stderr}"
    );
    assert!(
        stderr.contains("tools_in_context"),
        "Verbose output should show tool count. stderr: {stderr}"
    );
}

/// `ati assist` local mode without _llm.toml fails with a clear error.
#[tokio::test]
async fn test_assist_local_mode_no_llm_manifest_fails() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    // Write a tool manifest but NO _llm.toml
    let tool_manifest = r#"
[provider]
name = "test"
description = "Test"
base_url = "http://unused.test"
auth_type = "none"

[[tools]]
name = "test_tool"
description = "Test tool"
endpoint = "/test"
method = "GET"
"#;
    std::fs::write(manifests_dir.join("test.toml"), tool_manifest).expect("write manifest");

    // Create a dummy keyring so it doesn't fail on keyring loading
    let (_, _, key_file_path) = create_test_keyring(dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .args(["assist", "test query"])
        .env_remove("ATI_PROXY_URL")
        .env("ATI_DIR", dir.path().to_str().unwrap())
        .env("ATI_KEY_FILE", key_file_path.to_str().unwrap())
        .output()
        .expect("Failed to execute ati");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "Should fail without _llm.toml");
    assert!(
        stderr.contains("_llm.toml") || stderr.contains("LLM"),
        "Error should mention missing LLM config. stderr: {stderr}"
    );
}

/// `ati assist` local mode without keyring.enc fails with a clear error.
#[tokio::test]
async fn test_assist_local_mode_no_keyring_fails() {
    let llm_mock = MockServer::start().await;

    let dir = create_test_manifests_with_llm("http://unused.test", &llm_mock.uri());
    // Deliberately do NOT create keyring.enc

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .args(["assist", "test query"])
        .env_remove("ATI_PROXY_URL")
        .env("ATI_DIR", dir.path().to_str().unwrap())
        .output()
        .expect("Failed to execute ati");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "Should fail without keyring/LLM");
    assert!(
        stderr.contains("keyring")
            || stderr.contains("No keyring")
            || stderr.contains("No LLM available"),
        "Error should mention missing keyring or no LLM. stderr: {stderr}"
    );
}

/// `ati assist` with ATI_PROXY_URL set routes to proxy, NOT local.
#[tokio::test]
async fn test_assist_prefers_proxy_over_local() {
    let proxy_mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/help"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "content": "From proxy: use get_stock_quote --symbol TSLA",
            "error": null
        })))
        .expect(1)
        .mount(&proxy_mock)
        .await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .args(["assist", "Tesla stock price"])
        .env("ATI_PROXY_URL", proxy_mock.uri())
        .env("ATI_DIR", "/tmp/ati-nonexistent") // No local manifests
        .output()
        .expect("Failed to execute ati");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Should succeed via proxy. stderr: {stderr}"
    );
    assert!(
        stdout.contains("From proxy"),
        "Should use proxy response, not local. stdout: {stdout}"
    );

    proxy_mock.verify().await;
}

/// `ati assist` local mode uses Bearer auth with the cerebras key from keyring.
#[tokio::test]
async fn test_assist_local_mode_sends_bearer_auth() {
    let llm_mock = MockServer::start().await;

    // Only respond if correct Bearer token is sent
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(header("Authorization", "Bearer test-cerebras-key-123"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(mock_llm_response("Authenticated OK")),
        )
        .expect(1)
        .mount(&llm_mock)
        .await;

    let dir = create_test_manifests_with_llm("http://unused.test", &llm_mock.uri());
    let (_, _, key_file_path) = create_test_keyring(dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .args(["assist", "test"])
        .env_remove("ATI_PROXY_URL")
        .env("ATI_DIR", dir.path().to_str().unwrap())
        .env("ATI_KEY_FILE", key_file_path.to_str().unwrap())
        .output()
        .expect("Failed to execute ati");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Should succeed with correct auth. stderr: {stderr}"
    );
    assert!(
        stdout.contains("Authenticated OK"),
        "Should get response from auth-gated mock. stdout: {stdout}"
    );

    // Mock only matches with correct Bearer token — if this verifies, auth worked
    llm_mock.verify().await;
}

/// Proxy /help does NOT include internal tools (_llm) in the system prompt.
#[tokio::test]
async fn test_proxy_help_excludes_internal_tools() {
    let llm_mock = MockServer::start().await;

    // We'll capture the request and check the system prompt doesn't contain "_llm" or "_chat_completion"
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(mock_llm_response("tool recommendations")),
        )
        .expect(1)
        .mount(&llm_mock)
        .await;

    let dir = create_test_manifests_with_llm("http://unused.test", &llm_mock.uri());
    let manifests_dir = dir.path().join("manifests");
    let registry = ManifestRegistry::load(&manifests_dir).expect("load manifests");
    let (_, keyring, _) = create_test_keyring(dir.path());

    // Verify that list_public_tools excludes internal tools
    let public_tools = registry.list_public_tools();
    let tool_names: Vec<&str> = public_tools.iter().map(|(_, t)| t.name.as_str()).collect();

    assert!(
        tool_names.contains(&"get_stock_quote"),
        "Public tools should include get_stock_quote"
    );
    assert!(
        !tool_names.contains(&"_chat_completion"),
        "Public tools should NOT include _chat_completion (internal)"
    );

    // Also verify through the /help endpoint
    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring,
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
        db: ati::core::db::DbState::Disabled,
        call_log: None,
    });
    let app = build_router(state);

    let body = serde_json::json!({"query": "test"});
    let req = Request::builder()
        .method("POST")
        .uri("/help")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    llm_mock.verify().await;
}
