//! Integration tests for ATI_SESSION_TOKEN_FILE (issue #105).
//!
//! Unit tests for `resolve_session_token()` live alongside the helper in
//! `src/core/token.rs::tests`. This file exercises the full subprocess path:
//! - The `ati` binary picks up the token from a file when env is unset
//! - Rotating the file between invocations is observed by the next call
//! - Local-mode error message names all three sources

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// End-to-end rotation: launch `ati run` twice against a wiremock proxy,
/// rotating the token file between calls. Both calls must use the value
/// that was in the file at invocation time.
#[tokio::test]
async fn token_file_rotation_observed_by_subsequent_call() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/call"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "result": "ok",
            "error": null
        })))
        .mount(&mock_server)
        .await;

    let tmp = tempfile::tempdir().expect("create tempdir");
    let token_path = tmp.path().join("session_token");

    // First invocation
    std::fs::write(&token_path, "tok-rev1\n").unwrap();
    let out1 = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .args(["run", "anything", "--noop", "x"])
        .env("ATI_PROXY_URL", mock_server.uri())
        .env("ATI_DIR", "/tmp/ati-test-nonexistent")
        .env_remove("ATI_SESSION_TOKEN")
        .env("ATI_SESSION_TOKEN_FILE", &token_path)
        .output()
        .expect("Failed to execute ati");
    assert!(
        out1.status.success(),
        "first call failed: {}",
        String::from_utf8_lossy(&out1.stderr)
    );

    // Rotate the file in place
    std::fs::write(&token_path, "tok-rev2\n").unwrap();

    let out2 = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .args(["run", "anything", "--noop", "x"])
        .env("ATI_PROXY_URL", mock_server.uri())
        .env("ATI_DIR", "/tmp/ati-test-nonexistent")
        .env_remove("ATI_SESSION_TOKEN")
        .env("ATI_SESSION_TOKEN_FILE", &token_path)
        .output()
        .expect("Failed to execute ati");
    assert!(
        out2.status.success(),
        "second call failed: {}",
        String::from_utf8_lossy(&out2.stderr)
    );

    // Inspect what wiremock received: the first POST should carry rev1, the
    // second should carry rev2 — proving each invocation re-read the file.
    let received = mock_server.received_requests().await.expect("requests");
    assert_eq!(received.len(), 2, "expected 2 proxy calls");

    let auth1 = received[0]
        .headers
        .get("authorization")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
    let auth2 = received[1]
        .headers
        .get("authorization")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();

    assert_eq!(auth1, "Bearer tok-rev1", "first call used wrong token");
    assert_eq!(auth2, "Bearer tok-rev2", "second call used wrong token");
}

/// Env var wins over the file source — operator can still pin a token by env.
#[tokio::test]
async fn env_var_overrides_token_file() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/call"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "result": "ok",
            "error": null
        })))
        .mount(&mock_server)
        .await;

    let tmp = tempfile::tempdir().expect("create tempdir");
    let token_path = tmp.path().join("session_token");
    std::fs::write(&token_path, "from-file").unwrap();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .args(["run", "anything", "--noop", "x"])
        .env("ATI_PROXY_URL", mock_server.uri())
        .env("ATI_DIR", "/tmp/ati-test-nonexistent")
        .env("ATI_SESSION_TOKEN", "from-env")
        .env("ATI_SESSION_TOKEN_FILE", &token_path)
        .output()
        .expect("Failed to execute ati");
    assert!(out.status.success(), "ati call failed");

    let received = mock_server.received_requests().await.expect("requests");
    let auth = received[0]
        .headers
        .get("authorization")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
    assert_eq!(auth, "Bearer from-env");
}

/// Missing file + missing env + JWT validation configured = the new error
/// message naming all three sources. Preserves the legacy substring.
#[tokio::test]
async fn local_jwt_error_lists_all_token_sources() {
    let ati_dir = tempfile::tempdir().expect("create tempdir");
    let manifests = ati_dir.path().join("manifests");
    std::fs::create_dir_all(&manifests).unwrap();
    std::fs::write(
        manifests.join("noop.toml"),
        r#"
[provider]
name = "noop"
description = "Noop test provider"
base_url = "http://unused"
auth_type = "none"

[[tools]]
name = "noop_tool"
description = "noop"
endpoint = "/"
method = "GET"
scope = "tool:noop_tool"
"#,
    )
    .unwrap();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .args(["tool", "list"])
        .env("ATI_DIR", ati_dir.path())
        .env(
            "ATI_JWT_SECRET",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        .env_remove("ATI_SESSION_TOKEN")
        .env("ATI_SESSION_TOKEN_FILE", "/nonexistent/path/no/token/here")
        .env_remove("ATI_PROXY_URL")
        .output()
        .expect("Failed to execute ati");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "expected auth failure");
    // Legacy substring preserved for backwards compat with tests/proxy_test.rs
    assert!(
        stderr.contains("ATI_SESSION_TOKEN is required"),
        "missing legacy substring; stderr: {stderr}"
    );
    // New guidance mentions both alternative sources
    assert!(
        stderr.contains("ATI_SESSION_TOKEN_FILE"),
        "should mention file env var; stderr: {stderr}"
    );
    assert!(
        stderr.contains("/run/ati/session_token"),
        "should mention default path; stderr: {stderr}"
    );
}

