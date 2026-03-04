use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Without ATI_PROXY_URL, `ati run` should attempt local mode.
/// Since there's no manifest dir in the test env, it fails with a manifest error (not a proxy error).
#[tokio::test]
async fn test_call_without_proxy_uses_local_mode() {
    // Ensure ATI_PROXY_URL is not set
    std::env::remove_var("ATI_PROXY_URL");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .args(["run", "web_search", "--query", "test"])
        .env_remove("ATI_PROXY_URL")
        .env("ATI_DIR", "/tmp/ati-test-nonexistent")
        .output()
        .expect("Failed to execute ati");

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should fail with a manifest/directory error, NOT a proxy error
    assert!(!output.status.success());
    assert!(
        !stderr.contains("ATI_PROXY_URL"),
        "Should not mention proxy URL in local mode. stderr: {stderr}"
    );
}

/// With ATI_PROXY_URL set, `ati run` should forward to the proxy.
#[tokio::test]
async fn test_call_with_proxy_url_routes_to_proxy() {
    let mock_server = MockServer::start().await;

    // Mock the /call endpoint
    Mock::given(method("POST"))
        .and(path("/call"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": {"data": "from proxy"},
                "error": null
            })),
        )
        .mount(&mock_server)
        .await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .args(["run", "web_search", "--query", "test"])
        .env("ATI_PROXY_URL", mock_server.uri())
        .env("ATI_DIR", "/tmp/ati-test-nonexistent") // no local manifests needed
        .output()
        .expect("Failed to execute ati");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Proxy call should succeed. stderr: {stderr}"
    );
    assert!(
        stdout.contains("from proxy"),
        "Should contain proxy response. stdout: {stdout}"
    );
}

/// With ATI_PROXY_URL set and --verbose, should log proxy mode.
#[tokio::test]
async fn test_verbose_shows_proxy_mode() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/call"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": "ok",
                "error": null
            })),
        )
        .mount(&mock_server)
        .await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .args(["--verbose", "run", "some_tool"])
        .env("ATI_PROXY_URL", mock_server.uri())
        .env("ATI_DIR", "/tmp/ati-test-nonexistent")
        .output()
        .expect("Failed to execute ati");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Mode: proxy"),
        "Verbose output should show proxy mode. stderr: {stderr}"
    );
}

/// Proxy returns an error status code.
#[tokio::test]
async fn test_proxy_error_propagated() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/call"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .args(["run", "web_search", "--query", "test"])
        .env("ATI_PROXY_URL", mock_server.uri())
        .env("ATI_DIR", "/tmp/ati-test-nonexistent")
        .output()
        .expect("Failed to execute ati");

    assert!(!output.status.success(), "Should fail on proxy 500 error");
}

/// ati help with ATI_PROXY_URL routes to /help endpoint.
#[tokio::test]
async fn test_help_with_proxy_url_routes_to_proxy() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/help"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "content": "Use ati run web_search --query \"your query\"",
                "error": null
            })),
        )
        .mount(&mock_server)
        .await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .args(["assist", "how do I search the web?"])
        .env("ATI_PROXY_URL", mock_server.uri())
        .env("ATI_DIR", "/tmp/ati-test-nonexistent")
        .output()
        .expect("Failed to execute ati");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Proxy help call should succeed. stderr: {stderr}"
    );
    assert!(
        stdout.contains("web_search"),
        "Should contain proxy help response. stdout: {stdout}"
    );
}
