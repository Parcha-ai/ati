/// Integration tests for `ati provider add-mcp/list/remove` CLI commands.
///
/// Tests:
/// - HTTP transport manifest generation
/// - Stdio transport manifest generation
/// - Auth fields (bearer, header)
/// - Environment variables from --env KEY=VALUE
/// - List shows providers
/// - Remove deletes provider manifest (any type)
/// - Validation: --url required for http, --command required for stdio
use std::process::Command;
use tempfile::TempDir;

fn ati_bin() -> String {
    env!("CARGO_BIN_EXE_ati").to_string()
}

fn create_ati_dir() -> TempDir {
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("manifests")).unwrap();
    dir
}

// ---------------------------------------------------------------------------
// Test: add HTTP transport manifest
// ---------------------------------------------------------------------------

#[test]
fn test_mcp_add_http() {
    let dir = create_ati_dir();

    let output = Command::new(ati_bin())
        .args([
            "provider",
            "add-mcp",
            "serpapi",
            "--transport",
            "http",
            "--url",
            "https://mcp.serpapi.com/mcp",
        ])
        .env("ATI_DIR", dir.path().to_str().unwrap())
        .output()
        .expect("Failed to execute ati");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "Should succeed. stderr: {stderr}");

    // Verify manifest was created
    let manifest_path = dir.path().join("manifests/serpapi.toml");
    assert!(manifest_path.exists(), "Manifest file should exist");

    let content = std::fs::read_to_string(&manifest_path).unwrap();
    let parsed: toml::Value = toml::from_str(&content).unwrap();
    let provider = &parsed["provider"];

    assert_eq!(provider["name"].as_str().unwrap(), "serpapi");
    assert_eq!(provider["handler"].as_str().unwrap(), "mcp");
    assert_eq!(provider["mcp_transport"].as_str().unwrap(), "http");
    assert_eq!(
        provider["mcp_url"].as_str().unwrap(),
        "https://mcp.serpapi.com/mcp"
    );
    assert_eq!(provider["auth_type"].as_str().unwrap(), "none");
    assert_eq!(
        provider["description"].as_str().unwrap(),
        "serpapi MCP provider"
    );
}

// ---------------------------------------------------------------------------
// Test: add stdio transport manifest
// ---------------------------------------------------------------------------

#[test]
fn test_mcp_add_stdio() {
    let dir = create_ati_dir();

    let output = Command::new(ati_bin())
        .args([
            "provider",
            "add-mcp",
            "github",
            "--transport",
            "stdio",
            "--command",
            "npx",
            "--args",
            "-y",
            "--args",
            "@modelcontextprotocol/server-github",
        ])
        .env("ATI_DIR", dir.path().to_str().unwrap())
        .output()
        .expect("Failed to execute ati");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "Should succeed. stderr: {stderr}");

    let content = std::fs::read_to_string(dir.path().join("manifests/github.toml")).unwrap();
    let parsed: toml::Value = toml::from_str(&content).unwrap();
    let provider = &parsed["provider"];

    assert_eq!(provider["name"].as_str().unwrap(), "github");
    assert_eq!(provider["handler"].as_str().unwrap(), "mcp");
    assert_eq!(provider["mcp_transport"].as_str().unwrap(), "stdio");
    assert_eq!(provider["mcp_command"].as_str().unwrap(), "npx");

    let args: Vec<&str> = provider["mcp_args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(args, vec!["-y", "@modelcontextprotocol/server-github"]);
}

// ---------------------------------------------------------------------------
// Test: add with bearer auth
// ---------------------------------------------------------------------------

#[test]
fn test_mcp_add_with_auth() {
    let dir = create_ati_dir();

    let output = Command::new(ati_bin())
        .args([
            "provider",
            "add-mcp",
            "parallel",
            "--transport",
            "http",
            "--url",
            "https://search-mcp.parallel.ai/mcp",
            "--auth",
            "bearer",
            "--auth-key",
            "parallel_api_key",
        ])
        .env("ATI_DIR", dir.path().to_str().unwrap())
        .output()
        .expect("Failed to execute ati");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "Should succeed. stderr: {stderr}");
    assert!(
        stderr.contains("parallel_api_key"),
        "Should hint about adding the key. stderr: {stderr}"
    );

    let content = std::fs::read_to_string(dir.path().join("manifests/parallel.toml")).unwrap();
    let parsed: toml::Value = toml::from_str(&content).unwrap();
    let provider = &parsed["provider"];

    assert_eq!(provider["auth_type"].as_str().unwrap(), "bearer");
    assert_eq!(
        provider["auth_key_name"].as_str().unwrap(),
        "parallel_api_key"
    );
}

// ---------------------------------------------------------------------------
// Test: add with --env KEY=VALUE
// ---------------------------------------------------------------------------

#[test]
fn test_mcp_add_with_env() {
    let dir = create_ati_dir();

    let output = Command::new(ati_bin())
        .args([
            "provider",
            "add-mcp",
            "github",
            "--transport",
            "stdio",
            "--command",
            "npx",
            "--args",
            "-y",
            "--args",
            "@modelcontextprotocol/server-github",
            "--env",
            "GITHUB_PERSONAL_ACCESS_TOKEN=${github_token}",
        ])
        .env("ATI_DIR", dir.path().to_str().unwrap())
        .output()
        .expect("Failed to execute ati");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "Should succeed. stderr: {stderr}");

    let content = std::fs::read_to_string(dir.path().join("manifests/github.toml")).unwrap();
    let parsed: toml::Value = toml::from_str(&content).unwrap();
    let provider = &parsed["provider"];

    let env = provider["mcp_env"].as_table().unwrap();
    assert_eq!(
        env["GITHUB_PERSONAL_ACCESS_TOKEN"].as_str().unwrap(),
        "${github_token}"
    );
}

// ---------------------------------------------------------------------------
// Test: list shows added MCPs
// ---------------------------------------------------------------------------

#[test]
fn test_mcp_list() {
    let dir = create_ati_dir();

    // Add two MCP providers
    Command::new(ati_bin())
        .args([
            "provider",
            "add-mcp",
            "serpapi",
            "--transport",
            "http",
            "--url",
            "https://mcp.serpapi.com/mcp",
        ])
        .env("ATI_DIR", dir.path().to_str().unwrap())
        .output()
        .expect("add serpapi");

    Command::new(ati_bin())
        .args([
            "provider",
            "add-mcp",
            "github",
            "--transport",
            "stdio",
            "--command",
            "npx",
            "--args",
            "-y",
            "--args",
            "@modelcontextprotocol/server-github",
        ])
        .env("ATI_DIR", dir.path().to_str().unwrap())
        .output()
        .expect("add github");

    // List
    let output = Command::new(ati_bin())
        .args(["provider", "list"])
        .env("ATI_DIR", dir.path().to_str().unwrap())
        .output()
        .expect("list");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "Should succeed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("serpapi"),
        "Should list serpapi. stdout: {stdout}"
    );
    assert!(
        stdout.contains("github"),
        "Should list github. stdout: {stdout}"
    );
    assert!(
        stdout.contains("http"),
        "Should show http transport. stdout: {stdout}"
    );
    assert!(
        stdout.contains("stdio"),
        "Should show stdio transport. stdout: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// Test: remove deletes MCP manifest
// ---------------------------------------------------------------------------

#[test]
fn test_mcp_remove() {
    let dir = create_ati_dir();

    // Add
    Command::new(ati_bin())
        .args([
            "provider",
            "add-mcp",
            "serpapi",
            "--transport",
            "http",
            "--url",
            "https://mcp.serpapi.com/mcp",
        ])
        .env("ATI_DIR", dir.path().to_str().unwrap())
        .output()
        .expect("add serpapi");

    assert!(dir.path().join("manifests/serpapi.toml").exists());

    // Remove
    let output = Command::new(ati_bin())
        .args(["provider", "remove", "serpapi"])
        .env("ATI_DIR", dir.path().to_str().unwrap())
        .output()
        .expect("remove serpapi");

    assert!(
        output.status.success(),
        "Should succeed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !dir.path().join("manifests/serpapi.toml").exists(),
        "Manifest should be deleted"
    );
}

// ---------------------------------------------------------------------------
// Test: remove works for any provider type (not just MCP)
// ---------------------------------------------------------------------------

#[test]
fn test_provider_remove_works_for_any_type() {
    let dir = create_ati_dir();

    // Write a non-MCP (HTTP) manifest
    let http_manifest = r#"
[provider]
name = "example"
description = "Example API"
base_url = "https://api.example.com"
auth_type = "none"

[[tools]]
name = "search"
description = "Search"
endpoint = "/search"
method = "GET"
"#;
    std::fs::write(dir.path().join("manifests/example.toml"), http_manifest).unwrap();

    assert!(dir.path().join("manifests/example.toml").exists());

    let output = Command::new(ati_bin())
        .args(["provider", "remove", "example"])
        .env("ATI_DIR", dir.path().to_str().unwrap())
        .output()
        .expect("remove example");

    assert!(
        output.status.success(),
        "Should succeed for any provider type. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // File should be deleted
    assert!(
        !dir.path().join("manifests/example.toml").exists(),
        "Manifest should be deleted"
    );
}

// ---------------------------------------------------------------------------
// Test: add requires --url for http transport
// ---------------------------------------------------------------------------

#[test]
fn test_mcp_add_requires_url_for_http() {
    let dir = create_ati_dir();

    let output = Command::new(ati_bin())
        .args(["provider", "add-mcp", "broken", "--transport", "http"])
        .env("ATI_DIR", dir.path().to_str().unwrap())
        .output()
        .expect("Failed to execute ati");

    assert!(
        !output.status.success(),
        "Should fail without --url for http"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--url"),
        "Error should mention --url. stderr: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Test: add requires --command for stdio transport
// ---------------------------------------------------------------------------

#[test]
fn test_mcp_add_requires_command_for_stdio() {
    let dir = create_ati_dir();

    let output = Command::new(ati_bin())
        .args(["provider", "add-mcp", "broken", "--transport", "stdio"])
        .env("ATI_DIR", dir.path().to_str().unwrap())
        .output()
        .expect("Failed to execute ati");

    assert!(
        !output.status.success(),
        "Should fail without --command for stdio"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--command"),
        "Error should mention --command. stderr: {stderr}"
    );
}
