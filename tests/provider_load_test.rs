/// Integration tests for `ati provider load` and `ati provider unload`.
use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

fn ati_cmd() -> Command {
    let mut cmd = Command::cargo_bin("ati").unwrap();
    cmd.env("RUST_LOG", "");
    cmd
}

/// Minimal OpenAPI 3.0 spec with no auth — should result in status: "ready".
const PETSTORE_SPEC: &str = r#"{
    "openapi": "3.0.3",
    "info": { "title": "Petstore", "version": "1.0.0" },
    "servers": [{ "url": "https://petstore.example.com/v3" }],
    "paths": {
        "/pet/{petId}": {
            "get": {
                "operationId": "getPetById",
                "summary": "Find pet by ID",
                "tags": ["pet"],
                "parameters": [
                    {
                        "name": "petId",
                        "in": "path",
                        "required": true,
                        "schema": { "type": "integer" }
                    }
                ],
                "responses": { "200": { "description": "OK" } }
            }
        },
        "/pet": {
            "get": {
                "operationId": "listPets",
                "summary": "List all pets",
                "tags": ["pet"],
                "parameters": [
                    { "name": "limit", "in": "query", "schema": { "type": "integer" } }
                ],
                "responses": { "200": { "description": "OK" } }
            }
        }
    }
}"#;

/// OpenAPI spec with bearer auth — should result in status: "needs_auth".
const AUTH_SPEC: &str = r#"{
    "openapi": "3.0.3",
    "info": { "title": "Secure API", "version": "1.0.0" },
    "servers": [{ "url": "https://api.example.com/v1" }],
    "paths": {
        "/search": {
            "get": {
                "operationId": "search",
                "summary": "Search items",
                "responses": { "200": { "description": "OK" } }
            }
        }
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer"
            }
        }
    }
}"#;

/// OpenAPI spec with API key header auth.
const HEADER_AUTH_SPEC: &str = r#"{
    "openapi": "3.0.3",
    "info": { "title": "Header Auth API", "version": "1.0.0" },
    "servers": [{ "url": "https://api.example.com/v1" }],
    "paths": {
        "/data": {
            "get": {
                "operationId": "getData",
                "summary": "Get data",
                "responses": { "200": { "description": "OK" } }
            }
        }
    },
    "components": {
        "securitySchemes": {
            "apiKey": {
                "type": "apiKey",
                "in": "header",
                "name": "X-Custom-Key"
            }
        }
    }
}"#;

// ─── OpenAPI load tests ──────────────────────────────────────────────────────

#[test]
fn test_load_openapi_no_auth_json() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    // Write spec to a temp file
    let spec_path = dir.path().join("petstore.json");
    std::fs::write(&spec_path, PETSTORE_SPEC).unwrap();

    let output = ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args([
            "provider",
            "load",
            spec_path.to_str().unwrap(),
            "--name",
            "petstore",
            "-J",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "ready");
    assert_eq!(result["name"], "petstore");
    assert_eq!(result["provider_type"], "openapi");
    assert_eq!(result["base_url"], "https://petstore.example.com/v3");
    assert_eq!(result["tools_count"], 2);
    assert_eq!(result["auth"]["type"], "none");
    assert!(result["setup_commands"].as_array().unwrap().is_empty());
    assert!(result["cached_until"].is_string());

    // Verify cache file was created
    let cache_path = ati_dir
        .join("cache")
        .join("providers")
        .join("petstore.json");
    assert!(cache_path.exists(), "Cache file should exist");
}

#[test]
fn test_load_openapi_needs_auth_json() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    let spec_path = dir.path().join("secure.json");
    std::fs::write(&spec_path, AUTH_SPEC).unwrap();

    let output = ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args([
            "provider",
            "load",
            spec_path.to_str().unwrap(),
            "--name",
            "example",
            "-J",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "needs_auth");
    assert_eq!(result["name"], "example");
    assert_eq!(result["auth"]["type"], "bearer");
    assert_eq!(result["auth"]["key_name"], "example_api_key");
    assert_eq!(result["auth"]["resolved"], false);
    assert_eq!(result["tools_count"], 1);

    let commands = result["setup_commands"].as_array().unwrap();
    assert_eq!(commands.len(), 1);
    assert!(commands[0]
        .as_str()
        .unwrap()
        .contains("ati key set example_api_key"));
}

#[test]
fn test_load_openapi_header_auth_json() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    let spec_path = dir.path().join("header_auth.json");
    std::fs::write(&spec_path, HEADER_AUTH_SPEC).unwrap();

    let output = ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args([
            "provider",
            "load",
            spec_path.to_str().unwrap(),
            "--name",
            "headerapi",
            "-J",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "needs_auth");
    assert_eq!(result["auth"]["type"], "header");
    assert_eq!(result["auth"]["header_name"], "X-Custom-Key");
}

#[test]
fn test_load_openapi_custom_auth_key() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    let spec_path = dir.path().join("secure.json");
    std::fs::write(&spec_path, AUTH_SPEC).unwrap();

    let output = ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args([
            "provider",
            "load",
            spec_path.to_str().unwrap(),
            "--name",
            "example",
            "--auth-key",
            "my_custom_key",
            "-J",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());

    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["auth"]["key_name"], "my_custom_key");
    assert!(result["setup_commands"][0]
        .as_str()
        .unwrap()
        .contains("my_custom_key"));
}

#[test]
fn test_load_openapi_text_output() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    let spec_path = dir.path().join("petstore.json");
    std::fs::write(&spec_path, PETSTORE_SPEC).unwrap();

    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args([
            "provider",
            "load",
            spec_path.to_str().unwrap(),
            "--name",
            "petstore",
        ])
        .assert()
        .success()
        .stderr(predicates::str::contains("Loaded petstore"))
        .stderr(predicates::str::contains("2 tools"))
        .stderr(predicates::str::contains("ready"));
}

// ─── MCP load tests ─────────────────────────────────────────────────────────

#[test]
fn test_load_mcp_http_json() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    let output = ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args([
            "provider",
            "load",
            "--mcp",
            "--transport",
            "http",
            "--url",
            "https://mcp.example.com/mcp",
            "--name",
            "testmcp",
            "-J",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "ready");
    assert_eq!(result["name"], "testmcp");
    assert_eq!(result["provider_type"], "mcp");
    assert_eq!(result["transport"], "http");
    assert_eq!(result["url"], "https://mcp.example.com/mcp");

    // Verify cache file
    let cache_path = ati_dir.join("cache").join("providers").join("testmcp.json");
    assert!(cache_path.exists());
}

#[test]
fn test_load_mcp_stdio_json() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    let output = ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args([
            "provider",
            "load",
            "--mcp",
            "--transport",
            "stdio",
            "--command",
            "npx",
            "--args",
            "-y",
            "--args",
            "@modelcontextprotocol/server-github",
            "--name",
            "github",
            "-J",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "ready");
    assert_eq!(result["name"], "github");
    assert_eq!(result["transport"], "stdio");
    assert_eq!(result["command"], "npx");
}

#[test]
fn test_load_mcp_with_env_keyring_ref() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    let output = ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args([
            "provider",
            "load",
            "--mcp",
            "--transport",
            "stdio",
            "--command",
            "npx",
            "--args",
            "-y",
            "--args",
            "@modelcontextprotocol/server-github",
            "--name",
            "github",
            "--env",
            "GITHUB_PERSONAL_ACCESS_TOKEN=${github_token}",
            "-J",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "needs_keys");
    assert_eq!(
        result["env_vars"]["GITHUB_PERSONAL_ACCESS_TOKEN"]["keyring_ref"],
        "github_token"
    );
    assert_eq!(
        result["env_vars"]["GITHUB_PERSONAL_ACCESS_TOKEN"]["resolved"],
        false
    );

    let commands = result["setup_commands"].as_array().unwrap();
    assert!(!commands.is_empty());
    assert!(commands
        .iter()
        .any(|c| c.as_str().unwrap().contains("github_token")));
}

#[test]
fn test_load_mcp_http_requires_url() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args([
            "provider",
            "load",
            "--mcp",
            "--transport",
            "http",
            "--name",
            "bad",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("--url is required"));
}

#[test]
fn test_load_mcp_stdio_requires_command() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args([
            "provider",
            "load",
            "--mcp",
            "--transport",
            "stdio",
            "--name",
            "bad",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("--command is required"));
}

// ─── Unload tests ────────────────────────────────────────────────────────────

#[test]
fn test_unload_removes_cache() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    // First load
    let spec_path = dir.path().join("petstore.json");
    std::fs::write(&spec_path, PETSTORE_SPEC).unwrap();

    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args([
            "provider",
            "load",
            spec_path.to_str().unwrap(),
            "--name",
            "petstore",
        ])
        .assert()
        .success();

    let cache_path = ati_dir
        .join("cache")
        .join("providers")
        .join("petstore.json");
    assert!(cache_path.exists());

    // Then unload
    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["provider", "unload", "petstore"])
        .assert()
        .success()
        .stderr(predicates::str::contains("Unloaded"));

    assert!(!cache_path.exists());
}

#[test]
fn test_unload_nonexistent_fails() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["provider", "unload", "doesntexist"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("No cached provider"));
}

// ─── Cache loading into registry ─────────────────────────────────────────────

#[test]
fn test_cached_provider_visible_in_tool_list() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    // Load a provider
    let spec_path = dir.path().join("petstore.json");
    std::fs::write(&spec_path, PETSTORE_SPEC).unwrap();

    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args([
            "provider",
            "load",
            spec_path.to_str().unwrap(),
            "--name",
            "petstore",
        ])
        .assert()
        .success();

    // Now list tools — should see petstore tools
    let output = ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["tool", "list", "--provider", "petstore"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("petstore__getPetById") || stdout.contains("getPetById"),
        "Tool list should contain petstore tools: {}",
        stdout
    );
}

#[test]
fn test_cached_provider_visible_in_provider_list() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    let spec_path = dir.path().join("petstore.json");
    std::fs::write(&spec_path, PETSTORE_SPEC).unwrap();

    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args([
            "provider",
            "load",
            spec_path.to_str().unwrap(),
            "--name",
            "petstore",
        ])
        .assert()
        .success();

    // Provider list should show it
    let output = ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["provider", "list"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("petstore"),
        "Provider list should contain petstore: {}",
        stdout
    );
}

#[test]
fn test_cached_mcp_provider_visible_in_provider_list() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args([
            "provider",
            "load",
            "--mcp",
            "--transport",
            "http",
            "--url",
            "https://mcp.example.com/mcp",
            "--name",
            "testmcp",
        ])
        .assert()
        .success();

    let output = ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["provider", "list"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("testmcp"),
        "Provider list should contain testmcp: {}",
        stdout
    );
}

// ─── CachedProvider struct tests ─────────────────────────────────────────────

#[test]
fn test_cached_provider_serialization_roundtrip() {
    use ati::core::manifest::CachedProvider;
    use std::collections::HashMap;

    let cached = CachedProvider {
        name: "test".to_string(),
        provider_type: "openapi".to_string(),
        base_url: "https://api.example.com".to_string(),
        auth_type: "bearer".to_string(),
        auth_key_name: Some("test_api_key".to_string()),
        auth_header_name: None,
        auth_query_name: None,
        spec_content: Some("{}".to_string()),
        mcp_transport: None,
        mcp_url: None,
        mcp_command: None,
        mcp_args: vec![],
        mcp_env: HashMap::new(),
        cli_command: None,
        cli_default_args: Vec::new(),
        cli_env: HashMap::new(),
        cli_timeout_secs: None,
        auth: None,
        created_at: "2026-03-04T12:00:00Z".to_string(),
        ttl_seconds: 3600,
    };

    let json = serde_json::to_string(&cached).unwrap();
    let deserialized: CachedProvider = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.name, "test");
    assert_eq!(deserialized.auth_type, "bearer");
    assert_eq!(deserialized.auth_key_name.as_deref(), Some("test_api_key"));
    assert_eq!(deserialized.ttl_seconds, 3600);
}

#[test]
fn test_cached_provider_expiry() {
    use ati::core::manifest::CachedProvider;
    use std::collections::HashMap;

    // Create a provider that expired 1 hour ago
    let expired = CachedProvider {
        name: "old".to_string(),
        provider_type: "openapi".to_string(),
        base_url: "https://api.example.com".to_string(),
        auth_type: "none".to_string(),
        auth_key_name: None,
        auth_header_name: None,
        auth_query_name: None,
        spec_content: None,
        mcp_transport: None,
        mcp_url: None,
        mcp_command: None,
        mcp_args: vec![],
        mcp_env: HashMap::new(),
        cli_command: None,
        cli_default_args: Vec::new(),
        cli_env: HashMap::new(),
        cli_timeout_secs: None,
        auth: None,
        created_at: "2020-01-01T00:00:00Z".to_string(),
        ttl_seconds: 3600,
    };

    assert!(expired.is_expired());
    assert_eq!(expired.remaining_seconds(), 0);

    // Create a provider that expires in the far future
    let fresh = CachedProvider {
        name: "fresh".to_string(),
        provider_type: "openapi".to_string(),
        base_url: "https://api.example.com".to_string(),
        auth_type: "none".to_string(),
        auth_key_name: None,
        auth_header_name: None,
        auth_query_name: None,
        spec_content: None,
        mcp_transport: None,
        mcp_url: None,
        mcp_command: None,
        mcp_args: vec![],
        mcp_env: HashMap::new(),
        cli_command: None,
        cli_default_args: Vec::new(),
        cli_env: HashMap::new(),
        cli_timeout_secs: None,
        auth: None,
        created_at: chrono::Utc::now().to_rfc3339(),
        ttl_seconds: 999999,
    };

    assert!(!fresh.is_expired());
    assert!(fresh.remaining_seconds() > 0);
    assert!(fresh.expires_at().is_some());
}

#[test]
fn test_cached_provider_to_provider() {
    use ati::core::manifest::CachedProvider;
    use std::collections::HashMap;

    let cached = CachedProvider {
        name: "myapi".to_string(),
        provider_type: "openapi".to_string(),
        base_url: "https://api.example.com/v1".to_string(),
        auth_type: "bearer".to_string(),
        auth_key_name: Some("myapi_api_key".to_string()),
        auth_header_name: None,
        auth_query_name: None,
        spec_content: None,
        mcp_transport: None,
        mcp_url: None,
        mcp_command: None,
        mcp_args: vec![],
        mcp_env: HashMap::new(),
        cli_command: None,
        cli_default_args: Vec::new(),
        cli_env: HashMap::new(),
        cli_timeout_secs: None,
        auth: None,
        created_at: chrono::Utc::now().to_rfc3339(),
        ttl_seconds: 3600,
    };

    let provider = cached.to_provider();
    assert_eq!(provider.name, "myapi");
    assert_eq!(provider.base_url, "https://api.example.com/v1");
    assert!(provider.is_openapi());
    assert_eq!(provider.auth_key_name.as_deref(), Some("myapi_api_key"));
}

// ─── Expired cache cleanup test ──────────────────────────────────────────────

#[test]
fn test_expired_cache_cleaned_up_on_load() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    // Manually create an expired cache entry
    let cache_dir = ati_dir.join("cache").join("providers");
    std::fs::create_dir_all(&cache_dir).unwrap();

    let expired_json = serde_json::json!({
        "name": "expired_provider",
        "provider_type": "openapi",
        "base_url": "https://api.example.com",
        "auth_type": "none",
        "spec_content": "{}",
        "created_at": "2020-01-01T00:00:00Z",
        "ttl_seconds": 3600,
        "mcp_args": [],
        "mcp_env": {}
    });

    let expired_path = cache_dir.join("expired_provider.json");
    std::fs::write(
        &expired_path,
        serde_json::to_string_pretty(&expired_json).unwrap(),
    )
    .unwrap();
    assert!(expired_path.exists());

    // Running any command that loads the registry should clean up expired entries
    // Use tool list which triggers ManifestRegistry::load
    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["tool", "list"])
        .output()
        .unwrap();

    // Expired file should be deleted
    assert!(
        !expired_path.exists(),
        "Expired cache file should be cleaned up"
    );
}

// ─── TTL override test ──────────────────────────────────────────────────────

#[test]
fn test_load_with_custom_ttl() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    let spec_path = dir.path().join("petstore.json");
    std::fs::write(&spec_path, PETSTORE_SPEC).unwrap();

    let output = ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args([
            "provider",
            "load",
            spec_path.to_str().unwrap(),
            "--name",
            "petstore",
            "--ttl",
            "7200",
            "-J",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());

    // Check the cache file has the right TTL
    let cache_path = ati_dir
        .join("cache")
        .join("providers")
        .join("petstore.json");
    let cache_content = std::fs::read_to_string(&cache_path).unwrap();
    let cached: Value = serde_json::from_str(&cache_content).unwrap();
    assert_eq!(cached["ttl_seconds"], 7200);
}

// ─── Load without spec errors ────────────────────────────────────────────────

#[test]
fn test_load_openapi_without_spec_fails() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["provider", "load", "--name", "nospec"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("requires a spec"));
}

// ─── --auth-header and --auth-query tests ────────────────────────────────────

#[test]
fn test_load_mcp_with_auth_header_json() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    let output = ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args([
            "provider",
            "load",
            "--mcp",
            "--transport",
            "http",
            "--url",
            "https://mcp.example.com/mcp",
            "--name",
            "custom_header",
            "--auth",
            "header",
            "--auth-key",
            "custom_api_key",
            "--auth-header",
            "x-api-key",
            "-J",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the cache file has auth_header_name set
    let cache_path = ati_dir
        .join("cache")
        .join("providers")
        .join("custom_header.json");
    let cache_content = std::fs::read_to_string(&cache_path).unwrap();
    let cached: Value = serde_json::from_str(&cache_content).unwrap();
    assert_eq!(cached["auth_header_name"], "x-api-key");
}

#[test]
fn test_load_mcp_with_auth_query_json() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    let output = ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args([
            "provider",
            "load",
            "--mcp",
            "--transport",
            "http",
            "--url",
            "https://mcp.example.com/mcp",
            "--name",
            "custom_query",
            "--auth",
            "query",
            "--auth-key",
            "custom_api_key",
            "--auth-query",
            "api_token",
            "-J",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the cache file has auth_query_name set
    let cache_path = ati_dir
        .join("cache")
        .join("providers")
        .join("custom_query.json");
    let cache_content = std::fs::read_to_string(&cache_path).unwrap();
    let cached: Value = serde_json::from_str(&cache_content).unwrap();
    assert_eq!(cached["auth_query_name"], "api_token");
}

#[test]
fn test_load_openapi_with_auth_header_override() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    let spec_path = dir.path().join("secure.json");
    std::fs::write(&spec_path, AUTH_SPEC).unwrap();

    let output = ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args([
            "provider",
            "load",
            spec_path.to_str().unwrap(),
            "--name",
            "overridden",
            "--auth",
            "header",
            "--auth-header",
            "X-Custom-Override",
            "-J",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the cache file has the overridden auth_header_name
    let cache_path = ati_dir
        .join("cache")
        .join("providers")
        .join("overridden.json");
    let cache_content = std::fs::read_to_string(&cache_path).unwrap();
    let cached: Value = serde_json::from_str(&cache_content).unwrap();
    assert_eq!(cached["auth_header_name"], "X-Custom-Override");
}

// ─── MCP probe tests ────────────────────────────────────────────────────────

#[test]
fn test_load_mcp_probe_failure_still_caches() {
    // Loading an MCP provider with an unreachable URL should still cache the provider
    // but report a probe failure in the JSON output.
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    let output = ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args([
            "provider",
            "load",
            "--mcp",
            "--transport",
            "http",
            "--url",
            "https://unreachable.invalid/mcp",
            "--name",
            "probefail",
            "-J",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["name"], "probefail");
    // Probe should have failed (unreachable host)
    assert_eq!(result["probe"], "failed");
    assert!(result["probe_error"].is_string());

    // Cache file should still exist
    let cache_path = ati_dir
        .join("cache")
        .join("providers")
        .join("probefail.json");
    assert!(
        cache_path.exists(),
        "Cache file should exist even when probe fails"
    );
}

#[test]
fn test_load_mcp_probe_failure_text_output() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(ati_dir.join("manifests")).unwrap();

    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args([
            "provider",
            "load",
            "--mcp",
            "--transport",
            "http",
            "--url",
            "https://unreachable.invalid/mcp",
            "--name",
            "probefail_text",
        ])
        .assert()
        .success()
        .stderr(predicates::str::contains("probe failed"));
}
