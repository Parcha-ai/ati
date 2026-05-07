//! Live tests for the Particle MCP OAuth flow.
//!
//! These tests are **gated** on the env var `ATI_OAUTH_PARTICLE_TEST=1`. They
//! make real HTTP calls to https://mcp.particle.pro and require a valid
//! `~/.ati/oauth/particle.json` (run `ati provider authorize particle`
//! beforehand).
//!
//! We use the SKIP-on-missing-env-var pattern (rather than `#[ignore]`) so
//! `cargo test --no-run` doesn't choke when the file is compiled but the
//! tests are skipped.

use std::collections::HashMap;
use std::time::Duration;

use ati::core::keyring::Keyring;
use ati::core::manifest::{AuthType, Provider};
use ati::core::mcp_client::McpClient;

fn enabled() -> bool {
    std::env::var("ATI_OAUTH_PARTICLE_TEST")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn particle_provider() -> Provider {
    Provider {
        name: "particle".to_string(),
        description: "Particle".into(),
        base_url: String::new(),
        auth_type: AuthType::Oauth2Pkce,
        auth_key_name: None,
        auth_header_name: None,
        auth_query_name: None,
        auth_value_prefix: None,
        extra_headers: HashMap::new(),
        oauth2_token_url: None,
        auth_secret_name: None,
        oauth2_basic_auth: false,
        oauth_resource: Some("https://mcp.particle.pro".into()),
        oauth_scopes: vec!["mcp:read".into()],
        internal: false,
        handler: "mcp".into(),
        mcp_transport: Some("http".into()),
        mcp_command: None,
        mcp_args: vec![],
        mcp_url: Some("https://mcp.particle.pro".into()),
        mcp_env: HashMap::new(),
        cli_command: None,
        cli_default_args: vec![],
        cli_env: HashMap::new(),
        cli_timeout_secs: None,
        cli_output_args: vec![],
        cli_output_positional: HashMap::new(),
        upload_destinations: HashMap::new(),
        upload_default_destination: None,
        openapi_spec: None,
        openapi_include_tags: vec![],
        openapi_exclude_tags: vec![],
        openapi_include_operations: vec![],
        openapi_exclude_operations: vec![],
        openapi_max_operations: None,
        openapi_overrides: HashMap::new(),
        auth_generator: None,
        category: None,
        skills: vec![],
    }
}

#[tokio::test]
async fn live_tools_list_returns_at_least_one() {
    if !enabled() {
        eprintln!("SKIP: ATI_OAUTH_PARTICLE_TEST not set");
        return;
    }
    let provider = particle_provider();
    let keyring = Keyring::empty();
    let client = tokio::time::timeout(
        Duration::from_secs(30),
        McpClient::connect(&provider, &keyring),
    )
    .await
    .expect("connect timeout")
    .expect("connect failed (run `ati provider authorize particle` first)");
    let tools = client.list_tools().await.expect("tools/list failed");
    assert!(
        !tools.is_empty(),
        "expected ≥1 tool from Particle MCP, got 0"
    );
    eprintln!("Particle exposes {} tools", tools.len());
    for t in &tools {
        eprintln!("  - {}", t.name);
    }
    client.disconnect().await;
}
