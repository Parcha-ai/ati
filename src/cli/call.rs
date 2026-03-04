use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

use super::common;
use crate::core::jwt;
use crate::core::keyring::Keyring;
use crate::core::manifest::ManifestRegistry;
use crate::core::mcp_client;
use crate::core::scope::ScopeConfig;
use crate::output;
use crate::providers::generic;
use crate::proxy::client as proxy_client;
use crate::Cli;

/// Parse CLI args like --key value --flag into a HashMap.
fn parse_tool_args(args: &[String]) -> Result<HashMap<String, Value>, Box<dyn std::error::Error>> {
    let mut map = HashMap::new();
    let mut i = 0;

    while i < args.len() {
        let arg = &args[i];
        if arg.starts_with("--") {
            let key = arg.trim_start_matches("--").to_string();
            if key.is_empty() {
                return Err("Empty argument key".into());
            }

            // Check if next arg exists and is a value (not another flag)
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                let val_str = &args[i + 1];
                // Try to parse as JSON value, fall back to string
                let value = serde_json::from_str(val_str)
                    .unwrap_or_else(|_| Value::String(val_str.clone()));
                map.insert(key, value);
                i += 2;
            } else {
                // Flag with no value = true
                map.insert(key, Value::Bool(true));
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    Ok(map)
}

/// Load scopes from ATI_SESSION_TOKEN JWT, or return unrestricted if not set.
fn load_scopes_from_env(verbose: bool) -> ScopeConfig {
    match std::env::var("ATI_SESSION_TOKEN") {
        Ok(token) if !token.is_empty() => {
            // Try to load JWT config for full verification
            match jwt::config_from_env() {
                Ok(Some(config)) => match jwt::validate(&token, &config) {
                    Ok(claims) => {
                        if verbose {
                            eprintln!("JWT validated: sub={} scopes={}", claims.sub, claims.scope);
                        }
                        ScopeConfig::from_jwt(&claims)
                    }
                    Err(e) => {
                        eprintln!("Warning: JWT validation failed: {e}");
                        eprintln!("Falling back to inspect-only mode (scopes extracted but signature not verified)");
                        match jwt::inspect(&token) {
                            Ok(claims) => ScopeConfig::from_jwt(&claims),
                            Err(e2) => {
                                eprintln!("Error: Cannot decode JWT: {e2}");
                                ScopeConfig::unrestricted()
                            }
                        }
                    }
                },
                Ok(None) => {
                    // No JWT config — inspect without verification
                    if verbose {
                        eprintln!("No JWT public key configured — inspecting token without verification");
                    }
                    match jwt::inspect(&token) {
                        Ok(claims) => ScopeConfig::from_jwt(&claims),
                        Err(e) => {
                            eprintln!("Error: Cannot decode JWT: {e}");
                            ScopeConfig::unrestricted()
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Warning: JWT config error: {e}");
                    ScopeConfig::unrestricted()
                }
            }
        }
        _ => {
            if verbose {
                eprintln!("No ATI_SESSION_TOKEN — running in unrestricted mode");
            }
            ScopeConfig::unrestricted()
        }
    }
}

/// Execute: ati run <tool_name> [--arg val]...
///
/// Auto-detects mode:
/// - If ATI_PROXY_URL is set → proxy mode (forwards to external server)
/// - Otherwise → local mode (keyring + direct HTTP)
pub async fn execute(
    cli: &Cli,
    tool_name: &str,
    raw_args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_tool_args(raw_args)?;

    // Auto-detect: proxy mode if ATI_PROXY_URL is set
    if let Ok(proxy_url) = std::env::var("ATI_PROXY_URL") {
        if cli.verbose {
            eprintln!("Mode: proxy (ATI_PROXY_URL={proxy_url})");
        }
        return execute_via_proxy(cli, tool_name, &args, &proxy_url).await;
    }

    // Local mode: keyring + direct HTTP
    if cli.verbose {
        eprintln!("Mode: local (no ATI_PROXY_URL)");
    }
    execute_local(cli, tool_name, &args).await
}

/// Load keyring using cascade: keyring.enc (sealed) → keyring.enc (persistent) → credentials → empty.
pub(crate) fn load_keyring(ati_dir: &Path, verbose: bool) -> Keyring {
    // 1. Try encrypted keyring.enc (sealed one-shot key from /run/ati/.key)
    let keyring_path = ati_dir.join("keyring.enc");
    if keyring_path.exists() {
        if let Ok(kr) = Keyring::load(&keyring_path) {
            if verbose {
                eprintln!("Keyring: keyring.enc (sealed key)");
            }
            return kr;
        }
        // 2. Try persistent key alongside ATI dir
        if let Ok(kr) = Keyring::load_local(&keyring_path, ati_dir) {
            if verbose {
                eprintln!("Keyring: keyring.enc (persistent key)");
            }
            return kr;
        }
    }

    // 3. Try plaintext credentials (local mode)
    let creds_path = ati_dir.join("credentials");
    if creds_path.exists() {
        if let Ok(kr) = Keyring::load_credentials(&creds_path) {
            if verbose {
                eprintln!("Keyring: credentials (plaintext)");
            }
            return kr;
        }
    }

    if verbose {
        eprintln!("No keys found. Run `ati key set <name> <value>`.");
    }
    Keyring::empty()
}

/// Local mode: load manifests, scopes from JWT, keyring, call upstream API directly.
async fn execute_local(
    cli: &Cli,
    tool_name: &str,
    args: &HashMap<String, Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ati_dir = common::ati_dir();

    if cli.verbose {
        eprintln!("Tool: {tool_name}");
        eprintln!("Args: {args:?}");
        eprintln!("ATI dir: {}", ati_dir.display());
    }

    // Load manifests
    let manifests_dir = ati_dir.join("manifests");
    let mut registry = ManifestRegistry::load(&manifests_dir)?;

    // Load keyring using cascade
    let keyring = load_keyring(&ati_dir, cli.verbose);

    // Look up tool — if not found, try MCP discovery
    if registry.get_tool(tool_name).is_none() {
        if let Some(mcp_provider) = registry.find_mcp_provider_for_tool(tool_name) {
            if cli.verbose {
                eprintln!("Tool not in static index, discovering from MCP provider '{}'...", mcp_provider.name);
            }
            let provider_name = mcp_provider.name.clone();
            let client = mcp_client::McpClient::connect(mcp_provider, &keyring).await?;
            let mcp_tools = client.list_tools().await?;
            client.disconnect().await;
            let tools = mcp_tools.into_iter().map(|t| crate::core::manifest::McpToolDef {
                name: t.name,
                description: t.description,
                input_schema: t.input_schema,
            }).collect();
            registry.register_mcp_tools(&provider_name, tools);
        }
    }

    let (provider, tool) = registry.get_tool(tool_name).ok_or_else(|| {
        format!(
            "Unknown tool: '{tool_name}'. Run 'ati tool list' to see available tools."
        )
    })?;

    if cli.verbose {
        eprintln!("Provider: {} ({})", provider.name, provider.base_url);
        eprintln!("Endpoint: {} {}", tool.method, tool.endpoint);
    }

    // Load scopes from JWT
    let scopes = load_scopes_from_env(cli.verbose);

    if let Some(scope) = &tool.scope {
        scopes.check_access(tool_name, scope)?;
    }

    // Execute — dispatch based on handler type
    let result = match provider.handler.as_str() {
        "mcp" => {
            let value = mcp_client::execute(provider, tool_name, args, &keyring).await?;
            output::format_output(&value, &cli.output)
        }
        _ => {
            generic::execute(provider, tool, args, &keyring, &cli.output).await?
        }
    };

    println!("{result}");
    Ok(())
}

/// Proxy mode: forward the call to an external ATI proxy server.
async fn execute_via_proxy(
    cli: &Cli,
    tool_name: &str,
    args: &HashMap<String, Value>,
    proxy_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if cli.verbose {
        eprintln!("Tool: {tool_name}");
        eprintln!("Args: {args:?}");
        eprintln!("Proxy: {proxy_url}");
    }

    let result = proxy_client::call_tool(proxy_url, tool_name, args).await?;

    let formatted = output::format_output(&result, &cli.output);
    println!("{formatted}");
    Ok(())
}

