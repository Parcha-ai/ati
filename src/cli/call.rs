use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::core::keyring::Keyring;
use crate::core::manifest::ManifestRegistry;
use crate::core::mcp_client;
use crate::core::scope::ScopeConfig;
use crate::output;
use crate::providers::generic;
use crate::proxy::client as proxy_client;
use crate::Cli;

/// Default paths for ATI config
fn ati_dir() -> PathBuf {
    dirs_path().unwrap_or_else(|| PathBuf::from(".ati"))
}

fn dirs_path() -> Option<PathBuf> {
    std::env::var("ATI_DIR").ok().map(PathBuf::from).or_else(|| {
        dirs::home_dir().map(|h| h.join(".ati"))
    })
}

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
            // Skip non-flag args (shouldn't happen with our clap config)
            i += 1;
        }
    }

    Ok(map)
}

/// Execute: ati call <tool_name> [--arg val]...
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

/// Local mode: load manifests, scopes, keyring, call upstream API directly.
async fn execute_local(
    cli: &Cli,
    tool_name: &str,
    args: &HashMap<String, Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ati_dir = ati_dir();

    if cli.verbose {
        eprintln!("Tool: {tool_name}");
        eprintln!("Args: {args:?}");
        eprintln!("ATI dir: {}", ati_dir.display());
    }

    // Load manifests
    let manifests_dir = ati_dir.join("manifests");
    let registry = ManifestRegistry::load(&manifests_dir)?;

    // Look up tool
    let (provider, tool) = registry.get_tool(tool_name).ok_or_else(|| {
        format!(
            "Unknown tool: '{tool_name}'. Run 'ati tools list' to see available tools."
        )
    })?;

    if cli.verbose {
        eprintln!("Provider: {} ({})", provider.name, provider.base_url);
        eprintln!("Endpoint: {} {}", tool.method, tool.endpoint);
    }

    // Load and check scopes
    let scopes_path = ati_dir.join("scopes.json");
    let scopes = if scopes_path.exists() {
        ScopeConfig::load(&scopes_path)?
    } else {
        if cli.verbose {
            eprintln!("No scopes.json found — running in unrestricted mode");
        }
        ScopeConfig::unrestricted()
    };

    if let Some(scope) = &tool.scope {
        scopes.check_access(tool_name, scope)?;
    }

    // Load keyring
    let keyring_path = ati_dir.join("keyring.enc");
    let keyring = if keyring_path.exists() {
        Keyring::load(&keyring_path)?
    } else {
        if cli.verbose {
            eprintln!("No keyring.enc found — running without API keys");
        }
        Keyring::empty()
    };

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

    // Format using the requested output format
    let formatted = output::format_output(&result, &cli.output);
    println!("{formatted}");
    Ok(())
}

// We need `dirs` for home_dir — add a minimal fallback
mod dirs {
    use std::path::PathBuf;

    pub fn home_dir() -> Option<PathBuf> {
        std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .ok()
            .map(PathBuf::from)
    }
}
