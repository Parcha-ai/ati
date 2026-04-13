use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

use super::common;
use crate::core::auth_generator::{AuthCache, GenContext};
use crate::core::jwt;
use crate::core::keyring::Keyring;
use crate::core::manifest::ManifestRegistry;
use crate::core::mcp_client;
use crate::output;
use crate::providers::generic;
use crate::proxy::client as proxy_client;
use crate::Cli;

/// Parse CLI args like --key value --flag into a HashMap.
/// Strips known global flags (-J, --json, --verbose, --output) that may be
/// captured by trailing_var_arg.
fn parse_tool_args(args: &[String]) -> Result<HashMap<String, Value>, Box<dyn std::error::Error>> {
    // Filter out global flags that clap's trailing_var_arg swallowed
    let filtered: Vec<&String> = {
        let mut result = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];
            if arg == "-J" || arg == "--json" || arg == "--verbose" {
                i += 1; // skip flag
            } else if arg == "--output" || arg == "--format" {
                i += 2; // skip flag + value
            } else {
                result.push(arg);
                i += 1;
            }
        }
        result
    };

    let mut map = HashMap::new();
    let mut i = 0;

    while i < filtered.len() {
        let arg = &filtered[i];
        if arg.starts_with("--") {
            let key = arg.trim_start_matches("--").to_string();
            if key.is_empty() {
                return Err("Empty argument key".into());
            }

            // Check if next arg exists and is a value (not another flag)
            if i + 1 < filtered.len() && !filtered[i + 1].starts_with("--") {
                let val_str = filtered[i + 1].as_str();
                // Try to parse as JSON value, fall back to string
                let value = serde_json::from_str(val_str)
                    .unwrap_or_else(|_| Value::String(val_str.to_string()));
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

/// Normalize arg keys to match the tool's schema property names.
/// Handles: case mismatch (repo_name → repoName), hyphen/underscore (repo-name → repo_name),
/// and camelCase↔snake_case (repo_name ↔ repoName).
fn normalize_arg_keys(
    args: &HashMap<String, Value>,
    tool: &crate::core::manifest::Tool,
) -> HashMap<String, Value> {
    let schema_keys: Vec<String> = tool
        .input_schema
        .as_ref()
        .and_then(|s| s.get("properties"))
        .and_then(|p| p.as_object())
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default();

    if schema_keys.is_empty() {
        return args.clone();
    }

    let mut normalized = HashMap::new();
    for (key, value) in args {
        // Exact match — use as-is
        if schema_keys.contains(key) {
            normalized.insert(key.clone(), value.clone());
            continue;
        }
        // Normalize: lowercase, strip hyphens and underscores → "reponame" matches both "repo_name" and "repoName"
        let key_flat = key.to_lowercase().replace(['-', '_'], "");
        let mut matched = false;
        for schema_key in &schema_keys {
            let schema_flat = schema_key.to_lowercase().replace(['-', '_'], "");
            if key_flat == schema_flat {
                normalized.insert(schema_key.clone(), value.clone());
                matched = true;
                break;
            }
        }
        if !matched {
            // No match — pass through as-is (server will reject if invalid)
            normalized.insert(key.clone(), value.clone());
        }
    }
    normalized
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
    execute_with_registry(cli, tool_name, raw_args, None).await
}

/// Execute a tool call, optionally reusing a pre-loaded ManifestRegistry.
///
/// When `registry` is `Some`, skips loading manifests from disk (useful for
/// batch execution like `ati plan execute` where the registry is validated once).
pub async fn execute_with_registry(
    cli: &Cli,
    tool_name: &str,
    raw_args: &[String],
    registry: Option<ManifestRegistry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_tool_args(raw_args)?;

    // Note: -J/--json may be swallowed by trailing_var_arg when placed after
    // tool args. This is handled in execute_local's output formatting.

    // Auto-detect: proxy mode if ATI_PROXY_URL is set
    if let Ok(proxy_url) = std::env::var("ATI_PROXY_URL") {
        tracing::debug!(proxy_url = %proxy_url, "mode: proxy");
        return execute_via_proxy(cli, tool_name, &args, raw_args, &proxy_url).await;
    }

    // Local mode: keyring + direct HTTP
    tracing::debug!("mode: local (no ATI_PROXY_URL)");
    execute_local(cli, tool_name, &args, raw_args, registry).await
}

/// Load keyring using cascade: keyring.enc (sealed) → keyring.enc (persistent) → credentials → empty.
pub(crate) fn load_keyring(ati_dir: &Path) -> Keyring {
    // 1. Try encrypted keyring.enc (sealed one-shot key from /run/ati/.key)
    let keyring_path = ati_dir.join("keyring.enc");
    if keyring_path.exists() {
        if let Ok(kr) = Keyring::load(&keyring_path) {
            tracing::debug!("keyring: keyring.enc (sealed key)");
            return kr;
        }
        // 2. Try persistent key alongside ATI dir
        if let Ok(kr) = Keyring::load_local(&keyring_path, ati_dir) {
            tracing::debug!("keyring: keyring.enc (persistent key)");
            return kr;
        }
    }

    // 3. Try plaintext credentials (local mode)
    let creds_path = ati_dir.join("credentials");
    if creds_path.exists() {
        if let Ok(kr) = Keyring::load_credentials(&creds_path) {
            tracing::debug!("keyring: credentials (plaintext)");
            return kr;
        }
    }

    tracing::debug!("no keys found — run `ati key set <name> <value>`");
    Keyring::empty()
}

/// Local mode: load manifests, scopes from JWT, keyring, call upstream API directly.
async fn execute_local(
    cli: &Cli,
    tool_name: &str,
    args: &HashMap<String, Value>,
    raw_args: &[String],
    preloaded_registry: Option<ManifestRegistry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ati_dir = common::ati_dir();

    tracing::debug!(tool = %tool_name, ?args, ati_dir = %ati_dir.display(), "execute local");

    // Load manifests (or reuse pre-loaded registry)
    let manifests_dir = ati_dir.join("manifests");
    let mut registry = match preloaded_registry {
        Some(r) => r,
        None => ManifestRegistry::load(&manifests_dir)?,
    };

    // Load keyring using cascade
    let keyring = load_keyring(&ati_dir);

    // Look up tool — if not found, try MCP discovery
    if registry.get_tool(tool_name).is_none() {
        if let Some(mcp_provider) = registry.find_mcp_provider_for_tool(tool_name) {
            tracing::debug!(provider = %mcp_provider.name, "tool not in static index, discovering from MCP provider");
            let provider_name = mcp_provider.name.clone();
            let client = mcp_client::McpClient::connect(mcp_provider, &keyring).await?;
            let mcp_tools = client.list_tools().await?;
            client.disconnect().await;
            let tools = mcp_tools
                .into_iter()
                .map(|t| crate::core::manifest::McpToolDef {
                    name: t.name,
                    description: t.description,
                    input_schema: t.input_schema,
                })
                .collect();
            registry.register_mcp_tools(&provider_name, tools);
        }
    }

    let (provider, tool) = registry.get_tool(tool_name).ok_or_else(|| {
        // After MCP discovery, the registry has real tool names.
        // If exact match fails, check for prefix matches and suggest.
        let prefix = tool_name.split(crate::core::manifest::TOOL_SEP).next().unwrap_or("");
        let suggestions: Vec<String> = registry
            .list_public_tools()
            .iter()
            .filter(|(p, _)| p.name == prefix)
            .map(|(_, t)| t.name.clone())
            .collect();
        if suggestions.is_empty() {
            format!("Unknown tool: '{tool_name}'. Run 'ati tool list' to see available tools.")
        } else {
            format!(
                "Unknown tool: '{tool_name}'. Did you mean one of:\n{}\nRun 'ati tool info <name>' to see parameters.",
                suggestions.iter().map(|s| format!("  - {s}")).collect::<Vec<_>>().join("\n")
            )
        }
    })?;

    tracing::debug!(
        provider = %provider.name,
        base_url = %provider.base_url,
        method = %tool.method,
        endpoint = %tool.endpoint,
        "dispatching tool call"
    );

    // Normalize arg keys to match schema property names (case-insensitive, underscore/hyphen)
    let args = normalize_arg_keys(args, tool);

    // Load scopes from JWT
    let scopes = common::load_local_scopes_from_env()?;

    if let Some(scope) = &tool.scope {
        scopes.check_access(tool_name, scope)?;
    }

    // Rate limit check
    if let Some(ref rate_config) = scopes.rate_config {
        crate::core::rate::check_and_record(tool_name, rate_config)?;
    }

    // Build auth generator context from scope/JWT claims
    let gen_ctx = GenContext {
        jwt_sub: scopes.sub.clone(),
        jwt_scope: scopes.scopes.join(" "),
        tool_name: tool_name.to_string(),
        timestamp: crate::core::jwt::now_secs(),
    };
    let auth_cache = AuthCache::new();

    // Handle -J/--json that trailing_var_arg may have swallowed
    let effective_output = if raw_args.iter().any(|a| a == "-J" || a == "--json") {
        crate::OutputFormat::Json
    } else {
        cli.output.clone()
    };

    // Execute — dispatch based on handler type, with timing for audit
    let start = std::time::Instant::now();
    let exec_result: Result<String, Box<dyn std::error::Error>> = match provider.handler.as_str() {
        "mcp" => {
            match mcp_client::execute_with_gen(
                provider,
                tool_name,
                &args,
                &keyring,
                Some(&gen_ctx),
                Some(&auth_cache),
            )
            .await
            {
                Ok(value) => Ok(output::format_output(&value, &effective_output)),
                Err(e) => Err(e.into()),
            }
        }
        "cli" => {
            match crate::core::cli_executor::execute_with_gen(
                provider,
                raw_args,
                &keyring,
                Some(&gen_ctx),
                Some(&auth_cache),
            )
            .await
            {
                Ok(value) => Ok(output::format_output(&value, &effective_output)),
                Err(e) => Err(e.into()),
            }
        }
        _ => {
            generic::execute_with_gen(
                provider,
                tool,
                &args,
                &keyring,
                &effective_output,
                Some(&gen_ctx),
                Some(&auth_cache),
            )
            .await
        }
    };
    let duration = start.elapsed();

    // Build and write audit entry
    let (status, error_msg) = match &exec_result {
        Ok(_) => (crate::core::audit::AuditStatus::Ok, None),
        Err(e) => (crate::core::audit::AuditStatus::Error, Some(e.to_string())),
    };
    let audit_entry = crate::core::audit::AuditEntry {
        ts: chrono::Utc::now().to_rfc3339(),
        tool: tool_name.to_string(),
        args: crate::core::audit::sanitize_args(&serde_json::json!(args)),
        status,
        duration_ms: duration.as_millis() as u64,
        agent_sub: scopes.sub.clone(),
        job_id: None,
        sandbox_id: None,
        error: error_msg,
        exit_code: None,
    };
    if let Err(e) = crate::core::audit::append(&audit_entry) {
        tracing::warn!(error = %e, "failed to write audit log");
    }

    let result = exec_result?;
    println!("{result}");
    Ok(())
}

/// Proxy mode: forward the call to an external ATI proxy server.
/// The `-J` flag may have been swallowed by trailing_var_arg — handle it here too.
async fn execute_via_proxy(
    cli: &Cli,
    tool_name: &str,
    args: &HashMap<String, Value>,
    raw_args: &[String],
    proxy_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::debug!(tool = %tool_name, ?args, proxy_url = %proxy_url, "execute via proxy");

    let scopes = match std::env::var("ATI_SESSION_TOKEN") {
        Ok(token) if !token.is_empty() => match jwt::inspect(&token) {
            Ok(claims) => crate::core::scope::ScopeConfig::from_jwt(&claims),
            Err(_) => crate::core::scope::ScopeConfig::unrestricted(),
        },
        _ => crate::core::scope::ScopeConfig::unrestricted(),
    };
    let start = std::time::Instant::now();
    // Always send both the parsed args map AND the raw positional args.
    // - HTTP/MCP/OpenAPI tools: proxy uses args_as_map() → reads the map
    // - CLI tools: proxy uses args_as_positional() → reads raw_args first
    //
    // Without raw_args, CLI positional args like `ati run bb browse status`
    // lose "browse" and "status" because parse_tool_args only captures
    // --key value pairs into the map, dropping bare positional words.
    let exec_result = proxy_client::call_tool(proxy_url, tool_name, args, Some(raw_args)).await;
    let duration = start.elapsed();

    let (status, error_msg) = match &exec_result {
        Ok(_) => (crate::core::audit::AuditStatus::Ok, None),
        Err(e) => (crate::core::audit::AuditStatus::Error, Some(e.to_string())),
    };
    let audit_entry = crate::core::audit::AuditEntry {
        ts: chrono::Utc::now().to_rfc3339(),
        tool: tool_name.to_string(),
        args: crate::core::audit::sanitize_args(&serde_json::json!(args)),
        status,
        duration_ms: duration.as_millis() as u64,
        agent_sub: scopes.sub.clone(),
        job_id: None,
        sandbox_id: None,
        error: error_msg,
        exit_code: None,
    };
    if let Err(e) = crate::core::audit::append(&audit_entry) {
        tracing::warn!(error = %e, "failed to write audit log");
    }

    let result = exec_result?;
    // Handle -J/--json swallowed by trailing_var_arg
    let effective_output = if raw_args.iter().any(|a| a == "-J" || a == "--json") {
        crate::OutputFormat::Json
    } else {
        cli.output.clone()
    };
    let formatted = output::format_output(&result, &effective_output);
    println!("{formatted}");
    Ok(())
}
