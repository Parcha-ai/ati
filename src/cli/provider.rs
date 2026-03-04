/// CLI commands for unified provider management.
///
/// `ati provider add-mcp <name>` — generate a TOML manifest for an MCP provider
/// `ati provider import-openapi <spec>` — download spec and generate TOML manifest
/// `ati provider inspect-openapi <spec>` — preview operations in a spec
/// `ati provider list` — list all configured providers
/// `ati provider remove <name>` — remove a provider manifest
/// `ati provider info <name>` — show provider details

use super::common;
use crate::cli::call::load_keyring;
use crate::core::keyring::Keyring;
use crate::core::manifest::{CachedProvider, ManifestRegistry};
use crate::core::mcp_client::McpClient;
use crate::core::openapi::{self, OpenApiFilters};
use crate::output;
use crate::{Cli, OutputFormat, ProviderCommands};
use chrono::Utc;
use std::collections::HashMap;

pub async fn execute(
    cli: &Cli,
    subcmd: &ProviderCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match subcmd {
        ProviderCommands::AddMcp {
            name,
            transport,
            url,
            command,
            args,
            env,
            auth,
            auth_key,
            auth_header,
            description,
            category,
        } => add_mcp(
            name,
            transport,
            url.as_deref(),
            command.as_deref(),
            args,
            env,
            auth.as_deref().unwrap_or("none"),
            auth_key.as_deref(),
            auth_header.as_deref(),
            description.as_deref(),
            category.as_deref(),
        ),
        ProviderCommands::AddCli {
            name,
            command,
            default_args,
            env,
            description,
            category,
            timeout,
        } => add_cli(
            name,
            command,
            default_args,
            env,
            description.as_deref(),
            category.as_deref(),
            *timeout,
        ),
        ProviderCommands::ImportOpenapi {
            spec,
            name,
            auth_key,
            include_tags,
            dry_run,
        } => {
            let resolved_name = match name {
                Some(n) => n.clone(),
                None => derive_provider_name(spec),
            };
            import_openapi(spec, &resolved_name, auth_key.as_deref(), include_tags, *dry_run)
        }
        ProviderCommands::InspectOpenapi { spec, include_tags } => {
            inspect_openapi(spec, include_tags)
        }
        ProviderCommands::List => list_providers(cli),
        ProviderCommands::Remove { name } => remove_provider(name),
        ProviderCommands::Info { name } => provider_info(cli, name),
        ProviderCommands::Load {
            spec,
            name,
            mcp,
            transport,
            url,
            command,
            args,
            env,
            auth,
            auth_key,
            auth_header,
            auth_query,
            save,
            ttl,
        } => {
            load_provider(
                cli,
                spec.as_deref(),
                name,
                *mcp,
                transport.as_deref(),
                url.as_deref(),
                command.as_deref(),
                args,
                env,
                auth.as_deref(),
                auth_key.as_deref(),
                auth_header.as_deref(),
                auth_query.as_deref(),
                *save,
                *ttl,
            )
            .await
        }
        ProviderCommands::InstallSkills { name } => install_provider_skills(cli, name),
        ProviderCommands::Unload { name } => unload_provider(name),
    }
}

// ─── add-mcp ────────────────────────────────────────────────────────────────

fn add_mcp(
    name: &str,
    transport: &str,
    url: Option<&str>,
    command: Option<&str>,
    args: &[String],
    env: &[String],
    auth: &str,
    auth_key: Option<&str>,
    auth_header: Option<&str>,
    description: Option<&str>,
    category: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate transport-specific requirements
    match transport {
        "http" => {
            if url.is_none() {
                return Err("--url is required for HTTP transport".into());
            }
        }
        "stdio" => {
            if command.is_none() {
                return Err("--command is required for stdio transport".into());
            }
        }
        other => {
            return Err(format!("Unknown transport: {other} (expected http or stdio)").into());
        }
    }

    // Validate auth requirements
    match auth {
        "bearer" | "header" => {
            if auth_key.is_none() {
                return Err(format!("--auth-key is required for {auth} auth").into());
            }
        }
        "none" => {}
        other => {
            return Err(
                format!("Unknown auth type: {other} (expected none, bearer, or header)").into(),
            );
        }
    }

    // Parse --env KEY=VALUE pairs
    let mut mcp_env = HashMap::new();
    for entry in env {
        let (k, v) = entry
            .split_once('=')
            .ok_or_else(|| format!("Invalid --env format: {entry} (expected KEY=VALUE)"))?;
        mcp_env.insert(k.to_string(), v.to_string());
    }

    // Build the serializable manifest
    #[derive(serde::Serialize)]
    struct McpManifest {
        provider: McpProvider,
    }

    #[derive(serde::Serialize)]
    struct McpProvider {
        name: String,
        description: String,
        handler: String,
        mcp_transport: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        mcp_url: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        mcp_command: Option<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        mcp_args: Vec<String>,
        #[serde(skip_serializing_if = "HashMap::is_empty")]
        mcp_env: HashMap<String, String>,
        auth_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        auth_key_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        auth_header_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        category: Option<String>,
    }

    let desc = description
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{name} MCP provider"));

    let manifest = McpManifest {
        provider: McpProvider {
            name: name.to_string(),
            description: desc,
            handler: "mcp".to_string(),
            mcp_transport: transport.to_string(),
            mcp_url: url.map(|s| s.to_string()),
            mcp_command: command.map(|s| s.to_string()),
            mcp_args: args.to_vec(),
            mcp_env,
            auth_type: auth.to_string(),
            auth_key_name: auth_key.map(|s| s.to_string()),
            auth_header_name: if auth == "header" {
                auth_header.map(|s| s.to_string())
            } else {
                None
            },
            category: category.map(|s| s.to_string()),
        },
    };

    let toml_content = toml::to_string_pretty(&manifest)
        .map_err(|e| format!("Failed to serialize manifest: {e}"))?;

    // Save to manifests directory
    let ati_dir = common::ati_dir();
    let manifests_dir = ati_dir.join("manifests");
    std::fs::create_dir_all(&manifests_dir)?;

    let manifest_path = manifests_dir.join(format!("{name}.toml"));
    if manifest_path.exists() {
        return Err(format!("Manifest already exists: {}", manifest_path.display()).into());
    }

    std::fs::write(&manifest_path, &toml_content)?;
    eprintln!("Saved manifest to {}", manifest_path.display());

    // Hint about auth key
    if let Some(key_name) = auth_key {
        eprintln!("Remember to add your API key: ati key set {key_name} <your-key>");
    }

    Ok(())
}

// ─── add-cli ─────────────────────────────────────────────────────────────────

fn add_cli(
    name: &str,
    command: &str,
    default_args: &[String],
    env: &[String],
    description: Option<&str>,
    category: Option<&str>,
    timeout: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Parse --env KEY=VALUE pairs
    let mut cli_env = HashMap::new();
    for entry in env {
        let (k, v) = entry
            .split_once('=')
            .ok_or_else(|| format!("Invalid --env format: {entry} (expected KEY=VALUE)"))?;
        cli_env.insert(k.to_string(), v.to_string());
    }

    #[derive(serde::Serialize)]
    struct CliManifest {
        provider: CliProvider,
    }

    #[derive(serde::Serialize)]
    struct CliProvider {
        name: String,
        description: String,
        handler: String,
        cli_command: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        cli_default_args: Vec<String>,
        #[serde(skip_serializing_if = "HashMap::is_empty")]
        cli_env: HashMap<String, String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cli_timeout_secs: Option<u64>,
        auth_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        category: Option<String>,
    }

    let desc = description
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{name} CLI provider"));

    let manifest = CliManifest {
        provider: CliProvider {
            name: name.to_string(),
            description: desc,
            handler: "cli".to_string(),
            cli_command: command.to_string(),
            cli_default_args: default_args.to_vec(),
            cli_env,
            cli_timeout_secs: timeout,
            auth_type: "none".to_string(),
            category: category.map(|s| s.to_string()),
        },
    };

    let toml_content = toml::to_string_pretty(&manifest)
        .map_err(|e| format!("Failed to serialize manifest: {e}"))?;

    // Save to manifests directory
    let ati_dir = common::ati_dir();
    let manifests_dir = ati_dir.join("manifests");
    std::fs::create_dir_all(&manifests_dir)?;

    let manifest_path = manifests_dir.join(format!("{name}.toml"));
    if manifest_path.exists() {
        return Err(format!("Manifest already exists: {}", manifest_path.display()).into());
    }

    std::fs::write(&manifest_path, &toml_content)?;
    eprintln!("Saved CLI manifest to {}", manifest_path.display());

    // Hint about keyring references in env vars
    for v in manifest.provider.cli_env.values() {
        if let Some(key_ref) = v.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
            eprintln!("Remember to add your key: ati key set {key_ref} <value>");
        } else if let Some(key_ref) = v.strip_prefix("@{").and_then(|s| s.strip_suffix('}')) {
            eprintln!("Remember to add your credential: ati key set {key_ref} <content>");
        }
    }

    Ok(())
}

// ─── derive-provider-name ───────────────────────────────────────────────────

/// Derive a provider name from a spec URL or file path.
///
/// - URL: parse host, take the domain minus TLD
///   `clinicaltrials.gov` → `clinicaltrials`, `api.finnhub.io` → `finnhub`
/// - File path: stem without extension
///   `finnhub.json` → `finnhub`
/// - Sanitize: lowercase, non-alphanumeric → `_`, trim leading/trailing `_`
fn derive_provider_name(spec: &str) -> String {
    let raw = if spec.starts_with("http://") || spec.starts_with("https://") {
        // Extract host from URL: strip scheme, take up to first '/' or ':'
        let after_scheme = spec
            .strip_prefix("https://")
            .or_else(|| spec.strip_prefix("http://"))
            .unwrap_or(spec);
        let host = after_scheme
            .split('/')
            .next()
            .unwrap_or(after_scheme)
            .split(':')
            .next()
            .unwrap_or(after_scheme);

        // Split host into parts, remove common prefixes and TLD
        let parts: Vec<&str> = host.split('.').collect();
        match parts.len() {
            0 | 1 => host.to_string(),
            _ => {
                let skip_prefixes = ["api", "www", "mcp", "rest"];
                let skip_tlds = [
                    "com", "org", "net", "io", "dev", "ai", "co", "gov", "edu",
                ];
                let meaningful: Vec<&str> = parts
                    .iter()
                    .enumerate()
                    .filter(|(i, p)| {
                        let is_first = *i == 0;
                        let is_last = *i == parts.len() - 1;
                        let is_prefix = is_first && skip_prefixes.contains(p);
                        let is_tld = is_last && skip_tlds.contains(p);
                        !is_prefix && !is_tld
                    })
                    .map(|(_, p)| *p)
                    .collect();
                if meaningful.is_empty() {
                    parts[0].to_string()
                } else {
                    meaningful.join("_")
                }
            }
        }
    } else {
        // File path: use stem
        std::path::Path::new(spec)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string()
    };

    // Sanitize: lowercase, non-alphanumeric → _, trim _
    let sanitized: String = raw
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();
    sanitized.trim_matches('_').to_string()
}

// ─── import-openapi ─────────────────────────────────────────────────────────

fn import_openapi(
    spec_path: &str,
    name: &str,
    auth_key: Option<&str>,
    include_tags: &[String],
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = read_spec_content(spec_path)?;
    let spec = openapi::parse_spec(&content)?;

    // Detect auth
    let (auth_type, auth_extra) = openapi::detect_auth(&spec);

    // Determine base URL
    let base_url = openapi::spec_base_url(&spec).unwrap_or_default();

    // Count operations with tag filter
    let filters = OpenApiFilters {
        include_tags: include_tags.to_vec(),
        exclude_tags: vec![],
        include_operations: vec![],
        exclude_operations: vec![],
        max_operations: None,
    };
    let tools = openapi::extract_tools(&spec, &filters);

    // Build TOML manifest
    let spec_filename = format!("{name}.json");
    let default_key_name = format!("{name}_api_key");
    let key_name = auth_key.unwrap_or(&default_key_name);

    #[derive(serde::Serialize)]
    struct ProviderToml {
        name: String,
        description: String,
        handler: String,
        base_url: String,
        openapi_spec: String,
        auth_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        auth_key_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        auth_header_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        auth_query_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        openapi_include_tags: Option<Vec<String>>,
    }

    let provider_toml = ProviderToml {
        name: name.to_string(),
        description: spec.info.title.clone(),
        handler: "openapi".to_string(),
        base_url: base_url.clone(),
        openapi_spec: spec_filename.clone(),
        auth_type: auth_type.clone(),
        auth_key_name: if auth_type != "none" {
            Some(key_name.to_string())
        } else {
            None
        },
        auth_header_name: auth_extra.get("auth_header_name").cloned(),
        auth_query_name: auth_extra.get("auth_query_name").cloned(),
        openapi_include_tags: if include_tags.is_empty() {
            None
        } else {
            Some(include_tags.to_vec())
        },
    };

    #[derive(serde::Serialize)]
    struct ManifestToml {
        provider: ProviderToml,
    }

    let manifest = ManifestToml {
        provider: provider_toml,
    };
    let toml_content = toml::to_string_pretty(&manifest)
        .map_err(|e| format!("Failed to serialize TOML manifest: {e}"))?;

    if dry_run {
        println!("--- Generated manifest ({name}.toml) ---");
        println!("{toml_content}");
        println!(
            "--- Spec: {} ({} operations) ---",
            spec.info.title,
            tools.len()
        );
        println!("Would save spec to: ~/.ati/specs/{spec_filename}");
        println!("Would save manifest to: ~/.ati/manifests/{name}.toml");
        return Ok(());
    }

    // Save spec file
    let ati_dir = common::ati_dir();
    let specs_dir = ati_dir.join("specs");
    std::fs::create_dir_all(&specs_dir)?;
    let spec_dest = specs_dir.join(&spec_filename);

    let spec_json = serde_json::to_string_pretty(&spec)?;
    std::fs::write(&spec_dest, &spec_json)?;
    eprintln!("Saved spec to {}", spec_dest.display());

    // Save manifest
    let manifests_dir = ati_dir.join("manifests");
    std::fs::create_dir_all(&manifests_dir)?;
    let manifest_dest = manifests_dir.join(format!("{name}.toml"));
    std::fs::write(&manifest_dest, &toml_content)?;
    eprintln!("Saved manifest to {}", manifest_dest.display());

    eprintln!(
        "\nImported {} operations from \"{}\"",
        tools.len(),
        spec.info.title
    );
    if auth_type != "none" {
        eprintln!("Remember to add your API key: ati key set {key_name} <your-key>");
    }

    Ok(())
}

// ─── inspect-openapi ────────────────────────────────────────────────────────

fn inspect_openapi(
    spec_path: &str,
    include_tags: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let content = read_spec_content(spec_path)?;
    let spec = openapi::parse_spec(&content)?;

    println!("OpenAPI: {} v{}", spec.info.title, spec.info.version);
    if let Some(desc) = &spec.info.description {
        let short = if desc.len() > 120 {
            format!("{}...", &desc[..117])
        } else {
            desc.clone()
        };
        println!("  {short}");
    }

    if let Some(base_url) = openapi::spec_base_url(&spec) {
        println!("Base URL: {base_url}");
    }

    let (auth_type, auth_extra) = openapi::detect_auth(&spec);
    let auth_detail = if auth_extra.is_empty() {
        auth_type.clone()
    } else {
        let extras: Vec<String> = auth_extra.iter().map(|(k, v)| format!("{k}={v}")).collect();
        format!("{auth_type} ({})", extras.join(", "))
    };
    println!("Auth: {auth_detail}");

    let ops = openapi::list_operations(&spec);

    let filtered_ops: Vec<_> = if include_tags.is_empty() {
        ops.iter().collect()
    } else {
        ops.iter()
            .filter(|op| op.tags.iter().any(|t| include_tags.contains(t)))
            .collect()
    };

    println!("\nOperations ({}):", filtered_ops.len());

    let mut by_tag: std::collections::BTreeMap<String, Vec<&openapi::OperationSummary>> =
        std::collections::BTreeMap::new();

    for op in &filtered_ops {
        if op.tags.is_empty() {
            by_tag.entry("(untagged)".into()).or_default().push(op);
        } else {
            for tag in &op.tags {
                by_tag.entry(tag.clone()).or_default().push(op);
            }
        }
    }

    for (tag, ops) in &by_tag {
        println!("  TAG: {tag} ({} operations)", ops.len());
        for op in ops {
            let desc = if op.description.len() > 50 {
                format!("{}...", &op.description[..47])
            } else {
                op.description.clone()
            };
            println!(
                "    {:<24} {:<7} {:<30} {}",
                op.operation_id, op.method, op.path, desc
            );
        }
    }

    Ok(())
}

// ─── list ───────────────────────────────────────────────────────────────────

fn list_providers(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let ati_dir = common::ati_dir();
    let manifests_dir = ati_dir.join("manifests");

    // Collect all providers from manifests
    let mut providers: Vec<serde_json::Value> = Vec::new();

    if manifests_dir.exists() {
        let mut entries: Vec<_> = std::fs::read_dir(&manifests_dir)?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let parsed: toml::Value = match toml::from_str(&content) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let provider = match parsed.get("provider") {
                Some(p) => p,
                None => continue,
            };

            let name = provider
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("?");
            let description = provider
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("");
            let handler = provider
                .get("handler")
                .and_then(|h| h.as_str())
                .unwrap_or("http");
            let internal = provider
                .get("internal")
                .and_then(|i| i.as_bool())
                .unwrap_or(false);
            let auth_type = provider
                .get("auth_type")
                .and_then(|a| a.as_str())
                .unwrap_or("none");

            // Skip internal providers in non-JSON output
            if internal && !matches!(cli.output, OutputFormat::Json) {
                continue;
            }

            // Count tools (for HTTP providers with [[tools]] sections)
            let tool_count = parsed
                .get("tools")
                .and_then(|t| t.as_array())
                .map(|a| a.len())
                .unwrap_or(0);

            let handler_type = match handler {
                "mcp" => {
                    let transport = provider
                        .get("mcp_transport")
                        .and_then(|t| t.as_str())
                        .unwrap_or("stdio");
                    format!("mcp/{transport}")
                }
                "openapi" => "openapi".to_string(),
                "cli" => "cli".to_string(),
                _ => "http".to_string(),
            };

            let tool_label = if handler == "mcp" || handler == "openapi" {
                "auto".to_string()
            } else if handler == "cli" {
                "1".to_string()
            } else {
                tool_count.to_string()
            };

            providers.push(serde_json::json!({
                "name": name,
                "type": handler_type,
                "description": description,
                "auth": auth_type,
                "tools": tool_label,
                "internal": internal,
                "source": "permanent",
            }));
        }
    }

    // Also include cached providers
    let cache_dir = ati_dir.join("cache").join("providers");
    if cache_dir.is_dir() {
        let mut cache_entries: Vec<_> = std::fs::read_dir(&cache_dir)?
            .filter_map(|e| e.ok())
            .collect();
        cache_entries.sort_by_key(|e| e.file_name());

        for entry in cache_entries {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let cached: CachedProvider = match serde_json::from_str(&content) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // Skip expired (and clean up)
            if cached.is_expired() {
                let _ = std::fs::remove_file(&path);
                continue;
            }

            // Skip if a permanent provider with same name already listed
            if providers.iter().any(|p| p["name"].as_str() == Some(&cached.name)) {
                continue;
            }

            let remaining = cached.remaining_seconds();
            let remaining_label = format_remaining(remaining);

            let handler_type = match cached.provider_type.as_str() {
                "mcp" => {
                    let transport = cached.mcp_transport.as_deref().unwrap_or("stdio");
                    format!("mcp/{transport}")
                }
                _ => "openapi".to_string(),
            };

            let tool_label = "auto".to_string();

            providers.push(serde_json::json!({
                "name": cached.name,
                "type": handler_type,
                "description": format!("(cached, {})", remaining_label),
                "auth": cached.auth_type,
                "tools": tool_label,
                "internal": false,
                "source": "cached",
                "remaining_seconds": remaining,
            }));
        }
    }

    if providers.is_empty() {
        println!("No providers configured. Run `ati provider load`, `ati provider add-mcp`, or `ati provider import-openapi`.");
        return Ok(());
    }

    match cli.output {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&providers)?
            );
        }
        OutputFormat::Table | OutputFormat::Text => {
            let table_data: Vec<serde_json::Value> = providers
                .iter()
                .filter(|p| !p["internal"].as_bool().unwrap_or(false))
                .map(|p| {
                    serde_json::json!({
                        "NAME": p["name"],
                        "TYPE": p["type"],
                        "AUTH": p["auth"],
                        "TOOLS": p["tools"],
                        "DESCRIPTION": p["description"],
                    })
                })
                .collect();
            let value = serde_json::json!(table_data);
            println!("{}", output::table::format(&value));
        }
    }

    Ok(())
}

// ─── remove ─────────────────────────────────────────────────────────────────

fn remove_provider(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let ati_dir = common::ati_dir();
    let manifests_dir = ati_dir.join("manifests");
    let manifest_path = manifests_dir.join(format!("{name}.toml"));

    if !manifest_path.exists() {
        return Err(format!("Manifest not found: {}", manifest_path.display()).into());
    }

    std::fs::remove_file(&manifest_path)?;
    eprintln!("Removed {}", manifest_path.display());

    Ok(())
}

// ─── info ───────────────────────────────────────────────────────────────────

fn provider_info(cli: &Cli, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let ati_dir = common::ati_dir();
    let manifests_dir = ati_dir.join("manifests");

    // Try loading the full registry to get provider details
    let registry = ManifestRegistry::load(&manifests_dir)?;

    let provider = registry
        .list_providers()
        .into_iter()
        .find(|p| p.name == name)
        .ok_or_else(|| format!("Provider '{name}' not found. Run 'ati provider list' to see available providers."))?;

    let auth_str = format!("{:?}", provider.auth_type).to_lowercase();

    // Check declared skills vs installed
    let skills_declared = provider.skills.len();
    let mut skills_installed = 0;
    if skills_declared > 0 {
        let skills_dir = ati_dir.join("skills");
        if let Ok(skill_registry) = crate::core::skill::SkillRegistry::load(&skills_dir) {
            // Check how many skills for this provider are installed
            let provider_skills = skill_registry.skills_for_provider(&provider.name);
            skills_installed = provider_skills.len();
        }
    }

    match cli.output {
        OutputFormat::Json => {
            let mut info = serde_json::json!({
                "name": provider.name,
                "description": provider.description,
                "handler": provider.handler,
                "base_url": provider.base_url,
                "auth_type": auth_str,
                "category": provider.category,
                "internal": provider.internal,
            });
            if provider.is_cli() {
                info["cli_command"] = serde_json::json!(provider.cli_command);
                info["cli_default_args"] = serde_json::json!(provider.cli_default_args);
                info["cli_timeout_secs"] = serde_json::json!(provider.cli_timeout_secs);
            }
            if skills_declared > 0 {
                info["skills_declared"] = serde_json::json!(skills_declared);
                info["skills_installed"] = serde_json::json!(skills_installed);
                info["skills"] = serde_json::json!(provider.skills);
            }
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        OutputFormat::Table | OutputFormat::Text => {
            println!("Provider:    {}", provider.name);
            println!("Description: {}", provider.description);
            println!("Handler:     {}", provider.handler);
            println!("Base URL:    {}", provider.base_url);
            println!("Auth:        {}", auth_str);
            if let Some(cat) = &provider.category {
                println!("Category:    {cat}");
            }
            if provider.is_mcp() {
                println!("Transport:   MCP ({})", provider.mcp_transport_type());
            }
            if provider.is_cli() {
                if let Some(cmd) = &provider.cli_command {
                    println!("Command:     {cmd}");
                }
                if !provider.cli_default_args.is_empty() {
                    println!("Default args: {:?}", provider.cli_default_args);
                }
                if !provider.cli_env.is_empty() {
                    println!("Environment:");
                    for (k, v) in &provider.cli_env {
                        println!("  {k} = {v}");
                    }
                }
                if let Some(timeout) = provider.cli_timeout_secs {
                    println!("Timeout:     {timeout}s");
                }
            }
            if skills_declared > 0 {
                let not_installed = skills_declared.saturating_sub(skills_installed);
                println!(
                    "Skills:      {} declared ({} installed, {} not installed)",
                    skills_declared, skills_installed, not_installed
                );
                println!(
                    "  Install:   ati provider install-skills {}",
                    provider.name
                );
            }
        }
    }

    Ok(())
}

// ─── install-skills ──────────────────────────────────────────────────────────

fn install_provider_skills(_cli: &Cli, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let ati_dir = common::ati_dir();
    let manifests_dir = ati_dir.join("manifests");
    let registry = ManifestRegistry::load(&manifests_dir)?;

    let provider = registry
        .list_providers()
        .into_iter()
        .find(|p| p.name == name)
        .ok_or_else(|| format!("Provider '{name}' not found."))?;

    if provider.skills.is_empty() {
        println!("Provider '{name}' has no declared skills.");
        return Ok(());
    }

    let skills_dir = ati_dir.join("skills");
    std::fs::create_dir_all(&skills_dir)?;

    let mut installed = 0;
    let mut failed = 0;

    for skill_url in &provider.skills {
        println!("Installing skill from: {skill_url}");
        match crate::cli::skills::install_skill_from_url(skill_url, &skills_dir) {
            Ok(skill_name) => {
                println!("  Installed '{skill_name}'");
                installed += 1;
            }
            Err(e) => {
                eprintln!("  Failed: {e}");
                failed += 1;
            }
        }
    }

    println!(
        "\nDone: {installed} installed, {failed} failed (of {} declared).",
        provider.skills.len()
    );
    Ok(())
}

// ─── load ────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn load_provider(
    cli: &Cli,
    spec: Option<&str>,
    name: &str,
    mcp: bool,
    transport: Option<&str>,
    url: Option<&str>,
    command: Option<&str>,
    args: &[String],
    env: &[String],
    auth: Option<&str>,
    auth_key: Option<&str>,
    auth_header: Option<&str>,
    auth_query: Option<&str>,
    save: bool,
    ttl: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    if mcp {
        load_mcp_provider(cli, name, transport, url, command, args, env, auth, auth_key, auth_header, auth_query, save, ttl).await
    } else {
        load_openapi_provider(cli, spec, name, auth, auth_key, auth_header, auth_query, save, ttl).await
    }
}

/// Load an OpenAPI provider: fetch spec, detect auth, cache or save.
async fn load_openapi_provider(
    cli: &Cli,
    spec: Option<&str>,
    name: &str,
    auth_override: Option<&str>,
    auth_key: Option<&str>,
    auth_header_override: Option<&str>,
    auth_query_override: Option<&str>,
    save: bool,
    ttl: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let spec_path = spec.ok_or("OpenAPI mode requires a spec path or URL. Use --mcp for MCP providers.")?;

    // If --save, delegate to existing import_openapi
    if save {
        return import_openapi(
            spec_path,
            name,
            auth_key,
            &[],
            false,
        );
    }

    // Fetch/read the spec content
    let content = read_spec_content(spec_path)?;
    let parsed_spec = openapi::parse_spec(&content)?;

    // Detect auth from spec
    let (detected_auth_type, auth_extra) = openapi::detect_auth(&parsed_spec);
    let auth_type = auth_override.unwrap_or(&detected_auth_type);

    // Determine base URL
    let base_url = openapi::spec_base_url(&parsed_spec).unwrap_or_default();

    // Count tools
    let filters = OpenApiFilters {
        include_tags: vec![],
        exclude_tags: vec![],
        include_operations: vec![],
        exclude_operations: vec![],
        max_operations: None,
    };
    let tools = openapi::extract_tools(&parsed_spec, &filters);
    let tools_count = tools.len();

    // Determine key name
    let default_key_name = format!("{name}_api_key");
    let key_name = auth_key.unwrap_or(&default_key_name);

    // Check keyring for existing key
    let ati_dir = common::ati_dir();
    let keyring = load_keyring(&ati_dir, cli.verbose);
    let key_resolved = auth_type == "none" || keyring.contains(key_name);

    // Write cache
    let now = Utc::now();
    let cached = CachedProvider {
        name: name.to_string(),
        provider_type: "openapi".to_string(),
        base_url: base_url.clone(),
        auth_type: auth_type.to_string(),
        auth_key_name: if auth_type != "none" {
            Some(key_name.to_string())
        } else {
            None
        },
        auth_header_name: auth_header_override.map(|s| s.to_string()).or_else(|| auth_extra.get("auth_header_name").cloned()),
        auth_query_name: auth_query_override.map(|s| s.to_string()).or_else(|| auth_extra.get("auth_query_name").cloned()),
        spec_content: Some(content),
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
        created_at: now.to_rfc3339(),
        ttl_seconds: ttl,
    };

    let cache_dir = ati_dir.join("cache").join("providers");
    std::fs::create_dir_all(&cache_dir)?;
    let cache_path = cache_dir.join(format!("{name}.json"));
    let cache_json = serde_json::to_string_pretty(&cached)?;
    std::fs::write(&cache_path, &cache_json)?;

    // Build status
    let status = if key_resolved { "ready" } else { "needs_auth" };

    // Auth description for output
    let auth_description = match auth_type {
        "bearer" => "HTTP Bearer token (Authorization header)".to_string(),
        "header" => {
            let hdr = auth_extra
                .get("auth_header_name")
                .map(|s| s.as_str())
                .unwrap_or("X-Api-Key");
            format!("API key via header ({hdr})")
        }
        "query" => {
            let qn = auth_extra
                .get("auth_query_name")
                .map(|s| s.as_str())
                .unwrap_or("api_key");
            format!("API key via query parameter ({qn})")
        }
        "basic" => "HTTP Basic authentication".to_string(),
        "oauth2" => "OAuth2 client credentials".to_string(),
        _ => "No authentication required".to_string(),
    };

    let mut setup_commands = Vec::new();
    if !key_resolved {
        setup_commands.push(format!("ati key set {key_name} <your-api-key>"));
    }

    match cli.output {
        OutputFormat::Json => {
            let mut result = serde_json::json!({
                "status": status,
                "name": name,
                "provider_type": "openapi",
                "base_url": base_url,
                "tools_count": tools_count,
                "auth": {
                    "type": auth_type,
                    "key_name": if auth_type != "none" { Some(key_name) } else { None },
                    "description": auth_description,
                    "resolved": key_resolved,
                },
                "setup_commands": setup_commands,
                "cached_until": cached.expires_at(),
            });
            // Add auth extra fields
            if let Some(hdr) = auth_extra.get("auth_header_name") {
                result["auth"]["header_name"] = serde_json::json!(hdr);
            }
            if let Some(qn) = auth_extra.get("auth_query_name") {
                result["auth"]["query_name"] = serde_json::json!(qn);
            }
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OutputFormat::Table | OutputFormat::Text => {
            let ttl_label = format_ttl(ttl);
            eprintln!(
                "Loaded {} ({} tools, cached {}) — status: {}",
                name, tools_count, ttl_label, status
            );
            if !key_resolved {
                eprintln!("  Auth: {} (key: {})", auth_description, key_name);
                eprintln!("  Run: ati key set {} <your-api-key>", key_name);
            }
        }
    }

    Ok(())
}

/// Load an MCP provider: validate config, cache or save, then probe for tools.
async fn load_mcp_provider(
    cli: &Cli,
    name: &str,
    transport: Option<&str>,
    url: Option<&str>,
    command: Option<&str>,
    args: &[String],
    env: &[String],
    auth: Option<&str>,
    auth_key: Option<&str>,
    auth_header: Option<&str>,
    auth_query: Option<&str>,
    save: bool,
    ttl: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = transport.unwrap_or("stdio");

    // Validate transport-specific requirements
    match transport {
        "http" => {
            if url.is_none() {
                return Err("--url is required for HTTP transport".into());
            }
        }
        "stdio" => {
            if command.is_none() {
                return Err("--command is required for stdio transport".into());
            }
        }
        other => {
            return Err(format!("Unknown transport: {other} (expected http or stdio)").into());
        }
    }

    // If --save, delegate to existing add_mcp
    if save {
        let auth_str = auth.unwrap_or("none");
        return add_mcp(
            name,
            transport,
            url,
            command,
            args,
            env,
            auth_str,
            auth_key,
            None,
            None,
            None,
        );
    }

    // Parse env vars and detect keyring refs
    let mut mcp_env = HashMap::new();
    let mut env_vars_status: HashMap<String, serde_json::Value> = HashMap::new();
    let mut missing_keys = Vec::new();

    let ati_dir = common::ati_dir();
    let keyring = load_keyring(&ati_dir, cli.verbose);

    for entry in env {
        let (k, v) = entry
            .split_once('=')
            .ok_or_else(|| format!("Invalid --env format: {entry} (expected KEY=VALUE)"))?;
        mcp_env.insert(k.to_string(), v.to_string());

        // Check for ${keyring_ref} patterns
        if let Some(key_ref) = v.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
            let resolved = keyring.contains(key_ref);
            env_vars_status.insert(
                k.to_string(),
                serde_json::json!({
                    "keyring_ref": key_ref,
                    "resolved": resolved,
                }),
            );
            if !resolved {
                missing_keys.push(key_ref.to_string());
            }
        }
    }

    // Auth key check
    let auth_type = auth.unwrap_or("none");
    let default_key_name = format!("{name}_api_key");
    let key_name = auth_key.unwrap_or(&default_key_name);
    let auth_key_resolved = auth_type == "none" || keyring.contains(key_name);
    if !auth_key_resolved {
        missing_keys.push(key_name.to_string());
    }

    // Write cache
    let now = Utc::now();
    let cached = CachedProvider {
        name: name.to_string(),
        provider_type: "mcp".to_string(),
        base_url: String::new(),
        auth_type: auth_type.to_string(),
        auth_key_name: if auth_type != "none" {
            Some(key_name.to_string())
        } else {
            None
        },
        auth_header_name: auth_header.map(|s| s.to_string()),
        auth_query_name: auth_query.map(|s| s.to_string()),
        spec_content: None,
        mcp_transport: Some(transport.to_string()),
        mcp_url: url.map(|s| s.to_string()),
        mcp_command: command.map(|s| s.to_string()),
        mcp_args: args.to_vec(),
        mcp_env: mcp_env.clone(),
        cli_command: None,
        cli_default_args: Vec::new(),
        cli_env: HashMap::new(),
        cli_timeout_secs: None,
        auth: Some(auth_type.to_string()),
        created_at: now.to_rfc3339(),
        ttl_seconds: ttl,
    };

    let cache_dir = ati_dir.join("cache").join("providers");
    std::fs::create_dir_all(&cache_dir)?;
    let cache_path = cache_dir.join(format!("{name}.json"));
    let cache_json = serde_json::to_string_pretty(&cached)?;
    std::fs::write(&cache_path, &cache_json)?;

    // Build status
    let status = if missing_keys.is_empty() {
        "ready"
    } else if !env_vars_status.is_empty() && !auth_key_resolved {
        "needs_keys"
    } else if !auth_key_resolved {
        "needs_auth"
    } else {
        "needs_keys"
    };

    let mut setup_commands: Vec<String> = Vec::new();
    for key in &missing_keys {
        setup_commands.push(format!("ati key set {key} <your-{key}>"));
    }

    // Optional MCP probe: connect → list_tools → disconnect
    let probe_result = probe_mcp_provider(&cached, &keyring).await;

    match cli.output {
        OutputFormat::Json => {
            let mut result = serde_json::json!({
                "status": status,
                "name": name,
                "provider_type": "mcp",
                "transport": transport,
            });
            if let Some(u) = url {
                result["url"] = serde_json::json!(u);
            }
            if let Some(c) = command {
                result["command"] = serde_json::json!(c);
            }
            if auth_type != "none" {
                result["auth"] = serde_json::json!({
                    "type": auth_type,
                    "key_name": key_name,
                    "resolved": auth_key_resolved,
                });
            }
            if !env_vars_status.is_empty() {
                result["env_vars"] = serde_json::json!(env_vars_status);
            }
            result["setup_commands"] = serde_json::json!(setup_commands);
            result["cached_until"] = serde_json::json!(cached.expires_at());
            match &probe_result {
                Ok(tool_names) => {
                    result["tools_count"] = serde_json::json!(tool_names.len());
                    result["tools"] = serde_json::json!(tool_names);
                    result["probe"] = serde_json::json!("ok");
                }
                Err(e) => {
                    result["probe"] = serde_json::json!("failed");
                    result["probe_error"] = serde_json::json!(e.to_string());
                }
            }
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OutputFormat::Table | OutputFormat::Text => {
            let ttl_label = format_ttl(ttl);
            match &probe_result {
                Ok(tool_names) => {
                    eprintln!(
                        "Loaded {} (mcp/{}, {} tools, cached {}) — status: {}",
                        name, transport, tool_names.len(), ttl_label, status
                    );
                    if !tool_names.is_empty() {
                        eprintln!("  Tools: {}", tool_names.join(", "));
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Loaded {} (mcp/{}, probe failed: {}, cached {}) — status: {}",
                        name, transport, e, ttl_label, status
                    );
                }
            }
            for cmd in &setup_commands {
                eprintln!("  Run: {cmd}");
            }
        }
    }

    Ok(())
}

// ─── MCP probe ───────────────────────────────────────────────────────────────

/// Attempt to connect to an MCP server and list its tools.
/// Returns the list of tool names on success, or an error message.
async fn probe_mcp_provider(
    cached: &CachedProvider,
    keyring: &Keyring,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let provider = cached.to_provider();
    let client = McpClient::connect(&provider, keyring).await?;
    let tools = client.list_tools().await?;
    let tool_names: Vec<String> = tools.iter().map(|t| t.name.clone()).collect();
    client.disconnect().await;
    Ok(tool_names)
}

// ─── unload ──────────────────────────────────────────────────────────────────

fn unload_provider(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let ati_dir = common::ati_dir();
    let cache_path = ati_dir.join("cache").join("providers").join(format!("{name}.json"));

    if !cache_path.exists() {
        return Err(format!("No cached provider '{name}' found.").into());
    }

    std::fs::remove_file(&cache_path)?;
    eprintln!("Unloaded cached provider '{name}'");
    Ok(())
}

// ─── helpers ────────────────────────────────────────────────────────────────

/// Format a TTL in seconds to a human-readable string.
fn format_ttl(seconds: u64) -> String {
    if seconds >= 3600 {
        let hours = seconds / 3600;
        if hours == 1 {
            "1h".to_string()
        } else {
            format!("{hours}h")
        }
    } else {
        let mins = seconds / 60;
        if mins == 0 {
            format!("{seconds}s")
        } else {
            format!("{mins}m")
        }
    }
}

/// Format remaining seconds to a human-readable string (e.g., "58m remaining").
fn format_remaining(seconds: u64) -> String {
    if seconds >= 3600 {
        let hours = seconds / 3600;
        let mins = (seconds % 3600) / 60;
        if mins > 0 {
            format!("{hours}h{mins}m remaining")
        } else {
            format!("{hours}h remaining")
        }
    } else {
        let mins = seconds / 60;
        if mins == 0 {
            format!("{seconds}s remaining")
        } else {
            format!("{mins}m remaining")
        }
    }
}

fn read_spec_content(spec_ref: &str) -> Result<String, Box<dyn std::error::Error>> {
    if spec_ref.starts_with("http://") || spec_ref.starts_with("https://") {
        crate::core::http::validate_url_not_private(spec_ref)
            .map_err(|e| format!("SSRF protection: {e}"))?;

        if spec_ref.starts_with("http://") {
            eprintln!("Warning: downloading spec over insecure HTTP — consider using HTTPS");
        }

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let response = client.get(spec_ref).send()?;

        if response.status().is_redirection() {
            let location = response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown");
            return Err(format!(
                "URL redirected to '{location}' — fetch the target URL directly to avoid SSRF"
            )
            .into());
        }

        if !response.status().is_success() {
            return Err(format!(
                "Failed to fetch spec from {}: {}",
                spec_ref,
                response.status()
            )
            .into());
        }
        Ok(response.text()?)
    } else {
        Ok(std::fs::read_to_string(spec_ref)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_provider_name_url_with_tld() {
        assert_eq!(
            derive_provider_name("https://clinicaltrials.gov/api/v2/openapi.json"),
            "clinicaltrials"
        );
    }

    #[test]
    fn test_derive_provider_name_url_api_prefix() {
        assert_eq!(
            derive_provider_name("https://api.finnhub.io/openapi.json"),
            "finnhub"
        );
    }

    #[test]
    fn test_derive_provider_name_url_www_prefix() {
        assert_eq!(
            derive_provider_name("https://www.example.com/spec.json"),
            "example"
        );
    }

    #[test]
    fn test_derive_provider_name_url_multi_part() {
        assert_eq!(
            derive_provider_name("https://api.data.census.gov/spec.json"),
            "data_census"
        );
    }

    #[test]
    fn test_derive_provider_name_file_path() {
        assert_eq!(derive_provider_name("finnhub.json"), "finnhub");
    }

    #[test]
    fn test_derive_provider_name_file_path_nested() {
        assert_eq!(
            derive_provider_name("/path/to/my-spec.yaml"),
            "my_spec"
        );
    }

    #[test]
    fn test_derive_provider_name_url_with_port() {
        assert_eq!(
            derive_provider_name("http://localhost:8080/openapi.json"),
            "localhost"
        );
    }

    #[test]
    fn test_derive_provider_name_simple_domain() {
        assert_eq!(
            derive_provider_name("https://petstore3.swagger.io/api/v3/openapi.json"),
            "petstore3_swagger"
        );
    }
}
