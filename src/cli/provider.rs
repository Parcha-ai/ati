/// CLI commands for unified provider management.
///
/// `ati provider add-mcp <name>` — generate a TOML manifest for an MCP provider
/// `ati provider import-openapi <spec>` — download spec and generate TOML manifest
/// `ati provider inspect-openapi <spec>` — preview operations in a spec
/// `ati provider list` — list all configured providers
/// `ati provider remove <name>` — remove a provider manifest
/// `ati provider info <name>` — show provider details

use super::common;
use crate::core::manifest::ManifestRegistry;
use crate::core::openapi::{self, OpenApiFilters};
use crate::output;
use crate::{Cli, OutputFormat, ProviderCommands};
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
        ProviderCommands::ImportOpenapi {
            spec,
            name,
            auth_key,
            include_tags,
            dry_run,
        } => import_openapi(spec, name, auth_key.as_deref(), include_tags, *dry_run),
        ProviderCommands::InspectOpenapi { spec, include_tags } => {
            inspect_openapi(spec, include_tags)
        }
        ProviderCommands::List => list_providers(cli),
        ProviderCommands::Remove { name } => remove_provider(name),
        ProviderCommands::Info { name } => provider_info(cli, name),
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

    if !manifests_dir.exists() {
        println!("No manifests directory found at {}", manifests_dir.display());
        return Ok(());
    }

    // Collect all providers from manifests
    let mut providers: Vec<serde_json::Value> = Vec::new();

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
            _ => "http".to_string(),
        };

        let tool_label = if handler == "mcp" || handler == "openapi" {
            "auto".to_string()
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
        }));
    }

    if providers.is_empty() {
        println!("No providers configured. Run `ati provider add-mcp` or `ati provider import-openapi`.");
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

    match cli.output {
        OutputFormat::Json => {
            let info = serde_json::json!({
                "name": provider.name,
                "description": provider.description,
                "handler": provider.handler,
                "base_url": provider.base_url,
                "auth_type": auth_str,
                "category": provider.category,
                "internal": provider.internal,
            });
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
        }
    }

    Ok(())
}

// ─── helpers ────────────────────────────────────────────────────────────────

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
