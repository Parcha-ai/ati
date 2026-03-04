/// CLI commands for MCP provider management.
///
/// `ati mcp add <name>` — generate a TOML manifest for an MCP provider
/// `ati mcp list` — list configured MCP providers
/// `ati mcp remove <name>` — remove an MCP provider manifest

use super::common;
use crate::McpCommands;
use std::collections::HashMap;

pub fn execute(subcmd: &McpCommands) -> Result<(), Box<dyn std::error::Error>> {
    match subcmd {
        McpCommands::Add {
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
        } => add(
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
        McpCommands::List => list(),
        McpCommands::Remove { name } => remove(name),
    }
}

/// Generate and save a TOML manifest for an MCP provider.
fn add(
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
            return Err(format!("Unknown auth type: {other} (expected none, bearer, or header)").into());
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
            auth_header_name: if auth == "header" { auth_header.map(|s| s.to_string()) } else { None },
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
        eprintln!("Remember to add your API key: ati keys set {key_name} <your-key>");
    }

    Ok(())
}

/// List configured MCP providers from manifests directory.
fn list() -> Result<(), Box<dyn std::error::Error>> {
    let ati_dir = common::ati_dir();
    let manifests_dir = ati_dir.join("manifests");

    if !manifests_dir.exists() {
        println!("No manifests directory found at {}", manifests_dir.display());
        return Ok(());
    }

    let mut found = false;

    // Header
    println!(
        "{:<20} {:<10} {}",
        "NAME", "TRANSPORT", "URL / COMMAND"
    );
    println!("{}", "-".repeat(60));

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

        // Only show MCP handlers
        let handler = provider
            .get("handler")
            .and_then(|h| h.as_str())
            .unwrap_or("");
        if handler != "mcp" {
            continue;
        }

        let name = provider
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("?");
        let transport = provider
            .get("mcp_transport")
            .and_then(|t| t.as_str())
            .unwrap_or("stdio");

        let target = if transport == "http" {
            provider
                .get("mcp_url")
                .and_then(|u| u.as_str())
                .unwrap_or("-")
                .to_string()
        } else {
            let cmd = provider
                .get("mcp_command")
                .and_then(|c| c.as_str())
                .unwrap_or("-");
            let args = provider
                .get("mcp_args")
                .and_then(|a| a.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default();
            if args.is_empty() {
                cmd.to_string()
            } else {
                format!("{cmd} {args}")
            }
        };

        println!("{:<20} {:<10} {}", name, transport, target);
        found = true;
    }

    if !found {
        println!("(no MCP providers configured)");
    }

    Ok(())
}

/// Remove an MCP provider manifest.
fn remove(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let ati_dir = common::ati_dir();
    let manifests_dir = ati_dir.join("manifests");
    let manifest_path = manifests_dir.join(format!("{name}.toml"));

    if !manifest_path.exists() {
        return Err(format!("Manifest not found: {}", manifest_path.display()).into());
    }

    // Verify it's an MCP manifest
    let content = std::fs::read_to_string(&manifest_path)?;
    let parsed: toml::Value =
        toml::from_str(&content).map_err(|e| format!("Failed to parse manifest: {e}"))?;

    let handler = parsed
        .get("provider")
        .and_then(|p| p.get("handler"))
        .and_then(|h| h.as_str())
        .unwrap_or("");

    if handler != "mcp" {
        return Err(format!(
            "Refusing to remove non-MCP manifest (handler={handler:?}). Use a text editor to remove it manually."
        )
        .into());
    }

    std::fs::remove_file(&manifest_path)?;
    eprintln!("Removed {}", manifest_path.display());

    Ok(())
}
