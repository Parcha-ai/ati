use std::path::PathBuf;

use crate::core::manifest::ManifestRegistry;
use crate::core::scope::{self, ScopeConfig};
use crate::output;
use crate::{Cli, OutputFormat, ToolsCommands};

fn ati_dir() -> PathBuf {
    std::env::var("ATI_DIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".ati"))
                .unwrap_or_else(|_| PathBuf::from(".ati"))
        })
}

/// Execute: ati tools <subcommand>
pub async fn execute(
    cli: &Cli,
    subcmd: &ToolsCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    let ati_dir = ati_dir();
    let manifests_dir = ati_dir.join("manifests");
    let registry = ManifestRegistry::load(&manifests_dir)?;

    // Load scopes (optional)
    let scopes_path = ati_dir.join("scopes.json");
    let scopes = if scopes_path.exists() {
        ScopeConfig::load(&scopes_path)?
    } else {
        ScopeConfig::unrestricted()
    };

    match subcmd {
        ToolsCommands::List { provider } => list_tools(cli, &registry, &scopes, provider.as_deref()),
        ToolsCommands::Info { name } => tool_info(cli, &registry, name),
        ToolsCommands::Providers => list_providers(cli, &registry),
    }
}

fn list_tools(
    cli: &Cli,
    registry: &ManifestRegistry,
    scopes: &ScopeConfig,
    provider_filter: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tools = registry.list_public_tools();

    // Filter by scope
    tools = scope::filter_tools_by_scope(tools, scopes);

    // Filter by provider if specified
    if let Some(pf) = provider_filter {
        tools.retain(|(p, _)| p.name == pf);
    }

    if tools.is_empty() {
        eprintln!("No tools available. Check your scopes or manifests.");
        return Ok(());
    }

    match cli.output {
        OutputFormat::Json => {
            let json_tools: Vec<serde_json::Value> = tools
                .iter()
                .map(|(p, t)| {
                    serde_json::json!({
                        "provider": p.name,
                        "tool": t.name,
                        "description": t.description,
                        "method": t.method.to_string(),
                        "scope": t.scope,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_tools)?);
        }
        OutputFormat::Table | OutputFormat::Text => {
            let value = serde_json::json!(
                tools.iter().map(|(p, t)| {
                    serde_json::json!({
                        "PROVIDER": p.name,
                        "TOOL": t.name,
                        "DESCRIPTION": t.description,
                    })
                }).collect::<Vec<_>>()
            );
            println!("{}", output::table::format(&value));
        }
    }

    Ok(())
}

fn tool_info(
    cli: &Cli,
    registry: &ManifestRegistry,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (provider, tool) = registry.get_tool(name).ok_or_else(|| {
        format!("Unknown tool: '{name}'. Run 'ati tools list' to see available tools.")
    })?;

    match cli.output {
        OutputFormat::Json => {
            let info = serde_json::json!({
                "name": tool.name,
                "description": tool.description,
                "provider": provider.name,
                "base_url": provider.base_url,
                "method": tool.method.to_string(),
                "endpoint": tool.endpoint,
                "scope": tool.scope,
                "input_schema": tool.input_schema,
            });
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        OutputFormat::Table | OutputFormat::Text => {
            println!("Tool:        {}", tool.name);
            println!("Provider:    {} ({})", provider.name, provider.description);
            println!("Endpoint:    {} {}{}", tool.method, provider.base_url, tool.endpoint);
            println!("Description: {}", tool.description);
            if let Some(scope) = &tool.scope {
                println!("Scope:       {scope}");
            }
            if let Some(schema) = &tool.input_schema {
                println!("\nInput Schema:");
                println!("{}", serde_json::to_string_pretty(schema)?);
            }
            // Show example usage
            println!("\nExample:");
            print!("  ati call {}", tool.name);
            if let Some(schema) = &tool.input_schema {
                if let Some(props) = schema.get("properties") {
                    if let Some(obj) = props.as_object() {
                        for (k, v) in obj {
                            let example = v
                                .get("default")
                                .or_else(|| v.get("example"))
                                .map(|e| e.to_string())
                                .unwrap_or_else(|| format!("<{k}>"));
                            print!(" --{k} {example}");
                        }
                    }
                }
            }
            println!();
        }
    }

    Ok(())
}

fn list_providers(
    cli: &Cli,
    registry: &ManifestRegistry,
) -> Result<(), Box<dyn std::error::Error>> {
    let providers = registry.list_providers();

    match cli.output {
        OutputFormat::Json => {
            let json: Vec<serde_json::Value> = providers
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "name": p.name,
                        "description": p.description,
                        "base_url": p.base_url,
                        "internal": p.internal,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Table | OutputFormat::Text => {
            let value = serde_json::json!(
                providers.iter().filter(|p| !p.internal).map(|p| {
                    serde_json::json!({
                        "PROVIDER": p.name,
                        "DESCRIPTION": p.description,
                        "BASE_URL": p.base_url,
                    })
                }).collect::<Vec<_>>()
            );
            println!("{}", output::table::format(&value));
        }
    }

    Ok(())
}
