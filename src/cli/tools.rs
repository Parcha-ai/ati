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
        ToolsCommands::Search { query } => search_tools(cli, &registry, &scopes, query),
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
            println!("Handler:     {}", provider.handler);
            if provider.is_mcp() {
                println!("Transport:   MCP ({})", provider.mcp_transport_type());
            } else {
                println!("Endpoint:    {} {}{}", tool.method, provider.base_url, tool.endpoint);
            }
            println!("Description: {}", tool.description);
            if let Some(scope) = &tool.scope {
                println!("Scope:       {scope}");
            }
            if let Some(category) = &provider.category {
                println!("Category:    {category}");
            }
            if !tool.tags.is_empty() {
                println!("Tags:        {}", tool.tags.join(", "));
            }
            if let Some(hint) = &tool.hint {
                println!("Hint:        {hint}");
            }
            if let Some(schema) = &tool.input_schema {
                println!("\nInput Schema:");
                println!("{}", serde_json::to_string_pretty(schema)?);
            }
            if !tool.examples.is_empty() {
                println!("\nExamples:");
                for ex in &tool.examples {
                    println!("  {ex}");
                }
            }
            // Show example usage
            println!("\nUsage:");
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

fn search_tools(
    cli: &Cli,
    registry: &ManifestRegistry,
    scopes: &ScopeConfig,
    query: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tools = registry.list_public_tools();
    tools = scope::filter_tools_by_scope(tools, scopes);

    let query_lower = query.to_lowercase();
    let query_terms: Vec<&str> = query_lower.split_whitespace().collect();

    // Score each tool by how well it matches the query
    let mut scored: Vec<(f64, &crate::core::manifest::Provider, &crate::core::manifest::Tool)> = tools
        .iter()
        .filter_map(|(p, t)| {
            let score = score_tool_match(p, t, &query_terms);
            if score > 0.0 {
                Some((score, *p, *t))
            } else {
                None
            }
        })
        .collect();

    // Sort by score (highest first)
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    // Limit to top 20 results
    scored.truncate(20);

    if scored.is_empty() {
        eprintln!("No tools match '{query}'. Try a different search term.");
        return Ok(());
    }

    match cli.output {
        OutputFormat::Json => {
            let json_tools: Vec<serde_json::Value> = scored
                .iter()
                .map(|(_score, p, t)| {
                    serde_json::json!({
                        "provider": p.name,
                        "tool": t.name,
                        "description": t.description,
                        "handler": p.handler,
                        "category": p.category,
                        "tags": t.tags,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_tools)?);
        }
        OutputFormat::Table | OutputFormat::Text => {
            let value = serde_json::json!(
                scored.iter().map(|(_score, p, t)| {
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

/// Score how well a tool matches the search query terms.
/// Returns 0.0 for no match, higher scores for better matches.
fn score_tool_match(
    provider: &crate::core::manifest::Provider,
    tool: &crate::core::manifest::Tool,
    query_terms: &[&str],
) -> f64 {
    let mut score = 0.0;

    let name_lower = tool.name.to_lowercase();
    let desc_lower = tool.description.to_lowercase();
    let provider_lower = provider.name.to_lowercase();
    let category_lower = provider
        .category
        .as_deref()
        .unwrap_or("")
        .to_lowercase();
    let tags_lower: Vec<String> = tool.tags.iter().map(|t| t.to_lowercase()).collect();

    for term in query_terms {
        let mut term_score = 0.0;

        // Exact name match (highest weight)
        if name_lower == *term {
            term_score += 10.0;
        } else if name_lower.contains(term) {
            term_score += 5.0;
        }

        // Provider name match
        if provider_lower.contains(term) {
            term_score += 3.0;
        }

        // Category match
        if category_lower.contains(term) {
            term_score += 3.0;
        }

        // Tag match
        for tag in &tags_lower {
            if tag.contains(term) {
                term_score += 4.0;
                break;
            }
        }

        // Description match (lower weight)
        if desc_lower.contains(term) {
            term_score += 2.0;
        }

        // Hint match
        if let Some(hint) = &tool.hint {
            if hint.to_lowercase().contains(term) {
                term_score += 1.5;
            }
        }

        if term_score == 0.0 {
            // If any term has zero score, this tool doesn't match
            return 0.0;
        }

        score += term_score;
    }

    score
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
