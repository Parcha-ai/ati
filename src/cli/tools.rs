use super::common;
use crate::core::keyring::Keyring;
use crate::core::manifest::ManifestRegistry;
use crate::core::scope::{self, ScopeConfig};
use crate::output;
use crate::{Cli, OutputFormat, ToolCommands};

/// Discover and register tools from all MCP providers.
pub(crate) async fn discover_mcp_tools(
    registry: &mut ManifestRegistry,
    keyring: &Keyring,
    _verbose: bool,
) {
    crate::core::mcp_client::discover_all_mcp_tools(registry, keyring).await;
}

/// Execute: ati tool <subcommand>
pub async fn execute(cli: &Cli, subcmd: &ToolCommands) -> Result<(), Box<dyn std::error::Error>> {
    // Proxy mode: forward read-only commands to the proxy
    if let Ok(proxy_url) = std::env::var("ATI_PROXY_URL") {
        return execute_via_proxy(cli, subcmd, &proxy_url).await;
    }

    // Local mode
    let ati_dir = common::ati_dir();
    let manifests_dir = ati_dir.join("manifests");
    let mut registry = ManifestRegistry::load(&manifests_dir)?;

    // Load keyring for MCP discovery (cascade: keyring.enc → credentials → empty)
    let keyring = super::call::load_keyring(&ati_dir);

    // Discover MCP tools so they appear in list/search/info
    discover_mcp_tools(&mut registry, &keyring, cli.verbose).await;

    // Load scopes from JWT
    let scopes = common::load_local_scopes_from_env()?;

    match subcmd {
        ToolCommands::List { provider } => list_tools(cli, &registry, &scopes, provider.as_deref()),
        ToolCommands::Info { name } => tool_info(cli, &registry, &scopes, name),
        ToolCommands::Search { query } => search_tools(cli, &registry, &scopes, query),
    }
}

/// Forward tool commands to the proxy server.
async fn execute_via_proxy(
    cli: &Cli,
    subcmd: &ToolCommands,
    proxy_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::proxy::client as proxy_client;

    tracing::debug!(proxy_url = %proxy_url, "mode: proxy");

    match subcmd {
        ToolCommands::List { provider } => {
            let mut params = Vec::new();
            if let Some(p) = provider {
                params.push(format!("provider={p}"));
            }
            let query = params.join("&");
            let tools = proxy_client::list_tools(proxy_url, &query).await?;
            let empty = vec![];
            let tools_arr = tools.as_array().unwrap_or(&empty);

            if tools_arr.is_empty() {
                tracing::warn!("no tools available from proxy");
                return Ok(());
            }

            match cli.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&tools)?),
                _ => {
                    for tool in tools_arr {
                        let name = tool["name"].as_str().unwrap_or("?");
                        let desc = tool["description"].as_str().unwrap_or("");
                        let provider = tool["provider"].as_str().unwrap_or("?");
                        let desc_short: String = desc.chars().take(80).collect();
                        println!("{name:<40} {provider:<15} {desc_short}");
                    }
                }
            }
        }
        ToolCommands::Info { name } => {
            let info = proxy_client::get_tool_info(proxy_url, name).await?;
            if info.get("error").is_some() {
                return Err(format!("Tool '{}' not found", name).into());
            }
            match cli.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&info)?),
                _ => {
                    println!("Tool:        {}", info["name"].as_str().unwrap_or("?"));
                    println!("Provider:    {}", info["provider"].as_str().unwrap_or("?"));
                    println!(
                        "Description: {}",
                        info["description"].as_str().unwrap_or("")
                    );
                    println!("Method:      {}", info["method"].as_str().unwrap_or("?"));
                    if let Some(tags) = info["tags"].as_array() {
                        let tag_strs: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
                        if !tag_strs.is_empty() {
                            println!("Tags:        {}", tag_strs.join(", "));
                        }
                    }
                    if let Some(schema) = info.get("input_schema") {
                        if let Some(props) = schema.get("properties") {
                            println!("\nParameters:");
                            if let Some(obj) = props.as_object() {
                                for (key, val) in obj {
                                    let ptype = val["type"].as_str().unwrap_or("any");
                                    let pdesc = val["description"].as_str().unwrap_or("");
                                    println!("  --{key:<20} ({ptype}) {pdesc}");
                                }
                            }
                        }
                    }
                }
            }
        }
        ToolCommands::Search { query } => {
            let params = format!("search={query}");
            let tools = proxy_client::list_tools(proxy_url, &params).await?;
            let empty = vec![];
            let tools_arr = tools.as_array().unwrap_or(&empty);

            if tools_arr.is_empty() {
                tracing::warn!(query = %query, "no tools match search");
                return Ok(());
            }

            match cli.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&tools)?),
                _ => {
                    for tool in tools_arr {
                        let name = tool["name"].as_str().unwrap_or("?");
                        let desc = tool["description"].as_str().unwrap_or("");
                        let provider = tool["provider"].as_str().unwrap_or("?");
                        let desc_short: String = desc.chars().take(80).collect();
                        println!("{name:<40} {provider:<15} {desc_short}");
                    }
                }
            }
        }
    }

    Ok(())
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
        tracing::warn!("no tools available — check your scopes or manifests");
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
            let value = serde_json::json!(tools
                .iter()
                .map(|(p, t)| {
                    serde_json::json!({
                        "PROVIDER": p.name,
                        "TOOL": t.name,
                        "DESCRIPTION": t.description,
                    })
                })
                .collect::<Vec<_>>());
            println!("{}", output::table::format(&value));
        }
    }

    Ok(())
}

fn tool_info(
    cli: &Cli,
    registry: &ManifestRegistry,
    scopes: &ScopeConfig,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (provider, tool) = registry
        .get_tool(name)
        .filter(|(_, tool)| match &tool.scope {
            Some(scope) => scopes.is_allowed(scope),
            None => true,
        })
        .ok_or_else(|| format!("Unknown tool: '{name}'. Run 'ati tool list' to see available tools."))?;

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
                println!(
                    "Endpoint:    {} {}{}",
                    tool.method, provider.base_url, tool.endpoint
                );
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
            print!("  ati run {}", tool.name);
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
    let mut scored: Vec<(
        f64,
        &crate::core::manifest::Provider,
        &crate::core::manifest::Tool,
    )> = tools
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
        tracing::warn!("no tools match '{query}' — try a different search term");
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
            let value = serde_json::json!(scored
                .iter()
                .map(|(_score, p, t)| {
                    serde_json::json!({
                        "PROVIDER": p.name,
                        "TOOL": t.name,
                        "DESCRIPTION": t.description,
                    })
                })
                .collect::<Vec<_>>());
            println!("{}", output::table::format(&value));
        }
    }

    Ok(())
}

/// Score how well a tool matches the search query terms.
/// Returns 0.0 for no match, higher scores for better matches.
/// Common stop words to skip during fuzzy matching.
const STOP_WORDS: &[&str] = &[
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being", "have", "has", "had",
    "do", "does", "did", "will", "would", "could", "should", "may", "might", "shall", "can",
    "need", "must", "i", "me", "my", "we", "our", "you", "your", "he", "she", "it", "they", "how",
    "what", "when", "where", "which", "who", "whom", "why", "to", "of", "in", "for", "on", "with",
    "at", "by", "from", "about", "into", "through", "during", "before", "after", "above", "below",
    "and", "but", "or", "nor", "not", "so", "if", "than", "that", "this", "there", "here", "all",
    "each", "every", "both", "few", "more", "most", "some", "any", "no", "only", "very", "just",
    "also", "then", "use", "using", "want", "like", "way",
];

/// Jaro-Winkler threshold for considering two words a fuzzy match.
/// 0.85 catches "repos"→"repositories", "config"→"configuration" but
/// rejects unrelated short words.
const FUZZY_THRESHOLD: f64 = 0.85;

/// Check if a query term matches a word using substring OR Jaro-Winkler similarity.
/// Substring is tried first (cheaper). Fuzzy is only tried for terms >= 4 chars
/// to avoid false positives on short words.
fn term_matches_word(term: &str, word: &str) -> bool {
    if word.contains(term) {
        return true;
    }
    // Fuzzy match: only for longer terms where edit distance is meaningful
    if term.len() >= 4 {
        // Check against each word in the field (split on non-alphanumeric)
        // so "repos" can match "repositories" as a standalone word
        return strsim::jaro_winkler(term, word) >= FUZZY_THRESHOLD;
    }
    false
}

/// Score a term against a text field, checking each word in the field.
/// Returns the best match score (0.0 if no match).
fn score_term_against_field(term: &str, field: &str, weight: f64) -> f64 {
    // Fast path: substring match on the whole field
    if field.contains(term) {
        return weight;
    }
    // Slow path: fuzzy match against individual words (only for longer terms)
    if term.len() >= 4 {
        for word in field.split(|c: char| !c.is_alphanumeric() && c != '_') {
            if word.len() >= 3 && strsim::jaro_winkler(term, word) >= FUZZY_THRESHOLD {
                // Fuzzy matches score slightly less than exact substring
                return weight * 0.8;
            }
        }
    }
    0.0
}

pub(crate) fn score_tool_match(
    provider: &crate::core::manifest::Provider,
    tool: &crate::core::manifest::Tool,
    query_terms: &[&str],
) -> f64 {
    let mut score = 0.0;

    let name_lower = tool.name.to_lowercase();
    let desc_lower = tool.description.to_lowercase();
    let provider_lower = provider.name.to_lowercase();
    let category_lower = provider.category.as_deref().unwrap_or("").to_lowercase();
    let tags_lower: Vec<String> = tool.tags.iter().map(|t| t.to_lowercase()).collect();

    // Filter out stop words
    let content_terms: Vec<&str> = query_terms
        .iter()
        .filter(|t| t.len() >= 2 && !STOP_WORDS.contains(&t.to_lowercase().as_str()))
        .copied()
        .collect();

    if content_terms.is_empty() {
        return 0.0;
    }

    let mut matched_terms = 0;
    for term in &content_terms {
        let mut term_score = 0.0;

        // Name match (highest weight) — check both exact and fuzzy
        if name_lower == *term {
            term_score += 10.0;
        } else {
            term_score += score_term_against_field(term, &name_lower, 5.0);
        }

        // Provider name match
        term_score += score_term_against_field(term, &provider_lower, 3.0);

        // Category match
        if !category_lower.is_empty() {
            term_score += score_term_against_field(term, &category_lower, 3.0);
        }

        // Tag match
        for tag in &tags_lower {
            if term_matches_word(term, tag) {
                term_score += 4.0;
                break;
            }
        }

        // Description match
        term_score += score_term_against_field(term, &desc_lower, 2.0);

        // Hint match
        if let Some(hint) = &tool.hint {
            term_score += score_term_against_field(term, &hint.to_lowercase(), 1.5);
        }

        if term_score > 0.0 {
            matched_terms += 1;
        }
        score += term_score;
    }

    // Require at least half of content terms to match
    let min_required = content_terms.len().div_ceil(2);
    if matched_terms < min_required {
        return 0.0;
    }

    // Scale by match ratio so full matches rank higher than partial
    let match_ratio = matched_terms as f64 / content_terms.len() as f64;
    score * match_ratio
}
