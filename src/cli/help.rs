use std::path::PathBuf;

use crate::core::keyring::Keyring;
use crate::core::manifest::ManifestRegistry;
use crate::core::scope::{self, ScopeConfig};
use crate::core::skill::{self, SkillRegistry};
use crate::proxy::client as proxy_client;
use crate::Cli;

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

const HELP_SYSTEM_PROMPT: &str = r#"You are a tool recommendation assistant for an AI agent. The agent has access to these tools via the `ati` CLI:

## Available Tools
{tools}

{skills_section}

Given the user's query, recommend the most relevant tools and provide exact `ati call` commands with the right arguments. If a methodology skill is relevant, mention it and suggest `ati skills show <name>` to read the full guide. Be concise and practical. Format each recommendation as:

1. **tool_name** — description
   ```
   ati call tool_name --arg1 value1 --arg2 value2
   ```

Only recommend tools from the list above. If no tool matches, say so clearly."#;

/// Execute: ati help "natural language query"
///
/// Auto-detects mode:
/// - If ATI_PROXY_URL is set → forwards to proxy's /help endpoint
/// - Otherwise → loads local keyring, calls LLM directly
pub async fn execute(
    cli: &Cli,
    query: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Auto-detect: proxy mode if ATI_PROXY_URL is set
    if let Ok(proxy_url) = std::env::var("ATI_PROXY_URL") {
        if cli.verbose {
            eprintln!("Mode: proxy (ATI_PROXY_URL={proxy_url})");
        }
        return execute_via_proxy(cli, query, &proxy_url).await;
    }

    if cli.verbose {
        eprintln!("Mode: local (no ATI_PROXY_URL)");
    }
    execute_local(cli, query).await
}

/// Local mode: load manifests + keyring, call LLM directly.
async fn execute_local(
    cli: &Cli,
    query: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ati_dir = ati_dir();

    // Load manifests and scopes
    let manifests_dir = ati_dir.join("manifests");
    let registry = ManifestRegistry::load(&manifests_dir)?;

    let scopes_path = ati_dir.join("scopes.json");
    let scopes = if scopes_path.exists() {
        let s = ScopeConfig::load(&scopes_path)?;
        if !s.help_enabled() {
            return Err("Help is not enabled in your scopes. Add 'help' to your scopes list.".into());
        }
        s
    } else {
        ScopeConfig::unrestricted()
    };

    // Build tool context from in-scope tools
    let all_tools = registry.list_public_tools();
    let scoped_tools = scope::filter_tools_by_scope(all_tools, &scopes);
    let tools_context = build_tool_context(&scoped_tools);

    // Load skills and resolve by scopes
    let skills_dir = ati_dir.join("skills");
    let skill_registry = SkillRegistry::load(&skills_dir).unwrap_or_else(|_| {
        SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap()
    });
    let resolved_skills = skill::resolve_skills(&skill_registry, &registry, &scopes);
    let skills_section = if resolved_skills.is_empty() {
        String::new()
    } else {
        format!(
            "## Available Skills (methodology guides)\n{}",
            skill::build_skill_context(&resolved_skills)
        )
    };

    let system_prompt = HELP_SYSTEM_PROMPT
        .replace("{tools}", &tools_context)
        .replace("{skills_section}", &skills_section);

    if cli.verbose {
        eprintln!("System prompt length: {} chars", system_prompt.len());
        eprintln!("Tools in context: {}", scoped_tools.len());
        eprintln!("Skills in context: {}", resolved_skills.len());
    }

    // Look up the _llm provider for chat completions
    let (llm_provider, llm_tool) = registry
        .get_tool("_chat_completion")
        .ok_or("No _llm.toml manifest found. ATI help requires a configured LLM provider.")?;

    // Load keyring for LLM API key
    let keyring_path = ati_dir.join("keyring.enc");
    let keyring = if keyring_path.exists() {
        Keyring::load(&keyring_path)?
    } else {
        return Err("No keyring found. ATI help requires an LLM API key.".into());
    };

    // Get LLM API key
    let api_key = llm_provider
        .auth_key_name
        .as_deref()
        .and_then(|k| keyring.get(k))
        .ok_or("LLM API key not found in keyring")?;

    // Build chat completion request
    let request_body = serde_json::json!({
        "model": "zai-glm-4.7",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": query}
        ],
        "max_completion_tokens": 1024,
        "temperature": 0.3
    });

    // Make the request
    let client = reqwest::Client::new();
    let url = format!(
        "{}{}",
        llm_provider.base_url.trim_end_matches('/'),
        llm_tool.endpoint
    );

    let response = client
        .post(&url)
        .bearer_auth(api_key)
        .json(&request_body)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("LLM API error ({status}): {body}").into());
    }

    let body: serde_json::Value = response.json().await?;

    // Extract the assistant's message
    let content = body
        .pointer("/choices/0/message/content")
        .and_then(|c| c.as_str())
        .unwrap_or("No response from LLM");

    println!("{content}");
    Ok(())
}

/// Proxy mode: forward the help query to the proxy server.
async fn execute_via_proxy(
    cli: &Cli,
    query: &str,
    proxy_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if cli.verbose {
        eprintln!("Query: {query}");
        eprintln!("Proxy: {proxy_url}");
    }

    let content = proxy_client::call_help(proxy_url, query).await?;
    println!("{content}");
    Ok(())
}

/// Build tool context string from scoped tools for the LLM system prompt.
/// Includes category and tags for better semantic matching in `ati assist`.
fn build_tool_context(
    scoped_tools: &[(&crate::core::manifest::Provider, &crate::core::manifest::Tool)],
) -> String {
    let mut tool_summaries = Vec::new();
    for (provider, tool) in scoped_tools {
        let mut summary = if let Some(cat) = &provider.category {
            format!(
                "- **{}** (provider: {}, category: {}): {}",
                tool.name, provider.name, cat, tool.description
            )
        } else {
            format!(
                "- **{}** (provider: {}): {}",
                tool.name, provider.name, tool.description
            )
        };
        if !tool.tags.is_empty() {
            summary.push_str(&format!("\n  Tags: {}", tool.tags.join(", ")));
        }
        if let Some(schema) = &tool.input_schema {
            if let Some(props) = schema.get("properties") {
                if let Some(obj) = props.as_object() {
                    let params: Vec<String> = obj
                        .iter()
                        .filter(|(_, v)| {
                            // Skip internal metadata fields from display
                            v.get("x-ati-param-location").is_none()
                                || v.get("description").is_some()
                        })
                        .map(|(k, v)| {
                            let type_str = v.get("type").and_then(|t| t.as_str()).unwrap_or("string");
                            let desc = v.get("description").and_then(|d| d.as_str()).unwrap_or("");
                            format!("    --{k} ({type_str}): {desc}")
                        })
                        .collect();
                    if !params.is_empty() {
                        summary.push_str("\n  Parameters:\n");
                        summary.push_str(&params.join("\n"));
                    }
                }
            }
        }
        tool_summaries.push(summary);
    }
    tool_summaries.join("\n\n")
}
