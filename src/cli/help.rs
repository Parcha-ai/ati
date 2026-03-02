use std::path::PathBuf;

use crate::core::keyring::Keyring;
use crate::core::manifest::ManifestRegistry;
use crate::core::scope::{self, ScopeConfig};
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

{tools}

Given the user's query, recommend the most relevant tools and provide exact `ati call` commands with the right arguments. Be concise and practical. Format each recommendation as:

1. **tool_name** — description
   ```
   ati call tool_name --arg1 value1 --arg2 value2
   ```

Only recommend tools from the list above. If no tool matches, say so clearly."#;

/// Execute: ati help "natural language query"
pub async fn execute(
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

    let mut tool_summaries = Vec::new();
    for (provider, tool) in &scoped_tools {
        let mut summary = format!("- **{}** (provider: {}): {}", tool.name, provider.name, tool.description);
        if let Some(schema) = &tool.input_schema {
            if let Some(props) = schema.get("properties") {
                if let Some(obj) = props.as_object() {
                    let params: Vec<String> = obj
                        .iter()
                        .map(|(k, v)| {
                            let type_str = v.get("type").and_then(|t| t.as_str()).unwrap_or("string");
                            let desc = v.get("description").and_then(|d| d.as_str()).unwrap_or("");
                            format!("    --{k} ({type_str}): {desc}")
                        })
                        .collect();
                    summary.push_str("\n  Parameters:\n");
                    summary.push_str(&params.join("\n"));
                }
            }
        }
        tool_summaries.push(summary);
    }

    let tools_context = tool_summaries.join("\n\n");
    let system_prompt = HELP_SYSTEM_PROMPT.replace("{tools}", &tools_context);

    if cli.verbose {
        eprintln!("System prompt length: {} chars", system_prompt.len());
        eprintln!("Tools in context: {}", scoped_tools.len());
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
        "model": "llama-4-scout-17b-16e-instruct",
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
