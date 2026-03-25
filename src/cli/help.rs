use super::common;
use crate::core::jwt;
use crate::core::manifest::{ManifestRegistry, Provider, Tool};
use crate::core::scope::{self, ScopeConfig};
use crate::core::skill::SkillRegistry;
use crate::proxy::client as proxy_client;
use crate::Cli;
use std::process::{Command, Stdio};
use std::time::Duration;

const HELP_SYSTEM_PROMPT: &str = r#"You are a helpful assistant for an AI agent that uses external tools via the `ati` CLI.

## Available Tools
{tools}

{skills_section}

Answer the agent's question naturally, like a knowledgeable colleague would. Keep it short but useful:

- Explain which tools to use and why, with `ati run` commands showing realistic parameter values
- If multiple steps are needed, walk through them briefly in order
- Mention important gotchas or parameter choices that matter
- If skills were loaded, apply their guidance directly in your answer

Keep your answer concise — a few short paragraphs with embedded code blocks, not a formal report. Only recommend tools from the list above."#;

const SCOPED_HELP_SYSTEM_PROMPT: &str = r#"You are an expert on the `{tool_name}` tool, accessed via the `ati` CLI.

## Tool Details
{tool_details}

{skills_section}

The agent runs this tool via: `ati run {tool_name} -- <args>`

Answer the agent's question directly and concisely. Show exact commands with realistic values, explain parameter choices that matter, and mention gotchas. If skills were loaded, apply their guidance naturally. Keep it short — a helpful answer, not a manual."#;

/// Maximum characters of CLI --help output to include in context.
const CLI_HELP_MAX_CHARS: usize = 3000;

/// Timeout for capturing CLI --help output.
const CLI_HELP_TIMEOUT: Duration = Duration::from_secs(5);

/// Execute: ati assist [tool_or_provider] "natural language query"
/// With optional plan mode (--plan / --save).
pub async fn execute_with_plan(
    cli: &Cli,
    args: &[String],
    plan: bool,
    save: Option<&str>,
    local: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let plan_mode = plan || save.is_some();

    if plan_mode {
        return execute_plan_mode(cli, args, save, local).await;
    }

    execute(cli, args, local).await
}

/// Execute: ati assist [tool_or_provider] "natural language query"
///
/// Auto-detects mode:
/// - If ATI_PROXY_URL is set -> forwards to proxy's /help endpoint
/// - Otherwise -> loads local keyring, calls LLM directly
///
/// If the first positional arg matches a tool or provider name, scopes to that tool/provider.
pub async fn execute(
    cli: &Cli,
    args: &[String],
    local: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Auto-detect: proxy mode if ATI_PROXY_URL is set
    if let Ok(proxy_url) = std::env::var("ATI_PROXY_URL") {
        tracing::debug!(proxy_url = %proxy_url, "mode: proxy");
        // In proxy mode, we need to load registry to resolve scope (if any)
        let ati_dir = common::ati_dir();
        let manifests_dir = ati_dir.join("manifests");
        let registry =
            ManifestRegistry::load(&manifests_dir).unwrap_or_else(|_| ManifestRegistry::empty());
        let (scope_name, query) = resolve_assist_scope(args, &registry);
        if let Some(ref s) = scope_name {
            tracing::debug!(scope = %s, "scoped assist");
        }
        return execute_via_proxy(cli, &query, scope_name.as_deref(), &proxy_url).await;
    }

    tracing::debug!("mode: local (no ATI_PROXY_URL)");
    execute_local(cli, args, local).await
}

/// Parse the args to detect tool/provider scoping.
///
/// If the first arg matches a tool name or provider name, it's treated as a scope.
/// Returns (scope, query).
fn resolve_assist_scope(args: &[String], registry: &ManifestRegistry) -> (Option<String>, String) {
    if args.len() >= 2 {
        let candidate = &args[0];
        if registry.get_tool(candidate).is_some() || registry.has_provider(candidate) {
            return (Some(candidate.clone()), args[1..].join(" "));
        }
    }
    // No scope detected — entire args vector is the query
    (None, args.join(" "))
}

/// Capture CLI help text by running `<command> --help` with fallback to `<command> help`.
///
/// Returns None if the command fails, is not found, or times out.
fn capture_cli_help(provider: &Provider) -> Option<String> {
    let command = provider.cli_command.as_deref()?;

    // Try --help first
    if let Some(text) = try_capture_help(command, &["--help"]) {
        return Some(text);
    }

    // Fallback: try `help` subcommand
    try_capture_help(command, &["help"])
}

/// Attempt to run a command with given args and capture stdout/stderr.
fn try_capture_help(command: &str, help_args: &[&str]) -> Option<String> {
    let child = Command::new(command)
        .args(help_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    // Use wait_with_output with a manual timeout via thread
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let output = child.wait_with_output();
        let _ = tx.send(output);
    });

    let output = match rx.recv_timeout(CLI_HELP_TIMEOUT) {
        Ok(result) => result.ok()?,
        Err(_) => {
            // Timeout — drop the thread handle (child process will be cleaned up)
            drop(handle);
            return None;
        }
    };
    let _ = handle.join();

    // Prefer stdout, fall back to stderr (many CLIs print help to stderr)
    let text = if !output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stdout).to_string()
    } else if !output.stderr.is_empty() {
        String::from_utf8_lossy(&output.stderr).to_string()
    } else {
        return None;
    };

    let text = text.trim().to_string();
    if text.is_empty() {
        return None;
    }

    // Truncate to limit
    Some(truncate_help_text(&text, CLI_HELP_MAX_CHARS))
}

/// Truncate help text to a maximum character count, adding a marker if truncated.
fn truncate_help_text(text: &str, max_chars: usize) -> String {
    if text.len() <= max_chars {
        text.to_string()
    } else {
        let mut truncated: String = text.chars().take(max_chars).collect();
        truncated.push_str("\n[... truncated]");
        truncated
    }
}

/// Local mode: load manifests + keyring, call LLM directly.
async fn execute_local(
    cli: &Cli,
    args: &[String],
    local: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let ati_dir = common::ati_dir();

    // Load manifests
    let manifests_dir = ati_dir.join("manifests");
    let mut registry = ManifestRegistry::load(&manifests_dir)?;

    // Discover MCP tools so assist sees them
    let keyring = crate::cli::call::load_keyring(&ati_dir);
    crate::cli::tools::discover_mcp_tools(&mut registry, &keyring, cli.verbose).await;

    // Resolve scope
    let (scope_name, query) = resolve_assist_scope(args, &registry);

    if let Some(ref s) = scope_name {
        tracing::debug!(scope = %s, "scoped assist");
    }

    // Load scopes from JWT
    let scopes = match std::env::var("ATI_SESSION_TOKEN") {
        Ok(token) if !token.is_empty() => {
            match jwt::inspect(&token) {
                Ok(claims) => {
                    let s = ScopeConfig::from_jwt(&claims);
                    if !s.help_enabled() {
                        return Err("Help is not enabled in your scopes. Add 'help' to your JWT scope claim.".into());
                    }
                    s
                }
                Err(_) => ScopeConfig::unrestricted(),
            }
        }
        _ => ScopeConfig::unrestricted(),
    };

    // Load skills
    let skills_dir = ati_dir.join("skills");
    let skill_registry = SkillRegistry::load(&skills_dir)
        .unwrap_or_else(|_| SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap());

    // Build system prompt — scoped vs unscoped
    let (system_prompt, scoped_tools) = if let Some(ref tool_name) = scope_name {
        // For scoped mode, find skills for the specific tool/provider
        let skills_section =
            build_skills_for_tools(&skill_registry, &[tool_name.as_str()], cli.verbose);
        build_scoped_context(tool_name, &registry, &skills_section, cli.verbose)?
    } else {
        // Unscoped: all public tools, pre-filtered by query
        let all_tools = registry.list_public_tools();
        let scoped = scope::filter_tools_by_scope(all_tools, &scopes);
        let scoped = prefilter_tools_by_query(&scoped, &query, 50);
        let tools_context = build_tool_context(&scoped, false);

        // Find skills for the pre-filtered tools (not just JWT scopes)
        let tool_names: Vec<&str> = scoped.iter().map(|(_, t)| t.name.as_str()).collect();
        let skills_section = build_skills_for_tools(&skill_registry, &tool_names, cli.verbose);

        let prompt = HELP_SYSTEM_PROMPT
            .replace("{tools}", &tools_context)
            .replace("{skills_section}", &skills_section);

        (prompt, scoped)
    };

    tracing::debug!(
        prompt_len = system_prompt.len(),
        tools_in_context = scoped_tools.len(),
        "assist context built"
    );

    // Call LLM and print result
    let content = call_llm(cli, &registry, &keyring, &system_prompt, &query, local).await?;

    match cli.output {
        crate::OutputFormat::Json => {
            // Collect tool names mentioned in the response
            let tools_referenced: Vec<&str> = scoped_tools
                .iter()
                .filter(|(_, t)| content.contains(&t.name))
                .map(|(_, t)| t.name.as_str())
                .collect();
            let json = serde_json::json!({
                "content": content,
                "tools_referenced": tools_referenced,
            });
            println!("{}", serde_json::to_string(&json)?);
        }
        _ => {
            println!("{content}");
            print_tool_reference(&content, &scoped_tools);
        }
    }

    Ok(())
}

/// Build scoped context for a single tool or provider.
///
/// Returns (system_prompt, tools_in_context).
fn build_scoped_context<'a>(
    scope_name: &str,
    registry: &'a ManifestRegistry,
    skills_section: &str,
    verbose: bool,
) -> Result<(String, Vec<(&'a Provider, &'a Tool)>), Box<dyn std::error::Error>> {
    // Check if scope_name is a tool
    if let Some((provider, tool)) = registry.get_tool(scope_name) {
        let tool_details = build_scoped_tool_details(provider, tool, verbose);
        let prompt = SCOPED_HELP_SYSTEM_PROMPT
            .replace("{tool_name}", &tool.name)
            .replace("{tool_details}", &tool_details)
            .replace("{skills_section}", skills_section);
        return Ok((prompt, vec![(provider, tool)]));
    }

    // Check if scope_name is a provider
    if registry.has_provider(scope_name) {
        let tools = registry.tools_by_provider(scope_name);
        if tools.is_empty() {
            return Err(format!("Provider '{}' has no tools registered.", scope_name).into());
        }
        // For provider scope, build detailed context for all tools in the provider
        let tools_context = build_tool_context(&tools, true);
        let prompt = format!(
            "You are an expert assistant for the `{scope_name}` provider's tools, accessed via the `ati` CLI.\n\n\
            ## Tools in provider `{scope_name}`\n{tools_context}\n\n\
            {skills_section}\n\n\
            Answer the agent's question about these tools. Provide exact `ati run` commands, explain parameters, and give practical examples. Be concise and actionable."
        );
        return Ok((prompt, tools));
    }

    Err(format!("'{}' is not a known tool or provider.", scope_name).into())
}

/// Build detailed context for a single tool (used in scoped mode).
fn build_scoped_tool_details(provider: &Provider, tool: &Tool, _verbose: bool) -> String {
    let mut details = String::new();

    // Basic info
    details.push_str(&format!("**Name**: `{}`\n", tool.name));
    details.push_str(&format!(
        "**Provider**: {} (handler: {})\n",
        provider.name, provider.handler
    ));
    details.push_str(&format!("**Description**: {}\n", tool.description));

    if let Some(cat) = &provider.category {
        details.push_str(&format!("**Category**: {}\n", cat));
    }
    if !tool.tags.is_empty() {
        details.push_str(&format!("**Tags**: {}\n", tool.tags.join(", ")));
    }
    if let Some(hint) = &tool.hint {
        details.push_str(&format!("**Hint**: {}\n", hint));
    }

    // For CLI tools, capture --help output
    if provider.is_cli() {
        let cmd = provider.cli_command.as_deref().unwrap_or("?");
        details.push_str(&format!("\n**CLI Command**: `{}`\n", cmd));
        if !provider.cli_default_args.is_empty() {
            details.push_str(&format!(
                "**Default Args**: {}\n",
                provider.cli_default_args.join(" ")
            ));
        }
        if let Some(timeout) = provider.cli_timeout_secs {
            details.push_str(&format!("**Timeout**: {}s\n", timeout));
        }
        details.push_str(&format!("\n**Usage**: `ati run {} -- <args>`\n", tool.name));

        // Capture live --help output
        if let Some(help_text) = capture_cli_help(provider) {
            tracing::debug!(
                tool = %tool.name,
                chars = help_text.len(),
                "captured CLI help"
            );
            details.push_str("\n**CLI Help Output** (from `--help`):\n```\n");
            details.push_str(&help_text);
            details.push_str("\n```\n");
        } else {
            tracing::debug!(tool = %tool.name, "could not capture CLI help");
            details.push_str(&format!(
                "\n*CLI help not available. Run `{} --help` manually for usage details.*\n",
                cmd
            ));
        }
    } else {
        // Non-CLI tools: show parameters from schema
        details.push_str(&format!("\n**Usage**: `ati run {}", tool.name));
        if let Some(schema) = &tool.input_schema {
            if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
                let required: Vec<String> = schema
                    .get("required")
                    .and_then(|r| r.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();

                for key in props.keys() {
                    if required.contains(key) {
                        details.push_str(&format!(" --{key} <value>"));
                    }
                }
            }
        }
        details.push_str("`\n");

        if let Some(schema) = &tool.input_schema {
            if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
                let required: Vec<String> = schema
                    .get("required")
                    .and_then(|r| r.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();

                details.push_str("\n**Parameters**:\n");
                for (key, val) in props {
                    let type_str = val.get("type").and_then(|t| t.as_str()).unwrap_or("string");
                    let desc = val
                        .get("description")
                        .and_then(|d| d.as_str())
                        .unwrap_or("");
                    let req = if required.contains(key) {
                        " **(required)**"
                    } else {
                        ""
                    };
                    let enum_vals = val
                        .get("enum")
                        .and_then(|e| e.as_array())
                        .map(|arr| {
                            let vals: Vec<String> = arr
                                .iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect();
                            format!(" [values: {}]", vals.join(", "))
                        })
                        .unwrap_or_default();
                    details.push_str(&format!(
                        "- `--{key}` ({type_str}{req}){enum_vals}: {desc}\n"
                    ));
                }
            }
        }
    }

    // Examples
    if !tool.examples.is_empty() {
        details.push_str("\n**Examples**:\n");
        for ex in &tool.examples {
            details.push_str(&format!("- `{ex}`\n"));
        }
    }

    details
}

/// Call the LLM (Cerebras or Anthropic) with a system prompt and query.
async fn call_llm(
    cli: &Cli,
    registry: &ManifestRegistry,
    keyring: &crate::core::keyring::Keyring,
    system_prompt: &str,
    query: &str,
    local: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    // Check if local LLM is forced via --local flag or ATI_ASSIST_PROVIDER=local
    let force_local =
        local || std::env::var("ATI_ASSIST_PROVIDER").ok().as_deref() == Some("local");
    if force_local {
        return call_local_llm(system_prompt, query, cli.verbose).await;
    }

    // Priority: CEREBRAS_API_KEY (10x faster) -> keyring (credentials + keyring.enc) -> ANTHROPIC_API_KEY
    let cerebras_key = std::env::var("CEREBRAS_API_KEY").ok();

    let keyring_api_key = if cerebras_key.is_none() {
        registry
            .get_tool("_chat_completion")
            .and_then(|(provider, _)| {
                provider
                    .auth_key_name
                    .as_deref()
                    .and_then(|k| keyring.get(k).map(|v| v.to_string()))
            })
    } else {
        None
    };

    if let Some(api_key) = cerebras_key.or(keyring_api_key) {
        let (llm_provider, llm_tool) = registry
            .get_tool("_chat_completion")
            .ok_or("No _llm.toml manifest found. Required for Cerebras assist.")?;

        let request_body = serde_json::json!({
            "model": "zai-glm-4.7",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": query}
            ],
            "max_completion_tokens": 1536,
            "temperature": 0.3
        });

        let client = reqwest::Client::new();
        let url = format!(
            "{}{}",
            llm_provider.base_url.trim_end_matches('/'),
            llm_tool.endpoint
        );

        tracing::debug!(base_url = %llm_provider.base_url, "LLM: Cerebras");

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
        let content = body
            .pointer("/choices/0/message/content")
            .and_then(|c| c.as_str())
            .unwrap_or("No response from LLM");

        Ok(content.to_string())
    } else if let Ok(anthropic_key) = std::env::var("ANTHROPIC_API_KEY") {
        let model = std::env::var("ATI_ASSIST_MODEL")
            .unwrap_or_else(|_| "claude-haiku-4-5-20251001".to_string());

        tracing::debug!(%model, "LLM: Anthropic Messages API");

        let request_body = serde_json::json!({
            "model": model,
            "max_tokens": 1536,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": query}
            ]
        });

        let client = reqwest::Client::new();
        let response = client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &anthropic_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("Anthropic API error ({status}): {body}").into());
        }

        let body: serde_json::Value = response.json().await?;
        let content = body
            .pointer("/content/0/text")
            .and_then(|c| c.as_str())
            .unwrap_or("No response from LLM");

        Ok(content.to_string())
    } else {
        // Auto-fallback to local LLM (ollama, llama.cpp, etc.)
        tracing::debug!("LLM: no cloud keys found, falling back to local LLM");
        call_local_llm(system_prompt, query, cli.verbose).await.map_err(|e| {
            format!(
                "No LLM available. Options:\n\
                 1. Set ANTHROPIC_API_KEY or CEREBRAS_API_KEY for cloud\n\
                 2. Install a local LLM: ollama pull smollm3:3b && ollama serve\n\
                 3. Use any OpenAI-compatible server: OLLAMA_HOST=http://host:port ati assist ...\n\n\
                 Local LLM error: {e}"
            ).into()
        })
    }
}

/// Call a local OpenAI-compatible LLM server (ollama, llama.cpp, llamafile, etc.).
async fn call_local_llm(
    system_prompt: &str,
    query: &str,
    _verbose: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let host =
        std::env::var("OLLAMA_HOST").unwrap_or_else(|_| "http://localhost:11434".to_string());
    let model = std::env::var("ATI_OLLAMA_MODEL").unwrap_or_else(|_| "smollm3:3b".to_string());
    let url = format!("{}/v1/chat/completions", host.trim_end_matches('/'));

    tracing::debug!(%host, %model, "LLM: local");

    let body = serde_json::json!({
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": query}
        ],
        "temperature": 0.3
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?;
    let resp = client.post(&url).json(&body).send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Local LLM error ({status}): {body}").into());
    }

    let resp_body: serde_json::Value = resp.json().await?;
    let content = resp_body
        .pointer("/choices/0/message/content")
        .and_then(|c| c.as_str())
        .unwrap_or("No response from local LLM");

    Ok(content.to_string())
}

/// Proxy mode: forward the help query to the proxy server.
async fn execute_via_proxy(
    cli: &Cli,
    query: &str,
    tool: Option<&str>,
    proxy_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::debug!(%query, scope = ?tool, %proxy_url, "assist via proxy");

    let content = proxy_client::call_help(proxy_url, query, tool).await?;

    match cli.output {
        crate::OutputFormat::Json => {
            let json = serde_json::json!({
                "content": content,
                "tools_referenced": [],
            });
            println!("{}", serde_json::to_string(&json)?);
        }
        _ => {
            println!("{content}");
        }
    }
    Ok(())
}

/// Maximum total characters of skill content to inject into the assist prompt.
const MAX_SKILL_CONTENT_CHARS: usize = 16000;

/// Find skills for the given tool names and build a rich skills section
/// that includes actual SKILL.md content (not just metadata).
///
/// Searches by: tool name binding, provider binding, and keyword matching.
fn build_skills_for_tools(
    skill_registry: &SkillRegistry,
    tool_names: &[&str],
    verbose: bool,
) -> String {
    // Collect unique skills across all matched tools
    let mut seen_skills = std::collections::HashSet::new();
    let mut skill_entries: Vec<(String, String)> = Vec::new(); // (name, content)
    let mut total_chars = 0;

    // Collect provider names from tool names (tool name format: provider:tool)
    let mut provider_names = std::collections::HashSet::new();
    for tool_name in tool_names {
        if let Some(idx) = tool_name.find(crate::core::manifest::TOOL_SEP) {
            provider_names.insert(&tool_name[..idx]);
        }
    }

    // Phase 1: Skills bound to specific tools
    for tool_name in tool_names {
        for skill_meta in skill_registry.skills_for_tool(tool_name) {
            if !seen_skills.insert(skill_meta.name.clone()) {
                continue;
            }
            add_skill_content(
                skill_registry,
                skill_meta,
                &mut skill_entries,
                &mut total_chars,
                verbose,
            );
            if total_chars > MAX_SKILL_CONTENT_CHARS {
                break;
            }
        }
        if total_chars > MAX_SKILL_CONTENT_CHARS {
            break;
        }
    }

    // Phase 2: Skills bound to providers of matched tools
    // Sort provider names for deterministic ordering
    let mut sorted_providers: Vec<&str> = provider_names.into_iter().collect();
    sorted_providers.sort();

    if total_chars < MAX_SKILL_CONTENT_CHARS {
        if !sorted_providers.is_empty() {
            tracing::debug!(providers = ?sorted_providers, "skill search phase 2: by provider");
        }
        for provider_name in &sorted_providers {
            let provider_skills = skill_registry.skills_for_provider(provider_name);
            if !provider_skills.is_empty() {
                tracing::debug!(provider = %provider_name, count = provider_skills.len(), "provider skills found");
            }
            for skill_meta in provider_skills {
                if !seen_skills.insert(skill_meta.name.clone()) {
                    continue;
                }
                add_skill_content(
                    skill_registry,
                    skill_meta,
                    &mut skill_entries,
                    &mut total_chars,
                    verbose,
                );
                if total_chars > MAX_SKILL_CONTENT_CHARS {
                    break;
                }
            }
            if total_chars > MAX_SKILL_CONTENT_CHARS {
                break;
            }
        }
    }

    // Phase 3: Keyword search — match tool names against skill keywords
    if total_chars < MAX_SKILL_CONTENT_CHARS {
        for tool_name in tool_names {
            // Extract meaningful terms from tool name (split on : and _)
            let terms: Vec<&str> = tool_name
                .split(crate::core::manifest::TOOL_SEP)
                .flat_map(|s| s.split('_'))
                .filter(|s| s.len() > 2)
                .collect();
            for skill_meta in skill_registry.search(&terms.join(" ")) {
                if !seen_skills.insert(skill_meta.name.clone()) {
                    continue;
                }
                add_skill_content(
                    skill_registry,
                    skill_meta,
                    &mut skill_entries,
                    &mut total_chars,
                    verbose,
                );
                if total_chars > MAX_SKILL_CONTENT_CHARS {
                    break;
                }
            }
            if total_chars > MAX_SKILL_CONTENT_CHARS {
                break;
            }
        }
    }

    if skill_entries.is_empty() {
        return String::new();
    }

    let mut section = String::from("## Skill Methodologies (loaded for matched tools)\n\n");
    section.push_str("These skills contain expert methodology for using the tools above. Apply their guidance in your recommendations.\n\n");
    for (name, content) in &skill_entries {
        section.push_str(&format!("### Skill: {name}\n\n{content}\n\n"));
    }

    section
}

/// Helper: read and add a skill's SKILL.md content to the entries list.
fn add_skill_content(
    skill_registry: &SkillRegistry,
    skill_meta: &crate::core::skill::SkillMeta,
    skill_entries: &mut Vec<(String, String)>,
    total_chars: &mut usize,
    _verbose: bool,
) {
    match skill_registry.read_content(&skill_meta.name) {
        Ok(content) if !content.is_empty() => {
            let max_per_skill = 4000;
            let truncated = if content.len() > max_per_skill {
                format!("{}...\n[truncated]", &content[..max_per_skill])
            } else {
                content.clone()
            };

            *total_chars += truncated.len();
            skill_entries.push((skill_meta.name.clone(), truncated));
            tracing::debug!(skill = %skill_meta.name, chars = content.len(), "loaded skill content");
        }
        _ => {
            let meta_line = format!(
                "- **{}**: {} (covers: {})",
                skill_meta.name,
                skill_meta.description,
                skill_meta.tools.join(", ")
            );
            skill_entries.push((skill_meta.name.clone(), meta_line));
        }
    }
}

/// Pre-filter tools by fuzzy matching against the query.
/// Returns up to `limit` tools, sorted by relevance score (best first).
/// If fewer than `limit` tools match (score > 0), all tools are returned up to the limit.
fn prefilter_tools_by_query<'a>(
    tools: &[(&'a Provider, &'a Tool)],
    query: &str,
    limit: usize,
) -> Vec<(&'a Provider, &'a Tool)> {
    let query_lower = query.to_lowercase();
    let query_terms: Vec<&str> = query_lower.split_whitespace().collect();

    let mut scored: Vec<(f64, &Provider, &Tool)> = tools
        .iter()
        .map(|(p, t)| {
            let score = crate::cli::tools::score_tool_match(p, t, &query_terms);
            (score, *p, *t)
        })
        .collect();

    // Sort by score descending
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    // If we have enough scored matches, take only those; otherwise pad with unscored
    let matched_count = scored.iter().filter(|(s, _, _)| *s > 0.0).count();
    if matched_count >= limit {
        scored
            .into_iter()
            .filter(|(s, _, _)| *s > 0.0)
            .take(limit)
            .map(|(_, p, t)| (p, t))
            .collect()
    } else {
        // Take all scored matches + fill remaining slots from unscored (preserving original order)
        scored.truncate(limit);
        scored.into_iter().map(|(_, p, t)| (p, t)).collect()
    }
}

/// Scan LLM output for tool names mentioned, append ground-truth usage reference.
fn print_tool_reference(llm_output: &str, scoped_tools: &[(&Provider, &Tool)]) {
    let mut mentioned = Vec::new();
    for (_, tool) in scoped_tools {
        if llm_output.contains(&tool.name) {
            mentioned.push(tool);
        }
    }
    if mentioned.is_empty() {
        return;
    }

    // Deduplicate (a tool name might appear as both short and prefixed form)
    mentioned.sort_by_key(|t| &t.name);
    mentioned.dedup_by_key(|t| &t.name);

    println!("\n---\n**Quick Reference** (from schema)\n");
    for tool in &mentioned {
        println!("**`{}`**", tool.name);
        if let Some(usage) = build_usage_card(tool) {
            println!("```");
            println!("{usage}");
            println!("```");
        }
        if let Some(params) = build_param_table(tool) {
            println!("{params}");
        }
        println!();
    }
}

/// Generate an exact `ati run` command from the tool's input schema.
fn build_usage_card(tool: &Tool) -> Option<String> {
    let schema = tool.input_schema.as_ref()?;
    let props = schema.get("properties")?.as_object()?;
    let required: Vec<String> = schema
        .get("required")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let mut parts = vec![format!("ati run {}", tool.name)];
    for (key, val) in props {
        let is_required = required.iter().any(|r| r == key);
        let type_str = val.get("type").and_then(|t| t.as_str()).unwrap_or("string");
        let placeholder = match type_str {
            "array" => "'[\"value1\", \"value2\"]'".to_string(),
            "integer" | "number" => "<number>".to_string(),
            "boolean" => "true".to_string(),
            _ => format!("<{key}>"),
        };
        if is_required {
            parts.push(format!("--{key} {placeholder}"));
        }
    }
    Some(parts.join(" \\\n  "))
}

/// Generate a param table from the tool's input schema.
fn build_param_table(tool: &Tool) -> Option<String> {
    let schema = tool.input_schema.as_ref()?;
    let props = schema.get("properties")?.as_object()?;
    let required: Vec<String> = schema
        .get("required")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let mut lines = Vec::new();
    // Required params first, then optional
    let mut params: Vec<_> = props.iter().collect();
    params.sort_by_key(|(k, _)| !required.contains(&k.to_string()));

    for (key, val) in &params {
        let is_required = required.iter().any(|r| r == *key);
        let type_str = val.get("type").and_then(|t| t.as_str()).unwrap_or("string");
        let desc = val
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("");
        // Truncate long descriptions to first sentence
        let short_desc = desc
            .split('\n')
            .next()
            .unwrap_or(desc)
            .chars()
            .take(120)
            .collect::<String>();
        let req = if is_required { " **(required)**" } else { "" };
        lines.push(format!("  `--{key}` ({type_str}){req}: {short_desc}"));
    }
    if lines.is_empty() {
        return None;
    }
    Some(lines.join("\n"))
}

/// Plan mode: ask the LLM for a structured plan of tool calls.
async fn execute_plan_mode(
    cli: &Cli,
    args: &[String],
    save: Option<&str>,
    local: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let ati_dir = common::ati_dir();
    let manifests_dir = ati_dir.join("manifests");
    let mut registry = ManifestRegistry::load(&manifests_dir)?;
    let keyring = crate::cli::call::load_keyring(&ati_dir);
    crate::cli::tools::discover_mcp_tools(&mut registry, &keyring, cli.verbose).await;

    let (scope_name, query) = resolve_assist_scope(args, &registry);

    // Load skills
    let skills_dir = ati_dir.join("skills");
    let skill_registry =
        crate::core::skill::SkillRegistry::load(&skills_dir).unwrap_or_else(|_| {
            crate::core::skill::SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap()
        });

    // Build system prompt — similar to normal assist but with plan suffix
    let (system_prompt, _scoped_tools) = if let Some(ref tool_name) = scope_name {
        let skills_section =
            build_skills_for_tools(&skill_registry, &[tool_name.as_str()], cli.verbose);
        build_scoped_context(tool_name, &registry, &skills_section, cli.verbose)?
    } else {
        let all_tools = registry.list_public_tools();
        let scoped =
            crate::core::scope::filter_tools_by_scope(all_tools, &ScopeConfig::unrestricted());
        let scoped = prefilter_tools_by_query(&scoped, &query, 50);
        let tools_context = build_tool_context(&scoped, false);
        let tool_names: Vec<&str> = scoped.iter().map(|(_, t)| t.name.as_str()).collect();
        let skills_section = build_skills_for_tools(&skill_registry, &tool_names, cli.verbose);
        let prompt = HELP_SYSTEM_PROMPT
            .replace("{tools}", &tools_context)
            .replace("{skills_section}", &skills_section);
        (prompt, scoped)
    };

    // Add plan mode suffix to system prompt
    let plan_prompt = format!(
        "{}{}",
        system_prompt,
        crate::cli::plan::PLAN_SYSTEM_PROMPT_SUFFIX
    );

    let content = call_llm(cli, &registry, &keyring, &plan_prompt, &query, local).await?;

    // Parse the LLM response as a plan
    let plan = crate::cli::plan::parse_plan_response(&content, &query).map_err(|e| {
        format!("Failed to parse plan from LLM response: {e}\n\nRaw response:\n{content}")
    })?;

    let json = serde_json::to_string_pretty(&plan)?;

    // Save to file if requested
    if let Some(path) = save {
        std::fs::write(path, &json)?;
        tracing::info!(path = %path, "plan saved");
    }

    // Output the plan
    println!("{json}");

    Ok(())
}

/// Build tool context string from scoped tools for the LLM system prompt.
/// Includes category and tags for better semantic matching in `ati assist`.
///
/// If `include_cli_help` is true, captures --help output for CLI tools.
pub fn build_tool_context(scoped_tools: &[(&Provider, &Tool)], include_cli_help: bool) -> String {
    // Count CLI tools to decide whether to capture help (avoid slowdown with many CLIs)
    let cli_count = scoped_tools.iter().filter(|(p, _)| p.is_cli()).count();
    let capture_cli = include_cli_help || cli_count <= 5;

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

        // CLI tools: capture --help or show passthrough usage
        if provider.is_cli() && tool.input_schema.is_none() {
            let cmd = provider.cli_command.as_deref().unwrap_or("?");
            if capture_cli {
                if let Some(help_text) = capture_cli_help(provider) {
                    summary.push_str("\n  CLI usage (from --help):\n  ```\n");
                    // Indent help lines for readability in the prompt
                    for line in help_text.lines().take(40) {
                        summary.push_str("  ");
                        summary.push_str(line);
                        summary.push('\n');
                    }
                    summary.push_str("  ```");
                } else {
                    summary.push_str(&format!(
                        "\n  Usage: `ati run {} -- <args>`  (passthrough to `{}`)",
                        tool.name, cmd
                    ));
                }
            } else {
                summary.push_str(&format!(
                    "\n  Usage: `ati run {} -- <args>`  (passthrough to `{}`)",
                    tool.name, cmd
                ));
            }
        } else if let Some(schema) = &tool.input_schema {
            // Collect required field names
            let required: Vec<String> = schema
                .get("required")
                .and_then(|r| r.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

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
                            let type_str =
                                v.get("type").and_then(|t| t.as_str()).unwrap_or("string");
                            let desc = v.get("description").and_then(|d| d.as_str()).unwrap_or("");
                            let req_label = if required.iter().any(|r| r == k) {
                                " [REQUIRED]"
                            } else {
                                ""
                            };
                            format!("    --{k} ({type_str}{req_label}): {desc}")
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
