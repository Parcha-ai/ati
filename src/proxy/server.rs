/// ATI proxy server — holds API keys and executes tool calls on behalf of sandbox agents.
///
/// Authentication: ES256-signed JWT (or HS256 fallback). The JWT carries identity,
/// scopes, and expiry. No more static tokens or unsigned scope lists.
///
/// Usage: `ati proxy --port 8080 [--ati-dir ~/.ati]`
use axum::{
    body::Body,
    extract::{Extension, Query, State},
    http::{Request as HttpRequest, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use crate::core::auth_generator::{AuthCache, GenContext};
use crate::core::http;
use crate::core::jwt::{self, JwtConfig, TokenClaims};
use crate::core::keyring::Keyring;
use crate::core::manifest::{ManifestRegistry, Provider, Tool};
use crate::core::mcp_client;
use crate::core::response;
use crate::core::scope::ScopeConfig;
use crate::core::skill::{self, SkillRegistry};
use crate::core::skillati::{RemoteSkillMeta, SkillAtiClient, SkillAtiError};
use crate::core::xai;

/// Shared state for the proxy server.
pub struct ProxyState {
    pub registry: ManifestRegistry,
    pub skill_registry: SkillRegistry,
    pub keyring: Keyring,
    /// JWT validation config (None = auth disabled / dev mode).
    pub jwt_config: Option<JwtConfig>,
    /// Pre-computed JWKS JSON for the /.well-known/jwks.json endpoint.
    pub jwks_json: Option<Value>,
    /// Shared cache for dynamically generated auth credentials.
    pub auth_cache: AuthCache,
}

// --- Request/Response types ---

#[derive(Debug, Deserialize)]
pub struct CallRequest {
    pub tool_name: String,
    /// Tool arguments — accepts a JSON object (key-value pairs) for HTTP/MCP/OpenAPI tools,
    /// or a JSON array of strings / a single string for CLI tools.
    /// The proxy auto-detects the handler type and routes accordingly.
    #[serde(default = "default_args")]
    pub args: Value,
    /// Deprecated: use `args` with an array value instead.
    /// Kept for backward compatibility — if present, takes precedence for CLI tools.
    #[serde(default)]
    pub raw_args: Option<Vec<String>>,
}

fn default_args() -> Value {
    Value::Object(serde_json::Map::new())
}

impl CallRequest {
    /// Extract args as a HashMap for HTTP/MCP/OpenAPI tools.
    /// If `args` is a JSON object, returns its entries.
    /// If `args` is something else (array, string), returns an empty map.
    fn args_as_map(&self) -> HashMap<String, Value> {
        match &self.args {
            Value::Object(map) => map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            _ => HashMap::new(),
        }
    }

    /// Extract positional args for CLI tools.
    /// Priority: explicit `raw_args` field > `args` array > `args` string > `args._positional` > empty.
    fn args_as_positional(&self) -> Vec<String> {
        // Backward compat: explicit raw_args wins
        if let Some(ref raw) = self.raw_args {
            return raw.clone();
        }
        match &self.args {
            // ["pr", "list", "--repo", "X"]
            Value::Array(arr) => arr
                .iter()
                .map(|v| match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect(),
            // "pr list --repo X"
            Value::String(s) => s.split_whitespace().map(String::from).collect(),
            // {"_positional": ["pr", "list"]} or {"--key": "value"} converted to CLI flags
            Value::Object(map) => {
                if let Some(Value::Array(pos)) = map.get("_positional") {
                    return pos
                        .iter()
                        .map(|v| match v {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        })
                        .collect();
                }
                // Convert map entries to --key value pairs
                let mut result = Vec::new();
                for (k, v) in map {
                    result.push(format!("--{k}"));
                    match v {
                        Value::String(s) => result.push(s.clone()),
                        Value::Bool(true) => {} // flag, no value needed
                        other => result.push(other.to_string()),
                    }
                }
                result
            }
            _ => Vec::new(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CallResponse {
    pub result: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HelpRequest {
    pub query: String,
    #[serde(default)]
    pub tool: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HelpResponse {
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub tools: usize,
    pub providers: usize,
    pub skills: usize,
    pub auth: String,
}

// --- Skill endpoint types ---

#[derive(Debug, Deserialize)]
pub struct SkillsQuery {
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub search: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SkillDetailQuery {
    #[serde(default)]
    pub meta: Option<bool>,
    #[serde(default)]
    pub refs: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct SkillResolveRequest {
    pub scopes: Vec<String>,
    /// When true, include SKILL.md content in each resolved skill.
    #[serde(default)]
    pub include_content: bool,
}

#[derive(Debug, Deserialize)]
pub struct SkillBundleBatchRequest {
    pub names: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct SkillAtiCatalogQuery {
    #[serde(default)]
    pub search: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct SkillAtiResourcesQuery {
    #[serde(default)]
    pub prefix: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SkillAtiFileQuery {
    pub path: String,
}

// --- Tool endpoint types ---

#[derive(Debug, Deserialize)]
pub struct ToolsQuery {
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub search: Option<String>,
}

// --- Handlers ---

fn scopes_for_request(claims: Option<&TokenClaims>, state: &ProxyState) -> ScopeConfig {
    match claims {
        Some(claims) => ScopeConfig::from_jwt(claims),
        None if state.jwt_config.is_none() => ScopeConfig::unrestricted(),
        None => ScopeConfig {
            scopes: Vec::new(),
            sub: String::new(),
            expires_at: 0,
            rate_config: None,
        },
    }
}

fn visible_tools_for_scopes<'a>(
    state: &'a ProxyState,
    scopes: &ScopeConfig,
) -> Vec<(&'a Provider, &'a Tool)> {
    crate::core::scope::filter_tools_by_scope(state.registry.list_public_tools(), scopes)
}

fn visible_skill_names(
    state: &ProxyState,
    scopes: &ScopeConfig,
) -> std::collections::HashSet<String> {
    skill::visible_skills(&state.skill_registry, &state.registry, scopes)
        .into_iter()
        .map(|skill| skill.name.clone())
        .collect()
}

async fn handle_call(
    State(state): State<Arc<ProxyState>>,
    req: HttpRequest<Body>,
) -> impl IntoResponse {
    // Extract JWT claims from request extensions (set by auth middleware)
    let claims = req.extensions().get::<TokenClaims>().cloned();

    // Parse request body
    let body_bytes = match axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(CallResponse {
                    result: Value::Null,
                    error: Some(format!("Failed to read request body: {e}")),
                }),
            );
        }
    };

    let call_req: CallRequest = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(CallResponse {
                    result: Value::Null,
                    error: Some(format!("Invalid request: {e}")),
                }),
            );
        }
    };

    tracing::debug!(
        tool = %call_req.tool_name,
        args = ?call_req.args,
        "POST /call"
    );

    // Look up tool in registry.
    // If not found, try converting underscore format (finnhub_quote) to colon (finnhub:quote).
    let (provider, tool) = match state.registry.get_tool(&call_req.tool_name) {
        Some(pt) => pt,
        None => {
            // Try underscore → colon conversion at each underscore position.
            // "finnhub_quote" → try "finnhub:quote"
            // "test_api_get_data" → try "test:api_get_data", "test_api:get_data"
            let mut resolved = None;
            for (idx, _) in call_req.tool_name.match_indices('_') {
                let candidate = format!(
                    "{}:{}",
                    &call_req.tool_name[..idx],
                    &call_req.tool_name[idx + 1..]
                );
                if let Some(pt) = state.registry.get_tool(&candidate) {
                    tracing::debug!(
                        original = %call_req.tool_name,
                        resolved = %candidate,
                        "resolved underscore tool name to colon format"
                    );
                    resolved = Some(pt);
                    break;
                }
            }

            match resolved {
                Some(pt) => pt,
                None => {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(CallResponse {
                            result: Value::Null,
                            error: Some(format!("Unknown tool: '{}'", call_req.tool_name)),
                        }),
                    );
                }
            }
        }
    };

    // Scope enforcement from JWT claims
    if let Some(tool_scope) = &tool.scope {
        let scopes = match &claims {
            Some(c) => ScopeConfig::from_jwt(c),
            None if state.jwt_config.is_none() => ScopeConfig::unrestricted(), // Dev mode
            None => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(CallResponse {
                        result: Value::Null,
                        error: Some("Authentication required — no JWT provided".into()),
                    }),
                );
            }
        };

        if !scopes.is_allowed(tool_scope) {
            return (
                StatusCode::FORBIDDEN,
                Json(CallResponse {
                    result: Value::Null,
                    error: Some(format!(
                        "Access denied: '{}' is not in your scopes",
                        tool.name
                    )),
                }),
            );
        }
    }

    // Rate limit check
    {
        let scopes = match &claims {
            Some(c) => ScopeConfig::from_jwt(c),
            None => ScopeConfig::unrestricted(),
        };
        if let Some(ref rate_config) = scopes.rate_config {
            if let Err(e) = crate::core::rate::check_and_record(&call_req.tool_name, rate_config) {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(CallResponse {
                        result: Value::Null,
                        error: Some(format!("{e}")),
                    }),
                );
            }
        }
    }

    // Build auth generator context from JWT claims
    let gen_ctx = GenContext {
        jwt_sub: claims
            .as_ref()
            .map(|c| c.sub.clone())
            .unwrap_or_else(|| "dev".into()),
        jwt_scope: claims
            .as_ref()
            .map(|c| c.scope.clone())
            .unwrap_or_else(|| "*".into()),
        tool_name: call_req.tool_name.clone(),
        timestamp: crate::core::jwt::now_secs(),
    };

    // Execute tool call — dispatch based on handler type, with timing for audit
    let agent_sub = claims.as_ref().map(|c| c.sub.clone()).unwrap_or_default();
    let start = std::time::Instant::now();

    let response = match provider.handler.as_str() {
        "mcp" => {
            let args_map = call_req.args_as_map();
            match mcp_client::execute_with_gen(
                provider,
                &call_req.tool_name,
                &args_map,
                &state.keyring,
                Some(&gen_ctx),
                Some(&state.auth_cache),
            )
            .await
            {
                Ok(result) => (
                    StatusCode::OK,
                    Json(CallResponse {
                        result,
                        error: None,
                    }),
                ),
                Err(e) => (
                    StatusCode::BAD_GATEWAY,
                    Json(CallResponse {
                        result: Value::Null,
                        error: Some(format!("MCP error: {e}")),
                    }),
                ),
            }
        }
        "cli" => {
            let positional = call_req.args_as_positional();
            match crate::core::cli_executor::execute_with_gen(
                provider,
                &positional,
                &state.keyring,
                Some(&gen_ctx),
                Some(&state.auth_cache),
            )
            .await
            {
                Ok(result) => (
                    StatusCode::OK,
                    Json(CallResponse {
                        result,
                        error: None,
                    }),
                ),
                Err(e) => (
                    StatusCode::BAD_GATEWAY,
                    Json(CallResponse {
                        result: Value::Null,
                        error: Some(format!("CLI error: {e}")),
                    }),
                ),
            }
        }
        _ => {
            let args_map = call_req.args_as_map();
            let raw_response = match match provider.handler.as_str() {
                "xai" => xai::execute_xai_tool(provider, tool, &args_map, &state.keyring).await,
                _ => {
                    http::execute_tool_with_gen(
                        provider,
                        tool,
                        &args_map,
                        &state.keyring,
                        Some(&gen_ctx),
                        Some(&state.auth_cache),
                    )
                    .await
                }
            } {
                Ok(resp) => resp,
                Err(e) => {
                    let duration = start.elapsed();
                    write_proxy_audit(&call_req, &agent_sub, duration, Some(&e.to_string()));
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(CallResponse {
                            result: Value::Null,
                            error: Some(format!("Upstream API error: {e}")),
                        }),
                    );
                }
            };

            let processed = match response::process_response(&raw_response, tool.response.as_ref())
            {
                Ok(p) => p,
                Err(e) => {
                    let duration = start.elapsed();
                    write_proxy_audit(&call_req, &agent_sub, duration, Some(&e.to_string()));
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(CallResponse {
                            result: raw_response,
                            error: Some(format!("Response processing error: {e}")),
                        }),
                    );
                }
            };

            (
                StatusCode::OK,
                Json(CallResponse {
                    result: processed,
                    error: None,
                }),
            )
        }
    };

    let duration = start.elapsed();
    let error_msg = response.1.error.as_deref();
    write_proxy_audit(&call_req, &agent_sub, duration, error_msg);

    response
}

async fn handle_help(
    State(state): State<Arc<ProxyState>>,
    claims: Option<Extension<TokenClaims>>,
    Json(req): Json<HelpRequest>,
) -> impl IntoResponse {
    tracing::debug!(query = %req.query, tool = ?req.tool, "POST /help");

    let claims = claims.map(|Extension(claims)| claims);
    let scopes = scopes_for_request(claims.as_ref(), &state);
    if !scopes.help_enabled() {
        return (
            StatusCode::FORBIDDEN,
            Json(HelpResponse {
                content: String::new(),
                error: Some("Help is not enabled in your scopes.".into()),
            }),
        );
    }

    let (llm_provider, llm_tool) = match state.registry.get_tool("_chat_completion") {
        Some(pt) => pt,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(HelpResponse {
                    content: String::new(),
                    error: Some("No _llm.toml manifest found. Proxy help requires a configured LLM provider.".into()),
                }),
            );
        }
    };

    let api_key = match llm_provider
        .auth_key_name
        .as_deref()
        .and_then(|k| state.keyring.get(k))
    {
        Some(key) => key.to_string(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(HelpResponse {
                    content: String::new(),
                    error: Some("LLM API key not found in keyring".into()),
                }),
            );
        }
    };

    let resolved_skills = skill::resolve_skills(&state.skill_registry, &state.registry, &scopes);
    let local_skills_section = if resolved_skills.is_empty() {
        String::new()
    } else {
        format!(
            "## Available Skills (methodology guides)\n{}",
            skill::build_skill_context(&resolved_skills)
        )
    };
    let remote_query = req
        .tool
        .as_ref()
        .map(|tool| format!("{tool} {}", req.query))
        .unwrap_or_else(|| req.query.clone());
    let remote_skills_section =
        build_remote_skillati_section(&state.keyring, &remote_query, 12).await;
    let skills_section = merge_help_skill_sections(&[local_skills_section, remote_skills_section]);

    // Build system prompt — scoped or unscoped
    let visible_tools = visible_tools_for_scopes(&state, &scopes);
    let system_prompt = if let Some(ref tool_name) = req.tool {
        // Scoped mode: narrow tools to the specified tool or provider
        match build_scoped_prompt(tool_name, &visible_tools, &skills_section) {
            Some(prompt) => prompt,
            None => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(HelpResponse {
                        content: String::new(),
                        error: Some(format!(
                            "Scope '{tool_name}' is not visible in your current scopes."
                        )),
                    }),
                );
            }
        }
    } else {
        let tools_context = build_tool_context(&visible_tools);
        HELP_SYSTEM_PROMPT
            .replace("{tools}", &tools_context)
            .replace("{skills_section}", &skills_section)
    };

    let request_body = serde_json::json!({
        "model": "zai-glm-4.7",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": req.query}
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

    let response = match client
        .post(&url)
        .bearer_auth(&api_key)
        .json(&request_body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(HelpResponse {
                    content: String::new(),
                    error: Some(format!("LLM request failed: {e}")),
                }),
            );
        }
    };

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return (
            StatusCode::BAD_GATEWAY,
            Json(HelpResponse {
                content: String::new(),
                error: Some(format!("LLM API error ({status}): {body}")),
            }),
        );
    }

    let body: Value = match response.json().await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(HelpResponse {
                    content: String::new(),
                    error: Some(format!("Failed to parse LLM response: {e}")),
                }),
            );
        }
    };

    let content = body
        .pointer("/choices/0/message/content")
        .and_then(|c| c.as_str())
        .unwrap_or("No response from LLM")
        .to_string();

    (
        StatusCode::OK,
        Json(HelpResponse {
            content,
            error: None,
        }),
    )
}

async fn handle_health(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    let auth = if state.jwt_config.is_some() {
        "jwt"
    } else {
        "disabled"
    };

    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        tools: state.registry.list_public_tools().len(),
        providers: state.registry.list_providers().len(),
        skills: state.skill_registry.skill_count(),
        auth: auth.into(),
    })
}

/// GET /.well-known/jwks.json — serves the public key for JWT validation.
async fn handle_jwks(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    match &state.jwks_json {
        Some(jwks) => (StatusCode::OK, Json(jwks.clone())),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "JWKS not configured"})),
        ),
    }
}

// ---------------------------------------------------------------------------
// POST /mcp — MCP JSON-RPC proxy endpoint
// ---------------------------------------------------------------------------

async fn handle_mcp(
    State(state): State<Arc<ProxyState>>,
    claims: Option<Extension<TokenClaims>>,
    Json(msg): Json<Value>,
) -> impl IntoResponse {
    let claims = claims.map(|Extension(claims)| claims);
    let scopes = scopes_for_request(claims.as_ref(), &state);
    let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = msg.get("id").cloned();

    tracing::debug!(%method, "POST /mcp");

    match method {
        "initialize" => {
            let result = serde_json::json!({
                "protocolVersion": "2025-03-26",
                "capabilities": {
                    "tools": { "listChanged": false }
                },
                "serverInfo": {
                    "name": "ati-proxy",
                    "version": env!("CARGO_PKG_VERSION")
                }
            });
            jsonrpc_success(id, result)
        }

        "notifications/initialized" => (StatusCode::ACCEPTED, Json(Value::Null)),

        "tools/list" => {
            let visible_tools = visible_tools_for_scopes(&state, &scopes);
            let mcp_tools: Vec<Value> = visible_tools
                .iter()
                .map(|(_provider, tool)| {
                    serde_json::json!({
                        "name": tool.name,
                        "description": tool.description,
                        "inputSchema": tool.input_schema.clone().unwrap_or(serde_json::json!({
                            "type": "object",
                            "properties": {}
                        }))
                    })
                })
                .collect();

            let result = serde_json::json!({
                "tools": mcp_tools,
            });
            jsonrpc_success(id, result)
        }

        "tools/call" => {
            let params = msg.get("params").cloned().unwrap_or(Value::Null);
            let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let arguments: HashMap<String, Value> = params
                .get("arguments")
                .and_then(|a| serde_json::from_value(a.clone()).ok())
                .unwrap_or_default();

            if tool_name.is_empty() {
                return jsonrpc_error(id, -32602, "Missing tool name in params.name");
            }

            let (provider, _tool) = match state.registry.get_tool(tool_name) {
                Some(pt) => pt,
                None => {
                    return jsonrpc_error(id, -32602, &format!("Unknown tool: '{tool_name}'"));
                }
            };

            if let Some(tool_scope) = &_tool.scope {
                if !scopes.is_allowed(tool_scope) {
                    return jsonrpc_error(
                        id,
                        -32001,
                        &format!("Access denied: '{}' is not in your scopes", _tool.name),
                    );
                }
            }

            tracing::debug!(%tool_name, provider = %provider.name, "MCP tools/call");

            let mcp_gen_ctx = GenContext {
                jwt_sub: claims
                    .as_ref()
                    .map(|claims| claims.sub.clone())
                    .unwrap_or_else(|| "dev".into()),
                jwt_scope: claims
                    .as_ref()
                    .map(|claims| claims.scope.clone())
                    .unwrap_or_else(|| "*".into()),
                tool_name: tool_name.to_string(),
                timestamp: crate::core::jwt::now_secs(),
            };

            let result = if provider.is_mcp() {
                mcp_client::execute_with_gen(
                    provider,
                    tool_name,
                    &arguments,
                    &state.keyring,
                    Some(&mcp_gen_ctx),
                    Some(&state.auth_cache),
                )
                .await
            } else if provider.is_cli() {
                // Convert arguments map to CLI-style args for MCP passthrough
                let raw: Vec<String> = arguments
                    .iter()
                    .flat_map(|(k, v)| {
                        let val = match v {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        };
                        vec![format!("--{k}"), val]
                    })
                    .collect();
                crate::core::cli_executor::execute_with_gen(
                    provider,
                    &raw,
                    &state.keyring,
                    Some(&mcp_gen_ctx),
                    Some(&state.auth_cache),
                )
                .await
                .map_err(|e| mcp_client::McpError::Transport(e.to_string()))
            } else {
                match match provider.handler.as_str() {
                    "xai" => {
                        xai::execute_xai_tool(provider, _tool, &arguments, &state.keyring).await
                    }
                    _ => {
                        http::execute_tool_with_gen(
                            provider,
                            _tool,
                            &arguments,
                            &state.keyring,
                            Some(&mcp_gen_ctx),
                            Some(&state.auth_cache),
                        )
                        .await
                    }
                } {
                    Ok(val) => Ok(val),
                    Err(e) => Err(mcp_client::McpError::Transport(e.to_string())),
                }
            };

            match result {
                Ok(value) => {
                    let text = match &value {
                        Value::String(s) => s.clone(),
                        other => serde_json::to_string_pretty(other).unwrap_or_default(),
                    };
                    let mcp_result = serde_json::json!({
                        "content": [{"type": "text", "text": text}],
                        "isError": false,
                    });
                    jsonrpc_success(id, mcp_result)
                }
                Err(e) => {
                    let mcp_result = serde_json::json!({
                        "content": [{"type": "text", "text": format!("Error: {e}")}],
                        "isError": true,
                    });
                    jsonrpc_success(id, mcp_result)
                }
            }
        }

        _ => jsonrpc_error(id, -32601, &format!("Method not found: '{method}'")),
    }
}

fn jsonrpc_success(id: Option<Value>, result: Value) -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        })),
    )
}

fn jsonrpc_error(id: Option<Value>, code: i64, message: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code,
                "message": message,
            }
        })),
    )
}

// ---------------------------------------------------------------------------
// Tool endpoints
// ---------------------------------------------------------------------------

/// GET /tools — list available tools with optional filters.
async fn handle_tools_list(
    State(state): State<Arc<ProxyState>>,
    claims: Option<Extension<TokenClaims>>,
    axum::extract::Query(query): axum::extract::Query<ToolsQuery>,
) -> impl IntoResponse {
    tracing::debug!(
        provider = ?query.provider,
        search = ?query.search,
        "GET /tools"
    );

    let claims = claims.map(|Extension(claims)| claims);
    let scopes = scopes_for_request(claims.as_ref(), &state);
    let all_tools = visible_tools_for_scopes(&state, &scopes);

    let tools: Vec<Value> = all_tools
        .iter()
        .filter(|(provider, tool)| {
            if let Some(ref p) = query.provider {
                if provider.name != *p {
                    return false;
                }
            }
            if let Some(ref q) = query.search {
                let q = q.to_lowercase();
                let name_match = tool.name.to_lowercase().contains(&q);
                let desc_match = tool.description.to_lowercase().contains(&q);
                let tag_match = tool.tags.iter().any(|t| t.to_lowercase().contains(&q));
                if !name_match && !desc_match && !tag_match {
                    return false;
                }
            }
            true
        })
        .map(|(provider, tool)| {
            serde_json::json!({
                "name": tool.name,
                "description": tool.description,
                "provider": provider.name,
                "method": format!("{:?}", tool.method),
                "tags": tool.tags,
                "input_schema": tool.input_schema,
            })
        })
        .collect();

    (StatusCode::OK, Json(Value::Array(tools)))
}

/// GET /tools/:name — get detailed info about a specific tool.
async fn handle_tool_info(
    State(state): State<Arc<ProxyState>>,
    claims: Option<Extension<TokenClaims>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl IntoResponse {
    tracing::debug!(tool = %name, "GET /tools/:name");

    let claims = claims.map(|Extension(claims)| claims);
    let scopes = scopes_for_request(claims.as_ref(), &state);

    match state
        .registry
        .get_tool(&name)
        .filter(|(_, tool)| match &tool.scope {
            Some(scope) => scopes.is_allowed(scope),
            None => true,
        }) {
        Some((provider, tool)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "name": tool.name,
                "description": tool.description,
                "provider": provider.name,
                "method": format!("{:?}", tool.method),
                "endpoint": tool.endpoint,
                "tags": tool.tags,
                "hint": tool.hint,
                "input_schema": tool.input_schema,
                "scope": tool.scope,
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Tool '{name}' not found")})),
        ),
    }
}

// ---------------------------------------------------------------------------
// Skill endpoints
// ---------------------------------------------------------------------------

async fn handle_skills_list(
    State(state): State<Arc<ProxyState>>,
    claims: Option<Extension<TokenClaims>>,
    axum::extract::Query(query): axum::extract::Query<SkillsQuery>,
) -> impl IntoResponse {
    tracing::debug!(
        category = ?query.category,
        provider = ?query.provider,
        tool = ?query.tool,
        search = ?query.search,
        "GET /skills"
    );

    let claims = claims.map(|Extension(claims)| claims);
    let scopes = scopes_for_request(claims.as_ref(), &state);
    let visible_names = visible_skill_names(&state, &scopes);

    let skills: Vec<&skill::SkillMeta> = if let Some(search_query) = &query.search {
        state
            .skill_registry
            .search(search_query)
            .into_iter()
            .filter(|skill| visible_names.contains(&skill.name))
            .collect()
    } else if let Some(cat) = &query.category {
        state
            .skill_registry
            .skills_for_category(cat)
            .into_iter()
            .filter(|skill| visible_names.contains(&skill.name))
            .collect()
    } else if let Some(prov) = &query.provider {
        state
            .skill_registry
            .skills_for_provider(prov)
            .into_iter()
            .filter(|skill| visible_names.contains(&skill.name))
            .collect()
    } else if let Some(t) = &query.tool {
        state
            .skill_registry
            .skills_for_tool(t)
            .into_iter()
            .filter(|skill| visible_names.contains(&skill.name))
            .collect()
    } else {
        state
            .skill_registry
            .list_skills()
            .iter()
            .filter(|skill| visible_names.contains(&skill.name))
            .collect()
    };

    let json: Vec<Value> = skills
        .iter()
        .map(|s| {
            serde_json::json!({
                "name": s.name,
                "version": s.version,
                "description": s.description,
                "tools": s.tools,
                "providers": s.providers,
                "categories": s.categories,
                "hint": s.hint,
            })
        })
        .collect();

    (StatusCode::OK, Json(Value::Array(json)))
}

async fn handle_skill_detail(
    State(state): State<Arc<ProxyState>>,
    claims: Option<Extension<TokenClaims>>,
    axum::extract::Path(name): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<SkillDetailQuery>,
) -> impl IntoResponse {
    tracing::debug!(%name, meta = ?query.meta, refs = ?query.refs, "GET /skills/:name");

    let claims = claims.map(|Extension(claims)| claims);
    let scopes = scopes_for_request(claims.as_ref(), &state);
    let visible_names = visible_skill_names(&state, &scopes);

    let skill_meta = match state
        .skill_registry
        .get_skill(&name)
        .filter(|skill| visible_names.contains(&skill.name))
    {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": format!("Skill '{name}' not found")})),
            );
        }
    };

    if query.meta.unwrap_or(false) {
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "name": skill_meta.name,
                "version": skill_meta.version,
                "description": skill_meta.description,
                "author": skill_meta.author,
                "tools": skill_meta.tools,
                "providers": skill_meta.providers,
                "categories": skill_meta.categories,
                "keywords": skill_meta.keywords,
                "hint": skill_meta.hint,
                "depends_on": skill_meta.depends_on,
                "suggests": skill_meta.suggests,
                "license": skill_meta.license,
                "compatibility": skill_meta.compatibility,
                "allowed_tools": skill_meta.allowed_tools,
                "format": skill_meta.format,
            })),
        );
    }

    let content = match state.skill_registry.read_content(&name) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to read skill: {e}")})),
            );
        }
    };

    let mut response = serde_json::json!({
        "name": skill_meta.name,
        "version": skill_meta.version,
        "description": skill_meta.description,
        "content": content,
    });

    if query.refs.unwrap_or(false) {
        if let Ok(refs) = state.skill_registry.list_references(&name) {
            response["references"] = serde_json::json!(refs);
        }
    }

    (StatusCode::OK, Json(response))
}

/// GET /skills/:name/bundle — return all files in a skill directory.
/// Response: `{"name": "...", "files": {"SKILL.md": "...", "scripts/generate.sh": "...", ...}}`
/// Binary files are base64-encoded; text files are returned as-is.
async fn handle_skill_bundle(
    State(state): State<Arc<ProxyState>>,
    claims: Option<Extension<TokenClaims>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl IntoResponse {
    tracing::debug!(skill = %name, "GET /skills/:name/bundle");

    let claims = claims.map(|Extension(claims)| claims);
    let scopes = scopes_for_request(claims.as_ref(), &state);
    let visible_names = visible_skill_names(&state, &scopes);
    if !visible_names.contains(&name) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Skill '{name}' not found")})),
        );
    }

    let files = match state.skill_registry.bundle_files(&name) {
        Ok(f) => f,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": format!("Skill '{name}' not found")})),
            );
        }
    };

    // Convert bytes to strings (UTF-8 text) or base64 for binary files
    let mut file_map = serde_json::Map::new();
    for (path, data) in &files {
        match std::str::from_utf8(data) {
            Ok(text) => {
                file_map.insert(path.clone(), Value::String(text.to_string()));
            }
            Err(_) => {
                // Binary file — base64 encode
                use base64::Engine;
                let encoded = base64::engine::general_purpose::STANDARD.encode(data);
                file_map.insert(path.clone(), serde_json::json!({"base64": encoded}));
            }
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "name": name,
            "files": file_map,
        })),
    )
}

/// POST /skills/bundle — return all files for multiple skills in one response.
/// Request: `{"names": ["fal-generate", "compliance-screening"]}`
/// Response: `{"skills": {...}, "missing": [...]}`
async fn handle_skills_bundle_batch(
    State(state): State<Arc<ProxyState>>,
    claims: Option<Extension<TokenClaims>>,
    Json(req): Json<SkillBundleBatchRequest>,
) -> impl IntoResponse {
    const MAX_BATCH: usize = 50;
    if req.names.len() > MAX_BATCH {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": format!("batch size {} exceeds limit of {MAX_BATCH}", req.names.len())}),
            ),
        );
    }

    tracing::debug!(names = ?req.names, "POST /skills/bundle");

    let claims = claims.map(|Extension(claims)| claims);
    let scopes = scopes_for_request(claims.as_ref(), &state);
    let visible_names = visible_skill_names(&state, &scopes);

    let mut result = serde_json::Map::new();
    let mut missing: Vec<String> = Vec::new();

    for name in &req.names {
        if !visible_names.contains(name) {
            missing.push(name.clone());
            continue;
        }
        let files = match state.skill_registry.bundle_files(name) {
            Ok(f) => f,
            Err(_) => {
                missing.push(name.clone());
                continue;
            }
        };

        let mut file_map = serde_json::Map::new();
        for (path, data) in &files {
            match std::str::from_utf8(data) {
                Ok(text) => {
                    file_map.insert(path.clone(), Value::String(text.to_string()));
                }
                Err(_) => {
                    use base64::Engine;
                    let encoded = base64::engine::general_purpose::STANDARD.encode(data);
                    file_map.insert(path.clone(), serde_json::json!({"base64": encoded}));
                }
            }
        }

        result.insert(name.clone(), serde_json::json!({ "files": file_map }));
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "skills": result, "missing": missing })),
    )
}

async fn handle_skills_resolve(
    State(state): State<Arc<ProxyState>>,
    claims: Option<Extension<TokenClaims>>,
    Json(req): Json<SkillResolveRequest>,
) -> impl IntoResponse {
    tracing::debug!(scopes = ?req.scopes, include_content = req.include_content, "POST /skills/resolve");

    let include_content = req.include_content;
    let request_scopes = ScopeConfig {
        scopes: req.scopes,
        sub: String::new(),
        expires_at: 0,
        rate_config: None,
    };
    let claims = claims.map(|Extension(claims)| claims);
    let caller_scopes = scopes_for_request(claims.as_ref(), &state);
    let visible_names = visible_skill_names(&state, &caller_scopes);

    let resolved: Vec<&skill::SkillMeta> =
        skill::resolve_skills(&state.skill_registry, &state.registry, &request_scopes)
            .into_iter()
            .filter(|skill| visible_names.contains(&skill.name))
            .collect();

    let json: Vec<Value> = resolved
        .iter()
        .map(|s| {
            let mut entry = serde_json::json!({
                "name": s.name,
                "version": s.version,
                "description": s.description,
                "tools": s.tools,
                "providers": s.providers,
                "categories": s.categories,
            });
            if include_content {
                if let Ok(content) = state.skill_registry.read_content(&s.name) {
                    entry["content"] = Value::String(content);
                }
            }
            entry
        })
        .collect();

    (StatusCode::OK, Json(Value::Array(json)))
}

fn skillati_client(keyring: &Keyring) -> Result<SkillAtiClient, SkillAtiError> {
    match SkillAtiClient::from_env(keyring)? {
        Some(client) => Ok(client),
        None => Err(SkillAtiError::NotConfigured),
    }
}

async fn handle_skillati_catalog(
    State(state): State<Arc<ProxyState>>,
    Query(query): Query<SkillAtiCatalogQuery>,
) -> impl IntoResponse {
    tracing::debug!(search = ?query.search, "GET /skillati/catalog");

    let client = match skillati_client(&state.keyring) {
        Ok(client) => client,
        Err(err) => return skillati_error_response(err),
    };

    match client.catalog().await {
        Ok(catalog) => {
            let skills = if let Some(search) = query.search.as_deref() {
                SkillAtiClient::filter_catalog(&catalog, search, 25)
            } else {
                catalog
            };
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "skills": skills,
                })),
            )
        }
        Err(err) => skillati_error_response(err),
    }
}

async fn handle_skillati_read(
    State(state): State<Arc<ProxyState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl IntoResponse {
    tracing::debug!(%name, "GET /skillati/:name");

    let client = match skillati_client(&state.keyring) {
        Ok(client) => client,
        Err(err) => return skillati_error_response(err),
    };

    match client.read_skill(&name).await {
        Ok(activation) => (StatusCode::OK, Json(serde_json::json!(activation))),
        Err(err) => skillati_error_response(err),
    }
}

async fn handle_skillati_resources(
    State(state): State<Arc<ProxyState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
    Query(query): Query<SkillAtiResourcesQuery>,
) -> impl IntoResponse {
    tracing::debug!(%name, prefix = ?query.prefix, "GET /skillati/:name/resources");

    let client = match skillati_client(&state.keyring) {
        Ok(client) => client,
        Err(err) => return skillati_error_response(err),
    };

    match client.list_resources(&name, query.prefix.as_deref()).await {
        Ok(resources) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "name": name,
                "prefix": query.prefix,
                "resources": resources,
            })),
        ),
        Err(err) => skillati_error_response(err),
    }
}

async fn handle_skillati_file(
    State(state): State<Arc<ProxyState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
    Query(query): Query<SkillAtiFileQuery>,
) -> impl IntoResponse {
    tracing::debug!(%name, path = %query.path, "GET /skillati/:name/file");

    let client = match skillati_client(&state.keyring) {
        Ok(client) => client,
        Err(err) => return skillati_error_response(err),
    };

    match client.read_path(&name, &query.path).await {
        Ok(file) => (StatusCode::OK, Json(serde_json::json!(file))),
        Err(err) => skillati_error_response(err),
    }
}

async fn handle_skillati_refs(
    State(state): State<Arc<ProxyState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl IntoResponse {
    tracing::debug!(%name, "GET /skillati/:name/refs");

    let client = match skillati_client(&state.keyring) {
        Ok(client) => client,
        Err(err) => return skillati_error_response(err),
    };

    match client.list_references(&name).await {
        Ok(references) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "name": name,
                "references": references,
            })),
        ),
        Err(err) => skillati_error_response(err),
    }
}

async fn handle_skillati_ref(
    State(state): State<Arc<ProxyState>>,
    axum::extract::Path((name, reference)): axum::extract::Path<(String, String)>,
) -> impl IntoResponse {
    tracing::debug!(%name, %reference, "GET /skillati/:name/ref/:reference");

    let client = match skillati_client(&state.keyring) {
        Ok(client) => client,
        Err(err) => return skillati_error_response(err),
    };

    match client.read_reference(&name, &reference).await {
        Ok(content) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "name": name,
                "reference": reference,
                "content": content,
            })),
        ),
        Err(err) => skillati_error_response(err),
    }
}

fn skillati_error_response(err: SkillAtiError) -> (StatusCode, Json<Value>) {
    let status = match &err {
        SkillAtiError::NotConfigured
        | SkillAtiError::UnsupportedRegistry(_)
        | SkillAtiError::MissingCredentials(_)
        | SkillAtiError::ProxyUrlRequired => StatusCode::SERVICE_UNAVAILABLE,
        SkillAtiError::SkillNotFound(_) | SkillAtiError::PathNotFound { .. } => {
            StatusCode::NOT_FOUND
        }
        SkillAtiError::InvalidPath(_) => StatusCode::BAD_REQUEST,
        SkillAtiError::Gcs(_)
        | SkillAtiError::ProxyRequest(_)
        | SkillAtiError::ProxyResponse(_) => StatusCode::BAD_GATEWAY,
    };

    (
        status,
        Json(serde_json::json!({
            "error": err.to_string(),
        })),
    )
}

// --- Auth middleware ---

/// JWT authentication middleware.
///
/// - /health and /.well-known/jwks.json → skip auth
/// - JWT configured → validate Bearer token, attach claims to request extensions
/// - No JWT configured → allow all (dev mode)
async fn auth_middleware(
    State(state): State<Arc<ProxyState>>,
    mut req: HttpRequest<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = req.uri().path();

    // Skip auth for public endpoints
    if path == "/health" || path == "/.well-known/jwks.json" {
        return Ok(next.run(req).await);
    }

    // If no JWT configured, allow all (dev mode)
    let jwt_config = match &state.jwt_config {
        Some(c) => c,
        None => return Ok(next.run(req).await),
    };

    // Extract Authorization: Bearer <token>
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => &header[7..],
        _ => return Err(StatusCode::UNAUTHORIZED),
    };

    // Validate JWT
    match jwt::validate(token, jwt_config) {
        Ok(claims) => {
            tracing::debug!(sub = %claims.sub, scopes = %claims.scope, "JWT validated");
            req.extensions_mut().insert(claims);
            Ok(next.run(req).await)
        }
        Err(e) => {
            tracing::debug!(error = %e, "JWT validation failed");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

// --- Router builder ---

/// Build the axum Router from a pre-constructed ProxyState.
pub fn build_router(state: Arc<ProxyState>) -> Router {
    Router::new()
        .route("/call", post(handle_call))
        .route("/help", post(handle_help))
        .route("/mcp", post(handle_mcp))
        .route("/tools", get(handle_tools_list))
        .route("/tools/{name}", get(handle_tool_info))
        .route("/skills", get(handle_skills_list))
        .route("/skills/resolve", post(handle_skills_resolve))
        .route("/skills/bundle", post(handle_skills_bundle_batch))
        .route("/skills/{name}", get(handle_skill_detail))
        .route("/skills/{name}/bundle", get(handle_skill_bundle))
        .route("/skillati/catalog", get(handle_skillati_catalog))
        .route("/skillati/{name}", get(handle_skillati_read))
        .route("/skillati/{name}/resources", get(handle_skillati_resources))
        .route("/skillati/{name}/file", get(handle_skillati_file))
        .route("/skillati/{name}/refs", get(handle_skillati_refs))
        .route("/skillati/{name}/ref/{reference}", get(handle_skillati_ref))
        .route("/health", get(handle_health))
        .route("/.well-known/jwks.json", get(handle_jwks))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state)
}

// --- Server startup ---

/// Start the proxy server.
pub async fn run(
    port: u16,
    bind_addr: Option<String>,
    ati_dir: PathBuf,
    _verbose: bool,
    env_keys: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load manifests
    let manifests_dir = ati_dir.join("manifests");
    let mut registry = ManifestRegistry::load(&manifests_dir)?;
    let provider_count = registry.list_providers().len();

    // Load keyring
    let keyring_source;
    let keyring = if env_keys {
        // --env-keys: scan ATI_KEY_* environment variables
        let kr = Keyring::from_env();
        let key_names = kr.key_names();
        tracing::info!(
            count = key_names.len(),
            "loaded API keys from ATI_KEY_* env vars"
        );
        for name in &key_names {
            tracing::debug!(key = %name, "env key loaded");
        }
        keyring_source = "env-vars (ATI_KEY_*)";
        kr
    } else {
        // Cascade: keyring.enc (sealed) → keyring.enc (persistent) → credentials → empty
        let keyring_path = ati_dir.join("keyring.enc");
        if keyring_path.exists() {
            if let Ok(kr) = Keyring::load(&keyring_path) {
                keyring_source = "keyring.enc (sealed key)";
                kr
            } else if let Ok(kr) = Keyring::load_local(&keyring_path, &ati_dir) {
                keyring_source = "keyring.enc (persistent key)";
                kr
            } else {
                tracing::warn!("keyring.enc exists but could not be decrypted");
                keyring_source = "empty (decryption failed)";
                Keyring::empty()
            }
        } else {
            let creds_path = ati_dir.join("credentials");
            if creds_path.exists() {
                match Keyring::load_credentials(&creds_path) {
                    Ok(kr) => {
                        keyring_source = "credentials (plaintext)";
                        kr
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to load credentials");
                        keyring_source = "empty (credentials error)";
                        Keyring::empty()
                    }
                }
            } else {
                tracing::warn!("no keyring.enc or credentials found — running without API keys");
                tracing::warn!("tools requiring authentication will fail");
                keyring_source = "empty (no auth)";
                Keyring::empty()
            }
        }
    };

    // Discover MCP tools at startup so they appear in GET /tools.
    // Runs concurrently across providers with 30s per-provider timeout.
    mcp_client::discover_all_mcp_tools(&mut registry, &keyring).await;

    let tool_count = registry.list_public_tools().len();

    // Log MCP and OpenAPI providers
    let mcp_providers: Vec<(String, String)> = registry
        .list_mcp_providers()
        .iter()
        .map(|p| (p.name.clone(), p.mcp_transport_type().to_string()))
        .collect();
    let mcp_count = mcp_providers.len();
    let openapi_providers: Vec<String> = registry
        .list_openapi_providers()
        .iter()
        .map(|p| p.name.clone())
        .collect();
    let openapi_count = openapi_providers.len();

    // Load installed/local skill registry only.
    let skills_dir = ati_dir.join("skills");
    let skill_registry = SkillRegistry::load(&skills_dir).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "failed to load skills");
        SkillRegistry::load(std::path::Path::new("/nonexistent-fallback")).unwrap()
    });

    if let Ok(registry_url) = std::env::var("ATI_SKILL_REGISTRY") {
        if registry_url.strip_prefix("gcs://").is_some() {
            tracing::info!(
                registry = %registry_url,
                "SkillATI remote registry configured for lazy reads"
            );
        } else {
            tracing::warn!(url = %registry_url, "SkillATI only supports gcs:// registries");
        }
    }

    let skill_count = skill_registry.skill_count();

    // Load JWT config from environment
    let jwt_config = match jwt::config_from_env() {
        Ok(config) => config,
        Err(e) => {
            tracing::warn!(error = %e, "JWT config error");
            None
        }
    };

    let auth_status = if jwt_config.is_some() {
        "JWT enabled"
    } else {
        "DISABLED (no JWT keys configured)"
    };

    // Build JWKS for the endpoint
    let jwks_json = jwt_config.as_ref().and_then(|config| {
        config
            .public_key_pem
            .as_ref()
            .and_then(|pem| jwt::public_key_to_jwks(pem, config.algorithm, "ati-proxy-1").ok())
    });

    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring,
        jwt_config,
        jwks_json,
        auth_cache: AuthCache::new(),
    });

    let app = build_router(state);

    let addr: SocketAddr = if let Some(ref bind) = bind_addr {
        format!("{bind}:{port}").parse()?
    } else {
        SocketAddr::from(([127, 0, 0, 1], port))
    };

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        %addr,
        auth = auth_status,
        ati_dir = %ati_dir.display(),
        tools = tool_count,
        providers = provider_count,
        mcp = mcp_count,
        openapi = openapi_count,
        skills = skill_count,
        keyring = keyring_source,
        "ATI proxy server starting"
    );
    for (name, transport) in &mcp_providers {
        tracing::info!(provider = %name, transport = %transport, "MCP provider");
    }
    for name in &openapi_providers {
        tracing::info!(provider = %name, "OpenAPI provider");
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Write an audit entry from the proxy server. Failures are silently ignored.
fn write_proxy_audit(
    call_req: &CallRequest,
    agent_sub: &str,
    duration: std::time::Duration,
    error: Option<&str>,
) {
    let entry = crate::core::audit::AuditEntry {
        ts: chrono::Utc::now().to_rfc3339(),
        tool: call_req.tool_name.clone(),
        args: crate::core::audit::sanitize_args(&call_req.args),
        status: if error.is_some() {
            crate::core::audit::AuditStatus::Error
        } else {
            crate::core::audit::AuditStatus::Ok
        },
        duration_ms: duration.as_millis() as u64,
        agent_sub: agent_sub.to_string(),
        error: error.map(|s| s.to_string()),
        exit_code: None,
    };
    let _ = crate::core::audit::append(&entry);
}

// --- Helpers ---

const HELP_SYSTEM_PROMPT: &str = r#"You are a helpful assistant for an AI agent that uses external tools via the `ati` CLI.

## Available Tools
{tools}

{skills_section}

Answer the agent's question naturally, like a knowledgeable colleague would. Keep it short but useful:

- Explain which tools to use and why, with `ati run` commands showing realistic parameter values
- If multiple steps are needed, walk through them briefly in order
- Mention important gotchas or parameter choices that matter
- If skills are relevant, suggest `ati skill show <name>` for the full methodology

Keep your answer concise — a few short paragraphs with embedded code blocks. Only recommend tools from the list above."#;

async fn build_remote_skillati_section(keyring: &Keyring, query: &str, limit: usize) -> String {
    let client = match SkillAtiClient::from_env(keyring) {
        Ok(Some(client)) => client,
        Ok(None) => return String::new(),
        Err(err) => {
            tracing::warn!(error = %err, "failed to initialize SkillATI catalog for proxy help");
            return String::new();
        }
    };

    let catalog = match client.catalog().await {
        Ok(catalog) => catalog,
        Err(err) => {
            tracing::warn!(error = %err, "failed to load SkillATI catalog for proxy help");
            return String::new();
        }
    };

    let matched = SkillAtiClient::filter_catalog(&catalog, query, limit);
    if matched.is_empty() {
        return String::new();
    }

    render_remote_skillati_section(&matched, catalog.len())
}

fn render_remote_skillati_section(skills: &[RemoteSkillMeta], total_catalog: usize) -> String {
    let mut section = String::from("## Remote Skills Available Via SkillATI\n\n");
    section.push_str(
        "These skills are available remotely from the SkillATI registry. They are not installed locally. Activate one on demand with `ati skillati read <name>`, inspect bundled paths with `ati skillati resources <name>`, and fetch specific files with `ati skillati cat <name> <path>`.\n\n",
    );

    for skill in skills {
        section.push_str(&format!("- **{}**: {}\n", skill.name, skill.description));
    }

    if total_catalog > skills.len() {
        section.push_str(&format!(
            "\nOnly the most relevant {} remote skills are shown here.\n",
            skills.len()
        ));
    }

    section
}

fn merge_help_skill_sections(sections: &[String]) -> String {
    sections
        .iter()
        .filter_map(|section| {
            let trimmed = section.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn build_tool_context(
    tools: &[(
        &crate::core::manifest::Provider,
        &crate::core::manifest::Tool,
    )],
) -> String {
    let mut summaries = Vec::new();
    for (provider, tool) in tools {
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
        // CLI tools: show passthrough usage
        if provider.is_cli() && tool.input_schema.is_none() {
            let cmd = provider.cli_command.as_deref().unwrap_or("?");
            summary.push_str(&format!(
                "\n  Usage: `ati run {} -- <args>`  (passthrough to `{}`)",
                tool.name, cmd
            ));
        } else if let Some(schema) = &tool.input_schema {
            if let Some(props) = schema.get("properties") {
                if let Some(obj) = props.as_object() {
                    let params: Vec<String> = obj
                        .iter()
                        .filter(|(_, v)| {
                            v.get("x-ati-param-location").is_none()
                                || v.get("description").is_some()
                        })
                        .map(|(k, v)| {
                            let type_str =
                                v.get("type").and_then(|t| t.as_str()).unwrap_or("string");
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
        summaries.push(summary);
    }
    summaries.join("\n\n")
}

/// Build a scoped system prompt for a specific tool or provider.
///
/// Returns None if the scope_name doesn't match any tool or provider.
fn build_scoped_prompt(
    scope_name: &str,
    visible_tools: &[(&Provider, &Tool)],
    skills_section: &str,
) -> Option<String> {
    // Check if scope_name is a tool
    if let Some((provider, tool)) = visible_tools
        .iter()
        .find(|(_, tool)| tool.name == scope_name)
    {
        let mut details = format!(
            "**Name**: `{}`\n**Provider**: {} (handler: {})\n**Description**: {}\n",
            tool.name, provider.name, provider.handler, tool.description
        );
        if let Some(cat) = &provider.category {
            details.push_str(&format!("**Category**: {}\n", cat));
        }
        if provider.is_cli() {
            let cmd = provider.cli_command.as_deref().unwrap_or("?");
            details.push_str(&format!(
                "\n**Usage**: `ati run {} -- <args>`  (passthrough to `{}`)\n",
                tool.name, cmd
            ));
        } else if let Some(schema) = &tool.input_schema {
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
                    details.push_str(&format!("- `--{key}` ({type_str}{req}): {desc}\n"));
                }
            }
        }

        let prompt = format!(
            "You are an expert assistant for the `{}` tool, accessed via the `ati` CLI.\n\n\
            ## Tool Details\n{}\n\n{}\n\n\
            Answer the agent's question about this specific tool. Provide exact commands, explain flags and options, and give practical examples. Be concise and actionable.",
            tool.name, details, skills_section
        );
        return Some(prompt);
    }

    // Check if scope_name is a provider
    let tools: Vec<(&Provider, &Tool)> = visible_tools
        .iter()
        .copied()
        .filter(|(provider, _)| provider.name == scope_name)
        .collect();
    if !tools.is_empty() {
        let tools_context = build_tool_context(&tools);
        let prompt = format!(
            "You are an expert assistant for the `{}` provider's tools, accessed via the `ati` CLI.\n\n\
            ## Tools in provider `{}`\n{}\n\n{}\n\n\
            Answer the agent's question about these tools. Provide exact `ati run` commands, explain parameters, and give practical examples. Be concise and actionable.",
            scope_name, scope_name, tools_context, skills_section
        );
        return Some(prompt);
    }

    None
}
