/// ATI proxy server — holds API keys and executes tool calls on behalf of sandbox agents.
///
/// Authentication: ES256-signed JWT (or HS256 fallback). The JWT carries identity,
/// scopes, and expiry. No more static tokens or unsigned scope lists.
///
/// Usage: `ati proxy --port 8080 [--ati-dir ~/.ati]`

use axum::{
    body::Body,
    extract::State,
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

use crate::core::http;
use crate::core::jwt::{self, JwtConfig, TokenClaims};
use crate::core::keyring::Keyring;
use crate::core::manifest::ManifestRegistry;
use crate::core::mcp_client;
use crate::core::response;
use crate::core::scope::ScopeConfig;
use crate::core::skill::{self, SkillRegistry};
use crate::core::xai;

/// Shared state for the proxy server.
pub struct ProxyState {
    pub registry: ManifestRegistry,
    pub skill_registry: SkillRegistry,
    pub keyring: Keyring,
    pub verbose: bool,
    /// JWT validation config (None = auth disabled / dev mode).
    pub jwt_config: Option<JwtConfig>,
    /// Pre-computed JWKS JSON for the /.well-known/jwks.json endpoint.
    pub jwks_json: Option<Value>,
}

// --- Request/Response types ---

#[derive(Debug, Deserialize)]
pub struct CallRequest {
    pub tool_name: String,
    pub args: HashMap<String, Value>,
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
}

// --- Handlers ---

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

    if state.verbose {
        eprintln!("[proxy] /call tool={} args={:?}", call_req.tool_name, call_req.args);
    }

    // Look up tool in registry
    let (provider, tool) = match state.registry.get_tool(&call_req.tool_name) {
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

        if let Err(e) = scopes.check_access(&call_req.tool_name, tool_scope) {
            return (
                StatusCode::FORBIDDEN,
                Json(CallResponse {
                    result: Value::Null,
                    error: Some(format!("Access denied: {e}")),
                }),
            );
        }
    }

    // Execute tool call — dispatch based on handler type
    match provider.handler.as_str() {
        "mcp" => {
            match mcp_client::execute(provider, &call_req.tool_name, &call_req.args, &state.keyring).await {
                Ok(result) => (
                    StatusCode::OK,
                    Json(CallResponse { result, error: None }),
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
        _ => {
            let raw_response = match match provider.handler.as_str() {
                "xai" => xai::execute_xai_tool(provider, tool, &call_req.args, &state.keyring).await,
                _ => http::execute_tool(provider, tool, &call_req.args, &state.keyring).await,
            } {
                Ok(resp) => resp,
                Err(e) => {
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(CallResponse {
                            result: Value::Null,
                            error: Some(format!("Upstream API error: {e}")),
                        }),
                    );
                }
            };

            let processed = match response::process_response(&raw_response, tool.response.as_ref()) {
                Ok(p) => p,
                Err(e) => {
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
                Json(CallResponse { result: processed, error: None }),
            )
        }
    }
}

async fn handle_help(
    State(state): State<Arc<ProxyState>>,
    Json(req): Json<HelpRequest>,
) -> impl IntoResponse {
    if state.verbose {
        eprintln!("[proxy] /help query={}", req.query);
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

    let all_tools = state.registry.list_public_tools();
    let tools_context = build_tool_context(&all_tools);

    let scopes = ScopeConfig::unrestricted();
    let resolved_skills =
        skill::resolve_skills(&state.skill_registry, &state.registry, &scopes);
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

    let request_body = serde_json::json!({
        "model": "zai-glm-4.7",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": req.query}
        ],
        "max_completion_tokens": 1024,
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
    Json(msg): Json<Value>,
) -> impl IntoResponse {
    let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = msg.get("id").cloned();

    if state.verbose {
        eprintln!("[proxy] /mcp method={method}");
    }

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

        "notifications/initialized" => {
            (StatusCode::ACCEPTED, Json(Value::Null))
        }

        "tools/list" => {
            let all_tools = state.registry.list_public_tools();
            let mcp_tools: Vec<Value> = all_tools
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
                    return jsonrpc_error(
                        id,
                        -32602,
                        &format!("Unknown tool: '{tool_name}'"),
                    );
                }
            };

            if state.verbose {
                eprintln!("[proxy] /mcp tools/call name={tool_name} provider={}", provider.name);
            }

            let result = if provider.is_mcp() {
                mcp_client::execute(provider, tool_name, &arguments, &state.keyring).await
            } else {
                match match provider.handler.as_str() {
                    "xai" => xai::execute_xai_tool(provider, _tool, &arguments, &state.keyring).await,
                    _ => http::execute_tool(provider, _tool, &arguments, &state.keyring).await,
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

        _ => {
            jsonrpc_error(id, -32601, &format!("Method not found: '{method}'"))
        }
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
// Skill endpoints
// ---------------------------------------------------------------------------

async fn handle_skills_list(
    State(state): State<Arc<ProxyState>>,
    axum::extract::Query(query): axum::extract::Query<SkillsQuery>,
) -> impl IntoResponse {
    if state.verbose {
        eprintln!(
            "[proxy] GET /skills category={:?} provider={:?} tool={:?} search={:?}",
            query.category, query.provider, query.tool, query.search
        );
    }

    let skills: Vec<&skill::SkillMeta> = if let Some(search_query) = &query.search {
        state.skill_registry.search(search_query)
    } else if let Some(cat) = &query.category {
        state.skill_registry.skills_for_category(cat)
    } else if let Some(prov) = &query.provider {
        state.skill_registry.skills_for_provider(prov)
    } else if let Some(t) = &query.tool {
        state.skill_registry.skills_for_tool(t)
    } else {
        state.skill_registry.list_skills().iter().collect()
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
    axum::extract::Path(name): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<SkillDetailQuery>,
) -> impl IntoResponse {
    if state.verbose {
        eprintln!("[proxy] GET /skills/{name} meta={:?} refs={:?}", query.meta, query.refs);
    }

    let skill_meta = match state.skill_registry.get_skill(&name) {
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

async fn handle_skills_resolve(
    State(state): State<Arc<ProxyState>>,
    Json(req): Json<SkillResolveRequest>,
) -> impl IntoResponse {
    if state.verbose {
        eprintln!("[proxy] POST /skills/resolve scopes={:?}", req.scopes);
    }

    let scopes = ScopeConfig {
        scopes: req.scopes,
        sub: String::new(),
        expires_at: 0,
    };

    let resolved = skill::resolve_skills(&state.skill_registry, &state.registry, &scopes);

    let json: Vec<Value> = resolved
        .iter()
        .map(|s| {
            serde_json::json!({
                "name": s.name,
                "version": s.version,
                "description": s.description,
                "tools": s.tools,
                "providers": s.providers,
                "categories": s.categories,
            })
        })
        .collect();

    (StatusCode::OK, Json(Value::Array(json)))
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
            if state.verbose {
                eprintln!("[proxy] JWT validated: sub={} scopes={}", claims.sub, claims.scope);
            }
            req.extensions_mut().insert(claims);
            Ok(next.run(req).await)
        }
        Err(e) => {
            if state.verbose {
                eprintln!("[proxy] JWT validation failed: {e}");
            }
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
        .route("/skills", get(handle_skills_list))
        .route("/skills/resolve", post(handle_skills_resolve))
        .route("/skills/{name}", get(handle_skill_detail))
        .route("/health", get(handle_health))
        .route("/.well-known/jwks.json", get(handle_jwks))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state)
}

// --- Server startup ---

/// Start the proxy server.
pub async fn run(
    port: u16,
    bind_addr: Option<String>,
    ati_dir: PathBuf,
    verbose: bool,
    env_keys: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load manifests
    let manifests_dir = ati_dir.join("manifests");
    let registry = ManifestRegistry::load(&manifests_dir)?;

    let tool_count = registry.list_public_tools().len();
    let provider_count = registry.list_providers().len();

    // Load keyring
    let keyring_source;
    let keyring = if env_keys {
        // --env-keys: scan ATI_KEY_* environment variables
        let kr = Keyring::from_env();
        let key_names = kr.key_names();
        eprintln!("  Loaded {} API keys from ATI_KEY_* env vars:", key_names.len());
        for name in &key_names {
            eprintln!("    - {name}");
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
                eprintln!("Warning: keyring.enc exists but could not be decrypted");
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
                        eprintln!("Warning: Failed to load credentials: {e}");
                        keyring_source = "empty (credentials error)";
                        Keyring::empty()
                    }
                }
            } else {
                eprintln!("Warning: No keyring.enc or credentials found — running without API keys");
                eprintln!("Tools requiring authentication will fail.");
                keyring_source = "empty (no auth)";
                Keyring::empty()
            }
        }
    };

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

    // Load skill registry
    let skills_dir = ati_dir.join("skills");
    let skill_registry = SkillRegistry::load(&skills_dir).unwrap_or_else(|e| {
        if verbose {
            eprintln!("Warning: failed to load skills: {e}");
        }
        SkillRegistry::load(std::path::Path::new("/nonexistent-fallback")).unwrap()
    });
    let skill_count = skill_registry.skill_count();

    // Load JWT config from environment
    let jwt_config = match jwt::config_from_env() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Warning: JWT config error: {e}");
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
        config.public_key_pem.as_ref().and_then(|pem| {
            jwt::public_key_to_jwks(pem, config.algorithm, "ati-proxy-1").ok()
        })
    });

    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring,
        verbose,
        jwt_config,
        jwks_json,
    });

    let app = build_router(state);

    let addr: SocketAddr = if let Some(ref bind) = bind_addr {
        format!("{bind}:{port}").parse()?
    } else {
        SocketAddr::from(([127, 0, 0, 1], port))
    };

    eprintln!("ATI proxy server v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("  Listening on http://{addr}");
    eprintln!("  Auth: {auth_status}");
    eprintln!("  ATI dir: {}", ati_dir.display());
    eprintln!("  Tools: {tool_count}, Providers: {provider_count} ({mcp_count} MCP, {openapi_count} OpenAPI)");
    eprintln!("  Skills: {skill_count}");
    eprintln!("  Keyring: {keyring_source}");
    eprintln!("  Endpoints: /call, /help, /mcp, /skills, /skills/:name, /skills/resolve, /health, /.well-known/jwks.json");
    for (name, transport) in &mcp_providers {
        eprintln!("  MCP: {name} ({transport})");
    }
    for name in &openapi_providers {
        eprintln!("  OpenAPI: {name}");
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// --- Helpers ---

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

fn build_tool_context(
    tools: &[(&crate::core::manifest::Provider, &crate::core::manifest::Tool)],
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
        if let Some(schema) = &tool.input_schema {
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
                            let desc =
                                v.get("description").and_then(|d| d.as_str()).unwrap_or("");
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
