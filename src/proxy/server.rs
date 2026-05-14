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
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::core::auth_generator::{AuthCache, GenContext};
use crate::core::db::DbState;
use crate::core::http;
use crate::core::jwt::{self, JwtConfig, TokenClaims};
use crate::core::keyring::Keyring;
#[cfg(feature = "db")]
use crate::core::keys::KeyStore;
use crate::core::manifest::{ManifestRegistry, Provider, Tool};
use crate::core::mcp_client;
use crate::core::response;
use crate::core::scope::ScopeConfig;
use crate::core::sentry_scope;
use crate::core::skill::{self, SkillRegistry};
use crate::core::skillati::{RemoteSkillMeta, SkillAtiClient, SkillAtiError};

/// Cross-feature placeholder for the virtual-key store. When `feature=db` is
/// on, this is `Option<Arc<KeyStore>>`; when off, callers see `Option<()>` and
/// every code path that would consume it short-circuits to no-op.
#[cfg(feature = "db")]
pub type OptionalKeyStore = Option<Arc<KeyStore>>;
#[cfg(not(feature = "db"))]
pub type OptionalKeyStore = Option<()>;

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
    /// Optional Postgres persistence layer. `Disabled` is the normal path;
    /// downstream writers (call audit, virtual keys) borrow the pool from here.
    pub db: DbState,
    /// Compiled passthrough router. `None` when `--enable-passthrough` is off
    /// (the fallback handler returns 404 immediately in that case). The router
    /// is built once at startup; rebuilding requires a process restart (or a
    /// SIGHUP once `ati edge rotate-keyring` lands in PR 3).
    pub passthrough: Option<Arc<crate::core::passthrough::PassthroughRouter>>,
    /// HMAC sig-verify config. Always present (mode defaults to `Log` which is
    /// a no-op). The middleware wraps every non-exempt request and reads from
    /// here. Carries an `ArcSwapOption<Vec<u8>>` so a SIGHUP-driven keyring
    /// reload can swap the secret in place without restart.
    pub sig_verify: Arc<crate::core::sig_verify::SigVerifyConfig>,
    /// Optional ephemeral-key store. `None` when `ATI_DB_URL` is unset, when
    /// the binary is built without `--features db`, or in tests that don't
    /// exercise persistence. When `Some`, `auth_middleware` accepts
    /// `Authorization: Ati-Key <raw>` in addition to the existing JWT path.
    /// When `None`, only the JWT path works.
    pub key_store: OptionalKeyStore,
    /// Plaintext bearer token expected on `/admin/keys/*`. Sourced from the
    /// `ATI_ADMIN_TOKEN` env var at startup. `None` disables the admin
    /// endpoints (they return 503).
    pub admin_token: Option<String>,
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
    /// Persistence layer status: "disabled" | "connected".
    pub db: String,
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

/// Compute the set of remote (SkillATI-registry) skill names that the caller's
/// scopes grant access to.
///
/// Mirrors the scope cascade in `skill::resolve_skills` — explicit `skill:X`
/// scopes, `tool:Y` scopes resolved to the tool's covering skills (including
/// provider/category bindings) — but against a remote catalog whose skills
/// are **not** present in the local filesystem `SkillRegistry`.
///
/// Without this, proxies running `ATI_SKILL_REGISTRY=gcs://...` with an empty
/// local skills directory return 404 for every remote skill, because the
/// visibility gate only consults `state.skill_registry` (see issue #59).
fn visible_remote_skill_names(
    state: &ProxyState,
    scopes: &ScopeConfig,
    catalog: &[RemoteSkillMeta],
) -> std::collections::HashSet<String> {
    let mut visible: std::collections::HashSet<String> = std::collections::HashSet::new();
    if catalog.is_empty() {
        return visible;
    }
    if scopes.is_wildcard() {
        for entry in catalog {
            visible.insert(entry.name.clone());
        }
        return visible;
    }

    // Collect allowed tool/provider/category identifiers from the caller's scopes.
    // 1. Direct `tool:X` scopes (including wildcards) → walk against the public
    //    tool registry to collect concrete (provider, tool) pairs.
    let allowed_tool_pairs: Vec<(String, String)> =
        crate::core::scope::filter_tools_by_scope(state.registry.list_public_tools(), scopes)
            .into_iter()
            .map(|(p, t)| (p.name.clone(), t.name.clone()))
            .collect();
    let allowed_tool_names: std::collections::HashSet<&str> =
        allowed_tool_pairs.iter().map(|(_, t)| t.as_str()).collect();
    let allowed_provider_names: std::collections::HashSet<&str> =
        allowed_tool_pairs.iter().map(|(p, _)| p.as_str()).collect();
    let allowed_categories: std::collections::HashSet<String> = state
        .registry
        .list_providers()
        .into_iter()
        .filter(|p| allowed_provider_names.contains(p.name.as_str()))
        .filter_map(|p| p.category.clone())
        .collect();

    // Explicit `skill:X` scopes → include X if present in the remote catalog.
    for scope in &scopes.scopes {
        if let Some(skill_name) = scope.strip_prefix("skill:") {
            if catalog.iter().any(|e| e.name == skill_name) {
                visible.insert(skill_name.to_string());
            }
        }
    }

    // Tool/provider/category cascade → include a remote skill if any of its
    // `tools`, `providers`, or `categories` bindings match a scope-allowed
    // tool/provider/category.
    for entry in catalog {
        if entry
            .tools
            .iter()
            .any(|t| allowed_tool_names.contains(t.as_str()))
            || entry
                .providers
                .iter()
                .any(|p| allowed_provider_names.contains(p.as_str()))
            || entry
                .categories
                .iter()
                .any(|c| allowed_categories.contains(c))
        {
            visible.insert(entry.name.clone());
        }
    }

    visible
}

/// Union of local + remote visible skill names, computed on demand. The
/// remote catalog is fetched lazily (and is cached inside `SkillAtiClient`
/// after the first call on the hot path).
async fn visible_skill_names_with_remote(
    state: &ProxyState,
    scopes: &ScopeConfig,
    client: &SkillAtiClient,
) -> Result<std::collections::HashSet<String>, SkillAtiError> {
    let mut names = visible_skill_names(state, scopes);
    let catalog = client.catalog().await?;
    let remote = visible_remote_skill_names(state, scopes, &catalog);
    names.extend(remote);
    Ok(names)
}

#[tracing::instrument(name = "proxy.call", skip_all, fields(tool = tracing::field::Empty))]
async fn handle_call(
    State(state): State<Arc<ProxyState>>,
    req: HttpRequest<Body>,
) -> impl IntoResponse {
    // Extract JWT claims from request extensions (set by auth middleware)
    let claims = req.extensions().get::<TokenClaims>().cloned();
    // Grab the per-tool labels slot the observability middleware stashed
    // before calling us. After tool resolution we write (provider, tool)
    // into it; the middleware then attaches those as metric labels so
    // dashboards can drill down by tool. Clone the Arc so we still hold
    // a write-side handle after `req.into_body()` consumes the request.
    let metric_labels_slot = req
        .extensions()
        .get::<std::sync::Arc<CallMetricLabelsSlot>>()
        .cloned();

    // Parse request body. The ceiling must accommodate the worst-case upload
    // payload: `file_manager::MAX_UPLOAD_BYTES` of raw bytes, base64-inflated
    // (~1.34×), plus a few KB of JSON framing. Anti-abuse is enforced
    // downstream by per-tool limits (`max_bytes` on downloads, `MAX_UPLOAD_BYTES`
    // on uploads) and by JWT scope + rate limits — this is just the outer
    // wire cap.
    let body_bytes = match axum::body::to_bytes(req.into_body(), max_call_body_bytes()).await {
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

    tracing::Span::current().record("tool", call_req.tool_name.as_str());
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

    // Record (provider, tool) for the otel request-rate / latency metrics.
    // Done as soon as resolution succeeds — every subsequent path (scope
    // denial, rate-limit, upstream error, success) is then properly
    // labelled. Pre-resolution failures (bad JSON, unknown tool) skip this
    // write and surface in metrics as `/call` without per-tool labels,
    // which is the correct semantic ("could not attribute to a tool").
    if let Some(ref slot) = metric_labels_slot {
        if let Ok(mut guard) = slot.inner.lock() {
            *guard = Some((provider.name.clone(), tool.name.clone()));
        }
    }

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
    let job_id = claims
        .as_ref()
        .and_then(|c| c.job_id.clone())
        .unwrap_or_default();
    let sandbox_id = claims
        .as_ref()
        .and_then(|c| c.sandbox_id.clone())
        .unwrap_or_default();
    tracing::info!(
        tool = %call_req.tool_name,
        agent = %agent_sub,
        job_id = %job_id,
        sandbox_id = %sandbox_id,
        "tool call"
    );
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
                Err(e) => {
                    let (provider_name, operation_id) =
                        sentry_scope::split_tool_name(&call_req.tool_name);
                    sentry_scope::report_upstream_error(
                        &provider_name,
                        &operation_id,
                        0,
                        502,
                        None,
                        Some(&e.to_string()),
                    );
                    (
                        StatusCode::BAD_GATEWAY,
                        Json(CallResponse {
                            result: Value::Null,
                            error: Some(format!("MCP error: {e}")),
                        }),
                    )
                }
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
                Err(e) => {
                    let (provider_name, operation_id) =
                        sentry_scope::split_tool_name(&call_req.tool_name);
                    sentry_scope::report_upstream_error(
                        &provider_name,
                        &operation_id,
                        0,
                        502,
                        None,
                        Some(&e.to_string()),
                    );
                    (
                        StatusCode::BAD_GATEWAY,
                        Json(CallResponse {
                            result: Value::Null,
                            error: Some(format!("CLI error: {e}")),
                        }),
                    )
                }
            }
        }
        "file_manager" => {
            let args_map = call_req.args_as_map();
            match dispatch_file_manager(&call_req.tool_name, &args_map, provider, &state.keyring)
                .await
            {
                Ok(result) => (
                    StatusCode::OK,
                    Json(CallResponse {
                        result,
                        error: None,
                    }),
                ),
                Err((status, msg)) => (
                    status,
                    Json(CallResponse {
                        result: Value::Null,
                        error: Some(msg),
                    }),
                ),
            }
        }
        _ => {
            let args_map = call_req.args_as_map();
            let raw_response = match http::execute_tool_with_gen(
                provider,
                tool,
                &args_map,
                &state.keyring,
                Some(&gen_ctx),
                Some(&state.auth_cache),
            )
            .await
            {
                Ok(resp) => resp,
                Err(http::HttpError::NoRecordsFound { status }) => {
                    // Legit empty upstream result — not an error. Return a
                    // clean empty object so callers can distinguish from a
                    // failed call and move on without paging Sentry.
                    let duration = start.elapsed();
                    tracing::info!(
                        tool = %call_req.tool_name,
                        upstream_status = status,
                        "upstream returned no records"
                    );
                    write_proxy_audit(&call_req, &agent_sub, claims.as_ref(), duration, None);
                    return (
                        StatusCode::OK,
                        Json(CallResponse {
                            result: serde_json::json!({ "records": [] }),
                            error: None,
                        }),
                    );
                }
                Err(e) => {
                    let duration = start.elapsed();
                    let (provider_name, operation_id) =
                        sentry_scope::split_tool_name(&call_req.tool_name);
                    let (upstream_status, error_type, error_message) = match &e {
                        http::HttpError::ApiError {
                            status,
                            error_type,
                            error_message,
                            ..
                        } => (*status, error_type.clone(), error_message.clone()),
                        _ => (0u16, None, Some(e.to_string())),
                    };
                    sentry_scope::report_upstream_error(
                        &provider_name,
                        &operation_id,
                        upstream_status,
                        502,
                        error_type.as_deref(),
                        error_message.as_deref(),
                    );
                    write_proxy_audit(
                        &call_req,
                        &agent_sub,
                        claims.as_ref(),
                        duration,
                        Some(&e.to_string()),
                    );
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
                    write_proxy_audit(
                        &call_req,
                        &agent_sub,
                        claims.as_ref(),
                        duration,
                        Some(&e.to_string()),
                    );
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
    write_proxy_audit(&call_req, &agent_sub, claims.as_ref(), duration, error_msg);

    response
}

#[tracing::instrument(name = "proxy.help", skip_all)]
async fn handle_help(
    State(state): State<Arc<ProxyState>>,
    claims: Option<Extension<TokenClaims>>,
    Json(req): Json<HelpRequest>,
) -> impl IntoResponse {
    tracing::debug!(query = %req.query, tool = ?req.tool, "POST /help");

    let claims = claims.map(|Extension(claims)| claims);
    let scopes = scopes_for_request(claims.as_ref(), &state);

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
        db: state.db.status().into(),
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
// /admin/keys/* — virtual-key management (master-token gated)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct AdminIssueRequest {
    user_id: String,
    alias: String,
    #[serde(default)]
    tools: Vec<String>,
    #[serde(default)]
    providers: Vec<String>,
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    skills: Vec<String>,
    #[serde(default)]
    expires_in_secs: Option<u64>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
    #[serde(default)]
    created_by: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AdminBulkRevokeRequest {
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    alias_prefix: Option<String>,
    #[serde(default)]
    hashes: Option<Vec<String>>,
    #[serde(default)]
    by: Option<String>,
}

#[cfg(feature = "db")]
async fn handle_admin_keys_issue(
    State(state): State<Arc<ProxyState>>,
    Json(body): Json<AdminIssueRequest>,
) -> impl IntoResponse {
    let store = match state.key_store.as_ref() {
        Some(s) => s,
        None => return admin_unavailable(),
    };
    let params = crate::core::keys::IssueParams {
        user_id: body.user_id,
        key_alias: body.alias,
        tools: body.tools,
        providers: body.providers,
        categories: body.categories,
        skills: body.skills,
        expires_in: body.expires_in_secs.map(std::time::Duration::from_secs),
        metadata: body.metadata.unwrap_or(serde_json::Value::Null),
        created_by: body.created_by,
    };
    match store.issue(params).await {
        Ok(issued) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "raw_key": issued.raw_key,
                "hash": issued.hash,
                "alias": issued.alias,
                "expires_at": issued.expires_at,
            })),
        ),
        Err(crate::core::keys::KeyStoreError::InvalidParams(msg)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": msg})),
        ),
        Err(err) => {
            tracing::warn!(error = %err, "admin keys issue failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": err.to_string()})),
            )
        }
    }
}

#[cfg(feature = "db")]
async fn handle_admin_keys_revoke(
    State(state): State<Arc<ProxyState>>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> impl IntoResponse {
    let store = match state.key_store.as_ref() {
        Some(s) => s,
        None => return admin_unavailable(),
    };
    match store.revoke(&hash, Some("admin")).await {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({"revoked": true}))),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "no such key"})),
        ),
        Err(err) => {
            tracing::warn!(error = %err, "admin keys revoke failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": err.to_string()})),
            )
        }
    }
}

#[cfg(feature = "db")]
async fn handle_admin_keys_info(
    State(state): State<Arc<ProxyState>>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> impl IntoResponse {
    let store = match state.key_store.as_ref() {
        Some(s) => s,
        None => return admin_unavailable(),
    };
    match store.lookup(&hash).await {
        Ok(Some(key)) => (StatusCode::OK, Json(ati_key_to_json(&key))),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "no such key"})),
        ),
        Err(err) => {
            tracing::warn!(error = %err, "admin keys info failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": err.to_string()})),
            )
        }
    }
}

#[cfg(feature = "db")]
async fn handle_admin_keys_bulk_revoke(
    State(state): State<Arc<ProxyState>>,
    Json(body): Json<AdminBulkRevokeRequest>,
) -> impl IntoResponse {
    let store = match state.key_store.as_ref() {
        Some(s) => s,
        None => return admin_unavailable(),
    };
    let by = body.by.clone();
    let filter = crate::core::keys::BulkRevokeFilter {
        user_id: body.user_id,
        alias_prefix: body.alias_prefix,
        hashes: body.hashes,
    };
    match store.bulk_revoke(filter, by.as_deref()).await {
        Ok(count) => (StatusCode::OK, Json(serde_json::json!({"revoked": count}))),
        Err(crate::core::keys::KeyStoreError::InvalidParams(msg)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": msg})),
        ),
        Err(err) => {
            tracing::warn!(error = %err, "admin keys bulk revoke failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": err.to_string()})),
            )
        }
    }
}

#[cfg(feature = "db")]
async fn handle_admin_keys_list(
    State(state): State<Arc<ProxyState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let store = match state.key_store.as_ref() {
        Some(s) => s,
        None => return admin_unavailable(),
    };
    let user_id = match params.get("user_id") {
        Some(u) => u.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "user_id query param required"})),
            )
        }
    };
    match store.list_user_sessions(&user_id).await {
        Ok(rows) => {
            let json: Vec<Value> = rows.iter().map(ati_key_to_json).collect();
            (StatusCode::OK, Json(serde_json::json!({"sessions": json})))
        }
        Err(err) => {
            tracing::warn!(error = %err, "admin keys list failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": err.to_string()})),
            )
        }
    }
}

// Stubs when feature=db is off — admin endpoints just 503.
#[cfg(not(feature = "db"))]
async fn handle_admin_keys_issue(
    State(_state): State<Arc<ProxyState>>,
    Json(_body): Json<serde_json::Value>,
) -> impl IntoResponse {
    admin_unavailable()
}
#[cfg(not(feature = "db"))]
async fn handle_admin_keys_revoke(
    State(_state): State<Arc<ProxyState>>,
    axum::extract::Path(_hash): axum::extract::Path<String>,
) -> impl IntoResponse {
    admin_unavailable()
}
#[cfg(not(feature = "db"))]
async fn handle_admin_keys_info(
    State(_state): State<Arc<ProxyState>>,
    axum::extract::Path(_hash): axum::extract::Path<String>,
) -> impl IntoResponse {
    admin_unavailable()
}
#[cfg(not(feature = "db"))]
async fn handle_admin_keys_bulk_revoke(
    State(_state): State<Arc<ProxyState>>,
    Json(_body): Json<serde_json::Value>,
) -> impl IntoResponse {
    admin_unavailable()
}
#[cfg(not(feature = "db"))]
async fn handle_admin_keys_list(
    State(_state): State<Arc<ProxyState>>,
    Query(_params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    admin_unavailable()
}

fn admin_unavailable() -> (StatusCode, Json<Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"error": "admin endpoints require ATI_DB_URL + ATI_ADMIN_TOKEN"})),
    )
}

#[cfg(feature = "db")]
fn ati_key_to_json(key: &crate::core::keys::AtiKey) -> Value {
    serde_json::json!({
        "token_hash": key.token_hash,
        "key_alias": key.key_alias,
        "user_id": key.user_id,
        "blocked": key.blocked,
        "expires_at": key.expires_at,
        "tools": key.tools,
        "providers": key.providers,
        "categories": key.categories,
        "skills": key.skills,
        "request_count": key.request_count,
        "error_count": key.error_count,
        "last_used_at": key.last_used_at,
        "metadata": key.metadata,
        "created_at": key.created_at,
        "created_by": key.created_by,
    })
}

// ---------------------------------------------------------------------------
// POST /mcp — MCP JSON-RPC proxy endpoint
// ---------------------------------------------------------------------------

#[tracing::instrument(name = "proxy.mcp", skip_all, fields(jsonrpc.method = tracing::field::Empty))]
async fn handle_mcp(
    State(state): State<Arc<ProxyState>>,
    claims: Option<Extension<TokenClaims>>,
    Json(msg): Json<Value>,
) -> impl IntoResponse {
    let claims = claims.map(|Extension(claims)| claims);
    let scopes = scopes_for_request(claims.as_ref(), &state);
    let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = msg.get("id").cloned();
    // Record the JSON-RPC method onto the span so /mcp spans in any OTel
    // backend carry the actual method (`tools/call`, `tools/list`,
    // `initialize`, …) instead of the empty placeholder declared in the
    // `#[tracing::instrument]` `fields(...)` clause.
    tracing::Span::current().record("jsonrpc.method", method);
    tracing::info!(
        %method,
        agent = claims.as_ref().map(|c| c.sub.as_str()).unwrap_or(""),
        job_id = claims.as_ref().and_then(|c| c.job_id.as_deref()).unwrap_or(""),
        sandbox_id = claims.as_ref().and_then(|c| c.sandbox_id.as_deref()).unwrap_or(""),
        "mcp call"
    );

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
                match http::execute_tool_with_gen(
                    provider,
                    _tool,
                    &arguments,
                    &state.keyring,
                    Some(&mcp_gen_ctx),
                    Some(&state.auth_cache),
                )
                .await
                {
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
                "skills": provider.skills,
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
        Some((provider, tool)) => {
            // Merge skills from manifest + SkillRegistry (tool binding + provider binding)
            let mut skills: Vec<String> = provider.skills.clone();
            for s in state.skill_registry.skills_for_tool(&tool.name) {
                if !skills.contains(&s.name) {
                    skills.push(s.name.clone());
                }
            }
            for s in state.skill_registry.skills_for_provider(&provider.name) {
                if !skills.contains(&s.name) {
                    skills.push(s.name.clone());
                }
            }

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "name": tool.name,
                    "description": tool.description,
                    "provider": provider.name,
                    "method": format!("{:?}", tool.method),
                    "endpoint": tool.endpoint,
                    "tags": tool.tags,
                    "hint": tool.hint,
                    "skills": skills,
                    "input_schema": tool.input_schema,
                    "scope": tool.scope,
                })),
            )
        }
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
    claims: Option<Extension<TokenClaims>>,
    Query(query): Query<SkillAtiCatalogQuery>,
) -> impl IntoResponse {
    tracing::debug!(search = ?query.search, "GET /skillati/catalog");

    let client = match skillati_client(&state.keyring) {
        Ok(client) => client,
        Err(err) => return skillati_error_response(err),
    };

    let claims = claims.map(|Extension(c)| c);
    let scopes = scopes_for_request(claims.as_ref(), &state);

    match client.catalog().await {
        Ok(catalog) => {
            // Union of local + remote visibility. Merging here (instead of
            // calling visible_skill_names_with_remote, which would re-fetch)
            // avoids a redundant catalog request on the hot path.
            let mut visible_names = visible_skill_names(&state, &scopes);
            visible_names.extend(visible_remote_skill_names(&state, &scopes, &catalog));

            let mut skills: Vec<_> = catalog
                .into_iter()
                .filter(|s| visible_names.contains(&s.name))
                .collect();
            if let Some(search) = query.search.as_deref() {
                skills = SkillAtiClient::filter_catalog(&skills, search, 25);
            }
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
    claims: Option<Extension<TokenClaims>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl IntoResponse {
    tracing::debug!(%name, "GET /skillati/:name");

    let client = match skillati_client(&state.keyring) {
        Ok(client) => client,
        Err(err) => return skillati_error_response(err),
    };

    let claims = claims.map(|Extension(c)| c);
    let scopes = scopes_for_request(claims.as_ref(), &state);
    let visible_names = match visible_skill_names_with_remote(&state, &scopes, &client).await {
        Ok(v) => v,
        Err(err) => return skillati_error_response(err),
    };
    if !visible_names.contains(&name) {
        return skillati_error_response(SkillAtiError::SkillNotFound(name));
    }

    match client.read_skill(&name).await {
        Ok(activation) => (StatusCode::OK, Json(serde_json::json!(activation))),
        Err(err) => skillati_error_response(err),
    }
}

async fn handle_skillati_resources(
    State(state): State<Arc<ProxyState>>,
    claims: Option<Extension<TokenClaims>>,
    axum::extract::Path(name): axum::extract::Path<String>,
    Query(query): Query<SkillAtiResourcesQuery>,
) -> impl IntoResponse {
    tracing::debug!(%name, prefix = ?query.prefix, "GET /skillati/:name/resources");

    let client = match skillati_client(&state.keyring) {
        Ok(client) => client,
        Err(err) => return skillati_error_response(err),
    };

    let claims = claims.map(|Extension(c)| c);
    let scopes = scopes_for_request(claims.as_ref(), &state);
    let visible_names = match visible_skill_names_with_remote(&state, &scopes, &client).await {
        Ok(v) => v,
        Err(err) => return skillati_error_response(err),
    };
    if !visible_names.contains(&name) {
        return skillati_error_response(SkillAtiError::SkillNotFound(name));
    }

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
    claims: Option<Extension<TokenClaims>>,
    axum::extract::Path(name): axum::extract::Path<String>,
    Query(query): Query<SkillAtiFileQuery>,
) -> impl IntoResponse {
    tracing::debug!(%name, path = %query.path, "GET /skillati/:name/file");

    let client = match skillati_client(&state.keyring) {
        Ok(client) => client,
        Err(err) => return skillati_error_response(err),
    };

    let claims = claims.map(|Extension(c)| c);
    let scopes = scopes_for_request(claims.as_ref(), &state);
    let visible_names = match visible_skill_names_with_remote(&state, &scopes, &client).await {
        Ok(v) => v,
        Err(err) => return skillati_error_response(err),
    };
    if !visible_names.contains(&name) {
        return skillati_error_response(SkillAtiError::SkillNotFound(name));
    }

    match client.read_path(&name, &query.path).await {
        Ok(file) => (StatusCode::OK, Json(serde_json::json!(file))),
        Err(err) => skillati_error_response(err),
    }
}

async fn handle_skillati_refs(
    State(state): State<Arc<ProxyState>>,
    claims: Option<Extension<TokenClaims>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl IntoResponse {
    tracing::debug!(%name, "GET /skillati/:name/refs");

    let client = match skillati_client(&state.keyring) {
        Ok(client) => client,
        Err(err) => return skillati_error_response(err),
    };

    let claims = claims.map(|Extension(c)| c);
    let scopes = scopes_for_request(claims.as_ref(), &state);
    let visible_names = match visible_skill_names_with_remote(&state, &scopes, &client).await {
        Ok(v) => v,
        Err(err) => return skillati_error_response(err),
    };
    if !visible_names.contains(&name) {
        return skillati_error_response(SkillAtiError::SkillNotFound(name));
    }

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
    claims: Option<Extension<TokenClaims>>,
    axum::extract::Path((name, reference)): axum::extract::Path<(String, String)>,
) -> impl IntoResponse {
    tracing::debug!(%name, %reference, "GET /skillati/:name/ref/:reference");

    let client = match skillati_client(&state.keyring) {
        Ok(client) => client,
        Err(err) => return skillati_error_response(err),
    };

    let claims = claims.map(|Extension(c)| c);
    let scopes = scopes_for_request(claims.as_ref(), &state);
    let visible_names = match visible_skill_names_with_remote(&state, &scopes, &client).await {
        Ok(v) => v,
        Err(err) => return skillati_error_response(err),
    };
    if !visible_names.contains(&name) {
        return skillati_error_response(SkillAtiError::SkillNotFound(name));
    }

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

/// Request authentication middleware. Three parallel paths, additive:
///
///   - `Authorization: Bearer <jwt>` → existing JWT validation, claims into
///     extensions.
///   - `Authorization: Ati-Key <raw>` → DB-backed virtual key lookup. Synthesizes
///     a `TokenClaims` from the row's scope arrays so `scopes_for_request` and
///     every handler keep working unchanged.
///   - Passthrough routes → skip JWT entirely (those use HMAC sig-verify, wired
///     in PR 2) and live in a different identity model (HMAC-signed sandboxes,
///     not JWT-bearing agents).
///
/// Public endpoints (`/health`, `/.well-known/jwks.json`) skip all of the above.
/// Dev mode (no `jwt_config`) lets unauthenticated requests through *unless*
/// they explicitly present an `Ati-Key` header — in that case we still try to
/// validate the key against the DB so the JWT path is never the only option.
async fn auth_middleware(
    State(state): State<Arc<ProxyState>>,
    mut req: HttpRequest<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = req.uri().path();

    // Skip auth for public endpoints.
    if path == "/health" || path == "/.well-known/jwks.json" {
        return Ok(next.run(req).await);
    }

    // Skip JWT for passthrough routes — they're authenticated by sig-verify
    // (PR 2) and live in a different identity model (HMAC-signed sandboxes,
    // not JWT-bearing agents). The passthrough router is only consulted when
    // the incoming path doesn't match any named ATI route, so this check is
    // cheap and only kicks in when relevant.
    if let Some(ref router) = state.passthrough {
        let host = req
            .headers()
            .get(axum::http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h).to_string())
            .unwrap_or_default();
        if router.match_request(&host, path).is_some() && !is_named_route(path) {
            return Ok(next.run(req).await);
        }
    }

    let auth_header_owned: Option<String> = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Ati-Key path takes precedence when present — the orchestrator chose it
    // for a reason (per-job revocable credential), and we want the audit
    // trail to reflect that even if the request also happened to carry a JWT.
    if let Some(raw) = auth_header_owned
        .as_deref()
        .and_then(|h| h.strip_prefix("Ati-Key "))
    {
        return authenticate_ati_key(state, raw.to_string(), req, next).await;
    }

    // If no JWT configured, allow all (dev mode). This branch is reached only
    // when the request did NOT present an Ati-Key (handled above) — so we're
    // either an unauthenticated dev call or a legacy JWT call that the dev
    // proxy passes through.
    let jwt_config = match &state.jwt_config {
        Some(c) => c,
        None => return Ok(next.run(req).await),
    };

    // Extract Authorization: Bearer <token>
    let token = match auth_header_owned.as_deref() {
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

/// Returns true if `path` is one of ATI's own named routes (vs. a passthrough
/// route that should bypass JWT and run through the catch-all fallback).
///
/// Kept conservative — when in doubt we treat it as a named route, which
/// means JWT applies. The set is small and stable.
fn is_named_route(path: &str) -> bool {
    matches!(
        path,
        "/call"
            | "/help"
            | "/mcp"
            | "/tools"
            | "/skills"
            | "/skills/resolve"
            | "/skills/bundle"
            | "/skillati/catalog"
            | "/health"
            | "/.well-known/jwks.json"
    ) || path.starts_with("/tools/")
        || path.starts_with("/skills/")
        || path.starts_with("/skillati/")
}

/// Resolve an `Authorization: Ati-Key <raw>` header against the DB. On
/// success, synthesizes a `TokenClaims` from the row's scopes so the rest of
/// the request path (`scopes_for_request`, every handler) is unchanged.
///
/// 503 when the build doesn't include the `db` feature or the key store
/// isn't configured — the caller asked for a feature this proxy doesn't
/// support, which is different from "key not found" (401).
#[cfg(feature = "db")]
async fn authenticate_ati_key(
    state: Arc<ProxyState>,
    raw: String,
    mut req: HttpRequest<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let hash = sha256_hex(raw.as_bytes());
    let store = match state.key_store.as_ref() {
        Some(s) => s,
        None => return Err(StatusCode::SERVICE_UNAVAILABLE),
    };
    let key = match store.lookup(&hash).await {
        Ok(Some(k)) if k.is_active() => k,
        Ok(_) => {
            tracing::debug!("Ati-Key not found or not active");
            return Err(StatusCode::UNAUTHORIZED);
        }
        Err(err) => {
            tracing::warn!(error = %err, "Ati-Key lookup failed");
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let claims = key.to_synthetic_claims();
    tracing::debug!(sub = %claims.sub, "Ati-Key validated");
    req.extensions_mut().insert(TokenHash(hash.clone()));
    req.extensions_mut().insert(EphemeralKeyMarker { hash });
    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

#[cfg(not(feature = "db"))]
async fn authenticate_ati_key(
    _state: Arc<ProxyState>,
    _raw: String,
    _req: HttpRequest<Body>,
    _next: Next,
) -> Result<Response, StatusCode> {
    Err(StatusCode::SERVICE_UNAVAILABLE)
}

/// Per-request extension carrying a stable, irreversible identifier of the
/// bearer token used. Stored in axum request extensions by `auth_middleware`,
/// read by audit-log writers.
#[derive(Debug, Clone)]
pub struct TokenHash(pub String);

/// Marker extension inserted by `auth_middleware` when a request authenticated
/// via `Authorization: Ati-Key`. Carries the key hash so the post-call audit
/// path can bump `ati_keys.request_count` without re-hashing or looking up
/// the row again.
#[derive(Debug, Clone)]
pub struct EphemeralKeyMarker {
    pub hash: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    hex::encode(digest)
}

// --- Router builder ---

/// Build the axum Router from a pre-constructed ProxyState.
/// Outer body-size ceiling for `POST /call`. Large enough to carry the worst
/// case `file_manager:upload` payload (`MAX_UPLOAD_BYTES` of raw bytes,
/// base64-inflated ~4/3×, plus a few KB of JSON framing).
///
/// Per-tool limits (`max_bytes`, `MAX_UPLOAD_BYTES`) plus JWT scopes + rate
/// limits are the real gates — this is just the outermost wrapper check.
fn max_call_body_bytes() -> usize {
    (crate::core::file_manager::MAX_UPLOAD_BYTES as usize)
        .saturating_mul(4)
        .saturating_div(3)
        .saturating_add(8 * 1024)
}

pub fn build_router(state: Arc<ProxyState>) -> Router {
    use axum::extract::DefaultBodyLimit;

    let main = Router::new()
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
        // Fallback handles raw HTTP passthrough — runs only when no named
        // route matched. Returns 404 when `state.passthrough` is `None`
        // (passthrough disabled) or when no manifest claims the request's
        // host+path. The fallback is mounted *before* the layers so the
        // auth + body-limit middlewares wrap it like every other route.
        .fallback(crate::core::passthrough::handle_passthrough)
        // Raise axum's default 2 MB body-extractor limit so request bodies
        // carrying base64-encoded upload payloads aren't rejected before the
        // handler runs. `handle_call` still enforces its own
        // `max_call_body_bytes()` cap when streaming the body to bytes.
        .layer(DefaultBodyLimit::max(max_call_body_bytes()))
        // Layers run *outermost-first* on inbound. Order in code below =
        // inner→outer (axum reverses). We want:
        //   incoming → sig_verify → auth → handler
        // so a 403 in enforce mode never reaches JWT validation. That means
        // `.layer(auth)` is listed FIRST (inner), `.layer(sig_verify)` SECOND
        // (outer; runs first on the wire).
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::core::sig_verify::sig_verify_middleware,
        ))
        // Outermost layer — runs first on inbound, last on outbound. Mints
        // one span per request with HTTP attributes and (when the `otel`
        // feature is on and an exporter is configured) records the
        // `ati.proxy.requests` counter + `ati.proxy.request_duration_ms`
        // histogram. Cheap no-op when the feature is off.
        .layer(axum::middleware::from_fn(observability_middleware))
        .with_state(state.clone());

    // Admin sub-router lives behind its own middleware (master bearer
    // against `state.admin_token`) so the regular `auth_middleware` never
    // sees these paths and can't accidentally match them on a JWT scope.
    let admin = build_admin_router(state.clone());

    main.merge(admin)
}

fn build_admin_router(state: Arc<ProxyState>) -> Router {
    Router::new()
        .route("/admin/keys/issue", post(handle_admin_keys_issue))
        .route(
            "/admin/keys/bulk-revoke",
            post(handle_admin_keys_bulk_revoke),
        )
        .route("/admin/keys/{hash}", get(handle_admin_keys_info))
        .route(
            "/admin/keys/{hash}",
            axum::routing::delete(handle_admin_keys_revoke),
        )
        .route("/admin/keys", get(handle_admin_keys_list))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admin_auth_middleware,
        ))
        .with_state(state)
}

/// Per-tool metric attributes written by the `/call` handler after tool
/// resolution, then read by `observability_middleware` to attach
/// `tool`/`provider` labels to the request counter and duration histogram.
///
/// Only `/call` populates this. Other routes (`/help`, `/skills/*`, etc.)
/// leave the slot empty, so the middleware emits only the base
/// `(http.route, http.request.method, http.response.status_class)`
/// tuple for them and cardinality stays bounded.
///
/// Wrapped in `Arc<Mutex<Option<...>>>` because:
///   1. The middleware needs to read it AFTER the handler has consumed
///      the request body (i.e. after `req.into_body()`), so we can't pass
///      via response extensions without restructuring every early-return
///      path in `handle_call`. Pre-creating the slot lets the handler
///      fill it in-place without owning the request.
///   2. Arc-clone keeps the middleware's read-side handle alive
///      independently of the request being moved into the handler.
///
/// `pub(crate)` because the in-crate `proxy::server::tests` need to
/// construct one directly and observe what `handle_call` writes into it.
/// External callers should treat the per-tool label as an opaque
/// otel-metric attribute — this slot is an internal coordination type.
#[derive(Default)]
pub(crate) struct CallMetricLabelsSlot {
    /// `(provider_name, tool_name)`. Populated by `handle_call` after
    /// tool resolution succeeds. `None` if the request errored before
    /// resolution (bad body, unknown tool) — middleware then skips the
    /// extra labels.
    pub(crate) inner: std::sync::Mutex<Option<(String, String)>>,
}

/// Per-passthrough labels written by `handle_passthrough` after the route
/// matches, then read by `observability_middleware` to attach a `route`
/// label to the request counter / duration histogram. Cardinality is
/// bounded by the number of passthrough manifests (~10 in prod), so this
/// is safe to ship as a label.
///
/// Same Arc/Mutex coordination pattern as `CallMetricLabelsSlot` — see
/// that type's docs for the design rationale.
#[derive(Default)]
pub(crate) struct PassthroughMetricLabelsSlot {
    /// Manifest name of the matched passthrough route (e.g. "litellm",
    /// "browserbase"). `None` when no route matched (404), the request
    /// hit a named handler instead, or the slot was never written
    /// (passthrough disabled).
    pub(crate) route: std::sync::Mutex<Option<String>>,
}

/// Middleware enforcing master-token bearer auth on `/admin/*`. Constant-time
/// compares the request's `Authorization: Bearer …` against `state.admin_token`.
/// Returns 503 when no admin token is configured (i.e. don't expose admin
/// surfaces by accident).
async fn admin_auth_middleware(
    State(state): State<Arc<ProxyState>>,
    req: HttpRequest<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let configured = match state.admin_token.as_ref() {
        Some(t) => t,
        None => return Err(StatusCode::SERVICE_UNAVAILABLE),
    };
    let presented = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or("");
    if !constant_time_eq(configured.as_bytes(), presented.as_bytes()) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(req).await)
}

/// Constant-time byte-slice equality. Does NOT short-circuit on length
/// mismatch — that early return would leak the configured token's byte
/// length via response timing (an attacker could probe with various-length
/// candidates and time the rejection). Instead, we always walk the full
/// length of `a` (the configured token, length not secret to the server)
/// XOR-ing index-by-index against `b`, and fold the length difference
/// into `diff` so unequal-length inputs always return false.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Fold the FULL `usize` length-XOR into a single bit so any nonzero
    // length difference — including ones whose low 16 bits happen to be
    // zero (e.g. exactly 65536 bytes apart) — sets `len_diff_bit` to 1.
    // The previous shape `(len_xor as u8) | ((len_xor >> 8) as u8)` only
    // covered bits 0–15 of the usize XOR, so a length mismatch that was
    // an exact multiple of 65536 silently passed. Greptile flagged this
    // as a security P2; the exploit requires already knowing the token,
    // so blast radius was small, but the guarantee should hold without
    // qualification.
    let len_xor = (a.len() ^ b.len()) as u64;
    let len_diff_bit: u8 = if len_xor == 0 { 0 } else { 1 };
    let mut diff: u8 = len_diff_bit;
    let n = a.len();
    for i in 0..n {
        // Index `b` modulo its length when `b` is shorter; the diff
        // accumulator already records the length mismatch, so the value
        // we XOR is irrelevant — only the runtime needs to be uniform.
        let bi = if b.is_empty() { 0u8 } else { b[i % b.len()] };
        diff |= a[i] ^ bi;
    }
    diff == 0
}

/// Per-request observability layer. Always mints a `tracing` span so events
/// inside handlers nest under one identifiable parent; when the `otel`
/// feature is compiled in (and an exporter is configured), the span is
/// exported and request metrics are recorded.
///
/// Attributes follow OTel semantic conventions for HTTP servers:
/// `http.request.method`, `http.route`, `http.response.status_code`.
/// `http.route` falls back to the raw path when axum hasn't matched a route
/// yet (e.g. the passthrough fallback).
///
/// For `/call` requests, the `/call` handler additionally writes the
/// resolved `(provider, tool)` pair into a `CallMetricLabelsSlot` inserted
/// into request extensions — we pick it up after `next.run` and attach
/// those as extra metric labels so dashboards can break down request rate,
/// latency, and error rate by tool. Other routes leave the slot empty,
/// keeping the base label cardinality unchanged.
async fn observability_middleware(mut req: HttpRequest<Body>, next: Next) -> Response {
    use tracing::Instrument as _;

    let method = req.method().clone();
    let uri = req.uri().clone();
    // `http.route` must be a *template* (low cardinality), not a raw path.
    // axum's `MatchedPath` gives us the template for named routes
    // (`/skills/{name}`). When no named route matches, the request falls
    // through to the passthrough handler — using the raw path there would
    // make every unique forwarded URL its own metric label, which blows up
    // Prometheus/Mimir cardinality. Bucket all such requests under a single
    // low-cardinality value; the passthrough span (added in PR B) records
    // the actual route name + upstream as separate attributes.
    let raw_path = uri.path().to_string();
    let route = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| "/__passthrough_or_unmatched".to_string());

    let span = tracing::info_span!(
        "http.server.request",
        "http.request.method" = %method,
        "http.route" = %route,
        "url.path" = %raw_path,
        "http.response.status_code" = tracing::field::Empty,
    );

    // Extract inbound W3C trace context (`traceparent` / `tracestate`)
    // from the request headers and attach it as the span's parent. This is
    // what lets the agent's outer trace continue through ATI to upstream
    // services. No-op when the `otel` feature is off — `tracing` spans
    // still nest as usual.
    #[cfg(feature = "otel")]
    crate::core::otel::extract_request_parent_into_span(&span, req.headers());

    // Pre-create the per-tool labels slot and stash a clone for the
    // post-`next.run` read. Only the `/call` handler writes into it; for
    // every other route this stays `None` and the middleware emits the
    // base label tuple unchanged.
    let labels_slot = std::sync::Arc::new(CallMetricLabelsSlot::default());
    req.extensions_mut().insert(labels_slot.clone());

    // Same pattern for passthrough: `handle_passthrough` writes the
    // matched manifest name into this slot so the middleware can attach
    // a `route` label. Cardinality is bounded by the number of
    // passthrough manifests configured on the proxy (~10).
    let pt_slot = std::sync::Arc::new(PassthroughMetricLabelsSlot::default());
    req.extensions_mut().insert(pt_slot.clone());

    let start = std::time::Instant::now();
    let response = next.run(req).instrument(span.clone()).await;
    let status = response.status();
    span.record("http.response.status_code", status.as_u16());

    #[cfg(feature = "otel")]
    {
        if let Some(m) = crate::core::otel::metrics() {
            use opentelemetry::KeyValue;
            let status_class = format!("{}xx", status.as_u16() / 100);
            let mut attrs = vec![
                KeyValue::new("http.route", route.clone()),
                KeyValue::new("http.request.method", method.to_string()),
                KeyValue::new("http.response.status_class", status_class),
            ];
            // `/call`-only: pick up the resolved (provider, tool) the
            // handler wrote into the slot. Bounded cardinality — ~155
            // tools × 3 status classes × 1 method ≈ 465 series.
            //
            // Cloned (not `.take()`) so an outer test harness can also
            // observe the slot via its own Arc clone — read semantics
            // here, not move semantics.
            if let Some((provider, tool)) = labels_slot
                .inner
                .lock()
                .ok()
                .and_then(|g| g.as_ref().cloned())
            {
                attrs.push(KeyValue::new("provider", provider));
                attrs.push(KeyValue::new("tool", tool));
            }
            // Passthrough-only: pick up the matched route's manifest
            // name. Mutually exclusive with the per-tool labels in
            // practice (passthrough requests don't hit `/call` and vice
            // versa), but the middleware appends whichever is set so
            // the metric pipeline is symmetric.
            if let Some(pt_route) = pt_slot.route.lock().ok().and_then(|g| g.as_ref().cloned()) {
                attrs.push(KeyValue::new("route", pt_route));
            }
            m.proxy_requests.add(1, &attrs);
            m.proxy_request_duration_ms
                .record(start.elapsed().as_secs_f64() * 1000.0, &attrs);
        }
    }
    #[cfg(not(feature = "otel"))]
    {
        // Keep the variables referenced so the no-feature build doesn't warn.
        let _ = (&route, &method, start, &labels_slot, &pt_slot);
    }

    response
}

/// Install a SIGHUP handler that re-reads the keyring and hot-swaps the
/// sig-verify secret. Lets `ati edge rotate-keyring` (PR 3) replace the
/// signing secret without restarting the proxy.
///
/// Why not also reload `passthrough`? Passthrough's per-route auth headers
/// are also keyring-derived; full reload there means rebuilding
/// `PassthroughRouter`. Out of scope for PR 2 — when the rotate-keyring
/// command lands we'll extend this handler.
fn install_sighup_reload_handler(state: Arc<ProxyState>, ati_dir: PathBuf, env_keys: bool) {
    use tokio::signal::unix::{signal, SignalKind};
    tokio::spawn(async move {
        let mut sig = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "failed to install SIGHUP handler — keyring rotation will require restart");
                return;
            }
        };
        while sig.recv().await.is_some() {
            tracing::info!("SIGHUP received — reloading keyring and sig-verify secret");
            match reload_keyring(&ati_dir, env_keys) {
                Ok(kr) => {
                    // Keyring re-read successfully (even if empty by design).
                    // Apply the new state — secret may legitimately be removed,
                    // and ArcSwapOption::store(None) is the right thing then.
                    state.sig_verify.reload(&kr);
                }
                Err(e) => {
                    // Transient read/decrypt failure. PRESERVE the previously
                    // loaded secret — otherwise a single disk hiccup turns the
                    // proxy into a 403 machine in enforce mode (Greptile P1 on
                    // PR #96). The operator can re-issue SIGHUP after fixing
                    // the underlying problem.
                    tracing::error!(
                        error = %e,
                        "keyring reload failed on SIGHUP — keeping previously loaded secret in place"
                    );
                }
            }
        }
    });
}

/// Re-read the keyring from disk (or environment, with `--env-keys`).
/// Returns `Err` ONLY for transient/structural failures the caller should
/// recover from (file present but undecryptable, credentials file present
/// but corrupt). Returns `Ok(Keyring::empty())` if no keyring is configured
/// at all — that's a legitimate config state, not a failure.
///
/// The distinction matters for SIGHUP reload: on `Err` the proxy must keep
/// the previously-loaded sig-verify secret in place; on `Ok(empty)` the
/// operator has intentionally removed the keyring and the secret should go
/// with it.
fn reload_keyring(ati_dir: &Path, env_keys: bool) -> Result<Keyring, Box<dyn std::error::Error>> {
    if env_keys {
        return Ok(Keyring::from_env());
    }
    let keyring_path = ati_dir.join("keyring.enc");
    if keyring_path.exists() {
        if let Ok(kr) = Keyring::load(&keyring_path) {
            return Ok(kr);
        }
        if let Ok(kr) = Keyring::load_local(&keyring_path, ati_dir) {
            return Ok(kr);
        }
        return Err(format!(
            "keyring.enc at {} exists but could not be decrypted",
            keyring_path.display()
        )
        .into());
    }
    let creds_path = ati_dir.join("credentials");
    if creds_path.exists() {
        match Keyring::load_credentials(&creds_path) {
            Ok(kr) => return Ok(kr),
            Err(e) => {
                return Err(format!(
                    "credentials file at {} present but could not be parsed: {e}",
                    creds_path.display()
                )
                .into());
            }
        }
    }
    // No keyring configured at all — legitimate empty state.
    Ok(Keyring::empty())
}

// --- Server startup ---

/// Start the proxy server.
#[allow(clippy::too_many_arguments)] // call sites are all in main.rs and stay readable
pub async fn run(
    port: u16,
    bind_addr: Option<String>,
    ati_dir: PathBuf,
    _verbose: bool,
    env_keys: bool,
    migrate: bool,
    enable_passthrough: bool,
    sig_verify_mode: crate::core::sig_verify::SigVerifyMode,
    sig_drift_seconds: i64,
    sig_exempt_paths: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::core::sig_verify::{
        SigVerifyConfig, SigVerifyMode, DEFAULT_EXEMPT_PATHS, SECRET_KEY_NAME,
    };

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

    // Optional persistence layer. `Disabled` when ATI_DB_URL is unset or the
    // build was made without `--features db`.
    let db = crate::core::db::connect_optional().await?;
    if migrate {
        crate::core::db::run_migrations(&db).await?;
        if db.is_connected() {
            tracing::info!("applied database migrations");
        }
    }
    let db_status = db.status();

    // Build the passthrough router once at startup. When `--enable-passthrough`
    // is off, leave it as None — the fallback handler then 404s every request
    // that didn't hit a named route, matching today's behaviour.
    let passthrough = if enable_passthrough {
        match crate::core::passthrough::PassthroughRouter::build(&registry, &keyring) {
            Ok(router) => {
                tracing::info!(routes = router.len(), "passthrough router built");
                Some(Arc::new(router))
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to build passthrough router");
                return Err(Box::new(e));
            }
        }
    } else {
        None
    };
    let passthrough_count = passthrough.as_ref().map(|r| r.len()).unwrap_or(0);

    // Build the sig-verify config. Always built (even when passthrough is
    // disabled): the middleware wraps every non-exempt request regardless of
    // route type so that the eventual passthrough rollout doesn't need a
    // second wiring change. In `Log` mode the middleware is effectively a
    // no-op except for the structured log line.
    let exempt_owned: Vec<String> = match &sig_exempt_paths {
        Some(csv) => crate::core::sig_verify::parse_exempt_paths(csv),
        None => DEFAULT_EXEMPT_PATHS.iter().map(|s| s.to_string()).collect(),
    };
    let exempt_refs: Vec<&str> = exempt_owned.iter().map(|s| s.as_str()).collect();
    let sig_verify = Arc::new(SigVerifyConfig::build(
        sig_verify_mode,
        sig_drift_seconds,
        &exempt_refs,
        &keyring,
    )?);
    let sig_secret_loaded = sig_verify.has_secret();

    // Fail-closed gate: in Enforce mode, missing secret means every request
    // would 403. Refuse to start instead of silently breaking traffic.
    if sig_verify_mode == SigVerifyMode::Enforce && !sig_secret_loaded {
        return Err(format!(
            "--sig-verify-mode enforce requires the keyring entry '{SECRET_KEY_NAME}' \
             to be present. Without it every signed request fails closed. Either \
             populate the keyring (typically via `ati edge bootstrap-keyring` in PR 3, \
             or by setting ATI_KEY_SANDBOX_SIGNING_SHARED_SECRET if running with \
             --env-keys), or drop back to `--sig-verify-mode log` during rollout."
        )
        .into());
    }
    // Soft warning: passthrough enabled with non-blocking sig-verify (Log OR
    // Warn) AND no secret in the keyring = passthrough is effectively
    // unauthenticated. Mirror PR 1's loud warning so we don't regress.
    // Greptile review on #96 flagged that the original check only fired in
    // Log mode; Warn is just as porous — it adds a response header but never
    // returns 403.
    let non_blocking = matches!(sig_verify_mode, SigVerifyMode::Log | SigVerifyMode::Warn);
    if enable_passthrough && non_blocking && !sig_secret_loaded {
        tracing::error!(
            mode = ?sig_verify_mode,
            "*** SIG-VERIFY IS NON-BLOCKING AND NO SECRET IS CONFIGURED — passthrough is \
             effectively unauthenticated. Flip to --sig-verify-mode enforce + load \
             the keyring entry '{SECRET_KEY_NAME}' before exposing this to untrusted \
             networks."
        );
    }

    // Build the virtual-key store + LISTEN task when the DB is connected.
    // Connection is required for the LISTEN side; if it fails we degrade
    // gracefully (key path returns 503) rather than refusing to start.
    #[cfg(feature = "db")]
    let key_store: OptionalKeyStore = if let Some(pool) = db.pool() {
        match crate::core::keys::KeyStore::new(pool.clone()).await {
            Ok(store) => {
                tracing::info!("started ati_keys store + LISTEN task");
                Some(store)
            }
            Err(err) => {
                tracing::warn!(error = %err, "failed to start KeyStore; Ati-Key auth will return 503");
                None
            }
        }
    } else {
        None
    };
    #[cfg(not(feature = "db"))]
    let key_store: OptionalKeyStore = None;

    // Plain-text admin bearer from env. Required for /admin/keys/* endpoints.
    // Absent → endpoints return 503 (intentional: no token = no admin surface).
    let admin_token = std::env::var("ATI_ADMIN_TOKEN")
        .ok()
        .filter(|s| !s.is_empty());
    if key_store.is_some() && admin_token.is_none() {
        tracing::warn!("DB connected but ATI_ADMIN_TOKEN unset — /admin/keys/* will return 503");
    }

    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring,
        jwt_config,
        jwks_json,
        auth_cache: AuthCache::new(),
        db,
        passthrough,
        sig_verify,
        key_store,
        admin_token,
    });

    // Hot-reload secret on SIGHUP — `ati edge rotate-keyring` (PR 3) re-encrypts
    // the keyring then signals us. Spawned before `axum::serve` so a HUP that
    // races startup isn't lost. The handler clones a weak Arc-handle to state
    // so it doesn't keep the proxy alive past natural shutdown.
    install_sighup_reload_handler(state.clone(), ati_dir.clone(), env_keys);

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
        db = db_status,
        passthrough = passthrough_count,
        sig_verify_mode = ?sig_verify_mode,
        sig_verify_secret = sig_secret_loaded,
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

/// Dispatch a `file_manager:*` tool call. Returns either a JSON payload or an
/// (HTTP status, message) error for the caller to forward.
async fn dispatch_file_manager(
    tool_name: &str,
    args: &HashMap<String, Value>,
    provider: &Provider,
    keyring: &Keyring,
) -> Result<Value, (StatusCode, String)> {
    use crate::core::file_manager::{self, DownloadArgs, FileManagerError, UploadArgs};

    // One mapping, derived from FileManagerError::http_status, so adding an
    // error variant can't silently regress one handler while the other updates.
    let to_resp = |e: FileManagerError| {
        let status =
            StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, e.to_string())
    };

    match tool_name {
        "file_manager:download" => {
            let parsed = DownloadArgs::from_value(args).map_err(to_resp)?;
            let result = file_manager::fetch_bytes(&parsed).await.map_err(to_resp)?;
            Ok(file_manager::build_download_response(&result))
        }
        "file_manager:upload" => {
            let parsed = UploadArgs::from_wire(args).map_err(to_resp)?;
            file_manager::upload_to_destination(
                parsed,
                &provider.upload_destinations,
                provider.upload_default_destination.as_deref(),
                keyring,
            )
            .await
            .map_err(to_resp)
        }
        other => Err((
            StatusCode::NOT_FOUND,
            format!("Unknown file_manager tool: '{other}'"),
        )),
    }
}

fn write_proxy_audit(
    call_req: &CallRequest,
    agent_sub: &str,
    claims: Option<&TokenClaims>,
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
        job_id: claims.and_then(|c| c.job_id.clone()),
        sandbox_id: claims.and_then(|c| c.sandbox_id.clone()),
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
- If skills are relevant, tell the agent to load them using the Skill tool (e.g., `skill: "research-financial-data"`)

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
        "These skills are available. Load them using the Skill tool (e.g., `skill: \"skill-name\"`).\n\n",
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

#[cfg(test)]
mod tests {
    //! In-crate tests covering wiring that can't be observed from outside
    //! the crate (notably `CallMetricLabelsSlot` access on private types).

    use super::*;
    use crate::core::auth_generator::AuthCache;
    use crate::core::db::DbState;
    use crate::core::keyring::Keyring;
    use crate::core::manifest::ManifestRegistry;
    use crate::core::sig_verify::{SigVerifyConfig, SigVerifyMode, DEFAULT_EXEMPT_PATHS};
    use crate::core::skill::SkillRegistry;
    use axum::body::Body;
    use axum::extract::State;
    use std::sync::Arc;

    /// Build a minimal proxy state with one CLI-handler echo tool. Tools
    /// auto-register: the provider's name is also the tool's name, so the
    /// resolved labels are both "echoprov".
    ///
    /// Returns the TempDir alongside the state so it survives until the
    /// caller drops it — `ManifestRegistry::load` reads the manifests
    /// eagerly and `SkillRegistry::load("/nonexistent")` doesn't touch a
    /// real path, so the tempdir only needs to outlive the load call.
    /// Returning it keeps cleanup automatic (drop = unlink).
    fn state_with_echo_tool() -> (Arc<ProxyState>, tempfile::TempDir) {
        let manifests_tmp = tempfile::tempdir().expect("manifests tempdir");
        std::fs::write(
            manifests_tmp.path().join("myecho.toml"),
            r#"
[provider]
name = "echoprov"
description = "Test echo CLI"
handler = "cli"
cli_command = "echo"
auth_type = "none"
"#,
        )
        .unwrap();
        let registry = ManifestRegistry::load(manifests_tmp.path()).expect("load manifests");
        let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
        let state = Arc::new(ProxyState {
            registry,
            skill_registry,
            keyring: Keyring::empty(),
            jwt_config: None,
            jwks_json: None,
            auth_cache: AuthCache::new(),
            db: DbState::Disabled,
            passthrough: None,
            sig_verify: Arc::new(
                SigVerifyConfig::build(
                    SigVerifyMode::Log,
                    60,
                    DEFAULT_EXEMPT_PATHS,
                    &Keyring::empty(),
                )
                .expect("sig verify"),
            ),
            key_store: None,
            admin_token: None,
        });
        (state, manifests_tmp)
    }

    /// Issue #111: when `/call` resolves a tool, the request handler MUST
    /// write the resolved `(provider, tool)` pair into the
    /// `CallMetricLabelsSlot` so the observability middleware can attach
    /// them as metric labels for per-tool dashboards.
    #[tokio::test]
    async fn handle_call_writes_provider_and_tool_into_metric_labels_slot() {
        let (state, _tmp) = state_with_echo_tool();
        let slot = Arc::new(CallMetricLabelsSlot::default());

        let body = serde_json::json!({ "tool_name": "echoprov", "args": ["hi"] });
        let mut req = HttpRequest::builder()
            .method("POST")
            .uri("/call")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut().insert(slot.clone());

        let _resp = handle_call(State(state), req).await;

        let labels = slot
            .inner
            .lock()
            .unwrap()
            .clone()
            .expect("handle_call must populate the slot when tool resolution succeeds");
        assert_eq!(labels, ("echoprov".to_string(), "echoprov".to_string()));
    }

    /// Build a minimal proxy state with one passthrough route pointing at
    /// `upstream_url`. The route name is "echoroute"; the route forwards
    /// `/api/*` and has a deny on `/api/denied`.
    fn state_with_passthrough_route(upstream_url: &str) -> (Arc<ProxyState>, tempfile::TempDir) {
        let manifests_tmp = tempfile::tempdir().expect("manifests tempdir");
        std::fs::write(
            manifests_tmp.path().join("echoroute.toml"),
            format!(
                r#"
[provider]
name = "echoroute"
description = "passthrough route for slot test"
handler = "passthrough"
base_url = "{upstream_url}"
path_prefix = "/api"
auth_type = "none"
deny_paths = ["/denied"]
"#
            ),
        )
        .unwrap();
        let registry = ManifestRegistry::load(manifests_tmp.path()).expect("load manifests");
        let keyring = Keyring::empty();
        let passthrough = crate::core::passthrough::PassthroughRouter::build(&registry, &keyring)
            .expect("build passthrough router");
        let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
        let state = Arc::new(ProxyState {
            registry,
            skill_registry,
            keyring,
            jwt_config: None,
            jwks_json: None,
            auth_cache: AuthCache::new(),
            db: DbState::Disabled,
            passthrough: Some(Arc::new(passthrough)),
            sig_verify: Arc::new(
                SigVerifyConfig::build(
                    SigVerifyMode::Log,
                    60,
                    DEFAULT_EXEMPT_PATHS,
                    &Keyring::empty(),
                )
                .expect("sig verify"),
            ),
            key_store: None,
            admin_token: None,
        });
        (state, manifests_tmp)
    }

    /// Issue #113: `handle_passthrough` must write the matched route's
    /// manifest name into `PassthroughMetricLabelsSlot` so the
    /// observability middleware can attach a `route` label to
    /// ati.proxy.requests / ati.proxy.request_duration_ms.
    #[tokio::test]
    async fn handle_passthrough_writes_route_into_slot_on_match() {
        use wiremock::matchers::{method as m_method, path as m_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(m_method("GET"))
            .and(m_path("/v1/anything"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&upstream)
            .await;

        let (state, _tmp) = state_with_passthrough_route(&upstream.uri());
        let slot = Arc::new(PassthroughMetricLabelsSlot::default());

        let mut req = HttpRequest::builder()
            .method("GET")
            .uri("/api/v1/anything")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(slot.clone());

        let _resp = crate::core::passthrough::handle_passthrough(State(state), req).await;

        let route = slot
            .route
            .lock()
            .unwrap()
            .clone()
            .expect("handle_passthrough must populate route on match");
        assert_eq!(route, "echoroute");
    }

    /// When the path matches the route AND triggers a deny_paths rule,
    /// the route slot MUST still be populated — the route was matched,
    /// just the path was rejected. (The deny COUNTER is separately
    /// incremented at the same site; that's covered by inspection of
    /// the metric handle in the otel-feature build.)
    #[tokio::test]
    async fn handle_passthrough_writes_route_into_slot_even_on_deny() {
        let (state, _tmp) = state_with_passthrough_route("http://unused");
        let slot = Arc::new(PassthroughMetricLabelsSlot::default());

        let mut req = HttpRequest::builder()
            .method("GET")
            // `/api/denied` matches route "echoroute" but is in deny_paths.
            .uri("/api/denied")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(slot.clone());

        let resp = crate::core::passthrough::handle_passthrough(State(state), req).await;
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);

        let route = slot
            .route
            .lock()
            .unwrap()
            .clone()
            .expect("deny path must still attribute the request to its route");
        assert_eq!(route, "echoroute");
    }

    /// When no route matches at all (passthrough disabled or no manifest
    /// claims the path), the slot stays empty — the request can't be
    /// attributed to any route.
    #[tokio::test]
    async fn handle_passthrough_leaves_slot_empty_when_no_route_matches() {
        let (state, _tmp) = state_with_passthrough_route("http://unused");
        let slot = Arc::new(PassthroughMetricLabelsSlot::default());

        let mut req = HttpRequest::builder()
            .method("GET")
            // /unrelated/foo does NOT match the /api prefix.
            .uri("/unrelated/foo")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(slot.clone());

        let _resp = crate::core::passthrough::handle_passthrough(State(state), req).await;
        assert!(
            slot.route.lock().unwrap().is_none(),
            "no route match must leave the slot empty"
        );
    }

    /// Reverse: when tool resolution FAILS (unknown tool), the handler
    /// MUST NOT write anything — the slot stays empty so the middleware
    /// emits the base label tuple only. This preserves the contract that
    /// `tool=` is never set with a value that isn't a real resolved tool.
    #[tokio::test]
    async fn handle_call_leaves_slot_empty_on_unknown_tool() {
        let (state, _tmp) = state_with_echo_tool();
        let slot = Arc::new(CallMetricLabelsSlot::default());

        let body = serde_json::json!({ "tool_name": "does_not_exist", "args": [] });
        let mut req = HttpRequest::builder()
            .method("POST")
            .uri("/call")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut().insert(slot.clone());

        let _resp = handle_call(State(state), req).await;

        assert!(
            slot.inner.lock().unwrap().is_none(),
            "unknown-tool path must NOT populate the metric labels slot"
        );
    }
}
