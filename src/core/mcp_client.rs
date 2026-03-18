/// MCP client — connects to MCP servers via stdio or Streamable HTTP transport.
///
/// Implements the MCP protocol (2025-03-26 revision):
/// - JSON-RPC 2.0 message framing
/// - stdio transport: newline-delimited JSON over stdin/stdout
/// - Streamable HTTP transport: POST with Accept: application/json, text/event-stream
///   Server may respond with JSON or SSE stream. Supports Mcp-Session-Id for sessions.
/// - Lifecycle: initialize → tools/list → tools/call → shutdown
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write as IoWrite};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::core::auth_generator::{self, AuthCache, GenContext};
use crate::core::keyring::Keyring;
use crate::core::manifest::Provider;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum McpError {
    #[error("MCP transport error: {0}")]
    Transport(String),
    #[error("MCP protocol error (code {code}): {message}")]
    Protocol { code: i64, message: String },
    #[error("MCP server did not return tools capability")]
    NoToolsCapability,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("MCP initialization failed: {0}")]
    InitFailed(String),
    #[error("SSE parse error: {0}")]
    SseParse(String),
    #[error("MCP server process exited unexpectedly")]
    ProcessExited,
    #[error("Missing MCP configuration: {0}")]
    Config(String),
}

// ---------------------------------------------------------------------------
// JSON-RPC types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Value>,
}

// Note: We parse JSON-RPC responses manually via serde_json::Value
// rather than typed deserialization, since responses can be interleaved
// with notifications and batches in SSE streams.

// ---------------------------------------------------------------------------
// MCP protocol types
// ---------------------------------------------------------------------------

/// Tool definition from MCP tools/list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolDef {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, rename = "inputSchema")]
    pub input_schema: Option<Value>,
}

/// Content item from MCP tools/call response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpContent {
    #[serde(rename = "type")]
    pub content_type: String,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default, rename = "mimeType")]
    pub mime_type: Option<String>,
}

/// Result from tools/call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolResult {
    pub content: Vec<McpContent>,
    #[serde(default, rename = "isError")]
    pub is_error: bool,
}

// ---------------------------------------------------------------------------
// Transport abstraction
// ---------------------------------------------------------------------------

/// Internal transport enum — stdio or HTTP.
enum Transport {
    Stdio(StdioTransport),
    Http(HttpTransport),
}

/// Stdio transport: subprocess with stdin/stdout.
struct StdioTransport {
    child: Child,
    /// We write JSON-RPC to the child's stdin. Option so we can take() on disconnect.
    stdin: Option<std::process::ChildStdin>,
    /// We read newline-delimited JSON-RPC from stdout.
    reader: BufReader<std::process::ChildStdout>,
}

/// Streamable HTTP transport: POST to MCP endpoint.
struct HttpTransport {
    client: reqwest::Client,
    url: String,
    /// Session ID from Mcp-Session-Id header (set after initialize).
    session_id: Option<String>,
    /// Auth header name (default: "Authorization"). Custom for APIs using e.g. "x-api-key".
    auth_header_name: String,
    /// Auth header value (e.g., "Bearer <token>") injected on every request.
    auth_header: Option<String>,
    /// Extra headers from provider config.
    extra_headers: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// McpClient
// ---------------------------------------------------------------------------

/// MCP client that connects to a single MCP server.
pub struct McpClient {
    transport: Mutex<Transport>,
    next_id: AtomicU64,
    /// Cached tools from tools/list.
    cached_tools: Mutex<Option<Vec<McpToolDef>>>,
    /// Provider name (for logging).
    provider_name: String,
}

impl McpClient {
    /// Connect to an MCP server based on the provider's configuration.
    ///
    /// For stdio: spawns the subprocess with env vars resolved from keyring.
    /// For HTTP: creates an HTTP client with auth headers.
    pub async fn connect(provider: &Provider, keyring: &Keyring) -> Result<Self, McpError> {
        Self::connect_with_gen(provider, keyring, None, None).await
    }

    /// Connect to an MCP server, optionally using a dynamic auth generator.
    pub async fn connect_with_gen(
        provider: &Provider,
        keyring: &Keyring,
        gen_ctx: Option<&GenContext>,
        auth_cache: Option<&AuthCache>,
    ) -> Result<Self, McpError> {
        let transport = match provider.mcp_transport_type() {
            "stdio" => {
                let command = provider.mcp_command.as_deref().ok_or_else(|| {
                    McpError::Config("mcp_command required for stdio transport".into())
                })?;

                // Resolve env vars: "${key_name}" → keyring value
                let mut env_map: HashMap<String, String> = HashMap::new();
                // Selectively pass through essential env vars (don't leak secrets)
                if let Ok(path) = std::env::var("PATH") {
                    env_map.insert("PATH".to_string(), path);
                }
                if let Ok(home) = std::env::var("HOME") {
                    env_map.insert("HOME".to_string(), home);
                }
                // Add provider-specific env vars (resolved from keyring)
                for (k, v) in &provider.mcp_env {
                    let resolved = resolve_env_value(v, keyring);
                    env_map.insert(k.clone(), resolved);
                }

                // If auth_generator is configured, run it and inject into env
                if let Some(gen) = &provider.auth_generator {
                    let default_ctx = GenContext::default();
                    let ctx = gen_ctx.unwrap_or(&default_ctx);
                    let default_cache = AuthCache::new();
                    let cache = auth_cache.unwrap_or(&default_cache);
                    match auth_generator::generate(provider, gen, ctx, keyring, cache).await {
                        Ok(cred) => {
                            env_map.insert("ATI_AUTH_TOKEN".to_string(), cred.value);
                            for (k, v) in &cred.extra_env {
                                env_map.insert(k.clone(), v.clone());
                            }
                        }
                        Err(e) => {
                            return Err(McpError::Config(format!("auth_generator failed: {e}")));
                        }
                    }
                }

                let mut child = Command::new(command)
                    .args(&provider.mcp_args)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .env_clear()
                    .envs(&env_map)
                    .spawn()
                    .map_err(|e| {
                        McpError::Transport(format!("Failed to spawn MCP server '{command}': {e}"))
                    })?;

                let stdin = child
                    .stdin
                    .take()
                    .ok_or_else(|| McpError::Transport("No stdin".into()))?;
                let stdout = child
                    .stdout
                    .take()
                    .ok_or_else(|| McpError::Transport("No stdout".into()))?;
                let reader = BufReader::new(stdout);

                Transport::Stdio(StdioTransport {
                    child,
                    stdin: Some(stdin),
                    reader,
                })
            }
            "http" => {
                let url = provider.mcp_url.as_deref().ok_or_else(|| {
                    McpError::Config("mcp_url required for HTTP transport".into())
                })?;

                // Build auth header: generator takes priority over static keyring
                let auth_header = if let Some(gen) = &provider.auth_generator {
                    let default_ctx = GenContext::default();
                    let ctx = gen_ctx.unwrap_or(&default_ctx);
                    let default_cache = AuthCache::new();
                    let cache = auth_cache.unwrap_or(&default_cache);
                    match auth_generator::generate(provider, gen, ctx, keyring, cache).await {
                        Ok(cred) => match &provider.auth_type {
                            super::manifest::AuthType::Bearer => {
                                Some(format!("Bearer {}", cred.value))
                            }
                            super::manifest::AuthType::Header => {
                                if let Some(prefix) = &provider.auth_value_prefix {
                                    Some(format!("{prefix}{}", cred.value))
                                } else {
                                    Some(cred.value)
                                }
                            }
                            _ => Some(cred.value),
                        },
                        Err(e) => {
                            return Err(McpError::Config(format!("auth_generator failed: {e}")));
                        }
                    }
                } else {
                    build_auth_header(provider, keyring)
                };

                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(300))
                    .build()?;

                // Resolve ${key_name} placeholders in the URL from keyring
                let resolved_url = resolve_env_value(url, keyring);

                let auth_header_name = provider
                    .auth_header_name
                    .clone()
                    .unwrap_or_else(|| "Authorization".to_string());

                Transport::Http(HttpTransport {
                    client,
                    url: resolved_url,
                    session_id: None,
                    auth_header_name,
                    auth_header,
                    extra_headers: provider.extra_headers.clone(),
                })
            }
            other => {
                return Err(McpError::Config(format!(
                    "Unknown MCP transport: '{other}' (expected 'stdio' or 'http')"
                )));
            }
        };

        let client = McpClient {
            transport: Mutex::new(transport),
            next_id: AtomicU64::new(1),
            cached_tools: Mutex::new(None),
            provider_name: provider.name.clone(),
        };

        // Perform MCP initialize handshake
        client.initialize().await?;

        Ok(client)
    }

    /// Perform the MCP initialize handshake.
    async fn initialize(&self) -> Result<(), McpError> {
        let params = serde_json::json!({
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {
                "name": "ati",
                "version": env!("CARGO_PKG_VERSION")
            }
        });

        let response = self.send_request("initialize", Some(params)).await?;

        // Verify server has tools capability
        let capabilities = response.get("capabilities").unwrap_or(&Value::Null);
        if capabilities.get("tools").is_none() {
            return Err(McpError::NoToolsCapability);
        }

        // Extract session ID from HTTP transport response (handled inside send_request)

        // Send initialized notification
        self.send_notification("notifications/initialized", None)
            .await?;

        Ok(())
    }

    /// Discover tools via tools/list. Results are cached.
    pub async fn list_tools(&self) -> Result<Vec<McpToolDef>, McpError> {
        // Return cached if available
        {
            let cache = self.cached_tools.lock().await;
            if let Some(tools) = cache.as_ref() {
                return Ok(tools.clone());
            }
        }

        let mut all_tools = Vec::new();
        let mut cursor: Option<String> = None;
        const MAX_PAGES: usize = 100;
        const MAX_TOOLS: usize = 10_000;

        for _page in 0..MAX_PAGES {
            let params = cursor.as_ref().map(|c| serde_json::json!({"cursor": c}));
            let result = self.send_request("tools/list", params).await?;

            if let Some(tools_val) = result.get("tools") {
                let tools: Vec<McpToolDef> = serde_json::from_value(tools_val.clone())?;
                all_tools.extend(tools);
            }

            // Safety: cap total tools to prevent memory exhaustion
            if all_tools.len() > MAX_TOOLS {
                eprintln!("[mcp] Warning: tool count exceeds {MAX_TOOLS}, truncating");
                all_tools.truncate(MAX_TOOLS);
                break;
            }

            // Check for pagination
            match result.get("nextCursor").and_then(|v| v.as_str()) {
                Some(next) => cursor = Some(next.to_string()),
                None => break,
            }
        }

        // Cache the result
        {
            let mut cache = self.cached_tools.lock().await;
            *cache = Some(all_tools.clone());
        }

        Ok(all_tools)
    }

    /// Execute a tool via tools/call.
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: HashMap<String, Value>,
    ) -> Result<McpToolResult, McpError> {
        let params = serde_json::json!({
            "name": name,
            "arguments": arguments,
        });

        let result = self.send_request("tools/call", Some(params)).await?;
        let tool_result: McpToolResult = serde_json::from_value(result)?;
        Ok(tool_result)
    }

    /// Disconnect from the MCP server.
    pub async fn disconnect(&self) {
        let mut transport = self.transport.lock().await;
        match &mut *transport {
            Transport::Stdio(stdio) => {
                // Take ownership of stdin to drop it (signals EOF to child).
                // After this, stdin is None and the child should exit.
                let _ = stdio.stdin.take();
                // Try graceful shutdown, then kill
                let _ = stdio.child.kill();
                let _ = stdio.child.wait();
            }
            Transport::Http(http) => {
                // Send HTTP DELETE to terminate session if we have a session ID
                if let Some(session_id) = &http.session_id {
                    let mut req = http.client.delete(&http.url);
                    req = req.header("Mcp-Session-Id", session_id.as_str());
                    let _ = req.send().await;
                }
            }
        }
    }

    /// Invalidate cached tools (e.g., after tools/list_changed notification).
    pub async fn invalidate_cache(&self) {
        let mut cache = self.cached_tools.lock().await;
        *cache = None;
    }

    // -----------------------------------------------------------------------
    // Internal: send JSON-RPC request and receive response
    // -----------------------------------------------------------------------

    async fn send_request(&self, method: &str, params: Option<Value>) -> Result<Value, McpError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method: method.to_string(),
            params,
        };

        let mut transport = self.transport.lock().await;
        match &mut *transport {
            Transport::Stdio(stdio) => send_stdio_request(stdio, &request).await,
            Transport::Http(http) => send_http_request(http, &request, &self.provider_name).await,
        }
    }

    async fn send_notification(&self, method: &str, params: Option<Value>) -> Result<(), McpError> {
        let mut notification = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
        });
        if let Some(p) = params {
            notification["params"] = p;
        }

        let mut transport = self.transport.lock().await;
        match &mut *transport {
            Transport::Stdio(stdio) => {
                let stdin = stdio
                    .stdin
                    .as_mut()
                    .ok_or_else(|| McpError::Transport("stdin closed".into()))?;
                let msg = serde_json::to_string(&notification)?;
                stdin.write_all(msg.as_bytes())?;
                stdin.write_all(b"\n")?;
                stdin.flush()?;
                Ok(())
            }
            Transport::Http(http) => {
                let mut req = http
                    .client
                    .post(&http.url)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json, text/event-stream")
                    .json(&notification);

                if let Some(session_id) = &http.session_id {
                    req = req.header("Mcp-Session-Id", session_id.as_str());
                }
                if let Some(auth) = &http.auth_header {
                    req = req.header(http.auth_header_name.as_str(), auth.as_str());
                }
                for (name, value) in &http.extra_headers {
                    req = req.header(name.as_str(), value.as_str());
                }

                let resp = req.send().await?;
                // Notifications should get 202 Accepted
                if !resp.status().is_success() {
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    return Err(McpError::Transport(format!("HTTP {status}: {body}")));
                }
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Stdio transport I/O
// ---------------------------------------------------------------------------

/// Send a JSON-RPC request over stdio and read the response.
/// Messages are newline-delimited JSON (no embedded newlines).
async fn send_stdio_request(
    stdio: &mut StdioTransport,
    request: &JsonRpcRequest,
) -> Result<Value, McpError> {
    let stdin = stdio
        .stdin
        .as_mut()
        .ok_or_else(|| McpError::Transport("stdin closed".into()))?;

    // Serialize and send (newline-delimited)
    let msg = serde_json::to_string(request)?;
    stdin.write_all(msg.as_bytes())?;
    stdin.write_all(b"\n")?;
    stdin.flush()?;

    let request_id = request.id;

    // Read lines until we get a response matching our request ID.
    // We may receive notifications interleaved — skip them.
    loop {
        let mut line = String::new();
        let bytes_read = stdio.reader.read_line(&mut line)?;
        if bytes_read == 0 {
            return Err(McpError::ProcessExited);
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Try to parse as JSON-RPC response
        let parsed: Value = serde_json::from_str(line)?;

        // Check if it's a response (has "id" field matching ours)
        if let Some(id) = parsed.get("id") {
            let id_matches = match id {
                Value::Number(n) => n.as_u64() == Some(request_id),
                _ => false,
            };

            if id_matches {
                // It's our response
                if let Some(err) = parsed.get("error") {
                    let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
                    let message = err
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("Unknown error");
                    return Err(McpError::Protocol {
                        code,
                        message: message.to_string(),
                    });
                }

                return parsed
                    .get("result")
                    .cloned()
                    .ok_or_else(|| McpError::Protocol {
                        code: -1,
                        message: "Response missing 'result' field".into(),
                    });
            }
        }

        // Not our response — it's a notification or someone else's response; skip it.
    }
}

// ---------------------------------------------------------------------------
// HTTP Streamable transport I/O
// ---------------------------------------------------------------------------

/// Send a JSON-RPC request over Streamable HTTP.
///
/// Per MCP spec (2025-03-26):
/// - POST with Accept: application/json, text/event-stream
/// - Server may respond with Content-Type: application/json (single response)
///   or Content-Type: text/event-stream (SSE stream with one or more messages)
/// - Must handle Mcp-Session-Id header for session management
async fn send_http_request(
    http: &mut HttpTransport,
    request: &JsonRpcRequest,
    provider_name: &str,
) -> Result<Value, McpError> {
    let mut req = http
        .client
        .post(&http.url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .json(request);

    // Attach session ID if we have one
    if let Some(session_id) = &http.session_id {
        req = req.header("Mcp-Session-Id", session_id.as_str());
    }

    // Inject auth (using custom header name if configured, e.g. "x-api-key")
    if let Some(auth) = &http.auth_header {
        req = req.header(http.auth_header_name.as_str(), auth.as_str());
    }

    // Inject extra headers from provider config
    for (name, value) in &http.extra_headers {
        req = req.header(name.as_str(), value.as_str());
    }

    let response = req
        .send()
        .await
        .map_err(|e| McpError::Transport(format!("[{provider_name}] HTTP request failed: {e}")))?;

    // Capture session ID from response header (usually set during initialize)
    if let Some(session_val) = response.headers().get("mcp-session-id") {
        if let Ok(sid) = session_val.to_str() {
            http.session_id = Some(sid.to_string());
        }
    }

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(McpError::Transport(format!(
            "[{provider_name}] HTTP {}: {body}",
            status.as_u16()
        )));
    }

    // Determine response type from Content-Type header
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    if content_type.contains("text/event-stream") {
        // SSE stream — parse events to extract our JSON-RPC response
        parse_sse_response(response, request.id).await
    } else {
        // Plain JSON response
        let body: Value = response.json().await?;
        extract_jsonrpc_result(&body, request.id)
    }
}

/// Parse an SSE stream from an HTTP response, collecting JSON-RPC messages
/// until we find the response matching our request ID.
///
/// SSE format (per HTML spec):
///   event: message\n
///   data: {"jsonrpc":"2.0","id":1,"result":{...}}\n
///   \n
///
/// Each `data:` line contains a JSON-RPC message. The `event:` field is optional.
/// We may receive notifications and server requests before getting our response.
/// Maximum SSE response body size (50 MB) to prevent OOM from malicious servers.
const MAX_SSE_BODY_SIZE: usize = 50 * 1024 * 1024;

async fn parse_sse_response(
    response: reqwest::Response,
    request_id: u64,
) -> Result<Value, McpError> {
    // Enforce size limit on SSE stream body
    let bytes = response
        .bytes()
        .await
        .map_err(|e| McpError::SseParse(format!("Failed to read SSE stream: {e}")))?;
    if bytes.len() > MAX_SSE_BODY_SIZE {
        return Err(McpError::SseParse(format!(
            "SSE response body exceeds maximum size ({} bytes > {} bytes)",
            bytes.len(),
            MAX_SSE_BODY_SIZE,
        )));
    }
    let full_body = String::from_utf8_lossy(&bytes).into_owned();

    // Parse SSE events
    let mut current_data = String::new();

    for line in full_body.lines() {
        if line.starts_with("data:") {
            let data = line.strip_prefix("data:").unwrap().trim();
            if !data.is_empty() {
                current_data.push_str(data);
            }
        } else if line.is_empty() && !current_data.is_empty() {
            // End of event — process the accumulated data
            match process_sse_data(&current_data, request_id) {
                SseParseResult::OurResponse(result) => return result,
                SseParseResult::NotOurMessage => {}
                SseParseResult::ParseError(e) => {
                    eprintln!("[mcp] Warning: failed to parse SSE data: {e}");
                }
            }
            current_data.clear();
        }
        // Lines starting with "event:", "id:", "retry:", or ":" are SSE metadata — skip
    }

    // Handle any remaining data that wasn't terminated by a blank line
    if !current_data.is_empty() {
        if let SseParseResult::OurResponse(result) = process_sse_data(&current_data, request_id) {
            return result;
        }
    }

    Err(McpError::SseParse(
        "SSE stream ended without receiving a response for our request".into(),
    ))
}

#[derive(Debug)]
enum SseParseResult {
    OurResponse(Result<Value, McpError>),
    NotOurMessage,
    ParseError(String),
}

fn process_sse_data(data: &str, request_id: u64) -> SseParseResult {
    let parsed: Value = match serde_json::from_str(data) {
        Ok(v) => v,
        Err(e) => return SseParseResult::ParseError(e.to_string()),
    };

    // Could be a single message or a batch (array)
    let messages = if parsed.is_array() {
        parsed.as_array().unwrap().clone()
    } else {
        vec![parsed]
    };

    for msg in messages {
        // Check if it's a response matching our ID
        if let Some(id) = msg.get("id") {
            let id_matches = match id {
                Value::Number(n) => n.as_u64() == Some(request_id),
                _ => false,
            };
            if id_matches {
                return SseParseResult::OurResponse(extract_jsonrpc_result(&msg, request_id));
            }
        }
        // Otherwise it's a notification or request from server — skip
    }

    SseParseResult::NotOurMessage
}

/// Extract the result (or error) from a JSON-RPC response message.
fn extract_jsonrpc_result(msg: &Value, _request_id: u64) -> Result<Value, McpError> {
    if let Some(err) = msg.get("error") {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("Unknown error");
        return Err(McpError::Protocol {
            code,
            message: message.to_string(),
        });
    }

    msg.get("result")
        .cloned()
        .ok_or_else(|| McpError::Protocol {
            code: -1,
            message: "Response missing 'result' field".into(),
        })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve "${key_name}" placeholders in values from the keyring.
/// Supports both whole-string (`${key}`) and inline (`prefix/${key}/suffix`) patterns.
fn resolve_env_value(value: &str, keyring: &Keyring) -> String {
    let mut result = value.to_string();
    // Find all ${...} patterns and replace them
    while let Some(start) = result.find("${") {
        let rest = &result[start + 2..];
        if let Some(end) = rest.find('}') {
            let key_name = &rest[..end];
            let replacement = keyring.get(key_name).unwrap_or("");
            if replacement.is_empty() && keyring.get(key_name).is_none() {
                // Key not found — leave the placeholder as-is to avoid breaking the string
                break;
            }
            result = format!("{}{}{}", &result[..start], replacement, &rest[end + 1..]);
        } else {
            break; // No closing brace — stop
        }
    }
    result
}

/// Build an Authorization header value from the provider's auth config.
fn build_auth_header(provider: &Provider, keyring: &Keyring) -> Option<String> {
    let key_name = provider.auth_key_name.as_deref()?;
    let key_value = keyring.get(key_name)?;

    match &provider.auth_type {
        super::manifest::AuthType::Bearer => Some(format!("Bearer {key_value}")),
        super::manifest::AuthType::Header => {
            // For header auth with a custom prefix
            if let Some(prefix) = &provider.auth_value_prefix {
                Some(format!("{prefix}{key_value}"))
            } else {
                Some(key_value.to_string())
            }
        }
        super::manifest::AuthType::Basic => {
            let encoded = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                format!("{key_value}:"),
            );
            Some(format!("Basic {encoded}"))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// High-level execute function for the call dispatch
// ---------------------------------------------------------------------------

/// Execute an MCP tool call — high-level entry point for cli/call.rs dispatch.
///
/// 1. Connects to the MCP server (or reuses connection via cache — future optimization)
/// 2. Strips the provider prefix from the tool name (e.g., "github:read_file" → "read_file")
/// 3. Calls tools/call with the raw MCP tool name
/// 4. Returns the result as a serde_json::Value
pub async fn execute(
    provider: &Provider,
    tool_name: &str,
    args: &HashMap<String, Value>,
    keyring: &Keyring,
) -> Result<Value, McpError> {
    execute_with_gen(provider, tool_name, args, keyring, None, None).await
}

/// Execute an MCP tool call with optional dynamic auth generator.
pub async fn execute_with_gen(
    provider: &Provider,
    tool_name: &str,
    args: &HashMap<String, Value>,
    keyring: &Keyring,
    gen_ctx: Option<&GenContext>,
    auth_cache: Option<&AuthCache>,
) -> Result<Value, McpError> {
    let client = McpClient::connect_with_gen(provider, keyring, gen_ctx, auth_cache).await?;

    // Strip provider prefix: "github:read_file" → "read_file"
    let mcp_tool_name = tool_name
        .strip_prefix(&format!(
            "{}{}",
            provider.name,
            crate::core::manifest::TOOL_SEP_STR
        ))
        .unwrap_or(tool_name);

    let result = client.call_tool(mcp_tool_name, args.clone()).await?;

    // Convert MCP tool result to a single Value for ATI's output system
    let value = mcp_result_to_value(&result);

    // Clean up
    client.disconnect().await;

    Ok(value)
}

/// Convert an McpToolResult to a serde_json::Value.
fn mcp_result_to_value(result: &McpToolResult) -> Value {
    if result.content.len() == 1 {
        // Single content item — unwrap for cleaner output
        let item = &result.content[0];
        match item.content_type.as_str() {
            "text" => {
                if let Some(text) = &item.text {
                    // Try to parse as JSON (many MCP tools return JSON as text)
                    serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.clone()))
                } else {
                    Value::Null
                }
            }
            "image" | "audio" => {
                serde_json::json!({
                    "type": item.content_type,
                    "data": item.data,
                    "mimeType": item.mime_type,
                })
            }
            _ => serde_json::to_value(item).unwrap_or(Value::Null),
        }
    } else {
        // Multiple content items — return as array
        let items: Vec<Value> = result
            .content
            .iter()
            .map(|c| serde_json::to_value(c).unwrap_or(Value::Null))
            .collect();

        serde_json::json!({
            "content": items,
            "isError": result.is_error,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_env_value_keyring() {
        let keyring = Keyring::empty();
        // No key in keyring — should return the raw value
        assert_eq!(
            resolve_env_value("${missing_key}", &keyring),
            "${missing_key}"
        );
        // Plain value — no resolution
        assert_eq!(resolve_env_value("plain_value", &keyring), "plain_value");
    }

    #[test]
    fn test_resolve_env_value_inline() {
        // Build a keyring with a test key via load_credentials
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("creds");
        std::fs::write(&path, r#"{"my_key":"SECRET123"}"#).unwrap();
        let keyring = Keyring::load_credentials(&path).unwrap();

        // Whole-string
        assert_eq!(resolve_env_value("${my_key}", &keyring), "SECRET123");
        // Inline
        assert_eq!(
            resolve_env_value("https://example.com/${my_key}/path", &keyring),
            "https://example.com/SECRET123/path"
        );
        // Multiple placeholders
        assert_eq!(
            resolve_env_value("${my_key}--${my_key}", &keyring),
            "SECRET123--SECRET123"
        );
        // Missing key stays as-is
        assert_eq!(
            resolve_env_value("https://example.com/${unknown}/path", &keyring),
            "https://example.com/${unknown}/path"
        );
        // No placeholder
        assert_eq!(
            resolve_env_value("no_placeholder", &keyring),
            "no_placeholder"
        );
    }

    #[test]
    fn test_mcp_result_to_value_single_text() {
        let result = McpToolResult {
            content: vec![McpContent {
                content_type: "text".into(),
                text: Some("hello world".into()),
                data: None,
                mime_type: None,
            }],
            is_error: false,
        };
        assert_eq!(
            mcp_result_to_value(&result),
            Value::String("hello world".into())
        );
    }

    #[test]
    fn test_mcp_result_to_value_json_text() {
        let result = McpToolResult {
            content: vec![McpContent {
                content_type: "text".into(),
                text: Some(r#"{"key":"value"}"#.into()),
                data: None,
                mime_type: None,
            }],
            is_error: false,
        };
        let val = mcp_result_to_value(&result);
        assert_eq!(val, serde_json::json!({"key": "value"}));
    }

    #[test]
    fn test_extract_jsonrpc_result_success() {
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": []}
        });
        let result = extract_jsonrpc_result(&msg, 1).unwrap();
        assert_eq!(result, serde_json::json!({"tools": []}));
    }

    #[test]
    fn test_extract_jsonrpc_result_error() {
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32602, "message": "Invalid params"}
        });
        let err = extract_jsonrpc_result(&msg, 1).unwrap_err();
        assert!(matches!(err, McpError::Protocol { code: -32602, .. }));
    }

    #[test]
    fn test_process_sse_data_matching_response() {
        let data = r#"{"jsonrpc":"2.0","id":5,"result":{"tools":[]}}"#;
        match process_sse_data(data, 5) {
            SseParseResult::OurResponse(Ok(val)) => {
                assert_eq!(val, serde_json::json!({"tools": []}));
            }
            _ => panic!("Expected OurResponse"),
        }
    }

    #[test]
    fn test_process_sse_data_notification() {
        // Notifications don't have "id" — should be skipped
        let data = r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
        match process_sse_data(data, 5) {
            SseParseResult::NotOurMessage => {}
            _ => panic!("Expected NotOurMessage"),
        }
    }

    #[test]
    fn test_process_sse_data_batch() {
        let data = r#"[
            {"jsonrpc":"2.0","method":"notifications/progress","params":{}},
            {"jsonrpc":"2.0","id":3,"result":{"content":[],"isError":false}}
        ]"#;
        match process_sse_data(data, 3) {
            SseParseResult::OurResponse(Ok(val)) => {
                assert!(val.get("content").is_some());
            }
            _ => panic!("Expected OurResponse from batch"),
        }
    }

    #[test]
    fn test_process_sse_data_invalid_json() {
        let data = "not valid json {{{}";
        match process_sse_data(data, 1) {
            SseParseResult::ParseError(_) => {}
            other => panic!("Expected ParseError, got: {other:?}"),
        }
    }

    #[test]
    fn test_process_sse_data_wrong_id() {
        let data = r#"{"jsonrpc":"2.0","id":99,"result":{"data":"wrong"}}"#;
        match process_sse_data(data, 1) {
            SseParseResult::NotOurMessage => {}
            _ => panic!("Expected NotOurMessage for wrong ID"),
        }
    }

    #[test]
    fn test_process_sse_data_empty_batch() {
        let data = "[]";
        match process_sse_data(data, 1) {
            SseParseResult::NotOurMessage => {}
            _ => panic!("Expected NotOurMessage for empty batch"),
        }
    }

    #[test]
    fn test_extract_jsonrpc_result_missing_result() {
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1
        });
        let err = extract_jsonrpc_result(&msg, 1).unwrap_err();
        assert!(matches!(err, McpError::Protocol { code: -1, .. }));
    }

    #[test]
    fn test_extract_jsonrpc_error_defaults() {
        // Error with missing code and message fields
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {}
        });
        let err = extract_jsonrpc_result(&msg, 1).unwrap_err();
        match err {
            McpError::Protocol { code, message } => {
                assert_eq!(code, -1);
                assert_eq!(message, "Unknown error");
            }
            _ => panic!("Expected Protocol error"),
        }
    }

    #[test]
    fn test_mcp_result_to_value_error() {
        let result = McpToolResult {
            content: vec![McpContent {
                content_type: "text".into(),
                text: Some("Something went wrong".into()),
                data: None,
                mime_type: None,
            }],
            is_error: true,
        };
        let val = mcp_result_to_value(&result);
        assert_eq!(val, Value::String("Something went wrong".into()));
    }

    #[test]
    fn test_mcp_result_to_value_multiple_content() {
        let result = McpToolResult {
            content: vec![
                McpContent {
                    content_type: "text".into(),
                    text: Some("Part 1".into()),
                    data: None,
                    mime_type: None,
                },
                McpContent {
                    content_type: "text".into(),
                    text: Some("Part 2".into()),
                    data: None,
                    mime_type: None,
                },
            ],
            is_error: false,
        };
        let val = mcp_result_to_value(&result);
        // Multiple items → {"content": [...], "isError": false}
        let content_arr = val["content"].as_array().unwrap();
        assert_eq!(content_arr.len(), 2);
        assert_eq!(val["isError"], false);
    }

    #[test]
    fn test_mcp_result_to_value_empty_content() {
        let result = McpToolResult {
            content: vec![],
            is_error: false,
        };
        let val = mcp_result_to_value(&result);
        // Empty content → {"content": [], "isError": false}
        assert_eq!(val["content"].as_array().unwrap().len(), 0);
        assert_eq!(val["isError"], false);
    }

    #[test]
    fn test_resolve_env_value_unclosed_brace() {
        let keyring = Keyring::empty();
        assert_eq!(resolve_env_value("${unclosed", &keyring), "${unclosed");
    }
}
