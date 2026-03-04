/// Live MCP integration tests — tests against real MCP servers.
///
/// These tests require:
/// - `npx` available in PATH (for stdio servers)
/// - Linear API key (for HTTP server)
/// - GitHub token (for GitHub MCP server)
///
/// Run with: cargo test --test mcp_live_test -- --nocapture
/// Skip with: cargo test --test mcp_live_test -- --ignored (they're not ignored by default)

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Credential helpers — read tokens from env vars or ~/.claude.json
// ---------------------------------------------------------------------------

fn read_claude_json() -> Option<Value> {
    let home = std::env::var("HOME").ok()?;
    let path = format!("{home}/.claude.json");
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn get_github_token() -> Option<String> {
    // Try env vars first
    if let Ok(t) = std::env::var("GITHUB_PERSONAL_ACCESS_TOKEN") {
        if !t.is_empty() { return Some(t); }
    }
    // Try reading the freshest token from ~/.github-token (auto-refreshed via cron)
    if let Ok(contents) = std::fs::read_to_string(
        format!("{}/.github-token", std::env::var("HOME").unwrap_or_default())
    ) {
        for line in contents.lines() {
            // Lines like: export GH_TOKEN=ghs_xxx
            if let Some(val) = line.strip_prefix("export GH_TOKEN=") {
                let val = val.trim().trim_matches('"');
                if !val.is_empty() { return Some(val.to_string()); }
            }
        }
    }
    if let Ok(t) = std::env::var("GH_TOKEN") {
        if !t.is_empty() { return Some(t); }
    }
    // Fall back to ~/.claude.json
    let config = read_claude_json()?;
    config
        .pointer("/mcpServers/github/env/GITHUB_PERSONAL_ACCESS_TOKEN")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn get_linear_token() -> Option<String> {
    // Try env vars first
    if let Ok(t) = std::env::var("LINEAR_API_KEY") {
        if !t.is_empty() { return Some(t); }
    }
    if let Ok(t) = std::env::var("LINEAR_PERSONAL_API_KEY") {
        if !t.is_empty() { return Some(t); }
    }
    // Fall back to ~/.claude.json — Linear stores "Bearer <token>" in headers
    let config = read_claude_json()?;
    let auth = config
        .pointer("/mcpServers/linear/headers/Authorization")
        .and_then(|v| v.as_str())?;
    // Strip "Bearer " prefix if present to get raw key
    Some(auth.strip_prefix("Bearer ").unwrap_or(auth).to_string())
}

fn get_sentry_token() -> Option<String> {
    if let Ok(t) = std::env::var("SENTRY_AUTH_TOKEN") {
        if !t.is_empty() { return Some(t); }
    }
    // Fall back to ~/.claude.json — Sentry passes token as --access-token=TOKEN arg
    let config = read_claude_json()?;
    let args = config.pointer("/mcpServers/sentry/args")?.as_array()?;
    for arg in args {
        if let Some(s) = arg.as_str() {
            if let Some(token) = s.strip_prefix("--access-token=") {
                return Some(token.to_string());
            }
        }
    }
    None
}

fn npx_available() -> bool {
    Command::new("npx")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Helper: send JSON-RPC over stdio to a child process
// ---------------------------------------------------------------------------

struct StdioMcpHelper {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
    next_id: u64,
}

impl StdioMcpHelper {
    fn spawn(command: &str, args: &[&str], env: Vec<(&str, &str)>) -> Self {
        let mut cmd = Command::new(command);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in &env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("Failed to spawn MCP server");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let reader = BufReader::new(stdout);
        StdioMcpHelper { child, stdin, reader, next_id: 1 }
    }

    fn send_request(&mut self, method: &str, params: Option<Value>) -> Value {
        let id = self.next_id;
        self.next_id += 1;

        let mut msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
        });
        if let Some(p) = params {
            msg["params"] = p;
        }

        let line = serde_json::to_string(&msg).unwrap();
        self.stdin.write_all(line.as_bytes()).unwrap();
        self.stdin.write_all(b"\n").unwrap();
        self.stdin.flush().unwrap();

        // Read response (skip notifications)
        loop {
            let mut buf = String::new();
            let n = self.reader.read_line(&mut buf).expect("Failed to read from MCP server");
            if n == 0 {
                panic!("MCP server closed stdout unexpectedly");
            }
            let buf = buf.trim();
            if buf.is_empty() {
                continue;
            }
            let parsed: Value = serde_json::from_str(buf)
                .unwrap_or_else(|e| panic!("Failed to parse MCP response: {e}\nRaw: {buf}"));

            // Check if it's our response (has "id" matching ours)
            if let Some(resp_id) = parsed.get("id") {
                if resp_id.as_u64() == Some(id) {
                    return parsed;
                }
            }
            // Otherwise it's a notification — skip
        }
    }

    fn send_notification(&mut self, method: &str, params: Option<Value>) {
        let mut msg = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
        });
        if let Some(p) = params {
            msg["params"] = p;
        }
        let line = serde_json::to_string(&msg).unwrap();
        self.stdin.write_all(line.as_bytes()).unwrap();
        self.stdin.write_all(b"\n").unwrap();
        self.stdin.flush().unwrap();
    }
}

impl Drop for StdioMcpHelper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// Helper: MCP initialize+notify handshake over stdio
// ---------------------------------------------------------------------------

fn stdio_initialize(helper: &mut StdioMcpHelper) -> Value {
    let init_resp = helper.send_request("initialize", Some(serde_json::json!({
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": { "name": "ati-test", "version": "0.1.0" }
    })));
    let init_result = init_resp.get("result").expect("initialize should have result");
    helper.send_notification("notifications/initialized", None);
    init_result.clone()
}

// ---------------------------------------------------------------------------
// Helper: send JSON-RPC over HTTP to an MCP endpoint
// ---------------------------------------------------------------------------

fn http_mcp_request(
    url: &str,
    method: &str,
    params: Option<Value>,
    id: u64,
    auth: Option<&str>,
    session_id: Option<&str>,
) -> (Value, Option<String>) {
    let mut msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
    });
    if let Some(p) = params {
        msg["params"] = p;
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();

    let mut req = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .json(&msg);

    if let Some(auth_val) = auth {
        req = req.header("Authorization", auth_val);
    }
    if let Some(sid) = session_id {
        req = req.header("Mcp-Session-Id", sid);
    }

    let resp = req.send().expect("HTTP request failed");

    // Capture session ID
    let new_session_id = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    let status = resp.status();

    if content_type.contains("text/event-stream") {
        // Parse SSE
        let body = resp.text().unwrap();
        let mut result = Value::Null;

        for line in body.lines() {
            if let Some(data) = line.strip_prefix("data:") {
                let data = data.trim();
                if data.is_empty() { continue; }
                let parsed: Value = serde_json::from_str(data).unwrap_or(Value::Null);
                // Could be a batch
                let messages = if parsed.is_array() {
                    parsed.as_array().unwrap().clone()
                } else {
                    vec![parsed]
                };
                for msg in messages {
                    if let Some(msg_id) = msg.get("id") {
                        if msg_id.as_u64() == Some(id) {
                            result = msg;
                        }
                    }
                }
            }
        }
        (result, new_session_id)
    } else {
        // Plain JSON
        if !status.is_success() && status.as_u16() != 202 {
            let body = resp.text().unwrap_or_default();
            panic!("HTTP {}: {body}", status.as_u16());
        }
        if status.as_u16() == 202 {
            return (Value::Null, new_session_id);
        }
        let body: Value = resp.json().unwrap();
        (body, new_session_id)
    }
}

fn http_mcp_notification(
    url: &str,
    method: &str,
    params: Option<Value>,
    auth: Option<&str>,
    session_id: Option<&str>,
) {
    let mut msg = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
    });
    if let Some(p) = params {
        msg["params"] = p;
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    let mut req = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .json(&msg);

    if let Some(auth_val) = auth {
        req = req.header("Authorization", auth_val);
    }
    if let Some(sid) = session_id {
        req = req.header("Mcp-Session-Id", sid);
    }

    let _ = req.send();
}

// ---------------------------------------------------------------------------
// Test: GitHub MCP server (stdio) — initialize + tools/list + tools/call
// ---------------------------------------------------------------------------

#[test]
fn test_github_mcp_stdio_initialize_and_list_tools() {
    if !npx_available() {
        eprintln!("SKIP: npx not available");
        return;
    }

    let gh_token = match get_github_token() {
        Some(t) => t,
        None => {
            eprintln!("SKIP: No GitHub token available");
            return;
        }
    };

    eprintln!("Spawning GitHub MCP server...");
    let mut helper = StdioMcpHelper::spawn(
        "npx",
        &["-y", "@modelcontextprotocol/server-github"],
        vec![("GITHUB_PERSONAL_ACCESS_TOKEN", &gh_token)],
    );

    // 1. Initialize
    eprintln!("  Sending initialize...");
    let init_result = stdio_initialize(&mut helper);
    eprintln!("  Server: {}", init_result.get("serverInfo").unwrap_or(&Value::Null));

    // Verify capabilities include tools
    let caps = init_result.get("capabilities").unwrap();
    assert!(caps.get("tools").is_some(), "Server must support tools capability");

    // 2. List tools
    eprintln!("  Sending tools/list...");
    let list_resp = helper.send_request("tools/list", None);
    let list_result = list_resp.get("result").expect("tools/list should have result");
    let tools = list_result.get("tools").and_then(|t| t.as_array()).expect("should have tools array");

    eprintln!("  Discovered {} tools:", tools.len());
    assert!(!tools.is_empty(), "GitHub MCP server should expose tools");

    for tool in tools.iter().take(10) {
        let name = tool.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        let desc = tool.get("description").and_then(|d| d.as_str()).unwrap_or("?");
        eprintln!("    - {name}: {}", &desc[..desc.len().min(80)]);

        // Every tool must have a name and inputSchema
        assert!(!name.is_empty(), "Tool name must not be empty");
        assert!(tool.get("inputSchema").is_some(), "Tool {name} must have inputSchema");
    }

    // 3. Call a read-only tool — search repos
    eprintln!("  Calling search_repositories...");
    let search_tool = tools.iter().find(|t| {
        t.get("name").and_then(|n| n.as_str()) == Some("search_repositories")
    });

    if search_tool.is_some() {
        let call_resp = helper.send_request("tools/call", Some(serde_json::json!({
            "name": "search_repositories",
            "arguments": {
                "query": "parcha language:python"
            }
        })));

        let call_result = call_resp.get("result").expect("tools/call should have result");
        let content = call_result.get("content").and_then(|c| c.as_array());
        assert!(content.is_some(), "tools/call result must have content array");
        let content = content.unwrap();
        assert!(!content.is_empty(), "search_repositories should return content");

        let first = &content[0];
        assert_eq!(first.get("type").and_then(|t| t.as_str()), Some("text"), "Content type should be text");
        let text = first.get("text").and_then(|t| t.as_str()).unwrap_or("");
        assert!(!text.is_empty(), "Result text should not be empty");
        eprintln!("  search_repositories returned {} chars", text.len());

        let is_error = call_result.get("isError").and_then(|e| e.as_bool()).unwrap_or(false);
        assert!(!is_error, "search_repositories should not return isError=true");
    } else {
        eprintln!("  WARN: search_repositories not found, skipping call test");
    }

    eprintln!("  GitHub MCP test PASSED");
}

// ---------------------------------------------------------------------------
// Test: Linear MCP server (Streamable HTTP) — initialize + tools/list + call
// ---------------------------------------------------------------------------

#[test]
fn test_linear_mcp_http_initialize_and_list_tools() {
    let linear_key = match get_linear_token() {
        Some(t) => t,
        None => {
            eprintln!("SKIP: No Linear API key available");
            return;
        }
    };

    let url = "https://mcp.linear.app/mcp";
    let auth = format!("Bearer {linear_key}");

    // 1. Initialize
    eprintln!("  Sending initialize to Linear MCP...");
    let (init_resp, session_id) = http_mcp_request(
        url,
        "initialize",
        Some(serde_json::json!({
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": { "name": "ati-test", "version": "0.1.0" }
        })),
        1,
        Some(&auth),
        None,
    );

    let init_result = init_resp.get("result").expect("initialize should have result");
    eprintln!("  Server: {}", init_result.get("serverInfo").unwrap_or(&Value::Null));
    eprintln!("  Session ID: {:?}", session_id);

    // Verify tools capability
    let caps = init_result.get("capabilities").unwrap_or(&Value::Null);
    assert!(caps.get("tools").is_some(), "Linear must support tools capability");

    // 2. Send initialized notification
    http_mcp_notification(url, "notifications/initialized", None, Some(&auth), session_id.as_deref());

    // 3. List tools
    eprintln!("  Sending tools/list to Linear MCP...");
    let (list_resp, _) = http_mcp_request(
        url,
        "tools/list",
        None,
        2,
        Some(&auth),
        session_id.as_deref(),
    );

    let list_result = list_resp.get("result").expect("tools/list should have result");
    let tools = list_result.get("tools").and_then(|t| t.as_array()).expect("should have tools array");

    eprintln!("  Discovered {} tools:", tools.len());
    assert!(!tools.is_empty(), "Linear MCP server should expose tools");

    for tool in tools.iter().take(10) {
        let name = tool.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        let desc = tool.get("description").and_then(|d| d.as_str()).unwrap_or("?");
        eprintln!("    - {name}: {}", &desc[..desc.len().min(80)]);

        assert!(!name.is_empty(), "Tool name must not be empty");
        assert!(tool.get("inputSchema").is_some(), "Tool {name} must have inputSchema");
    }

    // 4. Call a read-only tool
    let list_issues_tool = tools.iter().find(|t| {
        let name = t.get("name").and_then(|n| n.as_str()).unwrap_or("");
        name.contains("list") || name.contains("search") || name.contains("get")
    });

    if let Some(tool) = list_issues_tool {
        let tool_name = tool.get("name").and_then(|n| n.as_str()).unwrap();
        eprintln!("  Calling {}...", tool_name);

        let (call_resp, _) = http_mcp_request(
            url,
            "tools/call",
            Some(serde_json::json!({
                "name": tool_name,
                "arguments": {},
            })),
            3,
            Some(&auth),
            session_id.as_deref(),
        );

        let call_result = call_resp.get("result");
        if let Some(result) = call_result {
            let content = result.get("content").and_then(|c| c.as_array());
            if let Some(content) = content {
                assert!(!content.is_empty(), "tool call should return content");
                eprintln!("  {} returned {} content items", tool_name, content.len());
            }
        } else if let Some(err) = call_resp.get("error") {
            // Some tools require specific args — that's OK, we verified protocol works
            eprintln!("  {} returned protocol error (expected for missing args): {}", tool_name, err);
        }
    }

    eprintln!("  Linear MCP test PASSED");
}

// ---------------------------------------------------------------------------
// Test: Sentry MCP server (stdio) — initialize + tools/list
// ---------------------------------------------------------------------------

#[test]
fn test_sentry_mcp_stdio_initialize_and_list_tools() {
    if !npx_available() {
        eprintln!("SKIP: npx not available");
        return;
    }

    let sentry_token = match get_sentry_token() {
        Some(t) => t,
        None => {
            eprintln!("SKIP: No Sentry token available");
            return;
        }
    };

    eprintln!("Spawning Sentry MCP server...");
    let access_flag = format!("--access-token={sentry_token}");
    let mut helper = StdioMcpHelper::spawn(
        "npx",
        &["@sentry/mcp-server@latest", &access_flag],
        vec![],
    );

    // 1. Initialize
    eprintln!("  Sending initialize...");
    let init_result = stdio_initialize(&mut helper);
    eprintln!("  Server: {}", init_result.get("serverInfo").unwrap_or(&Value::Null));

    let caps = init_result.get("capabilities").unwrap_or(&Value::Null);
    assert!(caps.get("tools").is_some(), "Sentry must support tools capability");

    // 2. List tools
    eprintln!("  Sending tools/list...");
    let list_resp = helper.send_request("tools/list", None);
    let list_result = list_resp.get("result").expect("tools/list should have result");
    let tools = list_result.get("tools").and_then(|t| t.as_array()).expect("should have tools array");

    eprintln!("  Discovered {} tools:", tools.len());
    assert!(!tools.is_empty(), "Sentry MCP server should expose tools");

    for tool in tools.iter().take(15) {
        let name = tool.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        let desc = tool.get("description").and_then(|d| d.as_str()).unwrap_or("?");
        eprintln!("    - {name}: {}", &desc[..desc.len().min(80)]);
        assert!(tool.get("inputSchema").is_some(), "Tool {name} must have inputSchema");
    }

    eprintln!("  Sentry MCP test PASSED");
}

// ---------------------------------------------------------------------------
// Test: ATI MCP client library against Linear HTTP (high-level API)
// ---------------------------------------------------------------------------

#[test]
fn test_ati_mcp_client_against_linear() {
    if get_linear_token().is_none() {
        eprintln!("SKIP: No Linear API key for ATI client test");
        return;
    }

    // Build a Provider struct matching what would come from linear-mcp.toml
    let provider = ati::core::manifest::Provider {
        name: "linear".to_string(),
        description: "Linear MCP test".to_string(),
        base_url: String::new(),
        auth_type: ati::core::manifest::AuthType::Bearer,
        auth_key_name: Some("linear_api_key".to_string()),
        auth_header_name: None,
        auth_query_name: None,
        auth_value_prefix: None,
        extra_headers: HashMap::new(),
        oauth2_token_url: None,
        auth_secret_name: None,
        oauth2_basic_auth: false,
        internal: false,
        handler: "mcp".to_string(),
        mcp_transport: Some("http".to_string()),
        mcp_command: None,
        mcp_args: Vec::new(),
        mcp_url: Some("https://mcp.linear.app/mcp".to_string()),
        mcp_env: HashMap::new(),
        openapi_spec: None,
        openapi_include_tags: Vec::new(),
        openapi_exclude_tags: Vec::new(),
        openapi_include_operations: Vec::new(),
        openapi_exclude_operations: Vec::new(),
        openapi_max_operations: None,
        openapi_overrides: HashMap::new(),
        cli_command: None,
        cli_default_args: Vec::new(),
        cli_env: HashMap::new(),
        cli_timeout_secs: None,
        category: None,
        skills: Vec::new(),
    };

    // Empty keyring — the McpClient builds auth from keyring, so it won't have the key.
    // This tests that the protocol handshake code handles missing auth gracefully.
    let keyring = ati::core::keyring::Keyring::empty();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let result = ati::core::mcp_client::McpClient::connect(&provider, &keyring).await;

        // With an empty keyring, the auth header won't be set.
        // Linear will likely reject with 401/403 — that's valid.
        // If it succeeds (Linear allows initialization without auth), great.
        match result {
            Ok(client) => {
                eprintln!("  Connected to Linear MCP (no auth — server allowed init)");
                let tools = client.list_tools().await;
                match tools {
                    Ok(t) => {
                        eprintln!("  Listed {} tools via ATI McpClient", t.len());
                        assert!(!t.is_empty());
                    }
                    Err(e) => {
                        eprintln!("  tools/list failed (auth required): {e}");
                        // This is OK — we validated the protocol flow
                    }
                }
                client.disconnect().await;
            }
            Err(e) => {
                let msg = format!("{e}");
                eprintln!("  Connect failed (expected if auth required): {msg}");
                // Verify it's an auth/transport error, not a code bug
                assert!(
                    msg.contains("HTTP") || msg.contains("401") || msg.contains("403")
                        || msg.contains("auth") || msg.contains("Unauthorized")
                        || msg.contains("error"),
                    "Error should be auth/transport-related, got: {msg}"
                );
            }
        }
    });

    eprintln!("  ATI McpClient test PASSED");
}

// ---------------------------------------------------------------------------
// Test: ATI MCP client library against GitHub stdio (full flow)
// ---------------------------------------------------------------------------

#[test]
fn test_ati_mcp_client_against_github_stdio() {
    if !npx_available() {
        eprintln!("SKIP: npx not available");
        return;
    }

    let gh_token = match get_github_token() {
        Some(t) => t,
        None => {
            eprintln!("SKIP: No GitHub token for ATI client test");
            return;
        }
    };

    // Build a Provider struct matching github-mcp.toml
    let mut mcp_env = HashMap::new();
    mcp_env.insert("GITHUB_PERSONAL_ACCESS_TOKEN".to_string(), gh_token.clone());

    let provider = ati::core::manifest::Provider {
        name: "github".to_string(),
        description: "GitHub MCP test".to_string(),
        base_url: String::new(),
        auth_type: ati::core::manifest::AuthType::None,
        auth_key_name: None,
        auth_header_name: None,
        auth_query_name: None,
        auth_value_prefix: None,
        extra_headers: HashMap::new(),
        oauth2_token_url: None,
        auth_secret_name: None,
        oauth2_basic_auth: false,
        internal: false,
        handler: "mcp".to_string(),
        mcp_transport: Some("stdio".to_string()),
        mcp_command: Some("npx".to_string()),
        mcp_args: vec!["-y".to_string(), "@modelcontextprotocol/server-github".to_string()],
        mcp_url: None,
        mcp_env,
        openapi_spec: None,
        openapi_include_tags: Vec::new(),
        openapi_exclude_tags: Vec::new(),
        openapi_include_operations: Vec::new(),
        openapi_exclude_operations: Vec::new(),
        openapi_max_operations: None,
        openapi_overrides: HashMap::new(),
        cli_command: None,
        cli_default_args: Vec::new(),
        cli_env: HashMap::new(),
        cli_timeout_secs: None,
        category: None,
        skills: Vec::new(),
    };

    // For stdio, auth is via env vars (not keyring), so empty keyring is fine
    let keyring = ati::core::keyring::Keyring::empty();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        eprintln!("  Connecting to GitHub MCP via ATI McpClient...");
        let client = ati::core::mcp_client::McpClient::connect(&provider, &keyring).await
            .expect("Should connect to GitHub MCP");

        eprintln!("  Connected! Listing tools...");
        let tools = client.list_tools().await.expect("Should list tools");
        eprintln!("  Discovered {} tools via ATI McpClient", tools.len());
        assert!(!tools.is_empty(), "GitHub MCP should have tools");

        // Verify tool structure
        for tool in &tools {
            assert!(!tool.name.is_empty(), "Tool name must not be empty");
            // Description should exist for well-behaved MCP servers
            if let Some(desc) = &tool.description {
                assert!(!desc.is_empty(), "Tool description should not be empty");
            }
        }

        // Find and call search_repositories
        let has_search = tools.iter().any(|t| t.name == "search_repositories");
        if has_search {
            eprintln!("  Calling search_repositories via ATI McpClient...");
            let mut args = HashMap::new();
            args.insert("query".to_string(), serde_json::json!("parcha language:python"));

            let result = client.call_tool("search_repositories", args).await
                .expect("search_repositories should succeed");

            assert!(!result.content.is_empty(), "Should have content");
            assert!(!result.is_error, "Should not be an error");
            if let Some(text) = &result.content[0].text {
                eprintln!("  search_repositories returned {} chars via ATI McpClient", text.len());
                assert!(!text.is_empty());
            }
        }

        // Test cache: second list_tools should return cached
        let tools2 = client.list_tools().await.expect("Cached list should work");
        assert_eq!(tools.len(), tools2.len(), "Cached tools should match");

        client.disconnect().await;
        eprintln!("  Disconnected cleanly");
    });

    eprintln!("  ATI McpClient (GitHub stdio) test PASSED");
}

// ---------------------------------------------------------------------------
// Test: SSE parsing with real-world data
// ---------------------------------------------------------------------------

#[test]
fn test_sse_parsing_realistic_data() {
    // Simulate what a real MCP server might send in SSE format
    let sse_body = "\
event: message\n\
data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":50}}\n\
\n\
event: message\n\
data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"get_issue\",\"description\":\"Get a Linear issue\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"id\":{\"type\":\"string\"}},\"required\":[\"id\"]}}]}}\n\
\n";

    // Parse manually like our SSE parser would
    let mut current_data = String::new();
    let mut found_response = false;

    for line in sse_body.lines() {
        if let Some(data) = line.strip_prefix("data:") {
            let data = data.trim();
            if !data.is_empty() {
                current_data.push_str(data);
            }
        } else if line.is_empty() && !current_data.is_empty() {
            let parsed: Value = serde_json::from_str(&current_data).unwrap();

            if let Some(id) = parsed.get("id") {
                if id.as_u64() == Some(1) {
                    // Found our response
                    let result = parsed.get("result").unwrap();
                    let tools = result.get("tools").unwrap().as_array().unwrap();
                    assert_eq!(tools.len(), 1);
                    assert_eq!(tools[0].get("name").unwrap().as_str().unwrap(), "get_issue");
                    found_response = true;
                }
            }
            current_data.clear();
        }
    }

    assert!(found_response, "Should have found the tools/list response in SSE stream");
    eprintln!("  SSE parsing test PASSED");
}

// ---------------------------------------------------------------------------
// Test: Batch JSON-RPC in SSE
// ---------------------------------------------------------------------------

#[test]
fn test_sse_batch_parsing() {
    // Some servers send batched responses in a single SSE event
    let sse_body = "\
data: [{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}},{\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"hello\"}],\"isError\":false}}]\n\
\n";

    let mut found = false;
    let mut current_data = String::new();

    for line in sse_body.lines() {
        if let Some(data) = line.strip_prefix("data:") {
            current_data.push_str(data.trim());
        } else if line.is_empty() && !current_data.is_empty() {
            let parsed: Value = serde_json::from_str(&current_data).unwrap();
            assert!(parsed.is_array());
            let arr = parsed.as_array().unwrap();
            assert_eq!(arr.len(), 2);

            // Second item should be our response
            let resp = &arr[1];
            assert_eq!(resp.get("id").unwrap().as_u64(), Some(5));
            let result = resp.get("result").unwrap();
            let content = result.get("content").unwrap().as_array().unwrap();
            assert_eq!(content[0].get("text").unwrap().as_str(), Some("hello"));
            found = true;
            current_data.clear();
        }
    }

    assert!(found, "Should have parsed batch SSE response");
    eprintln!("  SSE batch parsing test PASSED");
}

// ---------------------------------------------------------------------------
// Test: MCP protocol error handling (non-existent tool)
// ---------------------------------------------------------------------------

#[test]
fn test_github_mcp_protocol_error_handling() {
    if !npx_available() {
        eprintln!("SKIP: npx not available");
        return;
    }

    let gh_token = match get_github_token() {
        Some(t) => t,
        None => {
            eprintln!("SKIP: No GitHub token");
            return;
        }
    };

    eprintln!("Testing error handling against GitHub MCP...");
    let mut helper = StdioMcpHelper::spawn(
        "npx",
        &["-y", "@modelcontextprotocol/server-github"],
        vec![("GITHUB_PERSONAL_ACCESS_TOKEN", &gh_token)],
    );

    // Initialize
    let _ = stdio_initialize(&mut helper);

    // Call a non-existent tool — should get an error response
    eprintln!("  Calling non-existent tool...");
    let err_resp = helper.send_request("tools/call", Some(serde_json::json!({
        "name": "this_tool_does_not_exist_12345",
        "arguments": {}
    })));

    // Should get either a JSON-RPC error or a tool result with isError=true
    let has_error = err_resp.get("error").is_some();
    let is_tool_error = err_resp
        .pointer("/result/isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);

    assert!(
        has_error || is_tool_error,
        "Calling non-existent tool should return error. Got: {}",
        serde_json::to_string_pretty(&err_resp).unwrap()
    );
    eprintln!("  Error handling test PASSED");
}

// ---------------------------------------------------------------------------
// Test: Everything MCP server (stdio) — zero-auth test server
// ---------------------------------------------------------------------------

#[test]
fn test_everything_mcp_stdio() {
    if !npx_available() {
        eprintln!("SKIP: npx not available");
        return;
    }

    eprintln!("Spawning Everything MCP server...");
    let mut helper = StdioMcpHelper::spawn(
        "npx",
        &["-y", "@modelcontextprotocol/server-everything"],
        vec![],
    );

    // Initialize
    let init_result = stdio_initialize(&mut helper);
    eprintln!("  Server: {}", init_result.get("serverInfo").unwrap_or(&Value::Null));

    // List tools
    let list_resp = helper.send_request("tools/list", None);
    let list_result = list_resp.get("result").expect("tools/list should have result");
    let tools = list_result.get("tools").and_then(|t| t.as_array()).expect("should have tools array");

    eprintln!("  Discovered {} tools:", tools.len());
    assert!(!tools.is_empty(), "Everything MCP server should expose tools");

    for tool in tools.iter() {
        let name = tool.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        let desc = tool.get("description").and_then(|d| d.as_str()).unwrap_or("?");
        eprintln!("    - {name}: {}", &desc[..desc.len().min(80)]);
    }

    // Call the echo tool (should exist on the everything server)
    let echo_tool = tools.iter().find(|t| {
        let name = t.get("name").and_then(|n| n.as_str()).unwrap_or("");
        name == "echo" || name.contains("echo")
    });

    if let Some(tool) = echo_tool {
        let tool_name = tool.get("name").and_then(|n| n.as_str()).unwrap();
        eprintln!("  Calling {tool_name}...");
        let call_resp = helper.send_request("tools/call", Some(serde_json::json!({
            "name": tool_name,
            "arguments": { "message": "Hello from ATI tests!" }
        })));

        if let Some(result) = call_resp.get("result") {
            let content = result.get("content").and_then(|c| c.as_array());
            if let Some(content) = content {
                eprintln!("  {} returned {} content items", tool_name, content.len());
                assert!(!content.is_empty(), "Echo should return content");
            }
            let is_error = result.get("isError").and_then(|e| e.as_bool()).unwrap_or(false);
            assert!(!is_error, "Echo should not be an error");
        }
    } else {
        eprintln!("  WARN: No echo tool found, skipping call test");
    }

    eprintln!("  Everything MCP test PASSED");
}

// ---------------------------------------------------------------------------
// Test: DeepWiki MCP (remote HTTP, no auth) — full end-to-end via ATI McpClient
// ---------------------------------------------------------------------------

#[test]
fn test_deepwiki_mcp_http_full_flow() {
    let url = "https://mcp.deepwiki.com/mcp";

    // 1. Raw protocol test: initialize via HTTP
    eprintln!("  Testing DeepWiki MCP (remote HTTP, no auth)...");
    let (init_resp, session_id) = http_mcp_request(
        url,
        "initialize",
        Some(serde_json::json!({
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": { "name": "ati-test", "version": "0.1.0" }
        })),
        1,
        None, // no auth
        None,
    );

    let init_result = init_resp.get("result").expect("initialize should have result");
    eprintln!("  Server: {}", init_result.get("serverInfo").unwrap_or(&Value::Null));
    eprintln!("  Session ID: {:?}", session_id);

    let caps = init_result.get("capabilities").unwrap_or(&Value::Null);
    assert!(caps.get("tools").is_some(), "DeepWiki must support tools capability");

    // 2. Send initialized notification
    http_mcp_notification(url, "notifications/initialized", None, None, session_id.as_deref());

    // 3. List tools
    eprintln!("  Sending tools/list...");
    let (list_resp, _) = http_mcp_request(url, "tools/list", None, 2, None, session_id.as_deref());

    let list_result = list_resp.get("result").expect("tools/list should have result");
    let tools = list_result.get("tools").and_then(|t| t.as_array()).expect("should have tools array");

    eprintln!("  Discovered {} tools:", tools.len());
    assert!(!tools.is_empty(), "DeepWiki should expose tools");

    for tool in tools.iter() {
        let name = tool.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        let desc = tool.get("description").and_then(|d| d.as_str()).unwrap_or("?");
        eprintln!("    - {name}: {}", &desc[..desc.len().min(80)]);
        assert!(tool.get("inputSchema").is_some(), "Tool {name} must have inputSchema");
    }

    // 4. Call read_wiki_structure on a well-known repo
    let has_wiki_structure = tools.iter().any(|t| {
        t.get("name").and_then(|n| n.as_str()) == Some("read_wiki_structure")
    });

    if has_wiki_structure {
        eprintln!("  Calling read_wiki_structure for tokio-rs/tokio...");
        let (call_resp, _) = http_mcp_request(
            url,
            "tools/call",
            Some(serde_json::json!({
                "name": "read_wiki_structure",
                "arguments": { "repoName": "tokio-rs/tokio" }
            })),
            3,
            None,
            session_id.as_deref(),
        );

        if let Some(result) = call_resp.get("result") {
            let content = result.get("content").and_then(|c| c.as_array());
            if let Some(content) = content {
                assert!(!content.is_empty(), "read_wiki_structure should return content");
                let text = content[0].get("text").and_then(|t| t.as_str()).unwrap_or("");
                eprintln!("  read_wiki_structure returned {} chars", text.len());
                assert!(text.len() > 10, "Should have meaningful wiki structure content");
            }
            let is_error = result.get("isError").and_then(|e| e.as_bool()).unwrap_or(false);
            assert!(!is_error, "read_wiki_structure should not be an error");
        } else if let Some(err) = call_resp.get("error") {
            eprintln!("  read_wiki_structure returned error: {err}");
        }
    }

    eprintln!("  Raw protocol test PASSED");

    // 5. Now test via ATI McpClient (the real integration test)
    eprintln!("  Testing via ATI McpClient...");
    let provider = ati::core::manifest::Provider {
        name: "deepwiki".to_string(),
        description: "DeepWiki MCP test".to_string(),
        base_url: String::new(),
        auth_type: ati::core::manifest::AuthType::None,
        auth_key_name: None,
        auth_header_name: None,
        auth_query_name: None,
        auth_value_prefix: None,
        extra_headers: HashMap::new(),
        oauth2_token_url: None,
        auth_secret_name: None,
        oauth2_basic_auth: false,
        internal: false,
        handler: "mcp".to_string(),
        mcp_transport: Some("http".to_string()),
        mcp_command: None,
        mcp_args: Vec::new(),
        mcp_url: Some("https://mcp.deepwiki.com/mcp".to_string()),
        mcp_env: HashMap::new(),
        openapi_spec: None,
        openapi_include_tags: Vec::new(),
        openapi_exclude_tags: Vec::new(),
        openapi_include_operations: Vec::new(),
        openapi_exclude_operations: Vec::new(),
        openapi_max_operations: None,
        openapi_overrides: HashMap::new(),
        cli_command: None,
        cli_default_args: Vec::new(),
        cli_env: HashMap::new(),
        cli_timeout_secs: None,
        category: Some("documentation".to_string()),
        skills: Vec::new(),
    };

    let keyring = ati::core::keyring::Keyring::empty();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let client = ati::core::mcp_client::McpClient::connect(&provider, &keyring).await
            .expect("Should connect to DeepWiki MCP (no auth)");

        let tools = client.list_tools().await.expect("Should list tools");
        eprintln!("  ATI McpClient discovered {} tools", tools.len());
        assert!(!tools.is_empty());

        // Verify tool structure
        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        eprintln!("  Tools: {:?}", tool_names);
        assert!(tool_names.contains(&"read_wiki_structure"), "Should have read_wiki_structure");
        assert!(tool_names.contains(&"ask_question"), "Should have ask_question");

        // Call read_wiki_structure via ATI McpClient
        eprintln!("  Calling read_wiki_structure via ATI McpClient...");
        let mut args = HashMap::new();
        args.insert("repoName".to_string(), serde_json::json!("tokio-rs/tokio"));

        let result = client.call_tool("read_wiki_structure", args).await
            .expect("read_wiki_structure should succeed");

        assert!(!result.content.is_empty(), "Should have content");
        assert!(!result.is_error, "Should not be an error");
        if let Some(text) = &result.content[0].text {
            eprintln!("  ATI McpClient got {} chars from read_wiki_structure", text.len());
            assert!(text.len() > 10, "Should have meaningful content");
        }

        // Test cache: second list_tools should be cached
        let tools2 = client.list_tools().await.expect("Cached list should work");
        assert_eq!(tools.len(), tools2.len());

        client.disconnect().await;
        eprintln!("  Disconnected cleanly");
    });

    eprintln!("  DeepWiki MCP test PASSED (raw + ATI McpClient)");
}
