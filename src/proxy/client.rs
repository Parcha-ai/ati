/// Proxy client — forwards tool calls to an external ATI proxy server.
///
/// When ATI_PROXY_URL is set, `ati run <tool>` sends tool_name + args
/// to the proxy. Authentication is via JWT in the Authorization header
/// (ATI_SESSION_TOKEN env var).
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("Proxy request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Proxy error ({status}): {body}")]
    ProxyResponse { status: u16, body: String },
    #[error("Invalid proxy URL: {0}")]
    InvalidUrl(String),
    #[error("Proxy returned invalid response: {0}")]
    InvalidResponse(String),
}

/// Request payload sent to the proxy server's /call endpoint.
#[derive(Debug, Serialize)]
pub struct ProxyCallRequest {
    pub tool_name: String,
    /// Tool arguments — JSON object for HTTP/MCP tools, or JSON array for CLI tools.
    pub args: Value,
    /// Raw positional args for CLI tools. When present, the proxy's
    /// `args_as_positional()` uses these instead of parsing `args`.
    /// This preserves bare positional words like `browse status` that
    /// don't survive the `--key value` parse into the args map.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_args: Option<Vec<String>>,
}

/// Response payload from the proxy server.
#[derive(Debug, Deserialize)]
pub struct ProxyCallResponse {
    pub result: Value,
    #[serde(default)]
    pub error: Option<String>,
}

/// Request payload for the proxy's /help endpoint.
#[derive(Debug, Serialize)]
pub struct ProxyHelpRequest {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
}

/// Response from the proxy's /help endpoint.
#[derive(Debug, Deserialize)]
pub struct ProxyHelpResponse {
    pub content: String,
    #[serde(default)]
    pub error: Option<String>,
}

const PROXY_TIMEOUT_SECS: u64 = 120;

/// Build an HTTP request builder with JWT Bearer auth from ATI_SESSION_TOKEN.
fn build_proxy_request(
    client: &Client,
    method: reqwest::Method,
    url: &str,
) -> reqwest::RequestBuilder {
    let mut req = client.request(method, url);
    match crate::core::token::resolve_session_token() {
        Ok(Some(token)) => {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        Ok(None) => {}
        Err(e) => {
            // File-read error (e.g., permission denied on ATI_SESSION_TOKEN_FILE).
            // Don't block the request; let the proxy 401 if auth is required.
            tracing::debug!(error = %e, "session token file unreadable; sending request without Authorization");
        }
    }
    req
}

/// Execute a tool call via the proxy server.
///
/// POST {proxy_url}/call with JSON body: { tool_name, args }
/// Scopes are carried inside the JWT — not in the request body.
///
/// `args` carries key-value pairs for HTTP/MCP tools.
/// `raw_args`, if provided, is sent as an array in the `args` field for CLI tools.
pub async fn call_tool(
    proxy_url: &str,
    tool_name: &str,
    args: &HashMap<String, Value>,
    raw_args: Option<&[String]>,
) -> Result<Value, ProxyError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(PROXY_TIMEOUT_SECS))
        .build()?;

    let url = format!("{}/call", proxy_url.trim_end_matches('/'));

    // Send both the parsed args map (for HTTP/MCP/OpenAPI tools) AND the raw
    // positional args (for CLI tools). The proxy's CallRequest handler uses
    // args_as_map() for HTTP tools and args_as_positional() for CLI tools.
    // args_as_positional() checks `raw_args` first, so CLI tools always get
    // their original positional args even when the map is empty.
    let args_value = serde_json::to_value(args).unwrap_or(Value::Object(serde_json::Map::new()));
    let raw_args_vec = raw_args.filter(|r| !r.is_empty()).map(|r| r.to_vec());

    let payload = ProxyCallRequest {
        tool_name: tool_name.to_string(),
        args: args_value,
        raw_args: raw_args_vec,
    };

    let response = build_proxy_request(&client, reqwest::Method::POST, &url)
        .json(&payload)
        .send()
        .await?;
    let status = response.status();

    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|_| "empty".into());
        return Err(ProxyError::ProxyResponse {
            status: status.as_u16(),
            body,
        });
    }

    let body: ProxyCallResponse = response
        .json()
        .await
        .map_err(|e| ProxyError::InvalidResponse(e.to_string()))?;

    if let Some(err) = body.error {
        return Err(ProxyError::ProxyResponse {
            status: 200,
            body: err,
        });
    }

    Ok(body.result)
}

/// List available tools from the proxy.
pub async fn list_tools(proxy_url: &str, query_params: &str) -> Result<Value, ProxyError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(PROXY_TIMEOUT_SECS))
        .build()?;
    let mut url = format!("{}/tools", proxy_url.trim_end_matches('/'));
    if !query_params.is_empty() {
        url.push('?');
        url.push_str(query_params);
    }
    let response = build_proxy_request(&client, reqwest::Method::GET, &url)
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(ProxyError::ProxyResponse {
            status: status.as_u16(),
            body,
        });
    }
    Ok(response.json().await?)
}

/// Get detailed info about a specific tool from the proxy.
pub async fn get_tool_info(proxy_url: &str, name: &str) -> Result<Value, ProxyError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(PROXY_TIMEOUT_SECS))
        .build()?;
    let url = format!("{}/tools/{}", proxy_url.trim_end_matches('/'), name);
    let response = build_proxy_request(&client, reqwest::Method::GET, &url)
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(ProxyError::ProxyResponse {
            status: status.as_u16(),
            body,
        });
    }
    Ok(response.json().await?)
}

/// Forward a raw MCP JSON-RPC message via the proxy's /mcp endpoint.
pub async fn call_mcp(
    proxy_url: &str,
    method: &str,
    params: Option<Value>,
) -> Result<Value, ProxyError> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static MCP_ID: AtomicU64 = AtomicU64::new(1);

    let id = MCP_ID.fetch_add(1, Ordering::SeqCst);
    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    });

    let client = Client::builder()
        .timeout(Duration::from_secs(PROXY_TIMEOUT_SECS))
        .build()?;

    let url = format!("{}/mcp", proxy_url.trim_end_matches('/'));

    let response = build_proxy_request(&client, reqwest::Method::POST, &url)
        .json(&msg)
        .send()
        .await?;
    let status = response.status();

    if status == reqwest::StatusCode::ACCEPTED {
        return Ok(Value::Null);
    }

    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|_| "empty".into());
        return Err(ProxyError::ProxyResponse {
            status: status.as_u16(),
            body,
        });
    }

    let body: Value = response
        .json()
        .await
        .map_err(|e| ProxyError::InvalidResponse(e.to_string()))?;

    if let Some(err) = body.get("error") {
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("MCP proxy error");
        return Err(ProxyError::ProxyResponse {
            status: 200,
            body: message.to_string(),
        });
    }

    Ok(body.get("result").cloned().unwrap_or(Value::Null))
}

/// Fetch skill list from the proxy server.
pub async fn list_skills(
    proxy_url: &str,
    query_params: &str,
) -> Result<serde_json::Value, ProxyError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(PROXY_TIMEOUT_SECS))
        .build()?;

    let url = if query_params.is_empty() {
        format!("{}/skills", proxy_url.trim_end_matches('/'))
    } else {
        format!("{}/skills?{query_params}", proxy_url.trim_end_matches('/'))
    };

    let response = build_proxy_request(&client, reqwest::Method::GET, &url)
        .send()
        .await?;
    let status = response.status();

    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|_| "empty".into());
        return Err(ProxyError::ProxyResponse {
            status: status.as_u16(),
            body,
        });
    }

    response
        .json()
        .await
        .map_err(|e| ProxyError::InvalidResponse(e.to_string()))
}

/// Fetch a skill's detail from the proxy server.
pub async fn get_skill(
    proxy_url: &str,
    name: &str,
    query_params: &str,
) -> Result<serde_json::Value, ProxyError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(PROXY_TIMEOUT_SECS))
        .build()?;

    let url = if query_params.is_empty() {
        format!("{}/skills/{name}", proxy_url.trim_end_matches('/'))
    } else {
        format!(
            "{}/skills/{name}?{query_params}",
            proxy_url.trim_end_matches('/')
        )
    };

    let response = build_proxy_request(&client, reqwest::Method::GET, &url)
        .send()
        .await?;
    let status = response.status();

    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|_| "empty".into());
        return Err(ProxyError::ProxyResponse {
            status: status.as_u16(),
            body,
        });
    }

    response
        .json()
        .await
        .map_err(|e| ProxyError::InvalidResponse(e.to_string()))
}

async fn get_proxy_json(proxy_url: &str, path: &str) -> Result<serde_json::Value, ProxyError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(PROXY_TIMEOUT_SECS))
        .build()?;

    let url = format!(
        "{}/{}",
        proxy_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    );

    let response = build_proxy_request(&client, reqwest::Method::GET, &url)
        .send()
        .await?;
    let status = response.status();

    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|_| "empty".into());
        return Err(ProxyError::ProxyResponse {
            status: status.as_u16(),
            body,
        });
    }

    response
        .json()
        .await
        .map_err(|e| ProxyError::InvalidResponse(e.to_string()))
}

async fn get_proxy_json_with_query(
    proxy_url: &str,
    path: &str,
    query: &[(&str, String)],
) -> Result<serde_json::Value, ProxyError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(PROXY_TIMEOUT_SECS))
        .build()?;

    let mut url = format!(
        "{}/{}",
        proxy_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    );

    if !query.is_empty() {
        let params = query
            .iter()
            .map(|(key, value)| format!("{key}={}", urlencoding(value)))
            .collect::<Vec<_>>()
            .join("&");
        url.push('?');
        url.push_str(&params);
    }

    let response = build_proxy_request(&client, reqwest::Method::GET, &url)
        .send()
        .await?;
    let status = response.status();

    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|_| "empty".into());
        return Err(ProxyError::ProxyResponse {
            status: status.as_u16(),
            body,
        });
    }

    response
        .json()
        .await
        .map_err(|e| ProxyError::InvalidResponse(e.to_string()))
}

/// List remote SkillATI skills from the proxy server.
pub async fn get_skillati_catalog(
    proxy_url: &str,
    search: Option<&str>,
) -> Result<serde_json::Value, ProxyError> {
    let query = search
        .map(|value| vec![("search", value.to_string())])
        .unwrap_or_default();
    get_proxy_json_with_query(proxy_url, "skillati/catalog", &query).await
}

/// Read a remote SkillATI skill from the proxy server.
pub async fn get_skillati_read(
    proxy_url: &str,
    name: &str,
) -> Result<serde_json::Value, ProxyError> {
    get_proxy_json(proxy_url, &format!("skillati/{}", urlencoding(name))).await
}

/// List bundled resources for a remote SkillATI skill via the proxy server.
pub async fn get_skillati_resources(
    proxy_url: &str,
    name: &str,
    prefix: Option<&str>,
) -> Result<serde_json::Value, ProxyError> {
    let query = prefix
        .map(|value| vec![("prefix", value.to_string())])
        .unwrap_or_default();
    get_proxy_json_with_query(
        proxy_url,
        &format!("skillati/{}/resources", urlencoding(name)),
        &query,
    )
    .await
}

/// Read one arbitrary skill-relative path from a remote SkillATI skill via the proxy server.
pub async fn get_skillati_file(
    proxy_url: &str,
    name: &str,
    path: &str,
) -> Result<serde_json::Value, ProxyError> {
    get_proxy_json_with_query(
        proxy_url,
        &format!("skillati/{}/file", urlencoding(name)),
        &[("path", path.to_string())],
    )
    .await
}

/// List on-demand references for a remote SkillATI skill via the proxy server.
pub async fn get_skillati_refs(
    proxy_url: &str,
    name: &str,
) -> Result<serde_json::Value, ProxyError> {
    get_proxy_json(proxy_url, &format!("skillati/{}/refs", urlencoding(name))).await
}

/// Read one reference file from a remote SkillATI skill via the proxy server.
pub async fn get_skillati_ref(
    proxy_url: &str,
    name: &str,
    reference: &str,
) -> Result<serde_json::Value, ProxyError> {
    get_proxy_json(
        proxy_url,
        &format!(
            "skillati/{}/ref/{}",
            urlencoding(name),
            urlencoding(reference)
        ),
    )
    .await
}

fn urlencoding(s: &str) -> String {
    s.replace('%', "%25")
        .replace(' ', "%20")
        .replace('#', "%23")
        .replace('&', "%26")
        .replace('?', "%3F")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

/// Resolve skills for given scopes via the proxy.
pub async fn resolve_skills(
    proxy_url: &str,
    scopes: &serde_json::Value,
) -> Result<serde_json::Value, ProxyError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(PROXY_TIMEOUT_SECS))
        .build()?;

    let url = format!("{}/skills/resolve", proxy_url.trim_end_matches('/'));

    let response = build_proxy_request(&client, reqwest::Method::POST, &url)
        .json(scopes)
        .send()
        .await?;
    let status = response.status();

    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|_| "empty".into());
        return Err(ProxyError::ProxyResponse {
            status: status.as_u16(),
            body,
        });
    }

    response
        .json()
        .await
        .map_err(|e| ProxyError::InvalidResponse(e.to_string()))
}

/// Execute an LLM help query via the proxy server.
pub async fn call_help(
    proxy_url: &str,
    query: &str,
    tool: Option<&str>,
) -> Result<String, ProxyError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(PROXY_TIMEOUT_SECS))
        .build()?;

    let url = format!("{}/help", proxy_url.trim_end_matches('/'));

    let payload = ProxyHelpRequest {
        query: query.to_string(),
        tool: tool.map(|t| t.to_string()),
    };

    let response = build_proxy_request(&client, reqwest::Method::POST, &url)
        .json(&payload)
        .send()
        .await?;
    let status = response.status();

    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|_| "empty".into());
        return Err(ProxyError::ProxyResponse {
            status: status.as_u16(),
            body,
        });
    }

    let body: ProxyHelpResponse = response
        .json()
        .await
        .map_err(|e| ProxyError::InvalidResponse(e.to_string()))?;

    if let Some(err) = body.error {
        return Err(ProxyError::ProxyResponse {
            status: 200,
            body: err,
        });
    }

    Ok(body.content)
}
