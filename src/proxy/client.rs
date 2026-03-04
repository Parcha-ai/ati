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
    pub args: HashMap<String, Value>,
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
fn build_proxy_request(client: &Client, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
    let mut req = client.request(method, url);
    if let Ok(token) = std::env::var("ATI_SESSION_TOKEN") {
        if !token.is_empty() {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
    }
    req
}

/// Execute a tool call via the proxy server.
///
/// POST {proxy_url}/call with JSON body: { tool_name, args }
/// Scopes are carried inside the JWT — not in the request body.
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

    let payload = ProxyCallRequest {
        tool_name: tool_name.to_string(),
        args: args.clone(),
        raw_args: raw_args.map(|r| r.to_vec()),
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
) -> Result<String, ProxyError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(PROXY_TIMEOUT_SECS))
        .build()?;

    let url = format!("{}/help", proxy_url.trim_end_matches('/'));

    let payload = ProxyHelpRequest {
        query: query.to_string(),
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
