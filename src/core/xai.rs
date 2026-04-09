/// xAI agentic handler — constructs proper /responses requests for Grok tools.
///
/// xAI's API is NOT a simple REST endpoint. It accepts:
/// ```json
/// POST /v1/responses
/// { "model": "grok-3-mini", "tools": [{"type": "web_search"}], "input": "query" }
/// ```
/// The model internally calls tools and returns agentic results.
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;

use crate::core::http::HttpError;
use crate::core::manifest::{Provider, Tool};
use crate::core::secret_resolver::SecretResolver;

const XAI_TIMEOUT_SECS: u64 = 90;

/// Execute an xAI tool via the /responses agentic API.
pub async fn execute_xai_tool(
    provider: &Provider,
    tool: &Tool,
    args: &HashMap<String, Value>,
    keyring: &SecretResolver<'_>,
) -> Result<Value, HttpError> {
    let key_name = provider
        .auth_key_name
        .as_deref()
        .ok_or_else(|| HttpError::MissingKey("auth_key_name not set for xAI".into()))?;
    let api_key = keyring
        .get(key_name)
        .ok_or_else(|| HttpError::MissingKey(key_name.into()))?;

    let query = args
        .get("query")
        .and_then(|v| v.as_str())
        .unwrap_or("latest news");

    let model = args
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("grok-4-fast-non-reasoning");

    // Map tool name to xAI tool types
    let xai_tools = map_tool_types(&tool.name);

    // Build input prompt — for trending, prefix with "trending" context
    let input = if tool.name == "xai_trending_search" {
        format!("What are the trending topics and discussions about: {query}")
    } else {
        query.to_string()
    };

    let request_body = serde_json::json!({
        "model": model,
        "tools": xai_tools,
        "input": input,
    });

    let url = format!("{}/responses", provider.base_url.trim_end_matches('/'));

    let client = Client::builder()
        .timeout(Duration::from_secs(XAI_TIMEOUT_SECS))
        .build()?;

    let response = client
        .post(&url)
        .bearer_auth(api_key)
        .json(&request_body)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|_| "empty".into());
        return Err(HttpError::ApiError {
            status: status.as_u16(),
            body,
        });
    }

    let body: Value = response
        .json()
        .await
        .map_err(|e| HttpError::ParseError(format!("failed to parse xAI response: {e}")))?;

    // Extract useful content from the agentic response.
    // The response has an "output" array with items of different types.
    // We extract text content and search result URLs.
    Ok(extract_xai_results(&body))
}

/// Map ATI tool name to xAI tool type objects.
fn map_tool_types(tool_name: &str) -> Vec<Value> {
    match tool_name {
        "xai_web_search" => vec![serde_json::json!({"type": "web_search"})],
        "xai_x_search" | "xai_trending_search" => {
            vec![serde_json::json!({"type": "x_search"})]
        }
        "xai_combined_search" => vec![
            serde_json::json!({"type": "web_search"}),
            serde_json::json!({"type": "x_search"}),
        ],
        _ => vec![serde_json::json!({"type": "web_search"})],
    }
}

/// Extract meaningful results from xAI's agentic response format.
///
/// The output array contains items like:
/// - `{"type": "message", "content": [{"type": "output_text", "text": "..."}]}`
/// - `{"type": "web_search_call", "action": {"query": "...", "sources": [...]}}}`
fn extract_xai_results(body: &Value) -> Value {
    let output = match body.get("output").and_then(|o| o.as_array()) {
        Some(arr) => arr,
        None => return body.clone(),
    };

    let mut text_content = Vec::new();
    let mut search_queries = Vec::new();
    let mut annotations = Vec::new();

    for item in output {
        let item_type = item.get("type").and_then(|t| t.as_str()).unwrap_or("");

        if item_type == "message" {
            if let Some(content) = item.get("content").and_then(|c| c.as_array()) {
                for block in content {
                    let block_type = block.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    if block_type == "output_text" || block_type == "text" {
                        if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                            text_content.push(text.to_string());
                        }
                    }
                    // Collect URL citations from annotations
                    if let Some(annots) = block.get("annotations").and_then(|a| a.as_array()) {
                        for ann in annots {
                            if ann.get("type").and_then(|t| t.as_str()) == Some("url_citation") {
                                annotations.push(ann.clone());
                            }
                        }
                    }
                }
            }
        } else if item_type.ends_with("_call") {
            // web_search_call, x_search_call, etc.
            if let Some(action) = item.get("action") {
                if let Some(query) = action.get("query").and_then(|q| q.as_str()) {
                    search_queries.push(query.to_string());
                }
            }
        }
    }

    serde_json::json!({
        "text": text_content.join("\n\n"),
        "citations": annotations,
        "search_queries": search_queries,
        "raw_output_count": output.len(),
    })
}
