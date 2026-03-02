use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

use crate::core::keyring::Keyring;
use crate::core::manifest::{AuthType, HttpMethod, Provider, Tool};

#[derive(Error, Debug)]
pub enum HttpError {
    #[error("API key '{0}' not found in keyring")]
    MissingKey(String),
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("API error ({status}): {body}")]
    ApiError { status: u16, body: String },
    #[error("Failed to parse response as JSON: {0}")]
    ParseError(String),
}

const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Execute an HTTP tool call against a provider's API.
pub async fn execute_tool(
    provider: &Provider,
    tool: &Tool,
    args: &HashMap<String, Value>,
    keyring: &Keyring,
) -> Result<Value, HttpError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .build()?;

    // Build URL
    let url = format!("{}{}", provider.base_url.trim_end_matches('/'), &tool.endpoint);

    // Build request
    let mut request = match tool.method {
        HttpMethod::Get => {
            let mut req = client.get(&url);
            // Add args as query parameters
            for (k, v) in args {
                let str_val = match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                req = req.query(&[(k.as_str(), str_val)]);
            }
            req
        }
        HttpMethod::Post => client.post(&url).json(args),
        HttpMethod::Put => client.put(&url).json(args),
        HttpMethod::Delete => client.delete(&url).json(args),
    };

    // Inject authentication
    request = inject_auth(request, provider, keyring)?;

    // Execute request
    let response = request.send().await?;
    let status = response.status();

    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|_| "empty".into());
        return Err(HttpError::ApiError {
            status: status.as_u16(),
            body,
        });
    }

    // Parse response
    let text = response.text().await?;
    let value: Value = serde_json::from_str(&text).unwrap_or_else(|_| Value::String(text));

    Ok(value)
}

/// Inject authentication headers/params based on provider auth_type.
fn inject_auth(
    request: reqwest::RequestBuilder,
    provider: &Provider,
    keyring: &Keyring,
) -> Result<reqwest::RequestBuilder, HttpError> {
    match provider.auth_type {
        AuthType::None => Ok(request),
        AuthType::Bearer => {
            let key_name = provider
                .auth_key_name
                .as_deref()
                .ok_or_else(|| HttpError::MissingKey("auth_key_name not set".into()))?;
            let key_value = keyring
                .get(key_name)
                .ok_or_else(|| HttpError::MissingKey(key_name.into()))?;
            Ok(request.bearer_auth(key_value))
        }
        AuthType::Header => {
            let key_name = provider
                .auth_key_name
                .as_deref()
                .ok_or_else(|| HttpError::MissingKey("auth_key_name not set".into()))?;
            let key_value = keyring
                .get(key_name)
                .ok_or_else(|| HttpError::MissingKey(key_name.into()))?;
            let header_name = provider
                .auth_header_name
                .as_deref()
                .unwrap_or("X-Api-Key");
            Ok(request.header(header_name, key_value))
        }
        AuthType::Query => {
            let key_name = provider
                .auth_key_name
                .as_deref()
                .ok_or_else(|| HttpError::MissingKey("auth_key_name not set".into()))?;
            let key_value = keyring
                .get(key_name)
                .ok_or_else(|| HttpError::MissingKey(key_name.into()))?;
            let query_name = provider
                .auth_query_name
                .as_deref()
                .unwrap_or("api_key");
            Ok(request.query(&[(query_name, key_value)]))
        }
        AuthType::Basic => {
            let key_name = provider
                .auth_key_name
                .as_deref()
                .ok_or_else(|| HttpError::MissingKey("auth_key_name not set".into()))?;
            let key_value = keyring
                .get(key_name)
                .ok_or_else(|| HttpError::MissingKey(key_name.into()))?;
            Ok(request.basic_auth(key_value, None::<&str>))
        }
    }
}
