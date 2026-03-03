use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
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
    #[error("OAuth2 token exchange failed: {0}")]
    Oauth2Error(String),
}

/// Cached OAuth2 token: (access_token, expiry_instant)
static OAUTH2_CACHE: std::sync::LazyLock<Mutex<HashMap<String, (String, Instant)>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Merge manifest defaults into the args map for any params not provided by caller.
fn merge_defaults(tool: &Tool, args: &HashMap<String, Value>) -> HashMap<String, Value> {
    let mut merged = args.clone();
    if let Some(schema) = &tool.input_schema {
        if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
            for (key, prop_def) in props {
                if !merged.contains_key(key) {
                    if let Some(default_val) = prop_def.get("default") {
                        // Skip empty arrays/objects as defaults — they add no value
                        // and some APIs reject them (e.g. ClinicalTrials `sort=[]`).
                        let dominated = match default_val {
                            Value::Array(a) => a.is_empty(),
                            Value::Object(o) => o.is_empty(),
                            Value::Null => true,
                            _ => false,
                        };
                        if !dominated {
                            merged.insert(key.clone(), default_val.clone());
                        }
                    }
                }
            }
        }
    }
    merged
}

/// Classified parameter maps, split by location.
struct ClassifiedParams {
    path: HashMap<String, String>,
    query: HashMap<String, String>,
    header: HashMap<String, String>,
    body: HashMap<String, Value>,
}

/// Classify parameters by their `x-ati-param-location` metadata in the input schema.
/// If no location metadata exists (legacy TOML tools), returns None for legacy fallback.
fn classify_params(
    tool: &Tool,
    args: &HashMap<String, Value>,
) -> Option<ClassifiedParams> {
    let schema = tool.input_schema.as_ref()?;
    let props = schema.get("properties")?.as_object()?;

    // Check if any property has x-ati-param-location — if none do, this is a legacy tool
    let has_locations = props
        .values()
        .any(|p| p.get("x-ati-param-location").is_some());

    if !has_locations {
        return None;
    }

    let mut classified = ClassifiedParams {
        path: HashMap::new(),
        query: HashMap::new(),
        header: HashMap::new(),
        body: HashMap::new(),
    };

    for (key, value) in args {
        let location = props
            .get(key)
            .and_then(|p| p.get("x-ati-param-location"))
            .and_then(|l| l.as_str())
            .unwrap_or("body"); // default to body if no location specified

        match location {
            "path" => {
                classified.path.insert(key.clone(), value_to_string(value));
            }
            "query" => {
                classified.query.insert(key.clone(), value_to_string(value));
            }
            "header" => {
                classified.header.insert(key.clone(), value_to_string(value));
            }
            _ => {
                classified.body.insert(key.clone(), value.clone());
            }
        }
    }

    Some(classified)
}

/// Substitute path parameters like `{petId}` in the endpoint template.
/// Returns the resolved URL path string.
fn substitute_path_params(endpoint: &str, path_args: &HashMap<String, String>) -> String {
    let mut result = endpoint.to_string();
    for (key, value) in path_args {
        result = result.replace(&format!("{{{key}}}"), value);
    }
    result
}

/// Convert a serde_json::Value to a URL-safe string.
fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Execute an HTTP tool call against a provider's API.
///
/// Supports two modes:
/// 1. **Location-aware** (OpenAPI tools): Parameters are classified by `x-ati-param-location`
///    metadata in the input schema. Path params are substituted into the URL template,
///    query params go to the query string, header params become request headers,
///    and body params go to the JSON body.
/// 2. **Legacy** (hand-written TOML tools): GET → all args as query params, POST/PUT/DELETE → JSON body.
pub async fn execute_tool(
    provider: &Provider,
    tool: &Tool,
    args: &HashMap<String, Value>,
    keyring: &Keyring,
) -> Result<Value, HttpError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .build()?;

    // Merge manifest defaults into caller-provided args
    let merged_args = merge_defaults(tool, args);

    // Try location-aware classification (OpenAPI tools have x-ati-param-location)
    let mut request = if let Some(classified) = classify_params(tool, &merged_args) {
        // Location-aware mode: substitute path params, route by location
        let resolved_endpoint = substitute_path_params(&tool.endpoint, &classified.path);
        let url = format!(
            "{}{}",
            provider.base_url.trim_end_matches('/'),
            resolved_endpoint
        );

        let mut req = match tool.method {
            HttpMethod::Get | HttpMethod::Delete => {
                let base_req = match tool.method {
                    HttpMethod::Get => client.get(&url),
                    HttpMethod::Delete => client.delete(&url),
                    _ => unreachable!(),
                };
                // Query params to query string
                let mut r = base_req;
                for (k, v) in &classified.query {
                    r = r.query(&[(k.as_str(), v.as_str())]);
                }
                r
            }
            HttpMethod::Post | HttpMethod::Put => {
                let base_req = match tool.method {
                    HttpMethod::Post => client.post(&url),
                    HttpMethod::Put => client.put(&url),
                    _ => unreachable!(),
                };
                // Body params to JSON body, query params still to query string
                let mut r = if classified.body.is_empty() {
                    base_req
                } else {
                    base_req.json(&classified.body)
                };
                for (k, v) in &classified.query {
                    r = r.query(&[(k.as_str(), v.as_str())]);
                }
                r
            }
        };

        // Inject classified header params
        for (k, v) in &classified.header {
            req = req.header(k.as_str(), v.as_str());
        }

        req
    } else {
        // Legacy mode: no x-ati-param-location metadata
        let url = format!("{}{}", provider.base_url.trim_end_matches('/'), &tool.endpoint);

        match tool.method {
            HttpMethod::Get => {
                let mut req = client.get(&url);
                for (k, v) in &merged_args {
                    req = req.query(&[(k.as_str(), value_to_string(v))]);
                }
                req
            }
            HttpMethod::Post => client.post(&url).json(&merged_args),
            HttpMethod::Put => client.put(&url).json(&merged_args),
            HttpMethod::Delete => client.delete(&url).json(&merged_args),
        }
    };

    // Inject authentication
    request = inject_auth(request, provider, keyring).await?;

    // Inject extra headers from provider config
    for (header_name, header_value) in &provider.extra_headers {
        request = request.header(header_name.as_str(), header_value.as_str());
    }

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
async fn inject_auth(
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
            let final_value = match &provider.auth_value_prefix {
                Some(prefix) => format!("{}{}", prefix, key_value),
                None => key_value.to_string(),
            };
            Ok(request.header(header_name, final_value))
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
        AuthType::Oauth2 => {
            let access_token = get_oauth2_token(provider, keyring).await?;
            Ok(request.bearer_auth(access_token))
        }
    }
}

/// Fetch (or return cached) OAuth2 access token via client_credentials grant.
async fn get_oauth2_token(
    provider: &Provider,
    keyring: &Keyring,
) -> Result<String, HttpError> {
    let cache_key = provider.name.clone();

    // Check cache
    {
        let cache = OAUTH2_CACHE.lock().unwrap();
        if let Some((token, expiry)) = cache.get(&cache_key) {
            // Use cached token if it has at least 60s remaining
            if Instant::now() + Duration::from_secs(60) < *expiry {
                return Ok(token.clone());
            }
        }
    }

    // Token expired or not cached — exchange credentials
    let client_id_key = provider
        .auth_key_name
        .as_deref()
        .ok_or_else(|| HttpError::Oauth2Error("auth_key_name not set for OAuth2".into()))?;
    let client_id = keyring
        .get(client_id_key)
        .ok_or_else(|| HttpError::MissingKey(client_id_key.into()))?;

    let client_secret_key = provider
        .auth_secret_name
        .as_deref()
        .ok_or_else(|| HttpError::Oauth2Error("auth_secret_name not set for OAuth2".into()))?;
    let client_secret = keyring
        .get(client_secret_key)
        .ok_or_else(|| HttpError::MissingKey(client_secret_key.into()))?;

    let token_url = match &provider.oauth2_token_url {
        Some(url) if url.starts_with("http") => url.clone(),
        Some(path) => format!("{}{}", provider.base_url.trim_end_matches('/'), path),
        None => return Err(HttpError::Oauth2Error("oauth2_token_url not set".into())),
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    // Two OAuth2 client_credentials modes:
    // 1. Form body: client_id + client_secret in form data (Amadeus)
    // 2. Basic Auth: base64(client_id:client_secret) in Authorization header (Sovos)
    let response = if provider.oauth2_basic_auth {
        client
            .post(&token_url)
            .basic_auth(client_id, Some(client_secret))
            .form(&[("grant_type", "client_credentials")])
            .send()
            .await?
    } else {
        client
            .post(&token_url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id),
                ("client_secret", client_secret),
            ])
            .send()
            .await?
    };

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        return Err(HttpError::Oauth2Error(format!(
            "token exchange failed ({status}): {body}"
        )));
    }

    let body: Value = response
        .json()
        .await
        .map_err(|e| HttpError::Oauth2Error(format!("failed to parse token response: {e}")))?;

    let access_token = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| HttpError::Oauth2Error("no access_token in response".into()))?
        .to_string();

    let expires_in = body
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(1799);

    let expiry = Instant::now() + Duration::from_secs(expires_in);

    // Cache the token
    {
        let mut cache = OAUTH2_CACHE.lock().unwrap();
        cache.insert(cache_key, (access_token.clone(), expiry));
    }

    Ok(access_token)
}
