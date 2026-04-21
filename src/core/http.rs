use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use thiserror::Error;

use crate::core::auth_generator::{self, AuthCache, GenContext};
use crate::core::keyring::Keyring;
use crate::core::manifest::{AuthType, HttpMethod, Provider, Tool};

#[derive(Error, Debug)]
pub enum HttpError {
    #[error("API key '{0}' not found in keyring")]
    MissingKey(String),
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("API error ({status}): {body}")]
    ApiError {
        status: u16,
        body: String,
        /// Parsed from the upstream JSON body when present (e.g. "not_found",
        /// "invalid_request"). Used for Sentry tagging.
        error_type: Option<String>,
        /// Parsed human-readable message from the upstream body. Used for
        /// Sentry tagging after scrubbing.
        error_message: Option<String>,
    },
    /// Upstream returned a 404 with a body shape that signals "no records
    /// match" (PDL, Middesk, etc.). The caller should treat this as a legit
    /// empty result rather than a failure. Carries the parsed message for
    /// optional logging.
    #[error("No records found ({status})")]
    NoRecordsFound { status: u16 },
    #[error("Failed to parse response as JSON: {0}")]
    ParseError(String),
    #[error("OAuth2 token exchange failed: {0}")]
    Oauth2Error(String),
    #[error("Invalid path parameter '{key}': value '{value}' contains forbidden characters")]
    InvalidPathParam { key: String, value: String },
    #[error("Header '{0}' is not allowed as a user-supplied parameter")]
    DeniedHeader(String),
    #[error("SSRF protection: URL '{0}' targets a private/internal network address")]
    SsrfBlocked(String),
    #[error("OAuth2 token URL must use HTTPS: '{0}'")]
    InsecureTokenUrl(String),
}

/// Cached OAuth2 token: (access_token, expiry_instant)
static OAUTH2_CACHE: std::sync::LazyLock<Mutex<HashMap<String, (String, Instant)>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Validate that a URL does not target private/internal network addresses (SSRF protection).
/// Checks the hostname against deny-listed private IP ranges.
///
/// Enforcement is controlled by `ATI_SSRF_PROTECTION` env var:
/// - "1" or "true": block requests to private addresses (default in proxy mode)
/// - "warn": log a warning but allow the request
/// - unset/other: allow the request (for local development/testing)
pub fn validate_url_not_private(url: &str) -> Result<(), HttpError> {
    let mode = std::env::var("ATI_SSRF_PROTECTION").unwrap_or_default();
    let enforce = mode == "1" || mode.eq_ignore_ascii_case("true");
    let warn_only = mode.eq_ignore_ascii_case("warn");

    if !enforce && !warn_only {
        return Ok(());
    }
    let parsed = match reqwest::Url::parse(url) {
        Ok(parsed) => parsed,
        Err(_) => return Ok(()),
    };
    let host = parsed.host_str().unwrap_or("");
    let port = parsed.port_or_known_default().unwrap_or(80);
    let ip_host = host.trim_matches(['[', ']']);

    if host.is_empty() {
        return Ok(());
    }

    // Check common internal hostnames
    let host_lower = host.to_lowercase();
    let mut is_private = host_lower == "localhost"
        || host_lower == "metadata.google.internal"
        || host_lower.ends_with(".internal")
        || host_lower.ends_with(".local");

    if !is_private {
        if let Ok(ip) = ip_host.parse::<std::net::IpAddr>() {
            is_private = is_private_ip(ip);
        } else if let Ok(addrs) = (ip_host, port).to_socket_addrs() {
            is_private = addrs.into_iter().any(|addr| is_private_ip(addr.ip()));
        }
    }

    if is_private {
        if warn_only {
            tracing::warn!(url, "SSRF protection — URL targets private address");
            return Ok(());
        }
        return Err(HttpError::SsrfBlocked(url.to_string()));
    }

    Ok(())
}

/// Headers that must never be set by agent-supplied parameters.
/// Checked case-insensitively.
const DENIED_HEADERS: &[&str] = &[
    "authorization",
    "host",
    "cookie",
    "set-cookie",
    "content-type",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-authorization",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
];

/// Check that classified header parameters don't contain denied headers.
pub fn validate_headers(
    headers: &HashMap<String, String>,
    provider_auth_header: Option<&str>,
) -> Result<(), HttpError> {
    for key in headers.keys() {
        let lower = key.to_lowercase();
        if DENIED_HEADERS.contains(&lower.as_str()) {
            return Err(HttpError::DeniedHeader(key.clone()));
        }
        if let Some(auth_header) = provider_auth_header {
            if lower == auth_header.to_lowercase() {
                return Err(HttpError::DeniedHeader(key.clone()));
            }
        }
    }
    Ok(())
}

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

/// How array query parameters should be serialized.
#[derive(Debug, Clone, Copy, PartialEq)]
enum CollectionFormat {
    /// Repeated key: ?status=a&status=b
    Multi,
    /// Comma-separated: ?status=a,b
    Csv,
    /// Space-separated: ?status=a%20b
    Ssv,
    /// Pipe-separated: ?status=a|b
    Pipes,
}

/// How the request body should be encoded.
#[derive(Debug, Clone, Copy, PartialEq)]
enum BodyEncoding {
    Json,
    Form,
}

/// Classified parameter maps, split by location.
struct ClassifiedParams {
    path: HashMap<String, String>,
    query: HashMap<String, String>,
    query_arrays: HashMap<String, (Vec<String>, CollectionFormat)>,
    header: HashMap<String, String>,
    body: HashMap<String, Value>,
    body_encoding: BodyEncoding,
}

/// Classify parameters by their `x-ati-param-location` metadata in the input schema.
/// If no location metadata exists (legacy TOML tools), returns None for legacy fallback.
fn classify_params(tool: &Tool, args: &HashMap<String, Value>) -> Option<ClassifiedParams> {
    let schema = tool.input_schema.as_ref()?;
    let props = schema.get("properties")?.as_object()?;

    // Check if any property has x-ati-param-location — if none do, this is a legacy tool
    let has_locations = props
        .values()
        .any(|p| p.get("x-ati-param-location").is_some());

    if !has_locations {
        return None;
    }

    // Detect body encoding from schema-level metadata
    let body_encoding = match schema.get("x-ati-body-encoding").and_then(|v| v.as_str()) {
        Some("form") => BodyEncoding::Form,
        _ => BodyEncoding::Json,
    };

    let mut classified = ClassifiedParams {
        path: HashMap::new(),
        query: HashMap::new(),
        query_arrays: HashMap::new(),
        header: HashMap::new(),
        body: HashMap::new(),
        body_encoding,
    };

    for (key, value) in args {
        let prop_def = props.get(key);
        let location = prop_def
            .and_then(|p| p.get("x-ati-param-location"))
            .and_then(|l| l.as_str())
            .unwrap_or("body"); // default to body if no location specified

        match location {
            "path" => {
                classified.path.insert(key.clone(), value_to_string(value));
            }
            "query" => {
                // Check if this is an array value with a collection format
                if let Value::Array(arr) = value {
                    let cf_str = prop_def
                        .and_then(|p| p.get("x-ati-collection-format"))
                        .and_then(|v| v.as_str());
                    let cf = match cf_str {
                        Some("multi") => CollectionFormat::Multi,
                        Some("csv") => CollectionFormat::Csv,
                        Some("ssv") => CollectionFormat::Ssv,
                        Some("pipes") => CollectionFormat::Pipes,
                        _ => CollectionFormat::Multi, // default for arrays
                    };
                    let values: Vec<String> = arr.iter().map(value_to_string).collect();
                    classified.query_arrays.insert(key.clone(), (values, cf));
                } else {
                    classified.query.insert(key.clone(), value_to_string(value));
                }
            }
            "header" => {
                classified
                    .header
                    .insert(key.clone(), value_to_string(value));
            }
            _ => {
                classified.body.insert(key.clone(), value.clone());
            }
        }
    }

    Some(classified)
}

/// Substitute path parameters like `{petId}` in the endpoint template.
/// Rejects values containing path traversal or URL-breaking characters,
/// then percent-encodes the value before substitution.
fn substitute_path_params(
    endpoint: &str,
    path_args: &HashMap<String, String>,
) -> Result<String, HttpError> {
    let mut result = endpoint.to_string();
    for (key, value) in path_args {
        if value.contains("..")
            || value.contains('\\')
            || value.contains('?')
            || value.contains('#')
            || value.contains('\0')
        {
            return Err(HttpError::InvalidPathParam {
                key: key.clone(),
                value: value.clone(),
            });
        }
        let encoded = percent_encode_path_segment(value);
        result = result.replace(&format!("{{{key}}}"), &encoded);
    }
    Ok(result)
}

/// Percent-encode a path segment value. Encodes everything except unreserved chars
/// (RFC 3986 section 2.3: ALPHA / DIGIT / "-" / "." / "_" / "~").
pub(crate) fn percent_encode_path_segment(s: &str) -> String {
    let mut encoded = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}

fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || (ip.octets()[0] == 100 && ip.octets()[1] >= 64 && ip.octets()[1] <= 127)
        }
        std::net::IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
        }
    }
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

/// Apply array query parameters to a request builder using the specified collection format.
fn apply_query_arrays(
    mut req: reqwest::RequestBuilder,
    arrays: &HashMap<String, (Vec<String>, CollectionFormat)>,
) -> reqwest::RequestBuilder {
    for (key, (values, format)) in arrays {
        match format {
            CollectionFormat::Multi => {
                // Repeated key: ?status=a&status=b
                for val in values {
                    req = req.query(&[(key.as_str(), val.as_str())]);
                }
            }
            CollectionFormat::Csv => {
                let joined = values.join(",");
                req = req.query(&[(key.as_str(), joined.as_str())]);
            }
            CollectionFormat::Ssv => {
                let joined = values.join(" ");
                req = req.query(&[(key.as_str(), joined.as_str())]);
            }
            CollectionFormat::Pipes => {
                let joined = values.join("|");
                req = req.query(&[(key.as_str(), joined.as_str())]);
            }
        }
    }
    req
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
    execute_tool_with_gen(provider, tool, args, keyring, None, None).await
}

/// Execute an HTTP tool call, optionally using a dynamic auth generator.
pub async fn execute_tool_with_gen(
    provider: &Provider,
    tool: &Tool,
    args: &HashMap<String, Value>,
    keyring: &Keyring,
    gen_ctx: Option<&GenContext>,
    auth_cache: Option<&AuthCache>,
) -> Result<Value, HttpError> {
    // SSRF protection: validate base_url is not targeting private networks
    validate_url_not_private(&provider.base_url)?;

    let client = Client::builder()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .build()?;

    // Merge manifest defaults into caller-provided args
    let merged_args = merge_defaults(tool, args);

    // Try location-aware classification (OpenAPI tools have x-ati-param-location)
    let mut request = if let Some(classified) = classify_params(tool, &merged_args) {
        // Validate headers against deny-list before injecting
        validate_headers(&classified.header, provider.auth_header_name.as_deref())?;

        // Location-aware mode: substitute path params, route by location
        let resolved_endpoint = substitute_path_params(&tool.endpoint, &classified.path)?;
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
                r = apply_query_arrays(r, &classified.query_arrays);
                r
            }
            HttpMethod::Post | HttpMethod::Put => {
                let base_req = match tool.method {
                    HttpMethod::Post => client.post(&url),
                    HttpMethod::Put => client.put(&url),
                    _ => unreachable!(),
                };
                // Body params: encode as JSON or form-urlencoded based on metadata
                let mut r = if classified.body.is_empty() {
                    base_req
                } else {
                    match classified.body_encoding {
                        BodyEncoding::Json => base_req.json(&classified.body),
                        BodyEncoding::Form => {
                            let pairs: Vec<(String, String)> = classified
                                .body
                                .iter()
                                .map(|(k, v)| (k.clone(), value_to_string(v)))
                                .collect();
                            base_req.form(&pairs)
                        }
                    }
                };
                // Query params still go to query string
                for (k, v) in &classified.query {
                    r = r.query(&[(k.as_str(), v.as_str())]);
                }
                r = apply_query_arrays(r, &classified.query_arrays);
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
        let url = format!(
            "{}{}",
            provider.base_url.trim_end_matches('/'),
            &tool.endpoint
        );

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

    // Inject authentication (generator takes priority over static keyring)
    request = inject_auth(request, provider, keyring, gen_ctx, auth_cache).await?;

    // Inject extra headers from provider config
    for (header_name, header_value) in &provider.extra_headers {
        request = request.header(header_name.as_str(), header_value.as_str());
    }

    // Execute request
    let response = request.send().await?;
    let status = response.status();

    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|_| "empty".into());
        let status_u16 = status.as_u16();
        let (error_type, error_message) = crate::core::sentry_scope::parse_upstream_error(&body);
        if status_u16 == 404
            && crate::core::sentry_scope::is_no_records_body(
                error_type.as_deref(),
                error_message.as_deref(),
            )
        {
            return Err(HttpError::NoRecordsFound { status: status_u16 });
        }
        return Err(HttpError::ApiError {
            status: status_u16,
            body,
            error_type,
            error_message,
        });
    }

    // Parse response
    let text = response.text().await?;
    let value: Value = serde_json::from_str(&text).unwrap_or(Value::String(text));

    Ok(value)
}

/// Inject authentication headers/params based on provider auth_type.
///
/// If the provider has an `auth_generator`, the generator is run first to produce
/// dynamic credentials. Otherwise, static keyring credentials are used.
async fn inject_auth(
    request: reqwest::RequestBuilder,
    provider: &Provider,
    keyring: &Keyring,
    gen_ctx: Option<&GenContext>,
    auth_cache: Option<&AuthCache>,
) -> Result<reqwest::RequestBuilder, HttpError> {
    // Dynamic auth generator takes priority
    if let Some(gen) = &provider.auth_generator {
        let default_ctx = GenContext::default();
        let ctx = gen_ctx.unwrap_or(&default_ctx);
        let default_cache = AuthCache::new();
        let cache = auth_cache.unwrap_or(&default_cache);

        let cred = auth_generator::generate(provider, gen, ctx, keyring, cache)
            .await
            .map_err(|e| HttpError::MissingKey(format!("auth_generator: {e}")))?;

        // Inject primary credential based on auth_type
        let mut req = match provider.auth_type {
            AuthType::Bearer => request.bearer_auth(&cred.value),
            AuthType::Header => {
                let name = provider.auth_header_name.as_deref().unwrap_or("X-Api-Key");
                let val = match &provider.auth_value_prefix {
                    Some(pfx) => format!("{pfx}{}", cred.value),
                    None => cred.value.clone(),
                };
                request.header(name, val)
            }
            AuthType::Query => {
                let name = provider.auth_query_name.as_deref().unwrap_or("api_key");
                request.query(&[(name, &cred.value)])
            }
            _ => request,
        };
        // Inject extra headers from JSON inject targets
        for (name, value) in &cred.extra_headers {
            req = req.header(name.as_str(), value.as_str());
        }
        return Ok(req);
    }

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
            let header_name = provider.auth_header_name.as_deref().unwrap_or("X-Api-Key");
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
            let query_name = provider.auth_query_name.as_deref().unwrap_or("api_key");
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
        AuthType::Url => {
            // Auth key is already interpolated into the URL via
            // ${key_name} placeholders resolved at connection time.
            // No header or query param injection needed.
            Ok(request)
        }
    }
}

/// Fetch (or return cached) OAuth2 access token via client_credentials grant.
async fn get_oauth2_token(provider: &Provider, keyring: &Keyring) -> Result<String, HttpError> {
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

    // Enforce HTTPS for OAuth2 token URLs (credentials are sent in plaintext otherwise)
    if token_url.starts_with("http://") {
        return Err(HttpError::InsecureTokenUrl(token_url));
    }

    let client = Client::builder().timeout(Duration::from_secs(15)).build()?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_substitute_path_params_normal() {
        let mut args = HashMap::new();
        args.insert("petId".to_string(), "123".to_string());
        let result = substitute_path_params("/pet/{petId}", &args).unwrap();
        assert_eq!(result, "/pet/123");
    }

    #[test]
    fn test_substitute_path_params_rejects_dotdot() {
        let mut args = HashMap::new();
        args.insert("id".to_string(), "../admin".to_string());
        assert!(substitute_path_params("/resource/{id}", &args).is_err());
    }

    #[test]
    fn test_substitute_path_params_encodes_slash() {
        let mut args = HashMap::new();
        args.insert("id".to_string(), "fal-ai/flux/dev".to_string());
        let result = substitute_path_params("/resource/{id}", &args).unwrap();
        assert_eq!(result, "/resource/fal-ai%2Fflux%2Fdev");
    }

    #[test]
    fn test_substitute_path_params_rejects_backslash() {
        let mut args = HashMap::new();
        args.insert("id".to_string(), "foo\\bar".to_string());
        assert!(substitute_path_params("/resource/{id}", &args).is_err());
    }

    #[test]
    fn test_substitute_path_params_rejects_question() {
        let mut args = HashMap::new();
        args.insert("id".to_string(), "foo?bar=1".to_string());
        assert!(substitute_path_params("/resource/{id}", &args).is_err());
    }

    #[test]
    fn test_substitute_path_params_rejects_hash() {
        let mut args = HashMap::new();
        args.insert("id".to_string(), "foo#bar".to_string());
        assert!(substitute_path_params("/resource/{id}", &args).is_err());
    }

    #[test]
    fn test_substitute_path_params_rejects_null_byte() {
        let mut args = HashMap::new();
        args.insert("id".to_string(), "foo\0bar".to_string());
        assert!(substitute_path_params("/resource/{id}", &args).is_err());
    }

    #[test]
    fn test_substitute_path_params_encodes_special() {
        let mut args = HashMap::new();
        args.insert("name".to_string(), "hello world".to_string());
        let result = substitute_path_params("/users/{name}", &args).unwrap();
        assert_eq!(result, "/users/hello%20world");
    }

    #[test]
    fn test_substitute_path_params_preserves_unreserved() {
        let mut args = HashMap::new();
        args.insert("id".to_string(), "abc-123_test.v2~draft".to_string());
        let result = substitute_path_params("/items/{id}", &args).unwrap();
        assert_eq!(result, "/items/abc-123_test.v2~draft");
    }

    #[test]
    fn test_substitute_path_params_encodes_at_sign() {
        let mut args = HashMap::new();
        args.insert("user".to_string(), "user@domain".to_string());
        let result = substitute_path_params("/profile/{user}", &args).unwrap();
        assert_eq!(result, "/profile/user%40domain");
    }

    #[test]
    fn test_percent_encode_path_segment_empty() {
        assert_eq!(percent_encode_path_segment(""), "");
    }

    #[test]
    fn test_percent_encode_path_segment_ascii_only() {
        assert_eq!(percent_encode_path_segment("abc123"), "abc123");
    }

    #[test]
    fn test_substitute_path_params_multiple() {
        let mut args = HashMap::new();
        args.insert("owner".to_string(), "acme".to_string());
        args.insert("repo".to_string(), "widgets".to_string());
        let result = substitute_path_params("/repos/{owner}/{repo}/issues", &args).unwrap();
        assert_eq!(result, "/repos/acme/widgets/issues");
    }

    #[test]
    fn test_substitute_path_params_no_placeholders() {
        let args = HashMap::new();
        let result = substitute_path_params("/health", &args).unwrap();
        assert_eq!(result, "/health");
    }
}
