use ati::core::http::{execute_tool, validate_headers, HttpError};
use ati::core::keyring::Keyring;
use ati::core::manifest::{AuthType, HttpMethod, Provider, Tool};
use serde_json::{json, Value};
use std::collections::HashMap;
use wiremock::matchers::{body_string_contains, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn test_denied_header_authorization() {
    let mut headers = HashMap::new();
    headers.insert("Authorization".to_string(), "Bearer evil".to_string());
    let err = validate_headers(&headers, None).unwrap_err();
    assert!(matches!(err, HttpError::DeniedHeader(_)));
}

#[test]
fn test_denied_header_case_insensitive() {
    let mut headers = HashMap::new();
    headers.insert("AUTHORIZATION".to_string(), "Bearer evil".to_string());
    let err = validate_headers(&headers, None).unwrap_err();
    assert!(matches!(err, HttpError::DeniedHeader(_)));
}

#[test]
fn test_denied_header_host() {
    let mut headers = HashMap::new();
    headers.insert("Host".to_string(), "evil.com".to_string());
    assert!(validate_headers(&headers, None).is_err());
}

#[test]
fn test_denied_header_cookie() {
    let mut headers = HashMap::new();
    headers.insert("Cookie".to_string(), "session=evil".to_string());
    assert!(validate_headers(&headers, None).is_err());
}

#[test]
fn test_denied_header_set_cookie() {
    let mut headers = HashMap::new();
    headers.insert("Set-Cookie".to_string(), "session=evil".to_string());
    assert!(validate_headers(&headers, None).is_err());
}

#[test]
fn test_denied_header_content_type() {
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "text/html".to_string());
    assert!(validate_headers(&headers, None).is_err());
}

#[test]
fn test_denied_header_transfer_encoding() {
    let mut headers = HashMap::new();
    headers.insert("Transfer-Encoding".to_string(), "chunked".to_string());
    assert!(validate_headers(&headers, None).is_err());
}

#[test]
fn test_denied_header_proxy_authorization() {
    let mut headers = HashMap::new();
    headers.insert("Proxy-Authorization".to_string(), "Basic evil".to_string());
    assert!(validate_headers(&headers, None).is_err());
}

#[test]
fn test_denied_header_x_forwarded_for() {
    let mut headers = HashMap::new();
    headers.insert("X-Forwarded-For".to_string(), "1.2.3.4".to_string());
    assert!(validate_headers(&headers, None).is_err());
}

#[test]
fn test_allowed_header_passes() {
    let mut headers = HashMap::new();
    headers.insert("X-Custom-Header".to_string(), "safe-value".to_string());
    assert!(validate_headers(&headers, None).is_ok());
}

#[test]
fn test_allowed_multiple_headers_pass() {
    let mut headers = HashMap::new();
    headers.insert("X-Custom-Header".to_string(), "safe-value".to_string());
    headers.insert("Accept-Language".to_string(), "en-US".to_string());
    assert!(validate_headers(&headers, None).is_ok());
}

#[test]
fn test_empty_headers_pass() {
    let headers = HashMap::new();
    assert!(validate_headers(&headers, None).is_ok());
}

#[test]
fn test_denied_provider_auth_header() {
    let mut headers = HashMap::new();
    headers.insert("X-Api-Key".to_string(), "evil-key".to_string());
    assert!(validate_headers(&headers, Some("X-Api-Key")).is_err());
}

#[test]
fn test_denied_provider_auth_header_case_insensitive() {
    let mut headers = HashMap::new();
    headers.insert("x-api-key".to_string(), "evil-key".to_string());
    assert!(validate_headers(&headers, Some("X-Api-Key")).is_err());
}

#[test]
fn test_provider_auth_header_not_in_headers() {
    let mut headers = HashMap::new();
    headers.insert("X-Custom-Header".to_string(), "safe-value".to_string());
    assert!(validate_headers(&headers, Some("X-Api-Key")).is_ok());
}

// ---------------------------------------------------------------------------
// Helper: create a Provider pointing at a wiremock server
// ---------------------------------------------------------------------------

fn mock_provider(base_url: &str) -> Provider {
    Provider {
        name: "test".into(),
        description: String::new(),
        base_url: base_url.into(),
        auth_type: AuthType::None,
        auth_key_name: None,
        auth_header_name: None,
        auth_value_prefix: None,
        auth_query_name: None,
        auth_secret_name: None,
        handler: String::new(),
        internal: false,
        category: None,
        mcp_transport: None,
        mcp_command: None,
        mcp_args: vec![],
        mcp_env: HashMap::new(),
        mcp_url: None,
        cli_command: None,
        cli_default_args: vec![],
        cli_env: HashMap::new(),
        cli_timeout_secs: None,
        openapi_spec: None,
        openapi_include_tags: vec![],
        openapi_exclude_tags: vec![],
        openapi_include_operations: vec![],
        openapi_exclude_operations: vec![],
        openapi_max_operations: None,
        openapi_overrides: HashMap::new(),
        oauth2_token_url: None,
        oauth2_basic_auth: false,
        extra_headers: HashMap::new(),
        auth_generator: None,
        skills: vec![],
    }
}

fn mock_tool(endpoint: &str, method: HttpMethod, input_schema: Value) -> Tool {
    Tool {
        name: "test__op".into(),
        description: String::new(),
        endpoint: endpoint.into(),
        method,
        scope: None,
        input_schema: Some(input_schema),
        response: None,
        tags: vec![],
        hint: None,
        examples: vec![],
    }
}

// ---------------------------------------------------------------------------
// Test: array query param with multi format (repeated keys)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_array_query_param_multi() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/pets"))
        .and(query_param("status", "available"))
        .and(query_param("status", "pending"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&server)
        .await;

    let provider = mock_provider(&server.uri());
    let schema = json!({
        "type": "object",
        "properties": {
            "status": {
                "type": "array",
                "items": { "type": "string" },
                "x-ati-param-location": "query",
                "x-ati-collection-format": "multi"
            }
        }
    });
    let tool = mock_tool("/pets", HttpMethod::Get, schema);
    let keyring = Keyring::empty();

    let mut args = HashMap::new();
    args.insert("status".into(), json!(["available", "pending"]));

    let result = execute_tool(&provider, &tool, &args, &keyring)
        .await
        .unwrap();
    assert_eq!(result["ok"], true);
}

// ---------------------------------------------------------------------------
// Test: array query param with csv format (comma-separated)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_array_query_param_csv() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/items"))
        .and(query_param("ids", "1,2,3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&server)
        .await;

    let provider = mock_provider(&server.uri());
    let schema = json!({
        "type": "object",
        "properties": {
            "ids": {
                "type": "array",
                "items": { "type": "integer" },
                "x-ati-param-location": "query",
                "x-ati-collection-format": "csv"
            }
        }
    });
    let tool = mock_tool("/items", HttpMethod::Get, schema);
    let keyring = Keyring::empty();

    let mut args = HashMap::new();
    args.insert("ids".into(), json!([1, 2, 3]));

    let result = execute_tool(&provider, &tool, &args, &keyring)
        .await
        .unwrap();
    assert_eq!(result["ok"], true);
}

// ---------------------------------------------------------------------------
// Test: form-urlencoded body encoding
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_form_urlencoded_body() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("client_id=myapp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token": "abc123"})))
        .mount(&server)
        .await;

    let provider = mock_provider(&server.uri());
    let schema = json!({
        "type": "object",
        "x-ati-body-encoding": "form",
        "properties": {
            "grant_type": {
                "type": "string",
                "x-ati-param-location": "body"
            },
            "client_id": {
                "type": "string",
                "x-ati-param-location": "body"
            }
        }
    });
    let tool = mock_tool("/token", HttpMethod::Post, schema);
    let keyring = Keyring::empty();

    let mut args = HashMap::new();
    args.insert("grant_type".into(), json!("client_credentials"));
    args.insert("client_id".into(), json!("myapp"));

    let result = execute_tool(&provider, &tool, &args, &keyring)
        .await
        .unwrap();
    assert_eq!(result["access_token"], "abc123");
}
