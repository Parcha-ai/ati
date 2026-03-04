use ati::core::http::{validate_headers, HttpError};
use std::collections::HashMap;

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
    headers.insert(
        "Proxy-Authorization".to_string(),
        "Basic evil".to_string(),
    );
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
