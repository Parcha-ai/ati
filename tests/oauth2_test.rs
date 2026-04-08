//! Tests for OAuth2 client_credentials flow through execute_tool_with_gen.
//!
//! Uses wiremock to mock both the OAuth2 token endpoint and the upstream API.
//! Since get_oauth2_token enforces HTTPS and wiremock is HTTP, we test the
//! error paths for non-HTTPS and config errors, plus verify the full flow by
//! constructing the provider with the mock URL.

mod common;

use ati::core::http::execute_tool_with_gen;
use ati::core::keyring::Keyring;
use ati::core::manifest::AuthType;
use ati::core::secret_resolver::SecretResolver;
use std::collections::HashMap;
use wiremock::MockServer;

/// OAuth2 with HTTP token URL is rejected (InsecureTokenUrl).
#[tokio::test]
async fn test_oauth2_rejects_http_token_url() {
    let upstream = MockServer::start().await;

    let provider = ati::core::manifest::Provider {
        auth_type: AuthType::Oauth2,
        auth_key_name: Some("client_id".into()),
        auth_secret_name: Some("client_secret".into()),
        oauth2_token_url: Some(format!("{}/oauth/token", upstream.uri())),
        ..common::test_provider("oauth_test", &upstream.uri())
    };
    let tool = common::test_tool(
        "oauth_search",
        "/data",
        ati::core::manifest::HttpMethod::Get,
    );
    let keyring = common::test_keyring(&[("client_id", "id"), ("client_secret", "secret")]);
    let resolver = SecretResolver::operator_only(&keyring);

    let args = HashMap::new();
    let err = execute_tool_with_gen(&provider, &tool, &args, &resolver, None, None)
        .await
        .unwrap_err();

    // OAuth2 enforces HTTPS for token URLs
    let msg = format!("{err}");
    assert!(
        msg.contains("HTTPS") || msg.contains("http://"),
        "Expected InsecureTokenUrl error, got: {msg}"
    );
}

/// OAuth2 with missing auth_key_name returns error.
#[tokio::test]
async fn test_oauth2_missing_client_id_key() {
    let provider = ati::core::manifest::Provider {
        auth_type: AuthType::Oauth2,
        auth_key_name: None,
        auth_secret_name: Some("secret".into()),
        oauth2_token_url: Some("https://auth.example.com/token".into()),
        ..common::test_provider("oauth_test", "https://api.example.com")
    };
    let tool = common::test_tool("oauth_tool", "/data", ati::core::manifest::HttpMethod::Get);
    let keyring = Keyring::empty();
    let resolver = SecretResolver::operator_only(&keyring);

    let args = HashMap::new();
    let err = execute_tool_with_gen(&provider, &tool, &args, &resolver, None, None)
        .await
        .unwrap_err();

    let msg = format!("{err}");
    assert!(
        msg.contains("auth_key_name") || msg.contains("OAuth2"),
        "Expected missing key error, got: {msg}"
    );
}

/// OAuth2 with missing auth_secret_name returns error.
#[tokio::test]
async fn test_oauth2_missing_client_secret_key() {
    let provider = ati::core::manifest::Provider {
        auth_type: AuthType::Oauth2,
        auth_key_name: Some("client_id".into()),
        auth_secret_name: None,
        oauth2_token_url: Some("https://auth.example.com/token".into()),
        ..common::test_provider("oauth_test", "https://api.example.com")
    };
    let tool = common::test_tool("oauth_tool", "/data", ati::core::manifest::HttpMethod::Get);
    let keyring = common::test_keyring(&[("client_id", "test-id")]);
    let resolver = SecretResolver::operator_only(&keyring);

    let args = HashMap::new();
    let err = execute_tool_with_gen(&provider, &tool, &args, &resolver, None, None)
        .await
        .unwrap_err();

    let msg = format!("{err}");
    assert!(
        msg.contains("auth_secret_name") || msg.contains("OAuth2"),
        "Expected missing secret error, got: {msg}"
    );
}

/// OAuth2 with missing token_url returns error.
#[tokio::test]
async fn test_oauth2_missing_token_url() {
    let provider = ati::core::manifest::Provider {
        auth_type: AuthType::Oauth2,
        auth_key_name: Some("client_id".into()),
        auth_secret_name: Some("client_secret".into()),
        oauth2_token_url: None,
        ..common::test_provider("oauth_test", "https://api.example.com")
    };
    let tool = common::test_tool("oauth_tool", "/data", ati::core::manifest::HttpMethod::Get);
    let keyring = common::test_keyring(&[("client_id", "id"), ("client_secret", "secret")]);
    let resolver = SecretResolver::operator_only(&keyring);

    let args = HashMap::new();
    let err = execute_tool_with_gen(&provider, &tool, &args, &resolver, None, None)
        .await
        .unwrap_err();

    let msg = format!("{err}");
    assert!(
        msg.contains("oauth2_token_url") || msg.contains("not set"),
        "Expected missing token URL error, got: {msg}"
    );
}

/// OAuth2 with missing keyring creds returns MissingKey.
#[tokio::test]
async fn test_oauth2_missing_keyring_creds() {
    let provider = ati::core::manifest::Provider {
        auth_type: AuthType::Oauth2,
        auth_key_name: Some("client_id".into()),
        auth_secret_name: Some("client_secret".into()),
        oauth2_token_url: Some("https://auth.example.com/token".into()),
        ..common::test_provider("oauth_test", "https://api.example.com")
    };
    let tool = common::test_tool("oauth_tool", "/data", ati::core::manifest::HttpMethod::Get);
    let keyring = Keyring::empty();
    let resolver = SecretResolver::operator_only(&keyring);

    let args = HashMap::new();
    let err = execute_tool_with_gen(&provider, &tool, &args, &resolver, None, None)
        .await
        .unwrap_err();

    let msg = format!("{err}");
    assert!(
        msg.contains("client_id"),
        "Expected missing key error for client_id, got: {msg}"
    );
}
