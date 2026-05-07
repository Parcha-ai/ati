//! Integration tests for the OAuth 2.1 + PKCE protocol primitives.

use serde_json::json;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ati::core::oauth_mcp::{
    self, build_authorize_url, clear_discovery_cache_for_test, discover, exchange_code,
    make_pkce_pair, make_state, refresh, register_client, revoke,
};

#[tokio::test]
async fn discover_two_hop() {
    clear_discovery_cache_for_test();
    let as_server = MockServer::start().await;
    let mcp_server = MockServer::start().await;

    let prm = json!({
        "resource": mcp_server.uri(),
        "authorization_servers": [as_server.uri()],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp:read", "mcp:write"]
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-protected-resource"))
        .respond_with(ResponseTemplate::new(200).set_body_json(prm))
        .mount(&mcp_server)
        .await;

    let as_meta = json!({
        "issuer": as_server.uri(),
        "authorization_endpoint": format!("{}/authorize", as_server.uri()),
        "token_endpoint": format!("{}/token", as_server.uri()),
        "registration_endpoint": format!("{}/register", as_server.uri()),
        "revocation_endpoint": format!("{}/revoke", as_server.uri()),
        "jwks_uri": format!("{}/jwks", as_server.uri()),
        "code_challenge_methods_supported": ["S256"],
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(as_meta))
        .mount(&as_server)
        .await;

    let result = discover(&mcp_server.uri()).await.unwrap();
    assert_eq!(result.protected.authorization_servers[0], as_server.uri());
    assert_eq!(
        result.as_meta.token_endpoint,
        format!("{}/token", as_server.uri())
    );
}

#[tokio::test]
async fn discover_caches_within_ttl() {
    clear_discovery_cache_for_test();
    let as_server = MockServer::start().await;
    let mcp_server = MockServer::start().await;

    let prm = json!({
        "resource": mcp_server.uri(),
        "authorization_servers": [as_server.uri()],
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-protected-resource"))
        .respond_with(ResponseTemplate::new(200).set_body_json(prm))
        .expect(1)
        .mount(&mcp_server)
        .await;

    let as_meta = json!({
        "issuer": as_server.uri(),
        "authorization_endpoint": format!("{}/authorize", as_server.uri()),
        "token_endpoint": format!("{}/token", as_server.uri()),
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(as_meta))
        .expect(1)
        .mount(&as_server)
        .await;

    let _ = discover(&mcp_server.uri()).await.unwrap();
    let _ = discover(&mcp_server.uri()).await.unwrap();
    // Wiremock will assert the .expect(1) on drop.
}

#[tokio::test]
async fn register_client_form_body() {
    let as_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/register"))
        .and(body_string_contains("\"client_name\":\"ati-test\""))
        .and(body_string_contains("\"redirect_uris\""))
        .and(body_string_contains(
            "\"token_endpoint_auth_method\":\"none\"",
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "client_id": "oc_xyz123",
            "redirect_uris": ["http://127.0.0.1:9999/callback"],
            "token_endpoint_auth_method": "none"
        })))
        .mount(&as_server)
        .await;

    let cid = register_client(
        &format!("{}/register", as_server.uri()),
        "http://127.0.0.1:9999/callback",
        "ati-test",
    )
    .await
    .unwrap();
    assert_eq!(cid, "oc_xyz123");
}

#[tokio::test]
async fn exchange_code_includes_resource_and_verifier() {
    let as_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=authorization_code"))
        .and(body_string_contains("code=fakecode"))
        .and(body_string_contains("code_verifier=VERIFIER"))
        .and(body_string_contains("client_id=oc_abc"))
        .and(body_string_contains(
            "resource=https%3A%2F%2Fmcp.example.com",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "AT-1",
            "token_type": "Bearer",
            "expires_in": 900,
            "refresh_token": "RT-1",
            "scope": "mcp:read"
        })))
        .mount(&as_server)
        .await;

    let resp = exchange_code(
        &format!("{}/token", as_server.uri()),
        "fakecode",
        "VERIFIER",
        "http://127.0.0.1:9000/callback",
        "oc_abc",
        "https://mcp.example.com",
    )
    .await
    .unwrap();
    assert_eq!(resp.access_token, "AT-1");
    assert_eq!(resp.refresh_token.as_deref(), Some("RT-1"));
}

#[tokio::test]
async fn refresh_includes_resource() {
    let as_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("refresh_token=OLD-RT"))
        .and(body_string_contains("client_id=oc_abc"))
        .and(body_string_contains(
            "resource=https%3A%2F%2Fmcp.example.com",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "AT-2",
            "token_type": "Bearer",
            "expires_in": 900,
            "refresh_token": "RT-2",
            "scope": "mcp:read"
        })))
        .mount(&as_server)
        .await;

    let resp = refresh(
        &format!("{}/token", as_server.uri()),
        "OLD-RT",
        "oc_abc",
        "https://mcp.example.com",
        &["mcp:read".to_string()],
    )
    .await
    .unwrap();
    assert_eq!(resp.access_token, "AT-2");
    assert_eq!(resp.refresh_token.as_deref(), Some("RT-2"));
}

#[tokio::test]
async fn revoke_form_body() {
    let as_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/revoke"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string_contains("token=AT-1"))
        .and(body_string_contains("client_id=oc_abc"))
        .and(body_string_contains("token_type_hint=access_token"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&as_server)
        .await;

    revoke(
        &format!("{}/revoke", as_server.uri()),
        "AT-1",
        "oc_abc",
        Some("access_token"),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn non_2xx_maps_to_typed_error() {
    let as_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "code expired"
        })))
        .mount(&as_server)
        .await;

    let err = exchange_code(
        &format!("{}/token", as_server.uri()),
        "fakecode",
        "VERIFIER",
        "http://127.0.0.1:9000/callback",
        "oc_abc",
        "https://mcp.example.com",
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("oauth.exchange_failed"), "got: {msg}");
    assert!(msg.contains("400"), "got: {msg}");
}

#[test]
fn pkce_and_state_are_url_safe() {
    let (verifier, challenge) = make_pkce_pair();
    let state = make_state();
    for s in [&verifier, &challenge, &state] {
        assert!(!s.contains('+'));
        assert!(!s.contains('/'));
        assert!(!s.contains('='));
    }
}

#[test]
fn build_authorize_url_smoke() {
    let url = build_authorize_url(
        "https://as.example.com/authorize",
        "oc_abc",
        "http://127.0.0.1:9876/callback",
        "S",
        "C",
        "https://mcp.example.com",
        &["mcp:read".to_string()],
    )
    .unwrap();
    assert!(url.starts_with("https://as.example.com/authorize?"));
    assert!(url.contains("response_type=code"));
    assert!(url.contains("code_challenge_method=S256"));
    assert!(url.contains("scope=mcp%3Aread"));
}

#[test]
fn constant_time_eq_works() {
    assert!(oauth_mcp::constant_time_eq("a", "a"));
    assert!(!oauth_mcp::constant_time_eq("a", "b"));
    assert!(!oauth_mcp::constant_time_eq("ab", "a"));
}
