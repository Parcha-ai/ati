//! Integration tests for the race-safe refresh helper.

use chrono::{Duration, Utc};
use serde_json::json;
use std::collections::HashMap;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ati::core::manifest::{AuthType, Provider};
use ati::core::oauth_refresh::{ensure_fresh_token, force_refresh};
use ati::core::oauth_store::{self, ProviderTokens};

fn provider_for_test(name: &str, _token_endpoint: &str) -> Provider {
    Provider {
        name: name.to_string(),
        description: "test".into(),
        base_url: String::new(),
        auth_type: AuthType::Oauth2Pkce,
        auth_key_name: None,
        auth_header_name: None,
        auth_query_name: None,
        auth_value_prefix: None,
        extra_headers: HashMap::new(),
        oauth2_token_url: None,
        auth_secret_name: None,
        oauth2_basic_auth: false,
        oauth_resource: Some("https://mcp.example.com".into()),
        oauth_scopes: vec!["mcp:read".into()],
        internal: false,
        handler: "mcp".into(),
        mcp_transport: Some("http".into()),
        mcp_command: None,
        mcp_args: vec![],
        mcp_url: Some("https://mcp.example.com".into()),
        mcp_env: HashMap::new(),
        cli_command: None,
        cli_default_args: vec![],
        cli_env: HashMap::new(),
        cli_timeout_secs: None,
        cli_output_args: vec![],
        cli_output_positional: HashMap::new(),
        upload_destinations: HashMap::new(),
        upload_default_destination: None,
        openapi_spec: None,
        openapi_include_tags: vec![],
        openapi_exclude_tags: vec![],
        openapi_include_operations: vec![],
        openapi_exclude_operations: vec![],
        openapi_max_operations: None,
        openapi_overrides: HashMap::new(),
        auth_generator: None,
        category: None,
        skills: vec![],
    }
}

fn seed_tokens(name: &str, token_endpoint: &str, expires_in_secs: i64, refresh: Option<&str>) {
    let t = ProviderTokens {
        provider: name.to_string(),
        client_id: "oc_abc".into(),
        redirect_uri: "http://127.0.0.1:9000/callback".into(),
        access_token: "OLD-AT".into(),
        access_token_expires_at: Utc::now() + Duration::seconds(expires_in_secs),
        refresh_token: refresh.map(|s| s.to_string()),
        scopes: vec!["mcp:read".into()],
        resource: "https://mcp.example.com".into(),
        token_endpoint: token_endpoint.to_string(),
        revocation_endpoint: None,
        authorized_at: Utc::now(),
        updated_at: Utc::now(),
    };
    oauth_store::save(&t).unwrap();
}

// Tests in this file mutate ATI_DIR (a process-wide env var) and share the
// in-process refresh-mutex map. Serialize them via a single Mutex so they
// don't stomp on each other under cargo's parallel test runner.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct EnvGuard {
    _tmp: TempDir,
    _guard: std::sync::MutexGuard<'static, ()>,
}

fn with_tmp_ati_dir() -> EnvGuard {
    let guard = match SERIAL.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let tmp = TempDir::new().unwrap();
    std::env::set_var("ATI_DIR", tmp.path());
    EnvGuard {
        _tmp: tmp,
        _guard: guard,
    }
}

#[tokio::test]
async fn ensure_fresh_returns_cached_when_not_expiring() {
    let _g = with_tmp_ati_dir();
    seed_tokens("p_a", "http://127.0.0.1:1/token", 3600, Some("RT"));
    // No wiremock served. If the helper tried to refresh, it would error.
    let token = ensure_fresh_token(
        &provider_for_test("p_a", ""),
        std::time::Duration::from_secs(60),
    )
    .await
    .unwrap();
    assert_eq!(token, "OLD-AT");
    std::env::remove_var("ATI_DIR");
}

#[tokio::test]
async fn ensure_fresh_refreshes_when_near_expiry() {
    let _g = with_tmp_ati_dir();
    let as_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "NEW-AT",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "NEW-RT"
        })))
        .expect(1)
        .mount(&as_server)
        .await;

    seed_tokens(
        "p_b",
        &format!("{}/token", as_server.uri()),
        20, // about to expire
        Some("OLD-RT"),
    );

    let token = ensure_fresh_token(
        &provider_for_test("p_b", ""),
        std::time::Duration::from_secs(60),
    )
    .await
    .unwrap();
    assert_eq!(token, "NEW-AT");

    // Persisted tokens should reflect the new bundle.
    let persisted = oauth_store::load("p_b").unwrap().unwrap();
    assert_eq!(persisted.access_token, "NEW-AT");
    assert_eq!(persisted.refresh_token.as_deref(), Some("NEW-RT"));
    std::env::remove_var("ATI_DIR");
}

#[tokio::test]
async fn force_refresh_calls_token_endpoint() {
    let _g = with_tmp_ati_dir();
    let as_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "FORCE-AT",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "FORCE-RT"
        })))
        .expect(1)
        .mount(&as_server)
        .await;

    seed_tokens(
        "p_c",
        &format!("{}/token", as_server.uri()),
        7200, // not expiring
        Some("OLD-RT"),
    );

    // Make access token already-expired so force_refresh actually refreshes
    // (the implementation skips refresh if remaining > 30s; that's an
    // optimization, not a hard guarantee).
    let mut t = oauth_store::load("p_c").unwrap().unwrap();
    t.access_token_expires_at = Utc::now() - Duration::seconds(1);
    oauth_store::save(&t).unwrap();

    let token = force_refresh(&provider_for_test("p_c", "")).await.unwrap();
    assert_eq!(token, "FORCE-AT");
    std::env::remove_var("ATI_DIR");
}

#[tokio::test]
async fn not_authorized_when_no_tokens() {
    let _g = with_tmp_ati_dir();
    let err = ensure_fresh_token(
        &provider_for_test("p_d", ""),
        std::time::Duration::from_secs(60),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("oauth.not_authorized"));
    std::env::remove_var("ATI_DIR");
}
