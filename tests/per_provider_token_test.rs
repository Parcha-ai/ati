//! Per-provider session-token end-to-end test (issue #121).
//!
//! Proves the full chain:
//!   sandbox CLI → resolves provider's `auth_session_token_env` → reads
//!   that env var → sends `Authorization: Bearer <its-value>` → proxy
//!   validates against the multi-audience allowlist → handler runs.
//!
//! Setup pattern mirrors `tests/proxy_server_test.rs`: an axum Router
//! built from a `ProxyState`, exercised via `tower::ServiceExt::oneshot`.
//! We don't spin up an actual `ati proxy` subprocess (that's covered by
//! the runtime e2e harness at `/tmp/ati-e2e-115/`); here we focus on
//! the proxy-side JWT-validation contract that makes per-provider tokens
//! work at all.
//!
//! Three scenarios:
//!   1. Per-provider audience JWT (aud=parcha-custom-tools) accepted when
//!      `ATI_JWT_ACCEPTED_AUDIENCES` includes it.
//!   2. Same token REJECTED when the proxy only accepts `ati-proxy`
//!      (the pre-#121 behaviour — proves the fix is necessary).
//!   3. Default `ATI_SESSION_TOKEN` (aud=ati-proxy) still accepted when
//!      the proxy is configured with the multi-audience allowlist.
//!      Proves the backwards-compat guarantee.
//!
//! End-to-end exercise of the sandbox CLI's per-provider env-var lookup
//! (the `execute_via_proxy` registry path) lives in the runtime harness;
//! these unit-level tests pin the proxy-side acceptance contract.

use ati::core::jwt::{self, JwtConfig};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

const SECRET: &[u8] = b"per-provider-test-secret-32bytes";

/// Build a JwtConfig that accepts BOTH `ati-proxy` and `parcha-custom-tools`.
/// Mirrors what a production proxy would have when
/// `ATI_JWT_ACCEPTED_AUDIENCES="ati-proxy,parcha-custom-tools"` is set.
fn multi_aud_config() -> JwtConfig {
    jwt::config_from_secret(
        SECRET,
        None,
        vec!["ati-proxy".into(), "parcha-custom-tools".into()],
    )
}

/// Build a single-audience config matching the pre-#121 default: only
/// `ati-proxy` is accepted. Used to prove the fix is necessary (the
/// alt-aud token gets rejected here).
fn single_aud_config() -> JwtConfig {
    jwt::config_from_secret(SECRET, None, vec!["ati-proxy".into()])
}

/// Mint a JWT signed with `SECRET` for the given audience + scopes.
fn issue_test_token(aud: &str, scope: &str) -> String {
    use ati::core::jwt::{AtiNamespace, TokenClaims};
    use std::collections::HashMap;

    let now = jwt::now_secs();
    let claims = TokenClaims {
        iss: None,
        sub: "sandbox:e2e-121".into(),
        aud: aud.into(),
        iat: now,
        exp: now + 300,
        jti: Some(uuid::Uuid::new_v4().to_string()),
        scope: scope.into(),
        ati: Some(AtiNamespace {
            v: 1,
            rate: HashMap::new(),
        }),
        job_id: None,
        sandbox_id: None,
    };
    let config = jwt::config_from_secret(SECRET, None, vec![aud.into()]);
    jwt::issue(&claims, &config).expect("issue token")
}

fn build_app(jwt_config: JwtConfig) -> axum::Router {
    use ati::core::auth_generator::AuthCache;
    use ati::core::keyring::Keyring;
    use ati::core::manifest::ManifestRegistry;
    use ati::core::skill::SkillRegistry;
    use ati::proxy::server::{build_router, ProxyState};
    use std::sync::Arc;

    let dir = tempfile::tempdir().expect("tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("manifests dir");
    // Minimal HTTP provider whose tool is well-scoped; no auth_generator
    // needed for these tests — we're exercising JWT validation, not
    // outbound credential generation.
    std::fs::write(
        manifests_dir.join("echo.toml"),
        r#"
[provider]
name = "echo"
description = "Test echo provider"
base_url = "http://127.0.0.1:9"

[[tools]]
name = "ping"
description = "ping"
endpoint = "/ping"
method = "GET"
"#,
    )
    .expect("write manifest");
    let registry = ManifestRegistry::load(&manifests_dir).expect("load manifest");
    // `ManifestRegistry::load` reads all TOML files synchronously into memory;
    // the registry holds no file handles into `dir`, so we can drop the
    // tempdir immediately rather than leaking it (Greptile P2 on #123).
    drop(dir);

    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();

    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring: Keyring::empty(),
        jwt_config: Some(jwt_config),
        jwks_json: None,
        auth_cache: AuthCache::new(),
        upstream_url_allowlists: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
    });
    build_router(state)
}

async fn call_with_token(app: axum::Router, token: &str) -> StatusCode {
    let body = serde_json::json!({"tool_name": "ping", "args": {}});
    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    app.oneshot(req).await.expect("oneshot").status()
}

/// Issue #121 — the core regression. With the proxy configured to accept
/// `parcha-custom-tools` audience, an inbound JWT for that audience must
/// pass validation. (Without #121, the proxy would reject it because the
/// JWT's `aud` doesn't match the proxy's single hardcoded audience.)
#[tokio::test]
async fn per_provider_audience_jwt_accepted_when_in_allowlist() {
    let app = build_app(multi_aud_config());
    let token = issue_test_token("parcha-custom-tools", "tool:ping");
    let status = call_with_token(app, &token).await;
    // The only thing we care about is that the JWT validation gate
    // passed — i.e. status is NOT 401 (auth-rejected) or 403 (scope-rejected).
    // The handler runs through to attempting the upstream call against
    // the unreachable 127.0.0.1:9, which produces a 502 Bad Gateway —
    // that's a SUCCESS for this test (proves auth let the request
    // through).
    assert_ne!(
        status,
        StatusCode::UNAUTHORIZED,
        "alt-audience JWT must pass the auth gate when in allowlist"
    );
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "alt-audience JWT with tool:ping scope must pass the scope gate"
    );
}

/// Pre-#121 behaviour: a proxy configured with only `ati-proxy` in its
/// audience allowlist MUST reject the alt-audience JWT. This is the bug
/// the fix exists to address — a regression here means we accidentally
/// reverted to permissive audience handling.
#[tokio::test]
async fn per_provider_audience_jwt_rejected_when_not_in_allowlist() {
    let app = build_app(single_aud_config());
    let token = issue_test_token("parcha-custom-tools", "tool:ping");
    let status = call_with_token(app, &token).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "JWT with aud=parcha-custom-tools must be rejected by a proxy whose \
         accepted_audiences = [\"ati-proxy\"]"
    );
}

/// Backwards-compat sanity: the existing `ati-proxy` audience flow keeps
/// working when the proxy is configured with the multi-audience allowlist.
/// A v0.7.x sandbox that has never heard of per-provider tokens must
/// continue to authenticate successfully against a #121-aware proxy.
#[tokio::test]
async fn default_audience_jwt_still_accepted_in_multi_aud_mode() {
    let app = build_app(multi_aud_config());
    let token = issue_test_token("ati-proxy", "tool:ping");
    let status = call_with_token(app, &token).await;
    // Same expectation shape as the alt-audience case: NOT a 401/403 —
    // the upstream call to 127.0.0.1:9 may 502, that's fine.
    assert_ne!(
        status,
        StatusCode::UNAUTHORIZED,
        "ati-proxy-aud JWT must still pass when allowlist contains it"
    );
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "ati-proxy-aud JWT with tool:ping scope must pass the scope gate"
    );
}

/// Negative: a JWT with an audience NOT in either allowlist scenario gets
/// rejected even when the allowlist has multiple entries. Proves we don't
/// silently accept-any-aud when the list is non-empty.
#[tokio::test]
async fn unknown_audience_rejected_under_multi_aud() {
    let app = build_app(multi_aud_config());
    let token = issue_test_token("evil-aud", "tool:ping");
    let status = call_with_token(app, &token).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "aud=evil-aud must be rejected; multi-audience mode is an allowlist, not a bypass"
    );
}

// -----------------------------------------------------------------------------
// Sandbox-side path: prove that a Provider with `auth_session_token_env` set
// causes the registry lookup to surface the override. Pure deserialization +
// lookup test — the wire-level forwarding is exercised at runtime by the
// /tmp/ati-e2e-121 harness.
// -----------------------------------------------------------------------------

#[test]
fn manifest_auth_session_token_env_field_round_trip() {
    let toml = r#"
[provider]
name = "parcha_custom_tools"
description = "MCP that needs a per-audience JWT"
base_url = ""
handler = "mcp"
auth_type = "bearer"
auth_session_token_env = "PARCHA_TOOLS_SESSION_TOKEN"

[[tools]]
name = "parcha_custom_tools:recall"
description = "stub"
endpoint = "/recall"
method = "GET"
"#;
    let dir = tempfile::tempdir().expect("tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("manifests dir");
    std::fs::write(manifests_dir.join("p.toml"), toml).expect("write");

    let registry =
        ati::core::manifest::ManifestRegistry::load(&manifests_dir).expect("load manifest");

    let (provider, _tool) = registry
        .get_tool("parcha_custom_tools:recall")
        .expect("tool resolves under provider:tool form");
    assert_eq!(
        provider.auth_session_token_env.as_deref(),
        Some("PARCHA_TOOLS_SESSION_TOKEN"),
        "manifest field must survive TOML → Provider deserialization"
    );
}

#[test]
fn manifest_without_auth_session_token_env_defaults_to_none() {
    // Regression: any existing v0.7.x manifest must keep deserializing
    // unchanged with the new field defaulting to None.
    let toml = r#"
[provider]
name = "echo"
description = "no per-provider token"
base_url = "http://example.test"

[[tools]]
name = "ping"
description = "stub"
endpoint = "/ping"
method = "GET"
"#;
    let dir = tempfile::tempdir().expect("tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("manifests dir");
    std::fs::write(manifests_dir.join("p.toml"), toml).expect("write");

    let registry =
        ati::core::manifest::ManifestRegistry::load(&manifests_dir).expect("load manifest");

    let (provider, _) = registry.get_tool("ping").expect("tool resolves");
    assert_eq!(
        provider.auth_session_token_env, None,
        "absent field must default to None — backwards compat guarantee"
    );
}
