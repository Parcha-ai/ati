//! Proxy-side handler tests for `X-Ati-Upstream-Url` (issue #124).
//!
//! Exercises the six cases in `resolve_upstream_override`:
//!   1. Header absent + mcp_url_env absent → 200 (or 5xx from unreachable upstream)
//!   2. Header present + mcp_url_env absent → 400
//!   3. Header absent + mcp_url_env present → falls back to mcp_url
//!   4. Header present + mcp_url_env present + no allowlist → 403
//!   5. Header present + URL doesn't match allowlist → 403
//!   6. Header present + URL matches → dispatched to override URL
//!
//! Setup pattern mirrors `tests/per_provider_token_test.rs`: an axum
//! Router built from a `ProxyState` with hand-crafted manifests +
//! keyring entries, exercised via `tower::ServiceExt::oneshot`.
//!
//! End-to-end forwarding (sandbox subprocess → proxy → upstream
//! wiremock) lives in the runtime harness at `/tmp/ati-e2e-124/`.

use ati::core::auth_generator::AuthCache;
use ati::core::keyring::Keyring;
use ati::core::manifest::ManifestRegistry;
use ati::core::skill::SkillRegistry;
use ati::proxy::server::{build_router, ProxyState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;

/// Builds an axum Router with one MCP-handler provider:
///   - `with_env_var = true` → provider declares `mcp_url_env`
///   - `with_allowlist = Some(globs)` → keyring entry seeded
///   - Falls back to `mcp_url = "http://127.0.0.1:9/mcp"` (unreachable —
///     proves auth gating is what we're testing, not upstream success)
fn build_app(with_env_var: bool, with_allowlist: Option<&str>) -> axum::Router {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("manifests dir");

    let env_line = if with_env_var {
        r#"mcp_url_env = "PARCHA_TOOLS_MCP_URL""#
    } else {
        ""
    };
    let manifest = format!(
        r#"
[provider]
name = "parcha_tools"
description = "test"
handler = "mcp"
mcp_transport = "http"
mcp_url = "http://127.0.0.1:9/mcp"
{env_line}

# Explicit tool entry so /call's registry lookup succeeds. The actual
# MCP dispatch will fail to dial the unreachable upstream, which is
# fine — these tests assert the auth gate behaviour, not the dispatch
# success.
[[tools]]
name = "parcha_tools:foo"
description = "stub"
endpoint = "/foo"
method = "GET"
"#
    );
    std::fs::write(manifests_dir.join("p.toml"), &manifest).expect("write manifest");
    let registry = ManifestRegistry::load(&manifests_dir).expect("load manifest");
    drop(dir);

    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();

    // Keyring populated via env var dance so we exercise the same code path
    // operators use (`ATI_KEY_*` env). The Keyring::from_env scan reads
    // every ATI_KEY_* var at construction time.
    let keyring = if let Some(csv) = with_allowlist {
        std::env::set_var("ATI_KEY_PARCHA_TOOLS_ALLOWED_URLS", csv);
        let k = Keyring::from_env();
        std::env::remove_var("ATI_KEY_PARCHA_TOOLS_ALLOWED_URLS");
        k
    } else {
        std::env::remove_var("ATI_KEY_PARCHA_TOOLS_ALLOWED_URLS");
        Keyring::empty()
    };

    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring,
        jwt_config: None, // dev mode for these tests; not exercising JWT
        jwks_json: None,
        auth_cache: AuthCache::new(),
        db: ati::core::db::DbState::Disabled,
        passthrough: None,
        sig_verify: std::sync::Arc::new(
            ati::core::sig_verify::SigVerifyConfig::build(
                ati::core::sig_verify::SigVerifyMode::Log,
                60,
                ati::core::sig_verify::DEFAULT_EXEMPT_PATHS,
                &ati::core::keyring::Keyring::empty(),
            )
            .unwrap(),
        ),
        key_store: None,
        admin_token: None,
        upstream_url_allowlists: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
    });
    build_router(state)
}

async fn call_with_header(
    app: axum::Router,
    upstream_url: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({"tool_name": "parcha_tools:foo", "args": {}});
    let mut builder = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json");
    if let Some(u) = upstream_url {
        builder = builder.header("X-Ati-Upstream-Url", u);
    }
    let req = builder
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

// Case 2: header sent for a provider that doesn't accept it → 400 fail-loud.
#[tokio::test]
async fn header_without_mcp_url_env_returns_400() {
    let app = build_app(/* with_env_var */ false, /* allowlist */ None);
    let (status, body) = call_with_header(app, Some("https://parcha-tools.example.com/mcp")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let err = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        err.contains("does not declare mcp_url_env"),
        "expected fail-loud message; got: {err}"
    );
}

// Case 4: header sent, mcp_url_env declared, but no keyring allowlist → 403.
// Fail-closed: operator must opt in by setting ATI_KEY_<PROVIDER>_ALLOWED_URLS.
#[tokio::test]
async fn header_with_no_allowlist_returns_403() {
    let app = build_app(/* with_env_var */ true, /* allowlist */ None);
    let (status, body) = call_with_header(app, Some("https://parcha-tools.example.com/mcp")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let err = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        err.contains("no upstream URL allowlist"),
        "expected fail-closed message; got: {err}"
    );
}

// Case 5: header sent, allowlist present, but URL doesn't match → 403.
#[tokio::test]
async fn header_outside_allowlist_returns_403() {
    let app = build_app(
        /* with_env_var */ true,
        Some("https://parcha-tools-*.example.com/mcp"),
    );
    let (status, body) = call_with_header(app, Some("https://attacker.com/mcp")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let err = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        err.contains("not in provider 'parcha_tools's allowlist"),
        "expected allowlist message; got: {err}"
    );
}

// Greptile-flagged P1 regression: glob `*` MUST NOT cross URL path
// boundaries. Without `literal_separator(true)` on the GlobBuilder, a
// pattern like `https://parcha-tools-*` would match
// `https://parcha-tools-staging.evil.com/mcp` because `*` greedily
// swallows the rest of the string including the attacker host. This test
// pins the bypass closed: only same-segment matches allowed.
#[tokio::test]
async fn glob_star_must_not_cross_path_separator() {
    // Pattern intentionally LACKS the literal `.example.com/mcp` tail so
    // the bug, if present, would let a wildcard URL through.
    let app = build_app(/* with_env_var */ true, Some("https://parcha-tools-*"));
    // Attacker URL: starts with `parcha-tools-` (prefix match) but the rest
    // crosses a host boundary into evil.com. Vulnerable code would 200/502;
    // fixed code returns 403.
    let (status, _body) =
        call_with_header(app, Some("https://parcha-tools-staging.evil.com/mcp")).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "glob * must not match across `/` boundaries — \
         attacker URL got past the allowlist"
    );
}

// Same regression class, but the `*` in the path tries to swallow
// additional path segments. Pattern allows `/mcp` but not `/mcp/admin`.
#[tokio::test]
async fn glob_star_must_not_swallow_path_segments() {
    let app = build_app(
        /* with_env_var */ true,
        Some("https://parcha-tools.example.com/*"),
    );
    // The `*` matches only the first path segment; deeper paths must 403.
    let (status, _body) =
        call_with_header(app, Some("https://parcha-tools.example.com/mcp/admin")).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "glob * in path must not swallow additional segments"
    );
}

// Case 6: header sent, allowlist matches → request reaches mcp_client
// (which then errors trying to dial the unreachable URL). The proof the
// override took effect is that we DID NOT get a 400/403 — the request
// got past the auth gate.
#[tokio::test]
async fn header_inside_allowlist_passes_auth_gate() {
    let app = build_app(
        /* with_env_var */ true,
        Some("https://parcha-tools-*.example.com/mcp"),
    );
    let (status, _body) =
        call_with_header(app, Some("https://parcha-tools-staging.example.com/mcp")).await;
    assert_ne!(
        status,
        StatusCode::BAD_REQUEST,
        "allowed URL must pass case-2 gate"
    );
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "allowed URL must pass case-4/5 gate"
    );
    // The actual upstream dial fails (the URL is unreachable) — we just
    // care that auth let it through.
}

// Case 3: no header sent + mcp_url_env declared → falls back to provider.mcp_url.
// No 400/403 from the auth gate, then mcp_client uses the static manifest URL.
#[tokio::test]
async fn header_absent_falls_back_to_mcp_url() {
    let app = build_app(/* with_env_var */ true, /* allowlist */ None);
    let (status, _body) = call_with_header(app, None).await;
    assert_ne!(
        status,
        StatusCode::BAD_REQUEST,
        "no-header case must skip the auth gate"
    );
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "no-header case must skip the allowlist check"
    );
}

// Case 1: no header sent + no mcp_url_env declared → today's behaviour,
// proves backwards-compat. Provider's static mcp_url is used directly.
#[tokio::test]
async fn header_absent_no_mcp_url_env_works_as_today() {
    let app = build_app(/* with_env_var */ false, /* allowlist */ None);
    let (status, _body) = call_with_header(app, None).await;
    assert_ne!(
        status,
        StatusCode::BAD_REQUEST,
        "legacy path must not be 400'd"
    );
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "legacy path must not be 403'd"
    );
}
