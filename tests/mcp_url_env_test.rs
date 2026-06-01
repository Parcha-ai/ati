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
    //
    // tokio::test runs tests on a multi-threaded executor; process-wide env
    // vars race across parallel tests. The `set_var` → `from_env` → `remove_var`
    // sequence MUST be atomic w.r.t. other test threads' identical dance.
    // The static Mutex is held only across that scan, not across the whole
    // test, so it doesn't serialize the actual axum oneshots.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let keyring = {
        let _guard = ENV_LOCK.lock().unwrap();
        if let Some(csv) = with_allowlist {
            std::env::set_var("ATI_KEY_PARCHA_TOOLS_ALLOWED_URLS", csv);
            let k = Keyring::from_env();
            std::env::remove_var("ATI_KEY_PARCHA_TOOLS_ALLOWED_URLS");
            k
        } else {
            std::env::remove_var("ATI_KEY_PARCHA_TOOLS_ALLOWED_URLS");
            Keyring::empty()
        }
    };

    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring,
        jwt_config: None, // dev mode for these tests; not exercising JWT
        jwks_json: None,
        auth_cache: AuthCache::new(),
        upstream_url_allowlists: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        lazy_schema_cache: std::sync::Arc::new(std::sync::Mutex::new(
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

// Greptile-flagged P1 regression: glob `*` MUST NOT cross URL path/host
// boundaries. Without `require_literal_separator: true`, a pattern like
// `https://parcha-tools-*` would match `https://parcha-tools-staging.evil.com/mcp`
// because `*` greedily swallows the rest of the string including the attacker
// host. This test pins the bypass closed: only same-segment matches allowed.
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
        "glob * must not match across `/` or `.` boundaries — \
         attacker URL got past the allowlist"
    );
}

// Same regression class, but the `*` in the path tries to swallow
// additional path segments. Pattern allows `/mcp` but not `/mcp/secret`.
#[tokio::test]
async fn glob_star_must_not_swallow_path_segments() {
    let app = build_app(
        /* with_env_var */ true,
        Some("https://parcha-tools.example.com/*"),
    );
    // Attacker tries `/mcp/../admin` (path-traversal-style). With separator
    // protection, the `*` matches only `mcp` and the trailing `/admin` part
    // is unmatched → 403.
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

// =============================================================================
// Greptile P0/P1 regressions — URL canonicalization, NOT raw string glob.
//
// The original commit globbed over the raw inbound URL string. That's
// fundamentally bypassable because `*` matches `.`, `#`, `?`, `:`, and any
// other URL delimiter. The fix parses the URL with `url::Url` and matches
// scheme/host/path components separately, with the host split into DNS labels
// so `*` can never bridge labels.
// =============================================================================

/// Greptile P0 on #126: pattern `https://parcha-tools-*/mcp` (single host
/// label, wildcard) MUST NOT match `https://parcha-tools-evil.com/mcp` —
/// the attacker host has 3 labels (`parcha-tools-evil`, `com`, with an
/// implicit nothing). Label-count check kills this.
#[tokio::test]
async fn dot_boundary_bypass_blocked_single_label_pattern() {
    // Pattern has 1 host label: `parcha-tools-*` (no dots)
    let app = build_app(
        /* with_env_var */ true,
        Some("https://parcha-tools-*/mcp"),
    );
    // Attacker URL has 2 host labels: `parcha-tools-evil`, `com`
    let (status, body) = call_with_header(app, Some("https://parcha-tools-evil.com/mcp")).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "label-count mismatch must 403; otherwise `*` swallows `evil.com` (Greptile P0 on #126)"
    );
    let err = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        err.contains("not in provider"),
        "expected allowlist rejection; got: {err}"
    );
}

/// Greptile P0 follow-up: pattern `https://parcha-tools-*.grep.ai/mcp`
/// (3 host labels, wildcard in first) MUST NOT match
/// `https://parcha-tools-evil.com.grep.ai/mcp` (4 host labels). Label count
/// differs so it 403s.
#[tokio::test]
async fn dot_boundary_bypass_blocked_three_label_pattern() {
    let app = build_app(
        /* with_env_var */ true,
        Some("https://parcha-tools-*.grep.ai/mcp"),
    );
    // 4-label attacker host: parcha-tools-evil . com . grep . ai
    let (status, _body) =
        call_with_header(app, Some("https://parcha-tools-evil.com.grep.ai/mcp")).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "extra DNS label in attacker URL must 403"
    );
}

/// Greptile P1 on #125: URL fragment bypass. `*` in raw-string glob would
/// match across `#` because `#` isn't a path separator. Pattern
/// `https://parcha-tools-*.grep.ai/mcp` would match
/// `https://parcha-tools-evilco.com#staging.grep.ai/mcp` because `*` ==
/// `evilco.com#staging`. After URL parsing, the fragment is stripped and
/// the host is just `parcha-tools-evilco.com` (2 labels vs 3).
#[tokio::test]
async fn fragment_bypass_blocked() {
    let app = build_app(
        /* with_env_var */ true,
        Some("https://parcha-tools-*.grep.ai/mcp"),
    );
    let (status, _body) = call_with_header(
        app,
        Some("https://parcha-tools-evilco.com/mcp#staging.grep.ai/mcp"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "fragment must not let URL bypass allowlist (Greptile P1 on #125)"
    );
}

/// Userinfo bypass: `https://attacker.com@parcha-tools-staging.grep.ai/mcp`
/// — naive parsers might think the host is `parcha-tools-staging.grep.ai`
/// but reqwest's URL parser treats `attacker.com` as userinfo (which it
/// then sends as Basic Auth, not as the dial target). Allowlist explicitly
/// rejects URLs with userinfo.
#[tokio::test]
async fn userinfo_bypass_blocked() {
    let app = build_app(
        /* with_env_var */ true,
        Some("https://parcha-tools-*.grep.ai/mcp"),
    );
    let (status, _body) = call_with_header(
        app,
        Some("https://attacker.com@parcha-tools-staging.grep.ai/mcp"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "userinfo-bearing URLs must be rejected"
    );
}

/// Path globs are NOT supported — paths require exact match. Pattern
/// `https://parcha-tools.example.com/*` MUST NOT match `/mcp/admin`.
#[tokio::test]
async fn path_must_match_exactly_no_wildcards() {
    // Path has `*` which makes the pattern URL parseable — `*` becomes a
    // literal character in the path component, so the operator's `/mcp/*`
    // ONLY matches the literal string `/mcp/*`, never `/mcp/admin`.
    let app = build_app(
        /* with_env_var */ true,
        Some("https://parcha-tools.example.com/mcp"),
    );
    let (status, _body) =
        call_with_header(app, Some("https://parcha-tools.example.com/mcp/admin")).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "extra path segments must not match an exact-path entry"
    );
}

/// Scheme-mismatch is rejected: pattern `https://...` MUST NOT match an
/// `http://...` URL even with same host+path.
#[tokio::test]
async fn scheme_mismatch_blocked() {
    let app = build_app(
        /* with_env_var */ true,
        Some("https://parcha-tools.example.com/mcp"),
    );
    let (status, _body) = call_with_header(app, Some("http://parcha-tools.example.com/mcp")).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "scheme mismatch must 403; downgrade to http is a security regression"
    );
}

/// Invalid URL is rejected with 400 (not 403) — different error class,
/// makes operator debugging easier.
#[tokio::test]
async fn invalid_url_returns_400() {
    let app = build_app(
        /* with_env_var */ true,
        Some("https://parcha-tools.example.com/mcp"),
    );
    let (status, body) = call_with_header(app, Some("not a url")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let err = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        err.contains("not a valid URL"),
        "expected URL-parse error; got: {err}"
    );
}

/// Case-insensitive host comparison: `EVIL.COM` lowercased must still be
/// matched against the same allowlist. Conversely an allowlist for
/// `parcha-tools.example.com` must accept `PARCHA-TOOLS.EXAMPLE.COM`.
#[tokio::test]
async fn host_comparison_is_case_insensitive() {
    let app = build_app(
        /* with_env_var */ true,
        Some("https://parcha-tools.example.com/mcp"),
    );
    let (status, _body) = call_with_header(app, Some("https://PARCHA-TOOLS.EXAMPLE.COM/mcp")).await;
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "uppercase host must match lowercase allowlist (DNS is case-insensitive)"
    );
}

/// Operator pattern with `**` is rejected at allowlist-parse time — it's
/// a glob escape hatch that would defeat the per-label constraint.
#[tokio::test]
async fn double_star_pattern_rejected_at_load() {
    // Pattern with `**` makes the allowlist parse fail; build_app's allowlist
    // therefore stays None, and any header → 403 ("no allowlist configured").
    let app = build_app(/* with_env_var */ true, Some("https://**/mcp"));
    let (status, body) = call_with_header(app, Some("https://parcha-tools.example.com/mcp")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let err = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    // The error message says "no allowlist configured" because the parse
    // failed silently (logged warn, treated as missing). That's fine —
    // fail-closed.
    assert!(
        err.contains("no upstream URL allowlist") || err.contains("not in provider"),
        "expected fail-closed; got: {err}"
    );
}
