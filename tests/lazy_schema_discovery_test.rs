//! Lazy `inputSchema` discovery for sandbox-supplied-URL MCP providers (issue #135).
//!
//! Setup: a wiremock server impersonates a Streamable HTTP MCP server.
//! It serves `initialize` (with capabilities.tools) and `tools/list`
//! (returning two tools — one with an `inputSchema`, one without — so
//! we can also check that the absent-schema case stays `null`). The
//! ATI proxy is wired with a single MCP provider that:
//!   - declares the upstream as `mcp_url_env = "..."` (sandbox-supplied)
//!   - statically declares both tool *names* in `[[tools]]` so the
//!     registry doesn't return 404 for them
//!   - omits `[tools.input_schema]` on both tools so we hit the issue #135 path
//!
//! Then we exercise `GET /tools/<name>` with `X-Ati-Upstream-Url`
//! pointing at the wiremock server and assert:
//!   1. The schema for the tool that has one upstream is merged in.
//!   2. The schema for the tool that has none upstream stays null.
//!   3. Repeated calls don't re-dial the upstream (cache hit).
//!   4. Without the `X-Ati-Upstream-Url` header, schema stays null
//!      (graceful fall-back; today's behavior).
//!   5. The MCP JSON-RPC `tools/list` path also returns the merged schema.
//!   6. A request that *misses* the allowlist falls back silently — never
//!      turns a 200 into a 403 (the REST acceptance criterion).

use ati::core::auth_generator::AuthCache;
use ati::core::keyring::Keyring;
use ati::core::manifest::ManifestRegistry;
use ati::core::skill::SkillRegistry;
use ati::proxy::server::{build_router, ProxyState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;
use wiremock::matchers::{body_partial_json, method as wm_method, path as wm_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Mount the three minimum MCP HTTP responses on a wiremock server so a
/// real `mcp_client::McpClient` can `initialize` → `tools/list` against it.
///
/// `tools_response` is the body to return for `tools/list`. The
/// initialize/notifications responses are fixed.
async fn mount_mcp_upstream(server: &MockServer, tools_response: serde_json::Value) {
    // initialize: must include capabilities.tools so the client's
    // NoToolsCapability check passes.
    Mock::given(wm_method("POST"))
        .and(wm_path("/mcp"))
        .and(body_partial_json(json!({"method": "initialize"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "stub", "version": "0.0.0"}
            }
        })))
        .mount(server)
        .await;

    // notifications/initialized: 202 Accepted, no body.
    Mock::given(wm_method("POST"))
        .and(wm_path("/mcp"))
        .and(body_partial_json(
            json!({"method": "notifications/initialized"}),
        ))
        .respond_with(ResponseTemplate::new(202))
        .mount(server)
        .await;

    // tools/list: the custom body provided by the caller.
    Mock::given(wm_method("POST"))
        .and(wm_path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(tools_response))
        .mount(server)
        .await;
}

/// Build an axum Router wired with the issue #135 manifest pattern:
/// MCP provider with `mcp_url_env`, two statically named tools (both
/// without `input_schema` so the lazy-discovery code path fires — the
/// upstream stub then decides which tools get a schema and which stay
/// null), and a hostname-glob allowlist that admits the wiremock
/// server's host.
fn build_app(upstream_host_glob: &str) -> axum::Router {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("manifests dir");

    let manifest = r#"
[provider]
name = "parcha_tools"
description = "test"
handler = "mcp"
mcp_transport = "http"
mcp_url = "http://127.0.0.1:9/mcp"
mcp_url_env = "PARCHA_TOOLS_MCP_URL"

# Tool names declared so the registry has them; input_schema omitted
# deliberately so the issue #135 lazy-discovery code path fires.
[[tools]]
name = "parcha_tools:has_schema"
description = "has schema upstream"
endpoint = "/has_schema"
method = "POST"

[[tools]]
name = "parcha_tools:no_schema"
description = "no schema upstream either"
endpoint = "/no_schema"
method = "POST"
"#;
    std::fs::write(manifests_dir.join("p.toml"), manifest).expect("write manifest");
    let registry = ManifestRegistry::load(&manifests_dir).expect("load manifest");
    drop(dir);

    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let keyring = {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("ATI_KEY_PARCHA_TOOLS_ALLOWED_URLS", upstream_host_glob);
        let k = Keyring::from_env();
        std::env::remove_var("ATI_KEY_PARCHA_TOOLS_ALLOWED_URLS");
        k
    };

    // 0.7 ProxyState has 8 fields (no db / passthrough / sig_verify /
    // key_store / admin_token — those are 0.8-only). The test file
    // shipped on main as part of #136 included those fields; the
    // backport strips them to match the 0.7 shape.
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring,
        jwt_config: None,
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

async fn get_tool_info(
    app: axum::Router,
    tool: &str,
    upstream_url: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method("GET")
        .uri(format!("/tools/{tool}"));
    if let Some(u) = upstream_url {
        builder = builder.header("X-Ati-Upstream-Url", u);
    }
    let req = builder.body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Standard wiremock-host glob that matches `127.0.0.1` (the four-label
/// form the wiremock server binds to). url::Url's parser doesn't accept
/// `*` as a port, so we use the literal host (port is irrelevant to the
/// per-label host matcher — `build_url_allowlist` only carries scheme +
/// host_labels + path). The wiremock URL's path is always `/mcp` so the
/// path matcher passes too.
const HOST_GLOB: &str = "http://127.0.0.1/mcp";

// ---------- Acceptance criterion (1) ----------
//
// `ati tool info <name>` (which the proxy serves via GET /tools/:name)
// returns the live inputSchema when the static entry has none and the
// request carries a valid X-Ati-Upstream-Url for the provider.
#[tokio::test]
async fn tool_info_merges_upstream_schema_when_static_is_none() {
    let upstream = MockServer::start().await;
    mount_mcp_upstream(
        &upstream,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [
                    {
                        "name": "parcha_tools:has_schema",
                        "description": "discovered description",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "doc_url": {"type": "string"}
                            },
                            "required": ["doc_url"]
                        }
                    }
                ]
            }
        }),
    )
    .await;

    let app = build_app(HOST_GLOB);
    let upstream_url = format!("{}/mcp", upstream.uri());
    let (status, body) =
        get_tool_info(app, "parcha_tools:has_schema", Some(upstream_url.as_str())).await;
    assert_eq!(status, StatusCode::OK);

    let schema = body
        .get("input_schema")
        .expect("response has input_schema field");
    assert!(
        !schema.is_null(),
        "input_schema should be merged from upstream tools/list, not null: {body:#}"
    );
    assert_eq!(
        schema.pointer("/properties/doc_url/type"),
        Some(&serde_json::Value::String("string".into())),
        "merged schema should match upstream's response: {schema:#}"
    );
}

// ---------- Acceptance criterion (2) ----------
//
// No regression: when no X-Ati-Upstream-Url header is sent, behavior is
// unchanged from today — the static null is returned. This is the
// graceful-degradation contract the issue body asks for ("Boot still
// succeeds when the upstream URL is unresolvable (falls back to the
// static entry / null, as today)").
#[tokio::test]
async fn tool_info_without_header_falls_back_to_static_null() {
    let app = build_app(HOST_GLOB);
    let (status, body) = get_tool_info(app, "parcha_tools:has_schema", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("input_schema")
            .map(|v| v.is_null())
            .unwrap_or(false),
        "without X-Ati-Upstream-Url, input_schema should stay null: {body:#}"
    );
}

// ---------- Negative case: tool not in upstream's tools/list response ----------
//
// The proxy declares two tools statically. The upstream's tools/list
// only ships a schema for one of them. The other one MUST keep its
// static `input_schema: null` — we don't fabricate schemas, and we
// don't fail the request.
#[tokio::test]
async fn tool_info_keeps_null_when_upstream_omits_the_tool() {
    let upstream = MockServer::start().await;
    mount_mcp_upstream(
        &upstream,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [
                    {
                        "name": "parcha_tools:has_schema",
                        "description": "the one with a schema",
                        "inputSchema": {"type": "object", "properties": {}}
                    }
                ]
            }
        }),
    )
    .await;

    let app = build_app(HOST_GLOB);
    let upstream_url = format!("{}/mcp", upstream.uri());
    let (status, body) =
        get_tool_info(app, "parcha_tools:no_schema", Some(upstream_url.as_str())).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("input_schema")
            .map(|v| v.is_null())
            .unwrap_or(false),
        "tool absent from upstream tools/list should keep static null: {body:#}"
    );
}

// ---------- Graceful fall-back when upstream URL is outside the allowlist ----------
//
// The REST handlers can't return 403 for an allowlist miss the way /call
// does — they MUST silently degrade to the static schema (null), so a
// misconfigured sandbox can't turn a working `ati tool info` into a
// permission denied page.
#[tokio::test]
async fn tool_info_silently_falls_back_when_url_outside_allowlist() {
    let upstream = MockServer::start().await;
    mount_mcp_upstream(
        &upstream,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [
                    {
                        "name": "parcha_tools:has_schema",
                        "description": "",
                        "inputSchema": {"type": "object"}
                    }
                ]
            }
        }),
    )
    .await;

    // Allowlist that does NOT match localhost. The sandbox-supplied URL
    // is outside it → resolve_upstream_override rejects it → the REST
    // handler treats it as "no URL" and returns the static null. Status
    // stays 200; no 4xx surfaces.
    let app = build_app("https://elsewhere.example.com/mcp");
    let upstream_url = format!("{}/mcp", upstream.uri());
    let (status, body) =
        get_tool_info(app, "parcha_tools:has_schema", Some(upstream_url.as_str())).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "allowlist miss must NOT surface as 4xx on tool-info: {body:#}"
    );
    assert!(
        body.get("input_schema")
            .map(|v| v.is_null())
            .unwrap_or(false),
        "allowlist miss must fall back to static null: {body:#}"
    );
}

// ---------- Caching: repeated GET /tools/:name doesn't re-dial upstream ----------
//
// The cache is keyed (provider, upstream_url). Two consecutive requests
// for tools on the same (provider, url) MUST trigger exactly ONE
// tools/list against the upstream — the second one is served from cache.
#[tokio::test]
async fn lazy_schema_cache_avoids_redundant_upstream_calls() {
    let upstream = MockServer::start().await;
    mount_mcp_upstream(
        &upstream,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [
                    {
                        "name": "parcha_tools:has_schema",
                        "description": "",
                        "inputSchema": {"type": "object"}
                    }
                ]
            }
        }),
    )
    .await;

    let app = build_app(HOST_GLOB);
    let upstream_url = format!("{}/mcp", upstream.uri());

    // Fire two requests against the same URL on the same proxy state.
    let (s1, _b1) = get_tool_info(
        app.clone(),
        "parcha_tools:has_schema",
        Some(upstream_url.as_str()),
    )
    .await;
    let (s2, _b2) = get_tool_info(
        app.clone(),
        "parcha_tools:has_schema",
        Some(upstream_url.as_str()),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::OK);

    // Count how many tools/list requests the upstream actually received.
    // We don't pin to exactly 1 because the cache lives on `ProxyState`,
    // not on `axum::Router`. Each `build_router(state)` clone shares the
    // same Arc<ProxyState>, so requests on the same app instance share
    // the cache. But the initialize handshake doubles the request count,
    // so we assert "fewer than 2 * number-of-requests" — the cache MUST
    // have prevented at least one full handshake-and-list round trip.
    let received: Vec<_> = upstream.received_requests().await.unwrap_or_default();
    let tools_list_count = received
        .iter()
        .filter(|r| {
            let s = std::str::from_utf8(&r.body).unwrap_or("");
            s.contains("\"tools/list\"")
        })
        .count();
    assert!(
        tools_list_count <= 1,
        "expected at most 1 upstream tools/list (cache hit on 2nd call); saw {tools_list_count}: {received:?}"
    );
}

// ---------- Greptile #136: per-request batching short-circuits siblings ----------
//
// `GET /tools` lists multiple tools. For a single MCP provider with N
// tools all needing lazy schemas, the proxy MUST dial the upstream
// AT MOST ONCE per request — every sibling tool after the first should
// short-circuit on `schemas_by_provider.contains_key(...)`. This is
// true on both the success path (positive map cached) and the failure
// path (empty-map sentinel cached); we test the success path here.
#[tokio::test]
async fn tools_list_batches_one_dial_per_provider_per_request() {
    let upstream = MockServer::start().await;
    mount_mcp_upstream(
        &upstream,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [
                    {
                        "name": "parcha_tools:has_schema",
                        "description": "",
                        "inputSchema": {"type": "object"}
                    },
                    {
                        "name": "parcha_tools:no_schema",
                        "description": "",
                        "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}}
                    }
                ]
            }
        }),
    )
    .await;

    let app = build_app(HOST_GLOB);
    let upstream_url = format!("{}/mcp", upstream.uri());

    // One GET /tools, two tools needing lazy schemas, same provider.
    let req = Request::builder()
        .method("GET")
        .uri("/tools")
        .header("X-Ati-Upstream-Url", &upstream_url)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    // Exactly one upstream tools/list — the second tool short-circuits on
    // the batched provider entry, not on the negative-result cache that
    // fires only across requests.
    let received: Vec<_> = upstream.received_requests().await.unwrap_or_default();
    let tools_list_count = received
        .iter()
        .filter(|r| {
            let s = std::str::from_utf8(&r.body).unwrap_or("");
            s.contains("\"tools/list\"")
        })
        .count();
    assert_eq!(
        tools_list_count, 1,
        "expected exactly 1 upstream tools/list for a 2-tool provider in one GET /tools; saw {tools_list_count}"
    );
}

// ---------- MCP JSON-RPC tools/list path also merges schemas ----------
//
// Agents typically hit POST /mcp tools/list, not GET /tools. The lazy
// discovery applies there too. This test exercises the JSON-RPC arm
// directly to keep both surfaces honest.
#[tokio::test]
async fn mcp_tools_list_merges_upstream_schema() {
    let upstream = MockServer::start().await;
    mount_mcp_upstream(
        &upstream,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [
                    {
                        "name": "parcha_tools:has_schema",
                        "description": "discovered",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"doc_url": {"type": "string"}}
                        }
                    }
                ]
            }
        }),
    )
    .await;

    let app = build_app(HOST_GLOB);
    let upstream_url = format!("{}/mcp", upstream.uri());

    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("X-Ati-Upstream-Url", &upstream_url)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    let tools = json
        .pointer("/result/tools")
        .and_then(|v| v.as_array())
        .expect("tools array in response");
    let has = tools
        .iter()
        .find(|t| t.get("name").and_then(|v| v.as_str()) == Some("parcha_tools:has_schema"))
        .expect("has_schema tool in response");
    let schema = has.get("inputSchema").expect("inputSchema field");
    assert_eq!(
        schema.pointer("/properties/doc_url/type"),
        Some(&serde_json::Value::String("string".into())),
        "MCP tools/list should serve the lazily-discovered schema: {schema:#}"
    );
}
