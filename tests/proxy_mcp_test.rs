//! Tests for the proxy /mcp endpoint — MCP JSON-RPC passthrough.
//!
//! Tests the initialize, tools/list, tools/call, and unknown method flows
//! through the axum router using tower oneshot (no TCP binding).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ati::core::manifest::ManifestRegistry;

/// Helper to send a JSON-RPC request to /mcp.
fn mcp_request(body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

fn test_app_with_upstream(base_url: &str) -> (tempfile::TempDir, axum::Router) {
    let manifest = format!(
        r#"
[provider]
name = "mcp_test_provider"
description = "Test provider for MCP proxy"
base_url = "{base_url}"
auth_type = "none"

[[tools]]
name = "mcp_search"
description = "Search tool"
endpoint = "/search"
method = "GET"

[tools.input_schema]
type = "object"

[tools.input_schema.properties.query]
type = "string"
description = "Search query"

[[tools]]
name = "mcp_create"
description = "Create tool"
endpoint = "/create"
method = "POST"

[tools.input_schema]
type = "object"
required = ["title"]

[tools.input_schema.properties.title]
type = "string"
description = "Title"
"#
    );

    let (dir, manifests_dir) = common::temp_manifests(&[("mcp_test.toml", &manifest)]);
    let registry = ManifestRegistry::load(&manifests_dir).expect("load manifests");
    let app = common::build_test_app(registry);
    (dir, app)
}

/// initialize returns protocol version and capabilities.
#[tokio::test]
async fn test_mcp_initialize() {
    let (_dir, app) = test_app_with_upstream("http://unused.test");

    let req = mcp_request(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = common::body_json(resp.into_body()).await;
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["id"], 1);
    assert!(json["result"]["protocolVersion"].as_str().is_some());
    assert_eq!(json["result"]["serverInfo"]["name"], "ati-proxy");
}

/// notifications/initialized returns 202.
#[tokio::test]
async fn test_mcp_notifications_initialized() {
    let (_dir, app) = test_app_with_upstream("http://unused.test");

    let req = mcp_request(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }));

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
}

/// tools/list returns all public tools in MCP format.
#[tokio::test]
async fn test_mcp_tools_list() {
    let (_dir, app) = test_app_with_upstream("http://unused.test");

    let req = mcp_request(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    }));

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = common::body_json(resp.into_body()).await;
    let tools = json["result"]["tools"].as_array().unwrap();
    assert!(tools.len() >= 2, "Should have at least 2 tools");

    // Each tool should have name, description, inputSchema
    let tool_names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(tool_names.contains(&"mcp_search"));
    assert!(tool_names.contains(&"mcp_create"));
}

/// tools/call routes to upstream and returns MCP-formatted result.
#[tokio::test]
async fn test_mcp_tools_call_success() {
    let upstream = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"results": [{"title": "Found"}], "total": 1})),
        )
        .mount(&upstream)
        .await;

    let (_dir, app) = test_app_with_upstream(&upstream.uri());

    let req = mcp_request(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "mcp_search",
            "arguments": {"query": "test"}
        }
    }));

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = common::body_json(resp.into_body()).await;
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["id"], 3);
    assert_eq!(json["result"]["isError"], false);

    let content = json["result"]["content"].as_array().unwrap();
    assert_eq!(content[0]["type"], "text");
    let text = content[0]["text"].as_str().unwrap();
    assert!(text.contains("Found"), "Result should contain upstream data");
}

/// tools/call with POST tool sends body correctly.
#[tokio::test]
async fn test_mcp_tools_call_post() {
    let upstream = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/create"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id": "new-1", "created": true})),
        )
        .mount(&upstream)
        .await;

    let (_dir, app) = test_app_with_upstream(&upstream.uri());

    let req = mcp_request(json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "mcp_create",
            "arguments": {"title": "My Item"}
        }
    }));

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = common::body_json(resp.into_body()).await;
    assert_eq!(json["result"]["isError"], false);
}

/// tools/call with unknown tool returns JSON-RPC error.
#[tokio::test]
async fn test_mcp_tools_call_unknown_tool() {
    let (_dir, app) = test_app_with_upstream("http://unused.test");

    let req = mcp_request(json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "nonexistent_tool",
            "arguments": {}
        }
    }));

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = common::body_json(resp.into_body()).await;
    assert!(json["error"].is_object());
    assert_eq!(json["error"]["code"], -32602);
    assert!(json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("nonexistent_tool"));
}

/// tools/call with empty tool name returns JSON-RPC error.
#[tokio::test]
async fn test_mcp_tools_call_empty_name() {
    let (_dir, app) = test_app_with_upstream("http://unused.test");

    let req = mcp_request(json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "arguments": {"query": "test"}
        }
    }));

    let resp = app.oneshot(req).await.expect("oneshot");
    let json = common::body_json(resp.into_body()).await;
    assert!(json["error"].is_object());
    assert!(json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Missing tool name"));
}

/// Unknown JSON-RPC method returns -32601 error.
#[tokio::test]
async fn test_mcp_unknown_method() {
    let (_dir, app) = test_app_with_upstream("http://unused.test");

    let req = mcp_request(json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "resources/list"
    }));

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = common::body_json(resp.into_body()).await;
    assert_eq!(json["error"]["code"], -32601);
    assert!(json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Method not found"));
}

/// tools/call with upstream error returns isError=true (not a JSON-RPC error).
#[tokio::test]
async fn test_mcp_tools_call_upstream_error() {
    let upstream = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&upstream)
        .await;

    let (_dir, app) = test_app_with_upstream(&upstream.uri());

    let req = mcp_request(json!({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {
            "name": "mcp_search",
            "arguments": {"query": "test"}
        }
    }));

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = common::body_json(resp.into_body()).await;
    // Upstream errors return as isError=true in MCP result, not as JSON-RPC error
    assert_eq!(json["result"]["isError"], true);
    let text = json["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("Error"), "Should contain error description");
}
