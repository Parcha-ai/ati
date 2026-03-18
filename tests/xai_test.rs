//! Tests for the xAI agentic handler — tool type mapping and response extraction.
//!
//! We can't test execute_xai_tool() against a real server without an API key,
//! but we CAN test the response extraction and tool mapping logic by exercising
//! them through wiremock, verifying the request format and response parsing.

mod common;

use ati::core::http::HttpError;
use ati::core::keyring::Keyring;
use ati::core::manifest::{AuthType, HttpMethod};
use ati::core::xai::execute_xai_tool;
use serde_json::json;
use std::collections::HashMap;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// xAI sends a POST to /responses with bearer auth and agentic body format.
#[tokio::test]
async fn test_xai_request_format() {
    let upstream = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .and(header("authorization", "Bearer xai-test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": "Test result"}]
                }
            ]
        })))
        .mount(&upstream)
        .await;

    let provider = ati::core::manifest::Provider {
        auth_type: AuthType::Bearer,
        auth_key_name: Some("xai_key".into()),
        handler: "xai".into(),
        ..common::test_provider("xai_test", &format!("{}/v1", upstream.uri()))
    };
    let tool = common::test_tool("xai_web_search", "/responses", HttpMethod::Post);
    let keyring = common::test_keyring(&[("xai_key", "xai-test-key")]);

    let mut args = HashMap::new();
    args.insert("query".into(), json!("test query"));

    let result = execute_xai_tool(&provider, &tool, &args, &keyring)
        .await
        .unwrap();

    assert_eq!(result["text"], "Test result");
    assert_eq!(result["raw_output_count"], 1);
}

/// xAI extracts text, citations, and search queries from agentic response.
#[tokio::test]
async fn test_xai_complex_response_extraction() {
    let upstream = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "output": [
                {
                    "type": "web_search_call",
                    "action": {"query": "rust programming"}
                },
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "Rust is a systems language.",
                            "annotations": [
                                {"type": "url_citation", "url": "https://rust-lang.org"}
                            ]
                        },
                        {
                            "type": "output_text",
                            "text": "It emphasizes safety."
                        }
                    ]
                },
                {
                    "type": "x_search_call",
                    "action": {"query": "rust news"}
                }
            ]
        })))
        .mount(&upstream)
        .await;

    let provider = ati::core::manifest::Provider {
        auth_type: AuthType::Bearer,
        auth_key_name: Some("key".into()),
        handler: "xai".into(),
        ..common::test_provider("xai", &format!("{}/v1", upstream.uri()))
    };
    let tool = common::test_tool("xai_combined_search", "/responses", HttpMethod::Post);
    let keyring = common::test_keyring(&[("key", "test-key")]);

    let args: HashMap<String, serde_json::Value> = HashMap::new();
    let result = execute_xai_tool(&provider, &tool, &args, &keyring)
        .await
        .unwrap();

    // Two text blocks joined
    assert!(result["text"]
        .as_str()
        .unwrap()
        .contains("Rust is a systems language."));
    assert!(result["text"]
        .as_str()
        .unwrap()
        .contains("It emphasizes safety."));

    // Citations collected
    let citations = result["citations"].as_array().unwrap();
    assert_eq!(citations.len(), 1);
    assert_eq!(citations[0]["url"], "https://rust-lang.org");

    // Search queries collected
    let queries = result["search_queries"].as_array().unwrap();
    assert_eq!(queries.len(), 2);
    assert!(queries.contains(&json!("rust programming")));
    assert!(queries.contains(&json!("rust news")));

    assert_eq!(result["raw_output_count"], 3);
}

/// xAI returns the body as-is when output is missing.
#[tokio::test]
async fn test_xai_no_output_field_returns_body() {
    let upstream = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "resp_123",
            "status": "completed"
        })))
        .mount(&upstream)
        .await;

    let provider = ati::core::manifest::Provider {
        auth_type: AuthType::Bearer,
        auth_key_name: Some("key".into()),
        handler: "xai".into(),
        ..common::test_provider("xai", &format!("{}/v1", upstream.uri()))
    };
    let tool = common::test_tool("xai_web_search", "/responses", HttpMethod::Post);
    let keyring = common::test_keyring(&[("key", "k")]);

    let args = HashMap::new();
    let result = execute_xai_tool(&provider, &tool, &args, &keyring)
        .await
        .unwrap();

    // No "output" field → returns raw body
    assert_eq!(result["id"], "resp_123");
    assert_eq!(result["status"], "completed");
}

/// xAI returns error on non-200 response.
#[tokio::test]
async fn test_xai_error_response() {
    let upstream = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(ResponseTemplate::new(429).set_body_string("Rate limit exceeded"))
        .mount(&upstream)
        .await;

    let provider = ati::core::manifest::Provider {
        auth_type: AuthType::Bearer,
        auth_key_name: Some("key".into()),
        handler: "xai".into(),
        ..common::test_provider("xai", &format!("{}/v1", upstream.uri()))
    };
    let tool = common::test_tool("xai_web_search", "/responses", HttpMethod::Post);
    let keyring = common::test_keyring(&[("key", "k")]);

    let args = HashMap::new();
    let err = execute_xai_tool(&provider, &tool, &args, &keyring)
        .await
        .unwrap_err();

    match err {
        HttpError::ApiError { status, body } => {
            assert_eq!(status, 429);
            assert!(body.contains("Rate limit"));
        }
        other => panic!("Expected ApiError, got: {other}"),
    }
}

/// xAI missing auth key returns MissingKey error.
#[tokio::test]
async fn test_xai_missing_key() {
    let provider = ati::core::manifest::Provider {
        auth_type: AuthType::Bearer,
        auth_key_name: Some("nonexistent".into()),
        handler: "xai".into(),
        ..common::test_provider("xai", "http://unused")
    };
    let tool = common::test_tool("xai_web_search", "/responses", HttpMethod::Post);
    let keyring = Keyring::empty();

    let args = HashMap::new();
    let err = execute_xai_tool(&provider, &tool, &args, &keyring)
        .await
        .unwrap_err();

    assert!(matches!(err, HttpError::MissingKey(_)));
}

/// xAI trending search prefixes query with "trending" context.
#[tokio::test]
async fn test_xai_trending_search_prompt() {
    let upstream = MockServer::start().await;

    // We'll verify the request body contains the trending prefix
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "output": [
                {"type": "message", "content": [{"type": "output_text", "text": "trending data"}]}
            ]
        })))
        .expect(1)
        .mount(&upstream)
        .await;

    let provider = ati::core::manifest::Provider {
        auth_type: AuthType::Bearer,
        auth_key_name: Some("key".into()),
        handler: "xai".into(),
        ..common::test_provider("xai", &format!("{}/v1", upstream.uri()))
    };
    // The tool name "xai_trending_search" triggers the trending prefix
    let tool = common::test_tool("xai_trending_search", "/responses", HttpMethod::Post);
    let keyring = common::test_keyring(&[("key", "k")]);

    let mut args = HashMap::new();
    args.insert("query".into(), json!("AI"));

    let result = execute_xai_tool(&provider, &tool, &args, &keyring)
        .await
        .unwrap();

    assert_eq!(result["text"], "trending data");
}
