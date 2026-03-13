//! Tests for auth generator error paths through execute_tool_with_gen.
//!
//! Exercises error scenarios that unit tests in auth_generator.rs don't cover:
//! timeout, non-zero exit, bad output format — all through the HTTP execution path.

mod common;

use ati::core::auth_generator::{AuthCache, GenContext};
use ati::core::http::execute_tool_with_gen;
use ati::core::keyring::Keyring;
use ati::core::manifest::{
    AuthGenType, AuthGenerator, AuthOutputFormat, AuthType, HttpMethod, InjectTarget,
};
use serde_json::json;
use std::collections::HashMap;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Auth generator that times out propagates through execute_tool_with_gen.
#[tokio::test]
async fn test_auth_gen_timeout_through_execution() {
    let upstream = MockServer::start().await;

    // Don't need to mount a mock — generator will fail before reaching upstream.
    let gen = AuthGenerator {
        gen_type: AuthGenType::Command,
        command: Some("sleep".into()),
        args: vec!["10".into()],
        interpreter: None,
        script: None,
        cache_ttl_secs: 0,
        output_format: AuthOutputFormat::Text,
        env: HashMap::new(),
        inject: HashMap::new(),
        timeout_secs: 1,
    };

    let provider = ati::core::manifest::Provider {
        auth_type: AuthType::Bearer,
        auth_generator: Some(gen),
        ..common::test_provider("timeout_test", &upstream.uri())
    };
    let tool = common::test_tool("timeout_tool", "/data", HttpMethod::Get);
    let keyring = Keyring::empty();
    let cache = AuthCache::new();
    let ctx = GenContext::default();

    let err = execute_tool_with_gen(&provider, &tool, &HashMap::new(), &keyring, Some(&ctx), Some(&cache))
        .await
        .unwrap_err();

    let msg = format!("{err}");
    assert!(
        msg.contains("timed out") || msg.contains("Timeout") || msg.contains("timeout"),
        "Expected timeout error, got: {msg}"
    );
}

/// Auth generator with non-zero exit propagates error.
#[tokio::test]
async fn test_auth_gen_nonzero_exit_through_execution() {
    let gen = AuthGenerator {
        gen_type: AuthGenType::Command,
        command: Some("false".into()),
        args: vec![],
        interpreter: None,
        script: None,
        cache_ttl_secs: 0,
        output_format: AuthOutputFormat::Text,
        env: HashMap::new(),
        inject: HashMap::new(),
        timeout_secs: 5,
    };

    let provider = ati::core::manifest::Provider {
        auth_type: AuthType::Bearer,
        auth_generator: Some(gen),
        ..common::test_provider("exit_test", "http://unused.test")
    };
    let tool = common::test_tool("exit_tool", "/data", HttpMethod::Get);
    let keyring = Keyring::empty();
    let cache = AuthCache::new();
    let ctx = GenContext::default();

    let err = execute_tool_with_gen(&provider, &tool, &HashMap::new(), &keyring, Some(&ctx), Some(&cache))
        .await
        .unwrap_err();

    let msg = format!("{err}");
    assert!(
        msg.contains("auth_generator") || msg.contains("exit"),
        "Expected non-zero exit error, got: {msg}"
    );
}

/// Auth generator with JSON output but invalid JSON fails gracefully.
#[tokio::test]
async fn test_auth_gen_invalid_json_output() {
    let gen = AuthGenerator {
        gen_type: AuthGenType::Command,
        command: Some("echo".into()),
        args: vec!["not-valid-json".into()],
        interpreter: None,
        script: None,
        cache_ttl_secs: 0,
        output_format: AuthOutputFormat::Json,
        env: HashMap::new(),
        inject: HashMap::new(),
        timeout_secs: 5,
    };

    let provider = ati::core::manifest::Provider {
        auth_type: AuthType::Bearer,
        auth_generator: Some(gen),
        ..common::test_provider("json_err_test", "http://unused.test")
    };
    let tool = common::test_tool("json_err_tool", "/data", HttpMethod::Get);
    let keyring = Keyring::empty();
    let cache = AuthCache::new();
    let ctx = GenContext::default();

    let err = execute_tool_with_gen(&provider, &tool, &HashMap::new(), &keyring, Some(&ctx), Some(&cache))
        .await
        .unwrap_err();

    let msg = format!("{err}");
    assert!(
        msg.contains("JSON") || msg.contains("parse"),
        "Expected JSON parse error, got: {msg}"
    );
}

/// Auth generator with JSON output and missing inject path fails.
#[tokio::test]
async fn test_auth_gen_missing_inject_path() {
    let mut inject = HashMap::new();
    inject.insert(
        "nonexistent.path".into(),
        InjectTarget {
            inject_type: "header".into(),
            name: "X-Token".into(),
        },
    );

    let gen = AuthGenerator {
        gen_type: AuthGenType::Command,
        command: Some("echo".into()),
        args: vec![r#"{"token":"abc"}"#.into()],
        interpreter: None,
        script: None,
        cache_ttl_secs: 0,
        output_format: AuthOutputFormat::Json,
        env: HashMap::new(),
        inject,
        timeout_secs: 5,
    };

    let provider = ati::core::manifest::Provider {
        auth_type: AuthType::Bearer,
        auth_generator: Some(gen),
        ..common::test_provider("inject_err_test", "http://unused.test")
    };
    let tool = common::test_tool("inject_err_tool", "/data", HttpMethod::Get);
    let keyring = Keyring::empty();
    let cache = AuthCache::new();
    let ctx = GenContext::default();

    let err = execute_tool_with_gen(&provider, &tool, &HashMap::new(), &keyring, Some(&ctx), Some(&cache))
        .await
        .unwrap_err();

    let msg = format!("{err}");
    assert!(
        msg.contains("nonexistent.path") || msg.contains("not found"),
        "Expected missing path error, got: {msg}"
    );
}

/// Script-type auth generator through execute_tool_with_gen.
#[tokio::test]
async fn test_auth_gen_script_type_through_execution() {
    let upstream = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/data"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&upstream)
        .await;

    let gen = AuthGenerator {
        gen_type: AuthGenType::Script,
        command: None,
        args: vec![],
        interpreter: Some("bash".into()),
        script: Some("echo script-generated-token".into()),
        cache_ttl_secs: 0,
        output_format: AuthOutputFormat::Text,
        env: HashMap::new(),
        inject: HashMap::new(),
        timeout_secs: 5,
    };

    let provider = ati::core::manifest::Provider {
        auth_type: AuthType::Bearer,
        auth_generator: Some(gen),
        ..common::test_provider("script_test", &upstream.uri())
    };
    let tool = common::test_tool("script_tool", "/data", HttpMethod::Get);
    let keyring = Keyring::empty();
    let cache = AuthCache::new();
    let ctx = GenContext::default();

    // We can't easily check the exact header wiremock received, but we can
    // verify the call succeeds (200 from upstream means auth was injected and
    // the request reached the mock — wiremock doesn't reject on unknown headers)
    let result = execute_tool_with_gen(&provider, &tool, &HashMap::new(), &keyring, Some(&ctx), Some(&cache))
        .await
        .expect("script generator should succeed");

    assert_eq!(result["ok"], true);
}

/// Auth generator with command that doesn't exist.
#[tokio::test]
async fn test_auth_gen_command_not_found() {
    let gen = AuthGenerator {
        gen_type: AuthGenType::Command,
        command: Some("ati_nonexistent_binary_12345".into()),
        args: vec![],
        interpreter: None,
        script: None,
        cache_ttl_secs: 0,
        output_format: AuthOutputFormat::Text,
        env: HashMap::new(),
        inject: HashMap::new(),
        timeout_secs: 5,
    };

    let provider = ati::core::manifest::Provider {
        auth_type: AuthType::Bearer,
        auth_generator: Some(gen),
        ..common::test_provider("notfound_test", "http://unused.test")
    };
    let tool = common::test_tool("notfound_tool", "/data", HttpMethod::Get);
    let keyring = Keyring::empty();
    let cache = AuthCache::new();
    let ctx = GenContext::default();

    let err = execute_tool_with_gen(&provider, &tool, &HashMap::new(), &keyring, Some(&ctx), Some(&cache))
        .await
        .unwrap_err();

    let msg = format!("{err}");
    assert!(
        msg.contains("auth_generator") || msg.contains("spawn") || msg.contains("No such file"),
        "Expected spawn error, got: {msg}"
    );
}

/// Auth generator with header auth_type injects via custom header.
#[tokio::test]
async fn test_auth_gen_header_auth_type() {
    let upstream = MockServer::start().await;

    use wiremock::matchers::header;
    Mock::given(method("GET"))
        .and(path("/data"))
        .and(header("X-Custom-Auth", "gen-header-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"auth": "header"})))
        .mount(&upstream)
        .await;

    let gen = common::test_auth_generator_command("gen-header-token");

    let provider = ati::core::manifest::Provider {
        auth_type: AuthType::Header,
        auth_header_name: Some("X-Custom-Auth".into()),
        auth_generator: Some(gen),
        ..common::test_provider("header_gen_test", &upstream.uri())
    };
    let tool = common::test_tool("header_gen_tool", "/data", HttpMethod::Get);
    let keyring = Keyring::empty();
    let cache = AuthCache::new();
    let ctx = GenContext::default();

    let result = execute_tool_with_gen(&provider, &tool, &HashMap::new(), &keyring, Some(&ctx), Some(&cache))
        .await
        .expect("header auth generator should succeed");

    assert_eq!(result["auth"], "header");
}
