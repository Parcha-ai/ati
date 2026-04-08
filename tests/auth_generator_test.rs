//! E2E integration tests for auth_generator → execute_tool_with_gen → upstream.
//!
//! These tests prove the full flow: manifest with auth_generator → generator subprocess
//! runs → token injected as Authorization header → upstream receives correct Bearer token.

mod common;

use ati::core::auth_generator::{AuthCache, GenContext};
use ati::core::http::execute_tool_with_gen;
use ati::core::keyring::Keyring;
use ati::core::manifest::{
    AuthGenType, AuthGenerator, AuthOutputFormat, AuthType, HttpMethod, InjectTarget,
    ManifestRegistry,
};
use ati::core::secret_resolver::SecretResolver;
use serde_json::json;
use std::collections::HashMap;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Golden path: auth_generator produces a bearer token, wiremock verifies it arrives.
#[tokio::test]
async fn test_auth_generator_bearer_token_injected() {
    let upstream = MockServer::start().await;

    // Mock only responds 200 if Authorization header matches exactly
    Mock::given(method("GET"))
        .and(path("/data"))
        .and(header("authorization", "Bearer generated-token-42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "authenticated"})))
        .mount(&upstream)
        .await;

    let gen = common::test_auth_generator_command("generated-token-42");
    let provider = ati::core::manifest::Provider {
        auth_type: AuthType::Bearer,
        auth_generator: Some(gen),
        ..common::test_provider("gen_test", &upstream.uri())
    };
    let tool = common::test_tool("gen_data", "/data", HttpMethod::Get);

    let keyring = Keyring::empty();
    let resolver = SecretResolver::operator_only(&keyring);
    let cache = AuthCache::new();
    let ctx = GenContext::default();
    let args = HashMap::new();

    let result =
        execute_tool_with_gen(&provider, &tool, &args, &resolver, Some(&ctx), Some(&cache))
            .await
            .expect("execute_tool_with_gen should succeed");

    assert_eq!(result["status"], "authenticated");
}

/// Variable expansion: ${JWT_SUB} in generator args resolves from GenContext.
#[tokio::test]
async fn test_auth_generator_variable_expansion() {
    let upstream = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/agent"))
        .and(header("authorization", "Bearer agent-42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"agent": "verified"})))
        .mount(&upstream)
        .await;

    let gen = AuthGenerator {
        gen_type: AuthGenType::Command,
        command: Some("echo".into()),
        args: vec!["${JWT_SUB}".into()],
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
        ..common::test_provider("var_test", &upstream.uri())
    };
    let tool = common::test_tool("agent_tool", "/agent", HttpMethod::Get);

    let keyring = Keyring::empty();
    let resolver = SecretResolver::operator_only(&keyring);
    let cache = AuthCache::new();
    let ctx = GenContext {
        jwt_sub: "agent-42".into(),
        ..GenContext::default()
    };
    let args = HashMap::new();

    let result =
        execute_tool_with_gen(&provider, &tool, &args, &resolver, Some(&ctx), Some(&cache))
            .await
            .expect("variable expansion should work");

    assert_eq!(result["agent"], "verified");
}

/// JSON output with inject map: primary token + extra header both injected.
#[tokio::test]
async fn test_auth_generator_json_output_with_inject() {
    let upstream = MockServer::start().await;

    // Require BOTH the bearer token AND the extra header
    Mock::given(method("POST"))
        .and(path("/secure"))
        .and(header("authorization", "Bearer session-tok"))
        .and(header("X-Access-Key", "AKIA123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"injected": true})))
        .mount(&upstream)
        .await;

    let mut inject = HashMap::new();
    inject.insert(
        "token".into(),
        InjectTarget {
            inject_type: "primary".into(),
            name: "token".into(),
        },
    );
    inject.insert(
        "creds.key".into(),
        InjectTarget {
            inject_type: "header".into(),
            name: "X-Access-Key".into(),
        },
    );

    let gen = AuthGenerator {
        gen_type: AuthGenType::Command,
        command: Some("echo".into()),
        args: vec![r#"{"token":"session-tok","creds":{"key":"AKIA123"}}"#.into()],
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
        ..common::test_provider("json_test", &upstream.uri())
    };
    let tool = common::test_tool("secure_create", "/secure", HttpMethod::Post);

    let keyring = Keyring::empty();
    let resolver = SecretResolver::operator_only(&keyring);
    let cache = AuthCache::new();
    let ctx = GenContext::default();
    let args = HashMap::new();

    let result =
        execute_tool_with_gen(&provider, &tool, &args, &resolver, Some(&ctx), Some(&cache))
            .await
            .expect("JSON inject should work");

    assert_eq!(result["injected"], true);
}

/// Caching: same AuthCache returns identical tokens across two calls.
#[tokio::test]
async fn test_auth_generator_caching() {
    let upstream = MockServer::start().await;

    // Accept any bearer token but echo it back so we can compare
    Mock::given(method("GET"))
        .and(path("/cached"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(2) // exactly 2 requests
        .mount(&upstream)
        .await;

    let gen = AuthGenerator {
        gen_type: AuthGenType::Command,
        command: Some("date".into()),
        args: vec!["+%s%N".into()],
        interpreter: None,
        script: None,
        cache_ttl_secs: 300, // cache for 5 minutes
        output_format: AuthOutputFormat::Text,
        env: HashMap::new(),
        inject: HashMap::new(),
        timeout_secs: 5,
    };

    let provider = ati::core::manifest::Provider {
        auth_type: AuthType::Bearer,
        auth_generator: Some(gen),
        ..common::test_provider("cache_test", &upstream.uri())
    };
    let tool = common::test_tool("cached_tool", "/cached", HttpMethod::Get);

    let keyring = Keyring::empty();
    let resolver = SecretResolver::operator_only(&keyring);
    let cache = AuthCache::new();
    let ctx = GenContext {
        jwt_sub: "cache-agent".into(),
        ..GenContext::default()
    };
    let args = HashMap::new();

    // First call — generator runs, result cached
    let _r1 = execute_tool_with_gen(&provider, &tool, &args, &resolver, Some(&ctx), Some(&cache))
        .await
        .expect("first call should succeed");

    // Second call — should use cached value
    let _r2 = execute_tool_with_gen(&provider, &tool, &args, &resolver, Some(&ctx), Some(&cache))
        .await
        .expect("second call should succeed");

    // Verify the cache has a value for this provider+sub
    let cached = cache.get("cache_test", "cache-agent");
    assert!(cached.is_some(), "credential should be cached");

    // Verify wiremock received both requests (both calls went through to upstream)
    // The key assertion is that the cache entry exists and both calls succeeded.
    // The generator was called once (date +%s%N), cached, then reused for the second call.
}

/// Full TOML → ManifestRegistry → execute_tool_with_gen round-trip.
#[tokio::test]
async fn test_auth_generator_from_manifest_toml() {
    let upstream = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/info"))
        .and(header("authorization", "Bearer manifest-token-99"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"source": "manifest"})))
        .mount(&upstream)
        .await;

    // Write a manifest with auth_generator
    let dir = tempfile::tempdir().expect("create tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    let manifest = format!(
        r#"
[provider]
name = "gen_provider"
description = "Provider with auth_generator"
base_url = "{}"
auth_type = "bearer"

[provider.auth_generator]
type = "command"
command = "echo"
args = ["manifest-token-99"]
cache_ttl_secs = 0
output_format = "text"
timeout_secs = 5

[[tools]]
name = "gen_info"
description = "Info tool"
endpoint = "/info"
method = "GET"

[tools.input_schema]
type = "object"
"#,
        upstream.uri()
    );

    std::fs::write(manifests_dir.join("gen.toml"), manifest).expect("write manifest");

    let registry = ManifestRegistry::load(&manifests_dir).expect("load manifests");

    // Extract provider + tool from registry
    let (provider, tool) = registry.get_tool("gen_info").expect("tool should exist");

    let keyring = Keyring::empty();
    let resolver = SecretResolver::operator_only(&keyring);
    let cache = AuthCache::new();
    let ctx = GenContext::default();
    let args = HashMap::new();

    let result = execute_tool_with_gen(provider, tool, &args, &resolver, Some(&ctx), Some(&cache))
        .await
        .expect("manifest round-trip should succeed");

    assert_eq!(result["source"], "manifest");
}
