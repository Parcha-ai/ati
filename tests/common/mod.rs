#![allow(dead_code)]
//! Shared test helpers for ATI integration tests.
//!
//! Provides reusable builders that eliminate 30+ lines of Provider/Tool boilerplate.
//!
//! # Usage
//! ```ignore
//! // Override only the fields you care about:
//! let provider = Provider {
//!     auth_type: AuthType::Bearer,
//!     auth_generator: Some(gen),
//!     ..common::test_provider("test", &server.uri())
//! };
//!
//! // Or use a variant builder:
//! let provider = common::test_provider_bearer("test", &server.uri(), "my_key");
//!
//! // Quick manifest directories:
//! let (_dir, manifests_dir) = common::temp_manifests(&[("test.toml", &toml_content)]);
//! ```

use ati::core::auth_generator::AuthCache;
use ati::core::jwt::{self, AtiNamespace, JwtConfig, TokenClaims};
use ati::core::keyring::Keyring;
use ati::core::manifest::{
    AuthGenType, AuthGenerator, AuthOutputFormat, AuthType, HttpMethod, ManifestRegistry, Provider,
    Tool,
};
use ati::core::skill::SkillRegistry;
use ati::proxy::server::{build_router, ProxyState};
use axum::body::Body;
use http_body_util::BodyExt;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Provider builders
// ---------------------------------------------------------------------------

/// Returns a Provider with sensible defaults. Override fields via struct update syntax.
pub fn test_provider(name: &str, base_url: &str) -> Provider {
    Provider {
        name: name.into(),
        description: format!("{name} test provider"),
        base_url: base_url.into(),
        auth_type: AuthType::None,
        auth_key_name: None,
        auth_header_name: None,
        auth_query_name: None,
        auth_value_prefix: None,
        extra_headers: HashMap::new(),
        oauth2_token_url: None,
        auth_secret_name: None,
        oauth2_basic_auth: false,
        internal: false,
        handler: "http".into(),
        mcp_transport: None,
        mcp_command: None,
        mcp_args: vec![],
        mcp_url: None,
        mcp_env: HashMap::new(),
        cli_command: None,
        cli_default_args: vec![],
        cli_env: HashMap::new(),
        cli_timeout_secs: None,
        cli_output_args: Vec::new(),
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

/// Provider with bearer auth and an auth_key_name.
pub fn test_provider_bearer(name: &str, base_url: &str, key_name: &str) -> Provider {
    Provider {
        auth_type: AuthType::Bearer,
        auth_key_name: Some(key_name.into()),
        ..test_provider(name, base_url)
    }
}

/// Provider with OAuth2 auth.
pub fn test_provider_oauth2(
    name: &str,
    base_url: &str,
    key_name: &str,
    secret_name: &str,
    token_url: &str,
) -> Provider {
    Provider {
        auth_type: AuthType::Oauth2,
        auth_key_name: Some(key_name.into()),
        auth_secret_name: Some(secret_name.into()),
        oauth2_token_url: Some(token_url.into()),
        ..test_provider(name, base_url)
    }
}

/// Provider configured as a CLI handler.
#[allow(dead_code)]
pub fn test_provider_cli(name: &str, command: &str) -> Provider {
    Provider {
        handler: "cli".into(),
        cli_command: Some(command.into()),
        ..test_provider(name, "")
    }
}

// ---------------------------------------------------------------------------
// Tool builders
// ---------------------------------------------------------------------------

/// Returns a Tool with empty defaults.
pub fn test_tool(name: &str, endpoint: &str, method: HttpMethod) -> Tool {
    Tool {
        name: name.into(),
        description: format!("{name} test tool"),
        endpoint: endpoint.into(),
        method,
        scope: None,
        input_schema: None,
        response: None,
        tags: vec![],
        hint: None,
        examples: vec![],
    }
}

/// Returns a Tool with an input schema.
pub fn test_tool_with_schema(
    name: &str,
    endpoint: &str,
    method: HttpMethod,
    schema: Value,
) -> Tool {
    Tool {
        input_schema: Some(schema),
        ..test_tool(name, endpoint, method)
    }
}

// ---------------------------------------------------------------------------
// AuthGenerator builders
// ---------------------------------------------------------------------------

/// Returns an AuthGenerator that runs `echo <token>` with text output, 0 TTL.
pub fn test_auth_generator_command(token: &str) -> AuthGenerator {
    AuthGenerator {
        gen_type: AuthGenType::Command,
        command: Some("echo".into()),
        args: vec![token.into()],
        interpreter: None,
        script: None,
        cache_ttl_secs: 0,
        output_format: AuthOutputFormat::Text,
        env: HashMap::new(),
        inject: HashMap::new(),
        timeout_secs: 5,
    }
}

// ---------------------------------------------------------------------------
// Keyring builders
// ---------------------------------------------------------------------------

/// Keyring with specified key-value pairs, backed by a plaintext JSON credentials file.
pub fn test_keyring(pairs: &[(&str, &str)]) -> Keyring {
    let dir = tempfile::TempDir::new().expect("create tempdir");
    let creds: HashMap<&str, &str> = pairs.iter().copied().collect();
    let json = serde_json::to_string(&creds).expect("serialize creds");
    let path = dir.path().join("creds.json");
    std::fs::write(&path, json).expect("write creds");
    let keyring = Keyring::load_credentials(&path).expect("load credentials");
    // Keep the tempdir alive by leaking it (tests are short-lived)
    std::mem::forget(dir);
    keyring
}

// ---------------------------------------------------------------------------
// Manifest / TempDir helpers
// ---------------------------------------------------------------------------

/// Creates a temp directory with a `manifests/` subdirectory populated with the given TOML files.
/// Returns (TempDir, manifests_dir_path). Caller must hold the TempDir to keep files alive.
pub fn temp_manifests(files: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("create tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");
    for (filename, content) in files {
        std::fs::write(manifests_dir.join(filename), content).expect("write manifest");
    }
    let path = manifests_dir.clone();
    (dir, path)
}

/// Creates a temp manifest directory and loads a ManifestRegistry from it.
/// Returns (TempDir, ManifestRegistry).
pub fn temp_registry(files: &[(&str, &str)]) -> (tempfile::TempDir, ManifestRegistry) {
    let (dir, manifests_dir) = temp_manifests(files);
    let registry = ManifestRegistry::load(&manifests_dir).expect("load test manifests");
    (dir, registry)
}

/// Generates a simple TOML manifest string for a no-auth provider with one GET tool.
pub fn simple_manifest(provider_name: &str, base_url: &str, tool_name: &str) -> String {
    format!(
        r#"
[provider]
name = "{provider_name}"
description = "Test provider"
base_url = "{base_url}"
auth_type = "none"

[[tools]]
name = "{tool_name}"
description = "Test tool"
endpoint = "/test"
method = "GET"

[tools.input_schema]
type = "object"

[tools.input_schema.properties.q]
type = "string"
description = "Query"
"#
    )
}

// ---------------------------------------------------------------------------
// Proxy / Router builders
// ---------------------------------------------------------------------------

/// Build an axum Router for testing, with no JWT auth (dev mode).
pub fn build_test_app(registry: ManifestRegistry) -> axum::Router {
    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring: Keyring::empty(),
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
        db: ati::core::db::DbState::Disabled,
    });
    build_router(state)
}

/// Build an axum Router with JWT auth enabled (HS256).
pub fn build_test_app_with_jwt(registry: ManifestRegistry) -> axum::Router {
    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring: Keyring::empty(),
        jwt_config: Some(test_jwt_config()),
        jwks_json: None,
        auth_cache: AuthCache::new(),
        db: ati::core::db::DbState::Disabled,
    });
    build_router(state)
}

/// Build an axum Router with custom keyring and optional JWT.
pub fn build_test_app_full(
    registry: ManifestRegistry,
    keyring: Keyring,
    jwt: bool,
) -> axum::Router {
    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring,
        jwt_config: if jwt { Some(test_jwt_config()) } else { None },
        jwks_json: None,
        auth_cache: AuthCache::new(),
        db: ati::core::db::DbState::Disabled,
    });
    build_router(state)
}

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

/// Create an HS256 JWT config for testing.
pub fn test_jwt_config() -> JwtConfig {
    jwt::config_from_secret(
        b"test-secret-key-32-bytes-long!!!",
        None,
        "ati-proxy".into(),
    )
}

/// Issue a test JWT with given scopes.
pub fn issue_test_token(scope: &str) -> String {
    let config = test_jwt_config();
    let now = jwt::now_secs();
    let claims = TokenClaims {
        iss: None,
        sub: "test-agent".into(),
        aud: "ati-proxy".into(),
        iat: now,
        exp: now + 3600,
        jti: None,
        scope: scope.into(),
        ati: Some(AtiNamespace {
            v: 1,
            rate: HashMap::new(),
            customer_id: None,
        }),
        job_id: None,
        sandbox_id: None,
    };
    jwt::issue(&claims, &config).unwrap()
}

// ---------------------------------------------------------------------------
// Response body helpers
// ---------------------------------------------------------------------------

/// Reads an axum response body as JSON.
pub async fn body_json(body: Body) -> Value {
    let bytes = body.collect().await.expect("collect body").to_bytes();
    serde_json::from_slice(&bytes).expect("parse body as JSON")
}

// ---------------------------------------------------------------------------
// Env-var test helper
// ---------------------------------------------------------------------------

/// Serialize env-var mutating tests across this binary. Cargo runs tests on
/// multiple OS threads, so two tests touching the same env var would race.
/// Uses a tokio Mutex so async tests can hold it across `.await` boundaries.
pub static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Snapshot env vars, run the async body, restore on Drop. Panic-safe.
///
/// Hold this guard across the entire async body so the env mutation can't be
/// observed by another test mid-flight. Drop runs on scope exit (including
/// panic unwind) and restores the previous value.
pub struct EnvGuard<'a> {
    _lock: tokio::sync::MutexGuard<'a, ()>,
    restores: Vec<(String, Option<String>)>,
}

impl<'a> EnvGuard<'a> {
    pub async fn set(key: &str, value: Option<&str>) -> EnvGuard<'a> {
        let lock = ENV_LOCK.lock().await;
        let prev = std::env::var(key).ok();
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        EnvGuard {
            _lock: lock,
            restores: vec![(key.to_string(), prev)],
        }
    }
}

impl<'a> Drop for EnvGuard<'a> {
    fn drop(&mut self) {
        for (key, prev) in self.restores.drain(..) {
            match prev {
                Some(v) => std::env::set_var(&key, v),
                None => std::env::remove_var(&key),
            }
        }
    }
}
