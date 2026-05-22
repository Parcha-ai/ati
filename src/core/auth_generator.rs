//! Dynamic credential generator — produces short-lived auth tokens at call time.
//!
//! Generators run where secrets live: on the proxy server in proxy mode,
//! on the local machine in local mode. Signing keys never enter the sandbox.
//!
//! Two generator types:
//! - `command`: runs an external command, captures stdout
//! - `script`: writes an inline script to a temp file, runs via interpreter
//!
//! Results are cached per (provider, agent_sub) with configurable TTL.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use thiserror::Error;

use crate::core::keyring::Keyring;
use crate::core::manifest::{AuthGenType, AuthGenerator, AuthOutputFormat, Provider};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum AuthGenError {
    #[error("Auth generator config error: {0}")]
    Config(String),
    #[error("Failed to spawn generator process: {0}")]
    Spawn(String),
    #[error("Generator timed out after {0}s")]
    Timeout(u64),
    #[error("Generator exited with code {code}: {stderr}")]
    NonZeroExit { code: i32, stderr: String },
    #[error("Failed to parse generator output: {0}")]
    OutputParse(String),
    #[error("Keyring key '{0}' not found (required by auth_generator)")]
    KeyringMissing(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Context for variable expansion
// ---------------------------------------------------------------------------

/// Context for expanding `${VAR}` placeholders in generator args/env.
pub struct GenContext {
    pub jwt_sub: String,
    pub jwt_scope: String,
    pub tool_name: String,
    pub timestamp: u64,
    /// Raw inbound bearer token (the `<token>` from `Authorization: Bearer
    /// <token>`). Populated by the proxy from the request that triggered
    /// this generator run, or by the CLI from `$ATI_SESSION_TOKEN` in
    /// direct-CLI mode. Empty string when no inbound bearer is available
    /// (dev mode, no JWT validation configured, no env var set). Exposed
    /// to auth_generators via `${JWT_TOKEN}` so an MCP provider can forward
    /// the calling sandbox's identity to its upstream MCP without the proxy
    /// holding a long-lived static bearer that loses per-sandbox attribution.
    /// See issue #115.
    pub jwt_token: String,
}

impl Default for GenContext {
    fn default() -> Self {
        GenContext {
            jwt_sub: "dev".into(),
            jwt_scope: "*".into(),
            tool_name: String::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            jwt_token: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Generated credential
// ---------------------------------------------------------------------------

/// Result of running a generator — primary token + optional extra injections.
#[derive(Debug, Clone)]
pub struct GeneratedCredential {
    /// Primary token value (used for bearer/header/query auth).
    pub value: String,
    /// Extra headers from JSON inject targets with type="header".
    pub extra_headers: HashMap<String, String>,
    /// Extra env vars from JSON inject targets with type="env".
    pub extra_env: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

struct CachedCredential {
    cred: GeneratedCredential,
    expires_at: Instant,
}

/// TTL-based credential cache, keyed by `(provider_name, agent_sub,
/// token_fingerprint)`.
///
/// The token fingerprint is the SHA-256 of the raw inbound bearer truncated
/// to 16 hex chars (or the empty string when no bearer was presented). We
/// added this third dimension so a per-sandbox JWT (which rotates per request
/// in some deployments) doesn't either (a) cache one sandbox's generated
/// credential and serve it to another sandbox with the same `sub`, or
/// (b) force every consumer to set `cache_ttl_secs = 0`. With the fingerprint
/// in the key, legitimate same-sandbox reuse hits the cache and cross-sandbox
/// reuse misses — even when `sub` happens to collide. See issue #115.
///
/// The fingerprint is a one-way hash, so the cache map never carries raw
/// bearer bytes. Truncating to 16 hex chars (64 bits) is plenty for collision
/// avoidance at this cache's scale (provider × sub already partitions the
/// keyspace; the token dimension just needs to distinguish concurrent
/// per-request tokens for the same agent).
pub struct AuthCache {
    entries: Mutex<HashMap<(String, String, String), CachedCredential>>,
}

impl Default for AuthCache {
    fn default() -> Self {
        AuthCache {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

/// SHA-256 of `token`, truncated to 16 hex chars. Empty input → empty
/// fingerprint (intentional — sentinel for "no inbound bearer" so all the
/// no-bearer paths share one cache slot per (provider, sub)).
pub fn token_fingerprint(token: &str) -> String {
    if token.is_empty() {
        return String::new();
    }
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest)[..16].to_string()
}

impl AuthCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, provider: &str, sub: &str, token: &str) -> Option<GeneratedCredential> {
        let cache = self.entries.lock().unwrap();
        let key = (
            provider.to_string(),
            sub.to_string(),
            token_fingerprint(token),
        );
        match cache.get(&key) {
            Some(entry) if Instant::now() < entry.expires_at => Some(entry.cred.clone()),
            _ => None,
        }
    }

    pub fn insert(
        &self,
        provider: &str,
        sub: &str,
        token: &str,
        cred: GeneratedCredential,
        ttl_secs: u64,
    ) {
        if ttl_secs == 0 {
            return; // No caching
        }
        let mut cache = self.entries.lock().unwrap();
        // Sweep expired entries on every insert. Without the token-fingerprint
        // dimension the previous `(provider, sub)` key bounded the map to
        // O(providers × subs), so stale entries were always overwritten and a
        // background sweep wasn't needed. With per-token keys, rotating JWTs
        // (the very production scenario this PR is targeting — see issue #115)
        // create a new permanent map entry per request unless we prune. The
        // sweep runs under the same lock we already hold for the insert, so
        // it adds no contention; cost is O(n) over the live map, amortized
        // across inserts. Greptile P1 on PR #117.
        let now = Instant::now();
        cache.retain(|_, v| now < v.expires_at);
        let key = (
            provider.to_string(),
            sub.to_string(),
            token_fingerprint(token),
        );
        cache.insert(
            key,
            CachedCredential {
                cred,
                expires_at: now + Duration::from_secs(ttl_secs),
            },
        );
    }

    /// Number of map entries (live + just-expired-not-yet-swept).
    /// Test-only helper for asserting the sweep on insert actually evicts
    /// expired rows. Not exposed publicly to avoid encouraging callers
    /// to depend on a particular eviction cadence.
    #[cfg(test)]
    pub fn entry_count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

// ---------------------------------------------------------------------------
// Main generate function
// ---------------------------------------------------------------------------

/// Generate a credential by running the provider's auth_generator.
///
/// 1. Check cache → return if hit
/// 2. Expand variables in args and env
/// 3. Spawn subprocess (command or script)
/// 4. Parse output (text or JSON)
/// 5. Cache and return
pub async fn generate(
    provider: &Provider,
    gen: &AuthGenerator,
    ctx: &GenContext,
    keyring: &Keyring,
    cache: &AuthCache,
) -> Result<GeneratedCredential, AuthGenError> {
    // 1. Check cache. Key includes a fingerprint of the inbound JWT so that
    // per-sandbox bearers don't share cached credentials across sandboxes
    // even when they happen to land on the same `sub` (see issue #115).
    if gen.cache_ttl_secs > 0 {
        if let Some(cached) = cache.get(&provider.name, &ctx.jwt_sub, &ctx.jwt_token) {
            return Ok(cached);
        }
    }

    // 2. Expand variables in args and env
    let expanded_args: Vec<String> = gen
        .args
        .iter()
        .map(|a| expand_variables(a, ctx, keyring))
        .collect::<Result<Vec<_>, _>>()?;

    let mut expanded_env: HashMap<String, String> = HashMap::new();
    for (k, v) in &gen.env {
        expanded_env.insert(k.clone(), expand_variables(v, ctx, keyring)?);
    }

    // 3. Build curated env (don't leak host secrets)
    let mut final_env: HashMap<String, String> = HashMap::new();
    for var in &["PATH", "HOME", "TMPDIR"] {
        if let Ok(val) = std::env::var(var) {
            final_env.insert(var.to_string(), val);
        }
    }
    final_env.extend(expanded_env);

    // 4. Spawn subprocess
    let output =
        match gen.gen_type {
            AuthGenType::Command => {
                let command = gen.command.as_deref().ok_or_else(|| {
                    AuthGenError::Config("command required for type=command".into())
                })?;

                let child = tokio::process::Command::new(command)
                    .args(&expanded_args)
                    .env_clear()
                    .envs(&final_env)
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .kill_on_drop(true)
                    .spawn()
                    .map_err(|e| AuthGenError::Spawn(format!("{command}: {e}")))?;

                let timeout = Duration::from_secs(gen.timeout_secs);
                tokio::time::timeout(timeout, child.wait_with_output())
                    .await
                    .map_err(|_| AuthGenError::Timeout(gen.timeout_secs))?
                    .map_err(AuthGenError::Io)?
            }
            AuthGenType::Script => {
                let interpreter = gen.interpreter.as_deref().ok_or_else(|| {
                    AuthGenError::Config("interpreter required for type=script".into())
                })?;
                let script = gen.script.as_deref().ok_or_else(|| {
                    AuthGenError::Config("script required for type=script".into())
                })?;

                // Write script to a temp file
                let suffix: u32 = rand::random();
                let tmp_path = std::env::temp_dir().join(format!("ati_gen_{suffix}.tmp"));
                std::fs::write(&tmp_path, script).map_err(AuthGenError::Io)?;

                let child = tokio::process::Command::new(interpreter)
                    .arg(&tmp_path)
                    .env_clear()
                    .envs(&final_env)
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .kill_on_drop(true)
                    .spawn()
                    .map_err(|e| AuthGenError::Spawn(format!("{interpreter}: {e}")))?;

                let timeout = Duration::from_secs(gen.timeout_secs);
                let result = tokio::time::timeout(timeout, child.wait_with_output())
                    .await
                    .map_err(|_| AuthGenError::Timeout(gen.timeout_secs))?
                    .map_err(AuthGenError::Io)?;

                // Clean up temp file
                let _ = std::fs::remove_file(&tmp_path);
                result
            }
        };

    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(AuthGenError::NonZeroExit { code, stderr });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // 5. Parse output
    let cred = match gen.output_format {
        AuthOutputFormat::Text => GeneratedCredential {
            value: stdout.trim().to_string(),
            extra_headers: HashMap::new(),
            extra_env: HashMap::new(),
        },
        AuthOutputFormat::Json => {
            let json: serde_json::Value = serde_json::from_str(stdout.trim())
                .map_err(|e| AuthGenError::OutputParse(format!("invalid JSON: {e}")))?;

            let mut extra_headers = HashMap::new();
            let mut extra_env = HashMap::new();
            let mut primary_value = stdout.trim().to_string();

            // If no inject map, use the whole output as the primary value
            if gen.inject.is_empty() {
                // Try to extract a "token" or "access_token" field as primary
                if let Some(tok) = json.get("token").or(json.get("access_token")) {
                    if let Some(s) = tok.as_str() {
                        primary_value = s.to_string();
                    }
                }
            } else {
                // Extract fields per inject map
                let mut found_primary = false;
                for (json_path, target) in &gen.inject {
                    let extracted = extract_json_path(&json, json_path).ok_or_else(|| {
                        AuthGenError::OutputParse(format!(
                            "JSON path '{}' not found in output",
                            json_path
                        ))
                    })?;

                    match target.inject_type.as_str() {
                        "header" => {
                            extra_headers.insert(target.name.clone(), extracted);
                        }
                        "env" => {
                            extra_env.insert(target.name.clone(), extracted);
                        }
                        "query" => {
                            // For query injection, use as primary value
                            if !found_primary {
                                primary_value = extracted;
                                found_primary = true;
                            }
                        }
                        _ => {
                            // Default: treat as primary value
                            if !found_primary {
                                primary_value = extracted;
                                found_primary = true;
                            }
                        }
                    }
                }
            }

            GeneratedCredential {
                value: primary_value,
                extra_headers,
                extra_env,
            }
        }
    };

    // 6. Cache. See `cache.get` above for why the JWT fingerprint is part
    // of the key.
    cache.insert(
        &provider.name,
        &ctx.jwt_sub,
        &ctx.jwt_token,
        cred.clone(),
        gen.cache_ttl_secs,
    );

    Ok(cred)
}

// ---------------------------------------------------------------------------
// Variable expansion
// ---------------------------------------------------------------------------

/// Expand `${VAR}` placeholders in a string.
///
/// Recognized variables:
/// - `${JWT_SUB}`, `${JWT_SCOPE}`, `${TOOL_NAME}`, `${TIMESTAMP}` — from GenContext
/// - `${JWT_TOKEN}` — raw inbound bearer (proxy: from `Authorization: Bearer …`;
///   CLI: from `$ATI_SESSION_TOKEN`). Empty when no inbound bearer is present.
/// - `${anything_else}` — looked up in the keyring
fn expand_variables(
    input: &str,
    ctx: &GenContext,
    keyring: &Keyring,
) -> Result<String, AuthGenError> {
    let mut result = input.to_string();
    // Process all ${...} patterns
    while let Some(start) = result.find("${") {
        let rest = &result[start + 2..];
        let end = match rest.find('}') {
            Some(e) => e,
            None => break,
        };
        let var_name = &rest[..end];

        let replacement = match var_name {
            "JWT_SUB" => ctx.jwt_sub.clone(),
            "JWT_SCOPE" => ctx.jwt_scope.clone(),
            "TOOL_NAME" => ctx.tool_name.clone(),
            "TIMESTAMP" => ctx.timestamp.to_string(),
            // The raw inbound bearer. Empty in dev mode and in any context
            // where no JWT was presented (CLI direct mode without
            // `$ATI_SESSION_TOKEN`). Generators that *require* a non-empty
            // token should fail explicitly inside their own script rather
            // than relying on `expand_variables` to error — silently sending
            // an empty bearer to the upstream is a debuggable 401, whereas
            // synthesizing one would be a security hole.
            "JWT_TOKEN" => ctx.jwt_token.clone(),
            _ => {
                // Keyring lookup
                match keyring.get(var_name) {
                    Some(val) => val.to_string(),
                    None => return Err(AuthGenError::KeyringMissing(var_name.to_string())),
                }
            }
        };

        result = format!("{}{}{}", &result[..start], replacement, &rest[end + 1..]);
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// JSON path extraction (dot-notation)
// ---------------------------------------------------------------------------

/// Extract a value from a JSON object using dot-notation path.
///
/// Example: `extract_json_path(json, "Credentials.AccessKeyId")`
/// navigates `json["Credentials"]["AccessKeyId"]`.
fn extract_json_path(value: &serde_json::Value, path: &str) -> Option<String> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    match current {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        other => Some(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_variables_context() {
        let ctx = GenContext {
            jwt_sub: "agent-7".into(),
            jwt_scope: "tool:brain:*".into(),
            tool_name: "brain:query".into(),
            timestamp: 1773096459,
            jwt_token: "eyJhbGciOiJIUzI1NiJ9.payload.sig".into(),
        };
        let keyring = Keyring::empty();

        assert_eq!(
            expand_variables("${JWT_SUB}", &ctx, &keyring).unwrap(),
            "agent-7"
        );
        assert_eq!(
            expand_variables("${TOOL_NAME}", &ctx, &keyring).unwrap(),
            "brain:query"
        );
        assert_eq!(
            expand_variables("${TIMESTAMP}", &ctx, &keyring).unwrap(),
            "1773096459"
        );
        assert_eq!(
            expand_variables("${JWT_TOKEN}", &ctx, &keyring).unwrap(),
            "eyJhbGciOiJIUzI1NiJ9.payload.sig"
        );
        assert_eq!(
            expand_variables("sub=${JWT_SUB}&tool=${TOOL_NAME}", &ctx, &keyring).unwrap(),
            "sub=agent-7&tool=brain:query"
        );
        // The Bearer-prefix form a passthrough/MCP auth_generator would use.
        assert_eq!(
            expand_variables("Bearer ${JWT_TOKEN}", &ctx, &keyring).unwrap(),
            "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"
        );
    }

    #[test]
    fn test_expand_variables_jwt_token_empty_when_unset() {
        // Default context has no inbound bearer — expansion succeeds with
        // an empty string rather than erroring. That keeps existing
        // generators that never reference ${JWT_TOKEN} unaffected, and lets
        // generators that DO reference it fail visibly downstream (401
        // from the upstream) rather than silently substituting a static
        // bootstrap token from the keyring.
        let ctx = GenContext::default();
        let keyring = Keyring::empty();
        assert_eq!(
            expand_variables("${JWT_TOKEN}", &ctx, &keyring).unwrap(),
            ""
        );
    }

    #[test]
    fn test_expand_variables_keyring() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("creds");
        std::fs::write(&path, r#"{"my_secret":"s3cr3t"}"#).unwrap();
        let keyring = Keyring::load_credentials(&path).unwrap();

        let ctx = GenContext::default();
        assert_eq!(
            expand_variables("${my_secret}", &ctx, &keyring).unwrap(),
            "s3cr3t"
        );
    }

    #[test]
    fn test_expand_variables_missing_key() {
        let keyring = Keyring::empty();
        let ctx = GenContext::default();
        let err = expand_variables("${nonexistent}", &ctx, &keyring).unwrap_err();
        assert!(matches!(err, AuthGenError::KeyringMissing(_)));
    }

    #[test]
    fn test_expand_variables_no_placeholder() {
        let keyring = Keyring::empty();
        let ctx = GenContext::default();
        assert_eq!(
            expand_variables("plain text", &ctx, &keyring).unwrap(),
            "plain text"
        );
    }

    #[test]
    fn test_extract_json_path_simple() {
        let json: serde_json::Value = serde_json::json!({"token": "abc123", "expires_in": 3600});
        assert_eq!(extract_json_path(&json, "token"), Some("abc123".into()));
        assert_eq!(extract_json_path(&json, "expires_in"), Some("3600".into()));
    }

    #[test]
    fn test_extract_json_path_nested() {
        let json: serde_json::Value = serde_json::json!({
            "Credentials": {
                "AccessKeyId": "AKIA...",
                "SecretAccessKey": "wJalrX...",
                "SessionToken": "FwoGZ..."
            }
        });
        assert_eq!(
            extract_json_path(&json, "Credentials.AccessKeyId"),
            Some("AKIA...".into())
        );
        assert_eq!(
            extract_json_path(&json, "Credentials.SessionToken"),
            Some("FwoGZ...".into())
        );
    }

    #[test]
    fn test_extract_json_path_missing() {
        let json: serde_json::Value = serde_json::json!({"a": "b"});
        assert_eq!(extract_json_path(&json, "nonexistent"), None);
        assert_eq!(extract_json_path(&json, "a.b.c"), None);
    }

    #[test]
    fn test_auth_cache_basic() {
        let cache = AuthCache::new();
        assert!(cache.get("provider", "sub", "").is_none());

        let cred = GeneratedCredential {
            value: "token123".into(),
            extra_headers: HashMap::new(),
            extra_env: HashMap::new(),
        };
        cache.insert("provider", "sub", "", cred.clone(), 300);

        let cached = cache.get("provider", "sub", "").unwrap();
        assert_eq!(cached.value, "token123");
    }

    #[test]
    fn test_auth_cache_zero_ttl_no_cache() {
        let cache = AuthCache::new();
        let cred = GeneratedCredential {
            value: "token".into(),
            extra_headers: HashMap::new(),
            extra_env: HashMap::new(),
        };
        cache.insert("provider", "sub", "", cred, 0);
        assert!(cache.get("provider", "sub", "").is_none());
    }

    #[test]
    fn test_auth_cache_different_keys() {
        let cache = AuthCache::new();
        let cred1 = GeneratedCredential {
            value: "token-a".into(),
            extra_headers: HashMap::new(),
            extra_env: HashMap::new(),
        };
        let cred2 = GeneratedCredential {
            value: "token-b".into(),
            extra_headers: HashMap::new(),
            extra_env: HashMap::new(),
        };
        cache.insert("provider", "agent-1", "", cred1, 300);
        cache.insert("provider", "agent-2", "", cred2, 300);

        assert_eq!(
            cache.get("provider", "agent-1", "").unwrap().value,
            "token-a"
        );
        assert_eq!(
            cache.get("provider", "agent-2", "").unwrap().value,
            "token-b"
        );
    }

    #[test]
    fn test_auth_cache_per_token_isolation() {
        // Issue #115: two sandboxes with the same `sub` but different
        // inbound bearers must NOT share cached credentials. Otherwise the
        // first sandbox's generated token gets served to the second.
        let cache = AuthCache::new();
        let cred_a = GeneratedCredential {
            value: "for-sandbox-a".into(),
            extra_headers: HashMap::new(),
            extra_env: HashMap::new(),
        };
        let cred_b = GeneratedCredential {
            value: "for-sandbox-b".into(),
            extra_headers: HashMap::new(),
            extra_env: HashMap::new(),
        };
        cache.insert("provider", "sandbox-svc", "jwt-A", cred_a, 300);
        cache.insert("provider", "sandbox-svc", "jwt-B", cred_b, 300);

        // Each token gets its own cached cred.
        assert_eq!(
            cache.get("provider", "sandbox-svc", "jwt-A").unwrap().value,
            "for-sandbox-a"
        );
        assert_eq!(
            cache.get("provider", "sandbox-svc", "jwt-B").unwrap().value,
            "for-sandbox-b"
        );
        // A third unseen token misses (no leakage from either A or B).
        assert!(cache.get("provider", "sandbox-svc", "jwt-C").is_none());
    }

    #[test]
    fn test_token_fingerprint_stable_and_distinct() {
        let f1 = token_fingerprint("token-one");
        let f2 = token_fingerprint("token-two");
        assert_eq!(token_fingerprint("token-one"), f1, "fingerprint is stable");
        assert_ne!(f1, f2, "different tokens hash to different fingerprints");
        assert_eq!(f1.len(), 16, "fingerprint is 16 hex chars");
        assert!(f1.chars().all(|c| c.is_ascii_hexdigit()));
        // Empty input gets the empty sentinel so all no-bearer paths share
        // one cache slot per (provider, sub).
        assert_eq!(token_fingerprint(""), "");
    }

    #[test]
    fn test_auth_cache_insert_evicts_expired_entries() {
        // Greptile P1 on PR #117: rotating per-request JWTs would create one
        // permanent map entry per request because expired entries were never
        // swept. The fix prunes on every `insert`. Verify the prune actually
        // happens by inserting one entry with the smallest possible non-zero
        // TTL (1 second), waiting for it to expire, then inserting a
        // different key — the second insert MUST drop the first.
        let cache = AuthCache::new();
        let cred = GeneratedCredential {
            value: "ephemeral".into(),
            extra_headers: HashMap::new(),
            extra_env: HashMap::new(),
        };
        cache.insert("p", "s", "old-jwt", cred.clone(), 1);
        assert_eq!(cache.entry_count(), 1);

        // Sleep past the 1s TTL. 1100ms is plenty of headroom on a busy
        // runner without inflating test runtime.
        std::thread::sleep(Duration::from_millis(1100));

        // A second insert (different fingerprint) triggers the sweep.
        cache.insert("p", "s", "new-jwt", cred, 60);
        assert_eq!(
            cache.entry_count(),
            1,
            "sweep on insert should have dropped the expired entry; \
             only the new one should remain"
        );

        // Sanity-check which entry survived.
        assert!(cache.get("p", "s", "new-jwt").is_some());
        assert!(cache.get("p", "s", "old-jwt").is_none());
    }

    #[tokio::test]
    async fn test_generate_command_text() {
        let provider = Provider {
            name: "test".into(),
            description: "test provider".into(),
            base_url: String::new(),
            auth_type: crate::core::manifest::AuthType::Bearer,
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
            host_match: None,
            path_prefix: None,
            strip_prefix: true,
            path_replace: None,
            host_override: None,
            forward_websockets: false,
            deny_paths: Vec::new(),
            forward_authorization_paths: Vec::new(),
            connect_timeout_seconds: 5,
            read_timeout_seconds: 300,
            idle_timeout_seconds: 60,
            max_request_bytes: 100 * 1024 * 1024,
            max_response_bytes: 500 * 1024 * 1024,
            auth_generator: None,
            category: None,
            skills: vec![],
        };

        let gen = AuthGenerator {
            gen_type: AuthGenType::Command,
            command: Some("echo".into()),
            args: vec!["hello-token".into()],
            interpreter: None,
            script: None,
            cache_ttl_secs: 0,
            output_format: AuthOutputFormat::Text,
            env: HashMap::new(),
            inject: HashMap::new(),
            timeout_secs: 5,
        };

        let ctx = GenContext::default();
        let keyring = Keyring::empty();
        let cache = AuthCache::new();

        let cred = generate(&provider, &gen, &ctx, &keyring, &cache)
            .await
            .unwrap();
        assert_eq!(cred.value, "hello-token");
        assert!(cred.extra_headers.is_empty());
    }

    #[tokio::test]
    async fn test_generate_command_json() {
        let provider = Provider {
            name: "test".into(),
            description: "test".into(),
            base_url: String::new(),
            auth_type: crate::core::manifest::AuthType::Bearer,
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
            host_match: None,
            path_prefix: None,
            strip_prefix: true,
            path_replace: None,
            host_override: None,
            forward_websockets: false,
            deny_paths: Vec::new(),
            forward_authorization_paths: Vec::new(),
            connect_timeout_seconds: 5,
            read_timeout_seconds: 300,
            idle_timeout_seconds: 60,
            max_request_bytes: 100 * 1024 * 1024,
            max_response_bytes: 500 * 1024 * 1024,
            auth_generator: None,
            category: None,
            skills: vec![],
        };

        let mut inject = HashMap::new();
        inject.insert(
            "Credentials.AccessKeyId".into(),
            crate::core::manifest::InjectTarget {
                inject_type: "header".into(),
                name: "X-Access-Key".into(),
            },
        );
        inject.insert(
            "Credentials.Secret".into(),
            crate::core::manifest::InjectTarget {
                inject_type: "env".into(),
                name: "AWS_SECRET".into(),
            },
        );

        let gen = AuthGenerator {
            gen_type: AuthGenType::Command,
            command: Some("echo".into()),
            args: vec![
                r#"{"Credentials":{"AccessKeyId":"AKIA123","Secret":"wJalr","SessionToken":"FwoG"}}"#.into(),
            ],
            interpreter: None,
            script: None,
            cache_ttl_secs: 0,
            output_format: AuthOutputFormat::Json,
            env: HashMap::new(),
            inject,
            timeout_secs: 5,
        };

        let ctx = GenContext::default();
        let keyring = Keyring::empty();
        let cache = AuthCache::new();

        let cred = generate(&provider, &gen, &ctx, &keyring, &cache)
            .await
            .unwrap();
        assert_eq!(cred.extra_headers.get("X-Access-Key").unwrap(), "AKIA123");
        assert_eq!(cred.extra_env.get("AWS_SECRET").unwrap(), "wJalr");
    }

    #[tokio::test]
    async fn test_generate_script() {
        let provider = Provider {
            name: "test".into(),
            description: "test".into(),
            base_url: String::new(),
            auth_type: crate::core::manifest::AuthType::Bearer,
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
            host_match: None,
            path_prefix: None,
            strip_prefix: true,
            path_replace: None,
            host_override: None,
            forward_websockets: false,
            deny_paths: Vec::new(),
            forward_authorization_paths: Vec::new(),
            connect_timeout_seconds: 5,
            read_timeout_seconds: 300,
            idle_timeout_seconds: 60,
            max_request_bytes: 100 * 1024 * 1024,
            max_response_bytes: 500 * 1024 * 1024,
            auth_generator: None,
            category: None,
            skills: vec![],
        };

        let gen = AuthGenerator {
            gen_type: AuthGenType::Script,
            command: None,
            args: vec![],
            interpreter: Some("bash".into()),
            script: Some("echo script-token-42".into()),
            cache_ttl_secs: 0,
            output_format: AuthOutputFormat::Text,
            env: HashMap::new(),
            inject: HashMap::new(),
            timeout_secs: 5,
        };

        let ctx = GenContext::default();
        let keyring = Keyring::empty();
        let cache = AuthCache::new();

        let cred = generate(&provider, &gen, &ctx, &keyring, &cache)
            .await
            .unwrap();
        assert_eq!(cred.value, "script-token-42");
    }

    #[tokio::test]
    async fn test_generate_caches_result() {
        let provider = Provider {
            name: "cached_provider".into(),
            description: "test".into(),
            base_url: String::new(),
            auth_type: crate::core::manifest::AuthType::Bearer,
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
            host_match: None,
            path_prefix: None,
            strip_prefix: true,
            path_replace: None,
            host_override: None,
            forward_websockets: false,
            deny_paths: Vec::new(),
            forward_authorization_paths: Vec::new(),
            connect_timeout_seconds: 5,
            read_timeout_seconds: 300,
            idle_timeout_seconds: 60,
            max_request_bytes: 100 * 1024 * 1024,
            max_response_bytes: 500 * 1024 * 1024,
            auth_generator: None,
            category: None,
            skills: vec![],
        };

        let gen = AuthGenerator {
            gen_type: AuthGenType::Command,
            command: Some("date".into()),
            args: vec!["+%s%N".into()],
            interpreter: None,
            script: None,
            cache_ttl_secs: 300,
            output_format: AuthOutputFormat::Text,
            env: HashMap::new(),
            inject: HashMap::new(),
            timeout_secs: 5,
        };

        let ctx = GenContext {
            jwt_sub: "test-agent".into(),
            ..GenContext::default()
        };
        let keyring = Keyring::empty();
        let cache = AuthCache::new();

        let cred1 = generate(&provider, &gen, &ctx, &keyring, &cache)
            .await
            .unwrap();
        let cred2 = generate(&provider, &gen, &ctx, &keyring, &cache)
            .await
            .unwrap();
        // Second call should return cached value (same value)
        assert_eq!(cred1.value, cred2.value);
    }

    #[tokio::test]
    async fn test_generate_with_variable_expansion() {
        let provider = Provider {
            name: "test".into(),
            description: "test".into(),
            base_url: String::new(),
            auth_type: crate::core::manifest::AuthType::Bearer,
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
            host_match: None,
            path_prefix: None,
            strip_prefix: true,
            path_replace: None,
            host_override: None,
            forward_websockets: false,
            deny_paths: Vec::new(),
            forward_authorization_paths: Vec::new(),
            connect_timeout_seconds: 5,
            read_timeout_seconds: 300,
            idle_timeout_seconds: 60,
            max_request_bytes: 100 * 1024 * 1024,
            max_response_bytes: 500 * 1024 * 1024,
            auth_generator: None,
            category: None,
            skills: vec![],
        };

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

        let ctx = GenContext {
            jwt_sub: "agent-42".into(),
            jwt_scope: "*".into(),
            tool_name: "brain:query".into(),
            timestamp: 1234567890,
            jwt_token: String::new(),
        };
        let keyring = Keyring::empty();
        let cache = AuthCache::new();

        let cred = generate(&provider, &gen, &ctx, &keyring, &cache)
            .await
            .unwrap();
        assert_eq!(cred.value, "agent-42");
    }

    #[tokio::test]
    async fn test_generate_timeout() {
        let provider = Provider {
            name: "test".into(),
            description: "test".into(),
            base_url: String::new(),
            auth_type: crate::core::manifest::AuthType::Bearer,
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
            host_match: None,
            path_prefix: None,
            strip_prefix: true,
            path_replace: None,
            host_override: None,
            forward_websockets: false,
            deny_paths: Vec::new(),
            forward_authorization_paths: Vec::new(),
            connect_timeout_seconds: 5,
            read_timeout_seconds: 300,
            idle_timeout_seconds: 60,
            max_request_bytes: 100 * 1024 * 1024,
            max_response_bytes: 500 * 1024 * 1024,
            auth_generator: None,
            category: None,
            skills: vec![],
        };

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

        let ctx = GenContext::default();
        let keyring = Keyring::empty();
        let cache = AuthCache::new();

        let err = generate(&provider, &gen, &ctx, &keyring, &cache)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthGenError::Timeout(1)));
    }
}
