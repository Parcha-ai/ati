//! Pluggable per-user secret backend.
//!
//! The proxy calls `resolve()` at request time with the caller's identity
//! (JWT `sub`) and the key names needed by the tool. The backend returns
//! whatever user-specific secrets it has; missing keys fall through to the
//! operator keyring.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum SecretBackendError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("Backend error: {0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Pluggable backend for resolving per-user secrets.
///
/// Implementations must be `Send + Sync` for use in an `Arc<dyn SecretBackend>`
/// shared across request handlers.
pub trait SecretBackend: Send + Sync {
    /// Resolve secrets for a caller. Returns only the keys found — missing
    /// keys are not an error (they fall through to the operator keyring).
    fn resolve(
        &self,
        sub: &str,
        keys: &[&str],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<HashMap<String, String>, SecretBackendError>>
                + Send
                + '_,
        >,
    >;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SecretBackendConfig {
    File {
        path: String,
        #[serde(default = "default_cache_ttl")]
        cache_ttl_secs: u64,
    },
    Http {
        url: String,
        #[serde(default)]
        auth_header: Option<String>,
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
        #[serde(default = "default_cache_ttl")]
        cache_ttl_secs: u64,
    },
    Vault {
        addr: String,
        #[serde(default = "default_vault_mount")]
        mount: String,
        #[serde(default)]
        token_env: Option<String>,
        #[serde(default = "default_cache_ttl")]
        cache_ttl_secs: u64,
    },
}

fn default_cache_ttl() -> u64 {
    300
}
fn default_timeout() -> u64 {
    5
}
fn default_vault_mount() -> String {
    "secret".to_string()
}

/// Load secret backend config from environment variables.
/// Returns None if `ATI_SECRET_BACKEND` is not set.
pub fn config_from_env() -> Option<SecretBackendConfig> {
    let backend_type = std::env::var("ATI_SECRET_BACKEND").ok()?;
    let cache_ttl: u64 = std::env::var("ATI_SECRET_BACKEND_CACHE_TTL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default_cache_ttl());

    match backend_type.trim().to_lowercase().as_str() {
        "file" => {
            let path = std::env::var("ATI_SECRET_BACKEND_PATH")
                .unwrap_or_else(|_| "~/.ati/user-secrets".to_string());
            Some(SecretBackendConfig::File {
                path,
                cache_ttl_secs: cache_ttl,
            })
        }
        "http" => {
            let url = std::env::var("ATI_SECRET_BACKEND_URL").ok()?;
            let auth_header = std::env::var("ATI_SECRET_BACKEND_AUTH").ok();
            let timeout: u64 = std::env::var("ATI_SECRET_BACKEND_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default_timeout());
            Some(SecretBackendConfig::Http {
                url,
                auth_header,
                timeout_secs: timeout,
                cache_ttl_secs: cache_ttl,
            })
        }
        "vault" => {
            let addr = std::env::var("ATI_SECRET_BACKEND_VAULT_ADDR")
                .or_else(|_| std::env::var("VAULT_ADDR"))
                .ok()?;
            let mount = std::env::var("ATI_SECRET_BACKEND_VAULT_MOUNT")
                .unwrap_or_else(|_| default_vault_mount());
            let token_env = std::env::var("ATI_SECRET_BACKEND_VAULT_TOKEN_ENV").ok();
            Some(SecretBackendConfig::Vault {
                addr,
                mount,
                token_env,
                cache_ttl_secs: cache_ttl,
            })
        }
        _ => {
            tracing::warn!(
                backend = %backend_type,
                "unknown ATI_SECRET_BACKEND value, ignoring"
            );
            None
        }
    }
}

/// Build a backend from config.
pub fn build_backend(
    config: &SecretBackendConfig,
) -> Result<Box<dyn SecretBackend>, SecretBackendError> {
    match config {
        SecretBackendConfig::File {
            path,
            cache_ttl_secs,
        } => {
            let expanded = expand_tilde(path);
            Ok(Box::new(FileSecretBackend::new(
                PathBuf::from(expanded),
                Duration::from_secs(*cache_ttl_secs),
            )))
        }
        SecretBackendConfig::Http {
            url,
            auth_header,
            timeout_secs,
            cache_ttl_secs,
        } => Ok(Box::new(HttpSecretBackend::new(
            url.clone(),
            auth_header.clone(),
            Duration::from_secs(*timeout_secs),
            Duration::from_secs(*cache_ttl_secs),
        ))),
        SecretBackendConfig::Vault { .. } => Err(SecretBackendError::Other(
            "Vault backend not yet implemented".into(),
        )),
    }
}

// ---------------------------------------------------------------------------
// File backend
// ---------------------------------------------------------------------------

/// Reads per-user secrets from JSON files on disk.
///
/// Directory layout:
/// ```text
/// {base_path}/{sub}/keys.json  →  {"api_key": "xxx", ...}
/// ```
///
/// The `sub` value is sanitized to prevent path traversal.
pub struct FileSecretBackend {
    base_path: PathBuf,
    cache_ttl: Duration,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

struct CacheEntry {
    secrets: HashMap<String, String>,
    loaded_at: Instant,
}

impl FileSecretBackend {
    pub fn new(base_path: PathBuf, cache_ttl: Duration) -> Self {
        FileSecretBackend {
            base_path,
            cache_ttl,
            cache: Mutex::new(HashMap::new()),
        }
    }
}

impl SecretBackend for FileSecretBackend {
    fn resolve(
        &self,
        sub: &str,
        keys: &[&str],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<HashMap<String, String>, SecretBackendError>>
                + Send
                + '_,
        >,
    > {
        let sub = sub.to_string();
        let keys: Vec<String> = keys.iter().map(|k| k.to_string()).collect();
        Box::pin(async move {
            // Check cache
            {
                let cache = self.cache.lock().unwrap();
                if let Some(entry) = cache.get(&sub) {
                    if entry.loaded_at.elapsed() < self.cache_ttl {
                        let mut result = HashMap::new();
                        for key in &keys {
                            if let Some(val) = entry.secrets.get(key.as_str()) {
                                result.insert(key.clone(), val.clone());
                            }
                        }
                        return Ok(result);
                    }
                }
            }

            // Load from disk
            let base_path = self.base_path.clone();
            let sub_clone = sub.clone();
            let all_secrets = tokio::task::spawn_blocking(move || {
                let safe_sub = sanitize_sub(&sub_clone);
                let keys_file = base_path.join(&safe_sub).join("keys.json");
                if !keys_file.exists() {
                    return Ok(HashMap::new());
                }
                let content = std::fs::read_to_string(&keys_file)?;
                let secrets: HashMap<String, String> = serde_json::from_str(&content)?;
                Ok::<_, SecretBackendError>(secrets)
            })
            .await
            .map_err(|e| SecretBackendError::Other(e.to_string()))??;

            // Filter to requested keys
            let mut result = HashMap::new();
            for key in &keys {
                if let Some(val) = all_secrets.get(key.as_str()) {
                    result.insert(key.clone(), val.clone());
                }
            }

            // Update cache
            {
                let mut cache = self.cache.lock().unwrap();
                cache.insert(
                    sub,
                    CacheEntry {
                        secrets: all_secrets,
                        loaded_at: Instant::now(),
                    },
                );
            }

            Ok(result)
        })
    }
}

// ---------------------------------------------------------------------------
// HTTP backend
// ---------------------------------------------------------------------------

/// Calls an external webhook to resolve per-user secrets.
///
/// Request:
/// ```text
/// POST {url}
/// Content-Type: application/json
/// Authorization: {auth_header}   (if configured)
///
/// {"sub": "user:miguel", "keys": ["api_key", "secret"]}
/// ```
///
/// Response:
/// ```json
/// {"api_key": "xxx", "secret": "yyy"}
/// ```
pub struct HttpSecretBackend {
    url: String,
    auth_header: Option<String>,
    cache_ttl: Duration,
    client: reqwest::Client,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

impl HttpSecretBackend {
    pub fn new(
        url: String,
        auth_header: Option<String>,
        timeout: Duration,
        cache_ttl: Duration,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_default();
        HttpSecretBackend {
            url,
            auth_header,
            cache_ttl,
            client,
            cache: Mutex::new(HashMap::new()),
        }
    }
}

impl SecretBackend for HttpSecretBackend {
    fn resolve(
        &self,
        sub: &str,
        keys: &[&str],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<HashMap<String, String>, SecretBackendError>>
                + Send
                + '_,
        >,
    > {
        let sub = sub.to_string();
        let keys: Vec<String> = keys.iter().map(|k| k.to_string()).collect();
        Box::pin(async move {
            // Check cache
            {
                let cache = self.cache.lock().unwrap();
                if let Some(entry) = cache.get(&sub) {
                    if entry.loaded_at.elapsed() < self.cache_ttl {
                        let mut result = HashMap::new();
                        for key in &keys {
                            if let Some(val) = entry.secrets.get(key.as_str()) {
                                result.insert(key.clone(), val.clone());
                            }
                        }
                        return Ok(result);
                    }
                }
            }

            // Call the external backend
            let body = serde_json::json!({
                "sub": sub,
                "keys": keys,
            });

            let mut req = self.client.post(&self.url).json(&body);
            if let Some(ref auth) = self.auth_header {
                req = req.header("Authorization", auth);
            }

            let resp = req
                .send()
                .await
                .map_err(|e| SecretBackendError::Http(e.to_string()))?;

            let status = resp.status().as_u16();
            if status == 404 {
                return Ok(HashMap::new());
            }
            if status != 200 {
                let body_text = resp
                    .text()
                    .await
                    .unwrap_or_else(|_| "<no body>".to_string());
                return Err(SecretBackendError::Http(format!(
                    "HTTP {status}: {body_text}"
                )));
            }

            let all_secrets: HashMap<String, String> = resp
                .json()
                .await
                .map_err(|e| SecretBackendError::Http(e.to_string()))?;

            // Filter to requested keys
            let mut result = HashMap::new();
            for key in &keys {
                if let Some(val) = all_secrets.get(key.as_str()) {
                    result.insert(key.clone(), val.clone());
                }
            }

            // Update cache
            {
                let mut cache = self.cache.lock().unwrap();
                cache.insert(
                    sub,
                    CacheEntry {
                        secrets: all_secrets,
                        loaded_at: Instant::now(),
                    },
                );
            }

            Ok(result)
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Sanitize a `sub` claim for use as a filesystem path component.
/// Replaces path separators and dangerous characters.
fn sanitize_sub(sub: &str) -> String {
    sub.replace(['/', '\\', '\0'], "_").replace(':', "_")
}

/// Expand `~` to the user's home directory.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    path.to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_sub_prevents_traversal() {
        assert_eq!(sanitize_sub("user:miguel"), "user_miguel");
        // ../etc/passwd → .. becomes .., / replaced, no traversal possible
        let sanitized = sanitize_sub("../etc/passwd");
        assert!(!sanitized.contains('/'));
        assert!(!sanitized.contains('\\'));
        assert_eq!(sanitize_sub("simple"), "simple");
    }

    #[tokio::test]
    async fn file_backend_returns_empty_for_missing_user() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = FileSecretBackend::new(tmp.path().to_path_buf(), Duration::from_secs(60));
        let result = backend.resolve("nonexistent", &["api_key"]).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn file_backend_resolves_user_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        let user_dir = tmp.path().join("test_user");
        std::fs::create_dir_all(&user_dir).unwrap();
        std::fs::write(
            user_dir.join("keys.json"),
            r#"{"api_key": "user_secret", "other": "other_val"}"#,
        )
        .unwrap();

        let backend = FileSecretBackend::new(tmp.path().to_path_buf(), Duration::from_secs(60));
        let result = backend
            .resolve("test_user", &["api_key", "missing"])
            .await
            .unwrap();
        assert_eq!(result.get("api_key").unwrap(), "user_secret");
        assert!(!result.contains_key("missing"));
        assert!(!result.contains_key("other")); // not requested
    }

    #[tokio::test]
    async fn file_backend_caches_results() {
        let tmp = tempfile::tempdir().unwrap();
        let user_dir = tmp.path().join("cached_user");
        std::fs::create_dir_all(&user_dir).unwrap();
        std::fs::write(user_dir.join("keys.json"), r#"{"key": "value1"}"#).unwrap();

        let backend = FileSecretBackend::new(tmp.path().to_path_buf(), Duration::from_secs(300));

        // First call loads from disk
        let r1 = backend.resolve("cached_user", &["key"]).await.unwrap();
        assert_eq!(r1.get("key").unwrap(), "value1");

        // Modify file — cache should still return old value
        std::fs::write(user_dir.join("keys.json"), r#"{"key": "value2"}"#).unwrap();

        let r2 = backend.resolve("cached_user", &["key"]).await.unwrap();
        assert_eq!(r2.get("key").unwrap(), "value1"); // cached
    }

    #[test]
    fn config_from_env_returns_none_when_unset() {
        // ATI_SECRET_BACKEND not set → None
        assert!(config_from_env().is_none());
    }
}
