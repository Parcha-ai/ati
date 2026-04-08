use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use thiserror::Error;

use crate::core::auth_generator::{self, AuthCache, GenContext};
use crate::core::manifest::Provider;
use crate::core::secret_resolver::SecretResolver;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum CliError {
    #[error("CLI config error: {0}")]
    Config(String),
    #[error("Missing keyring key: {0}")]
    MissingKey(String),
    #[error("Failed to spawn CLI process: {0}")]
    Spawn(String),
    #[error("CLI timed out after {0}s")]
    Timeout(u64),
    #[error("CLI exited with code {code}: {stderr}")]
    NonZeroExit { code: i32, stderr: String },
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Credential file error: {0}")]
    CredentialFile(String),
}

// ---------------------------------------------------------------------------
// CredentialFile — wipe-on-drop temporary credential files
// ---------------------------------------------------------------------------

pub struct CredentialFile {
    pub path: PathBuf,
    wipe_on_drop: bool,
}

impl Drop for CredentialFile {
    fn drop(&mut self) {
        if self.wipe_on_drop {
            // Best-effort overwrite with zeros then delete
            if let Ok(meta) = std::fs::metadata(&self.path) {
                let len = meta.len() as usize;
                if len > 0 {
                    if let Ok(file) = std::fs::OpenOptions::new().write(true).open(&self.path) {
                        use std::io::Write;
                        let zeros = vec![0u8; len];
                        let _ = (&file).write_all(&zeros);
                        let _ = file.sync_all();
                    }
                }
            }
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

// ---------------------------------------------------------------------------
// Credential file materialization
// ---------------------------------------------------------------------------

/// Materialize a keyring secret as a file on disk with 0600 permissions.
///
/// In dev mode (`wipe_on_drop = false`), uses a stable path so repeated runs
/// reuse the same file. In prod mode (`wipe_on_drop = true`), appends a random
/// suffix so concurrent invocations don't collide.
pub fn materialize_credential_file(
    key_name: &str,
    content: &str,
    wipe_on_drop: bool,
    ati_dir: &Path,
) -> Result<CredentialFile, CliError> {
    use std::os::unix::fs::OpenOptionsExt;

    let creds_dir = ati_dir.join(".creds");
    std::fs::create_dir_all(&creds_dir).map_err(|e| {
        CliError::CredentialFile(format!("failed to create {}: {e}", creds_dir.display()))
    })?;

    let path = if wipe_on_drop {
        let suffix: u32 = rand::random();
        creds_dir.join(format!("{key_name}_{suffix}"))
    } else {
        creds_dir.join(key_name)
    };

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| {
            CliError::CredentialFile(format!("failed to write {}: {e}", path.display()))
        })?;

    {
        use std::io::Write;
        file.write_all(content.as_bytes()).map_err(|e| {
            CliError::CredentialFile(format!("failed to write {}: {e}", path.display()))
        })?;
        file.sync_all().map_err(|e| {
            CliError::CredentialFile(format!("failed to sync {}: {e}", path.display()))
        })?;
    }

    Ok(CredentialFile { path, wipe_on_drop })
}

// ---------------------------------------------------------------------------
// Env resolution
// ---------------------------------------------------------------------------

/// Resolve `${key_ref}` placeholders in a string from the keyring.
/// Same logic as `resolve_env_value` in `mcp_client.rs`.
fn resolve_env_value(value: &str, keyring: &SecretResolver<'_>) -> Result<String, CliError> {
    let mut result = value.to_string();
    while let Some(start) = result.find("${") {
        let rest = &result[start + 2..];
        if let Some(end) = rest.find('}') {
            let key_name = &rest[..end];
            let replacement = keyring
                .get(key_name)
                .ok_or_else(|| CliError::MissingKey(key_name.to_string()))?;
            result = format!("{}{}{}", &result[..start], replacement, &rest[end + 1..]);
        } else {
            break; // No closing brace
        }
    }
    Ok(result)
}

/// Resolve a provider's `cli_env` map against the keyring.
///
/// Three value forms:
/// - `@{key_ref}`: materialize the keyring value as a credential file; env value = file path
/// - `${key_ref}` (possibly inline): substitute from keyring
/// - plain string: pass through unchanged
///
/// Returns the resolved env map and a vec of `CredentialFile`s whose lifetimes
/// must span the subprocess execution (they are wiped on drop).
pub fn resolve_cli_env(
    env_map: &HashMap<String, String>,
    keyring: &SecretResolver<'_>,
    wipe_on_drop: bool,
    ati_dir: &Path,
) -> Result<(HashMap<String, String>, Vec<CredentialFile>), CliError> {
    let mut resolved = HashMap::with_capacity(env_map.len());
    let mut cred_files: Vec<CredentialFile> = Vec::new();

    for (key, value) in env_map {
        if let Some(key_ref) = value.strip_prefix("@{").and_then(|s| s.strip_suffix('}')) {
            // File-materialized credential
            let content = keyring
                .get(key_ref)
                .ok_or_else(|| CliError::MissingKey(key_ref.to_string()))?;
            let cf = materialize_credential_file(key_ref, content, wipe_on_drop, ati_dir)?;
            resolved.insert(key.clone(), cf.path.to_string_lossy().into_owned());
            cred_files.push(cf);
        } else if value.contains("${") {
            // Inline keyring substitution
            let val = resolve_env_value(value, keyring)?;
            resolved.insert(key.clone(), val);
        } else {
            // Plain passthrough
            resolved.insert(key.clone(), value.clone());
        }
    }

    Ok((resolved, cred_files))
}

// ---------------------------------------------------------------------------
// Execute CLI tool
// ---------------------------------------------------------------------------

/// Execute a CLI provider tool as a subprocess.
///
/// Builds a curated environment (only safe vars from the host + resolved
/// provider env), spawns the CLI command with the provider's default args
/// plus the caller's raw args, enforces a timeout, and returns stdout
/// parsed as JSON (or as a plain string fallback).
pub async fn execute(
    provider: &Provider,
    raw_args: &[String],
    keyring: &SecretResolver<'_>,
) -> Result<serde_json::Value, CliError> {
    execute_with_gen(provider, raw_args, keyring, None, None).await
}

/// Execute a CLI provider tool, optionally using a dynamic auth generator.
pub async fn execute_with_gen(
    provider: &Provider,
    raw_args: &[String],
    keyring: &SecretResolver<'_>,
    gen_ctx: Option<&GenContext>,
    auth_cache: Option<&AuthCache>,
) -> Result<serde_json::Value, CliError> {
    let cli_command = provider
        .cli_command
        .as_deref()
        .ok_or_else(|| CliError::Config("provider missing cli_command".into()))?;

    let timeout_secs = provider.cli_timeout_secs.unwrap_or(120);

    let ati_dir = std::env::var("ATI_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/tmp"))
                .join(".ati")
        });

    let wipe_on_drop = keyring.ephemeral();

    // Resolve provider CLI env vars against keyring.
    // cred_files must live until after the subprocess exits (Drop does cleanup).
    let (resolved_env, cred_files) =
        resolve_cli_env(&provider.cli_env, keyring, wipe_on_drop, &ati_dir)?;

    // Build curated base env from host
    let mut final_env: HashMap<String, String> = HashMap::new();
    for var in &["PATH", "HOME", "TMPDIR", "LANG", "USER", "TERM"] {
        if let Ok(val) = std::env::var(var) {
            final_env.insert(var.to_string(), val);
        }
    }
    // Layer provider-resolved env on top
    final_env.extend(resolved_env);

    // If auth_generator is configured, run it and inject into env
    if let Some(gen) = &provider.auth_generator {
        let default_ctx = GenContext::default();
        let ctx = gen_ctx.unwrap_or(&default_ctx);
        let default_cache = AuthCache::new();
        let cache = auth_cache.unwrap_or(&default_cache);
        match auth_generator::generate(provider, gen, ctx, keyring, cache).await {
            Ok(cred) => {
                final_env.insert("ATI_AUTH_TOKEN".to_string(), cred.value);
                for (k, v) in &cred.extra_env {
                    final_env.insert(k.clone(), v.clone());
                }
            }
            Err(e) => {
                return Err(CliError::Config(format!("auth_generator failed: {e}")));
            }
        }
    }

    // Clone values for the blocking closure
    let command = cli_command.to_string();
    let default_args = provider.cli_default_args.clone();
    let extra_args = raw_args.to_vec();
    let env_snapshot = final_env;
    let timeout_dur = std::time::Duration::from_secs(timeout_secs);

    // Spawn the subprocess via tokio::process so we get an async-aware child
    // that we can kill on timeout (unlike spawn_blocking + std::process which
    // would leave the subprocess running when the timeout fires).
    let child = tokio::process::Command::new(&command)
        .args(&default_args)
        .args(&extra_args)
        .env_clear()
        .envs(&env_snapshot)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| CliError::Spawn(format!("{command}: {e}")))?;

    // Apply timeout — kill_on_drop ensures the child is killed if we bail early
    let output = tokio::time::timeout(timeout_dur, child.wait_with_output())
        .await
        .map_err(|_| CliError::Timeout(timeout_secs))?
        .map_err(CliError::Io)?;

    // cred_files still alive here — drop explicitly after subprocess exits
    drop(cred_files);

    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(CliError::NonZeroExit { code, stderr });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value = match serde_json::from_str::<serde_json::Value>(stdout.trim()) {
        Ok(v) => v,
        Err(_) => serde_json::Value::String(stdout.trim().to_string()),
    };

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_materialize_credential_file_dev_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let cf = materialize_credential_file("test_key", "secret123", false, tmp.path()).unwrap();
        assert_eq!(cf.path, tmp.path().join(".creds/test_key"));
        let content = fs::read_to_string(&cf.path).unwrap();
        assert_eq!(content, "secret123");

        // Check permissions (unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&cf.path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn test_materialize_credential_file_prod_mode_unique() {
        let tmp = tempfile::tempdir().unwrap();
        let cf1 = materialize_credential_file("key", "val1", true, tmp.path()).unwrap();
        let cf2 = materialize_credential_file("key", "val2", true, tmp.path()).unwrap();
        // Prod mode paths should differ (random suffix)
        assert_ne!(cf1.path, cf2.path);
    }

    #[test]
    fn test_credential_file_wipe_on_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let path;
        {
            let cf = materialize_credential_file("wipe_me", "sensitive", true, tmp.path()).unwrap();
            path = cf.path.clone();
            assert!(path.exists());
        }
        // After drop, file should be deleted
        assert!(!path.exists());
    }
}
