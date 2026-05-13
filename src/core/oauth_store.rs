//! Persistence layer for OAuth 2.1 + PKCE tokens (one file per provider).
//!
//! Tokens live at `${ATI_DIR}/oauth/<provider>.json`, mode 0600. Writes are
//! atomic (write to `.tmp`, rename) so a crash mid-refresh can never produce
//! a half-written token file.
//!
//! Cross-process safety relies on a sibling `.lock` file: callers acquire an
//! exclusive `fcntl(F_SETLKW)` advisory lock for the entire read-modify-write
//! span (see `core::oauth_refresh`). The lock blocks for at most 10 seconds —
//! a deadlocked holder can't pin every other ATI process forever.
//!
//! Plaintext-on-disk for v1: refresh tokens are bearer credentials but the
//! file is mode 0600 in the operator's home directory. Encryption-at-rest is
//! a follow-up (will reuse the keyring's session-key sealing pattern).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::core::oauth_mcp::OauthError;

/// Persisted token bundle for one OAuth-authorized MCP provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderTokens {
    pub provider: String,
    pub client_id: String,
    /// Loopback redirect URI used at authorization time. Stored so we can
    /// detect a port change at next-`authorize` and re-DCR if the registered
    /// URI no longer matches the new listener port.
    pub redirect_uri: String,
    pub access_token: String,
    pub access_token_expires_at: DateTime<Utc>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub resource: String,
    /// Cached so refresh doesn't need a fresh discovery round-trip.
    pub token_endpoint: String,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    /// When this token bundle was first issued (initial code exchange).
    #[serde(default = "Utc::now")]
    pub authorized_at: DateTime<Utc>,
    /// Updated on every successful refresh.
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

impl ProviderTokens {
    pub fn is_access_expired(&self) -> bool {
        self.access_token_expires_at <= Utc::now()
    }

    pub fn access_remaining(&self) -> chrono::Duration {
        self.access_token_expires_at
            .signed_duration_since(Utc::now())
    }
}

/// `${ATI_DIR}/oauth/<provider>.json`.
pub fn path_for(provider: &str) -> PathBuf {
    crate::core::dirs::ati_dir()
        .join("oauth")
        .join(format!("{provider}.json"))
}

/// `${ATI_DIR}/oauth/<provider>.lock`.
pub fn lock_path_for(provider: &str) -> PathBuf {
    crate::core::dirs::ati_dir()
        .join("oauth")
        .join(format!("{provider}.lock"))
}

fn oauth_dir() -> PathBuf {
    crate::core::dirs::ati_dir().join("oauth")
}

fn ensure_dir() -> Result<(), OauthError> {
    let dir = oauth_dir();
    fs::create_dir_all(&dir).map_err(OauthError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&dir).map_err(OauthError::Io)?.permissions();
        perms.set_mode(0o700);
        let _ = fs::set_permissions(&dir, perms);
    }
    Ok(())
}

/// Load the token bundle for a provider. Returns `Ok(None)` if no file exists.
pub fn load(provider: &str) -> Result<Option<ProviderTokens>, OauthError> {
    let path = path_for(provider);
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path).map_err(OauthError::Io)?;
    let tokens: ProviderTokens = serde_json::from_str(&text)
        .map_err(|e| OauthError::Parse(format!("read {}: {e}", path.display())))?;
    Ok(Some(tokens))
}

/// Atomically save the token bundle for a provider. Mode 0600 on Unix.
pub fn save(tokens: &ProviderTokens) -> Result<(), OauthError> {
    ensure_dir()?;
    let path = path_for(&tokens.provider);
    let tmp = path.with_extension("json.tmp");

    let json = serde_json::to_vec_pretty(tokens)
        .map_err(|e| OauthError::Parse(format!("serialize tokens: {e}")))?;

    {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(OauthError::Io)?;
        f.write_all(&json).map_err(OauthError::Io)?;
        f.sync_all().map_err(OauthError::Io)?;
    }

    fs::rename(&tmp, &path).map_err(|e| {
        // Best-effort cleanup
        let _ = fs::remove_file(&tmp);
        OauthError::Io(e)
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        let _ = fs::set_permissions(&path, perms);
    }
    Ok(())
}

/// Delete the persisted token bundle for a provider. Idempotent.
pub fn delete(provider: &str) -> Result<(), OauthError> {
    let path = path_for(provider);
    if path.exists() {
        fs::remove_file(&path).map_err(OauthError::Io)?;
    }
    let lock = lock_path_for(provider);
    if lock.exists() {
        // OK to fail — another process may still hold the lock.
        let _ = fs::remove_file(&lock);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// fcntl advisory file lock (cross-process)
// ---------------------------------------------------------------------------

/// RAII handle for a held fcntl advisory lock. Lock is released when dropped.
pub struct FileLock {
    file: Option<File>,
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // Closing the FD releases the lock automatically on POSIX. Be explicit
        // anyway by issuing F_UNLCK first so the fd close can't be reordered
        // around an in-flight refresh in the same process.
        if let Some(f) = self.file.take() {
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                unsafe {
                    let mut fl: libc::flock = std::mem::zeroed();
                    fl.l_type = libc::F_UNLCK as i16;
                    fl.l_whence = libc::SEEK_SET as i16;
                    let _ = libc::fcntl(f.as_raw_fd(), libc::F_SETLK, &fl);
                }
            }
            drop(f);
        }
    }
}

/// Acquire an exclusive advisory lock on `<ATI_DIR>/oauth/<provider>.lock`.
/// Blocks for up to `wait` (default 10 s) before giving up.
pub fn acquire_file_lock(provider: &str) -> Result<FileLock, OauthError> {
    acquire_file_lock_with_timeout(provider, Duration::from_secs(10))
}

/// Acquire variant with caller-specified timeout (used by tests).
pub fn acquire_file_lock_with_timeout(
    provider: &str,
    timeout: Duration,
) -> Result<FileLock, OauthError> {
    ensure_dir()?;
    let path = lock_path_for(provider);

    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(&path).map_err(OauthError::Io)?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        let start = Instant::now();
        loop {
            let mut fl: libc::flock = unsafe { std::mem::zeroed() };
            fl.l_type = libc::F_WRLCK as i16;
            fl.l_whence = libc::SEEK_SET as i16;
            fl.l_start = 0;
            fl.l_len = 0;

            let rc = unsafe { libc::fcntl(fd, libc::F_SETLK, &fl) };
            if rc == 0 {
                return Ok(FileLock { file: Some(file) });
            }
            let err = std::io::Error::last_os_error();
            let raw = err.raw_os_error().unwrap_or(0);
            if raw != libc::EAGAIN && raw != libc::EACCES && raw != libc::EWOULDBLOCK {
                return Err(OauthError::Io(err));
            }
            if start.elapsed() >= timeout {
                return Err(OauthError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "timed out after {:?} waiting for OAuth lock {}",
                        timeout,
                        path.display()
                    ),
                )));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[cfg(not(unix))]
    {
        // Non-Unix fallback: take the lock as a best-effort exclusive open.
        // Cross-process safety on Windows would need LockFileEx; we don't
        // ship a Windows-target binary today. This shouldn't compile-error,
        // and lets the in-process tokio mutex still serialize callers.
        Ok(FileLock { file: Some(file) })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use tempfile::TempDir;

    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_ati_dir<F: FnOnce()>(f: F) -> TempDir {
        let _guard = match SERIAL.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let tmp = TempDir::new().unwrap();
        std::env::set_var("ATI_DIR", tmp.path());
        f();
        std::env::remove_var("ATI_DIR");
        tmp
    }

    fn sample_tokens(name: &str) -> ProviderTokens {
        ProviderTokens {
            provider: name.to_string(),
            client_id: "oc_abc".into(),
            redirect_uri: "http://127.0.0.1:9000/callback".into(),
            access_token: "AT".into(),
            access_token_expires_at: Utc::now() + Duration::seconds(3600),
            refresh_token: Some("RT".into()),
            scopes: vec!["mcp:read".into()],
            resource: "https://mcp.example.com".into(),
            token_endpoint: "https://as.example.com/token".into(),
            revocation_endpoint: Some("https://as.example.com/revoke".into()),
            authorized_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn save_load_roundtrip() {
        let _g = with_ati_dir(|| {
            let t = sample_tokens("particle");
            save(&t).unwrap();
            let loaded = load("particle").unwrap().unwrap();
            assert_eq!(loaded.provider, "particle");
            assert_eq!(loaded.access_token, "AT");
            assert_eq!(loaded.refresh_token.as_deref(), Some("RT"));
        });
    }

    #[test]
    fn load_missing_returns_none() {
        let _g = with_ati_dir(|| {
            assert!(load("missing").unwrap().is_none());
        });
    }

    #[test]
    fn delete_idempotent() {
        let _g = with_ati_dir(|| {
            delete("nope").unwrap();
            let t = sample_tokens("p");
            save(&t).unwrap();
            delete("p").unwrap();
            delete("p").unwrap();
            assert!(load("p").unwrap().is_none());
        });
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_mode_0600() {
        let _g = with_ati_dir(|| {
            use std::os::unix::fs::PermissionsExt;
            let t = sample_tokens("p");
            save(&t).unwrap();
            let meta = std::fs::metadata(path_for("p")).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        });
    }

    #[test]
    fn save_no_tmp_residue() {
        let _g = with_ati_dir(|| {
            let t = sample_tokens("p");
            save(&t).unwrap();
            let tmp = path_for("p").with_extension("json.tmp");
            assert!(!tmp.exists());
        });
    }
}
