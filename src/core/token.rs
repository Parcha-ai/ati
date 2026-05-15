//! Session token resolution with file-backed fallback for hot-rotation.
//!
//! Long-lived agent processes that embed `ati` as subprocesses inherit
//! `ATI_SESSION_TOKEN` at start and never see env updates. JWTs expire after
//! ~3h, leaving the agent unable to call the proxy without a restart. The
//! file-backed path lets an external supervisor rotate the token atomically;
//! the next `ati` invocation picks up the new value transparently.
//!
//! Resolution order (first non-empty wins):
//! 1. `ATI_SESSION_TOKEN` env var
//! 2. `ATI_SESSION_TOKEN_FILE` env var → file path
//! 3. `/run/ati/session_token` default path
//!
//! Each call re-reads the file from disk — no in-process caching.

use std::io::ErrorKind;

const DEFAULT_TOKEN_FILE: &str = "/run/ati/session_token";

/// Resolve the active session token from env or a token file.
///
/// Returns:
/// - `Ok(Some(token))` if a non-empty token was found
/// - `Ok(None)` if no source supplied a token (env unset/empty, file missing or empty)
/// - `Err(msg)` only if a configured file path exists but cannot be read (e.g., permission denied)
pub fn resolve_session_token() -> Result<Option<String>, String> {
    if let Ok(raw) = std::env::var("ATI_SESSION_TOKEN") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed.to_string()));
        }
    }

    let path = std::env::var("ATI_SESSION_TOKEN_FILE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_TOKEN_FILE.to_string());

    match std::fs::read_to_string(&path) {
        Ok(contents) => {
            let trimmed = contents.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("Cannot read {path}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The helper reads process-wide env vars. Tests must serialize to avoid
    // clobbering each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        keys: Vec<&'static str>,
        prev: Vec<(String, Option<String>)>,
    }

    impl EnvGuard {
        fn set(pairs: &[(&'static str, Option<&str>)]) -> Self {
            let mut prev = Vec::new();
            let mut keys = Vec::new();
            for (k, v) in pairs {
                prev.push(((*k).to_string(), std::env::var(k).ok()));
                keys.push(*k);
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
            Self { keys, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.prev {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
            // belt-and-suspenders: ensure nothing leaks
            let _ = &self.keys;
        }
    }

    #[test]
    fn env_var_wins_over_file() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tok");
        std::fs::write(&path, "from-file").unwrap();
        let _e = EnvGuard::set(&[
            ("ATI_SESSION_TOKEN", Some("from-env")),
            ("ATI_SESSION_TOKEN_FILE", Some(path.to_str().unwrap())),
        ]);
        assert_eq!(
            resolve_session_token().unwrap(),
            Some("from-env".to_string())
        );
    }

    #[test]
    fn empty_env_falls_through_to_file_and_rereads() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tok");
        std::fs::write(&path, "tok-v1").unwrap();
        let _e = EnvGuard::set(&[
            ("ATI_SESSION_TOKEN", Some("")),
            ("ATI_SESSION_TOKEN_FILE", Some(path.to_str().unwrap())),
        ]);
        assert_eq!(resolve_session_token().unwrap(), Some("tok-v1".to_string()));

        // Overwrite the file; next call must see the new value (no caching).
        std::fs::write(&path, "tok-v2").unwrap();
        assert_eq!(resolve_session_token().unwrap(), Some("tok-v2".to_string()));
    }

    #[test]
    fn trims_whitespace_in_file_contents() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tok");
        std::fs::write(&path, "  hello-tok\n\n").unwrap();
        let _e = EnvGuard::set(&[
            ("ATI_SESSION_TOKEN", None),
            ("ATI_SESSION_TOKEN_FILE", Some(path.to_str().unwrap())),
        ]);
        assert_eq!(
            resolve_session_token().unwrap(),
            Some("hello-tok".to_string())
        );
    }

    #[test]
    fn empty_file_returns_none() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tok");
        std::fs::write(&path, "   \n\t").unwrap();
        let _e = EnvGuard::set(&[
            ("ATI_SESSION_TOKEN", None),
            ("ATI_SESSION_TOKEN_FILE", Some(path.to_str().unwrap())),
        ]);
        assert_eq!(resolve_session_token().unwrap(), None);
    }

    #[test]
    fn missing_file_no_env_returns_none() {
        let _g = ENV_LOCK.lock().unwrap();
        let _e = EnvGuard::set(&[
            ("ATI_SESSION_TOKEN", None),
            (
                "ATI_SESSION_TOKEN_FILE",
                Some("/nonexistent/path/never/exists/session_token"),
            ),
        ]);
        assert_eq!(resolve_session_token().unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_file_returns_err_with_path() {
        use std::os::unix::fs::PermissionsExt;

        // Skip when running as root — root bypasses unix permission bits, so we
        // can't simulate "permission denied" reliably.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping unreadable_file_returns_err_with_path: running as root");
            return;
        }

        let _g = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tok");
        std::fs::write(&path, "secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let _e = EnvGuard::set(&[
            ("ATI_SESSION_TOKEN", None),
            ("ATI_SESSION_TOKEN_FILE", Some(path.to_str().unwrap())),
        ]);
        let err = resolve_session_token().unwrap_err();
        assert!(err.contains("Cannot read"), "unexpected error: {err}");
        assert!(
            err.contains(path.to_str().unwrap()),
            "error should mention path: {err}"
        );

        // Restore perms so tempdir can clean up.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
}
