//! Session token resolution with file-backed fallback for hot-rotation.
//!
//! Long-lived agent processes that embed `ati` as subprocesses inherit
//! `ATI_SESSION_TOKEN` at start and never see env updates. JWTs expire after
//! ~3h, leaving the agent unable to call the proxy without a restart. The
//! file-backed path lets an external supervisor rotate the token atomically;
//! the next `ati` invocation picks up the new value transparently.
//!
//! For a given env-var name `<NAME>`, resolution order (first non-empty wins):
//! 1. `<NAME>` env var
//! 2. `<NAME>_FILE` env var → file path
//! 3. Default file path derived from `<NAME>` (see [`default_token_file`])
//!
//! Each call re-reads the file from disk — no in-process caching.
//!
//! [`resolve_session_token`] is a thin wrapper for the default
//! `ATI_SESSION_TOKEN`. [`resolve_token`] takes an arbitrary env-var name so
//! per-provider tokens (e.g. `PARCHA_TOOLS_SESSION_TOKEN`) get the same
//! file-fallback + hot-rotation semantics — see issue #121.

use std::io::ErrorKind;

const DEFAULT_SESSION_TOKEN_FILE: &str = "/run/ati/session_token";

/// Compute the default file path for a given session-token env var name.
///
/// Convention: strip a trailing `_SESSION_TOKEN` suffix (either uppercase or
/// lowercase — POSIX env var names are always uppercase in practice, so we
/// don't bother with mixed-case forms like `Parcha_Tools_Session_Token`),
/// lowercase the rest, prefix with `/run/ati/`. `ATI_SESSION_TOKEN` is a
/// hardcoded exception that resolves to `/run/ati/session_token` to preserve
/// the v0.7.x deployed path (the slugify rule alone would produce
/// `/run/ati/ati`, breaking existing supervisors).
pub(crate) fn default_token_file(env_name: &str) -> String {
    if env_name == "ATI_SESSION_TOKEN" {
        return DEFAULT_SESSION_TOKEN_FILE.to_string();
    }
    let trimmed = env_name
        .strip_suffix("_SESSION_TOKEN")
        .or_else(|| env_name.strip_suffix("_session_token"))
        .unwrap_or(env_name);
    format!("/run/ati/{}", trimmed.to_lowercase())
}

/// Resolve a session token from env or a token file, for an arbitrary env
/// var name. See module docs for the resolution order.
///
/// `env_name` is e.g. `"ATI_SESSION_TOKEN"` or `"PARCHA_TOOLS_SESSION_TOKEN"`.
/// The associated file path defaults to [`default_token_file`]`(env_name)`
/// but can be overridden by `<env_name>_FILE`.
///
/// Returns:
/// - `Ok(Some(token))` if a non-empty token was found
/// - `Ok(None)` if no source supplied a token (env unset/empty, file missing or empty)
/// - `Err(msg)` only if a configured file path exists but cannot be read
///   (e.g., permission denied)
pub fn resolve_token(env_name: &str) -> Result<Option<String>, String> {
    if let Ok(raw) = std::env::var(env_name) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed.to_string()));
        }
    }

    let file_env = format!("{env_name}_FILE");
    let path = std::env::var(&file_env)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_token_file(env_name));

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

/// Resolve the default session token (`ATI_SESSION_TOKEN`). Thin wrapper
/// around [`resolve_token`] preserved for callers that don't care about
/// per-provider token selection (issue #121).
pub fn resolve_session_token() -> Result<Option<String>, String> {
    resolve_token("ATI_SESSION_TOKEN")
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

    // -----------------------------------------------------------------------
    // Per-provider token resolution (issue #121).
    //
    // `resolve_token(env_name)` generalizes the session-token resolver so
    // that a manifest's `auth_session_token_env` can name any env var (e.g.
    // `PARCHA_TOOLS_SESSION_TOKEN`) and get the same env → file → default
    // semantics that `ATI_SESSION_TOKEN` enjoys. Tests below cover:
    //   - arbitrary env name short-circuits
    //   - `<NAME>_FILE` fallback fires
    //   - `default_token_file` slugify rule
    //   - `resolve_session_token()` wrapper is still semantically identical
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_token_reads_arbitrary_env_var() {
        let _g = ENV_LOCK.lock().unwrap();
        let _e = EnvGuard::set(&[("PARCHA_TOOLS_SESSION_TOKEN", Some("parcha-tok"))]);
        assert_eq!(
            resolve_token("PARCHA_TOOLS_SESSION_TOKEN").unwrap(),
            Some("parcha-tok".to_string())
        );
    }

    #[test]
    fn resolve_token_falls_back_to_named_file_env() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ptok");
        std::fs::write(&path, "file-tok").unwrap();
        let _e = EnvGuard::set(&[
            ("PARCHA_TOOLS_SESSION_TOKEN", None),
            (
                "PARCHA_TOOLS_SESSION_TOKEN_FILE",
                Some(path.to_str().unwrap()),
            ),
        ]);
        assert_eq!(
            resolve_token("PARCHA_TOOLS_SESSION_TOKEN").unwrap(),
            Some("file-tok".to_string())
        );
    }

    #[test]
    fn resolve_token_empty_env_falls_through_to_file() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ptok");
        std::fs::write(&path, "from-file").unwrap();
        let _e = EnvGuard::set(&[
            ("PARCHA_TOOLS_SESSION_TOKEN", Some("")),
            (
                "PARCHA_TOOLS_SESSION_TOKEN_FILE",
                Some(path.to_str().unwrap()),
            ),
        ]);
        assert_eq!(
            resolve_token("PARCHA_TOOLS_SESSION_TOKEN").unwrap(),
            Some("from-file".to_string())
        );
    }

    #[test]
    fn resolve_session_token_wrapper_back_compat() {
        // The wrapper must behave identically to calling
        // resolve_token("ATI_SESSION_TOKEN") — that's the contract a v0.7.11
        // user relies on (no caller changes).
        let _g = ENV_LOCK.lock().unwrap();
        let _e = EnvGuard::set(&[("ATI_SESSION_TOKEN", Some("wrapped-tok"))]);
        assert_eq!(
            resolve_session_token().unwrap(),
            resolve_token("ATI_SESSION_TOKEN").unwrap(),
        );
        assert_eq!(
            resolve_session_token().unwrap(),
            Some("wrapped-tok".to_string())
        );
    }

    #[test]
    fn default_token_file_hardcoded_ati_session_token() {
        // Preserves the v0.7.x deployed path. Hardcoded because the slugify
        // rule would otherwise produce `/run/ati/ati`, breaking supervisors.
        assert_eq!(
            default_token_file("ATI_SESSION_TOKEN"),
            "/run/ati/session_token"
        );
    }

    #[test]
    fn default_token_file_strips_session_token_suffix() {
        assert_eq!(
            default_token_file("PARCHA_TOOLS_SESSION_TOKEN"),
            "/run/ati/parcha_tools"
        );
        assert_eq!(
            default_token_file("FOO_BAR_SESSION_TOKEN"),
            "/run/ati/foo_bar"
        );
    }

    #[test]
    fn default_token_file_lowercases_when_no_suffix_to_strip() {
        assert_eq!(default_token_file("CUSTOM_TOKEN"), "/run/ati/custom_token");
        assert_eq!(default_token_file("FOO"), "/run/ati/foo");
    }
}
