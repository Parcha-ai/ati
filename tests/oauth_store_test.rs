//! Integration tests for the OAuth token persistence layer.
//!
//! Tests use `ATI_DIR` overrides + tempdirs; each test owns its own dir so
//! they can run in parallel without interference.

use chrono::{Duration, Utc};
use tempfile::TempDir;

use ati::core::oauth_store::{self, delete, load, path_for, save, ProviderTokens};

fn sample(name: &str) -> ProviderTokens {
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

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct EnvGuard {
    _tmp: TempDir,
    _guard: std::sync::MutexGuard<'static, ()>,
}

fn with_tmp_ati_dir() -> EnvGuard {
    let guard = match SERIAL.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let tmp = TempDir::new().unwrap();
    std::env::set_var("ATI_DIR", tmp.path());
    EnvGuard {
        _tmp: tmp,
        _guard: guard,
    }
}

#[test]
fn save_load_roundtrip() {
    let _g = with_tmp_ati_dir();
    let t = sample("p1");
    save(&t).unwrap();
    let loaded = load("p1").unwrap().unwrap();
    assert_eq!(loaded.provider, "p1");
    assert_eq!(loaded.access_token, "AT");
    assert_eq!(loaded.refresh_token.as_deref(), Some("RT"));
    assert_eq!(loaded.scopes, vec!["mcp:read"]);
    std::env::remove_var("ATI_DIR");
}

#[test]
fn load_missing_returns_none() {
    let _g = with_tmp_ati_dir();
    assert!(load("nonexistent").unwrap().is_none());
    std::env::remove_var("ATI_DIR");
}

#[test]
fn delete_idempotent() {
    let _g = with_tmp_ati_dir();
    delete("nope").unwrap();
    let t = sample("d1");
    save(&t).unwrap();
    delete("d1").unwrap();
    delete("d1").unwrap();
    assert!(load("d1").unwrap().is_none());
    std::env::remove_var("ATI_DIR");
}

#[cfg(unix)]
#[test]
fn save_writes_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let _g = with_tmp_ati_dir();
    let t = sample("p2");
    save(&t).unwrap();
    let meta = std::fs::metadata(path_for("p2")).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    std::env::remove_var("ATI_DIR");
}

#[test]
fn save_no_tmp_residue() {
    let _g = with_tmp_ati_dir();
    let t = sample("p3");
    save(&t).unwrap();
    let tmp_file = path_for("p3").with_extension("json.tmp");
    assert!(!tmp_file.exists(), "atomic-write tmp file should be gone");
    std::env::remove_var("ATI_DIR");
}

#[cfg(unix)]
#[test]
fn lock_acquires_then_releases() {
    let _g = with_tmp_ati_dir();
    {
        let _lock = oauth_store::acquire_file_lock("p4").unwrap();
        // Holding the lock; a second acquire from the same process should
        // also succeed because fcntl locks are per-process (advisory).
        // What we care about for the test is just that release works.
    }
    // Re-acquire after release succeeds.
    let _lock = oauth_store::acquire_file_lock("p4").unwrap();
    std::env::remove_var("ATI_DIR");
}

// Note: a cross-process lock test is intentionally omitted here.
// `flock(1)` from util-linux uses BSD-style flock(2), which doesn't
// contend with POSIX fcntl(F_SETLK) locks on Linux. A faithful
// cross-process test would need to spawn another `cargo test` binary
// that uses the same fcntl path — overkill for unit coverage. The
// in-process tests above + the live Particle E2E exercise the lock
// codepath end-to-end.
#[allow(dead_code)]
fn _lock_path_used(_provider: &str) -> std::path::PathBuf {
    path_for("dummy").with_extension("lock")
}
