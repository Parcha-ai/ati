//! Optional-DB invariants for the proxy:
//!
//!   - `DbState::Disabled` is the default — no env touching needed
//!   - `/health` reports `db: "disabled"` so operators can tell at a glance
//!   - `connect_optional` returns `Disabled` cleanly when `ATI_DB_URL` is unset
//!     or empty
//!
//! Live-Postgres tests (verifying that `connect_optional` actually opens a pool
//! and `run_migrations` applies SQL) need a real DB and live in a separate
//! `--ignored` file so CI doesn't require Postgres.

use ati::core::db::{connect_optional, run_migrations, DbState};
use std::sync::Mutex;

/// Serialize env-var mutating tests. Cargo runs test functions across multiple
/// OS threads; without this, two tests touching `ATI_DB_URL` would race.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Snapshot one env var, run the body, restore on Drop. Panic-safe.
fn with_env<R>(key: &str, value: Option<&str>, body: impl FnOnce() -> R) -> R {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev = std::env::var(key).ok();
    match value {
        Some(v) => std::env::set_var(key, v),
        None => std::env::remove_var(key),
    }
    struct Restore<'a> {
        key: &'a str,
        prev: Option<String>,
    }
    impl<'a> Drop for Restore<'a> {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }
    let _restore = Restore { key, prev };
    body()
}

#[tokio::test]
async fn db_state_disabled_reports_disabled() {
    let state = DbState::Disabled;
    assert!(!state.is_connected());
    assert_eq!(state.status(), "disabled");
}

#[tokio::test]
async fn run_migrations_is_noop_when_disabled() {
    // Must be safe to leave `ati proxy --migrate` in production startup
    // scripts even when ATI_DB_URL is unset.
    let state = DbState::Disabled;
    run_migrations(&state)
        .await
        .expect("noop migration on disabled state should succeed");
}

#[tokio::test]
async fn connect_optional_unset_env_returns_disabled() {
    let state = with_env("ATI_DB_URL", None, || {
        futures::executor::block_on(connect_optional())
    })
    .expect("unset ATI_DB_URL must not error");
    assert!(!state.is_connected());
}

#[tokio::test]
async fn connect_optional_empty_env_returns_disabled() {
    let state = with_env("ATI_DB_URL", Some(""), || {
        futures::executor::block_on(connect_optional())
    })
    .expect("empty ATI_DB_URL must be treated as unset, not error");
    assert!(!state.is_connected());
}

/// When the binary is built without `--features db` but ATI_DB_URL is set, we
/// surface a loud error so the operator notices instead of silently ignoring
/// their config.
#[cfg(not(feature = "db"))]
#[tokio::test]
async fn connect_optional_set_env_without_feature_errors() {
    let result = with_env("ATI_DB_URL", Some("postgres://example/db"), || {
        futures::executor::block_on(connect_optional())
    });
    assert!(
        result.is_err(),
        "ATI_DB_URL set without db feature should produce a clear error"
    );
}
