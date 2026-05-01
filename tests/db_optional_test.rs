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

mod common;

use ati::core::db::{connect_optional, run_migrations, DbState};
use common::EnvGuard;

#[test]
fn db_state_disabled_reports_disabled() {
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
    let _guard = EnvGuard::set("ATI_DB_URL", None).await;
    let state = connect_optional()
        .await
        .expect("unset ATI_DB_URL must not error");
    assert!(!state.is_connected());
}

#[tokio::test]
async fn connect_optional_empty_env_returns_disabled() {
    let _guard = EnvGuard::set("ATI_DB_URL", Some("")).await;
    let state = connect_optional()
        .await
        .expect("empty ATI_DB_URL must be treated as unset, not error");
    assert!(!state.is_connected());
}

/// When the binary is built without `--features db` but ATI_DB_URL is set, we
/// surface a loud error so the operator notices instead of silently ignoring
/// their config.
#[cfg(not(feature = "db"))]
#[tokio::test]
async fn connect_optional_set_env_without_feature_errors() {
    let _guard = EnvGuard::set("ATI_DB_URL", Some("postgres://example/db")).await;
    let result = connect_optional().await;
    assert!(
        result.is_err(),
        "ATI_DB_URL set without db feature should produce a clear error"
    );
}
