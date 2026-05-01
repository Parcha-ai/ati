//! PR 1 invariants: the proxy starts and serves /health correctly whether
//! the DB feature is on or off, and whether ATI_DB_URL is set or not.
//!
//! What this test pins down:
//!   - `DbState::Disabled` is the default, no env touching needed
//!   - `/health` reports `db: "disabled"` so operators can tell at a glance
//!   - `connect_optional` returns `Disabled` cleanly when the env var is unset
//!     or empty
//!
//! Live-Postgres tests (verifying `connect_optional` actually opens a pool and
//! `run_migrations` applies SQL) are intentionally NOT in this file. They need
//! a real DB; we'll add them in a follow-up `db_live_test.rs` gated behind
//! `--ignored` so CI doesn't require Postgres.

use ati::core::db::{connect_optional, run_migrations, DbState};

#[tokio::test]
async fn db_state_disabled_reports_disabled() {
    let state = DbState::Disabled;
    assert!(!state.is_connected());
    assert_eq!(state.status(), "disabled");
}

#[tokio::test]
async fn run_migrations_is_noop_when_disabled() {
    // run_migrations on a Disabled state must be a clean no-op so
    // `ati proxy --migrate` is safe to leave in production startup scripts
    // even when the DB isn't configured.
    let state = DbState::Disabled;
    run_migrations(&state)
        .await
        .expect("noop migration on disabled state should succeed");
}

#[tokio::test]
async fn connect_optional_unset_env_returns_disabled() {
    // Snapshot + clear so other tests in this binary don't observe our mutation.
    let prev = std::env::var("ATI_DB_URL").ok();
    unsafe {
        std::env::remove_var("ATI_DB_URL");
    }

    let state = connect_optional()
        .await
        .expect("unset ATI_DB_URL must not error");
    assert!(!state.is_connected());

    if let Some(v) = prev {
        unsafe {
            std::env::set_var("ATI_DB_URL", v);
        }
    }
}

#[tokio::test]
async fn connect_optional_empty_env_returns_disabled() {
    let prev = std::env::var("ATI_DB_URL").ok();
    unsafe {
        std::env::set_var("ATI_DB_URL", "");
    }

    let state = connect_optional()
        .await
        .expect("empty ATI_DB_URL must be treated as unset, not error");
    assert!(!state.is_connected());

    match prev {
        Some(v) => unsafe { std::env::set_var("ATI_DB_URL", v) },
        None => unsafe { std::env::remove_var("ATI_DB_URL") },
    }
}

/// When the binary is built without `--features db` but ATI_DB_URL is set, we
/// surface a loud error so the operator notices instead of silently ignoring
/// their config.
#[cfg(not(feature = "db"))]
#[tokio::test]
async fn connect_optional_set_env_without_feature_errors() {
    let prev = std::env::var("ATI_DB_URL").ok();
    unsafe {
        std::env::set_var("ATI_DB_URL", "postgres://example/db");
    }

    let result = connect_optional().await;
    assert!(
        result.is_err(),
        "ATI_DB_URL set without db feature should produce a clear error"
    );

    match prev {
        Some(v) => unsafe { std::env::set_var("ATI_DB_URL", v) },
        None => unsafe { std::env::remove_var("ATI_DB_URL") },
    }
}
