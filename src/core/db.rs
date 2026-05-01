//! Optional Postgres persistence layer.
//!
//! Opt-in at compile time (Cargo feature `db`) and at runtime (env var
//! `ATI_DB_URL`). When either is off, the proxy works exactly as before — no
//! DB calls, no crashes if Postgres is down.
//!
//! Future work in this area (call audit log, virtual keys) layers on top of
//! the pool exposed here.
//!
//! ## Operator UX
//!
//! ```ignore
//! export ATI_DB_URL=postgres://ati:secret@db:5432/ati
//! ati proxy --migrate   # apply migrations on startup, then serve
//! ati proxy             # serve without running migrations (production)
//! ```
//!
//! ## Failure semantics
//!
//! Connection failures at startup are surfaced loudly so operators notice. Once
//! the proxy is running, the DB is treated as best-effort: dropping a row is
//! preferable to dropping a request. Downstream writers must use a bounded
//! channel and swallow DB errors after a single `tracing::warn!`.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[cfg(feature = "db")]
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[cfg(feature = "db")]
    #[error("migrate error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("ATI built without `db` feature; rebuild with --features db to use ATI_DB_URL")]
    FeatureDisabled,
}

/// State of the persistence layer.
///
/// `Disabled` is the normal case — no `ATI_DB_URL` set, or built without the
/// `db` feature. `Connected` carries a live pool that downstream writers borrow
/// via [`DbState::pool`].
#[derive(Clone)]
pub enum DbState {
    Disabled,
    #[cfg(feature = "db")]
    Connected(sqlx::PgPool),
}

impl DbState {
    /// True when a live pool is available.
    pub fn is_connected(&self) -> bool {
        match self {
            DbState::Disabled => false,
            #[cfg(feature = "db")]
            DbState::Connected(_) => true,
        }
    }

    /// Borrow the pool if connected.
    #[cfg(feature = "db")]
    pub fn pool(&self) -> Option<&sqlx::PgPool> {
        match self {
            DbState::Disabled => None,
            DbState::Connected(p) => Some(p),
        }
    }

    /// Status string for `/health` reporting.
    pub fn status(&self) -> &'static str {
        match self {
            DbState::Disabled => "disabled",
            #[cfg(feature = "db")]
            DbState::Connected(_) => "connected",
        }
    }
}

impl std::fmt::Debug for DbState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbState")
            .field("status", &self.status())
            .finish()
    }
}

/// Connect to Postgres if `ATI_DB_URL` is set; otherwise return `Disabled`.
///
/// `PgPoolOptions::connect()` opens and validates one connection before
/// returning, so the operator gets fail-fast semantics without a separate
/// round-trip from us.
#[cfg(feature = "db")]
pub async fn connect_optional() -> Result<DbState, DbError> {
    let Ok(url) = std::env::var("ATI_DB_URL") else {
        return Ok(DbState::Disabled);
    };
    if url.trim().is_empty() {
        return Ok(DbState::Disabled);
    }

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&url)
        .await?;

    Ok(DbState::Connected(pool))
}

#[cfg(not(feature = "db"))]
pub async fn connect_optional() -> Result<DbState, DbError> {
    if std::env::var("ATI_DB_URL")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
    {
        return Err(DbError::FeatureDisabled);
    }
    Ok(DbState::Disabled)
}

/// Apply migrations if connected. No-op when disabled.
///
/// Embeds `migrations/*.sql` at compile time, so the running binary always
/// carries the schema it expects. Safe to call multiple times — sqlx tracks
/// applied migrations in `_sqlx_migrations`.
#[cfg(feature = "db")]
pub async fn run_migrations(state: &DbState) -> Result<(), DbError> {
    if let DbState::Connected(pool) = state {
        sqlx::migrate!("./migrations").run(pool).await?;
    }
    Ok(())
}

#[cfg(not(feature = "db"))]
pub async fn run_migrations(_state: &DbState) -> Result<(), DbError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialize env-var mutating tests across the binary.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Snapshot a single env var, run the body, restore on Drop. Panic-safe.
    /// Tests that touch `ATI_DB_URL` MUST go through this helper, otherwise
    /// they race with each other under cargo's multi-threaded test runner.
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
    async fn disabled_when_env_unset() {
        let state = with_env("ATI_DB_URL", None, || {
            futures::executor::block_on(connect_optional())
        })
        .expect("disabled is not an error");
        assert!(!state.is_connected());
        assert_eq!(state.status(), "disabled");
    }

    #[tokio::test]
    async fn disabled_when_env_empty() {
        let state = with_env("ATI_DB_URL", Some(""), || {
            futures::executor::block_on(connect_optional())
        })
        .expect("empty is treated as unset");
        assert!(!state.is_connected());
    }

    #[tokio::test]
    async fn run_migrations_noop_when_disabled() {
        let state = DbState::Disabled;
        run_migrations(&state).await.expect("no-op should succeed");
    }
}
