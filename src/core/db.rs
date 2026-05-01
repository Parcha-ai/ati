//! Optional Postgres persistence layer.
//!
//! ATI's persistence layer is **opt-in** at compile time (Cargo feature `db`)
//! and **opt-in** at runtime (env var `ATI_DB_URL`). When either is off, the
//! proxy works exactly as before — no DB calls, no crashes if Postgres is down.
//!
//! Subsequent PRs build on top of this:
//!   - PR 2 writes to `ati_call_log` from the proxy request path
//!   - PR 3 reads/writes `ati_keys` for virtual-key auth
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
//! preferable to dropping a request. PR 2 enforces this via an async write
//! queue with a bounded channel.

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
/// `db` feature. `Connected` carries the live pool that PR 2 / PR 3 will use.
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

    /// Borrow the pool if connected. PRs 2 and 3 use this from request handlers.
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
/// Connection failures are returned as errors so the operator can decide
/// (fail-fast vs. degrade). The proxy's startup path treats this as fatal —
/// if you set `ATI_DB_URL` you mean it.
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

    // Cheap round-trip to confirm the connection is real before we report it
    // as Connected. PgPool can lazy-connect, which would defer failure until
    // the first query — surprising for operators.
    sqlx::query("SELECT 1").execute(&pool).await?;

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

    #[tokio::test]
    async fn disabled_when_env_unset() {
        // Save and clear ATI_DB_URL so this test is deterministic.
        let prev = std::env::var("ATI_DB_URL").ok();
        // SAFETY: tests in this binary run single-threaded by default for env
        // mutations; if we ever run them in parallel, gate with a mutex.
        unsafe {
            std::env::remove_var("ATI_DB_URL");
        }

        let state = connect_optional().await.expect("disabled is not an error");
        assert!(!state.is_connected());
        assert_eq!(state.status(), "disabled");

        if let Some(v) = prev {
            unsafe {
                std::env::set_var("ATI_DB_URL", v);
            }
        }
    }

    #[tokio::test]
    async fn disabled_when_env_empty() {
        let prev = std::env::var("ATI_DB_URL").ok();
        unsafe {
            std::env::set_var("ATI_DB_URL", "");
        }

        let state = connect_optional().await.expect("empty is treated as unset");
        assert!(!state.is_connected());

        match prev {
            Some(v) => unsafe { std::env::set_var("ATI_DB_URL", v) },
            None => unsafe { std::env::remove_var("ATI_DB_URL") },
        }
    }

    #[tokio::test]
    async fn run_migrations_noop_when_disabled() {
        let state = DbState::Disabled;
        run_migrations(&state).await.expect("no-op should succeed");
    }
}
