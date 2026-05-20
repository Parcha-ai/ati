//! CRUD for `ati_customers` — tenant registry.
//!
//! Customers are Parcha-customer identities ("cust_alpha") that other rows in
//! the control plane scope themselves to via `customer_id`. Created and
//! managed via the admin UI (PR #4 in the stack) or, eventually, by
//! parcha-backend when a new org is provisioned.
//!
//! This module is gated on the `db` feature — when disabled at compile time,
//! every function in here is absent and the proxy degrades to "shared
//! credentials only".
//!
//! ## Soft delete
//!
//! Following the same convention as `ati_keys`, every mutating function
//! treats `deleted_at IS NOT NULL` rows as gone. The actual rows stay for
//! audit purposes; a separate operator flow does hard delete.

#![cfg(feature = "db")]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::{PgPool, Row};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CustomerStoreError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("invalid customer id '{0}': must match ^[a-z][a-z0-9_-]*$")]
    InvalidId(String),
    #[error("customer '{0}' not found")]
    NotFound(String),
}

/// A row in `ati_customers`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Customer {
    pub id: String,
    pub display_name: String,
    pub parcha_org_id: Option<String>,
    pub enabled: bool,
    pub metadata: JsonValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Validate the same shape the DB CHECK constraint enforces, but server-side
/// so the operator sees a clean 400 before sqlx round-trips and rolls back.
fn validate_id(id: &str) -> Result<(), CustomerStoreError> {
    if id.is_empty() {
        return Err(CustomerStoreError::InvalidId(id.to_string()));
    }
    let mut chars = id.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_lowercase() {
        return Err(CustomerStoreError::InvalidId(id.to_string()));
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-') {
            return Err(CustomerStoreError::InvalidId(id.to_string()));
        }
    }
    Ok(())
}

/// Insert a new customer row.
///
/// Returns `Err(Sqlx(DatabaseError))` with a unique-violation kind if a
/// customer with the same id already exists (live or soft-deleted — soft
/// delete keeps the PK occupied).
pub async fn create(
    pool: &PgPool,
    id: &str,
    display_name: &str,
    parcha_org_id: Option<&str>,
    metadata: Option<JsonValue>,
) -> Result<Customer, CustomerStoreError> {
    validate_id(id)?;
    let meta = metadata.unwrap_or_else(|| JsonValue::Object(Default::default()));
    let row = sqlx::query(
        r#"
        INSERT INTO ati_customers (id, display_name, parcha_org_id, metadata)
        VALUES ($1, $2, $3, $4)
        RETURNING id, display_name, parcha_org_id, enabled, metadata,
                  created_at, updated_at, deleted_at
        "#,
    )
    .bind(id)
    .bind(display_name)
    .bind(parcha_org_id)
    .bind(meta)
    .fetch_one(pool)
    .await?;
    Ok(row_to_customer(&row))
}

/// Fetch a single customer by id. Returns `Ok(None)` if absent or
/// soft-deleted.
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<Customer>, CustomerStoreError> {
    let row = sqlx::query(
        r#"
        SELECT id, display_name, parcha_org_id, enabled, metadata,
               created_at, updated_at, deleted_at
        FROM ati_customers
        WHERE id = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.as_ref().map(row_to_customer))
}

/// List all non-deleted customers ordered by id.
pub async fn list(pool: &PgPool) -> Result<Vec<Customer>, CustomerStoreError> {
    let rows = sqlx::query(
        r#"
        SELECT id, display_name, parcha_org_id, enabled, metadata,
               created_at, updated_at, deleted_at
        FROM ati_customers
        WHERE deleted_at IS NULL
        ORDER BY id
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(row_to_customer).collect())
}

/// Partial update — any field passed as `Some` is overwritten; `None` is
/// ignored. Returns the updated row, or `NotFound` if nothing matches.
pub async fn update(
    pool: &PgPool,
    id: &str,
    display_name: Option<&str>,
    parcha_org_id: Option<Option<&str>>,
    enabled: Option<bool>,
    metadata: Option<JsonValue>,
) -> Result<Customer, CustomerStoreError> {
    // COALESCE($N, col) only works for non-nullable fields — for
    // parcha_org_id (nullable) we need a separate flag column. Easier to
    // hand-build the SET clause; the call set is small enough that
    // performance isn't an issue.
    let mut sets: Vec<String> = Vec::new();
    let mut idx = 2;
    if display_name.is_some() {
        sets.push(format!("display_name = ${idx}"));
        idx += 1;
    }
    if parcha_org_id.is_some() {
        sets.push(format!("parcha_org_id = ${idx}"));
        idx += 1;
    }
    if enabled.is_some() {
        sets.push(format!("enabled = ${idx}"));
        idx += 1;
    }
    if metadata.is_some() {
        sets.push(format!("metadata = ${idx}"));
        // idx is no longer needed; we're done.
    }
    if sets.is_empty() {
        // Nothing to update — return current.
        return get(pool, id)
            .await?
            .ok_or_else(|| CustomerStoreError::NotFound(id.to_string()));
    }
    sets.push("updated_at = now()".to_string());

    let sql = format!(
        r#"
        UPDATE ati_customers
        SET {}
        WHERE id = $1 AND deleted_at IS NULL
        RETURNING id, display_name, parcha_org_id, enabled, metadata,
                  created_at, updated_at, deleted_at
        "#,
        sets.join(", ")
    );

    let mut q = sqlx::query(&sql).bind(id);
    if let Some(v) = display_name {
        q = q.bind(v);
    }
    if let Some(inner) = parcha_org_id {
        q = q.bind(inner);
    }
    if let Some(v) = enabled {
        q = q.bind(v);
    }
    if let Some(v) = metadata {
        q = q.bind(v);
    }

    let row = q
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| CustomerStoreError::NotFound(id.to_string()))?;
    Ok(row_to_customer(&row))
}

/// Soft delete. Idempotent — calling twice is a no-op. Returns
/// `NotFound` only if the row never existed.
pub async fn soft_delete(pool: &PgPool, id: &str) -> Result<(), CustomerStoreError> {
    let result = sqlx::query(
        r#"
        UPDATE ati_customers
        SET deleted_at = now(), updated_at = now()
        WHERE id = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        // Did the row exist at all? If yes, it was already soft-deleted —
        // idempotent. If no, surface NotFound.
        let exists = sqlx::query("SELECT 1 FROM ati_customers WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?;
        if exists.is_none() {
            return Err(CustomerStoreError::NotFound(id.to_string()));
        }
    }
    Ok(())
}

fn row_to_customer(row: &sqlx::postgres::PgRow) -> Customer {
    Customer {
        id: row.get("id"),
        display_name: row.get("display_name"),
        parcha_org_id: row.get("parcha_org_id"),
        enabled: row.get("enabled"),
        metadata: row.get("metadata"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        deleted_at: row.get("deleted_at"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_id_accepts_canonical() {
        validate_id("cust_alpha").unwrap();
        validate_id("a").unwrap();
        validate_id("abc-123_def").unwrap();
    }

    #[test]
    fn validate_id_rejects_uppercase() {
        assert!(matches!(
            validate_id("Cust_Alpha"),
            Err(CustomerStoreError::InvalidId(_))
        ));
    }

    #[test]
    fn validate_id_rejects_leading_digit() {
        assert!(matches!(
            validate_id("1abc"),
            Err(CustomerStoreError::InvalidId(_))
        ));
    }

    #[test]
    fn validate_id_rejects_empty() {
        assert!(matches!(
            validate_id(""),
            Err(CustomerStoreError::InvalidId(_))
        ));
    }

    #[test]
    fn validate_id_rejects_special_chars() {
        for bad in ["cust.alpha", "cust alpha", "cust/alpha", "cust@alpha"] {
            assert!(
                matches!(validate_id(bad), Err(CustomerStoreError::InvalidId(_))),
                "should reject {bad:?}"
            );
        }
    }
}
