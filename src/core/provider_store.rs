//! CRUD for `ati_providers` — the DB-backed manifest source-of-truth.
//!
//! The disk-based `ManifestRegistry::load(dir)` is still the bootstrap input,
//! but the runtime registry is rebuilt from PG every time the proxy starts
//! (or whenever the admin UI mutates a row). This module handles the
//! round-trip:
//!
//! - **Serialize** a parsed `Provider` into the hot-column-plus-JSONB shape
//!   the table expects.
//! - **Deserialize** a `PgRow` back into a `Provider` by injecting the hot
//!   columns into the JSONB config envelope.
//!
//! ## Why hot columns + JSONB
//!
//! The proxy's hot path queries by `(name, customer_id)` and filters by
//! `enabled`, `handler`, and (rarely) `category`. Putting those in typed
//! columns keeps lookup indexed and cheap. Every other field on `Provider`
//! is either MCP-only or OpenAPI-only or auth-config — proxy reads, never
//! filters — so JSONB is the right place: a new `Provider` field doesn't
//! need a schema migration.
//!
//! Gated on the `db` feature; absent when the feature is off.

#![cfg(feature = "db")]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use thiserror::Error;

use crate::core::manifest::{AuthType, Provider};

#[derive(Debug, Error)]
pub enum ProviderStoreError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("serde_json: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("invalid provider name '{0}': must match ^[a-z][a-z0-9_-]*$")]
    InvalidName(String),
    #[error("invalid handler '{0}': expected http|mcp|openapi|cli|file_manager")]
    InvalidHandler(String),
    #[error("provider '{0}' not found")]
    NotFound(String),
}

/// Where this provider row came from. Bootstrap rows are written once on
/// first DB connect from each `manifests/*.toml`; admin rows come from the
/// UI / API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderSource {
    Toml,
    Admin,
}

impl ProviderSource {
    fn as_str(self) -> &'static str {
        match self {
            ProviderSource::Toml => "toml",
            ProviderSource::Admin => "admin",
        }
    }

    fn from_str(s: &str) -> Self {
        match s {
            "toml" => ProviderSource::Toml,
            _ => ProviderSource::Admin,
        }
    }
}

/// Metadata returned alongside a fetched `Provider`. The actual provider
/// fields live in the `Provider` struct from `core::manifest`; this type
/// carries the row-level metadata the admin UI cares about.
#[derive(Debug, Clone)]
pub struct ProviderRecord {
    pub id: uuid::Uuid,
    pub customer_id: Option<String>,
    pub source: ProviderSource,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub provider: Provider,
}

/// Insert a new provider row.
///
/// Use `customer_id = None` for the shared (Parcha-owned) variant. The
/// partial unique indexes will reject a second shared row with the same
/// name, and a second per-customer row with the same (customer, name) — see
/// the migration for the exact constraint shape.
pub async fn create(
    pool: &PgPool,
    customer_id: Option<&str>,
    provider: &Provider,
    source: ProviderSource,
) -> Result<ProviderRecord, ProviderStoreError> {
    validate_name(&provider.name)?;
    validate_handler(&provider.handler)?;

    let config = provider_to_config(provider)?;

    let row = sqlx::query(
        r#"
        INSERT INTO ati_providers (
            customer_id, name, handler, description, base_url,
            auth_type, category, internal, enabled, config, source
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING id, customer_id, name, handler, description, base_url,
                  auth_type, category, internal, enabled, config, source,
                  created_at, updated_at, deleted_at
        "#,
    )
    .bind(customer_id)
    .bind(&provider.name)
    .bind(&provider.handler)
    .bind(&provider.description)
    .bind(&provider.base_url)
    .bind(auth_type_to_str(&provider.auth_type))
    .bind(provider.category.as_deref())
    .bind(provider.internal)
    .bind(true) // enabled defaults TRUE; admin can flip via update()
    .bind(config)
    .bind(source.as_str())
    .fetch_one(pool)
    .await?;
    row_to_record(&row)
}

/// Upsert for the TOML bootstrap path.
///
/// `INSERT ... ON CONFLICT DO NOTHING` keyed on the partial unique index
/// `uq_ati_providers_shared_name`. Returns `Ok(Some(_))` when a row was
/// inserted, `Ok(None)` when a shared row with that name already existed
/// (operator may have edited it via the UI — we don't clobber).
///
/// Only useful for `customer_id = NULL` rows; per-customer rows are always
/// operator-created via `create()`.
pub async fn bootstrap_shared(
    pool: &PgPool,
    provider: &Provider,
) -> Result<Option<ProviderRecord>, ProviderStoreError> {
    validate_name(&provider.name)?;
    validate_handler(&provider.handler)?;

    let config = provider_to_config(provider)?;

    // ON CONFLICT against a partial unique index uses the column list +
    // a matching WHERE predicate. The predicate here mirrors the
    // uq_ati_providers_shared_name partial index from the migration —
    // (name) where customer_id IS NULL AND deleted_at IS NULL.
    let row = sqlx::query(
        r#"
        INSERT INTO ati_providers (
            customer_id, name, handler, description, base_url,
            auth_type, category, internal, enabled, config, source
        )
        VALUES (NULL, $1, $2, $3, $4, $5, $6, $7, TRUE, $8, 'toml')
        ON CONFLICT (name) WHERE customer_id IS NULL AND deleted_at IS NULL
        DO NOTHING
        RETURNING id, customer_id, name, handler, description, base_url,
                  auth_type, category, internal, enabled, config, source,
                  created_at, updated_at, deleted_at
        "#,
    )
    .bind(&provider.name)
    .bind(&provider.handler)
    .bind(&provider.description)
    .bind(&provider.base_url)
    .bind(auth_type_to_str(&provider.auth_type))
    .bind(provider.category.as_deref())
    .bind(provider.internal)
    .bind(config)
    .fetch_optional(pool)
    .await?;
    row.as_ref().map(row_to_record).transpose()
}

/// Look up a provider by `(customer_id, name)`.
///
/// The control-plane resolver's cascade (PR #3) reads per-customer first,
/// then shared. This function returns exactly the row matching the
/// `customer_id` you pass — it does NOT cascade. For the cascade, call
/// `resolve_for_customer()` below.
pub async fn get(
    pool: &PgPool,
    customer_id: Option<&str>,
    name: &str,
) -> Result<Option<ProviderRecord>, ProviderStoreError> {
    let row = sqlx::query(
        r#"
        SELECT id, customer_id, name, handler, description, base_url,
               auth_type, category, internal, enabled, config, source,
               created_at, updated_at, deleted_at
        FROM ati_providers
        WHERE name = $1
          AND deleted_at IS NULL
          AND ((customer_id IS NULL AND $2::text IS NULL)
               OR customer_id = $2)
        "#,
    )
    .bind(name)
    .bind(customer_id)
    .fetch_optional(pool)
    .await?;
    row.as_ref().map(row_to_record).transpose()
}

/// Cascade lookup used by the resolver: prefer the row matching
/// `customer_id`, fall back to the shared (NULL) row.
///
/// Single round-trip. ORDER BY customer_id NULLS LAST means the
/// customer-scoped row sorts before the shared row when both exist.
pub async fn resolve_for_customer(
    pool: &PgPool,
    customer_id: Option<&str>,
    name: &str,
) -> Result<Option<ProviderRecord>, ProviderStoreError> {
    let row = sqlx::query(
        r#"
        SELECT id, customer_id, name, handler, description, base_url,
               auth_type, category, internal, enabled, config, source,
               created_at, updated_at, deleted_at
        FROM ati_providers
        WHERE name = $1
          AND deleted_at IS NULL
          AND enabled = TRUE
          AND (customer_id = $2 OR customer_id IS NULL)
        ORDER BY customer_id NULLS LAST
        LIMIT 1
        "#,
    )
    .bind(name)
    .bind(customer_id)
    .fetch_optional(pool)
    .await?;
    row.as_ref().map(row_to_record).transpose()
}

/// List providers visible to a customer. Returns the customer-specific row
/// if one exists for that name, else the shared row. Per-customer overrides
/// are listed alongside their shared counterparts using the cascade rule.
///
/// `customer_id = None` lists only shared rows — used by the proxy when no
/// JWT customer scope is set.
pub async fn list_visible(
    pool: &PgPool,
    customer_id: Option<&str>,
) -> Result<Vec<ProviderRecord>, ProviderStoreError> {
    // DISTINCT ON (name) plus an ORDER BY that puts the customer-specific
    // row first does the cascade in one query, just like resolve_for_customer
    // does for the single-name case.
    let rows = sqlx::query(
        r#"
        SELECT DISTINCT ON (name)
            id, customer_id, name, handler, description, base_url,
            auth_type, category, internal, enabled, config, source,
            created_at, updated_at, deleted_at
        FROM ati_providers
        WHERE deleted_at IS NULL
          AND (customer_id = $1 OR customer_id IS NULL)
        ORDER BY name, customer_id NULLS LAST
        "#,
    )
    .bind(customer_id)
    .fetch_all(pool)
    .await?;
    rows.iter().map(row_to_record).collect()
}

/// List all rows (admin view). Includes per-customer rows alongside shared.
/// Filtering by customer_id at the call site is up to the admin endpoint.
pub async fn list_all(pool: &PgPool) -> Result<Vec<ProviderRecord>, ProviderStoreError> {
    let rows = sqlx::query(
        r#"
        SELECT id, customer_id, name, handler, description, base_url,
               auth_type, category, internal, enabled, config, source,
               created_at, updated_at, deleted_at
        FROM ati_providers
        WHERE deleted_at IS NULL
        ORDER BY customer_id NULLS FIRST, name
        "#,
    )
    .fetch_all(pool)
    .await?;
    rows.iter().map(row_to_record).collect()
}

/// Soft delete by id. Idempotent.
pub async fn soft_delete(pool: &PgPool, id: uuid::Uuid) -> Result<(), ProviderStoreError> {
    sqlx::query("UPDATE ati_providers SET deleted_at = now(), updated_at = now() WHERE id = $1 AND deleted_at IS NULL")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Provider <-> JSONB conversion
// ---------------------------------------------------------------------------

/// Serialize a Provider into the JSONB `config` column. The hot columns
/// (name, handler, etc.) are dropped because they live in typed columns;
/// only the cold fields ride in JSONB.
fn provider_to_config(p: &Provider) -> Result<serde_json::Value, ProviderStoreError> {
    // We serialize the full Provider, then strip the hot fields. This keeps
    // the JSON encoding identical to what `serde_json::to_value(p)` produces
    // elsewhere — same string keys, same default-skipping, no risk of drift
    // between the round-trip endpoints.
    let mut v = serde_json::to_value(p)?;
    if let serde_json::Value::Object(ref mut map) = v {
        for hot in [
            "name",
            "handler",
            "description",
            "base_url",
            "auth_type",
            "category",
            "internal",
        ] {
            map.remove(hot);
        }
    }
    Ok(v)
}

/// Typed hot columns pulled off a `PgRow` and bundled together for the
/// reverse `config_to_provider` step. Keeps the arg list short for clippy
/// and makes call sites self-documenting.
struct ProviderHotColumns {
    name: String,
    handler: String,
    description: String,
    base_url: String,
    auth_type: String,
    category: Option<String>,
    internal: bool,
}

/// Reverse: given the typed hot columns plus the JSONB envelope, reconstruct
/// the full Provider struct.
fn config_to_provider(
    hot: ProviderHotColumns,
    config: &serde_json::Value,
) -> Result<Provider, ProviderStoreError> {
    let mut full = config.clone();
    if let serde_json::Value::Object(ref mut map) = full {
        map.insert("name".into(), serde_json::Value::String(hot.name));
        map.insert("handler".into(), serde_json::Value::String(hot.handler));
        map.insert(
            "description".into(),
            serde_json::Value::String(hot.description),
        );
        map.insert("base_url".into(), serde_json::Value::String(hot.base_url));
        map.insert("auth_type".into(), serde_json::Value::String(hot.auth_type));
        if let Some(c) = hot.category {
            map.insert("category".into(), serde_json::Value::String(c));
        }
        map.insert("internal".into(), serde_json::Value::Bool(hot.internal));
    }
    let provider: Provider = serde_json::from_value(full)?;
    Ok(provider)
}

fn auth_type_to_str(a: &AuthType) -> &'static str {
    match a {
        AuthType::Bearer => "bearer",
        AuthType::Header => "header",
        AuthType::Query => "query",
        AuthType::Basic => "basic",
        AuthType::None => "none",
        AuthType::Oauth2 => "oauth2",
        AuthType::Url => "url",
    }
}

fn validate_name(name: &str) -> Result<(), ProviderStoreError> {
    let err = || ProviderStoreError::InvalidName(name.to_string());
    if name.is_empty() {
        return Err(err());
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_lowercase() {
        return Err(err());
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-') {
            return Err(err());
        }
    }
    Ok(())
}

fn validate_handler(h: &str) -> Result<(), ProviderStoreError> {
    match h {
        "http" | "mcp" | "openapi" | "cli" | "file_manager" => Ok(()),
        other => Err(ProviderStoreError::InvalidHandler(other.to_string())),
    }
}

fn row_to_record(row: &sqlx::postgres::PgRow) -> Result<ProviderRecord, ProviderStoreError> {
    let hot = ProviderHotColumns {
        name: row.get("name"),
        handler: row.get("handler"),
        description: row.get("description"),
        base_url: row.get("base_url"),
        auth_type: row.get("auth_type"),
        category: row.get("category"),
        internal: row.get("internal"),
    };
    let id: uuid::Uuid = row.get("id");
    let customer_id: Option<String> = row.get("customer_id");
    let _enabled: bool = row.get("enabled");
    let config: serde_json::Value = row.get("config");
    let source: String = row.get("source");
    let created_at: DateTime<Utc> = row.get("created_at");
    let updated_at: DateTime<Utc> = row.get("updated_at");
    let deleted_at: Option<DateTime<Utc>> = row.get("deleted_at");

    let provider = config_to_provider(hot, &config)?;

    Ok(ProviderRecord {
        id,
        customer_id,
        source: ProviderSource::from_str(&source),
        created_at,
        updated_at,
        deleted_at,
        provider,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::manifest::Provider;
    use std::collections::HashMap;

    fn sample_provider() -> Provider {
        Provider {
            name: "particle".into(),
            description: "Particle IoT".into(),
            base_url: String::new(),
            auth_type: AuthType::None,
            auth_key_name: None,
            auth_header_name: None,
            auth_query_name: None,
            auth_value_prefix: None,
            extra_headers: HashMap::new(),
            oauth2_token_url: None,
            auth_secret_name: None,
            oauth2_basic_auth: false,
            internal: false,
            handler: "mcp".into(),
            mcp_transport: Some("http".into()),
            mcp_command: None,
            mcp_args: Vec::new(),
            mcp_url: Some("https://mcp.particle.pro".into()),
            mcp_env: HashMap::new(),
            cli_command: None,
            cli_default_args: Vec::new(),
            cli_env: HashMap::new(),
            cli_timeout_secs: None,
            cli_output_args: Vec::new(),
            cli_output_positional: HashMap::new(),
            upload_destinations: HashMap::new(),
            upload_default_destination: None,
            openapi_spec: None,
            openapi_include_tags: Vec::new(),
            openapi_exclude_tags: Vec::new(),
            openapi_include_operations: Vec::new(),
            openapi_exclude_operations: Vec::new(),
            openapi_max_operations: None,
            openapi_overrides: HashMap::new(),
            auth_generator: None,
            category: Some("iot".into()),
            skills: Vec::new(),
        }
    }

    #[test]
    fn provider_config_roundtrip() {
        let p = sample_provider();
        let config = provider_to_config(&p).unwrap();
        let cfg_obj = config.as_object().expect("config is object");
        // Hot fields are stripped — they're in typed columns.
        assert!(!cfg_obj.contains_key("name"));
        assert!(!cfg_obj.contains_key("handler"));
        assert!(!cfg_obj.contains_key("auth_type"));
        // Cold fields are present.
        assert!(cfg_obj.contains_key("mcp_url"));
        assert!(cfg_obj.contains_key("mcp_transport"));

        let rebuilt = config_to_provider(
            ProviderHotColumns {
                name: p.name.clone(),
                handler: p.handler.clone(),
                description: p.description.clone(),
                base_url: p.base_url.clone(),
                auth_type: auth_type_to_str(&p.auth_type).into(),
                category: p.category.clone(),
                internal: p.internal,
            },
            &config,
        )
        .unwrap();
        assert_eq!(rebuilt.name, p.name);
        assert_eq!(rebuilt.handler, p.handler);
        assert_eq!(rebuilt.mcp_url, p.mcp_url);
        assert_eq!(rebuilt.category, p.category);
    }

    #[test]
    fn validate_name_canonical() {
        validate_name("particle").unwrap();
        validate_name("middesk_mcp").unwrap();
        validate_name("api-v2").unwrap();
    }

    #[test]
    fn validate_name_rejects_bad() {
        for bad in ["", "1abc", "Abc", "ab.cd", "ab cd"] {
            assert!(
                matches!(validate_name(bad), Err(ProviderStoreError::InvalidName(_))),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn validate_handler_canonical() {
        for h in ["http", "mcp", "openapi", "cli", "file_manager"] {
            validate_handler(h).unwrap();
        }
    }

    #[test]
    fn validate_handler_rejects_unknown() {
        assert!(matches!(
            validate_handler("grpc"),
            Err(ProviderStoreError::InvalidHandler(_))
        ));
    }

    #[test]
    fn provider_source_string_roundtrip() {
        assert_eq!(ProviderSource::Toml.as_str(), "toml");
        assert_eq!(ProviderSource::Admin.as_str(), "admin");
        assert_eq!(ProviderSource::from_str("toml"), ProviderSource::Toml);
        assert_eq!(ProviderSource::from_str("admin"), ProviderSource::Admin);
        // Unknown defaults to Admin (defensive — Admin is the "could be
        // anything the operator did" bucket; toml is the precise bootstrap
        // signal).
        assert_eq!(ProviderSource::from_str("unknown"), ProviderSource::Admin);
    }
}
