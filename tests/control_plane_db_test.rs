//! Live-Postgres integration tests for the control-plane stores.
//!
//! Gated on `ATI_TEST_DB_URL` so they only run when an operator explicitly
//! opts in with a usable test database. The standard CI run skips them.
//!
//! Each test creates its own schema-isolated namespace (transaction-rollback
//! style would be cleaner, but several tests want to observe the actual
//! committed-row behavior of ON CONFLICT / partial-unique indexes, which
//! requires real commits).
//!
//! Usage:
//!   docker run --name ati-test-pg -d -e POSTGRES_PASSWORD=test \
//!     -p 5440:5432 postgres:16
//!   export ATI_TEST_DB_URL=postgres://postgres:test@localhost:5440/postgres
//!   cargo test --features db --test control_plane_db_test

#![cfg(feature = "db")]

use std::collections::HashMap;

use ati::core::customer_store;
use ati::core::manifest::{AuthType, Provider};
use ati::core::provider_store::{self, ProviderSource};

fn test_db_url() -> Option<String> {
    std::env::var("ATI_TEST_DB_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
}

/// Spin up a one-shot connection pool and apply all migrations into a fresh
/// per-test database. Returns the pool + the test-DB name so the caller can
/// drop it on cleanup.
async fn fresh_db() -> Option<(sqlx::PgPool, String)> {
    let url = test_db_url()?;
    let test_name = format!(
        "ati_test_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..16]
    );

    // Connect to the admin db to CREATE DATABASE.
    let admin = sqlx::PgPool::connect(&url).await.expect("connect admin");
    sqlx::query(&format!("CREATE DATABASE {test_name}"))
        .execute(&admin)
        .await
        .expect("create test db");
    admin.close().await;

    // Connect to the new db.
    let test_url = swap_database(&url, &test_name);
    let pool = sqlx::PgPool::connect(&test_url)
        .await
        .expect("connect test db");

    // Apply migrations.
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrate");

    Some((pool, test_name))
}

fn swap_database(url: &str, new_db: &str) -> String {
    // `postgres://user:pass@host:port/dbname?params` → swap the path segment.
    let url = url.trim_end_matches('/');
    let last_slash = url.rfind('/').expect("url has slash");
    let host_part = &url[..last_slash];
    // Preserve any query string from the original DB segment.
    let rest = &url[last_slash + 1..];
    let qs_idx = rest.find('?').unwrap_or(rest.len());
    let qs = &rest[qs_idx..];
    format!("{host_part}/{new_db}{qs}")
}

async fn drop_db(test_name: String) {
    let Some(url) = test_db_url() else {
        return;
    };
    if let Ok(admin) = sqlx::PgPool::connect(&url).await {
        let _ = sqlx::query(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{test_name}' AND pid <> pg_backend_pid()"
        )).execute(&admin).await;
        let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {test_name}"))
            .execute(&admin)
            .await;
        admin.close().await;
    }
}

fn sample_provider(name: &str) -> Provider {
    Provider {
        name: name.into(),
        description: format!("{name} description"),
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
        mcp_args: vec![],
        mcp_url: Some(format!("https://mcp.{name}.test")),
        mcp_env: HashMap::new(),
        cli_command: None,
        cli_default_args: vec![],
        cli_env: HashMap::new(),
        cli_timeout_secs: None,
        cli_output_args: vec![],
        cli_output_positional: HashMap::new(),
        upload_destinations: HashMap::new(),
        upload_default_destination: None,
        openapi_spec: None,
        openapi_include_tags: vec![],
        openapi_exclude_tags: vec![],
        openapi_include_operations: vec![],
        openapi_exclude_operations: vec![],
        openapi_max_operations: None,
        openapi_overrides: HashMap::new(),
        auth_generator: None,
        category: Some("iot".into()),
        skills: vec![],
    }
}

#[tokio::test]
async fn customer_crud_roundtrip() {
    let Some((pool, db_name)) = fresh_db().await else {
        eprintln!("SKIP: ATI_TEST_DB_URL not set");
        return;
    };

    let c = customer_store::create(&pool, "cust_alpha", "Customer Alpha", None, None)
        .await
        .unwrap();
    assert_eq!(c.id, "cust_alpha");
    assert_eq!(c.display_name, "Customer Alpha");
    assert!(c.enabled);
    assert!(c.deleted_at.is_none());

    let fetched = customer_store::get(&pool, "cust_alpha")
        .await
        .unwrap()
        .expect("customer present after create");
    assert_eq!(fetched.id, c.id);

    let list = customer_store::list(&pool).await.unwrap();
    assert_eq!(list.len(), 1);

    // Soft delete is idempotent.
    customer_store::soft_delete(&pool, "cust_alpha")
        .await
        .unwrap();
    customer_store::soft_delete(&pool, "cust_alpha")
        .await
        .unwrap();
    assert!(customer_store::get(&pool, "cust_alpha")
        .await
        .unwrap()
        .is_none());

    pool.close().await;
    drop_db(db_name).await;
}

#[tokio::test]
async fn provider_bootstrap_idempotent() {
    let Some((pool, db_name)) = fresh_db().await else {
        eprintln!("SKIP: ATI_TEST_DB_URL not set");
        return;
    };

    let p = sample_provider("particle");
    let first = provider_store::bootstrap_shared(&pool, &p).await.unwrap();
    assert!(first.is_some(), "first bootstrap should insert");
    let first = first.unwrap();
    assert_eq!(first.source, ProviderSource::Toml);
    assert_eq!(first.provider.name, "particle");
    assert_eq!(first.customer_id, None);

    // Second bootstrap is a no-op.
    let second = provider_store::bootstrap_shared(&pool, &p).await.unwrap();
    assert!(
        second.is_none(),
        "second bootstrap returns None when shared row already exists"
    );

    pool.close().await;
    drop_db(db_name).await;
}

#[tokio::test]
async fn provider_per_customer_coexists_with_shared() {
    let Some((pool, db_name)) = fresh_db().await else {
        eprintln!("SKIP: ATI_TEST_DB_URL not set");
        return;
    };

    customer_store::create(&pool, "cust_alpha", "Alpha", None, None)
        .await
        .unwrap();

    // Shared row.
    let p_shared = sample_provider("particle");
    let _shared = provider_store::create(&pool, None, &p_shared, ProviderSource::Toml)
        .await
        .unwrap();

    // Per-customer row with same name, different URL — must succeed.
    let mut p_cust = sample_provider("particle");
    p_cust.mcp_url = Some("https://customer-specific.particle.test".into());
    let _cust = provider_store::create(&pool, Some("cust_alpha"), &p_cust, ProviderSource::Admin)
        .await
        .unwrap();

    // Cascade lookup returns the customer-specific row when customer scope set.
    let resolved = provider_store::resolve_for_customer(&pool, Some("cust_alpha"), "particle")
        .await
        .unwrap()
        .expect("resolved provider");
    assert_eq!(resolved.customer_id.as_deref(), Some("cust_alpha"));
    assert_eq!(
        resolved.provider.mcp_url.as_deref(),
        Some("https://customer-specific.particle.test")
    );

    // Cascade lookup with no customer falls back to shared.
    let resolved = provider_store::resolve_for_customer(&pool, None, "particle")
        .await
        .unwrap()
        .expect("resolved shared");
    assert_eq!(resolved.customer_id, None);
    assert_eq!(
        resolved.provider.mcp_url.as_deref(),
        Some("https://mcp.particle.test")
    );

    // Cascade with a customer that has no override falls back to shared.
    customer_store::create(&pool, "cust_beta", "Beta", None, None)
        .await
        .unwrap();
    let resolved = provider_store::resolve_for_customer(&pool, Some("cust_beta"), "particle")
        .await
        .unwrap()
        .expect("resolved fallback");
    assert_eq!(
        resolved.customer_id, None,
        "cust_beta has no override, falls back"
    );

    pool.close().await;
    drop_db(db_name).await;
}

#[tokio::test]
async fn duplicate_shared_provider_rejected() {
    let Some((pool, db_name)) = fresh_db().await else {
        eprintln!("SKIP: ATI_TEST_DB_URL not set");
        return;
    };

    let p = sample_provider("particle");
    provider_store::create(&pool, None, &p, ProviderSource::Admin)
        .await
        .unwrap();
    let err = provider_store::create(&pool, None, &p, ProviderSource::Admin)
        .await
        .unwrap_err();
    // The partial unique index trips on the second insert.
    let msg = err.to_string();
    assert!(
        msg.contains("uq_ati_providers_shared_name") || msg.contains("duplicate"),
        "expected unique-violation; got: {msg}"
    );

    pool.close().await;
    drop_db(db_name).await;
}

#[tokio::test]
async fn list_visible_cascades() {
    let Some((pool, db_name)) = fresh_db().await else {
        eprintln!("SKIP: ATI_TEST_DB_URL not set");
        return;
    };

    customer_store::create(&pool, "cust_alpha", "Alpha", None, None)
        .await
        .unwrap();

    // Two shared providers; one of them overridden for cust_alpha.
    provider_store::create(
        &pool,
        None,
        &sample_provider("particle"),
        ProviderSource::Toml,
    )
    .await
    .unwrap();
    provider_store::create(
        &pool,
        None,
        &sample_provider("middesk"),
        ProviderSource::Toml,
    )
    .await
    .unwrap();

    let mut override_particle = sample_provider("particle");
    override_particle.description = "Customer-specific Particle".into();
    provider_store::create(
        &pool,
        Some("cust_alpha"),
        &override_particle,
        ProviderSource::Admin,
    )
    .await
    .unwrap();

    let visible_alpha = provider_store::list_visible(&pool, Some("cust_alpha"))
        .await
        .unwrap();
    assert_eq!(visible_alpha.len(), 2, "alpha sees 2 providers (cascade)");
    let particle_for_alpha = visible_alpha
        .iter()
        .find(|p| p.provider.name == "particle")
        .unwrap();
    assert_eq!(
        particle_for_alpha.customer_id.as_deref(),
        Some("cust_alpha"),
        "cust_alpha gets its own particle row"
    );
    assert_eq!(
        particle_for_alpha.provider.description,
        "Customer-specific Particle"
    );

    let visible_shared = provider_store::list_visible(&pool, None).await.unwrap();
    assert_eq!(visible_shared.len(), 2, "no-customer sees only shared rows");
    for p in &visible_shared {
        assert_eq!(p.customer_id, None);
    }

    pool.close().await;
    drop_db(db_name).await;
}

#[tokio::test]
async fn toml_manifests_bootstrap_to_db() {
    // End-to-end: parse a `manifests/` directory off disk with the real
    // ManifestRegistry, then bootstrap every provider into ati_providers.
    // This mirrors what `proxy::server::run` does at startup with a real
    // ATI_DIR.
    let Some((pool, db_name)) = fresh_db().await else {
        eprintln!("SKIP: ATI_TEST_DB_URL not set");
        return;
    };

    let tmp = tempfile::tempdir().unwrap();
    let manifests = tmp.path().join("manifests");
    std::fs::create_dir_all(&manifests).unwrap();
    std::fs::write(
        manifests.join("foo.toml"),
        r#"
[provider]
name = "foo"
description = "Foo provider for testing"
handler = "http"
base_url = "https://api.foo.test"
auth_type = "none"
category = "test"
"#,
    )
    .unwrap();
    std::fs::write(
        manifests.join("bar.toml"),
        r#"
[provider]
name = "bar"
description = "Bar MCP provider"
handler = "mcp"
mcp_transport = "http"
mcp_url = "https://mcp.bar.test"
auth_type = "none"
category = "test"
"#,
    )
    .unwrap();

    let registry = ati::core::manifest::ManifestRegistry::load(&manifests).unwrap();
    let providers = registry.list_providers();
    assert!(providers.iter().any(|p| p.name == "foo"));
    assert!(providers.iter().any(|p| p.name == "bar"));

    // Bootstrap them. ManifestRegistry::load() also auto-registers the
    // virtual `file_manager` provider on every load, so we expect 3 inserts
    // total — foo, bar, and file_manager. That's the production behavior
    // and what the proxy startup path exercises.
    let mut inserted = 0;
    for p in providers {
        if p.internal {
            continue;
        }
        let outcome = provider_store::bootstrap_shared(&pool, p).await.unwrap();
        if outcome.is_some() {
            inserted += 1;
        }
    }
    assert_eq!(inserted, 3, "foo + bar + auto-registered file_manager");

    // Roundtrip via resolve_for_customer with no customer scope.
    let foo = provider_store::resolve_for_customer(&pool, None, "foo")
        .await
        .unwrap()
        .expect("foo present");
    assert_eq!(foo.source, ProviderSource::Toml);
    assert_eq!(foo.provider.base_url, "https://api.foo.test");

    let bar = provider_store::resolve_for_customer(&pool, None, "bar")
        .await
        .unwrap()
        .expect("bar present");
    assert_eq!(bar.provider.handler, "mcp");
    assert_eq!(
        bar.provider.mcp_url.as_deref(),
        Some("https://mcp.bar.test")
    );

    // Second bootstrap is a no-op (ON CONFLICT DO NOTHING).
    let mut existed = 0;
    for p in registry.list_providers() {
        if p.internal {
            continue;
        }
        let outcome = provider_store::bootstrap_shared(&pool, p).await.unwrap();
        if outcome.is_none() {
            existed += 1;
        }
    }
    assert_eq!(existed, 3, "re-bootstrap leaves all three rows untouched");

    pool.close().await;
    drop_db(db_name).await;
}

#[tokio::test]
async fn provider_jsonb_roundtrip_preserves_cold_fields() {
    let Some((pool, db_name)) = fresh_db().await else {
        eprintln!("SKIP: ATI_TEST_DB_URL not set");
        return;
    };

    let mut p = sample_provider("particle");
    // Pack the provider with cold fields that must round-trip through JSONB.
    p.mcp_args = vec!["-y".into(), "@particle/mcp".into()];
    p.mcp_env.insert("FOO".into(), "${api_key}".into());
    p.extra_headers.insert("X-Custom".into(), "value".into());
    p.openapi_include_tags = vec!["device".into()];
    p.openapi_max_operations = Some(50);
    p.skills = vec!["particle-skill".into()];

    let created = provider_store::create(&pool, None, &p, ProviderSource::Admin)
        .await
        .unwrap();

    let fetched = provider_store::get(&pool, None, "particle")
        .await
        .unwrap()
        .unwrap();

    assert_eq!(fetched.provider.mcp_args, p.mcp_args);
    assert_eq!(fetched.provider.mcp_env, p.mcp_env);
    assert_eq!(fetched.provider.extra_headers, p.extra_headers);
    assert_eq!(
        fetched.provider.openapi_include_tags,
        p.openapi_include_tags
    );
    assert_eq!(
        fetched.provider.openapi_max_operations,
        p.openapi_max_operations
    );
    assert_eq!(fetched.provider.skills, p.skills);

    // Soft delete then list — should disappear.
    provider_store::soft_delete(&pool, created.id)
        .await
        .unwrap();
    assert!(provider_store::get(&pool, None, "particle")
        .await
        .unwrap()
        .is_none());

    pool.close().await;
    drop_db(db_name).await;
}
