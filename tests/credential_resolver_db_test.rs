//! Live-Postgres integration tests for `DbResolver`.
//!
//! Gated on `ATI_TEST_DB_URL`. Each test creates its own database to keep
//! state isolated.
//!
//! Usage:
//!   docker run --name ati-test-pg -d -e POSTGRES_PASSWORD=test \
//!     -p 5440:5432 postgres:16
//!   export ATI_TEST_DB_URL=postgres://postgres:test@localhost:5440/postgres
//!   cargo test --features db --test credential_resolver_db_test

#![cfg(feature = "db")]

use std::sync::Arc;
use std::time::Duration;

use ati::core::resolver::{CredentialResolver, DbResolver, ResolverError};
use ati::core::secrets::{seal, LocalKek};
use chrono::Utc;

fn test_db_url() -> Option<String> {
    std::env::var("ATI_TEST_DB_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
}

async fn fresh_db() -> Option<(sqlx::PgPool, String)> {
    let url = test_db_url()?;
    let test_name = format!(
        "ati_test_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..16]
    );
    let admin = sqlx::PgPool::connect(&url).await.expect("connect admin");
    sqlx::query(&format!("CREATE DATABASE {test_name}"))
        .execute(&admin)
        .await
        .expect("create");
    admin.close().await;

    let pool_url = swap_database(&url, &test_name);
    let pool = sqlx::PgPool::connect(&pool_url)
        .await
        .expect("connect test");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrate");
    Some((pool, test_name))
}

fn swap_database(url: &str, new_db: &str) -> String {
    let url = url.trim_end_matches('/');
    let last_slash = url.rfind('/').expect("url has slash");
    let host_part = &url[..last_slash];
    let rest = &url[last_slash + 1..];
    let qs_idx = rest.find('?').unwrap_or(rest.len());
    let qs = &rest[qs_idx..];
    format!("{host_part}/{new_db}{qs}")
}

async fn drop_db(name: String) {
    let Some(url) = test_db_url() else { return };
    if let Ok(admin) = sqlx::PgPool::connect(&url).await {
        let _ = sqlx::query(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{name}' AND pid <> pg_backend_pid()"
        )).execute(&admin).await;
        let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {name}"))
            .execute(&admin)
            .await;
        admin.close().await;
    }
}

fn test_kek() -> Arc<LocalKek> {
    Arc::new(LocalKek::from_bytes("m1", [0xAB; 32]))
}

/// Insert a row into `ati_provider_credentials` so the resolver has
/// something to read.
async fn seed_static_credential(
    pool: &sqlx::PgPool,
    provider: &str,
    key_name: &str,
    customer_id: Option<&str>,
    plaintext: &str,
    kek: &dyn ati::core::secrets::Kek,
) {
    let aad = format!(
        "static:{provider}:{key_name}:{}",
        customer_id.unwrap_or("_shared")
    );
    let blob = seal(plaintext.as_bytes(), aad.as_bytes(), kek).expect("seal");
    let suffix4 = plaintext
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    sqlx::query(
        r#"
        INSERT INTO ati_provider_credentials
            (customer_id, provider_name, key_name, ciphertext, nonce,
             wrapped_dek, kek_id, suffix4)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(customer_id)
    .bind(provider)
    .bind(key_name)
    .bind(&blob.ciphertext)
    .bind(blob.nonce.to_vec())
    .bind(&blob.wrapped_dek)
    .bind(&blob.kek_id)
    .bind(&suffix4)
    .execute(pool)
    .await
    .expect("insert credential");
}

/// Insert a row into `ati_oauth_tokens`.
#[allow(clippy::too_many_arguments)]
async fn seed_oauth_token(
    pool: &sqlx::PgPool,
    provider: &str,
    customer_id: Option<&str>,
    access_token: &str,
    refresh_token: Option<&str>,
    expires_at: chrono::DateTime<chrono::Utc>,
    token_endpoint: &str,
    kek: &dyn ati::core::secrets::Kek,
) {
    let bundle = serde_json::json!({
        "access": access_token,
        "refresh": refresh_token,
    });
    let bundle_json = serde_json::to_vec(&bundle).unwrap();
    let aad = format!("oauth:{provider}:{}", customer_id.unwrap_or("_shared"));
    let blob = seal(&bundle_json, aad.as_bytes(), kek).expect("seal");

    sqlx::query(
        r#"
        INSERT INTO ati_oauth_tokens
            (customer_id, provider_name, client_id, redirect_uri,
             ciphertext, nonce, wrapped_dek, kek_id,
             access_token_expires_at, scopes, resource, token_endpoint)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#,
    )
    .bind(customer_id)
    .bind(provider)
    .bind("test-client-id")
    .bind("http://localhost/callback")
    .bind(&blob.ciphertext)
    .bind(blob.nonce.to_vec())
    .bind(&blob.wrapped_dek)
    .bind(&blob.kek_id)
    .bind(expires_at)
    .bind(&["mcp:read".to_string()])
    .bind("https://example.com")
    .bind(token_endpoint)
    .execute(pool)
    .await
    .expect("insert oauth token");
}

#[tokio::test]
async fn static_cred_shared_only() {
    let Some((pool, db_name)) = fresh_db().await else {
        eprintln!("SKIP: ATI_TEST_DB_URL not set");
        return;
    };
    let kek = test_kek();
    seed_static_credential(
        &pool,
        "particle",
        "particle_api_key",
        None,
        "shared-secret",
        &*kek,
    )
    .await;

    let r = DbResolver::new(pool.clone(), kek);
    let v = r
        .resolve_static("particle", "particle_api_key", None)
        .await
        .unwrap();
    assert_eq!(&*v, "shared-secret");

    pool.close().await;
    drop_db(db_name).await;
}

#[tokio::test]
async fn static_cred_customer_cascades_to_shared() {
    // No customer-specific row. The resolver should fall back to shared
    // when a customer_id is passed.
    let Some((pool, db_name)) = fresh_db().await else {
        eprintln!("SKIP: ATI_TEST_DB_URL not set");
        return;
    };
    let kek = test_kek();
    sqlx::query("INSERT INTO ati_customers (id, display_name) VALUES ('cust_alpha', 'Alpha')")
        .execute(&pool)
        .await
        .unwrap();
    seed_static_credential(
        &pool,
        "particle",
        "particle_api_key",
        None,
        "shared-secret",
        &*kek,
    )
    .await;

    let r = DbResolver::new(pool.clone(), kek);
    let v = r
        .resolve_static("particle", "particle_api_key", Some("cust_alpha"))
        .await
        .unwrap();
    assert_eq!(&*v, "shared-secret");

    pool.close().await;
    drop_db(db_name).await;
}

#[tokio::test]
async fn static_cred_customer_beats_shared() {
    let Some((pool, db_name)) = fresh_db().await else {
        eprintln!("SKIP: ATI_TEST_DB_URL not set");
        return;
    };
    let kek = test_kek();
    sqlx::query("INSERT INTO ati_customers (id, display_name) VALUES ('cust_alpha', 'Alpha')")
        .execute(&pool)
        .await
        .unwrap();
    seed_static_credential(
        &pool,
        "particle",
        "particle_api_key",
        None,
        "shared-secret",
        &*kek,
    )
    .await;
    seed_static_credential(
        &pool,
        "particle",
        "particle_api_key",
        Some("cust_alpha"),
        "alpha-specific",
        &*kek,
    )
    .await;

    let r = DbResolver::new(pool.clone(), kek);

    let alpha = r
        .resolve_static("particle", "particle_api_key", Some("cust_alpha"))
        .await
        .unwrap();
    assert_eq!(&*alpha, "alpha-specific");

    let shared = r
        .resolve_static("particle", "particle_api_key", None)
        .await
        .unwrap();
    assert_eq!(&*shared, "shared-secret");

    pool.close().await;
    drop_db(db_name).await;
}

#[tokio::test]
async fn static_cred_not_configured() {
    let Some((pool, db_name)) = fresh_db().await else {
        eprintln!("SKIP: ATI_TEST_DB_URL not set");
        return;
    };
    let r = DbResolver::new(pool.clone(), test_kek());
    let err = r
        .resolve_static("particle", "missing_key", None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, ResolverError::NotConfigured { .. }),
        "got {err:?}"
    );

    pool.close().await;
    drop_db(db_name).await;
}

#[tokio::test]
async fn static_cred_decrypt_failure_with_wrong_kek() {
    let Some((pool, db_name)) = fresh_db().await else {
        eprintln!("SKIP: ATI_TEST_DB_URL not set");
        return;
    };
    // Seal with one KEK, resolve with another. AES-KW's integrity check
    // rejects the wrapped DEK and we surface DecryptFailed.
    let seal_kek = test_kek();
    seed_static_credential(&pool, "particle", "k", None, "secret", &*seal_kek).await;

    let wrong_kek = Arc::new(LocalKek::from_bytes("m1", [0xCD; 32]));
    let r = DbResolver::new(pool.clone(), wrong_kek);
    let err = r.resolve_static("particle", "k", None).await.unwrap_err();
    assert!(
        matches!(err, ResolverError::DecryptFailed(_)),
        "got {err:?}"
    );

    pool.close().await;
    drop_db(db_name).await;
}

#[tokio::test]
async fn oauth_resolve_returns_cached_when_fresh() {
    let Some((pool, db_name)) = fresh_db().await else {
        eprintln!("SKIP: ATI_TEST_DB_URL not set");
        return;
    };
    let kek = test_kek();
    // Token good for an hour — no refresh needed.
    let expires_at = Utc::now() + chrono::Duration::hours(1);
    seed_oauth_token(
        &pool,
        "particle",
        None,
        "AT-FRESH",
        Some("RT"),
        expires_at,
        "https://as.example.com/token",
        &*kek,
    )
    .await;

    let r = DbResolver::new(pool.clone(), kek);
    let v = r
        .resolve_oauth("particle", None, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(&*v, "AT-FRESH");

    pool.close().await;
    drop_db(db_name).await;
}

#[tokio::test]
async fn oauth_resolve_attempts_refresh_when_near_expiry() {
    // Seed an expiring token. The token_endpoint will be unreachable,
    // so the refresh round-trip fails — we expect OauthExpired (or
    // similar typed error) rather than the cached access token. This
    // proves the refresh branch was taken.
    let Some((pool, db_name)) = fresh_db().await else {
        eprintln!("SKIP: ATI_TEST_DB_URL not set");
        return;
    };
    let kek = test_kek();
    let expires_at = Utc::now() + chrono::Duration::seconds(10); // within 60s window
    seed_oauth_token(
        &pool,
        "particle",
        None,
        "AT-STALE",
        Some("RT"),
        expires_at,
        "http://127.0.0.1:1/token", // refused
        &*kek,
    )
    .await;

    let r = DbResolver::new(pool.clone(), kek);
    let err = r
        .resolve_oauth("particle", None, Duration::from_secs(60))
        .await
        .unwrap_err();
    // The token endpoint refused the connection; the resolver surfaces
    // OauthExpired with the underlying reason embedded. Any error class
    // that isn't NotConfigured is acceptable proof that refresh was
    // attempted.
    match err {
        ResolverError::OauthExpired(_) | ResolverError::Other(_) => {}
        other => panic!("expected refresh attempt error, got: {other:?}"),
    }

    pool.close().await;
    drop_db(db_name).await;
}

#[tokio::test]
async fn oauth_not_configured() {
    let Some((pool, db_name)) = fresh_db().await else {
        eprintln!("SKIP: ATI_TEST_DB_URL not set");
        return;
    };
    let r = DbResolver::new(pool.clone(), test_kek());
    let err = r
        .resolve_oauth("particle", None, Duration::from_secs(60))
        .await
        .unwrap_err();
    assert!(matches!(err, ResolverError::NotConfigured { .. }));

    pool.close().await;
    drop_db(db_name).await;
}

#[tokio::test]
async fn static_cache_hits_avoid_db() {
    // Seed a row, resolve once (warms cache), then drop the row from PG.
    // Cache should still serve the value within the TTL window.
    let Some((pool, db_name)) = fresh_db().await else {
        eprintln!("SKIP: ATI_TEST_DB_URL not set");
        return;
    };
    let kek = test_kek();
    seed_static_credential(&pool, "particle", "k", None, "first-value", &*kek).await;

    let r = DbResolver::new(pool.clone(), kek);
    let v1 = r.resolve_static("particle", "k", None).await.unwrap();
    assert_eq!(&*v1, "first-value");

    // Hard-delete from PG.
    sqlx::query("DELETE FROM ati_provider_credentials WHERE provider_name = 'particle'")
        .execute(&pool)
        .await
        .unwrap();

    // Resolver still returns the cached value — proves cache short-circuit
    // works. (PR #5 will add pg_notify invalidation so admin DELETE is
    // immediate; until then the TTL is the safety net.)
    let v2 = r.resolve_static("particle", "k", None).await.unwrap();
    assert_eq!(
        &*v2, "first-value",
        "cached value survives DB delete within TTL"
    );

    pool.close().await;
    drop_db(db_name).await;
}
