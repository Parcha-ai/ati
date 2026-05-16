//! Live-Postgres end-to-end tests for the virtual-key store + Ati-Key auth
//! path. Same gating pattern as `tests/db_live_test.rs`: skip with
//! `eprintln!` if `ATI_DB_URL_TEST` is unset so CI runs harmlessly without
//! Postgres.
//!
//! ```sh
//! export ATI_DB_URL_TEST="postgres://parcha:parcha_pool@localhost:5510/ati_pr3_test"
//! cargo test --features db --test keys_live_test
//! ```
#![cfg(feature = "db")]

use std::sync::Arc;
use std::time::Duration;

use ati::core::keys::{self, BulkRevokeFilter, IssueParams, KeyStore};
use ati::core::manifest::ManifestRegistry;
use ati::core::skill::SkillRegistry;
use ati::proxy::server::{build_router, ProxyState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Tests share `ati_keys` / `ati_call_log`; serialize them so cleanup is
/// deterministic.
fn shared_lock() -> &'static tokio::sync::Mutex<()> {
    static M: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    M.get_or_init(|| tokio::sync::Mutex::new(()))
}

async fn connect_test_db() -> Option<sqlx::PgPool> {
    let url = match std::env::var("ATI_DB_URL_TEST") {
        Ok(u) if !u.trim().is_empty() => u,
        _ => return None,
    };
    let pool = sqlx::PgPool::connect(&url).await.ok()?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations apply");
    Some(pool)
}

async fn truncate_all(pool: &sqlx::PgPool) {
    for table in [
        "ati_keys",
        "ati_deleted_keys",
        "ati_call_log",
        "ati_audit_log",
    ] {
        sqlx::query(&format!("TRUNCATE {table}"))
            .execute(pool)
            .await
            .expect("truncate");
    }
}

fn mk_params(user_id: &str, alias: &str, tools: Vec<&str>) -> IssueParams {
    IssueParams {
        user_id: user_id.to_string(),
        key_alias: alias.to_string(),
        tools: tools.into_iter().map(String::from).collect(),
        providers: vec![],
        categories: vec![],
        skills: vec![],
        expires_in: None,
        metadata: serde_json::Value::Null,
        created_by: Some("test".into()),
    }
}

/// Build a proxy `ProxyState` wired to a real DB + key store and a one-tool
/// manifest pointing at the given mock server.
fn build_state_for_test(
    mock_uri: &str,
    pool: sqlx::PgPool,
    store: Arc<KeyStore>,
    admin_token: Option<String>,
) -> (tempfile::TempDir, Arc<ProxyState>) {
    use ati::core::auth_generator::AuthCache;
    use ati::core::keyring::Keyring;

    let dir = tempfile::tempdir().expect("tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("manifests dir");
    let manifest = format!(
        r#"
[provider]
name = "test_provider"
description = "Test"
base_url = "{mock_uri}"
auth_type = "none"

[[tools]]
name = "test_get"
description = "test get"
endpoint = "/search"
method = "GET"

[[tools]]
name = "test_other"
description = "test other"
endpoint = "/other"
method = "GET"
"#
    );
    std::fs::write(manifests_dir.join("test.toml"), manifest).expect("write manifest");
    let registry = ManifestRegistry::load(&manifests_dir).expect("load manifest");

    // Spin up a JWT config so the proxy enforces auth on /call (rather than
    // dev-mode bypass). We use HS256 with a test secret; we never actually
    // mint JWTs in these tests — auth flows through the Ati-Key path.
    let jwt_config = ati::core::jwt::config_from_secret(
        b"test-secret-key-32-bytes-long!!!",
        None,
        "ati-proxy".into(),
    );

    let state = Arc::new(ProxyState {
        registry,
        skill_registry: SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap(),
        keyring: Keyring::empty(),
        jwt_config: Some(jwt_config),
        jwks_json: None,
        auth_cache: AuthCache::new(),
        db: ati::core::db::DbState::Connected(pool),
        passthrough: None,
        sig_verify: std::sync::Arc::new(
            ati::core::sig_verify::SigVerifyConfig::build(
                ati::core::sig_verify::SigVerifyMode::Log,
                60,
                ati::core::sig_verify::DEFAULT_EXEMPT_PATHS,
                &ati::core::keyring::Keyring::empty(),
            )
            .unwrap(),
        ),
        key_store: Some(store),
        admin_token,
    });
    (dir, state)
}

#[tokio::test]
async fn issue_writes_row_and_lookup_returns_it() {
    let _g = shared_lock().lock().await;
    let Some(pool) = connect_test_db().await else {
        eprintln!("SKIP: ATI_DB_URL_TEST not set");
        return;
    };
    truncate_all(&pool).await;

    let store = KeyStore::new(pool.clone()).await.expect("store");
    let issued = store
        .issue(mk_params("u1", "alias1", vec!["test_get"]))
        .await
        .expect("issue");
    assert!(issued.raw_key.starts_with("ati-key_"));
    assert_eq!(issued.alias, "alias1");

    let row: (String, String, Vec<String>) =
        sqlx::query_as("SELECT user_id, key_alias, tools FROM ati_keys WHERE token_hash = $1")
            .bind(&issued.hash)
            .fetch_one(&pool)
            .await
            .expect("fetch row");
    assert_eq!(row.0, "u1");
    assert_eq!(row.1, "alias1");
    assert_eq!(row.2, vec!["test_get"]);

    let key = store
        .lookup(&issued.hash)
        .await
        .expect("lookup")
        .expect("Some");
    assert_eq!(key.user_id, "u1");
    assert!(key.is_active());

    // Audit log row landed too.
    let audit_count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM ati_audit_log WHERE action = 'key.issue' AND target_id = $1",
    )
    .bind(&issued.hash)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit_count.0, 1);
}

#[tokio::test]
async fn revoke_moves_row_and_purges_cache() {
    let _g = shared_lock().lock().await;
    let Some(pool) = connect_test_db().await else {
        eprintln!("SKIP: ATI_DB_URL_TEST not set");
        return;
    };
    truncate_all(&pool).await;

    let store = KeyStore::new(pool.clone()).await.expect("store");
    let issued = store
        .issue(mk_params("u1", "rev1", vec!["test_get"]))
        .await
        .expect("issue");

    // Warm the cache.
    let _ = store.lookup(&issued.hash).await;

    let did_revoke = store
        .revoke(&issued.hash, Some("admin"))
        .await
        .expect("revoke");
    assert!(did_revoke);

    // Source row gone.
    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM ati_keys WHERE token_hash = $1")
        .bind(&issued.hash)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 0);

    // Snapshot row in deleted_keys.
    let deleted_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM ati_deleted_keys WHERE token_hash = $1")
            .bind(&issued.hash)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(deleted_count.0, 1);

    // Cache purged immediately on the revoking node.
    let after = store.lookup(&issued.hash).await.expect("lookup");
    assert!(after.is_none(), "lookup must miss after revoke");
}

#[tokio::test]
async fn ati_key_auth_succeeds_against_call() {
    let _g = shared_lock().lock().await;
    let Some(pool) = connect_test_db().await else {
        eprintln!("SKIP: ATI_DB_URL_TEST not set");
        return;
    };
    truncate_all(&pool).await;

    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": []})))
        .mount(&mock)
        .await;

    let store = KeyStore::new(pool.clone()).await.expect("store");
    let issued = store
        .issue(mk_params("u1", "ok1", vec!["test_get"]))
        .await
        .expect("issue");

    let (_dir, state) = build_state_for_test(&mock.uri(), pool, store, None);
    let app = build_router(state);

    let body = json!({"tool_name": "test_get", "args": {}});
    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("authorization", format!("Ati-Key {}", issued.raw_key))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn ati_key_scope_check_denies_out_of_scope_tool() {
    let _g = shared_lock().lock().await;
    let Some(pool) = connect_test_db().await else {
        eprintln!("SKIP: ATI_DB_URL_TEST not set");
        return;
    };
    truncate_all(&pool).await;

    let mock = MockServer::start().await;
    let store = KeyStore::new(pool.clone()).await.expect("store");
    // Issue a key scoped to test_get only — calling test_other must be denied
    // because the synthetic claims only carry `tool:test_get`.
    let issued = store
        .issue(mk_params("u1", "scoped", vec!["test_get"]))
        .await
        .expect("issue");

    let (_dir, state) = build_state_for_test(&mock.uri(), pool, store, None);
    let app = build_router(state);

    let body = json!({"tool_name": "test_other", "args": {}});
    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("authorization", format!("Ati-Key {}", issued.raw_key))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn revoked_key_returns_401() {
    let _g = shared_lock().lock().await;
    let Some(pool) = connect_test_db().await else {
        eprintln!("SKIP: ATI_DB_URL_TEST not set");
        return;
    };
    truncate_all(&pool).await;

    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&mock)
        .await;

    let store = KeyStore::new(pool.clone()).await.expect("store");
    let issued = store
        .issue(mk_params("u1", "rev2", vec!["test_get"]))
        .await
        .expect("issue");
    store
        .revoke(&issued.hash, Some("admin"))
        .await
        .expect("revoke");

    let (_dir, state) = build_state_for_test(&mock.uri(), pool, store, None);
    let app = build_router(state);

    let body = json!({"tool_name": "test_get", "args": {}});
    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("authorization", format!("Ati-Key {}", issued.raw_key))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cross_pod_listen_notify_invalidates_cache() {
    // Two `KeyStore` instances against the same DB. Revoke through A; B's
    // cache must be invalidated within ~1s by the LISTEN/NOTIFY channel
    // before the 30s TTL would otherwise rescue it.
    let _g = shared_lock().lock().await;
    let Some(pool) = connect_test_db().await else {
        eprintln!("SKIP: ATI_DB_URL_TEST not set");
        return;
    };
    truncate_all(&pool).await;

    let store_a = KeyStore::new(pool.clone()).await.expect("store A");
    let store_b = KeyStore::new(pool.clone()).await.expect("store B");

    let issued = store_a
        .issue(mk_params("u1", "cross", vec!["test_get"]))
        .await
        .expect("issue");

    // Warm B's cache.
    let warm = store_b
        .lookup(&issued.hash)
        .await
        .expect("lookup B")
        .expect("Some");
    assert_eq!(warm.user_id, "u1");

    // Revoke via A.
    store_a
        .revoke(&issued.hash, Some("admin"))
        .await
        .expect("revoke");

    // Wait for NOTIFY to propagate (poll up to 3s).
    let mut after: Option<keys::AtiKey> = warm.clone().into();
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        match store_b
            .lookup(&issued.hash)
            .await
            .expect("lookup B post-revoke")
        {
            None => {
                after = None;
                break;
            }
            Some(_) => continue,
        }
    }
    assert!(
        after.is_none(),
        "Pod B's cache must be invalidated within 3s via LISTEN/NOTIFY"
    );
}

#[tokio::test]
async fn bulk_revoke_by_user_id_revokes_all_matching() {
    let _g = shared_lock().lock().await;
    let Some(pool) = connect_test_db().await else {
        eprintln!("SKIP: ATI_DB_URL_TEST not set");
        return;
    };
    truncate_all(&pool).await;

    let store = KeyStore::new(pool.clone()).await.expect("store");
    let _a = store
        .issue(mk_params("user-a", "alias-1", vec!["test_get"]))
        .await
        .expect("a");
    let _b = store
        .issue(mk_params("user-a", "alias-2", vec!["test_get"]))
        .await
        .expect("b");
    let _c = store
        .issue(mk_params("user-b", "alias-3", vec!["test_get"]))
        .await
        .expect("c");

    let n = store
        .bulk_revoke(
            BulkRevokeFilter {
                user_id: Some("user-a".into()),
                ..Default::default()
            },
            Some("admin"),
        )
        .await
        .expect("bulk revoke");
    assert_eq!(n, 2);

    let remaining: (i64,) = sqlx::query_as("SELECT count(*) FROM ati_keys")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining.0, 1, "user-b's row must remain");
}

#[tokio::test]
async fn bulk_revoke_alias_prefix_does_not_match_wildcards() {
    // Regression for the security bug Greptile flagged: passing `%` as the
    // alias_prefix would previously expand to `LIKE '%%'` and revoke every
    // row in the table. The fix escapes `%` and `_` so they match literally.
    let _g = shared_lock().lock().await;
    let Some(pool) = connect_test_db().await else {
        eprintln!("SKIP: ATI_DB_URL_TEST not set");
        return;
    };
    truncate_all(&pool).await;

    let store = KeyStore::new(pool.clone()).await.expect("store");
    // Three keys with non-wildcard aliases.
    let _a = store
        .issue(mk_params("user-a", "alpha-1", vec!["test_get"]))
        .await
        .expect("a");
    let _b = store
        .issue(mk_params("user-a", "beta-1", vec!["test_get"]))
        .await
        .expect("b");
    let _c = store
        .issue(mk_params("user-b", "gamma-1", vec!["test_get"]))
        .await
        .expect("c");

    // Pass `%` as the prefix — should match ZERO rows, not the entire table.
    let n = store
        .bulk_revoke(
            BulkRevokeFilter {
                alias_prefix: Some("%".into()),
                ..Default::default()
            },
            Some("admin"),
        )
        .await
        .expect("bulk revoke");
    assert_eq!(n, 0, "alias_prefix='%' must match zero rows after escape");

    // All three keys still present.
    let remaining: (i64,) = sqlx::query_as("SELECT count(*) FROM ati_keys")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining.0, 3);
}

#[tokio::test]
async fn bulk_revoke_with_empty_filter_errors() {
    let _g = shared_lock().lock().await;
    let Some(pool) = connect_test_db().await else {
        eprintln!("SKIP: ATI_DB_URL_TEST not set");
        return;
    };

    let store = KeyStore::new(pool).await.expect("store");
    let result = store
        .bulk_revoke(BulkRevokeFilter::default(), Some("admin"))
        .await;
    assert!(matches!(result, Err(keys::KeyStoreError::InvalidParams(_))));
}

#[tokio::test]
async fn admin_endpoint_requires_master_token() {
    let _g = shared_lock().lock().await;
    let Some(pool) = connect_test_db().await else {
        eprintln!("SKIP: ATI_DB_URL_TEST not set");
        return;
    };
    truncate_all(&pool).await;

    let mock = MockServer::start().await;
    let store = KeyStore::new(pool.clone()).await.expect("store");
    let (_dir, state) =
        build_state_for_test(&mock.uri(), pool, store, Some("master-secret".into()));
    let app = build_router(state);

    // Right token → 201.
    let req = Request::builder()
        .method("POST")
        .uri("/admin/keys/issue")
        .header("authorization", "Bearer master-secret")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"user_id":"u","alias":"job","tools":["test_get"]}).to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Wrong token → 401.
    let req = Request::builder()
        .method("POST")
        .uri("/admin/keys/issue")
        .header("authorization", "Bearer wrong")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"user_id":"u","alias":"job2","tools":["test_get"]}).to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_endpoint_503_when_admin_token_unset() {
    let _g = shared_lock().lock().await;
    let Some(pool) = connect_test_db().await else {
        eprintln!("SKIP: ATI_DB_URL_TEST not set");
        return;
    };
    truncate_all(&pool).await;

    let mock = MockServer::start().await;
    let store = KeyStore::new(pool.clone()).await.expect("store");
    let (_dir, state) = build_state_for_test(&mock.uri(), pool, store, None);
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/admin/keys/issue")
        .header("authorization", "Bearer anything")
        .header("content-type", "application/json")
        .body(Body::from(json!({"user_id":"u","alias":"job"}).to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}
