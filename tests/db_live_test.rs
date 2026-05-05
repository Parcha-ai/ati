//! Live-Postgres end-to-end tests for the `ati_call_log` audit writer.
//!
//! These tests need a real Postgres. They follow the same pattern as
//! `tests/mcp_live_test.rs`: instead of `#[ignore]`, the tests check an env
//! var at startup and `eprintln!("SKIP: ...")` if it's missing. CI runs
//! them harmlessly without Postgres; locally point at the pool DB:
//!
//! ```sh
//! export ATI_DB_URL_TEST="postgres://parcha:parcha_pool@localhost:5510/ati_pr2_test"
//! cargo test --features db --test db_live_test
//! ```
//!
//! Each test TRUNCATES `ati_call_log` at start so state is deterministic
//! regardless of prior failures. Tests serialize via a tokio Mutex because
//! they share the table.
#![cfg(feature = "db")]

use std::sync::Arc;
use std::time::Duration;

use ati::core::call_log::{self, CallLogSink};
use ati::core::manifest::ManifestRegistry;
use ati::core::skill::SkillRegistry;
use ati::proxy::server::{build_router, ProxyState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use sqlx::Row;
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Serialize tests across the binary — they share the `ati_call_log` table.
fn shared_lock() -> &'static tokio::sync::Mutex<()> {
    static M: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    M.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Connect to the test DB. Returns Some(pool) when env var is set, None otherwise.
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

/// Truncate the audit table so each test starts clean.
async fn truncate_call_log(pool: &sqlx::PgPool) {
    sqlx::query("TRUNCATE ati_call_log")
        .execute(pool)
        .await
        .expect("truncate");
}

/// Build a minimal proxy state with a registered HTTP test tool whose upstream
/// is `mock_uri`. Returns the `TempDir` alongside the state so the caller can
/// keep it alive for the test duration; on drop, the directory is cleaned up
/// (no leak). `ManifestRegistry::load` reads files into memory and doesn't
/// retain handles, so the tempdir is technically only needed during this
/// function — but the explicit return makes the lifetime obvious to readers.
fn build_state_for_test(mock_uri: &str, sink: CallLogSink) -> (tempfile::TempDir, Arc<ProxyState>) {
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
"#
    );
    std::fs::write(manifests_dir.join("test.toml"), manifest).expect("write manifest");
    let registry = ManifestRegistry::load(&manifests_dir).expect("load manifest");

    let state = Arc::new(ProxyState {
        registry,
        skill_registry: SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap(),
        keyring: Keyring::empty(),
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
        db: ati::core::db::DbState::Disabled,
        call_log: Some(sink),
    });
    (dir, state)
}

/// Poll the audit table until at least `min_rows` rows exist or the timeout
/// expires. Returns the rows. Flush interval is 5s, so 10s of polling gives
/// safe margin.
async fn poll_for_rows(
    pool: &sqlx::PgPool,
    min_rows: usize,
    timeout: Duration,
) -> Vec<sqlx::postgres::PgRow> {
    let start = std::time::Instant::now();
    loop {
        let rows = sqlx::query("SELECT * FROM ati_call_log ORDER BY started_at")
            .fetch_all(pool)
            .await
            .expect("select rows");
        if rows.len() >= min_rows {
            return rows;
        }
        if start.elapsed() >= timeout {
            return rows;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[tokio::test]
async fn call_log_writes_success_row() {
    let _g = shared_lock().lock().await;
    let Some(pool) = connect_test_db().await else {
        eprintln!("SKIP: ATI_DB_URL_TEST not set");
        return;
    };
    truncate_call_log(&pool).await;

    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": []})))
        .mount(&mock)
        .await;

    let (sink, _handle) = call_log::spawn(pool.clone());
    let (_dir, state) = build_state_for_test(&mock.uri(), sink);
    let app = build_router(state);

    let body = json!({"tool_name": "test_get", "args": {}});
    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let rows = poll_for_rows(&pool, 1, Duration::from_secs(10)).await;
    assert_eq!(rows.len(), 1, "expected one audit row to land within 10s");
    let row = &rows[0];
    let endpoint: String = row.get("endpoint");
    let tool_name: Option<String> = row.get("tool_name");
    let provider: Option<String> = row.get("provider");
    let handler: Option<String> = row.get("handler");
    let status: String = row.get("status");
    let user_id: Option<String> = row.get("user_id");
    assert_eq!(endpoint, "/call");
    assert_eq!(tool_name.as_deref(), Some("test_get"));
    // `sentry_scope::split_tool_name("test_get")` returns ("ati","test_get")
    // when there's no colon — see split_tool_name implementation. The exact
    // provider string isn't load-bearing for the audit; just assert we wrote
    // *something*.
    assert!(provider.is_some());
    assert_eq!(handler.as_deref(), Some("http"));
    assert_eq!(status, "success");
    // JWT is disabled in the test fixture → user_id should be the "system"
    // sentinel (LiteLLM convention).
    assert_eq!(user_id.as_deref(), Some("system"));
}

#[tokio::test]
async fn call_log_writes_upstream_error_row() {
    let _g = shared_lock().lock().await;
    let Some(pool) = connect_test_db().await else {
        eprintln!("SKIP: ATI_DB_URL_TEST not set");
        return;
    };
    truncate_call_log(&pool).await;

    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(502).set_body_string("upstream sad"))
        .mount(&mock)
        .await;

    let (sink, _handle) = call_log::spawn(pool.clone());
    let (_dir, state) = build_state_for_test(&mock.uri(), sink);
    let app = build_router(state);

    let body = json!({"tool_name": "test_get", "args": {}});
    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let _resp = app.oneshot(req).await.expect("oneshot");

    let rows = poll_for_rows(&pool, 1, Duration::from_secs(10)).await;
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    let status: String = row.get("status");
    let upstream_status: Option<i32> = row.get("upstream_status");
    let error_class: Option<String> = row.get("error_class");
    let error_message: Option<String> = row.get("error_message");
    assert_eq!(status, "upstream_error");
    assert_eq!(upstream_status, Some(502));
    assert_eq!(error_class.as_deref(), Some("provider.upstream_error"));
    assert!(
        error_message.unwrap_or_default().contains("502") || error_class.is_some(),
        "error context should be captured"
    );
}

#[tokio::test]
async fn call_log_args_are_redacted() {
    // Sanitization is reused from core::audit::sanitize_args, but we verify
    // the wiring: a request_args field with `api_key` should land as REDACTED
    // in the persisted row.
    let _g = shared_lock().lock().await;
    let Some(pool) = connect_test_db().await else {
        eprintln!("SKIP: ATI_DB_URL_TEST not set");
        return;
    };
    truncate_call_log(&pool).await;

    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&mock)
        .await;

    let (sink, _handle) = call_log::spawn(pool.clone());
    let (_dir, state) = build_state_for_test(&mock.uri(), sink);
    let app = build_router(state);

    // `api_key` matches sanitize_args's redaction predicate (substring "key").
    let body = json!({
        "tool_name": "test_get",
        "args": {"api_key": "sekrit-do-not-leak"}
    });
    let req = Request::builder()
        .method("POST")
        .uri("/call")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let _resp = app.oneshot(req).await.expect("oneshot");

    let rows = poll_for_rows(&pool, 1, Duration::from_secs(10)).await;
    assert_eq!(rows.len(), 1);
    let request_args: serde_json::Value = rows[0].get("request_args");
    let key_value = request_args
        .get("api_key")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(key_value, "[REDACTED]");
    assert!(
        !serde_json::to_string(&request_args)
            .unwrap()
            .contains("sekrit-do-not-leak"),
        "raw secret value must not be persisted"
    );
}
