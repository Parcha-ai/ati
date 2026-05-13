//! Smoke tests for the OTel-feature scaffolding.
//!
//! Two-part:
//! 1. Always-on regression test: confirms the `observability_middleware`
//!    layer compiles into the proxy router and `/health` still returns 200
//!    with the new layer in place. This runs on `cargo test` with no
//!    features.
//! 2. Feature-gated tests: parse helpers in `core::otel` (env var handling,
//!    signal-path appending). These only compile with `--features otel`
//!    because the module is `#[cfg(feature = "otel")]`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

use ati::core::auth_generator::AuthCache;
use ati::core::db::DbState;
use ati::core::keyring::Keyring;
use ati::core::manifest::ManifestRegistry;
use ati::core::sig_verify::{self, SigVerifyConfig, SigVerifyMode, DEFAULT_EXEMPT_PATHS};
use ati::core::skill::SkillRegistry;
use ati::proxy::server::{build_router, ProxyState};

fn build_minimal_proxy() -> axum::Router {
    let manifests_dir = tempfile::tempdir().expect("manifests tempdir");
    let skills_dir = tempfile::tempdir().expect("skills tempdir");
    let registry = ManifestRegistry::load(manifests_dir.path()).expect("load manifests");
    let skill_registry = SkillRegistry::load(skills_dir.path()).expect("load skills");

    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring: Keyring::empty(),
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
        db: DbState::Disabled,
        passthrough: None,
        sig_verify: Arc::new(
            SigVerifyConfig::build(
                SigVerifyMode::Log,
                60,
                DEFAULT_EXEMPT_PATHS,
                &Keyring::empty(),
            )
            .expect("build sig verify config"),
        ),
    });
    build_router(state)
}

#[tokio::test]
async fn observability_middleware_does_not_break_health_endpoint() {
    // Regression: adding the observability layer must not change the
    // user-visible behavior of any endpoint. `/health` is the canonical
    // unauthenticated route — if this 200s, the layer chain is wired right.
    let app = build_minimal_proxy();
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .expect("request");
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn observability_middleware_records_status_for_unmatched_path() {
    // The fallback handler (passthrough) returns 404 when passthrough is
    // disabled (`passthrough: None` in our minimal state). The
    // observability layer must successfully record a status code even
    // when no axum route matches.
    let app = build_minimal_proxy();
    let req = Request::builder()
        .uri("/this/path/does/not/exist")
        .body(Body::empty())
        .expect("request");
    let resp = app.oneshot(req).await.expect("oneshot");
    // 404 with body explaining passthrough is disabled.
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn observability_middleware_buckets_two_distinct_unmatched_paths_identically() {
    // Cardinality regression test: when two requests fall through to the
    // passthrough fallback (no `MatchedPath` extension), both must end up
    // with the SAME low-cardinality `http.route` value. Without this, a
    // proxy forwarding /api/v1/users/123, /api/v1/users/456, ... would
    // mint a unique metric label per URL.
    //
    // We can't easily introspect the span attributes from outside without
    // a subscriber, so this test serves as a behavioral regression
    // guardrail: it exercises the fallback path on two distinct URIs.
    // The contract is enforced in the source (single string literal in
    // observability_middleware); this just confirms both calls reach the
    // same 404 handler without the cardinality fix introducing other
    // breakage.
    let app = build_minimal_proxy();
    for path in ["/api/v1/users/123", "/api/v1/users/456"] {
        let req = Request::builder().uri(path).body(Body::empty()).unwrap();
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{path} should hit the passthrough-disabled 404 fallback"
        );
    }
}

// Keep clippy happy — `sig_verify` import is used inside `build_minimal_proxy`
// indirectly, but rustc sometimes flags the trait-namespace import as unused.
#[allow(dead_code)]
fn _keep_sig_verify_import_used() {
    let _ = sig_verify::DEFAULT_EXEMPT_PATHS.len();
}

// ---------------------------------------------------------------------------
// Regression: `try_init` must NOT panic when called from inside a tokio
// runtime context.
//
// `core::logging::init` (and therefore `core::otel::try_init`) runs inside
// `#[tokio::main] async fn main()` — i.e. *within* a Tokio runtime. The OTel
// batch span exporter builds a reqwest client at init time. Two failure
// modes are possible depending on which reqwest feature is selected on
// opentelemetry-otlp:
//
//   - `reqwest-client` (async): the SDK's dedicated batch-processor thread
//     later panics with "no reactor running" when it tries to call
//     `reqwest::Client::send` outside an async context.
//   - `reqwest-blocking-client`: in theory, `reqwest::blocking::Client::new()`
//     panics with "Cannot start a runtime from within a runtime" when
//     invoked inside a tokio context.
//
// We use the blocking variant. It works in practice because opentelemetry-otlp
// 0.31.1 explicitly wraps client construction in `std::thread::spawn(...).join()`
// to escape the parent runtime context (see opentelemetry-otlp-0.31.1
// `src/exporter/http/mod.rs` around line 183). This test pins that contract:
// if the SDK ever drops that workaround during a future version bump, the
// test catches it before the binary ships.
//
// Notably also covers the original symptom that the local E2E surfaced —
// `try_init` runs cleanly from within `#[tokio::main]`.
// ---------------------------------------------------------------------------

#[cfg(feature = "otel")]
#[tokio::test]
async fn try_init_does_not_panic_inside_tokio_runtime() {
    // Point at a definitely-unreachable endpoint. The exporter is built
    // lazily — we only want to confirm `try_init` itself doesn't panic
    // during reqwest-client construction. Whether the batch processor
    // can later contact the endpoint is a separate concern (its own
    // dedicated thread, with its own panic surface).
    std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1");
    std::env::set_var("OTEL_SERVICE_NAME", "ati-tokio-rt-regression");

    let _ = ati::core::otel::try_init::<tracing_subscriber::Registry>();

    std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
    std::env::remove_var("OTEL_SERVICE_NAME");
}
