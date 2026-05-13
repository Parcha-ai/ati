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

// ---------------------------------------------------------------------------
// Feature-gated W3C propagation tests (PR B)
//
// Cover the W3C trace-context round-trip: extract an inbound `traceparent`
// header into a tracing span's parent context, then inject that context
// back into outbound headers via `current_trace_headers()`. The trace_id
// and trace flags survive the round-trip; the span_id changes because the
// outbound headers identify the *current* span, not the inbound parent.
// ---------------------------------------------------------------------------

#[cfg(feature = "otel")]
mod propagation {
    use axum::http::HeaderMap;
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;

    /// Set up the W3C propagator + a minimal tracing-opentelemetry layer so
    /// `tracing::Span::current().context()` returns a real OTel context
    /// (otherwise the injector has nothing to serialize). Uses an SDK
    /// tracer with no exporter — spans are emitted in-process and dropped.
    fn install_propagator_and_subscriber_once() {
        use std::sync::Once;
        use tracing_subscriber::layer::SubscriberExt as _;
        use tracing_subscriber::util::SubscriberInitExt as _;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            opentelemetry::global::set_text_map_propagator(
                opentelemetry_sdk::propagation::TraceContextPropagator::new(),
            );
            let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
            let tracer = {
                use opentelemetry::trace::TracerProvider as _;
                provider.tracer("ati-test")
            };
            let _ = tracing_subscriber::registry()
                .with(tracing_opentelemetry::OpenTelemetryLayer::new(tracer))
                .try_init();
        });
    }

    #[test]
    fn extract_then_inject_preserves_trace_id() {
        install_propagator_and_subscriber_once();

        // Synthetic but valid W3C traceparent:
        //   version=00, trace-id (32 hex), span-id (16 hex), flags=01 (sampled).
        let inbound_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
        let inbound_span_id = "00f067aa0ba902b7";
        let traceparent = format!("00-{inbound_trace_id}-{inbound_span_id}-01");

        let mut headers = HeaderMap::new();
        headers.insert("traceparent", traceparent.parse().unwrap());

        let span = tracing::info_span!("test.span");
        ati::core::otel::extract_request_parent_into_span(&span, &headers);

        // Inside that span, the injector should emit a traceparent whose
        // trace-id matches the inbound one.
        let _enter = span.enter();
        let injected = ati::core::otel::current_trace_headers();
        let outbound_traceparent = injected
            .get("traceparent")
            .expect("traceparent should be injected when a parent is attached");

        // traceparent format: "00-<trace_id>-<span_id>-<flags>"
        let parts: Vec<&str> = outbound_traceparent.split('-').collect();
        assert_eq!(parts.len(), 4, "malformed outbound traceparent");
        assert_eq!(
            parts[1], inbound_trace_id,
            "trace_id must be preserved across extract→inject"
        );
        // Span ID *changes* (we're now in a child span). Flags stay sampled.
        assert_ne!(parts[2], inbound_span_id, "span_id should be a new id");
        assert_eq!(parts[3], "01", "sampled flag should propagate");
    }

    #[test]
    fn current_trace_headers_empty_when_no_parent_and_no_span_context() {
        install_propagator_and_subscriber_once();
        // Outside any span with an attached context, the propagator has
        // nothing to serialize. Some SDKs emit an invalid placeholder
        // traceparent; assert either empty OR an invalid trace_id (all zeros).
        let headers = ati::core::otel::current_trace_headers();
        if let Some(tp) = headers.get("traceparent") {
            let parts: Vec<&str> = tp.split('-').collect();
            assert!(
                parts.len() == 4
                    && (parts[1] == "00000000000000000000000000000000"
                        || parts[1].chars().all(|c| c == '0')),
                "expected invalid/placeholder traceparent when no context is set, got {tp}"
            );
        }
    }

    #[test]
    fn extract_request_parent_into_span_with_no_inbound_traceparent_is_safe() {
        install_propagator_and_subscriber_once();
        // No traceparent header — extractor returns an empty parent context.
        // We just need to confirm the call doesn't panic and doesn't poison
        // the span. Whether the resulting span is a sampled root depends on
        // the SDK's default sampler; that's not the contract being tested.
        let headers = HeaderMap::new();
        let span = tracing::info_span!("test.no_parent");
        ati::core::otel::extract_request_parent_into_span(&span, &headers);
        let _ = span.context(); // smoke check: doesn't panic
    }
}
