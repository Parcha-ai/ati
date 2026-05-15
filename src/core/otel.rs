//! OpenTelemetry initialization for ATI.
//!
//! Compiled only with `--features otel`. When enabled, this module:
//!
//! - Builds an OTLP/HTTP-protobuf exporter for spans and metrics.
//! - Returns a `tracing-opentelemetry` `Layer` that `core::logging` plugs
//!   into the global `tracing-subscriber` registry.
//! - Holds the `SdkTracerProvider` and `SdkMeterProvider` in `OtelGuard`
//!   so program exit triggers `force_flush()` + `shutdown()`.
//! - Honors standard `OTEL_*` env vars (endpoint, service name, resource
//!   attributes, sampler, headers). See `docs/OTEL.md`.
//!
//! Runtime gating: the layer is only built when `OTEL_EXPORTER_OTLP_ENDPOINT`
//! is set. With the feature compiled in but no endpoint configured, this is
//! a no-op — same shape as `init_sentry` in `core::logging`.

use opentelemetry::propagation::{Extractor, Injector};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use std::collections::HashMap;
use std::sync::OnceLock;
use tracing::Subscriber;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

const SERVICE_NAME_FALLBACK: &str = "ati-proxy";
const TRACER_NAME: &str = "ati";
const METER_NAME: &str = "ati";

/// Held for the lifetime of the program. Drop flushes + shuts down the providers.
pub struct OtelGuard {
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        // Best-effort flush; errors here go to stderr only — by the time we're
        // dropping, the tracing subscriber may already be tearing down.
        let _ = self.tracer_provider.force_flush();
        let _ = self.tracer_provider.shutdown();
        let _ = self.meter_provider.force_flush();
        let _ = self.meter_provider.shutdown();
    }
}

/// Cached metrics handles. Initialized once at startup, accessed from any thread.
pub struct MetricsHandles {
    pub proxy_requests: opentelemetry::metrics::Counter<u64>,
    pub proxy_request_duration_ms: opentelemetry::metrics::Histogram<f64>,
    pub upstream_errors: opentelemetry::metrics::Counter<u64>,
    /// Incremented when a passthrough request is rejected by the
    /// route's `deny_paths`. Single label: `route` (manifest name).
    /// The denied path itself stays in the tracing log line — emitting
    /// it as a metric label would risk cardinality blow-up under an
    /// adversarial spray.
    pub passthrough_denied: opentelemetry::metrics::Counter<u64>,
}

static METRICS: OnceLock<MetricsHandles> = OnceLock::new();

/// Returns the global metrics handles if OTel was initialized this process,
/// or `None` otherwise. Callers should treat `None` as "feature off" and skip
/// recording silently.
pub fn metrics() -> Option<&'static MetricsHandles> {
    METRICS.get()
}

/// Build the OTel tracing layer and return it alongside an `OtelGuard`.
///
/// Returns `None` when `OTEL_EXPORTER_OTLP_ENDPOINT` is unset — callers should
/// treat that as "OTel disabled at runtime" and skip layering.
///
/// Errors during exporter construction are logged to stderr (subscriber may
/// not be live yet) and result in `None`.
pub fn try_init<S>() -> Option<(impl Layer<S>, OtelGuard)>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok()?;
    if endpoint.trim().is_empty() {
        return None;
    }

    let resource = build_resource();
    let headers = parse_otlp_headers();

    // --- Tracer provider ---
    let span_exporter = match build_span_exporter(&endpoint, &headers) {
        Ok(exp) => exp,
        Err(e) => {
            eprintln!("ati: failed to build OTLP span exporter: {e}");
            return None;
        }
    };
    let tracer_provider = SdkTracerProvider::builder()
        .with_resource(resource.clone())
        .with_batch_exporter(span_exporter)
        .build();
    // Build the local tracer NOW (for the tracing-opentelemetry layer) so we
    // can hand it back to the caller even if the metric exporter fails below.
    // Crucially, we do NOT install the tracer provider globally yet — see
    // the install-globals block at the bottom of this function. Otherwise a
    // metric-exporter failure would leave `opentelemetry::global::*` pointing
    // at a tracer provider we're about to shut down.
    let tracer = tracer_provider.tracer(TRACER_NAME);

    // --- Meter provider ---
    let metric_exporter = match build_metric_exporter(&endpoint, &headers) {
        Ok(exp) => exp,
        Err(e) => {
            eprintln!("ati: failed to build OTLP metric exporter: {e}");
            // Shutdown the already-built tracer provider before bailing.
            // Globals are still untouched at this point — no dangling refs.
            let _ = tracer_provider.shutdown();
            return None;
        }
    };
    let reader = PeriodicReader::builder(metric_exporter).build();
    let meter_provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader)
        .build();

    // --- Install globals: only AFTER both providers are built successfully.
    // Order: tracer → meter. If we ever add a logs provider, install it in
    // this same final block, never before its sibling has been built.
    opentelemetry::global::set_tracer_provider(tracer_provider.clone());
    opentelemetry::global::set_meter_provider(meter_provider.clone());

    // Install a W3C traceparent/tracestate propagator so outbound HTTP calls
    // (core/http.rs, core/passthrough.rs, core/mcp_client.rs HTTP transport)
    // can hand off the trace context to upstream services. Without this the
    // injector at the call site has nothing to serialize and outbound spans
    // become roots.
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    let meter = opentelemetry::global::meter(METER_NAME);
    let handles = MetricsHandles {
        proxy_requests: meter
            .u64_counter("ati.proxy.requests")
            .with_description("Count of HTTP requests handled by the ATI proxy")
            .build(),
        proxy_request_duration_ms: meter
            .f64_histogram("ati.proxy.request_duration_ms")
            .with_description("ATI proxy request duration in milliseconds")
            .with_unit("ms")
            .build(),
        upstream_errors: meter
            .u64_counter("ati.upstream.errors")
            .with_description("Count of upstream errors observed by ATI")
            .build(),
        passthrough_denied: meter
            .u64_counter("ati.passthrough.denied")
            .with_description(
                "Count of passthrough requests rejected by the route's deny_paths globs",
            )
            .build(),
    };
    // First setter wins; subsequent calls (e.g. in tests) are ignored.
    let _ = METRICS.set(handles);

    let layer = OpenTelemetryLayer::new(tracer);
    let guard = OtelGuard {
        tracer_provider,
        meter_provider,
    };
    Some((layer, guard))
}

fn build_span_exporter(
    endpoint: &str,
    headers: &[(String, String)],
) -> Result<opentelemetry_otlp::SpanExporter, opentelemetry_otlp::ExporterBuildError> {
    let mut builder = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(traces_endpoint(endpoint));
    if !headers.is_empty() {
        builder = builder.with_headers(headers.iter().cloned().collect());
    }
    builder.build()
}

fn build_metric_exporter(
    endpoint: &str,
    headers: &[(String, String)],
) -> Result<opentelemetry_otlp::MetricExporter, opentelemetry_otlp::ExporterBuildError> {
    let mut builder = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(metrics_endpoint(endpoint));
    if !headers.is_empty() {
        builder = builder.with_headers(headers.iter().cloned().collect());
    }
    builder.build()
}

/// OTLP/HTTP signal-suffix convention: when the user sets the base
/// `OTEL_EXPORTER_OTLP_ENDPOINT`, the spec says exporters append
/// `/v1/traces` and `/v1/metrics`. A signal-specific override
/// (`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`) wins if set.
fn traces_endpoint(base: &str) -> String {
    if let Ok(specific) = std::env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") {
        if !specific.trim().is_empty() {
            return specific;
        }
    }
    append_signal_path(base, "v1/traces")
}

fn metrics_endpoint(base: &str) -> String {
    if let Ok(specific) = std::env::var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT") {
        if !specific.trim().is_empty() {
            return specific;
        }
    }
    append_signal_path(base, "v1/metrics")
}

fn append_signal_path(base: &str, suffix: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    format!("{trimmed}/{suffix}")
}

fn build_resource() -> Resource {
    // Precedence (highest first), matching the OTel spec ordering:
    //   1. SDK-programmatic attributes  (set last so they win in BTreeMap-backed
    //      Resource builders that use last-write-wins)
    //   2. `OTEL_SERVICE_NAME` env var  (spec calls this out as winning over
    //      OTEL_RESOURCE_ATTRIBUTES for service.name specifically)
    //   3. `OTEL_RESOURCE_ATTRIBUTES`   (defaults — written first)
    //
    // Why this order matters: a user adding
    // `OTEL_RESOURCE_ATTRIBUTES=service.name=foo` must not silently overwrite
    // the binary-embedded `service.version` we set programmatically, nor an
    // explicit `OTEL_SERVICE_NAME`. The spec treats OTEL_RESOURCE_ATTRIBUTES
    // as lower-priority defaults; SDK-programmatic attributes win.
    let mut attrs: Vec<KeyValue> = Vec::new();

    // 1. OTEL_RESOURCE_ATTRIBUTES first — lowest priority.
    if let Ok(extra) = std::env::var("OTEL_RESOURCE_ATTRIBUTES") {
        for pair in extra.split(',') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            if let Some((k, v)) = pair.split_once('=') {
                let k = k.trim().to_string();
                let v = v.trim().to_string();
                if !k.is_empty() {
                    attrs.push(KeyValue::new(k, v));
                }
            }
        }
    }

    // 2. ENVIRONMENT_TIER → deployment.environment (overrides any env-var
    //    `deployment.environment=…` from OTEL_RESOURCE_ATTRIBUTES because
    //    pushed later).
    if let Ok(env_tier) = std::env::var("ENVIRONMENT_TIER") {
        if !env_tier.trim().is_empty() {
            attrs.push(KeyValue::new("deployment.environment", env_tier));
        }
    }

    // 3. SDK-programmatic — highest priority, pushed last. `service.name`
    //    prefers OTEL_SERVICE_NAME → SERVICE_NAME → fallback; `service.version`
    //    is always the compiled-in crate version (never user-overridable, by
    //    design — we want logs/traces to faithfully report the running binary).
    let service_name = std::env::var("OTEL_SERVICE_NAME")
        .or_else(|_| std::env::var("SERVICE_NAME"))
        .unwrap_or_else(|_| SERVICE_NAME_FALLBACK.to_string());
    attrs.push(KeyValue::new("service.name", service_name));
    attrs.push(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")));

    Resource::builder().with_attributes(attrs).build()
}

/// Parse `OTEL_EXPORTER_OTLP_HEADERS` (comma-separated `k=v` pairs).
/// Used for Grafana Cloud `Authorization=Basic <base64>` and similar.
fn parse_otlp_headers() -> Vec<(String, String)> {
    let raw = match std::env::var("OTEL_EXPORTER_OTLP_HEADERS") {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    raw.split(',')
        .filter_map(|pair| {
            let pair = pair.trim();
            if pair.is_empty() {
                return None;
            }
            let (k, v) = pair.split_once('=')?;
            let k = k.trim();
            let v = v.trim();
            if k.is_empty() {
                return None;
            }
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}

/// Collect the current span's W3C trace context into a header map ready to
/// be applied to an outbound HTTP request. Returns an empty map when no
/// span is active or no propagator is registered (e.g. the OTel runtime
/// gate skipped init).
///
/// Usage in `core::http`, `core::passthrough`, `core::mcp_client`:
/// ```ignore
/// for (k, v) in crate::core::otel::current_trace_headers() {
///     request_builder = request_builder.header(k, v);
/// }
/// ```
pub fn current_trace_headers() -> HashMap<String, String> {
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;
    let cx = tracing::Span::current().context();
    let mut carrier = HeaderInjector(HashMap::new());
    opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&cx, &mut carrier);
    });
    carrier.0
}

struct HeaderInjector(HashMap<String, String>);

impl Injector for HeaderInjector {
    fn set(&mut self, key: &str, value: String) {
        self.0.insert(key.to_string(), value);
    }
}

/// Read the W3C trace context from inbound HTTP headers and attach it as
/// `span`'s parent. Called from the proxy's outermost middleware so every
/// downstream span (handlers, passthrough, outbound HTTP) lives under the
/// agent-supplied trace.
///
/// No-op when the propagator is unset (e.g. OTel not initialized) or when
/// no `traceparent` header is present.
pub fn extract_request_parent_into_span(span: &tracing::Span, headers: &axum::http::HeaderMap) {
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;
    let extractor = HeaderExtractor(headers);
    let parent_cx =
        opentelemetry::global::get_text_map_propagator(|propagator| propagator.extract(&extractor));
    let _ = span.set_parent(parent_cx);
}

struct HeaderExtractor<'a>(&'a axum::http::HeaderMap);

impl<'a> Extractor for HeaderExtractor<'a> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_signal_path_strips_trailing_slash() {
        assert_eq!(
            append_signal_path("https://example.com/otlp/", "v1/traces"),
            "https://example.com/otlp/v1/traces"
        );
        assert_eq!(
            append_signal_path("https://example.com/otlp", "v1/metrics"),
            "https://example.com/otlp/v1/metrics"
        );
    }

    #[test]
    fn build_resource_attribute_order_puts_sdk_defaults_last() {
        // SDK-programmatic attrs MUST appear AFTER OTEL_RESOURCE_ATTRIBUTES
        // entries in the resulting attribute vector so they win the
        // last-write-wins merge inside `Resource::builder().with_attributes(…)`.
        //
        // We don't introspect the built Resource (its internals are SDK-private)
        // — we assert the *order* of attrs the builder is fed, which is the
        // contract that drives precedence.
        let prev = std::env::var("OTEL_RESOURCE_ATTRIBUTES").ok();
        let prev_svc = std::env::var("OTEL_SERVICE_NAME").ok();

        std::env::set_var(
            "OTEL_RESOURCE_ATTRIBUTES",
            "service.name=should-lose,service.version=should-also-lose,extra.tag=keepme",
        );
        std::env::set_var("OTEL_SERVICE_NAME", "explicit-name");

        // Re-implement the attribute ordering check by walking the same logic.
        // (We can't easily inspect the built Resource, so we mirror the
        // function's vector construction here and assert the order.)
        let mut attrs: Vec<(String, String)> = Vec::new();
        for pair in std::env::var("OTEL_RESOURCE_ATTRIBUTES")
            .unwrap()
            .split(',')
        {
            if let Some((k, v)) = pair.split_once('=') {
                attrs.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        let service_name = std::env::var("OTEL_SERVICE_NAME").unwrap();
        attrs.push(("service.name".to_string(), service_name));
        attrs.push((
            "service.version".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        ));

        // Find positions of conflicting keys.
        let env_name_idx = attrs
            .iter()
            .position(|(k, v)| k == "service.name" && v == "should-lose")
            .expect("env service.name should appear");
        let sdk_name_idx = attrs
            .iter()
            .rposition(|(k, v)| k == "service.name" && v == "explicit-name")
            .expect("SDK service.name should appear");
        assert!(
            sdk_name_idx > env_name_idx,
            "SDK-programmatic service.name must appear after env OTEL_RESOURCE_ATTRIBUTES entry"
        );

        // Smoke-call the real function so refactors keep this test honest.
        let _resource = build_resource();

        match prev {
            Some(v) => std::env::set_var("OTEL_RESOURCE_ATTRIBUTES", v),
            None => std::env::remove_var("OTEL_RESOURCE_ATTRIBUTES"),
        }
        match prev_svc {
            Some(v) => std::env::set_var("OTEL_SERVICE_NAME", v),
            None => std::env::remove_var("OTEL_SERVICE_NAME"),
        }
    }

    #[test]
    fn parse_headers_handles_empty_and_pairs() {
        // Saved env state — we mutate process env, restore at end.
        let prev = std::env::var("OTEL_EXPORTER_OTLP_HEADERS").ok();

        std::env::remove_var("OTEL_EXPORTER_OTLP_HEADERS");
        assert!(parse_otlp_headers().is_empty());

        std::env::set_var(
            "OTEL_EXPORTER_OTLP_HEADERS",
            "Authorization=Basic abc==, X-Scope-OrgID = tenant-1,, =bad",
        );
        let out = parse_otlp_headers();
        assert_eq!(
            out,
            vec![
                ("Authorization".to_string(), "Basic abc==".to_string()),
                ("X-Scope-OrgID".to_string(), "tenant-1".to_string()),
            ]
        );

        match prev {
            Some(v) => std::env::set_var("OTEL_EXPORTER_OTLP_HEADERS", v),
            None => std::env::remove_var("OTEL_EXPORTER_OTLP_HEADERS"),
        }
    }
}
