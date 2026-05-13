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

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
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
    let tracer = tracer_provider.tracer(TRACER_NAME);

    // --- Meter provider ---
    let metric_exporter = match build_metric_exporter(&endpoint, &headers) {
        Ok(exp) => exp,
        Err(e) => {
            eprintln!("ati: failed to build OTLP metric exporter: {e}");
            // Shutdown the already-built tracer provider before bailing.
            let _ = tracer_provider.shutdown();
            return None;
        }
    };
    let reader = PeriodicReader::builder(metric_exporter).build();
    let meter_provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader)
        .build();

    // Set the global meter provider so `opentelemetry::global::meter(...)`
    // returns a meter backed by our exporter.
    opentelemetry::global::set_meter_provider(meter_provider.clone());

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
    let service_name = std::env::var("OTEL_SERVICE_NAME")
        .or_else(|_| std::env::var("SERVICE_NAME"))
        .unwrap_or_else(|_| SERVICE_NAME_FALLBACK.to_string());

    let mut attrs: Vec<KeyValue> = vec![
        KeyValue::new("service.name", service_name),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
    ];

    if let Ok(env_tier) = std::env::var("ENVIRONMENT_TIER") {
        if !env_tier.trim().is_empty() {
            attrs.push(KeyValue::new("deployment.environment", env_tier));
        }
    }

    // OTEL_RESOURCE_ATTRIBUTES: comma-separated k=v pairs per the spec.
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
