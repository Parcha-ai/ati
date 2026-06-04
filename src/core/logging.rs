//! Structured logging initialization for ATI.
//!
//! - **Proxy mode**: JSON to stderr (Docker/container friendly, machine-parseable)
//! - **CLI mode**: Compact human-readable to stderr
//!
//! Sentry integration is behind the `sentry` cargo feature (off by default).

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

/// Controls the log output format.
pub enum LogMode {
    /// CLI commands — compact human-readable stderr.
    Cli,
    /// Proxy server — structured JSON to stderr.
    Proxy,
}

/// Opaque guard type. When the `sentry` feature is enabled this is
/// `sentry::ClientInitGuard` (must be held for program lifetime).
/// Otherwise it is `()`.
#[cfg(feature = "sentry")]
pub type SentryGuard = sentry::ClientInitGuard;
#[cfg(not(feature = "sentry"))]
pub type SentryGuard = ();

/// Bundle of guards returned by `init`. Holds Sentry's `ClientInitGuard`
/// (when compiled+enabled) and ATI's `OtelGuard` (when compiled+enabled),
/// either or both of which may be `None` at runtime depending on env config.
///
/// The whole struct must be held until program exit so the `Drop`s fire and
/// flush pending events / spans / metrics.
#[derive(Default)]
pub struct InitGuards {
    pub sentry: Option<SentryGuard>,
    #[cfg(feature = "otel")]
    pub otel: Option<crate::core::otel::OtelGuard>,
}

/// Initialize the tracing subscriber and (optionally) Sentry + OpenTelemetry.
///
/// Call once at program startup, before any `tracing` macros fire. The
/// returned guards must be held until program exit so pending events and
/// spans get flushed on drop.
pub fn init(mode: LogMode, verbose: bool) -> InitGuards {
    let filter = match std::env::var("RUST_LOG") {
        Ok(val) if !val.is_empty() => EnvFilter::from_default_env(),
        _ if verbose => EnvFilter::new("debug"),
        _ => EnvFilter::new("info"),
    };

    // Init Sentry first (before subscriber) so sentry-tracing layer can be wired in.
    let sentry_guard = init_sentry();

    // Init OTel before the subscriber so its layer can be wired in.
    #[cfg(feature = "otel")]
    let (otel_layer, otel_guard) = match crate::core::otel::try_init() {
        Some((layer, guard)) => (Some(layer), Some(guard)),
        None => (None, None),
    };

    // Build the layered subscriber.
    // The sentry-tracing layer (when enabled) bridges tracing events to Sentry:
    //   error! → Sentry issue, warn!/info! → breadcrumbs.
    let registry = tracing_subscriber::registry().with(filter);

    #[cfg(feature = "sentry")]
    let registry = registry.with(sentry_guard.as_ref().map(|_| sentry_tracing::layer()));

    #[cfg(feature = "otel")]
    let registry = registry.with(otel_layer);

    match mode {
        LogMode::Proxy => {
            registry
                .with(
                    fmt::layer()
                        .json()
                        .flatten_event(true)
                        .with_writer(std::io::stderr)
                        .with_target(true)
                        .with_current_span(false),
                )
                .init();
        }
        LogMode::Cli => {
            registry
                .with(
                    fmt::layer()
                        .compact()
                        .with_writer(std::io::stderr)
                        .with_target(false),
                )
                .init();
        }
    }

    // Warn after subscriber is initialized so the message actually appears.
    #[cfg(not(feature = "sentry"))]
    if std::env::var("SENTRY_DSN").is_ok() || std::env::var("GREP_SENTRY_DSN").is_ok() {
        tracing::warn!(
            "SENTRY_DSN is set but this binary was compiled without the sentry feature — ignoring. \
             Build with: cargo build --features sentry"
        );
    }
    #[cfg(not(feature = "otel"))]
    if std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok() {
        tracing::warn!(
            "OTEL_EXPORTER_OTLP_ENDPOINT is set but this binary was compiled without the otel feature — ignoring. \
             Build with: cargo build --features otel"
        );
    }

    InitGuards {
        sentry: sentry_guard,
        #[cfg(feature = "otel")]
        otel: otel_guard,
    }
}

/// Flush the Sentry transport queue and the OTel exporters before a
/// non-returning exit (e.g. `process::exit`, which bypasses destructors).
///
/// Safe to call with `InitGuards::default()` — the inner `Option`s and the
/// guards' `Drop` impls handle the "feature off or runtime-disabled" case.
/// When neither `sentry` nor `otel` is compiled in, `InitGuards` has no
/// non-trivial drop and this is a compile-time no-op.
#[allow(clippy::needless_pass_by_value)]
pub fn shutdown(_guards: InitGuards) {
    // Body intentionally empty: dropping `_guards` at the end of this scope
    // runs the (cfg-gated) `Drop` impls on `SentryGuard` / `OtelGuard`,
    // which is what triggers the flush + shutdown. Calling `drop()`
    // explicitly trips `clippy::drop_non_drop` when neither feature is
    // compiled in.
}

/// Sentry `before_send` hook. Runs on every event the SDK is about to
/// transport. Today's job is narrow: drop events whose
/// `upstream_error_class` tag identifies them as quota / rate-limited
/// noise.
///
/// Why: 402 (out of credit) and 429 (rate limited) are real and worth
/// breadcrumbing, but they're billing/throttling outcomes — not code
/// bugs — and the user reported thousands of them spamming the issue
/// list and burning quota. The `report_upstream_error` helper sets
/// `tags.upstream_error_class` for every classified event; we read
/// that tag here.
///
/// We keep the helper's call to `tracing::warn!` for the quota/rate-
/// limited classes so the breadcrumb buffer still records context for
/// the *next* real error — but we never let the standalone Sentry
/// event ship.
///
/// Anything without the tag (panics, unrelated `tracing::error!` from
/// other code paths) passes through unchanged.
#[cfg(feature = "sentry")]
fn before_send(
    event: sentry::protocol::Event<'static>,
) -> Option<sentry::protocol::Event<'static>> {
    if let Some(class) = event.tags.get("upstream_error_class").map(String::as_str) {
        if class == "quota" || class == "rate_limited" {
            return None;
        }
    }
    Some(event)
}

/// Initialize Sentry if a DSN is configured. Returns `None` when Sentry is
/// disabled (no DSN, or feature not compiled in).
fn init_sentry() -> Option<SentryGuard> {
    #[cfg(feature = "sentry")]
    {
        let dsn = std::env::var("GREP_SENTRY_DSN")
            .or_else(|_| std::env::var("SENTRY_DSN"))
            .ok()?;

        let environment =
            std::env::var("ENVIRONMENT_TIER").unwrap_or_else(|_| "development".into());

        // Only send to Sentry in production/staging/demo — skip in development
        match environment.as_str() {
            "production" | "staging" | "demo" => {}
            _ => {
                tracing::debug!(environment = %environment, "sentry disabled for this environment");
                return None;
            }
        }

        let service = std::env::var("SERVICE_NAME").unwrap_or_else(|_| "ati-proxy".into());

        let sample_rate = match environment.as_str() {
            "production" => 0.25,
            "staging" => 0.5,
            _ => 1.0,
        };

        let sentry_debug = std::env::var("ATI_SENTRY_DEBUG")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let guard = sentry::init((
            dsn,
            sentry::ClientOptions {
                release: Some(env!("CARGO_PKG_VERSION").into()),
                environment: Some(environment.into()),
                server_name: Some(service.into()),
                traces_sample_rate: sample_rate,
                attach_stacktrace: true,
                send_default_pii: false,
                // Bumped from the SDK default (30) so that a slow-burn
                // failure — where the eventual error is preceded by a
                // long tail of tool_call info breadcrumbs — still shows
                // the breadcrumbs that matter. The breadcrumb buffer is
                // per-scope so there's no global memory concern.
                max_breadcrumbs: 100,
                // Sentry's Logs product — when enabled, structured
                // tracing fields ride along on every event so we can
                // search/filter in Sentry's log explorer too, not just
                // in the issue grouping.
                enable_logs: true,
                debug: sentry_debug,
                before_send: Some(std::sync::Arc::new(before_send)),
                ..Default::default()
            },
        ));

        if guard.is_enabled() {
            Some(guard)
        } else {
            None
        }
    }

    #[cfg(not(feature = "sentry"))]
    {
        None
    }
}

#[cfg(all(test, feature = "sentry"))]
mod tests {
    use super::*;
    use sentry::protocol::Event;

    fn event_with_class(class: &str) -> Event<'static> {
        let mut ev = Event::default();
        ev.tags
            .insert("upstream_error_class".to_string(), class.to_string());
        ev
    }

    #[test]
    fn before_send_drops_quota_class_events() {
        // 402 path — `report_upstream_error` classifies as `quota` and
        // emits at Warning. Without before_send, the user reported these
        // were spamming the issue list and burning Sentry quota.
        let ev = event_with_class("quota");
        assert!(before_send(ev).is_none());
    }

    #[test]
    fn before_send_drops_rate_limited_class_events() {
        // 429 path — same noise problem. Breadcrumbs still record the
        // context for the next real error; this just stops the
        // standalone events from shipping.
        let ev = event_with_class("rate_limited");
        assert!(before_send(ev).is_none());
    }

    #[test]
    fn before_send_passes_bad_input_through() {
        // 400 / 422 is a real bug we want to see.
        let ev = event_with_class("bad_input");
        assert!(before_send(ev).is_some());
    }

    #[test]
    fn before_send_passes_server_error_through() {
        let ev = event_with_class("server_error");
        assert!(before_send(ev).is_some());
    }

    #[test]
    fn before_send_passes_auth_error_through() {
        let ev = event_with_class("auth_error");
        assert!(before_send(ev).is_some());
    }

    #[test]
    fn before_send_passes_transport_error_through() {
        let ev = event_with_class("transport_error");
        assert!(before_send(ev).is_some());
    }

    #[test]
    fn before_send_passes_events_without_class_tag() {
        // Panics, generic tracing::error! from elsewhere — no class tag.
        // Must not be dropped.
        let ev = Event::default();
        assert!(before_send(ev).is_some());
    }
}
