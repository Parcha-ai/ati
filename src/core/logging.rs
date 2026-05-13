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
                debug: sentry_debug,
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
