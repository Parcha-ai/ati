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

/// Initialize the tracing subscriber and (optionally) Sentry.
///
/// Call once at program startup, before any `tracing` macros fire.
/// The returned guard (if `Some`) must be held until program exit so
/// that pending Sentry events are flushed on drop.
pub fn init(mode: LogMode, verbose: bool) -> Option<SentryGuard> {
    let filter = match std::env::var("RUST_LOG") {
        Ok(val) if !val.is_empty() => EnvFilter::from_default_env(),
        _ if verbose => EnvFilter::new("debug"),
        _ => EnvFilter::new("info"),
    };

    let sentry_guard = init_sentry();

    // Build the layered subscriber.
    // The sentry-tracing layer (when enabled) bridges tracing events to Sentry:
    //   error! → Sentry issue, warn!/info! → breadcrumbs.
    let registry = tracing_subscriber::registry().with(filter);

    #[cfg(feature = "sentry")]
    let registry = registry.with(sentry_guard.as_ref().map(|_| sentry_tracing::layer()));

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

    sentry_guard
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

        let service = std::env::var("SERVICE_NAME").unwrap_or_else(|_| "ati-proxy".into());

        let sample_rate = match environment.as_str() {
            "production" => 0.25,
            "staging" => 0.5,
            _ => 1.0,
        };

        let guard = sentry::init((
            dsn,
            sentry::ClientOptions {
                release: Some(env!("CARGO_PKG_VERSION").into()),
                environment: Some(environment.into()),
                server_name: Some(service.into()),
                traces_sample_rate: sample_rate,
                attach_stacktrace: true,
                send_default_pii: false,
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
