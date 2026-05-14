# OpenTelemetry

ATI ships optional native OpenTelemetry instrumentation behind the `otel` cargo feature. When enabled, the `ati proxy` server and `ati run` CLI emit OTLP traces and metrics to any OTLP-compatible backend (Grafana Cloud Tempo+Mimir, Honeycomb, Jaeger, the OTel Collector, …).

Default off. The OSS binary stays lean unless you ask for OTel.

## TL;DR

```bash
cargo build --release --features otel
export OTEL_EXPORTER_OTLP_ENDPOINT=https://otlp-gateway-prod-us-central-0.grafana.net/otlp
export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Basic $(echo -n "<instance>:<api-token>" | base64)"
export OTEL_SERVICE_NAME=ati-proxy
./target/release/ati proxy --port 8080
```

Spans show up in Grafana Cloud Tempo within ~30 seconds. Metrics in Grafana Cloud Mimir.

## What gets emitted

### Spans (OTel semantic conventions)

| Span | Where minted | Attributes |
|---|---|---|
| `http.server.request` | Outermost proxy middleware | `http.request.method`, `http.route` (matched-path template, low cardinality), `http.response.status_code`, `url.path` (raw, high cardinality) |
| `proxy.call` | `POST /call` handler | `tool` |
| `proxy.mcp` | `POST /mcp` handler | `jsonrpc.method` |
| `proxy.help` | `POST /help` handler | — |
| `passthrough.request` | Passthrough fallback handler | `route` (manifest name), `upstream` (base URL) |

W3C trace context (`traceparent` / `tracestate`) is extracted from inbound HTTP headers and injected into outbound HTTP calls in `core/http.rs`, `core/passthrough.rs`, and the MCP HTTP transport. Stdio MCP gets span attributes only — there are no HTTP headers to inject into a subprocess pipe. Sandbox-supplied inbound `traceparent`/`tracestate` headers are stripped from passthrough traffic (per W3C §2.3, since the OTel propagator injects our own); the upstream sees one and only one traceparent.

### Metrics

| Instrument | Type | Labels |
|---|---|---|
| `ati.proxy.requests` | counter (u64) | `http.route`, `http.request.method`, `http.response.status_class` |
| `ati.proxy.request_duration_ms` | histogram (f64, ms) | same as above |
| `ati.upstream.errors` | counter (u64) | `provider`, `error_kind` ∈ {`timeout`, `connect`, `send`} |

**Cardinality note.** `http.route` is the matched axum template (e.g. `/skills/{name}`), not the raw path. Unmatched requests (passthrough fallback) all collapse to a single value `/__passthrough_or_unmatched`, so a proxy forwarding millions of distinct upstream URLs does not blow up your metrics backend. The raw path is available on the *span* via `url.path` for forensic inspection.

## Environment variables

All variables are standard OTel except `ATI_OTEL_DEBUG`.

| Variable | Default | Notes |
|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset → OTel disabled at runtime | Base OTLP endpoint. When unset, the layer isn't installed — zero overhead. |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | `${OTEL_EXPORTER_OTLP_ENDPOINT}/v1/traces` | Signal-specific override; takes precedence over the base. |
| `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | `${OTEL_EXPORTER_OTLP_ENDPOINT}/v1/metrics` | Signal-specific override. |
| `OTEL_EXPORTER_OTLP_HEADERS` | unset | Comma-separated `k=v` pairs. Typical: `Authorization=Basic <base64>` for Grafana Cloud. |
| `OTEL_SERVICE_NAME` | `ati-proxy` | Wins over any `service.name=…` in `OTEL_RESOURCE_ATTRIBUTES`. |
| `OTEL_RESOURCE_ATTRIBUTES` | unset | Lower-priority defaults per spec. SDK-set `service.name` / `service.version` win on collision. |
| `ENVIRONMENT_TIER` | unset | When set (e.g. `production`, `staging`), exposed as the `deployment.environment` resource attribute. |
| `OTEL_TRACES_SAMPLER` | parent-based / always-on | Standard OTel sampler env var; honored by the SDK. |
| `OTEL_TRACES_SAMPLER_ARG` | — | Ratio for the trace ratio sampler (0.0–1.0). |
| `ATI_OTEL_DEBUG` | `false` | Reserved for verbose exporter diagnostics (no-op today). |

When the feature is **compiled out** but `OTEL_EXPORTER_OTLP_ENDPOINT` is set, ATI logs a warning at startup pointing you to `cargo build --features otel`. Symmetric with Sentry's existing check.

## Coexistence with Sentry

Build with both at once:

```bash
cargo build --release --features sentry,otel
```

Same `tracing::error!` event lands in both Sentry (as an issue) and the OTel exporter (as a span event). This is the **intended prod build** — Sentry handles error triage, OTel handles distributed traces and RED metrics.

## Grafana Cloud quickstart

Grafana Cloud OTLP endpoints use HTTP Basic auth with `<instance-id>:<api-token>`.

1. In Grafana Cloud → **Connections** → **OpenTelemetry (OTLP)**, copy your instance ID and create an API token with `MetricsPublisher` + `tracingWrite` scopes.
2. Base64-encode the credentials:
   ```bash
   echo -n "${GRAFANA_INSTANCE_ID}:${GRAFANA_API_TOKEN}" | base64
   ```
3. Set the env vars:
   ```bash
   export OTEL_EXPORTER_OTLP_ENDPOINT="https://otlp-gateway-prod-us-central-0.grafana.net/otlp"
   export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Basic <base64-from-step-2>"
   export OTEL_SERVICE_NAME=ati-proxy
   export ENVIRONMENT_TIER=production
   ```
4. Run the binary built in step 1 (with `--features otel` baked in):

   ```bash
   ./target/release/ati proxy --port 8080
   ```

   `--features otel` is a **build-time** Cargo flag, not a runtime CLI flag — `ati proxy` will reject it. The OTel layer is on because you compiled it in; the env vars decide whether export actually happens.
5. Explore: in Grafana Cloud → Explore → pick the Tempo data source → filter on `service.name=ati-proxy`.

## Build size

Adding `--features otel` to a release build costs about **+500 KiB** on x86_64 Linux. Well under the +3 MB budget in the original TDD ([#100](https://github.com/Parcha-ai/ati/issues/100)).

The `opentelemetry-otlp` crate's `http-proto` feature transitively pulls `tonic` + `tonic-prost` *into the build* for prost-generated message types. We do NOT run gRPC at runtime — the exporter ships protobuf over HTTP via reqwest, no `tonic::transport::Channel`, no second async runtime. tonic is a compile-time dependency for message types only.

## Version pinning

`tracing-opentelemetry 0.32.x` still tracks `opentelemetry`/`opentelemetry_sdk` **0.31**. The whole quartet is pinned together:

```toml
opentelemetry        = "0.31"
opentelemetry_sdk    = "0.31"
opentelemetry-otlp   = "0.31"
tracing-opentelemetry = "0.32"
```

Bumping any one alone trips a "multiple versions of crate `opentelemetry` in the dependency graph" compile error. **Bump them as a group** when upgrading.

## How it nests under `core::logging`

`core::logging::init` returns an `InitGuards` struct holding both the (optional) Sentry guard and the (optional) OTel guard. Drop semantics flush + shut down each exporter. `main.rs` holds this struct for program lifetime and calls `core::logging::shutdown(guards)` before `process::exit` (which bypasses destructors).

The OTel `tracing-opentelemetry` layer is added to the same `tracing-subscriber` registry as the existing `sentry-tracing` layer (`src/core/logging.rs`), so one `tracing::error!` reaches both sinks.
