//! Passthrough handler — manifest-driven raw HTTP reverse proxying.
//!
//! Distinct from the `http` handler (which executes hand-written tools with a
//! fixed input schema), passthrough takes the request *as-is* — method, path,
//! query string, headers, body — strips the configured prefix, optionally
//! rewrites the leading path segment, injects upstream credentials from the
//! keyring, and streams the request body to the upstream + the response body
//! back to the client.
//!
//! Routes are dispatched by a longest-match on `(host_match, path_prefix)`
//! computed at startup. Hostname matches always beat default-host matches at
//! equal prefix lengths.
//!
//! See `Provider`'s passthrough-prefixed fields in `core::manifest` for the
//! configuration surface, and `crate::proxy::server::build_router` for the
//! `Router::fallback(handle_passthrough)` wiring.

use axum::body::Body;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequest, State};
use axum::http::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Method, Request, Response, StatusCode,
};
use axum::response::IntoResponse;
use bytes::Bytes;
use futures::stream::Stream;
use futures::{SinkExt, StreamExt};
use globset::{Glob, GlobSet, GlobSetBuilder};
use pin_project_lite::pin_project;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use thiserror::Error;

use crate::core::keyring::Keyring;
use crate::core::manifest::{AuthType, ManifestRegistry, Provider};

#[derive(Error, Debug)]
pub enum PassthroughBuildError {
    #[error("provider '{0}': {1}")]
    BadProvider(String, String),
    #[error("provider '{0}': bad deny_paths glob '{1}': {2}")]
    BadDenyGlob(String, String, String),
    #[error("provider '{0}': bad forward_authorization_paths glob '{1}': {2}")]
    BadForwardAuthGlob(String, String, String),
    #[error("provider '{0}': bad header name '{1}'")]
    BadHeaderName(String, String),
    #[error("provider '{0}': bad header value '{1}'")]
    BadHeaderValue(String, String),
    #[error("provider '{0}': failed to build reqwest client: {1}")]
    ClientBuild(String, reqwest::Error),
    #[error("provider '{0}': base_url is not a valid URL: {1}")]
    BadBaseUrl(String, String),
}

/// A compiled passthrough route: everything frozen at startup.
///
/// The `auth_header` / `extra_headers` are fully resolved against the keyring
/// at build time, not per-request. This means a keyring rotation requires a
/// SIGHUP-driven router rebuild (PR 2 wires that for the sig-verify secret;
/// passthrough credential rotation lives in the same SIGHUP path).
pub struct PassthroughRoute {
    pub name: String,
    pub host_match: Option<String>,
    pub path_prefix: Option<String>,
    pub strip_prefix: bool,
    pub path_replace: Option<(String, String)>,
    /// Trailing-slash-stripped base URL ("https://api.example.com/v1").
    pub base_url: String,
    /// Value to substitute into the upstream `Host` header and SNI.
    pub host_override: Option<String>,
    /// Pre-resolved auth header to inject, if any (`auth_type` ∈ {bearer, header}).
    pub auth_header: Option<(HeaderName, HeaderValue)>,
    /// Pre-resolved auth query parameter to inject, if any (`auth_type = "query"`).
    pub auth_query: Option<(String, String)>,
    /// Pre-resolved extra headers (`provider.extra_headers` with `${var}`
    /// expansion done at startup).
    pub extra_headers: Vec<(HeaderName, HeaderValue)>,
    /// Compiled deny-globs over the post-prefix-strip path.
    pub deny_globs: GlobSet,
    /// Compiled globs over the post-prefix-strip path where ATI should
    /// FORWARD the sandbox's inbound `Authorization` header verbatim AND
    /// SKIP injecting `auth_header` (the manifest-defined credential).
    ///
    /// Empty GlobSet = today's behaviour: strip inbound, inject manifest.
    /// Matched paths see the sandbox's own bearer reach upstream — required
    /// for LiteLLM virtual keys so per-sandbox spend caps are enforced.
    pub forward_auth_globs: GlobSet,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    /// TCP connect timeout for the upstream. The HTTP path bakes this into
    /// the per-route `reqwest::Client`; the WS path uses it to wrap
    /// `tokio_tungstenite::connect_async` in `tokio::time::timeout`
    /// (Greptile P1 on PR #98 — `connect_async` has no built-in timeout).
    pub connect_timeout_seconds: u64,
    /// Whether this route is allowed to be upgraded to a WebSocket. When
    /// `false`, an inbound `Upgrade: websocket` request is treated as
    /// ordinary HTTP — which the upstream will likely reject. When `true`,
    /// the handler intercepts the upgrade and opens a parallel WS to
    /// upstream, pumping frames bidirectionally.
    pub forward_websockets: bool,
    /// Dedicated reqwest client with the route's timeouts baked in. Sharing
    /// one client per route means the connection pool is route-scoped — no
    /// cross-route head-of-line blocking on a single upstream's keep-alives.
    pub client: Arc<reqwest::Client>,
}

/// Dispatch table — sorted at construction so `match_request` is a linear scan
/// that returns the first hit (which is, by sort order, the most specific).
pub struct PassthroughRouter {
    routes: Vec<Arc<PassthroughRoute>>,
}

impl PassthroughRouter {
    /// Build the router from every `handler = "passthrough"` provider in the
    /// registry. Pre-resolves auth headers and `extra_headers` against the
    /// supplied keyring. Returns an empty router if no providers are
    /// passthrough — callers should still mount the fallback, which will
    /// 404 every request that doesn't hit a named route.
    pub fn build(
        registry: &ManifestRegistry,
        keyring: &Keyring,
    ) -> Result<Self, PassthroughBuildError> {
        let mut routes: Vec<Arc<PassthroughRoute>> = Vec::new();

        for manifest in registry.manifests().iter() {
            let p = &manifest.provider;
            if !p.is_passthrough() {
                continue;
            }
            routes.push(Arc::new(compile_route(p, keyring)?));
        }

        // Longest-prefix-and-host-first sort.
        // Ordering rules:
        //   1. Routes with a host_match win over default-host routes (so
        //      `bb.grep.ai/v1/...` lands on browserbase even if a default-host
        //      `/v1` route exists).
        //   2. Within the same host class, longer path_prefix wins so that
        //      `/litellm/v1` beats `/litellm` if both are configured.
        //   3. None path_prefix (= root) sorts last within its host class.
        routes.sort_by(|a, b| {
            let host_rank = |r: &PassthroughRoute| if r.host_match.is_some() { 0 } else { 1 };
            let prefix_len =
                |r: &PassthroughRoute| r.path_prefix.as_deref().map(|s| s.len()).unwrap_or(0);
            host_rank(a)
                .cmp(&host_rank(b))
                .then_with(|| prefix_len(b).cmp(&prefix_len(a)))
        });

        Ok(Self { routes })
    }

    /// Match an incoming `(host, path)` to a route. Host is compared
    /// case-insensitively; `host_match = None` routes match any host.
    pub fn match_request(&self, host: &str, path: &str) -> Option<Arc<PassthroughRoute>> {
        let host_lc = host.to_ascii_lowercase();
        for route in &self.routes {
            if let Some(ref want_host) = route.host_match {
                if want_host.eq_ignore_ascii_case(&host_lc)
                    && matches_prefix(route.path_prefix.as_deref(), path)
                {
                    return Some(route.clone());
                }
            } else if matches_prefix(route.path_prefix.as_deref(), path) {
                return Some(route.clone());
            }
        }
        None
    }

    /// Number of compiled routes.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// Expand a single operator-supplied `deny_paths` pattern into one or more
/// globs that, together, cover the *intent* of "block this URL prefix and
/// everything under it." This closes the `/config/*` → `/config/a/b` bypass
/// reported by Greptile.
///
/// Rules:
/// - Already-recursive patterns (`**` anywhere) pass through unchanged.
/// - Patterns ending in `/*` get a recursive twin: `/foo/*` → `[/foo/*, /foo/**]`.
/// - Patterns ending with a path segment but no glob (e.g. `/foo`) get both
///   the literal AND a `/foo/**` recursive twin.
/// - Patterns not anchored at `/` (`*.json`) are left alone — those are
///   genuine single-segment wildcards.
///
/// Always returns at least the original pattern. Operators who *deliberately*
/// want single-segment matching (rare for HTTP paths) can write `[!/]*`-style
/// negations; the expansion still adds a recursive twin but that's strictly
/// more conservative.
fn expand_deny_pattern(pattern: &str) -> Vec<String> {
    let mut out = vec![pattern.to_string()];
    // Already recursive (contains `**` anywhere) — operator was explicit.
    if pattern.contains("**") {
        return out;
    }
    // Not anchored as an HTTP path prefix — don't touch (could be *.json etc).
    if !pattern.starts_with('/') {
        return out;
    }
    // `/foo/*` → also add `/foo/**`.
    if let Some(stripped) = pattern.strip_suffix("/*") {
        out.push(format!("{stripped}/**"));
        return out;
    }
    // `/foo` (no trailing wildcard) → also add `/foo/**` so sub-paths are
    // caught. The literal `/foo` is already matched by the original entry.
    if !pattern.contains('*') {
        out.push(format!("{}/**", pattern.trim_end_matches('/')));
        return out;
    }
    out
}

fn matches_prefix(prefix: Option<&str>, path: &str) -> bool {
    match prefix {
        None | Some("/") => true,
        Some(p) => {
            // Match either exact ("/litellm") or with a slash boundary
            // ("/litellm/v1/..."). Disallow "/litellmx/..." matching "/litellm".
            if path == p {
                return true;
            }
            if let Some(rest) = path.strip_prefix(p) {
                return rest.starts_with('/');
            }
            false
        }
    }
}

fn compile_route(
    p: &Provider,
    keyring: &Keyring,
) -> Result<PassthroughRoute, PassthroughBuildError> {
    // Validate the base_url parses as an absolute URL. We don't store the
    // parsed url::Url because we build the upstream URL from string concat —
    // but the parse step catches typos at startup instead of at first call.
    let parsed = url::Url::parse(&p.base_url)
        .map_err(|e| PassthroughBuildError::BadBaseUrl(p.name.clone(), e.to_string()))?;
    let base_url = p.base_url.trim_end_matches('/').to_string();

    // Build the deny-paths GlobSet. Glob `*` does NOT cross `/`, so a naive
    // `/config/*` would silently miss `/config/a/b` — a sandbox could escape
    // the LiteLLM admin denylist by appending a sub-segment. We therefore
    // expand every pattern to also match recursively below the prefix:
    //   /config/*  → /config/*  AND /config/**
    //   /config    → /config    AND /config/**   (also blocks the literal path)
    //   /config/** → /config/** (already recursive — passed through)
    // Plain non-anchored patterns (e.g. "*.json") are left alone.
    let mut deny_builder = GlobSetBuilder::new();
    for pattern in &p.deny_paths {
        for expanded in expand_deny_pattern(pattern) {
            let glob = Glob::new(&expanded).map_err(|e| {
                PassthroughBuildError::BadDenyGlob(p.name.clone(), expanded.clone(), e.to_string())
            })?;
            deny_builder.add(glob);
        }
    }
    let deny_globs = deny_builder.build().map_err(|e| {
        PassthroughBuildError::BadDenyGlob(p.name.clone(), String::new(), e.to_string())
    })?;

    // Build the forward-auth GlobSet with the same recursive expansion as
    // deny_paths — `/v1/*` should also match `/v1/chat/completions`.
    let mut forward_auth_builder = GlobSetBuilder::new();
    for pattern in &p.forward_authorization_paths {
        for expanded in expand_deny_pattern(pattern) {
            let glob = Glob::new(&expanded).map_err(|e| {
                PassthroughBuildError::BadForwardAuthGlob(
                    p.name.clone(),
                    expanded.clone(),
                    e.to_string(),
                )
            })?;
            forward_auth_builder.add(glob);
        }
    }
    let forward_auth_globs = forward_auth_builder.build().map_err(|e| {
        PassthroughBuildError::BadForwardAuthGlob(p.name.clone(), String::new(), e.to_string())
    })?;

    // Resolve credentials at startup.
    let (auth_header, auth_query) = resolve_auth(p, keyring)?;

    // Resolve extra_headers with ${key} expansion.
    let mut extra_headers = Vec::with_capacity(p.extra_headers.len());
    for (name, raw_value) in &p.extra_headers {
        let resolved = resolve_env_value(raw_value, keyring);
        let header_name = HeaderName::try_from(name.as_str())
            .map_err(|_| PassthroughBuildError::BadHeaderName(p.name.clone(), name.clone()))?;
        let header_value = HeaderValue::from_str(&resolved)
            .map_err(|_| PassthroughBuildError::BadHeaderValue(p.name.clone(), name.clone()))?;
        extra_headers.push((header_name, header_value));
    }

    // Build the per-route reqwest client. SNI follows the URL host (which we
    // control via base_url). Reqwest negotiates HTTP/1.1 vs HTTP/2 automatically
    // based on ALPN.
    let _ = parsed;
    let client = reqwest::Client::builder()
        .pool_idle_timeout(Duration::from_secs(p.idle_timeout_seconds))
        .timeout(Duration::from_secs(p.read_timeout_seconds))
        .connect_timeout(Duration::from_secs(p.connect_timeout_seconds))
        // DO NOT follow redirects. Passthrough is a transparent reverse proxy:
        // 3xx responses must be returned to the client unchanged so the client
        // (sandbox runner) can decide whether to follow. Following them inside
        // the proxy would forward keyring-derived `extra_headers` to whatever
        // host the upstream redirects to — reqwest strips `Authorization` on
        // cross-origin hops but does NOT strip arbitrary custom headers. That's
        // a credential-leak vector flagged by Greptile review #2 on PR #95.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| PassthroughBuildError::ClientBuild(p.name.clone(), e))?;

    Ok(PassthroughRoute {
        name: p.name.clone(),
        host_match: p.host_match.clone(),
        path_prefix: p.path_prefix.clone(),
        strip_prefix: p.strip_prefix,
        path_replace: p.path_replace.clone(),
        base_url,
        host_override: p.host_override.clone(),
        auth_header,
        auth_query,
        extra_headers,
        deny_globs,
        forward_auth_globs,
        max_request_bytes: p.max_request_bytes,
        max_response_bytes: p.max_response_bytes,
        connect_timeout_seconds: p.connect_timeout_seconds,
        forward_websockets: p.forward_websockets,
        client: Arc::new(client),
    })
}

/// Either an injected header (bearer/header/basic auth) or a query-string
/// parameter (`auth_type = "query"`). Returned by `resolve_auth` so the
/// per-request handler can apply whichever the provider configured.
type ResolvedAuth = (Option<(HeaderName, HeaderValue)>, Option<(String, String)>);

/// Look up `auth_key_name` in the keyring, normalising to lowercase so that
/// manifests authored in either case work against the `ATI_KEY_*` convention
/// (env-var loader lowercases on insert — `keyring.rs::from_env`).
///
/// Returns the resolved value on hit. On miss, logs a clear warning naming
/// the provider + the (un-normalised) key and returns `None` — the caller
/// then skips auth-header injection entirely, preventing `Authorization:
/// Bearer ` (empty value) from reaching upstream.
fn lookup_auth_key<'k>(
    provider_name: &str,
    key_name: &str,
    keyring: &'k Keyring,
) -> Option<&'k str> {
    let lowered = key_name.to_ascii_lowercase();
    if let Some(v) = keyring.get(&lowered) {
        return Some(v);
    }
    // Fall back to the literal name in case an operator inserted a mixed-case
    // entry through a custom keyring loader. Pure-lowercase is the expected
    // convention; this is a safety net.
    if lowered != key_name {
        if let Some(v) = keyring.get(key_name) {
            tracing::debug!(
                provider = provider_name,
                key = key_name,
                "auth_key_name resolved via case-sensitive fallback; consider using lowercase for consistency with ATI_KEY_* convention"
            );
            return Some(v);
        }
    }
    tracing::warn!(
        provider = provider_name,
        key = key_name,
        "auth_key_name not found in keyring — auth header will NOT be injected; \
         check that ATI_KEY_{} is set or that the keyring contains the key",
        key_name.to_ascii_uppercase()
    );
    None
}

fn resolve_auth(p: &Provider, keyring: &Keyring) -> Result<ResolvedAuth, PassthroughBuildError> {
    match p.auth_type {
        AuthType::None | AuthType::Oauth2 | AuthType::Url => Ok((None, None)),
        AuthType::Bearer => {
            let key = match &p.auth_key_name {
                Some(k) => k,
                None => return Ok((None, None)),
            };
            let value = match lookup_auth_key(&p.name, key, keyring) {
                Some(v) => v,
                None => return Ok((None, None)),
            };
            let header_value = HeaderValue::from_str(&format!("Bearer {value}")).map_err(|_| {
                PassthroughBuildError::BadHeaderValue(p.name.clone(), "Authorization".to_string())
            })?;
            Ok((
                Some((HeaderName::from_static("authorization"), header_value)),
                None,
            ))
        }
        AuthType::Header => {
            let key = match &p.auth_key_name {
                Some(k) => k,
                None => return Ok((None, None)),
            };
            let header_name_str = p.auth_header_name.as_deref().unwrap_or("X-Api-Key");
            let header_name = HeaderName::try_from(header_name_str).map_err(|_| {
                PassthroughBuildError::BadHeaderName(p.name.clone(), header_name_str.to_string())
            })?;
            let key_value = match lookup_auth_key(&p.name, key, keyring) {
                Some(v) => v,
                None => return Ok((None, None)),
            };
            let value = if let Some(prefix) = &p.auth_value_prefix {
                format!("{prefix}{key_value}")
            } else {
                key_value.to_string()
            };
            let header_value = HeaderValue::from_str(&value).map_err(|_| {
                PassthroughBuildError::BadHeaderValue(p.name.clone(), header_name_str.to_string())
            })?;
            Ok((Some((header_name, header_value)), None))
        }
        AuthType::Query => {
            let key = match &p.auth_key_name {
                Some(k) => k,
                None => return Ok((None, None)),
            };
            let query_name = p
                .auth_query_name
                .clone()
                .unwrap_or_else(|| "api_key".to_string());
            let value = match lookup_auth_key(&p.name, key, keyring) {
                Some(v) => v.to_string(),
                None => return Ok((None, None)),
            };
            Ok((None, Some((query_name, value))))
        }
        AuthType::Basic => {
            let key = match &p.auth_key_name {
                Some(k) => k,
                None => return Ok((None, None)),
            };
            // Basic auth in passthrough: keyring entry is the user:pass string
            // (caller's responsibility). We base64 it. If the operator wants
            // user/pass split they can use `extra_headers` directly.
            use base64::Engine;
            let creds = match lookup_auth_key(&p.name, key, keyring) {
                Some(v) => v,
                None => return Ok((None, None)),
            };
            let encoded = base64::engine::general_purpose::STANDARD.encode(creds.as_bytes());
            let header_value =
                HeaderValue::from_str(&format!("Basic {encoded}")).map_err(|_| {
                    PassthroughBuildError::BadHeaderValue(
                        p.name.clone(),
                        "Authorization".to_string(),
                    )
                })?;
            Ok((
                Some((HeaderName::from_static("authorization"), header_value)),
                None,
            ))
        }
    }
}

/// Expand `${keyring_var}` placeholders against the keyring. Unknown keys are
/// left as the literal `${var}` token (matches mcp_client::resolve_env_value
/// behaviour for compatibility with operators copy-pasting between handlers).
fn resolve_env_value(value: &str, keyring: &Keyring) -> String {
    let mut result = String::with_capacity(value.len());
    let mut chars = value.char_indices().peekable();
    while let Some((i, ch)) = chars.next() {
        if ch == '$' && chars.peek().map(|(_, c)| *c) == Some('{') {
            // Find the closing brace.
            if let Some(end) = value[i + 2..].find('}') {
                let key = &value[i + 2..i + 2 + end];
                if let Some(v) = keyring.get(key) {
                    result.push_str(v);
                } else {
                    result.push_str(&value[i..i + 2 + end + 1]);
                }
                // Skip past the closing brace.
                for _ in 0..(2 + end) {
                    chars.next();
                }
                continue;
            }
        }
        result.push(ch);
    }
    result
}

// --- Hop-by-hop header filtering --------------------------------------------

/// RFC 7230 §6.1 hop-by-hop headers, plus a handful of headers we strip
/// because we *set* them explicitly (`host`) or because forwarding them
/// upstream is a security smell (`x-sandbox-*`, `authorization`).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    // RFC 7230 §6.1 spells this header "Trailer" (singular). "Trailers"
    // (plural) is a *value* of TE: trailers, not a header name. Both are
    // listed so a misspelling on either side gets stripped.
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// Headers stripped from inbound requests before forwarding upstream. Either
/// because we set them explicitly (`host`), because forwarding sandbox-side
/// auth would leak it across trust boundaries (`authorization`), or because
/// upstream has no business knowing the sandbox identity (`x-sandbox-*`
/// prefix — match prefix, not specific names, so future signing headers we
/// haven't named yet are also filtered).
const STRIP_DOWNSTREAM: &[&str] = &[
    "host",
    "authorization", // upstream-specific auth comes from the manifest
    // W3C Trace Context (RFC TraceContext §2.3): forwarding the sandbox-
    // supplied `traceparent` verbatim WHILE we also inject our own from
    // OTel produces two `traceparent` headers — the spec mandates
    // receivers treat that as if neither was present, silently severing
    // trace continuity. Strip on the way in; the OTel propagator injects
    // a new one (with the same trace_id but our span_id) at send time.
    // The strip is unconditional (NOT cfg-gated) so the behaviour is the
    // same whether or not the `otel` feature is compiled in: upstream
    // never sees the sandbox's raw traceparent, only what we choose to
    // emit.
    "traceparent",
    "tracestate",
];

/// Returns true if `name` matches a header we always strip from inbound
/// requests before forwarding upstream.
fn is_sandbox_internal_header(name: &str) -> bool {
    if STRIP_DOWNSTREAM
        .iter()
        .any(|h| h.eq_ignore_ascii_case(name))
    {
        return true;
    }
    // Strip ALL `x-sandbox-*` headers, not just the two we name. This
    // future-proofs against new signing or telemetry headers introduced
    // by the sandbox runner (e.g. `x-sandbox-trace-id`, `x-sandbox-attempt`).
    let n = name.to_ascii_lowercase();
    n.starts_with("x-sandbox-")
}

/// Collect the header names listed inside `Connection: a, b, c` — per
/// RFC 7230 §6.1 these are also hop-by-hop and MUST NOT be forwarded
/// downstream. Returned lower-cased for case-insensitive comparison.
fn connection_hop_names(src: &HeaderMap) -> Vec<String> {
    let mut names = Vec::new();
    for v in src.get_all(axum::http::header::CONNECTION).iter() {
        if let Ok(s) = v.to_str() {
            for part in s.split(',') {
                let trimmed = part.trim();
                if !trimmed.is_empty() {
                    names.push(trimmed.to_ascii_lowercase());
                }
            }
        }
    }
    names
}

/// Filter request headers before forwarding upstream.
///
/// `keep_authorization` opts out of the inbound-`Authorization` strip — used
/// by routes that list the matched path in `forward_authorization_paths` so
/// the sandbox's bearer (e.g. a LiteLLM virtual key) reaches the upstream.
/// All other strip rules (hop-by-hop, `x-sandbox-*`, traceparent) still apply.
fn filter_request_headers(src: &HeaderMap, keep_authorization: bool) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(src.len());
    let conn_hops = connection_hop_names(src);
    for (name, value) in src.iter() {
        let n = name.as_str();
        if HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(n)) {
            continue;
        }
        // RFC 7230 §6.1: any header listed in `Connection:` is hop-by-hop.
        // Without this the sandbox could leak custom transport-coupled
        // headers (e.g. `Connection: keep-alive, X-Sandbox-Hop`) upstream.
        if conn_hops.iter().any(|h| h.eq_ignore_ascii_case(n)) {
            continue;
        }
        if is_sandbox_internal_header(n) {
            // `Authorization` is in STRIP_DOWNSTREAM but virtual-key routes
            // need it forwarded. All other STRIP_DOWNSTREAM entries (`host`,
            // `traceparent`, `tracestate`) keep their unconditional strip.
            if keep_authorization && n.eq_ignore_ascii_case("authorization") {
                out.append(name.clone(), value.clone());
                continue;
            }
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

/// Filter response headers before forwarding to the downstream client.
///
/// When `cap_active = true` (i.e. `max_response_bytes > 0`), `Content-Length`
/// is *also* stripped — because the cap may truncate the body mid-stream and
/// any `Content-Length` we'd forward would be a lie. The downstream client
/// then frames using chunked transfer-encoding, which axum/hyper applies
/// automatically when no `Content-Length` is set. Compressed responses are
/// fine: the cap is on transferred (post-encoding) bytes, so `Content-Encoding`
/// stays valid even when truncation happens.
fn filter_response_headers(src: &HeaderMap, cap_active: bool) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(src.len());
    for (name, value) in src.iter() {
        let n = name.as_str();
        if HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(n)) {
            continue;
        }
        if cap_active && n.eq_ignore_ascii_case("content-length") {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

// --- Streaming body cap -----------------------------------------------------

pin_project! {
    /// Wraps a `Stream<Item = Result<Bytes, E>>` and tears it down with an
    /// `Err(io::Error)` if the total bytes seen exceed `max`. Used in both
    /// directions (request body cap before upstream send, response body cap
    /// before client send).
    ///
    /// A `max` of 0 means "unlimited" — used for git clone passthroughs.
    pub struct MaxBytesStream<S> {
        #[pin]
        inner: S,
        seen: usize,
        max: usize,
        tripped: bool,
    }
}

impl<S> MaxBytesStream<S> {
    pub fn new(inner: S, max: usize) -> Self {
        Self {
            inner,
            seen: 0,
            max,
            tripped: false,
        }
    }
}

impl<S, E> Stream for MaxBytesStream<S>
where
    S: Stream<Item = Result<Bytes, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        if *this.tripped {
            return Poll::Ready(None);
        }
        match this.inner.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(std::io::Error::other(e)))),
            Poll::Ready(Some(Ok(chunk))) => {
                if *this.max > 0 {
                    let new_total = this.seen.saturating_add(chunk.len());
                    if new_total > *this.max {
                        *this.tripped = true;
                        return Poll::Ready(Some(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("body exceeded max_bytes={}", *this.max),
                        ))));
                    }
                    *this.seen = new_total;
                }
                Poll::Ready(Some(Ok(chunk)))
            }
        }
    }
}

// --- Path rewriting ---------------------------------------------------------

/// Compute the upstream path from the incoming path, applying `strip_prefix`
/// then `path_replace`. Returns the path that goes after `base_url`.
fn rewrite_path(incoming: &str, route: &PassthroughRoute) -> String {
    let stripped = if route.strip_prefix {
        if let Some(ref prefix) = route.path_prefix {
            // Strip exactly the prefix; if the result is empty, use "/".
            if let Some(rest) = incoming.strip_prefix(prefix) {
                if rest.is_empty() {
                    "/".to_string()
                } else {
                    rest.to_string()
                }
            } else {
                incoming.to_string()
            }
        } else {
            incoming.to_string()
        }
    } else {
        incoming.to_string()
    };

    if let Some((ref from, ref to)) = route.path_replace {
        if let Some(rest) = stripped.strip_prefix(from) {
            let mut out = String::with_capacity(to.len() + rest.len());
            out.push_str(to);
            out.push_str(rest);
            return out;
        }
    }
    stripped
}

// --- Request handler --------------------------------------------------------

/// Catch-all handler. Mounted via `Router::fallback`, runs for every request
/// that didn't match a named route. Returns 404 when no passthrough route
/// matches.
#[tracing::instrument(
    name = "passthrough.request",
    skip_all,
    fields(
        route = tracing::field::Empty,
        upstream = tracing::field::Empty,
    ),
)]
pub async fn handle_passthrough(
    State(state): State<Arc<crate::proxy::server::ProxyState>>,
    req: Request<Body>,
) -> Response<Body> {
    let router = match state.passthrough.as_ref() {
        Some(r) => r.clone(),
        None => return not_found("passthrough disabled"),
    };

    // Resolve the host from the Host header. Fall back to the URI authority
    // (set by HTTP/2 clients) if Host is absent.
    let host = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .or_else(|| req.uri().host().map(String::from))
        .unwrap_or_default();

    let path = req.uri().path().to_string();
    let query = req.uri().query().map(String::from);

    let route = match router.match_request(&host, &path) {
        Some(r) => r,
        None => {
            tracing::debug!(host = %host, path = %path, "no passthrough route matched");
            return not_found("no passthrough route");
        }
    };
    tracing::Span::current().record("route", route.name.as_str());
    tracing::Span::current().record("upstream", route.base_url.as_str());

    // Write the matched route name into the per-passthrough metric slot
    // the observability middleware allocated. Read by the middleware
    // post-response to attach a `route` label to ati.proxy.requests and
    // ati.proxy.request_duration_ms. Issue #113: per-upstream dashboards.
    if let Some(slot) = req
        .extensions()
        .get::<Arc<crate::proxy::server::PassthroughMetricLabelsSlot>>()
    {
        if let Ok(mut g) = slot.route.lock() {
            *g = Some(route.name.clone());
        }
    }

    // Compute the rewritten path BEFORE checking deny-paths, so denials are
    // expressed against the path the upstream would actually see.
    let upstream_path = rewrite_path(&path, &route);

    if route.deny_globs.is_match(&upstream_path) {
        tracing::info!(
            route = %route.name,
            path = %upstream_path,
            "passthrough denied by deny_paths"
        );
        // Bump the deny counter (#113) — bounded cardinality, route label
        // only. The path itself stays in the tracing log line above.
        #[cfg(feature = "otel")]
        if let Some(m) = crate::core::otel::metrics() {
            use opentelemetry::KeyValue;
            m.passthrough_denied
                .add(1, &[KeyValue::new("route", route.name.clone())]);
        }
        return forbidden("path denied by policy");
    }

    // Forward-auth mode: when the upstream path matches a glob in
    // `forward_authorization_paths`, keep the sandbox's inbound Authorization
    // and SKIP the manifest-defined auth_header. Required for LiteLLM
    // virtual keys so per-sandbox spend caps are enforced.
    let forward_auth = route.forward_auth_globs.is_match(&upstream_path);

    // WebSocket upgrade dispatch — runs only when the route explicitly
    // allows it AND the client asks for an upgrade. Otherwise fall
    // through to plain HTTP (in which case the upstream will reject the
    // upgrade itself if it doesn't speak WS).
    if route.forward_websockets && is_websocket_upgrade(req.headers()) {
        return handle_passthrough_ws(req, route, upstream_path, query, forward_auth).await;
    }

    let method = req.method().clone();
    let req_headers = filter_request_headers(req.headers(), forward_auth);
    let body = req.into_body();

    // Enforce sync content-length cap if present — avoids streaming when we
    // know the request is over budget. Streaming cap still applies for
    // chunked-encoding requests via MaxBytesStream.
    if route.max_request_bytes > 0 {
        if let Some(cl) = req_headers
            .get(axum::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
        {
            if cl > route.max_request_bytes {
                tracing::warn!(
                    route = %route.name,
                    content_length = cl,
                    cap = route.max_request_bytes,
                    "request rejected: content-length exceeds max_request_bytes"
                );
                return too_large("request exceeds max_request_bytes");
            }
        }
    }

    // Build the upstream URL: base_url + rewritten path + query.
    let mut upstream_url = String::with_capacity(
        route.base_url.len()
            + upstream_path.len()
            + query.as_deref().map(|q| q.len() + 1).unwrap_or(0),
    );
    upstream_url.push_str(&route.base_url);
    if !upstream_path.starts_with('/') {
        upstream_url.push('/');
    }
    upstream_url.push_str(&upstream_path);
    if let Some(ref q) = query {
        upstream_url.push('?');
        upstream_url.push_str(q);
    }

    // Reqwest builder.
    let mut builder = route.client.request(reqwest_method(&method), &upstream_url);

    for (name, value) in req_headers.iter() {
        builder = builder.header(name.clone(), value.clone());
    }

    // Host override: set the upstream Host header explicitly. reqwest's URL
    // already controls SNI by virtue of the URL host; this lines the header
    // up with the SNI we send.
    if let Some(ref host_override) = route.host_override {
        builder = builder.header(axum::http::header::HOST, host_override);
    }

    // Manifest-defined auth header (one of bearer/header/basic).
    // Skipped when the path is in forward_authorization_paths — the
    // sandbox's inbound Authorization was already preserved above.
    if !forward_auth {
        if let Some((ref name, ref value)) = route.auth_header {
            builder = builder.header(name.clone(), value.clone());
        }
    }

    // Manifest-defined query auth. Same forward-auth semantics: when the
    // sandbox is supplying its own credential on this path, we don't append
    // the manifest's `?api_key=...` either.
    if !forward_auth {
        if let Some((ref name, ref value)) = route.auth_query {
            builder = builder.query(&[(name.as_str(), value.as_str())]);
        }
    }

    // Extra headers from the manifest (already keyring-expanded).
    for (name, value) in &route.extra_headers {
        builder = builder.header(name.clone(), value.clone());
    }

    // Stream the request body upstream.
    if accepts_body(&method) {
        let stream = body.into_data_stream();
        let capped = MaxBytesStream::new(stream, route.max_request_bytes);
        builder = builder.body(reqwest::Body::wrap_stream(capped));
    }

    // Inject W3C trace context so the upstream service joins our trace.
    // No-op when the `otel` feature is off or no exporter is configured.
    //
    // The sandbox-supplied inbound `traceparent` is not forwarded verbatim
    // (see `STRIP_DOWNSTREAM`). When an inbound `traceparent` was present,
    // `observability_middleware` in `proxy/server.rs` extracted it as the
    // parent of the outermost `http.server.request` span — so our current
    // span is already a child of the agent's outer trace, and the
    // `traceparent` we inject here carries the same trace_id with our own
    // span_id. Upstream receivers see one (and only one) traceparent.
    #[cfg(feature = "otel")]
    for (k, v) in crate::core::otel::current_trace_headers() {
        builder = builder.header(k, v);
    }

    let upstream_resp = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                route = %route.name,
                error = %e,
                upstream_url = %upstream_url,
                "upstream request failed"
            );
            #[cfg(feature = "otel")]
            if let Some(m) = crate::core::otel::metrics() {
                use opentelemetry::KeyValue;
                let kind = if e.is_timeout() {
                    "timeout"
                } else if e.is_connect() {
                    "connect"
                } else {
                    "send"
                };
                m.upstream_errors.add(
                    1,
                    &[
                        KeyValue::new("provider", route.name.clone()),
                        KeyValue::new("error_kind", kind),
                    ],
                );
            }
            return bad_gateway(&format!("upstream error: {e}"));
        }
    };

    let status = upstream_resp.status();
    // Strip Content-Length when a response cap is in play: MaxBytesStream
    // can truncate the body mid-stream, and forwarding the upstream's CL
    // would frame the response as a lie. Without CL, axum/hyper falls back
    // to chunked transfer-encoding which handles truncation cleanly.
    let cap_active = route.max_response_bytes > 0;
    let resp_headers = filter_response_headers(upstream_resp.headers(), cap_active);
    // reqwest::Response::bytes_stream gives us Result<Bytes, reqwest::Error>;
    // axum::body::Body::from_stream wants the same shape modulo error type.
    let upstream_stream = upstream_resp.bytes_stream();
    let capped = MaxBytesStream::new(upstream_stream, route.max_response_bytes);
    let body = Body::from_stream(capped);

    let mut response = Response::builder().status(reqwest_status_to_axum(status));
    {
        let h = response.headers_mut().expect("response headers");
        for (name, value) in resp_headers.iter() {
            h.append(name.clone(), value.clone());
        }
    }
    response.body(body).unwrap_or_else(|e| {
        tracing::error!(error = %e, "failed to assemble passthrough response");
        bad_gateway("response build failed")
    })
}

fn reqwest_method(m: &Method) -> reqwest::Method {
    // axum's Method is from the `http` crate; reqwest re-exports the same type.
    // Conversion is a string round-trip to keep the dependency edges clean.
    reqwest::Method::from_bytes(m.as_str().as_bytes()).unwrap_or(reqwest::Method::GET)
}

fn reqwest_status_to_axum(s: reqwest::StatusCode) -> StatusCode {
    StatusCode::from_u16(s.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY)
}

fn accepts_body(m: &Method) -> bool {
    !matches!(
        *m,
        Method::GET | Method::HEAD | Method::DELETE | Method::OPTIONS
    )
}

fn not_found(reason: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from(format!("not found: {reason}")))
        .expect("404 response")
}

fn forbidden(reason: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::from(format!("forbidden: {reason}")))
        .expect("403 response")
}

fn too_large(reason: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::PAYLOAD_TOO_LARGE)
        .body(Body::from(format!("payload too large: {reason}")))
        .expect("413 response")
}

fn bad_gateway(reason: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Body::from(format!("bad gateway: {reason}")))
        .expect("502 response")
}

// --- WebSocket passthrough ----------------------------------------------

/// Detect WebSocket-upgrade intent on an inbound request. Per RFC 6455
/// §4.2, a client signals upgrade with:
///   - `Connection: upgrade` (case-insensitive, may be comma-separated)
///   - `Upgrade: websocket`  (case-insensitive)
fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let upgrade = headers
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let connection = headers
        .get(axum::http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    upgrade.eq_ignore_ascii_case("websocket")
        && connection
            .split(',')
            .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
}

/// Convert a passthrough route's HTTP base_url + rewritten path/query into
/// the `ws://`/`wss://` URL the upstream WebSocket library expects.
fn build_ws_upstream_url(base_url: &str, path: &str, query: Option<&str>) -> String {
    let scheme_swapped = if let Some(rest) = base_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base_url.to_string()
    };
    let trimmed = scheme_swapped.trim_end_matches('/');
    let leading = if path.starts_with('/') { "" } else { "/" };
    match query {
        Some(q) => format!("{trimmed}{leading}{path}?{q}"),
        None => format!("{trimmed}{leading}{path}"),
    }
}

/// WS-specific passthrough handler. Accepts the inbound upgrade via
/// `WebSocketUpgrade::from_request`, opens an upstream WS via
/// `tokio_tungstenite::connect_async`, then runs a bidirectional frame
/// pump until either side closes.
async fn handle_passthrough_ws(
    req: Request<Body>,
    route: Arc<PassthroughRoute>,
    upstream_path: String,
    query: Option<String>,
    forward_auth: bool,
) -> Response<Body> {
    // Append auth_query (if any) to the upstream URL. Routes with
    // `auth_type = "query"` carry the credential in the query string;
    // earlier PR-5 code only handled the header-based variants.
    // (Greptile P1 #98)
    //
    // Skipped on forward_auth paths: the sandbox is supplying its own
    // credential and the manifest auth should not be appended.
    let mut combined_query = query.unwrap_or_default();
    if !forward_auth {
        if let Some((ref name, ref value)) = route.auth_query {
            if !combined_query.is_empty() {
                combined_query.push('&');
            }
            let encoded_value = urlencode(value);
            combined_query.push_str(name);
            combined_query.push('=');
            combined_query.push_str(&encoded_value);
        }
    }
    let upstream_url = build_ws_upstream_url(
        &route.base_url,
        &upstream_path,
        if combined_query.is_empty() {
            None
        } else {
            Some(combined_query.as_str())
        },
    );

    // Extract + filter the inbound client headers BEFORE consuming `req`
    // via `WebSocketUpgrade::from_request`. axum's extractor takes
    // ownership of the request, so we have to capture anything we need to
    // forward (subprotocol negotiation, custom application headers, etc.)
    // up front. We use the same hop-by-hop / sandbox-internal filter as
    // the HTTP path — and additionally strip the `sec-websocket-*`
    // handshake-control headers, which tokio_tungstenite generates fresh
    // for the upstream connection.
    let client_headers = filter_ws_client_headers(req.headers(), forward_auth);

    // Capture the client's offered subprotocols up front. axum's
    // WebSocketUpgrade::from_request consumes the request and would
    // otherwise leave the inbound 101 with no Sec-WebSocket-Protocol — so
    // even when the upstream picks one, the sandbox client sees nothing
    // negotiated. We mirror tokio_tungstenite's selection (first offered
    // subprotocol) on the inbound side via WebSocketUpgrade::protocols.
    let offered_subprotocols: Vec<String> = client_headers
        .get_all("sec-websocket-protocol")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let upgrade = match WebSocketUpgrade::from_request(req, &()).await {
        Ok(u) => u,
        Err(rej) => {
            tracing::warn!(
                route = %route.name,
                "client sent Upgrade: websocket but the request didn't satisfy axum's WS handshake"
            );
            return rej.into_response();
        }
    };
    let upgrade = if offered_subprotocols.is_empty() {
        upgrade
    } else {
        upgrade.protocols(offered_subprotocols)
    };
    let route_for_log = route.name.clone();
    upgrade.on_upgrade(move |socket| async move {
        if let Err(e) = pump_ws(
            route,
            upstream_url.clone(),
            client_headers,
            socket,
            forward_auth,
        )
        .await
        {
            tracing::warn!(
                route = %route_for_log,
                error = %e,
                upstream = %upstream_url,
                "WS pump exited with error"
            );
        }
    })
}

/// Minimal percent-encoder for the auth_query value. Only encodes a
/// conservative set that's safe in URL query position (RFC 3986).
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// Filter inbound client headers for forwarding through a WS handshake.
/// Strips:
/// - hop-by-hop headers (RFC 7230 §6.1)
/// - sandbox-internal headers (host, authorization, x-sandbox-*)
/// - `sec-websocket-*` handshake-control headers — tokio_tungstenite
///   generates fresh `Sec-WebSocket-Key`/`Sec-WebSocket-Version` for
///   the upstream connection; forwarding the client's values would
///   break the handshake.
///
/// What survives: `Sec-WebSocket-Protocol` (subprotocol negotiation) is
/// explicitly KEPT — that's the one `sec-websocket-*` header upstreams
/// can need.
fn filter_ws_client_headers(src: &HeaderMap, keep_authorization: bool) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(src.len());
    // RFC 7230 §6.1: headers named in `Connection:` are hop-by-hop. The HTTP
    // path strips these in `filter_request_headers`; the WS upgrade path is
    // a real socket too and the same leak applies — `Connection: keep-alive,
    // X-Custom-Hop` would otherwise drop `Connection` but forward
    // `X-Custom-Hop` verbatim to the upstream. (Greptile #99 P1)
    let conn_hops = connection_hop_names(src);
    for (name, value) in src.iter() {
        let n = name.as_str();
        if HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(n)) {
            continue;
        }
        if conn_hops.iter().any(|h| h.eq_ignore_ascii_case(n)) {
            continue;
        }
        if is_sandbox_internal_header(n) {
            if keep_authorization && n.eq_ignore_ascii_case("authorization") {
                out.append(name.clone(), value.clone());
                continue;
            }
            continue;
        }
        let n_lc = n.to_ascii_lowercase();
        // Strip Sec-WebSocket-Key / -Version / -Accept / -Extensions.
        // Keep Sec-WebSocket-Protocol for subprotocol negotiation.
        if n_lc.starts_with("sec-websocket-") && n_lc != "sec-websocket-protocol" {
            continue;
        }
        // Strip the upgrade signaling headers — tokio_tungstenite handles
        // those itself on the upstream side.
        if matches!(n_lc.as_str(), "upgrade" | "connection") {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

/// Open the upstream WebSocket connection (injecting auth, extra
/// headers, and the filtered client headers) and pump frames in both
/// directions until one side closes. Ping/Pong frames are NOT relayed:
/// both libraries auto-respond on their own leg, so forwarding would
/// cause double-Pongs (Greptile P2 #98).
async fn pump_ws(
    route: Arc<PassthroughRoute>,
    upstream_url: String,
    client_headers: HeaderMap,
    mut sandbox: WebSocket,
    forward_auth: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::str::FromStr;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue as TtHeaderValue;
    use tokio_tungstenite::tungstenite::Message as TtMessage;

    let mut up_req = upstream_url
        .as_str()
        .into_client_request()
        .map_err(|e| format!("invalid upstream URL: {e}"))?;

    // Forward filtered client headers FIRST so route-configured ones can
    // override them (host_override / auth_header / extra_headers below
    // use `insert` which replaces).
    for (name, value) in &client_headers {
        if let Ok(n) = tokio_tungstenite::tungstenite::http::HeaderName::from_str(name.as_str()) {
            if let Ok(v) = TtHeaderValue::from_bytes(value.as_bytes()) {
                up_req.headers_mut().append(n, v);
            }
        }
    }
    if let Some(ref host_override) = route.host_override {
        if let Ok(v) = TtHeaderValue::from_str(host_override) {
            up_req.headers_mut().insert("host", v);
        }
    }
    if !forward_auth {
        if let Some((ref name, ref value)) = route.auth_header {
            if let (Ok(n), Ok(v)) = (
                tokio_tungstenite::tungstenite::http::HeaderName::from_str(name.as_str()),
                TtHeaderValue::from_bytes(value.as_bytes()),
            ) {
                up_req.headers_mut().insert(n, v);
            }
        }
    }
    for (name, value) in &route.extra_headers {
        if let (Ok(n), Ok(v)) = (
            tokio_tungstenite::tungstenite::http::HeaderName::from_str(name.as_str()),
            TtHeaderValue::from_bytes(value.as_bytes()),
        ) {
            up_req.headers_mut().insert(n, v);
        }
    }

    // Bound the upstream handshake. `connect_async` has no built-in
    // timeout, so a stalled upstream would leak one task per WS attempt
    // (the 101 back to the client is already sent at this point).
    let connect_timeout = Duration::from_secs(route.connect_timeout_seconds.max(1));
    let upstream =
        match tokio::time::timeout(connect_timeout, tokio_tungstenite::connect_async(up_req)).await
        {
            Ok(Ok((ws, _resp))) => ws,
            Ok(Err(e)) => return Err(format!("upstream WS handshake failed: {e}").into()),
            Err(_) => {
                return Err(format!(
                    "upstream WS handshake timed out after {}s",
                    connect_timeout.as_secs()
                )
                .into());
            }
        };
    let (mut up_tx, mut up_rx) = upstream.split();

    loop {
        tokio::select! {
            inbound = sandbox.recv() => match inbound {
                Some(Ok(msg)) => {
                    // Drop Ping/Pong from the relay — each library auto-
                    // responds on its own leg. Forwarding them produces
                    // double-Pongs that confuse heartbeat counters.
                    if matches!(msg, Message::Ping(_) | Message::Pong(_)) {
                        continue;
                    }
                    let tt_msg = axum_to_tungstenite(msg);
                    let is_close = matches!(tt_msg, TtMessage::Close(_));
                    if let Err(e) = up_tx.send(tt_msg).await {
                        tracing::debug!(error = %e, "upstream send failed; closing");
                        break;
                    }
                    if is_close { break; }
                }
                Some(Err(e)) => {
                    tracing::debug!(error = %e, "sandbox recv error");
                    break;
                }
                None => break,
            },
            outbound = up_rx.next() => match outbound {
                Some(Ok(msg)) => {
                    if matches!(msg, TtMessage::Ping(_) | TtMessage::Pong(_)) {
                        continue;
                    }
                    let is_close = matches!(msg, TtMessage::Close(_));
                    if let Some(m) = tungstenite_to_axum(msg) {
                        if let Err(e) = sandbox.send(m).await {
                            tracing::debug!(error = %e, "sandbox send failed; closing");
                            break;
                        }
                    }
                    if is_close { break; }
                }
                Some(Err(e)) => {
                    tracing::debug!(error = %e, "upstream recv error");
                    break;
                }
                None => break,
            },
        }
    }
    let _ = up_tx.close().await;
    let _ = sandbox.close().await;
    Ok(())
}

fn axum_to_tungstenite(m: Message) -> tokio_tungstenite::tungstenite::Message {
    use tokio_tungstenite::tungstenite::protocol::CloseFrame as TtCloseFrame;
    use tokio_tungstenite::tungstenite::Message as TtMessage;
    match m {
        Message::Text(s) => TtMessage::Text(s.to_string()),
        Message::Binary(b) => TtMessage::Binary(b.to_vec()),
        Message::Ping(b) => TtMessage::Ping(b.to_vec()),
        Message::Pong(b) => TtMessage::Pong(b.to_vec()),
        Message::Close(Some(c)) => TtMessage::Close(Some(TtCloseFrame {
            code: c.code.into(),
            reason: c.reason.to_string().into(),
        })),
        Message::Close(None) => TtMessage::Close(None),
    }
}

fn tungstenite_to_axum(m: tokio_tungstenite::tungstenite::Message) -> Option<Message> {
    use axum::extract::ws::CloseFrame as AxCloseFrame;
    use tokio_tungstenite::tungstenite::Message as TtMessage;
    match m {
        TtMessage::Text(s) => Some(Message::Text(s.to_string().into())),
        TtMessage::Binary(b) => Some(Message::Binary(b.to_vec().into())),
        TtMessage::Ping(b) => Some(Message::Ping(b.to_vec().into())),
        TtMessage::Pong(b) => Some(Message::Pong(b.to_vec().into())),
        TtMessage::Close(Some(c)) => Some(Message::Close(Some(AxCloseFrame {
            code: c.code.into(),
            reason: c.reason.to_string().into(),
        }))),
        TtMessage::Close(None) => Some(Message::Close(None)),
        TtMessage::Frame(_) => None,
    }
}

// --- Adapter for ManifestRegistry::manifests() -----------------------------
//
// `ManifestRegistry` exposes manifests via accessor methods (`list_providers`,
// `list_public_tools`, etc.) but doesn't currently expose the raw `Vec<Manifest>`.
// For the passthrough builder we need to iterate all providers including
// internal ones — so we extend the registry with a `manifests()` accessor.
// That accessor lives next to the other read methods in core::manifest.

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use std::collections::HashMap;

    fn dummy_keyring() -> Keyring {
        Keyring::empty()
    }

    /// Process-wide mutex around env-var manipulation. `Keyring::from_env`
    /// scans the process environment, so two concurrent tests setting
    /// `ATI_KEY_*` would race. Hold this for the duration of any test that
    /// touches env vars used by `from_env`.
    fn env_mutex() -> &'static std::sync::Mutex<()> {
        static M: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        M.get_or_init(|| std::sync::Mutex::new(()))
    }

    fn keyring_with(pairs: &[(&str, &str)]) -> Keyring {
        // Hold the env mutex for the whole set/build/clear cycle so concurrent
        // tests don't see each other's keyrings.
        let _guard = env_mutex().lock().unwrap_or_else(|p| p.into_inner());
        for (k, v) in pairs {
            std::env::set_var(format!("ATI_KEY_{}", k.to_uppercase()), v);
        }
        let kr = Keyring::from_env();
        for (k, _) in pairs {
            std::env::remove_var(format!("ATI_KEY_{}", k.to_uppercase()));
        }
        kr
    }

    fn passthrough_provider(name: &str) -> Provider {
        Provider {
            name: name.to_string(),
            description: "test".to_string(),
            base_url: "https://upstream.example".to_string(),
            auth_type: AuthType::None,
            auth_key_name: None,
            auth_header_name: None,
            auth_query_name: None,
            auth_value_prefix: None,
            extra_headers: HashMap::new(),
            oauth2_token_url: None,
            auth_secret_name: None,
            oauth2_basic_auth: false,
            internal: false,
            handler: "passthrough".to_string(),
            mcp_transport: None,
            mcp_command: None,
            mcp_args: Vec::new(),
            mcp_url: None,
            mcp_env: HashMap::new(),
            cli_command: None,
            cli_default_args: Vec::new(),
            cli_env: HashMap::new(),
            cli_timeout_secs: None,
            cli_output_args: Vec::new(),
            cli_output_positional: HashMap::new(),
            upload_destinations: HashMap::new(),
            upload_default_destination: None,
            host_match: None,
            path_prefix: Some("/test".to_string()),
            strip_prefix: true,
            path_replace: None,
            host_override: None,
            forward_websockets: false,
            deny_paths: Vec::new(),
            forward_authorization_paths: Vec::new(),
            connect_timeout_seconds: 5,
            read_timeout_seconds: 30,
            idle_timeout_seconds: 60,
            max_request_bytes: 1024 * 1024,
            max_response_bytes: 1024 * 1024,
            openapi_spec: None,
            openapi_include_tags: Vec::new(),
            openapi_exclude_tags: Vec::new(),
            openapi_include_operations: Vec::new(),
            openapi_exclude_operations: Vec::new(),
            openapi_max_operations: None,
            openapi_overrides: HashMap::new(),
            auth_generator: None,
            category: None,
            skills: Vec::new(),
        }
    }

    #[test]
    fn matches_prefix_handles_boundaries() {
        assert!(matches_prefix(Some("/litellm"), "/litellm"));
        assert!(matches_prefix(Some("/litellm"), "/litellm/v1/chat"));
        assert!(!matches_prefix(Some("/litellm"), "/litellmx"));
        assert!(!matches_prefix(Some("/litellm"), "/lite"));
        assert!(matches_prefix(None, "/anything"));
        assert!(matches_prefix(Some("/"), "/foo"));
    }

    #[test]
    fn resolve_env_value_expands_known_keys() {
        let kr = keyring_with(&[("my_secret", "S3CR3T")]);
        assert_eq!(resolve_env_value("${my_secret}", &kr), "S3CR3T");
        assert_eq!(
            resolve_env_value("Bearer ${my_secret}", &kr),
            "Bearer S3CR3T"
        );
        // Unknown keys are left as the literal placeholder, matching
        // mcp_client::resolve_env_value behaviour.
        assert_eq!(resolve_env_value("${unknown}", &kr), "${unknown}");
        // Unclosed brace: leave alone.
        assert_eq!(resolve_env_value("${unclosed", &kr), "${unclosed");
        // No placeholder at all.
        assert_eq!(resolve_env_value("plain", &kr), "plain");
    }

    #[test]
    fn rewrite_path_strips_prefix() {
        let p = passthrough_provider("t");
        let route = compile_route(&p, &dummy_keyring()).unwrap();
        assert_eq!(rewrite_path("/test/foo", &route), "/foo");
        assert_eq!(rewrite_path("/test", &route), "/");
        // Non-matching paths pass through unchanged.
        assert_eq!(rewrite_path("/other", &route), "/other");
    }

    #[test]
    fn rewrite_path_no_strip() {
        let mut p = passthrough_provider("t");
        p.strip_prefix = false;
        let route = compile_route(&p, &dummy_keyring()).unwrap();
        assert_eq!(rewrite_path("/test/foo", &route), "/test/foo");
    }

    #[test]
    fn rewrite_path_applies_replace() {
        let mut p = passthrough_provider("t");
        p.path_prefix = Some("/otel".to_string());
        p.path_replace = Some(("/".to_string(), "/otlp/".to_string()));
        let route = compile_route(&p, &dummy_keyring()).unwrap();
        // strip /otel → "/v1/traces" → replace "/" with "/otlp/" → "/otlp/v1/traces"
        assert_eq!(rewrite_path("/otel/v1/traces", &route), "/otlp/v1/traces");
    }

    #[test]
    fn auth_bearer_resolves_at_startup() {
        let mut p = passthrough_provider("t");
        p.auth_type = AuthType::Bearer;
        p.auth_key_name = Some("my_secret".to_string());
        let kr = keyring_with(&[("my_secret", "S3CR3T")]);
        let route = compile_route(&p, &kr).unwrap();
        let (name, value) = route.auth_header.expect("expected auth_header");
        assert_eq!(name.as_str(), "authorization");
        assert_eq!(value.to_str().unwrap(), "Bearer S3CR3T");
    }

    #[test]
    fn auth_header_with_prefix() {
        let mut p = passthrough_provider("t");
        p.auth_type = AuthType::Header;
        p.auth_header_name = Some("X-Custom-Auth".to_string());
        p.auth_value_prefix = Some("Token ".to_string());
        p.auth_key_name = Some("my_secret".to_string());
        let kr = keyring_with(&[("my_secret", "abc123")]);
        let route = compile_route(&p, &kr).unwrap();
        let (name, value) = route.auth_header.expect("expected auth_header");
        assert_eq!(name.as_str(), "x-custom-auth");
        assert_eq!(value.to_str().unwrap(), "Token abc123");
    }

    #[test]
    fn auth_query_resolves() {
        let mut p = passthrough_provider("t");
        p.auth_type = AuthType::Query;
        p.auth_query_name = Some("api_token".to_string());
        p.auth_key_name = Some("my_secret".to_string());
        let kr = keyring_with(&[("my_secret", "v1")]);
        let route = compile_route(&p, &kr).unwrap();
        let (n, v) = route.auth_query.expect("expected auth_query");
        assert_eq!(n, "api_token");
        assert_eq!(v, "v1");
    }

    #[test]
    fn auth_basic_base64_encodes() {
        let mut p = passthrough_provider("t");
        p.auth_type = AuthType::Basic;
        p.auth_key_name = Some("creds".to_string());
        let kr = keyring_with(&[("creds", "user:pass")]);
        let route = compile_route(&p, &kr).unwrap();
        let (name, value) = route.auth_header.expect("basic auth header");
        assert_eq!(name.as_str(), "authorization");
        // base64("user:pass") = "dXNlcjpwYXNz"
        assert_eq!(value.to_str().unwrap(), "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn extra_headers_expand_keyring_placeholders() {
        let mut p = passthrough_provider("t");
        p.extra_headers
            .insert("X-Token".to_string(), "Tok ${secret}".to_string());
        let kr = keyring_with(&[("secret", "abc")]);
        let route = compile_route(&p, &kr).unwrap();
        let (name, value) = &route.extra_headers[0];
        assert_eq!(name.as_str(), "x-token");
        assert_eq!(value.to_str().unwrap(), "Tok abc");
    }

    #[test]
    fn deny_globs_match() {
        let mut p = passthrough_provider("t");
        p.deny_paths = vec!["/config/*".to_string(), "/model/*".to_string()];
        let route = compile_route(&p, &dummy_keyring()).unwrap();
        assert!(route.deny_globs.is_match("/config/secrets"));
        assert!(route.deny_globs.is_match("/model/list"));
        assert!(!route.deny_globs.is_match("/v1/chat"));
    }

    #[test]
    fn deny_globs_block_nested_subpaths_not_just_one_segment() {
        // Greptile review #2 P1: `/config/*` must also block `/config/a/b`
        // because `*` doesn't cross `/`. Without the expand_deny_pattern
        // helper, a sandbox could bypass the LiteLLM admin denylist by
        // appending a sub-segment.
        let mut p = passthrough_provider("t");
        p.deny_paths = vec!["/config/*".to_string()];
        let route = compile_route(&p, &dummy_keyring()).unwrap();
        assert!(route.deny_globs.is_match("/config/x"), "single segment");
        assert!(route.deny_globs.is_match("/config/x/y"), "two segments");
        assert!(route.deny_globs.is_match("/config/x/y/z"), "deeply nested");
        assert!(
            !route.deny_globs.is_match("/configuration"),
            "no false-positive on prefix without /"
        );
        assert!(!route.deny_globs.is_match("/v1"));
    }

    #[test]
    fn expand_deny_pattern_rules() {
        // /config/*  →  [/config/*, /config/**]
        let exp = expand_deny_pattern("/config/*");
        assert!(exp.contains(&"/config/*".to_string()));
        assert!(exp.contains(&"/config/**".to_string()));

        // /admin  →  [/admin, /admin/**]
        let exp = expand_deny_pattern("/admin");
        assert!(exp.contains(&"/admin".to_string()));
        assert!(exp.contains(&"/admin/**".to_string()));

        // /admin/  →  [/admin/, /admin/**]  (trailing slash normalized)
        let exp = expand_deny_pattern("/admin/");
        assert!(exp.contains(&"/admin/**".to_string()));

        // /config/**  →  [/config/**]  (operator was already explicit)
        let exp = expand_deny_pattern("/config/**");
        assert_eq!(exp, vec!["/config/**".to_string()]);

        // *.json  →  [*.json]  (not anchored — non-HTTP-path pattern)
        let exp = expand_deny_pattern("*.json");
        assert_eq!(exp, vec!["*.json".to_string()]);
    }

    #[test]
    fn deny_globs_match_literal_root_when_no_glob() {
        // /admin (no trailing wildcard) blocks both /admin and /admin/anything
        let mut p = passthrough_provider("t");
        p.deny_paths = vec!["/admin".to_string()];
        let route = compile_route(&p, &dummy_keyring()).unwrap();
        assert!(route.deny_globs.is_match("/admin"));
        assert!(route.deny_globs.is_match("/admin/users"));
        assert!(route.deny_globs.is_match("/admin/users/list"));
        assert!(!route.deny_globs.is_match("/administrator"));
    }

    #[test]
    fn build_sorts_routes_longest_prefix_first() {
        // Build a registry with two passthroughs: /lite and /litellm/v1.
        // /litellm/v1 must come first so that a request for /litellm/v1/x
        // matches it rather than /lite.
        let mut p1 = passthrough_provider("a");
        p1.path_prefix = Some("/lite".to_string());
        let mut p2 = passthrough_provider("b");
        p2.path_prefix = Some("/litellm/v1".to_string());

        let kr = dummy_keyring();
        let routes = vec![
            Arc::new(compile_route(&p1, &kr).unwrap()),
            Arc::new(compile_route(&p2, &kr).unwrap()),
        ];
        // Manually invoke the same sort the builder uses.
        let mut routes = routes;
        routes.sort_by(|a, b| {
            let host_rank = |r: &PassthroughRoute| if r.host_match.is_some() { 0 } else { 1 };
            let prefix_len =
                |r: &PassthroughRoute| r.path_prefix.as_deref().map(|s| s.len()).unwrap_or(0);
            host_rank(a)
                .cmp(&host_rank(b))
                .then_with(|| prefix_len(b).cmp(&prefix_len(a)))
        });
        assert_eq!(routes[0].name, "b");
        assert_eq!(routes[1].name, "a");
    }

    #[test]
    fn host_match_beats_default_host() {
        let mut p1 = passthrough_provider("default");
        p1.host_match = None;
        p1.path_prefix = Some("/v1".to_string());

        let mut p2 = passthrough_provider("bb");
        p2.host_match = Some("bb.example.com".to_string());
        // No path_prefix → matches any path on that host.
        p2.path_prefix = None;

        let kr = dummy_keyring();
        let router = PassthroughRouter {
            routes: {
                let mut r = vec![
                    Arc::new(compile_route(&p1, &kr).unwrap()),
                    Arc::new(compile_route(&p2, &kr).unwrap()),
                ];
                r.sort_by(|a, b| {
                    let host_rank =
                        |r: &PassthroughRoute| if r.host_match.is_some() { 0 } else { 1 };
                    let prefix_len = |r: &PassthroughRoute| {
                        r.path_prefix.as_deref().map(|s| s.len()).unwrap_or(0)
                    };
                    host_rank(a)
                        .cmp(&host_rank(b))
                        .then_with(|| prefix_len(b).cmp(&prefix_len(a)))
                });
                r
            },
        };

        let hit_bb = router
            .match_request("bb.example.com", "/v1/sessions")
            .unwrap();
        assert_eq!(hit_bb.name, "bb");

        let hit_default = router
            .match_request("api.example.com", "/v1/sessions")
            .unwrap();
        assert_eq!(hit_default.name, "default");
    }

    #[test]
    fn match_request_returns_none_when_no_route() {
        let p = passthrough_provider("t");
        let kr = dummy_keyring();
        let router = PassthroughRouter {
            routes: vec![Arc::new(compile_route(&p, &kr).unwrap())],
        };
        assert!(router.match_request("any", "/elsewhere").is_none());
    }

    #[tokio::test]
    async fn max_bytes_stream_trips_over_cap() {
        use futures::stream;
        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
            Ok(Bytes::from(vec![0u8; 100])),
            Ok(Bytes::from(vec![0u8; 100])),
        ];
        let s = stream::iter(chunks);
        let mut capped = MaxBytesStream::new(s, 150);
        // First chunk fits.
        let first = capped.next().await.unwrap();
        assert!(first.is_ok());
        // Second chunk pushes past the cap → Err.
        let second = capped.next().await.unwrap();
        assert!(second.is_err());
        // Subsequent polls return None.
        assert!(capped.next().await.is_none());
    }

    #[tokio::test]
    async fn max_bytes_stream_zero_is_unlimited() {
        use futures::stream;
        let chunks: Vec<Result<Bytes, std::io::Error>> =
            vec![Ok(Bytes::from(vec![0u8; 10_000_000]))];
        let s = stream::iter(chunks);
        let mut capped = MaxBytesStream::new(s, 0);
        let chunk = capped.next().await.unwrap();
        assert!(chunk.is_ok());
    }

    #[test]
    fn filter_request_strips_hop_by_hop_and_auth() {
        let mut h = HeaderMap::new();
        h.insert("connection", "keep-alive".parse().unwrap());
        h.insert("host", "api.example.com".parse().unwrap());
        h.insert("authorization", "Bearer leak".parse().unwrap());
        h.insert("x-sandbox-signature", "t=1,s=ab".parse().unwrap());
        h.insert("x-keep", "yes".parse().unwrap());
        let out = filter_request_headers(&h, false);
        assert!(out.get("connection").is_none());
        assert!(out.get("host").is_none());
        assert!(out.get("authorization").is_none());
        assert!(out.get("x-sandbox-signature").is_none());
        assert_eq!(out.get("x-keep").unwrap().to_str().unwrap(), "yes");
    }

    #[test]
    fn filter_request_strips_inbound_w3c_trace_headers() {
        // W3C Trace Context §2.3: multiple `traceparent` headers on a single
        // request MUST be treated as if none was present. Since the OTel
        // injection in handle_passthrough adds its own `traceparent` /
        // `tracestate` before send, we MUST strip the sandbox-supplied
        // ones inbound or the upstream sees both and silently discards
        // the trace context. This test pins that strip.
        let mut h = HeaderMap::new();
        h.insert(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .unwrap(),
        );
        h.insert("tracestate", "vendor=value,other=v2".parse().unwrap());
        h.insert("x-keep", "yes".parse().unwrap());
        let out = filter_request_headers(&h, false);
        assert!(
            out.get("traceparent").is_none(),
            "inbound traceparent must be stripped — see W3C Trace Context §2.3"
        );
        assert!(
            out.get("tracestate").is_none(),
            "inbound tracestate must be stripped alongside traceparent"
        );
        assert_eq!(out.get("x-keep").unwrap().to_str().unwrap(), "yes");
    }

    #[test]
    fn filter_request_strips_all_x_sandbox_prefix_headers() {
        // Greptile pointed out that the original strip list named only
        // x-sandbox-signature and x-sandbox-job-id — but the sandbox runner
        // can add any number of x-sandbox-* telemetry/tracing headers. The
        // filter must catch all of them by prefix.
        let mut h = HeaderMap::new();
        h.insert("x-sandbox-signature", "t=1,s=ab".parse().unwrap());
        h.insert("x-sandbox-job-id", "job-123".parse().unwrap());
        h.insert("x-sandbox-trace-id", "tr-xyz".parse().unwrap());
        h.insert("x-sandbox-attempt", "2".parse().unwrap());
        h.insert("x-keep", "yes".parse().unwrap());
        let out = filter_request_headers(&h, false);
        for sandbox_hdr in &[
            "x-sandbox-signature",
            "x-sandbox-job-id",
            "x-sandbox-trace-id",
            "x-sandbox-attempt",
        ] {
            assert!(
                out.get(*sandbox_hdr).is_none(),
                "expected {sandbox_hdr} to be stripped"
            );
        }
        assert_eq!(out.get("x-keep").unwrap().to_str().unwrap(), "yes");
    }

    #[test]
    fn filter_request_keeps_authorization_when_opted_in() {
        // `keep_authorization = true` opts out of the Authorization strip
        // for forward_authorization_paths routes (LiteLLM virtual keys).
        // Other STRIP_DOWNSTREAM entries (host, traceparent) still strip
        // unconditionally — only Authorization is gated by the flag.
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer sk-virtual".parse().unwrap());
        h.insert("host", "leaks.example.com".parse().unwrap());
        h.insert("traceparent", "00-x-y-01".parse().unwrap());
        h.insert("x-sandbox-signature", "t=1,s=ab".parse().unwrap());
        h.insert("x-keep", "yes".parse().unwrap());
        let out = filter_request_headers(&h, true);
        assert_eq!(
            out.get("authorization").unwrap().to_str().unwrap(),
            "Bearer sk-virtual",
            "Authorization MUST be preserved when keep_authorization = true"
        );
        // Everything else still strips — only Authorization is opt-out.
        assert!(out.get("host").is_none());
        assert!(out.get("traceparent").is_none());
        assert!(out.get("x-sandbox-signature").is_none());
        assert_eq!(out.get("x-keep").unwrap().to_str().unwrap(), "yes");
    }

    #[test]
    fn filter_response_strips_hop_by_hop_keeps_content_length_when_no_cap() {
        // cap_active=false → Content-Length is preserved (no truncation risk).
        let mut h = HeaderMap::new();
        h.insert("connection", "close".parse().unwrap());
        h.insert("content-type", "application/json".parse().unwrap());
        h.insert("content-length", "42".parse().unwrap());
        h.insert("authorization", "Bearer upstream".parse().unwrap());
        let out = filter_response_headers(&h, false);
        assert!(out.get("connection").is_none());
        // We don't strip authorization on responses — upstream may legitimately
        // set it (e.g. an OAuth-flow handshake).
        assert!(out.get("authorization").is_some());
        assert!(out.get("content-type").is_some());
        assert_eq!(out.get("content-length").unwrap().to_str().unwrap(), "42");
    }

    #[test]
    fn filter_response_strips_content_length_when_cap_active() {
        // cap_active=true → Content-Length is dropped. MaxBytesStream can
        // truncate the body mid-stream; forwarding the original CL would
        // tell the client to expect more bytes than it'll receive, breaking
        // HTTP framing.
        let mut h = HeaderMap::new();
        h.insert("content-type", "application/octet-stream".parse().unwrap());
        h.insert("content-length", "999999".parse().unwrap());
        let out = filter_response_headers(&h, true);
        assert!(
            out.get("content-length").is_none(),
            "content-length must be stripped when cap is active"
        );
        assert!(out.get("content-type").is_some());
    }
}
