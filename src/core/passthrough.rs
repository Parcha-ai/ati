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
use axum::extract::State;
use axum::http::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Method, Request, Response, StatusCode,
};
use bytes::Bytes;
use futures::stream::Stream;
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
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
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
            let prefix_len = |r: &PassthroughRoute| r.path_prefix.as_deref().map(|s| s.len()).unwrap_or(0);
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

fn compile_route(p: &Provider, keyring: &Keyring) -> Result<PassthroughRoute, PassthroughBuildError> {
    // Validate the base_url parses as an absolute URL. We don't store the
    // parsed url::Url because we build the upstream URL from string concat —
    // but the parse step catches typos at startup instead of at first call.
    let parsed = url::Url::parse(&p.base_url)
        .map_err(|e| PassthroughBuildError::BadBaseUrl(p.name.clone(), e.to_string()))?;
    let base_url = p.base_url.trim_end_matches('/').to_string();

    // Build the deny-paths GlobSet.
    let mut deny_builder = GlobSetBuilder::new();
    for pattern in &p.deny_paths {
        let glob = Glob::new(pattern).map_err(|e| {
            PassthroughBuildError::BadDenyGlob(p.name.clone(), pattern.clone(), e.to_string())
        })?;
        deny_builder.add(glob);
    }
    let deny_globs = deny_builder
        .build()
        .map_err(|e| PassthroughBuildError::BadDenyGlob(p.name.clone(), String::new(), e.to_string()))?;

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
        // Caddy followed redirects by default; ATI passthrough follows the
        // 8-hop browser convention. Loop detection comes free with reqwest.
        .redirect(reqwest::redirect::Policy::limited(8))
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
        max_request_bytes: p.max_request_bytes,
        max_response_bytes: p.max_response_bytes,
        client: Arc::new(client),
    })
}

/// Either an injected header (bearer/header/basic auth) or a query-string
/// parameter (`auth_type = "query"`). Returned by `resolve_auth` so the
/// per-request handler can apply whichever the provider configured.
type ResolvedAuth = (
    Option<(HeaderName, HeaderValue)>,
    Option<(String, String)>,
);

fn resolve_auth(p: &Provider, keyring: &Keyring) -> Result<ResolvedAuth, PassthroughBuildError> {
    match p.auth_type {
        AuthType::None | AuthType::Oauth2 | AuthType::Url => Ok((None, None)),
        AuthType::Bearer => {
            let key = match &p.auth_key_name {
                Some(k) => k,
                None => return Ok((None, None)),
            };
            let value = keyring.get(key).unwrap_or("");
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
            let key_value = keyring.get(key).unwrap_or("");
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
            let query_name = p.auth_query_name.clone().unwrap_or_else(|| "api_key".to_string());
            let value = keyring.get(key).unwrap_or("").to_string();
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
            let creds = keyring.get(key).unwrap_or("");
            let encoded = base64::engine::general_purpose::STANDARD.encode(creds.as_bytes());
            let header_value = HeaderValue::from_str(&format!("Basic {encoded}")).map_err(|_| {
                PassthroughBuildError::BadHeaderValue(p.name.clone(), "Authorization".to_string())
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
];

/// Returns true if `name` matches a header we always strip from inbound
/// requests before forwarding upstream.
fn is_sandbox_internal_header(name: &str) -> bool {
    if STRIP_DOWNSTREAM.iter().any(|h| h.eq_ignore_ascii_case(name)) {
        return true;
    }
    // Strip ALL `x-sandbox-*` headers, not just the two we name. This
    // future-proofs against new signing or telemetry headers introduced
    // by the sandbox runner (e.g. `x-sandbox-trace-id`, `x-sandbox-attempt`).
    let n = name.to_ascii_lowercase();
    n.starts_with("x-sandbox-")
}

fn filter_request_headers(src: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(src.len());
    for (name, value) in src.iter() {
        let n = name.as_str();
        if HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(n)) {
            continue;
        }
        if is_sandbox_internal_header(n) {
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

    // Compute the rewritten path BEFORE checking deny-paths, so denials are
    // expressed against the path the upstream would actually see.
    let upstream_path = rewrite_path(&path, &route);

    if route.deny_globs.is_match(&upstream_path) {
        tracing::info!(
            route = %route.name,
            path = %upstream_path,
            "passthrough denied by deny_paths"
        );
        return forbidden("path denied by policy");
    }

    let method = req.method().clone();
    let req_headers = filter_request_headers(req.headers());
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
        route.base_url.len() + upstream_path.len() + query.as_deref().map(|q| q.len() + 1).unwrap_or(0),
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
    let mut builder = route
        .client
        .request(reqwest_method(&method), &upstream_url);

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
    if let Some((ref name, ref value)) = route.auth_header {
        builder = builder.header(name.clone(), value.clone());
    }

    // Manifest-defined query auth.
    if let Some((ref name, ref value)) = route.auth_query {
        builder = builder.query(&[(name.as_str(), value.as_str())]);
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

    let upstream_resp = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                route = %route.name,
                error = %e,
                upstream_url = %upstream_url,
                "upstream request failed"
            );
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
    !matches!(*m, Method::GET | Method::HEAD | Method::DELETE | Method::OPTIONS)
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
            let prefix_len = |r: &PassthroughRoute| r.path_prefix.as_deref().map(|s| s.len()).unwrap_or(0);
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
                    let host_rank = |r: &PassthroughRoute| if r.host_match.is_some() { 0 } else { 1 };
                    let prefix_len = |r: &PassthroughRoute| r.path_prefix.as_deref().map(|s| s.len()).unwrap_or(0);
                    host_rank(a)
                        .cmp(&host_rank(b))
                        .then_with(|| prefix_len(b).cmp(&prefix_len(a)))
                });
                r
            },
        };

        let hit_bb = router.match_request("bb.example.com", "/v1/sessions").unwrap();
        assert_eq!(hit_bb.name, "bb");

        let hit_default = router.match_request("api.example.com", "/v1/sessions").unwrap();
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
        let chunks: Vec<Result<Bytes, std::io::Error>> =
            vec![Ok(Bytes::from(vec![0u8; 100])), Ok(Bytes::from(vec![0u8; 100]))];
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
        let out = filter_request_headers(&h);
        assert!(out.get("connection").is_none());
        assert!(out.get("host").is_none());
        assert!(out.get("authorization").is_none());
        assert!(out.get("x-sandbox-signature").is_none());
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
        let out = filter_request_headers(&h);
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
        assert!(out.get("content-length").is_none(), "content-length must be stripped when cap is active");
        assert!(out.get("content-type").is_some());
    }
}
