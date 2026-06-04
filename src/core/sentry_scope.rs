//! Sentry scope helpers for proxy-side upstream error classification.
//!
//! Adds structured tags + a class-based dynamic event title so each error
//! class becomes a distinct Sentry issue bucket instead of every failure
//! collapsing into one generic "upstream server error" bucket. Also routes
//! log level by status class (info/warn/error).
//!
//! Title strategy: Sentry's tracing bridge maps `tracing::error!` messages
//! to event titles, and Sentry groups events by title when no fingerprint
//! is set. We dispatch the report into 5 buckets — `auth_error`,
//! `bad_input`, `rate_limited`, `server_error`, `transport_error` — each
//! with its own literal-string `tracing::error!`. Provider/operation/
//! status live as tags so each bucket is filterable per-provider without
//! splitting the buckets per-provider.
//!
//! See issue #81 for the original context; the redesign closes the
//! "Sentry errors really fucking suck" report — generic titles, missing
//! source chains, lying tags.

use crate::core::jwt::TokenClaims;

/// Coarse classification of an upstream failure. Each class maps to a
/// distinct Sentry bucket via a unique literal `tracing::error!` /
/// `tracing::warn!` message — that's how grouping survives across
/// providers without collapsing every error into one mega-bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamErrorClass {
    /// 401 / 403 / 407 — credentials missing, revoked, or insufficient.
    AuthError,
    /// 400 / 404 (non-no-records) / 422 — request shape was wrong.
    BadInput,
    /// 402 — out of credit; not actionable code-side. Always Warning.
    Quota,
    /// 429 — rate limited. Often actionable as a retry; Warning level.
    RateLimited,
    /// 5xx — upstream service broke.
    ServerError,
    /// 0 — no HTTP status (DNS, TCP, TLS, MCP transport error, etc.).
    TransportError,
}

impl UpstreamErrorClass {
    pub fn classify(upstream_status: u16) -> Self {
        match upstream_status {
            401 | 403 | 407 => Self::AuthError,
            400 | 404 | 422 => Self::BadInput,
            402 => Self::Quota,
            429 => Self::RateLimited,
            500..=599 => Self::ServerError,
            _ => Self::TransportError,
        }
    }

    /// Short, stable label used in Sentry tags + event extras.
    pub fn as_tag(self) -> &'static str {
        match self {
            Self::AuthError => "auth_error",
            Self::BadInput => "bad_input",
            Self::Quota => "quota",
            Self::RateLimited => "rate_limited",
            Self::ServerError => "server_error",
            Self::TransportError => "transport_error",
        }
    }

    /// True for classes that should NOT page on-call. The Sentry
    /// `before_send` hook drops these silently to keep the issue list
    /// useful — they still appear as breadcrumbs inside the next real
    /// event so context isn't lost.
    pub fn is_quota_class(self) -> bool {
        matches!(self, Self::Quota | Self::RateLimited)
    }
}

/// Split a proxy tool reference into `(provider, operation_id)`.
///
/// Three input shapes are common in the wild:
///   - `"finnhub:price_target"` — explicit `provider:op` (recent OpenAPI tools).
///   - `"pdl_person_enrichment"` — flat, no separator, prefixed with
///     provider name (PDL, datalastic, several others).
///   - `"web_search"` — flat, no separator, no prefix (`parallel` MCP-ish).
///
/// We always know the resolved `provider_name` at the call site because
/// the registry told us. Use that as the source of truth, then derive
/// the operation by stripping a `{provider}:` or `{provider}_` prefix
/// when present. Never fabricate "unknown" — if we can't split cleanly,
/// the operation tag IS the tool_name verbatim (still useful for grouping
/// and search). The old "unknown" sentinel made every flat-named tool
/// land in one mega-bucket.
pub fn provider_and_op(provider_name: &str, tool_name: &str) -> (String, String) {
    // Explicit `provider:op` wins regardless of provider_name (handles the
    // colon-namespaced OpenAPI naming).
    if let Some((p, op)) = tool_name.split_once(crate::core::manifest::TOOL_SEP) {
        if !p.is_empty() && !op.is_empty() {
            return (p.to_string(), op.to_string());
        }
    }
    // Flat name — try to strip the provider as a colon-or-underscore prefix.
    // Underscore is the convention PDL uses (`pdl_person_enrichment` →
    // operation = `person_enrichment`).
    if let Some(rest) = tool_name
        .strip_prefix(&format!("{provider_name}:"))
        .or_else(|| tool_name.strip_prefix(&format!("{provider_name}_")))
    {
        if !rest.is_empty() {
            return (provider_name.to_string(), rest.to_string());
        }
    }
    // No prefix — the tool_name IS the operation under this provider.
    (provider_name.to_string(), tool_name.to_string())
}

/// Back-compat shim for call sites that still don't know the resolved
/// provider name. New code should call `provider_and_op` directly.
///
/// Falls back to the old colon-only split for `provider:op` style names.
/// For flat tool names with no separator, returns the tool name as the
/// operation (NOT "unknown" — never lie about what failed) and an empty
/// provider, which the caller is expected to overwrite.
pub fn split_tool_name(tool_name: &str) -> (String, String) {
    if let Some((p, op)) = tool_name.split_once(crate::core::manifest::TOOL_SEP) {
        if !p.is_empty() && !op.is_empty() {
            return (p.to_string(), op.to_string());
        }
    }
    (String::new(), tool_name.to_string())
}

/// Scrub obvious PII patterns (UUIDs, emails, IPv4s, long hex tokens) from a
/// user-facing message and truncate to `max_len` chars. Keeps the short form
/// safe to send to Sentry as a tag-adjacent extra.
pub fn scrub_and_truncate(s: &str, max_len: usize) -> String {
    let scrubbed = scrub(s);
    if scrubbed.chars().count() <= max_len {
        scrubbed
    } else {
        let mut out: String = scrubbed.chars().take(max_len.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn scrub(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        // All matchers below only match ASCII bytes (UUID/email/IPv4/hex all
        // have an ASCII-only charset), so a match attempt at byte index `i` is
        // safe even if `i` is the start of a multi-byte UTF-8 char — the first
        // byte of any multi-byte sequence is `>= 0x80` and none of the matchers
        // accept it, so they bail cleanly.
        if let Some(end) = match_uuid(bytes, i) {
            out.push_str("***");
            i = end;
        } else if let Some(end) = match_email(bytes, i) {
            out.push_str("***");
            i = end;
        } else if let Some(end) = match_ipv4(bytes, i) {
            out.push_str("***");
            i = end;
        } else if let Some(end) = match_long_hex(bytes, i) {
            out.push_str("***");
            i = end;
        } else {
            // Decode one UTF-8 char at `i` and advance by its byte length,
            // preserving multi-byte chars correctly.
            let ch_len = utf8_char_len(bytes[i]);
            let end = (i + ch_len).min(bytes.len());
            // SAFETY: the caller passes a &str, so bytes[i..end] is a valid
            // UTF-8 slice starting at a char boundary.
            out.push_str(std::str::from_utf8(&bytes[i..end]).unwrap_or(""));
            i = end;
        }
    }
    out
}

/// Length in bytes of the UTF-8 char starting with `lead`. Returns 1 for
/// ASCII, orphaned continuation bytes, or unknown lead bytes so the scrubber
/// always makes forward progress without panicking.
fn utf8_char_len(lead: u8) -> usize {
    match lead {
        0..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xFF => 4,
        _ => 1, // 0x80..=0xBF: orphan continuation byte
    }
}

fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// Match `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`.
fn match_uuid(b: &[u8], start: usize) -> Option<usize> {
    let spans = [8usize, 4, 4, 4, 12];
    let mut i = start;
    for (idx, span) in spans.iter().enumerate() {
        if i + span > b.len() {
            return None;
        }
        for k in 0..*span {
            if !is_hex(b[i + k]) {
                return None;
            }
        }
        i += span;
        if idx < spans.len() - 1 {
            if i >= b.len() || b[i] != b'-' {
                return None;
            }
            i += 1;
        }
    }
    Some(i)
}

/// Match a hex token of at least 24 chars (API keys, token IDs). Requires
/// the run to contain at least one digit and at least one letter to avoid
/// scrubbing long runs of a single char or plain English words.
fn match_long_hex(b: &[u8], start: usize) -> Option<usize> {
    // Tokens should be bounded by non-hex (word boundary-ish) on the left.
    if start > 0 && is_hex(b[start - 1]) {
        return None;
    }
    let mut i = start;
    let mut has_digit = false;
    let mut has_alpha = false;
    while i < b.len() && is_hex(b[i]) {
        if b[i].is_ascii_digit() {
            has_digit = true;
        } else {
            has_alpha = true;
        }
        i += 1;
    }
    if i - start >= 24 && has_digit && has_alpha {
        Some(i)
    } else {
        None
    }
}

fn match_email(b: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    let local_start = i;
    while i < b.len() && is_email_local(b[i]) {
        i += 1;
    }
    if i == local_start || i >= b.len() || b[i] != b'@' {
        return None;
    }
    i += 1; // skip @
    let domain_start = i;
    while i < b.len() && is_email_domain(b[i]) {
        i += 1;
    }
    if i == domain_start {
        return None;
    }
    // Require at least one dot in the domain.
    if !b[domain_start..i].contains(&b'.') {
        return None;
    }
    Some(i)
}

fn is_email_local(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+')
}

fn is_email_domain(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
}

fn match_ipv4(b: &[u8], start: usize) -> Option<usize> {
    // Don't match inside a longer dotted-numeric run (e.g. "library 1.2.3.4"
    // in a version string — left boundary should not be a digit or a dot).
    if start > 0 && (b[start - 1].is_ascii_digit() || b[start - 1] == b'.') {
        return None;
    }
    let mut i = start;
    for octet in 0..4 {
        let octet_start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
            if i - octet_start > 3 {
                return None;
            }
        }
        if i == octet_start {
            return None;
        }
        // Validate octet value ≤ 255 to reject "999.999.999.999".
        let octet_str = std::str::from_utf8(&b[octet_start..i]).unwrap_or("");
        let octet_val: u16 = octet_str.parse().unwrap_or(u16::MAX);
        if octet_val > 255 {
            return None;
        }
        if octet < 3 {
            if i >= b.len() || b[i] != b'.' {
                return None;
            }
            i += 1;
        }
    }
    // Don't match if followed by another digit or dot (continuation of longer run).
    if i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
        return None;
    }
    Some(i)
}

/// Best-effort parse of common upstream error JSON shapes:
///   `{"error": {"type": "X", "message": "Y"}}`   (PDL, Stripe, Anthropic)
///   `{"type": "X", "message": "Y"}`              (flat)
///   `{"error": "message string"}`                (xAI, finnhub flat)
///   `{"message": "Y"}`                           (generic)
///
/// Returns `(error_type, error_message)` where each is Some when extractable.
pub fn parse_upstream_error(body: &str) -> (Option<String>, Option<String>) {
    // Cheap early-out for non-JSON bodies (HTML error pages from load
    // balancers, plaintext "Bad Gateway", empty strings). Avoids allocating
    // for serde_json::from_str on every proxy error.
    let trimmed = body.trim_start();
    if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
        return (None, None);
    }
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return (None, None),
    };

    let (error_type, error_message) = match v {
        serde_json::Value::Object(ref map) => {
            let err_field = map.get("error");
            let error_type = err_field
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str())
                .map(str::to_string)
                .or_else(|| map.get("type").and_then(|t| t.as_str()).map(str::to_string))
                .or_else(|| {
                    map.get("error_type")
                        .and_then(|t| t.as_str())
                        .map(str::to_string)
                });

            let error_message = err_field
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .map(str::to_string)
                .or_else(|| {
                    // `error` is a string itself (xAI-style).
                    err_field.and_then(|e| e.as_str()).map(str::to_string)
                })
                .or_else(|| {
                    map.get("message")
                        .and_then(|m| m.as_str())
                        .map(str::to_string)
                });

            (error_type, error_message)
        }
        _ => (None, None),
    };

    (error_type, error_message)
}

/// True when a 404 body looks like a legit "no records" response the caller
/// should treat as an empty result, not an error.
///
/// Requires the message to match one of the known "No X (were )?found"
/// phrases. The `error.type == "not_found"` hint **narrows** rather than
/// short-circuits: a response with `type: not_found` and no recognizable
/// message is treated as a real error so we don't silently convert genuine
/// 404s (removed endpoints, mistyped routes) to empty results.
pub fn is_no_records_body(error_type: Option<&str>, error_message: Option<&str>) -> bool {
    let msg = match error_message {
        Some(m) => m.trim(),
        None => return false,
    };
    let lower = msg.to_ascii_lowercase();
    let lower = lower.trim_start_matches("no ");
    let keywords = [
        "records were found",
        "companies were found",
        "persons were found",
        "results were found",
        "matches were found",
        "records found",
        "companies found",
        "persons found",
        "results found",
        "matches found",
    ];
    let message_matches = keywords.iter().any(|k| lower.starts_with(k));
    if message_matches {
        return true;
    }
    // Accept `type: not_found` only when accompanied by a short, generic
    // "not found" message (no specific resource-name in the text). This keeps
    // PDL's `{type: not_found, message: "No records were found..."}` flowing
    // through (already matched above) while still catching providers that
    // send `{type: not_found, message: "not found"}` without being specific
    // about what was missing.
    if matches!(error_type, Some("not_found")) {
        return lower == "not found" || lower.is_empty();
    }
    false
}

/// Attach structured tags + class-based dynamic title to the current Sentry
/// scope and emit a tracing event at the appropriate level for the upstream
/// status class.
///
/// Buckets (event title literal):
///   - `auth_error`      → 401, 403, 407 (Error)
///   - `bad_input`       → 400, 404 (non-no-records), 422 (Error)
///   - `quota`           → 402 (Warning; dropped by `before_send`)
///   - `rate_limited`    → 429 (Warning; dropped by `before_send`)
///   - `server_error`    → 5xx (Error)
///   - `transport_error` → 0 / unknown (Error)
///
/// Each title is a distinct literal so `sentry-tracing` creates a separate
/// Sentry issue per class. The (provider, operation_id, status) live as
/// tags so each bucket stays per-provider searchable without splitting
/// into one bucket per provider.
///
/// When the `sentry` feature is off, emits the tracing event only.
pub fn report_upstream_error(
    provider: &str,
    operation_id: &str,
    upstream_status: u16,
    proxy_status: u16,
    error_type: Option<&str>,
    error_message: Option<&str>,
) {
    let msg_short = error_message
        .map(|m| scrub_and_truncate(m, 140))
        .unwrap_or_default();
    let class = UpstreamErrorClass::classify(upstream_status);

    // `sentry::with_scope` pushes a temporary scope for the duration of the
    // closure, then pops it — so tags never leak across requests running on
    // the same tokio worker thread. The tracing macros inside the closure
    // are picked up by `sentry_tracing::layer()` and emitted with these
    // tags attached. `class` becomes its own tag so operators can filter
    // a single bucket by error shape without grouping each subclass into
    // its own issue.
    with_upstream_scope(
        provider,
        operation_id,
        upstream_status,
        proxy_status,
        error_type,
        &msg_short,
        class,
        || {
            emit_classified(
                class,
                provider,
                operation_id,
                upstream_status,
                proxy_status,
                error_type,
                &msg_short,
            )
        },
    );
}

/// Each arm carries its own LITERAL `tracing::*!` message because the
/// `sentry-tracing` bridge maps the literal to the Sentry event title,
/// and Sentry groups events by title. Five literals → five distinct
/// Sentry issue buckets. All the variable detail lives in fields.
fn emit_classified(
    class: UpstreamErrorClass,
    provider: &str,
    operation_id: &str,
    upstream_status: u16,
    proxy_status: u16,
    error_type: Option<&str>,
    msg_short: &str,
) {
    let error_type = error_type.unwrap_or("");
    match class {
        UpstreamErrorClass::AuthError => tracing::error!(
            provider,
            operation_id,
            upstream_status,
            proxy_status,
            class = class.as_tag(),
            error_type,
            msg = %msg_short,
            "upstream auth_error"
        ),
        UpstreamErrorClass::BadInput => tracing::error!(
            provider,
            operation_id,
            upstream_status,
            proxy_status,
            class = class.as_tag(),
            error_type,
            msg = %msg_short,
            "upstream bad_input"
        ),
        UpstreamErrorClass::Quota => tracing::warn!(
            provider,
            operation_id,
            upstream_status,
            proxy_status,
            class = class.as_tag(),
            error_type,
            msg = %msg_short,
            "upstream quota"
        ),
        UpstreamErrorClass::RateLimited => tracing::warn!(
            provider,
            operation_id,
            upstream_status,
            proxy_status,
            class = class.as_tag(),
            error_type,
            msg = %msg_short,
            "upstream rate_limited"
        ),
        UpstreamErrorClass::ServerError => tracing::error!(
            provider,
            operation_id,
            upstream_status,
            proxy_status,
            class = class.as_tag(),
            error_type,
            msg = %msg_short,
            "upstream server_error"
        ),
        UpstreamErrorClass::TransportError => tracing::error!(
            provider,
            operation_id,
            upstream_status,
            proxy_status,
            class = class.as_tag(),
            error_type,
            msg = %msg_short,
            "upstream transport_error"
        ),
    }
}

/// Attach the structured Rust error (with its full `source()` chain) to
/// the current Sentry scope and capture it as an exception event. This
/// is what gives the issue page a real "Exception" block with the
/// reqwest / `HttpError` / `McpError` source chain — without this, all
/// Sentry sees is the tracing-bridge's flat title + tags.
///
/// Pair with `report_upstream_error`: that one creates the
/// titled/grouped issue, this one attaches the structured context.
/// When the `sentry` feature is off, this is a no-op.
#[allow(unused_variables)]
pub fn capture_error_with_scope(
    err: &(dyn std::error::Error + 'static),
    provider: &str,
    operation_id: &str,
    upstream_status: u16,
    proxy_status: u16,
    error_type: Option<&str>,
    error_message: Option<&str>,
) {
    #[cfg(feature = "sentry")]
    {
        let msg_short = error_message
            .map(|m| scrub_and_truncate(m, 140))
            .unwrap_or_default();
        let class = UpstreamErrorClass::classify(upstream_status);
        // Skip quota / rate-limit classes — they're already dropped by
        // before_send and we don't want to spend the quota encoding the
        // backtrace just to throw it away.
        if class.is_quota_class() {
            return;
        }
        with_upstream_scope(
            provider,
            operation_id,
            upstream_status,
            proxy_status,
            error_type,
            &msg_short,
            class,
            || {
                sentry::capture_error(err);
            },
        );
    }
}

/// Attach JWT identity (sub, sandbox_id, job_id, organization, audience)
/// to the current Sentry scope so every event raised during this request
/// is searchable by those facets. Set once at the start of `/call`,
/// `/mcp`, and `/help` handlers.
///
/// Sentry's `configure_scope` mutates the per-thread scope; subsequent
/// `with_scope` pushes layer on top without losing what we set here.
/// Cleared automatically when the tokio worker reaches the next request
/// because Sentry's scope is request-keyed by the `with_scope` blocks
/// the report helpers push.
#[allow(unused_variables)]
pub fn set_jwt_sentry_scope(claims: &TokenClaims) {
    #[cfg(feature = "sentry")]
    sentry::configure_scope(|scope| {
        scope.set_tag("sub", claims.sub.as_str());
        if let Some(ref id) = claims.sandbox_id {
            scope.set_tag("sandbox_id", id.as_str());
        }
        if let Some(ref id) = claims.job_id {
            scope.set_tag("job_id", id.as_str());
        }
        // Sentry's `user.id` is the standard slot for the auth subject —
        // populating it lets the issue page show "users affected" counts
        // and gives the search UI a first-class facet.
        scope.set_user(Some(sentry::User {
            id: Some(claims.sub.clone()),
            ..Default::default()
        }));
    });
}

// 8 parameters by design: each is a distinct Sentry tag value resolved
// at the call site. Bundling into a struct would just move the noise
// without removing it, and the helper is private. Same allow on the
// no-sentry stub below for signature parity.
#[cfg(feature = "sentry")]
#[allow(clippy::too_many_arguments)]
fn with_upstream_scope<F: FnOnce()>(
    provider: &str,
    operation_id: &str,
    upstream_status: u16,
    proxy_status: u16,
    error_type: Option<&str>,
    msg_short: &str,
    class: UpstreamErrorClass,
    body: F,
) {
    let upstream_s = upstream_status.to_string();
    let proxy_s = proxy_status.to_string();
    let class_tag = class.as_tag();
    sentry::with_scope(
        |scope| {
            scope.set_tag("provider", provider);
            scope.set_tag("operation_id", operation_id);
            scope.set_tag("upstream_status", &upstream_s);
            scope.set_tag("proxy_status", &proxy_s);
            scope.set_tag("upstream_error_class", class_tag);
            if let Some(t) = error_type {
                scope.set_tag("upstream_error_type", t);
            }
            if !msg_short.is_empty() {
                scope.set_extra(
                    "upstream_error_message",
                    serde_json::Value::String(msg_short.to_string()),
                );
            }
            // Fingerprint keys on the error CLASS, not the upstream status,
            // so a provider that returns 502 vs 504 doesn't fork into two
            // buckets. Combined with the per-class literal title, this
            // gives one issue per (provider, operation, class) — fine-
            // grained enough to alert on a specific tool going bad but
            // not so fine that every transient blip is a new issue.
            scope.set_fingerprint(Some(
                [
                    "ati.proxy.upstream_error",
                    provider,
                    operation_id,
                    class_tag,
                ]
                .as_slice(),
            ));
        },
        body,
    );
}

#[cfg(not(feature = "sentry"))]
#[allow(clippy::too_many_arguments)]
fn with_upstream_scope<F: FnOnce()>(
    _provider: &str,
    _operation_id: &str,
    _upstream_status: u16,
    _proxy_status: u16,
    _error_type: Option<&str>,
    _msg_short: &str,
    _class: UpstreamErrorClass,
    body: F,
) {
    body();
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- provider_and_op: the path call sites should actually use ---

    #[test]
    fn provider_and_op_explicit_colon() {
        assert_eq!(
            provider_and_op("finnhub", "finnhub:price_target"),
            ("finnhub".into(), "price_target".into())
        );
    }

    #[test]
    fn provider_and_op_strips_underscore_prefix() {
        // The bug from the user's screenshot: PDL ships flat tool names
        // like `pdl_person_enrichment`. The fix peels the provider as a
        // `{provider}_` prefix when present.
        assert_eq!(
            provider_and_op("pdl", "pdl_person_enrichment"),
            ("pdl".into(), "person_enrichment".into())
        );
    }

    #[test]
    fn provider_and_op_strips_colon_prefix() {
        assert_eq!(
            provider_and_op("github", "github:search_repositories"),
            ("github".into(), "search_repositories".into())
        );
    }

    #[test]
    fn provider_and_op_no_prefix_keeps_tool_name() {
        // No prefix to strip — operation is the tool name verbatim. This
        // is the correct behavior; the OLD code returned "unknown" here,
        // which clumped every prefixless-tool failure into one mega-
        // bucket and forced the on-call to read the body to find out
        // which tool failed.
        assert_eq!(
            provider_and_op("parallel", "web_search"),
            ("parallel".into(), "web_search".into())
        );
    }

    #[test]
    fn provider_and_op_empty_op_after_strip_keeps_tool_name() {
        // Edge case: `pdl_` — stripping leaves an empty operation, so we
        // keep the tool_name as-is to avoid generating empty tags.
        assert_eq!(
            provider_and_op("pdl", "pdl_"),
            ("pdl".into(), "pdl_".into())
        );
    }

    // --- split_tool_name back-compat shim (no longer fabricates "unknown") ---

    #[test]
    fn split_tool_name_colon_form() {
        assert_eq!(
            split_tool_name("finnhub:price_target"),
            ("finnhub".into(), "price_target".into())
        );
    }

    #[test]
    fn split_tool_name_flat_returns_tool_name_as_op() {
        // The OLD behavior was `("bare_tool", "unknown")` — that lied
        // about what operation failed. New behavior keeps the tool name
        // as the op; the caller is expected to overwrite the empty
        // provider with the registry-resolved name.
        assert_eq!(
            split_tool_name("bare_tool"),
            ("".into(), "bare_tool".into())
        );
    }

    // --- UpstreamErrorClass: classification ---

    #[test]
    fn classify_400_is_bad_input() {
        assert_eq!(
            UpstreamErrorClass::classify(400),
            UpstreamErrorClass::BadInput
        );
        assert_eq!(
            UpstreamErrorClass::classify(404),
            UpstreamErrorClass::BadInput
        );
        assert_eq!(
            UpstreamErrorClass::classify(422),
            UpstreamErrorClass::BadInput
        );
    }

    #[test]
    fn classify_401_is_auth_error() {
        assert_eq!(
            UpstreamErrorClass::classify(401),
            UpstreamErrorClass::AuthError
        );
        assert_eq!(
            UpstreamErrorClass::classify(403),
            UpstreamErrorClass::AuthError
        );
        assert_eq!(
            UpstreamErrorClass::classify(407),
            UpstreamErrorClass::AuthError
        );
    }

    #[test]
    fn classify_402_is_quota() {
        assert_eq!(UpstreamErrorClass::classify(402), UpstreamErrorClass::Quota);
        assert!(UpstreamErrorClass::Quota.is_quota_class());
    }

    #[test]
    fn classify_429_is_rate_limited() {
        assert_eq!(
            UpstreamErrorClass::classify(429),
            UpstreamErrorClass::RateLimited
        );
        assert!(UpstreamErrorClass::RateLimited.is_quota_class());
    }

    #[test]
    fn classify_5xx_is_server_error() {
        assert_eq!(
            UpstreamErrorClass::classify(500),
            UpstreamErrorClass::ServerError
        );
        assert_eq!(
            UpstreamErrorClass::classify(503),
            UpstreamErrorClass::ServerError
        );
        assert_eq!(
            UpstreamErrorClass::classify(599),
            UpstreamErrorClass::ServerError
        );
        assert!(!UpstreamErrorClass::ServerError.is_quota_class());
    }

    #[test]
    fn classify_zero_is_transport_error() {
        // The proxy passes `upstream_status = 0` for MCP/CLI/transport
        // failures with no HTTP exchange. Those need their own bucket.
        assert_eq!(
            UpstreamErrorClass::classify(0),
            UpstreamErrorClass::TransportError
        );
    }

    #[test]
    fn class_tags_are_stable_strings() {
        assert_eq!(UpstreamErrorClass::AuthError.as_tag(), "auth_error");
        assert_eq!(UpstreamErrorClass::BadInput.as_tag(), "bad_input");
        assert_eq!(UpstreamErrorClass::Quota.as_tag(), "quota");
        assert_eq!(UpstreamErrorClass::RateLimited.as_tag(), "rate_limited");
        assert_eq!(UpstreamErrorClass::ServerError.as_tag(), "server_error");
        assert_eq!(
            UpstreamErrorClass::TransportError.as_tag(),
            "transport_error"
        );
    }

    #[test]
    fn parse_nested_pdl_body() {
        let body = r#"{"status":404,"error":{"type":"not_found","message":"No records were found matching your request"}}"#;
        let (t, m) = parse_upstream_error(body);
        assert_eq!(t.as_deref(), Some("not_found"));
        assert_eq!(
            m.as_deref(),
            Some("No records were found matching your request")
        );
    }

    #[test]
    fn parse_flat_xai_style_body() {
        let body = r#"{"error":"Insufficient credits","message":"Your current balance is $0.01"}"#;
        let (t, m) = parse_upstream_error(body);
        assert!(t.is_none());
        assert_eq!(m.as_deref(), Some("Insufficient credits"));
    }

    #[test]
    fn parse_non_json_body() {
        let (t, m) = parse_upstream_error("not json at all");
        assert!(t.is_none());
        assert!(m.is_none());
    }

    #[test]
    fn no_records_type_alone_does_not_match() {
        // `type: not_found` without a message is ambiguous — could be a
        // genuine missing-resource 404 (removed endpoint, mistyped route).
        // Don't silently convert it to an empty result.
        assert!(!is_no_records_body(Some("not_found"), None));
        assert!(!is_no_records_body(
            Some("not_found"),
            Some("User account 42 was deleted")
        ));
    }

    #[test]
    fn no_records_type_with_generic_not_found_message_matches() {
        // `type: not_found` + generic message → treat as empty result.
        assert!(is_no_records_body(Some("not_found"), Some("not found")));
        assert!(is_no_records_body(Some("not_found"), Some("")));
    }

    #[test]
    fn no_records_message_matches() {
        assert!(is_no_records_body(
            None,
            Some("No records were found matching your request")
        ));
        assert!(is_no_records_body(
            None,
            Some("No companies were found matching your request")
        ));
        assert!(is_no_records_body(None, Some("no results found")));
    }

    #[test]
    fn no_records_rejects_real_errors() {
        assert!(!is_no_records_body(Some("invalid_request"), None));
        assert!(!is_no_records_body(None, Some("Insufficient credits")));
        assert!(!is_no_records_body(None, Some("Forbidden")));
        assert!(!is_no_records_body(None, None));
    }

    #[test]
    fn scrub_uuid() {
        let s = "request id 550e8400-e29b-41d4-a716-446655440000 failed";
        assert_eq!(scrub(s), "request id *** failed");
    }

    #[test]
    fn scrub_email() {
        assert_eq!(scrub("contact miguel@parcha.ai now"), "contact *** now");
    }

    #[test]
    fn scrub_ipv4() {
        assert_eq!(scrub("from 192.168.1.1 blocked"), "from *** blocked");
    }

    #[test]
    fn scrub_ipv4_rejects_version_strings() {
        // Version strings with more than 4 groups or trailing digits should
        // not be scrubbed — left/right boundary guards prevent false-positives.
        assert_eq!(
            scrub("library 1.2.3.4.5 raised an error"),
            "library 1.2.3.4.5 raised an error"
        );
        assert_eq!(scrub("version 10.11.12.13.0"), "version 10.11.12.13.0");
    }

    #[test]
    fn scrub_ipv4_rejects_out_of_range_octets() {
        // 999.999.999.999 isn't a valid IPv4 address.
        assert_eq!(
            scrub("bogus 999.999.999.999 ip"),
            "bogus 999.999.999.999 ip"
        );
    }

    #[test]
    fn scrub_long_hex_token() {
        // 40-char hex (GitHub token length)
        let tok = "abcdef0123456789abcdef0123456789abcdef01";
        assert_eq!(scrub(&format!("token {tok} bad")), "token *** bad");
    }

    #[test]
    fn scrub_preserves_short_hex() {
        // Don't scrub short hex sequences (e.g. "abc123" is not a token).
        assert_eq!(scrub("hex abc123 fine"), "hex abc123 fine");
    }

    #[test]
    fn scrub_preserves_multibyte_utf8() {
        // Regression: byte-as-char casting corrupted non-ASCII.
        assert_eq!(scrub("café résumé 日本語"), "café résumé 日本語");
    }

    #[test]
    fn scrub_mixed_utf8_and_secrets() {
        let input = "café contact miguel@parcha.ai résumé";
        assert_eq!(scrub(input), "café contact *** résumé");
    }

    #[test]
    fn parse_non_json_html_body_early_outs() {
        // Load-balancer HTML error pages are common on 502/503. Should not
        // attempt JSON parsing at all.
        let (t, m) = parse_upstream_error("<html><body>502 Bad Gateway</body></html>");
        assert!(t.is_none());
        assert!(m.is_none());
    }

    #[test]
    fn parse_empty_body_returns_none() {
        let (t, m) = parse_upstream_error("");
        assert!(t.is_none());
        assert!(m.is_none());
    }

    #[test]
    fn truncate_long_message() {
        let s = "a".repeat(500);
        let out = scrub_and_truncate(&s, 20);
        assert_eq!(out.chars().count(), 20);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn truncate_short_message_untouched() {
        assert_eq!(scrub_and_truncate("short", 100), "short");
    }
}
