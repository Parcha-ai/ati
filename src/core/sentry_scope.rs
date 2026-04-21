//! Sentry scope helpers for proxy-side upstream error classification.
//!
//! Adds structured tags and a per-{provider, operation_id, upstream_status}
//! fingerprint so each root-cause bucket becomes a distinct Sentry issue
//! instead of one "ati command failed" mega-bucket. Also routes log level
//! by status class (info/warn/error).
//!
//! See issue #81 for context.

/// Split a proxy tool_name (`"provider:operation_id"`) into its parts.
/// Tool names missing a separator are treated as having an unknown operation.
pub fn split_tool_name(tool_name: &str) -> (String, String) {
    match tool_name.split_once(crate::core::manifest::TOOL_SEP) {
        Some((p, op)) if !p.is_empty() && !op.is_empty() => (p.to_string(), op.to_string()),
        _ => (tool_name.to_string(), "unknown".to_string()),
    }
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
        if octet < 3 {
            if i >= b.len() || b[i] != b'.' {
                return None;
            }
            i += 1;
        }
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
/// should treat as an empty result, not an error. Matches:
///   - `error.type == "not_found"`
///   - message starting with /^No (records|companies|persons|results|matches) (were )?found/
pub fn is_no_records_body(error_type: Option<&str>, error_message: Option<&str>) -> bool {
    if matches!(error_type, Some("not_found")) {
        return true;
    }
    let msg = match error_message {
        Some(m) => m.trim(),
        None => return false,
    };
    let lower = msg.to_ascii_lowercase();
    let lower = lower.trim_start_matches("no ");
    // After stripping "no ", check for a keyword + "found" / "were found".
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
    keywords.iter().any(|k| lower.starts_with(k))
}

/// Attach structured tags + fingerprint to the current Sentry scope and emit a
/// tracing event at the appropriate level for the given upstream status class.
///
/// Levels:
///   402 / 403 / 422 → warn (expected client-side upstream error, Sentry event
///                            at warning level for filtering, does not page)
///   all others      → error (includes 5xx, network failures, unknown)
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

    // `sentry::with_scope` pushes a temporary scope for the duration of the
    // closure, then pops it — so tags never leak across requests running on
    // the same tokio worker thread. The tracing macros inside the closure
    // are picked up by `sentry_tracing::layer()` and emitted with these tags
    // attached.
    with_upstream_scope(
        provider,
        operation_id,
        upstream_status,
        proxy_status,
        error_type,
        &msg_short,
        || match upstream_status {
            402 | 403 | 422 => {
                tracing::warn!(
                    provider,
                    operation_id,
                    upstream_status,
                    proxy_status,
                    error_type = error_type.unwrap_or(""),
                    msg = %msg_short,
                    "upstream client error"
                );
                // sentry-tracing maps warn → breadcrumb by default. We want an
                // actual event for warn-tier upstream errors so operators can
                // search by tag — capture explicitly at Warning level.
                #[cfg(feature = "sentry")]
                sentry::capture_message(
                    &format!("upstream client error ({upstream_status}) {provider}:{operation_id}"),
                    sentry::Level::Warning,
                );
            }
            _ => tracing::error!(
                provider,
                operation_id,
                upstream_status,
                proxy_status,
                error_type = error_type.unwrap_or(""),
                msg = %msg_short,
                "upstream server error"
            ),
        },
    );
}

#[cfg(feature = "sentry")]
fn with_upstream_scope<F: FnOnce()>(
    provider: &str,
    operation_id: &str,
    upstream_status: u16,
    proxy_status: u16,
    error_type: Option<&str>,
    msg_short: &str,
    body: F,
) {
    let upstream_s = upstream_status.to_string();
    let proxy_s = proxy_status.to_string();
    sentry::with_scope(
        |scope| {
            scope.set_tag("provider", provider);
            scope.set_tag("operation_id", operation_id);
            scope.set_tag("upstream_status", &upstream_s);
            scope.set_tag("proxy_status", &proxy_s);
            if let Some(t) = error_type {
                scope.set_tag("upstream_error_type", t);
            }
            if !msg_short.is_empty() {
                scope.set_extra(
                    "upstream_error_message",
                    serde_json::Value::String(msg_short.to_string()),
                );
            }
            scope.set_fingerprint(Some(
                [
                    "ati.proxy.upstream_error",
                    provider,
                    operation_id,
                    &upstream_s,
                ]
                .as_slice(),
            ));
        },
        body,
    );
}

#[cfg(not(feature = "sentry"))]
fn with_upstream_scope<F: FnOnce()>(
    _provider: &str,
    _operation_id: &str,
    _upstream_status: u16,
    _proxy_status: u16,
    _error_type: Option<&str>,
    _msg_short: &str,
    body: F,
) {
    body();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_tool_name_ok() {
        assert_eq!(
            split_tool_name("finnhub:price_target"),
            ("finnhub".into(), "price_target".into())
        );
    }

    #[test]
    fn split_tool_name_missing_op() {
        assert_eq!(
            split_tool_name("bare_tool"),
            ("bare_tool".into(), "unknown".into())
        );
    }

    #[test]
    fn split_tool_name_empty_op() {
        assert_eq!(
            split_tool_name("provider:"),
            ("provider:".into(), "unknown".into())
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
    fn no_records_type_matches() {
        assert!(is_no_records_body(Some("not_found"), None));
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
