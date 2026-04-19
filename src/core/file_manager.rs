//! File manager — `file_manager:download` / `file_manager:upload` virtual
//! tools. Registered automatically with no TOML manifest so sandboxed agents
//! can move binary bytes through the proxy (network egress is otherwise
//! confined to the proxy host).
//!
//! In proxy mode the proxy performs the fetch/upload; bytes travel over the
//! `/call` JSON wire as base64. The sandbox-side CLI materializes them to
//! disk (`--out`) or ships them (`--path`). Local mode does the work inline.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::time::Duration;
use thiserror::Error;

/// Default ceiling on download/upload size (500 MB).
pub const DEFAULT_MAX_BYTES: u64 = 500 * 1024 * 1024;
/// Default timeout for the upstream HTTP fetch.
pub const DEFAULT_TIMEOUT_SECS: u64 = 120;
/// Hard ceiling on upload payload accepted by the proxy (1 GB).
pub const MAX_UPLOAD_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Error, Debug)]
pub enum FileManagerError {
    #[error("Missing required argument: {0}")]
    MissingArg(&'static str),
    #[error("Invalid argument '{name}': {reason}")]
    InvalidArg { name: &'static str, reason: String },
    #[error("URL is not allowed (private/internal address): {0}")]
    PrivateUrl(String),
    #[error("Host '{host}' is not in the download allowlist")]
    HostNotAllowed { host: String },
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
    #[error("HTTP error fetching '{url}': {source}")]
    Http {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("Upstream returned status {status} for '{url}': {body}")]
    Upstream {
        url: String,
        status: u16,
        body: String,
    },
    #[error("Response exceeds max-bytes ({limit} bytes)")]
    SizeCap { limit: u64 },
    #[error("Invalid extra header '{name}': {reason}")]
    BadHeader { name: String, reason: String },
    #[error("Failed to read file '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Upload destinations not configured on the proxy — operator must declare `[provider.upload_destinations.<name>]` in `manifests/file_manager.toml`")]
    UploadNotConfigured,
    #[error("Unknown upload destination '{0}' — not in the operator's allowlist")]
    UnknownDestination(String),
    #[error("Upload failed: {0}")]
    Upload(String),
    #[error("Invalid base64 in upload payload: {0}")]
    Base64(#[from] base64::DecodeError),
}

impl FileManagerError {
    /// HTTP status this variant should map to when surfaced over the proxy
    /// `POST /call` endpoint. Kept here (rather than in `proxy/server.rs`)
    /// so adding a new error variant doesn't silently default to 500 in one
    /// handler and 400 in another.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::MissingArg(_)
            | Self::InvalidArg { .. }
            | Self::BadHeader { .. }
            | Self::Base64(_) => 400,
            Self::PrivateUrl(_) | Self::HostNotAllowed { .. } | Self::UnknownDestination(_) => 403,
            Self::SizeCap { .. } => 413,
            Self::UploadNotConfigured => 503,
            Self::Upstream { status, .. } => (*status).clamp(400, 599),
            Self::Http { .. } | Self::InvalidUrl(_) | Self::Upload(_) => 502,
            Self::Io { .. } => 500,
        }
    }
}

/// Headers an agent must not be able to set on outbound downloads.
const DENIED_DOWNLOAD_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-authorization",
];

/// Validate caller-supplied headers against the deny-list.
fn validate_extra_headers(headers: &HashMap<String, String>) -> Result<(), FileManagerError> {
    for name in headers.keys() {
        let lower = name.to_lowercase();
        if DENIED_DOWNLOAD_HEADERS.contains(&lower.as_str()) {
            return Err(FileManagerError::BadHeader {
                name: name.clone(),
                reason: "header is not allowed".into(),
            });
        }
        if !name.bytes().all(|b| b.is_ascii() && b > 32 && b != b':') {
            return Err(FileManagerError::BadHeader {
                name: name.clone(),
                reason: "header name contains invalid characters".into(),
            });
        }
    }
    Ok(())
}

/// Parsed download arguments.
#[derive(Debug, Clone)]
pub struct DownloadArgs {
    pub url: String,
    pub max_bytes: u64,
    pub timeout: Duration,
    pub follow_redirects: bool,
    pub headers: HashMap<String, String>,
}

impl DownloadArgs {
    pub fn from_value(args: &HashMap<String, Value>) -> Result<Self, FileManagerError> {
        let url = args
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or(FileManagerError::MissingArg("url"))?
            .trim()
            .to_string();
        if url.is_empty() {
            return Err(FileManagerError::MissingArg("url"));
        }

        let max_bytes = parse_u64_arg(args, &["max_bytes", "max-bytes"], "max_bytes")?
            .unwrap_or(DEFAULT_MAX_BYTES);
        if max_bytes == 0 {
            return Err(FileManagerError::InvalidArg {
                name: "max_bytes",
                reason: "must be > 0".into(),
            });
        }

        let timeout_secs =
            parse_u64_arg(args, &["timeout"], "timeout")?.unwrap_or(DEFAULT_TIMEOUT_SECS);

        let follow_redirects = args
            .get("follow_redirects")
            .or_else(|| args.get("follow-redirects"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let headers = parse_headers(args.get("headers"))?;
        validate_extra_headers(&headers)?;

        Ok(DownloadArgs {
            url,
            max_bytes,
            timeout: Duration::from_secs(timeout_secs),
            follow_redirects,
            headers,
        })
    }
}

/// Look up an optional u64 arg under any of several aliases (to handle both
/// `max_bytes` and `max-bytes` from CLI arg normalization). Accepts JSON
/// numbers or numeric strings.
fn parse_u64_arg(
    args: &HashMap<String, Value>,
    aliases: &[&str],
    field: &'static str,
) -> Result<Option<u64>, FileManagerError> {
    let raw = aliases.iter().find_map(|k| args.get(*k));
    let Some(v) = raw else {
        return Ok(None);
    };
    let err = || FileManagerError::InvalidArg {
        name: field,
        reason: "must be a positive integer".into(),
    };
    match v {
        Value::Number(n) => n.as_u64().map(Some).ok_or_else(err),
        Value::String(s) => s
            .parse::<u64>()
            .map(Some)
            .map_err(|e| FileManagerError::InvalidArg {
                name: field,
                reason: e.to_string(),
            }),
        _ => Err(err()),
    }
}

/// Parse a `headers` argument that may be a JSON object or a JSON-encoded string.
fn parse_headers(value: Option<&Value>) -> Result<HashMap<String, String>, FileManagerError> {
    let value = match value {
        Some(v) => v,
        None => return Ok(HashMap::new()),
    };
    let map = match value {
        Value::Object(map) => map.clone(),
        Value::String(s) if s.trim().is_empty() => return Ok(HashMap::new()),
        Value::String(s) => match serde_json::from_str::<Value>(s) {
            Ok(Value::Object(map)) => map,
            Ok(_) => {
                return Err(FileManagerError::InvalidArg {
                    name: "headers",
                    reason: "must be a JSON object".into(),
                });
            }
            Err(e) => {
                return Err(FileManagerError::InvalidArg {
                    name: "headers",
                    reason: format!("invalid JSON: {e}"),
                });
            }
        },
        Value::Null => return Ok(HashMap::new()),
        _ => {
            return Err(FileManagerError::InvalidArg {
                name: "headers",
                reason: "must be a JSON object or JSON string".into(),
            });
        }
    };
    let mut out = HashMap::with_capacity(map.len());
    for (k, v) in map {
        let s = match v {
            Value::String(s) => s,
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            _ => {
                return Err(FileManagerError::InvalidArg {
                    name: "headers",
                    reason: format!("value for '{k}' must be a string, number, or bool"),
                });
            }
        };
        out.insert(k, s);
    }
    Ok(out)
}

/// Result of a successful download — the bytes plus discovered metadata.
/// Intentionally NOT `Clone` — `bytes` can be up to `DEFAULT_MAX_BYTES`.
#[derive(Debug)]
pub struct DownloadResult {
    pub bytes: Vec<u8>,
    pub content_type: Option<String>,
    pub source_url: String,
}

/// Read the `ATI_DOWNLOAD_ALLOWLIST` env var. Returns `None` if unset or empty
/// (meaning "no allowlist configured"); returns `Some(patterns)` otherwise.
///
/// Patterns are comma-separated and case-insensitive. Each pattern is one of:
/// - exact host: `v3b.fal.media`
/// - subdomain wildcard: `*.fal.media` matches `v3b.fal.media`, `cdn.fal.media`, etc.
/// - bare wildcard: `*` matches anything (NOT recommended — defeats the purpose)
fn allowlist_patterns() -> Option<Vec<String>> {
    let raw = std::env::var("ATI_DOWNLOAD_ALLOWLIST").ok()?;
    let patterns: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if patterns.is_empty() {
        None
    } else {
        Some(patterns)
    }
}

/// Returns true if `host` matches any of the configured allowlist patterns.
fn host_matches_pattern(host: &str, pattern: &str) -> bool {
    let host = host.to_lowercase();
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    host == pattern
}

/// Reject the URL if `ATI_DOWNLOAD_ALLOWLIST` is set and the host doesn't match.
/// When the env var is unset or empty, downloads to any (non-private) host are
/// allowed — local-mode operators who want a wide-open dev experience can leave
/// the allowlist off; production proxies should always set it.
pub fn enforce_download_allowlist(url: &str) -> Result<(), FileManagerError> {
    let patterns = match allowlist_patterns() {
        Some(p) => p,
        None => return Ok(()),
    };
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| FileManagerError::InvalidUrl(format!("could not parse URL: {e}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| FileManagerError::InvalidUrl("URL has no host component".into()))?;

    if patterns.iter().any(|p| host_matches_pattern(host, p)) {
        Ok(())
    } else {
        Err(FileManagerError::HostNotAllowed {
            host: host.to_string(),
        })
    }
}

/// Perform the actual HTTP fetch. Streams the body and aborts if it exceeds `max_bytes`.
///
/// Applies SSRF protection per `crate::core::http::validate_url_not_private`,
/// then enforces the download host allowlist (env `ATI_DOWNLOAD_ALLOWLIST`).
pub async fn fetch_bytes(args: &DownloadArgs) -> Result<DownloadResult, FileManagerError> {
    crate::core::http::validate_url_not_private(&args.url).map_err(|e| match e {
        crate::core::http::HttpError::SsrfBlocked(url) => FileManagerError::PrivateUrl(url),
        other => FileManagerError::InvalidUrl(other.to_string()),
    })?;

    enforce_download_allowlist(&args.url)?;

    let redirect_policy = if args.follow_redirects {
        reqwest::redirect::Policy::limited(10)
    } else {
        reqwest::redirect::Policy::none()
    };

    let client = reqwest::Client::builder()
        .timeout(args.timeout)
        .redirect(redirect_policy)
        .build()
        .map_err(|e| FileManagerError::Http {
            url: args.url.clone(),
            source: e,
        })?;

    let mut req = client.get(&args.url);
    for (k, v) in &args.headers {
        req = req.header(k.as_str(), v.as_str());
    }

    let response = req.send().await.map_err(|e| FileManagerError::Http {
        url: args.url.clone(),
        source: e,
    })?;
    let status = response.status();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        let truncated = if body.len() > 512 {
            &body[..512]
        } else {
            &body
        };
        return Err(FileManagerError::Upstream {
            url: args.url.clone(),
            status: status.as_u16(),
            body: truncated.to_string(),
        });
    }

    // Pre-flight against Content-Length when present, and use it to seed the
    // accumulator's capacity so we avoid ~log2(N) regrow memcpy cycles for
    // large downloads.
    let content_length = response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    if let Some(len) = content_length {
        if len > args.max_bytes {
            return Err(FileManagerError::SizeCap {
                limit: args.max_bytes,
            });
        }
    }

    // Stream the body so we can abort early on oversize. Cap the preallocation
    // at `max_bytes` so a spoofed Content-Length can't force a huge allocation.
    use futures::StreamExt;
    let initial_cap = content_length
        .map(|l| l.min(args.max_bytes) as usize)
        .unwrap_or(64 * 1024);
    let mut bytes = Vec::with_capacity(initial_cap);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| FileManagerError::Http {
            url: args.url.clone(),
            source: e,
        })?;
        if (bytes.len() as u64).saturating_add(chunk.len() as u64) > args.max_bytes {
            return Err(FileManagerError::SizeCap {
                limit: args.max_bytes,
            });
        }
        bytes.extend_from_slice(&chunk);
    }

    Ok(DownloadResult {
        bytes,
        content_type,
        source_url: args.url.clone(),
    })
}

/// Build the JSON response payload that the proxy / local-mode core returns
/// to the CLI. Always carries `content_base64` so the CLI can write to `--out`
/// or print inline depending on caller intent.
pub fn build_download_response(result: &DownloadResult) -> Value {
    json!({
        "success": true,
        "size_bytes": result.bytes.len(),
        "content_type": result.content_type,
        "source_url": result.source_url,
        "content_base64": B64.encode(&result.bytes),
    })
}

/// Best-effort MIME type from a path's extension. Shared across
/// `file_manager:*` tools and CLI output capture. Falls back to octet-stream.
pub fn guess_content_type(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("");
    match ext {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "mp4" | "m4v" => "video/mp4",
        "mov" => "video/quicktime",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" | "oga" => "audio/ogg",
        "flac" => "audio/flac",
        "m4a" => "audio/mp4",
        "csv" => "text/csv",
        "json" => "application/json",
        "xml" => "application/xml",
        "zip" => "application/zip",
        "html" | "htm" => "text/html",
        "md" => "text/markdown",
        "txt" | "log" => "text/plain",
        _ => "application/octet-stream",
    }
}

// ---------------------------------------------------------------------------
// Upload
// ---------------------------------------------------------------------------

/// Parsed upload arguments — what the caller needs to send to the proxy.
/// Intentionally NOT `Clone` — `bytes` can be up to `MAX_UPLOAD_BYTES` and
/// cloning it would be a costly footgun. Each sink consumes `args` by value.
#[derive(Debug)]
pub struct UploadArgs {
    pub filename: String,
    pub content_type: Option<String>,
    pub bytes: Vec<u8>,
    /// Destination key from the proxy's allowlist. `None` means "use the
    /// operator-configured default."
    pub destination: Option<String>,
}

impl UploadArgs {
    /// Decode upload args sent over the wire (base64 + filename + content_type
    /// + optional destination).
    pub fn from_wire(args: &HashMap<String, Value>) -> Result<Self, FileManagerError> {
        let filename = args
            .get("filename")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or(FileManagerError::MissingArg("filename"))?;
        let content_type = args
            .get("content_type")
            .or_else(|| args.get("content-type"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let b64 = args
            .get("content_base64")
            .or_else(|| args.get("content-base64"))
            .and_then(|v| v.as_str())
            .ok_or(FileManagerError::MissingArg("content_base64"))?;
        let bytes = B64.decode(b64.as_bytes())?;
        if (bytes.len() as u64) > MAX_UPLOAD_BYTES {
            return Err(FileManagerError::SizeCap {
                limit: MAX_UPLOAD_BYTES,
            });
        }
        let destination = args
            .get("destination")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Ok(UploadArgs {
            filename: sanitize_filename(&filename),
            content_type,
            bytes,
            destination,
        })
    }
}

/// Strip directory components and disallow path traversal in the filename
/// the agent gave us — we use it as the GCS object key.
fn sanitize_filename(input: &str) -> String {
    let trimmed = input.trim_matches(|c: char| c == '/' || c.is_whitespace());
    let last = trimmed.rsplit('/').next().unwrap_or(trimmed);
    let cleaned: String = last.chars().filter(|c| !c.is_control()).collect::<String>();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        format!("upload-{}", chrono::Utc::now().timestamp_millis())
    } else {
        cleaned
    }
}

/// Outcome of a successful upload — what the proxy returns to the CLI.
#[derive(Debug)]
pub struct UploadResult {
    pub url: String,
    pub size_bytes: u64,
    pub content_type: String,
    /// Which configured destination key was used.
    pub destination: String,
}

// ---------------------------------------------------------------------------
// Upload destination allowlist
// ---------------------------------------------------------------------------

/// One typed sink the operator's manifest declares as a permitted upload
/// destination. The agent can pick from these keys via `--destination <key>`;
/// anything else is refused with a typed error.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UploadDestination {
    /// Google Cloud Storage bucket. Object goes to `<bucket>/<prefix>/<date>/<uuid>-<filename>`.
    /// `key_ref` names a keyring key holding the GCP service account JSON.
    Gcs {
        bucket: String,
        #[serde(default = "default_gcs_prefix")]
        prefix: String,
        #[serde(default = "default_gcs_key_ref")]
        key_ref: String,
    },
    /// fal.ai CDN — uploads via fal's signed-token storage flow.
    /// `key_ref` names a keyring key holding the fal API key.
    /// `endpoint` overrides the REST base (default `https://rest.alpha.fal.ai`).
    FalStorage {
        #[serde(default = "default_fal_key_ref")]
        key_ref: String,
        #[serde(default)]
        endpoint: Option<String>,
    },
}

fn default_gcs_prefix() -> String {
    "ati-uploads".to_string()
}

fn default_gcs_key_ref() -> String {
    "gcp_credentials".to_string()
}

fn default_fal_key_ref() -> String {
    "fal_api_key".to_string()
}

/// Resolve a caller-supplied (or omitted) destination key against the operator
/// manifest's allowlist. Refuses any key not in the map with a typed error.
pub fn resolve_destination<'a>(
    destinations: &'a HashMap<String, UploadDestination>,
    default: Option<&str>,
    requested: Option<&str>,
) -> Result<(String, &'a UploadDestination), FileManagerError> {
    if destinations.is_empty() {
        return Err(FileManagerError::UploadNotConfigured);
    }
    let key = match requested {
        Some(k) if !k.is_empty() => k.to_string(),
        _ => default
            .map(|s| s.to_string())
            .ok_or(FileManagerError::UploadNotConfigured)?,
    };
    let sink = destinations
        .get(&key)
        .ok_or_else(|| FileManagerError::UnknownDestination(key.clone()))?;
    Ok((key, sink))
}

pub fn build_upload_response(result: &UploadResult) -> Value {
    json!({
        "success": true,
        "url": result.url,
        "size_bytes": result.size_bytes,
        "content_type": result.content_type,
        "destination": result.destination,
    })
}

/// Dispatch an upload to one of the operator-allowlisted destinations.
/// Resolves the requested key (or default) against the manifest's destinations
/// map, then routes to the typed sink. Refuses any key not in the map.
pub async fn upload_to_destination(
    args: UploadArgs,
    destinations: &HashMap<String, UploadDestination>,
    default: Option<&str>,
    keyring: &crate::core::keyring::Keyring,
) -> Result<Value, FileManagerError> {
    let (key, sink) = resolve_destination(destinations, default, args.destination.as_deref())?;
    let result = match sink {
        UploadDestination::Gcs {
            bucket,
            prefix,
            key_ref,
        } => upload_to_gcs(args, bucket, prefix, key_ref, keyring, &key).await?,
        UploadDestination::FalStorage { key_ref, endpoint } => {
            upload_to_fal(args, key_ref, endpoint.as_deref(), keyring, &key).await?
        }
    };
    Ok(build_upload_response(&result))
}

async fn upload_to_gcs(
    args: UploadArgs,
    bucket: &str,
    prefix: &str,
    key_ref: &str,
    keyring: &crate::core::keyring::Keyring,
    destination_key: &str,
) -> Result<UploadResult, FileManagerError> {
    let service_account_json = keyring
        .get(key_ref)
        .ok_or_else(|| {
            FileManagerError::Upload(format!("keyring key '{key_ref}' missing for GCS upload"))
        })?
        .to_string();

    let content_type = args
        .content_type
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let size_bytes = args.bytes.len() as u64;
    let date = chrono::Utc::now().format("%Y-%m-%d");
    let uuid = uuid::Uuid::new_v4();
    let object_name = format!("{prefix}/{date}/{uuid}-{}", args.filename);

    let client =
        crate::core::gcs::GcsClient::new_read_write(bucket.to_string(), &service_account_json)
            .map_err(|e| FileManagerError::Upload(e.to_string()))?;
    let url = client
        .upload_object(&object_name, args.bytes, &content_type)
        .await
        .map_err(|e| FileManagerError::Upload(e.to_string()))?;

    Ok(UploadResult {
        url,
        size_bytes,
        content_type,
        destination: destination_key.to_string(),
    })
}

/// Always-on SSRF guard for URLs that came from a remote server's response.
///
/// Applies to URLs derived from a third-party response rather than from agent
/// input or operator config. Refuses non-HTTPS URLs and any host that
/// resolves to a private/internal address.
///
/// Ignores the `ATI_SSRF_PROTECTION` env knob — that's for the
/// agent-controlled-URL path where the operator might want unrestricted dev
/// mode. Here we have no reason to ever trust a server-supplied internal
/// address.
fn require_public_https_url(url: &str) -> Result<(), FileManagerError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| FileManagerError::Upload(format!("server returned malformed URL: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(FileManagerError::Upload(format!(
            "refusing non-HTTPS URL from server: {url}"
        )));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| FileManagerError::Upload(format!("server URL has no host: {url}")))?;
    let host_lower = host.to_lowercase();
    if host_lower == "localhost"
        || host_lower == "metadata.google.internal"
        || host_lower.ends_with(".internal")
        || host_lower.ends_with(".local")
    {
        return Err(FileManagerError::Upload(format!(
            "server URL targets a private hostname: {url}"
        )));
    }
    let port = parsed.port_or_known_default().unwrap_or(443);
    let ip_host = host.trim_matches(['[', ']']);
    let is_private = if let Ok(ip) = ip_host.parse::<std::net::IpAddr>() {
        is_private_ip_addr(ip)
    } else if let Ok(addrs) = (ip_host, port).to_socket_addrs() {
        addrs.into_iter().any(|addr| is_private_ip_addr(addr.ip()))
    } else {
        false
    };
    if is_private {
        return Err(FileManagerError::Upload(format!(
            "server URL resolves to a private address: {url}"
        )));
    }
    Ok(())
}

fn is_private_ip_addr(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => is_private_ipv4(ip),
        std::net::IpAddr::V6(ip) => {
            // IPv4-mapped IPv6 (::ffff:a.b.c.d): a compromised server could
            // return a URL like `https://[::ffff:169.254.169.254]/` and bypass
            // the v4-only private checks. Unwrap the mapped form and recurse
            // through the v4 rules.
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_private_ipv4(v4);
            }
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
        }
    }
}

fn is_private_ipv4(ip: std::net::Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        // Carrier-grade NAT (RFC 6598): 100.64.0.0/10
        || (ip.octets()[0] == 100 && ip.octets()[1] >= 64 && ip.octets()[1] <= 127)
}

/// Upload to fal.ai's CDN via their two-step signed-token flow.
///
/// 1. POST `<rest>/storage/auth/token?storage_type=fal-cdn-v3` with
///    `Authorization: Key <api_key>` → `{token, token_type, base_url, expires_at}`
/// 2. POST `<base_url or v3.fal.media>/files/upload` with the signed token,
///    `Content-Type: <mime>`, `X-Fal-File-Name: <filename>`, body = bytes
///    → `{access_url: "..."}`
async fn upload_to_fal(
    args: UploadArgs,
    key_ref: &str,
    endpoint: Option<&str>,
    keyring: &crate::core::keyring::Keyring,
    destination_key: &str,
) -> Result<UploadResult, FileManagerError> {
    use serde::Deserialize;

    let api_key = keyring
        .get(key_ref)
        .ok_or_else(|| {
            FileManagerError::Upload(format!("keyring key '{key_ref}' missing for fal upload"))
        })?
        .to_string();
    let rest_base = endpoint.unwrap_or("https://rest.alpha.fal.ai");

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| FileManagerError::Upload(format!("http client init: {e}")))?;

    // Step 1: mint signed token
    let token_url = format!("{rest_base}/storage/auth/token?storage_type=fal-cdn-v3");
    let token_resp = http
        .post(&token_url)
        .header("Authorization", format!("Key {api_key}"))
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await
        .map_err(|e| FileManagerError::Upload(format!("fal token request failed: {e}")))?;
    if !token_resp.status().is_success() {
        let status = token_resp.status().as_u16();
        let body = token_resp.text().await.unwrap_or_default();
        return Err(FileManagerError::Upload(format!(
            "fal token mint returned {status}: {body}"
        )));
    }
    #[derive(Deserialize)]
    struct FalToken {
        token: String,
        token_type: String,
        base_url: String,
    }
    let token: FalToken = token_resp
        .json()
        .await
        .map_err(|e| FileManagerError::Upload(format!("fal token JSON parse failed: {e}")))?;

    // Step 2: PUT bytes to <base_url>/files/upload
    let content_type = args
        .content_type
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let size_bytes = args.bytes.len() as u64;
    let upload_url = format!("{}/files/upload", token.base_url.trim_end_matches('/'));

    // SSRF guard: the `base_url` came from fal's token response. A compromised
    // or DNS-hijacked fal endpoint returning e.g. `base_url =
    // "http://169.254.169.254/"` would otherwise cause the proxy to POST the
    // file payload + signed token to that internal address. Always enforce —
    // the env-gated `ATI_SSRF_PROTECTION` is for agent-supplied URLs where the
    // operator might want unrestricted dev access; this is a server-supplied
    // URL we can't trust unconditionally.
    require_public_https_url(&upload_url)?;

    let upload_resp = http
        .post(&upload_url)
        .header(
            "Authorization",
            format!("{} {}", token.token_type, token.token),
        )
        .header("Content-Type", &content_type)
        .header("X-Fal-File-Name", &args.filename)
        .body(args.bytes)
        .send()
        .await
        .map_err(|e| FileManagerError::Upload(format!("fal upload request failed: {e}")))?;
    if !upload_resp.status().is_success() {
        let status = upload_resp.status().as_u16();
        let body = upload_resp.text().await.unwrap_or_default();
        return Err(FileManagerError::Upload(format!(
            "fal upload returned {status}: {body}"
        )));
    }
    #[derive(Deserialize)]
    struct FalUploadResponse {
        access_url: String,
    }
    let body: FalUploadResponse = upload_resp
        .json()
        .await
        .map_err(|e| FileManagerError::Upload(format!("fal upload JSON parse failed: {e}")))?;

    Ok(UploadResult {
        url: body.access_url,
        size_bytes,
        content_type,
        destination: destination_key.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_headers_object() {
        let v = serde_json::json!({"X-Test": "1", "X-Other": "abc"});
        let map = parse_headers(Some(&v)).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("X-Test").map(String::as_str), Some("1"));
    }

    #[test]
    fn parse_headers_string_json() {
        let v = Value::String(r#"{"Authorization":"Bearer abc"}"#.into());
        let map = parse_headers(Some(&v)).unwrap();
        assert_eq!(
            map.get("Authorization").map(String::as_str),
            Some("Bearer abc")
        );
    }

    #[test]
    fn parse_headers_empty_string() {
        let v = Value::String("".into());
        assert!(parse_headers(Some(&v)).unwrap().is_empty());
    }

    #[test]
    fn parse_headers_invalid_type() {
        let v = Value::Number(42.into());
        assert!(parse_headers(Some(&v)).is_err());
    }

    #[test]
    fn validate_denied_header() {
        let mut map = HashMap::new();
        map.insert("Host".to_string(), "evil.com".to_string());
        assert!(validate_extra_headers(&map).is_err());
    }

    #[test]
    fn download_args_defaults() {
        let mut args = HashMap::new();
        args.insert(
            "url".to_string(),
            Value::String("https://example.com".into()),
        );
        let parsed = DownloadArgs::from_value(&args).unwrap();
        assert_eq!(parsed.max_bytes, DEFAULT_MAX_BYTES);
        assert_eq!(parsed.timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
        assert!(parsed.follow_redirects);
        assert!(parsed.headers.is_empty());
    }

    #[test]
    fn download_args_missing_url() {
        let args = HashMap::new();
        assert!(DownloadArgs::from_value(&args).is_err());
    }

    #[test]
    fn download_args_zero_max_bytes_rejected() {
        let mut args = HashMap::new();
        args.insert(
            "url".to_string(),
            Value::String("https://example.com".into()),
        );
        args.insert("max_bytes".to_string(), Value::Number(0.into()));
        assert!(DownloadArgs::from_value(&args).is_err());
    }

    #[test]
    fn download_args_max_bytes_string() {
        let mut args = HashMap::new();
        args.insert(
            "url".to_string(),
            Value::String("https://example.com".into()),
        );
        args.insert("max_bytes".to_string(), Value::String("1024".into()));
        let parsed = DownloadArgs::from_value(&args).unwrap();
        assert_eq!(parsed.max_bytes, 1024);
    }

    #[test]
    fn upload_args_round_trip() {
        let bytes = b"hello world".to_vec();
        let mut args = HashMap::new();
        args.insert("filename".to_string(), Value::String("hello.txt".into()));
        args.insert(
            "content_type".to_string(),
            Value::String("text/plain".into()),
        );
        args.insert(
            "content_base64".to_string(),
            Value::String(B64.encode(&bytes)),
        );
        let parsed = UploadArgs::from_wire(&args).unwrap();
        assert_eq!(parsed.bytes, bytes);
        assert_eq!(parsed.filename, "hello.txt");
        assert_eq!(parsed.content_type.as_deref(), Some("text/plain"));
    }

    #[test]
    fn upload_args_path_traversal_stripped() {
        let mut args = HashMap::new();
        args.insert(
            "filename".to_string(),
            Value::String("../../etc/passwd".into()),
        );
        args.insert(
            "content_base64".to_string(),
            Value::String(B64.encode(b"x")),
        );
        let parsed = UploadArgs::from_wire(&args).unwrap();
        assert_eq!(parsed.filename, "passwd");
    }

    #[test]
    fn upload_args_missing_filename() {
        let mut args = HashMap::new();
        args.insert(
            "content_base64".to_string(),
            Value::String(B64.encode(b"x")),
        );
        assert!(UploadArgs::from_wire(&args).is_err());
    }

    #[test]
    fn upload_args_invalid_base64() {
        let mut args = HashMap::new();
        args.insert("filename".to_string(), Value::String("a".into()));
        args.insert(
            "content_base64".to_string(),
            Value::String("!!! not base64 !!!".into()),
        );
        assert!(UploadArgs::from_wire(&args).is_err());
    }

    #[test]
    fn build_download_response_includes_base64() {
        let bytes = b"hello".to_vec();
        let result = DownloadResult {
            bytes,
            content_type: Some("text/plain".into()),
            source_url: "https://example.com/h".into(),
        };
        let v = build_download_response(&result);
        assert_eq!(v["size_bytes"], 5);
        assert_eq!(v["content_type"], "text/plain");
        assert!(v["content_base64"].as_str().is_some());
    }

    #[test]
    fn host_pattern_exact_match() {
        assert!(host_matches_pattern("v3b.fal.media", "v3b.fal.media"));
        assert!(!host_matches_pattern("evil.com", "v3b.fal.media"));
        assert!(host_matches_pattern("V3B.FAL.MEDIA", "v3b.fal.media"));
    }

    #[test]
    fn host_pattern_subdomain_wildcard() {
        assert!(host_matches_pattern("v3b.fal.media", "*.fal.media"));
        assert!(host_matches_pattern("cdn.fal.media", "*.fal.media"));
        assert!(host_matches_pattern("fal.media", "*.fal.media"));
        assert!(!host_matches_pattern("evil.com", "*.fal.media"));
        // Don't match suffix-collision tricks like "evilfal.media"
        assert!(!host_matches_pattern("evilfal.media", "*.fal.media"));
    }

    #[test]
    fn host_pattern_bare_wildcard_matches_anything() {
        assert!(host_matches_pattern("anywhere.com", "*"));
    }

    fn make_destinations() -> HashMap<String, UploadDestination> {
        let mut m = HashMap::new();
        m.insert(
            "gcs".to_string(),
            UploadDestination::Gcs {
                bucket: "b".to_string(),
                prefix: "p".to_string(),
                key_ref: "gcp_credentials".to_string(),
            },
        );
        m.insert(
            "fal".to_string(),
            UploadDestination::FalStorage {
                key_ref: "fal_api_key".to_string(),
                endpoint: None,
            },
        );
        m
    }

    #[test]
    fn resolve_destination_picks_explicit_key() {
        let m = make_destinations();
        let (k, sink) = resolve_destination(&m, Some("gcs"), Some("fal")).unwrap();
        assert_eq!(k, "fal");
        assert!(matches!(sink, UploadDestination::FalStorage { .. }));
    }

    #[test]
    fn resolve_destination_falls_back_to_default() {
        let m = make_destinations();
        let (k, _) = resolve_destination(&m, Some("gcs"), None).unwrap();
        assert_eq!(k, "gcs");
    }

    #[test]
    fn resolve_destination_unknown_key_rejected() {
        let m = make_destinations();
        let err = resolve_destination(&m, Some("gcs"), Some("evil")).unwrap_err();
        assert!(matches!(err, FileManagerError::UnknownDestination(ref s) if s == "evil"));
    }

    #[test]
    fn resolve_destination_empty_map_not_configured() {
        let m: HashMap<String, UploadDestination> = HashMap::new();
        let err = resolve_destination(&m, None, None).unwrap_err();
        assert!(matches!(err, FileManagerError::UploadNotConfigured));
    }

    #[test]
    fn resolve_destination_no_default_no_request_not_configured() {
        let m = make_destinations();
        let err = resolve_destination(&m, None, None).unwrap_err();
        assert!(matches!(err, FileManagerError::UploadNotConfigured));
    }

    // Always-on SSRF guard for server-supplied URLs (e.g. fal's base_url).
    #[test]
    fn require_public_https_accepts_public_https() {
        assert!(require_public_https_url("https://v3b.fal.media/files/upload").is_ok());
    }

    #[test]
    fn require_public_https_rejects_http_scheme() {
        let err = require_public_https_url("http://v3b.fal.media/files/upload").unwrap_err();
        assert!(
            matches!(&err, FileManagerError::Upload(m) if m.contains("non-HTTPS")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn require_public_https_rejects_loopback_hostname() {
        let err = require_public_https_url("https://localhost/files/upload").unwrap_err();
        assert!(matches!(&err, FileManagerError::Upload(m) if m.contains("private")));
    }

    #[test]
    fn require_public_https_rejects_metadata_ip() {
        // GCP metadata service
        let err = require_public_https_url("https://169.254.169.254/").unwrap_err();
        assert!(matches!(&err, FileManagerError::Upload(m) if m.contains("private")));
    }

    #[test]
    fn require_public_https_rejects_rfc1918() {
        assert!(require_public_https_url("https://10.0.0.1/x").is_err());
        assert!(require_public_https_url("https://192.168.1.1/x").is_err());
        assert!(require_public_https_url("https://172.16.0.1/x").is_err());
    }

    #[test]
    fn require_public_https_rejects_link_local_ipv6() {
        assert!(require_public_https_url("https://[fe80::1]/x").is_err());
    }

    /// Regression: v1 of `is_private_ip_addr` missed IPv4-mapped IPv6 addresses,
    /// letting a compromised server bypass the SSRF guard with
    /// `::ffff:169.254.169.254` et al.
    #[test]
    fn require_public_https_rejects_ipv4_mapped_metadata_address() {
        assert!(require_public_https_url("https://[::ffff:169.254.169.254]/").is_err());
    }

    #[test]
    fn require_public_https_rejects_ipv4_mapped_loopback() {
        assert!(require_public_https_url("https://[::ffff:127.0.0.1]/x").is_err());
    }

    #[test]
    fn require_public_https_rejects_ipv4_mapped_rfc1918() {
        assert!(require_public_https_url("https://[::ffff:10.0.0.1]/x").is_err());
        assert!(require_public_https_url("https://[::ffff:192.168.1.1]/x").is_err());
        assert!(require_public_https_url("https://[::ffff:172.16.0.1]/x").is_err());
    }

    #[test]
    fn require_public_https_rejects_ipv4_mapped_cgnat() {
        // 100.64.0.0/10 — carrier-grade NAT
        assert!(require_public_https_url("https://[::ffff:100.64.0.1]/x").is_err());
    }

    #[test]
    fn require_public_https_rejects_dotinternal_hostname() {
        assert!(require_public_https_url("https://storage.internal/x").is_err());
        assert!(require_public_https_url("https://api.local/x").is_err());
    }

    #[test]
    fn require_public_https_rejects_malformed_url() {
        assert!(require_public_https_url("not a url").is_err());
    }
}
