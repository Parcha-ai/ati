//! CLI-side file_manager handling.
//!
//! The proxy server performs the actual network fetch (download) or GCS upload
//! (upload). The CLI is responsible for file I/O on the caller's side:
//!
//! - download: read args, call core/proxy, decode returned base64, write to `--out`
//! - upload: read file bytes from `--path`, base64-encode, send to core/proxy
//!
//! Local mode and proxy mode share this shim — only the middle call differs.
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

use crate::core::file_manager as fm;
use crate::core::keyring::Keyring;
use crate::OutputFormat;

/// Is `tool_name` one of the file_manager tools that the CLI short-circuits?
pub fn is_file_manager_tool(tool_name: &str) -> bool {
    matches!(tool_name, "file_manager:download" | "file_manager:upload")
}

/// Entry point from `cli/call.rs`. Returns the formatted output string.
pub async fn execute(
    tool_name: &str,
    args: &HashMap<String, Value>,
    output_format: &OutputFormat,
    mode: DispatchMode<'_>,
) -> Result<String, Box<dyn std::error::Error>> {
    match tool_name {
        "file_manager:download" => run_download(args, output_format, mode).await,
        "file_manager:upload" => run_upload(args, output_format, mode).await,
        other => Err(format!("Unknown file_manager tool: '{other}'").into()),
    }
}

/// How the CLI dispatches the actual work after handling file I/O.
pub enum DispatchMode<'a> {
    /// Run directly in this process. Must provide keyring for GCS credentials.
    Local { keyring: &'a Keyring },
    /// Forward to an ATI proxy server.
    Proxy { proxy_url: &'a str },
}

// --- Download ---

async fn run_download(
    args: &HashMap<String, Value>,
    output_format: &OutputFormat,
    mode: DispatchMode<'_>,
) -> Result<String, Box<dyn std::error::Error>> {
    let out_path = args
        .get("out")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let inline = args
        .get("inline")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Strip CLI-only args before sending to server.
    let mut server_args = args.clone();
    server_args.remove("out");
    server_args.remove("inline");

    let response = match mode {
        DispatchMode::Local { keyring: _ } => {
            let parsed = fm::DownloadArgs::from_value(&server_args)?;
            let result = fm::fetch_bytes(&parsed).await?;
            fm::build_download_response(&result)
        }
        DispatchMode::Proxy { proxy_url } => {
            crate::proxy::client::call_tool(proxy_url, "file_manager:download", &server_args, None)
                .await?
        }
    };

    let content_b64 = response
        .get("content_base64")
        .and_then(|v| v.as_str())
        .ok_or("download response missing content_base64")?;
    let bytes = B64
        .decode(content_b64.as_bytes())
        .map_err(|e| format!("invalid base64 in response: {e}"))?;

    let size_bytes = bytes.len();
    let content_type = response
        .get("content_type")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let source_url = response
        .get("source_url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_default();

    let mut out_json = json!({
        "success": true,
        "size_bytes": size_bytes,
        "content_type": content_type,
        "source_url": source_url,
    });

    if let Some(path) = out_path {
        std::fs::write(&path, &bytes).map_err(|e| format!("failed to write {path}: {e}"))?;
        out_json["path"] = Value::String(path);
    } else if inline {
        out_json["content_base64"] = Value::String(content_b64.to_string());
    } else {
        // No --out and no --inline flag → return base64 by default (issue's "inline if absent").
        out_json["content_base64"] = Value::String(content_b64.to_string());
    }

    Ok(crate::output::format_output(&out_json, output_format))
}

// --- Upload ---

async fn run_upload(
    args: &HashMap<String, Value>,
    output_format: &OutputFormat,
    mode: DispatchMode<'_>,
) -> Result<String, Box<dyn std::error::Error>> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or("missing required --path")?
        .to_string();
    let explicit_ct = args
        .get("content_type")
        .or_else(|| args.get("content-type"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let explicit_object_name = args
        .get("object_name")
        .or_else(|| args.get("object-name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let destination = args
        .get("destination")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| format!("failed to read {path}: {e}"))?;

    let filename = Path::new(&path)
        .file_name()
        .and_then(|f| f.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("upload-{}", chrono::Utc::now().timestamp_millis()));
    let content_type = explicit_ct.unwrap_or_else(|| guess_content_type(&path));

    let mut wire_args: HashMap<String, Value> = HashMap::new();
    wire_args.insert(
        "filename".into(),
        Value::String(explicit_object_name.clone().unwrap_or(filename)),
    );
    wire_args.insert("content_type".into(), Value::String(content_type));
    wire_args.insert("content_base64".into(), Value::String(B64.encode(&bytes)));
    if let Some(ref d) = destination {
        wire_args.insert("destination".into(), Value::String(d.clone()));
    }

    let response = match mode {
        DispatchMode::Local { keyring } => upload_local(&wire_args, keyring).await?,
        DispatchMode::Proxy { proxy_url } => {
            crate::proxy::client::call_tool(proxy_url, "file_manager:upload", &wire_args, None)
                .await?
        }
    };

    Ok(crate::output::format_output(&response, output_format))
}

/// Run upload directly using the local manifest-declared destinations.
/// The `file_manager` provider's `upload_destinations` map governs what's
/// allowed — same allowlist semantics as the proxy path.
async fn upload_local(
    wire_args: &HashMap<String, Value>,
    keyring: &Keyring,
) -> Result<Value, Box<dyn std::error::Error>> {
    use crate::core::file_manager::{upload_to_destination, UploadArgs};
    use crate::core::manifest::ManifestRegistry;

    let parsed = UploadArgs::from_wire(wire_args)?;

    // Load the local manifest registry to find the operator's `file_manager`
    // provider with its declared upload destinations. If no manifest exists,
    // the auto-registered virtual provider has an empty destinations map,
    // which yields a clean `UploadNotConfigured` error.
    let ati_dir = super::common::ati_dir();
    let manifests_dir = ati_dir.join("manifests");
    let registry = ManifestRegistry::load(&manifests_dir)?;
    let provider = registry
        .list_providers()
        .into_iter()
        .find(|p| p.handler == "file_manager")
        .ok_or("file_manager provider not registered")?
        .clone();

    Ok(upload_to_destination(
        parsed,
        &provider.upload_destinations,
        provider.upload_default_destination.as_deref(),
        keyring,
    )
    .await?)
}

/// Map common extensions to MIME types. Falls back to octet-stream.
fn guess_content_type(path: &str) -> String {
    let lower = path.to_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("");
    match ext {
        "mp4" | "m4v" => "video/mp4",
        "mov" => "video/quicktime",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" | "oga" => "audio/ogg",
        "flac" => "audio/flac",
        "m4a" => "audio/mp4",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "csv" => "text/csv",
        "json" => "application/json",
        "xml" => "application/xml",
        "zip" => "application/zip",
        "txt" | "log" => "text/plain",
        "html" | "htm" => "text/html",
        "md" => "text/markdown",
        _ => "application/octet-stream",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guess_content_type_mp4() {
        assert_eq!(guess_content_type("/tmp/a.mp4"), "video/mp4");
        assert_eq!(guess_content_type("A.MP4"), "video/mp4");
    }

    #[test]
    fn guess_content_type_unknown() {
        assert_eq!(
            guess_content_type("/tmp/mystery.xyz"),
            "application/octet-stream"
        );
    }

    #[test]
    fn is_file_manager_tool_matches() {
        assert!(is_file_manager_tool("file_manager:download"));
        assert!(is_file_manager_tool("file_manager:upload"));
        assert!(!is_file_manager_tool("github:search"));
    }
}
