//! Sandbox-side handling of CLI tool responses that contain captured output files.
//!
//! When a CLI tool was invoked with output-path args (per the provider manifest's
//! `cli_output_args` / `cli_output_positional`), the proxy/local executor returns
//! a structured envelope:
//!
//! ```json
//! {
//!   "stdout": "<subprocess stdout>",
//!   "outputs": {
//!     "/tmp/shot.png": {
//!       "content_base64": "...",
//!       "size_bytes": 18432,
//!       "content_type": "image/png"
//!     }
//!   }
//! }
//! ```
//!
//! This module decodes each base64 payload and writes it to the agent's
//! original path inside the sandbox, then rewrites the response so that the
//! base64 isn't echoed back through stdout (which would be useless noise — the
//! file is what the agent wanted).

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::Value;

/// Inspect a CLI tool response. If it contains the `outputs` envelope, decode
/// and write each captured file to disk on the sandbox side, then return a
/// version of the response with `content_base64` stripped (replaced with a
/// `path` field on each output) so the agent sees a clean record of what
/// landed where.
///
/// Returns the (possibly rewritten) response. On any decode/write failure,
/// returns the underlying error so the caller can surface it.
pub fn materialize_outputs(response: Value) -> Result<Value, Box<dyn std::error::Error>> {
    let mut response = response;
    let outputs_val = match response.get_mut("outputs") {
        Some(v) => v,
        None => return Ok(response),
    };
    let outputs_map = match outputs_val.as_object_mut() {
        Some(m) => m,
        None => return Ok(response),
    };
    if outputs_map.is_empty() {
        return Ok(response);
    }

    for (path, entry) in outputs_map.iter_mut() {
        let entry_obj = match entry.as_object_mut() {
            Some(o) => o,
            None => continue,
        };
        let b64 = match entry_obj.get("content_base64").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let bytes = B64
            .decode(b64.as_bytes())
            .map_err(|e| format!("output '{path}' has invalid base64: {e}"))?;
        std::fs::write(path, &bytes)
            .map_err(|e| format!("failed to write output '{path}': {e}"))?;
        // Strip the base64 from the user-facing response (it's already on disk
        // and re-emitting it just wastes context). Keep size + content_type so
        // the agent can sanity-check what landed.
        entry_obj.remove("content_base64");
        entry_obj.insert("path".to_string(), Value::String(path.clone()));
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn no_outputs_field_passes_through() {
        let v = json!({"stdout": "ok"});
        let out = materialize_outputs(v.clone()).unwrap();
        assert_eq!(out, v);
    }

    #[test]
    fn writes_outputs_to_disk_and_strips_base64() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shot.png");
        let path_str = path.to_string_lossy().to_string();

        let bytes = b"fake-png-bytes".to_vec();
        let response = json!({
            "stdout": "Saved screenshot",
            "outputs": {
                path_str.clone(): {
                    "content_base64": B64.encode(&bytes),
                    "size_bytes": bytes.len(),
                    "content_type": "image/png",
                }
            }
        });

        let materialized = materialize_outputs(response).unwrap();

        // File was written
        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(on_disk, bytes);

        // base64 stripped, path injected, size/content_type preserved
        let entry = &materialized["outputs"][&path_str];
        assert!(entry.get("content_base64").is_none());
        assert_eq!(entry["path"], path_str);
        assert_eq!(entry["size_bytes"], bytes.len());
        assert_eq!(entry["content_type"], "image/png");
    }

    #[test]
    fn invalid_base64_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.bin").to_string_lossy().to_string();
        let response = json!({
            "outputs": {
                path: {"content_base64": "!!!not base64!!!", "size_bytes": 0}
            }
        });
        assert!(materialize_outputs(response).is_err());
    }
}
