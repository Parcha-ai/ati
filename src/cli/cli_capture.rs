//! Sandbox-side handling of CLI tool responses with an `outputs` envelope —
//! the proxy rewrote agent-supplied output paths to proxy-side temps and
//! ships the bytes back as base64 per captured file. This module decodes
//! each payload, writes to the agent's original path, and strips the base64
//! from the user-facing response.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::Value;

/// Decode any `outputs` envelope in a CLI tool response, write each captured
/// file to disk on the sandbox side, and strip the base64 payload from the
/// returned JSON (replacing it with a `path` field per output).
///
/// Async because captured files can be up to `ATI_CLI_MAX_OUTPUT_BYTES`
/// (default 500 MB) each — blocking disk I/O on the tokio runtime would
/// stall every other task on the same worker.
pub async fn materialize_outputs(response: Value) -> Result<Value, Box<dyn std::error::Error>> {
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
        // mkdir -p the parent so deep sandbox paths like
        // /workspace/out/renders/frame.png land when intermediates don't exist.
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| format!("failed to create parent directory for '{path}': {e}"))?;
            }
        }
        tokio::fs::write(path, &bytes)
            .await
            .map_err(|e| format!("failed to write output '{path}': {e}"))?;
        entry_obj.remove("content_base64");
        entry_obj.insert("path".to_string(), Value::String(path.clone()));
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn no_outputs_field_passes_through() {
        let v = json!({"stdout": "ok"});
        let out = materialize_outputs(v.clone()).await.unwrap();
        assert_eq!(out, v);
    }

    #[tokio::test]
    async fn writes_outputs_to_disk_and_strips_base64() {
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

        let materialized = materialize_outputs(response).await.unwrap();

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

    #[tokio::test]
    async fn invalid_base64_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.bin").to_string_lossy().to_string();
        let response = json!({
            "outputs": {
                path: {"content_base64": "!!!not base64!!!", "size_bytes": 0}
            }
        });
        assert!(materialize_outputs(response).await.is_err());
    }

    /// Agents routinely pass deep paths where intermediate directories don't
    /// yet exist (e.g. a fresh sandbox workspace). Without create_dir_all the
    /// write would fail with ENOENT.
    #[tokio::test]
    async fn writes_to_deep_path_creates_intermediate_directories() {
        let dir = tempfile::tempdir().unwrap();
        let deep_path = dir.path().join("a").join("b").join("c").join("frame.png");
        let path_str = deep_path.to_string_lossy().to_string();
        let bytes = b"deep-bytes".to_vec();
        let response = json!({
            "outputs": {
                path_str.clone(): {
                    "content_base64": B64.encode(&bytes),
                    "size_bytes": bytes.len(),
                }
            }
        });

        assert!(
            !deep_path.parent().unwrap().exists(),
            "parent dir must not exist before the call"
        );

        materialize_outputs(response).await.unwrap();

        assert!(deep_path.exists(), "deep path should have been created");
        assert_eq!(std::fs::read(&deep_path).unwrap(), bytes);
    }
}
