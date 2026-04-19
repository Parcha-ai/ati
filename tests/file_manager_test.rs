//! Integration tests for the `file_manager` virtual provider.
//!
//! Covers:
//! - Tool registration via `ManifestRegistry`
//! - Download happy path (small body)
//! - Download size cap (max-bytes exceeded)
//! - Download upstream 404
//! - Download bad URL / connection failure
//! - Download header-based auth
//! - Upload wire-format round-trip

use ati::core::file_manager::{
    self, build_download_response, DownloadArgs, FileManagerError, UploadArgs,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};
use std::collections::HashMap;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Registry exposes file_manager tools
// ---------------------------------------------------------------------------

#[test]
fn registry_exposes_file_manager_tools() {
    let registry = ati::core::manifest::ManifestRegistry::empty();
    let download = registry
        .get_tool("file_manager:download")
        .expect("file_manager:download must be registered");
    assert!(download.0.is_file_manager());
    assert_eq!(
        download.1.scope.as_deref(),
        Some("tool:file_manager:download")
    );

    let upload = registry
        .get_tool("file_manager:upload")
        .expect("file_manager:upload must be registered");
    assert_eq!(upload.1.scope.as_deref(), Some("tool:file_manager:upload"));
}

#[test]
fn file_manager_tools_have_input_schemas() {
    let registry = ati::core::manifest::ManifestRegistry::empty();
    let (_, download) = registry.get_tool("file_manager:download").unwrap();
    let schema = download.input_schema.as_ref().unwrap();
    let required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(required.contains(&"url"));

    let props = schema["properties"].as_object().unwrap();
    assert!(props.contains_key("url"));
    assert!(props.contains_key("out"));
    assert!(props.contains_key("inline"));
    assert!(props.contains_key("max_bytes"));
    assert!(props.contains_key("timeout"));
    assert!(props.contains_key("headers"));
    assert!(props.contains_key("follow_redirects"));
}

// ---------------------------------------------------------------------------
// Download — happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn download_happy_path_returns_bytes_and_metadata() {
    let server = MockServer::start().await;
    let body = b"hello binary world".to_vec();

    Mock::given(method("GET"))
        .and(path("/file.bin"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/octet-stream")
                .set_body_bytes(body.clone()),
        )
        .mount(&server)
        .await;

    let mut args = HashMap::new();
    args.insert(
        "url".to_string(),
        Value::String(format!("{}/file.bin", server.uri())),
    );
    let parsed = DownloadArgs::from_value(&args).unwrap();
    let result = file_manager::fetch_bytes(&parsed).await.unwrap();

    assert_eq!(result.bytes, body);
    assert_eq!(
        result.content_type.as_deref(),
        Some("application/octet-stream")
    );

    let resp = build_download_response(&result);
    assert_eq!(resp["size_bytes"], body.len());
    assert_eq!(resp["content_type"], "application/octet-stream");
    let b64 = resp["content_base64"].as_str().unwrap();
    assert_eq!(B64.decode(b64).unwrap(), body);
}

// ---------------------------------------------------------------------------
// Download — size cap enforcement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn download_max_bytes_exceeded_returns_typed_error() {
    let server = MockServer::start().await;
    let body = vec![0u8; 1024]; // 1 KB

    Mock::given(method("GET"))
        .and(path("/big.bin"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/octet-stream")
                .set_body_bytes(body),
        )
        .mount(&server)
        .await;

    let mut args = HashMap::new();
    args.insert(
        "url".to_string(),
        Value::String(format!("{}/big.bin", server.uri())),
    );
    args.insert("max_bytes".to_string(), Value::Number(100.into()));
    let parsed = DownloadArgs::from_value(&args).unwrap();
    let err = file_manager::fetch_bytes(&parsed).await.unwrap_err();
    assert!(
        matches!(err, FileManagerError::SizeCap { limit: 100 }),
        "expected SizeCap, got {err:?}"
    );
}

#[tokio::test]
async fn download_max_bytes_via_content_length_preflight() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/preflight.bin"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/octet-stream")
                .insert_header("Content-Length", "5000")
                .set_body_bytes(vec![0u8; 5000]),
        )
        .mount(&server)
        .await;

    let mut args = HashMap::new();
    args.insert(
        "url".to_string(),
        Value::String(format!("{}/preflight.bin", server.uri())),
    );
    args.insert("max_bytes".to_string(), Value::Number(1000.into()));
    let parsed = DownloadArgs::from_value(&args).unwrap();
    let err = file_manager::fetch_bytes(&parsed).await.unwrap_err();
    assert!(matches!(err, FileManagerError::SizeCap { .. }));
}

// ---------------------------------------------------------------------------
// Download — upstream errors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn download_404_returns_upstream_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not here"))
        .mount(&server)
        .await;

    let mut args = HashMap::new();
    args.insert(
        "url".to_string(),
        Value::String(format!("{}/missing", server.uri())),
    );
    let parsed = DownloadArgs::from_value(&args).unwrap();
    let err = file_manager::fetch_bytes(&parsed).await.unwrap_err();
    match err {
        FileManagerError::Upstream { status, .. } => assert_eq!(status, 404),
        other => panic!("expected Upstream, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Download — bad URL
// ---------------------------------------------------------------------------

#[tokio::test]
async fn download_invalid_url_returns_http_error() {
    let mut args = HashMap::new();
    // Reserved TLD that won't resolve. Set short timeout.
    args.insert(
        "url".to_string(),
        Value::String("https://this-host-does-not-exist.invalid/x".into()),
    );
    args.insert("timeout".to_string(), Value::Number(5.into()));
    let parsed = DownloadArgs::from_value(&args).unwrap();
    let err = file_manager::fetch_bytes(&parsed).await.unwrap_err();
    assert!(matches!(err, FileManagerError::Http { .. }));
}

// ---------------------------------------------------------------------------
// Download — header injection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn download_caller_supplied_headers_are_forwarded() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/auth"))
        .and(header("X-Test-Token", "abc123"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/plain")
                .set_body_bytes(b"ok".to_vec()),
        )
        .mount(&server)
        .await;

    let mut args = HashMap::new();
    args.insert(
        "url".to_string(),
        Value::String(format!("{}/auth", server.uri())),
    );
    args.insert("headers".to_string(), json!({"X-Test-Token": "abc123"}));
    let parsed = DownloadArgs::from_value(&args).unwrap();
    let result = file_manager::fetch_bytes(&parsed).await.unwrap();
    assert_eq!(result.bytes, b"ok");
}

#[tokio::test]
async fn download_denied_header_rejected_pre_send() {
    let mut args = HashMap::new();
    args.insert(
        "url".to_string(),
        Value::String("https://example.com/x".into()),
    );
    args.insert("headers".to_string(), json!({"Host": "evil.com"}));
    let err = DownloadArgs::from_value(&args).unwrap_err();
    assert!(matches!(err, FileManagerError::BadHeader { .. }));
}

// ---------------------------------------------------------------------------
// Upload — wire format
// ---------------------------------------------------------------------------

#[test]
fn upload_args_round_trip_filename_content_type_bytes() {
    let bytes = vec![1u8, 2, 3, 4];
    let mut args = HashMap::new();
    args.insert(
        "filename".to_string(),
        Value::String("clip.mp4".to_string()),
    );
    args.insert(
        "content_type".to_string(),
        Value::String("video/mp4".to_string()),
    );
    args.insert(
        "content_base64".to_string(),
        Value::String(B64.encode(&bytes)),
    );
    let parsed = UploadArgs::from_wire(&args).unwrap();
    assert_eq!(parsed.filename, "clip.mp4");
    assert_eq!(parsed.content_type.as_deref(), Some("video/mp4"));
    assert_eq!(parsed.bytes, bytes);
}

#[test]
fn upload_response_payload_shape() {
    let result = file_manager::UploadResult {
        url: "https://storage.googleapis.com/bucket/x.mp4".into(),
        size_bytes: 1234,
        content_type: "video/mp4".into(),
    };
    let v = file_manager::build_upload_response(&result);
    assert_eq!(v["success"], true);
    assert_eq!(v["url"], "https://storage.googleapis.com/bucket/x.mp4");
    assert_eq!(v["size_bytes"], 1234);
    assert_eq!(v["content_type"], "video/mp4");
}
