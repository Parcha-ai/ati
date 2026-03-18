use ati::core::audit::{self, AuditEntry, AuditStatus};
use serde_json::json;
use std::io::Write;
use std::sync::Mutex;
use tempfile::NamedTempFile;

// Global mutex to serialize tests that use ATI_AUDIT_FILE env var.
// Rust tests run in parallel and set_var is process-wide.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn make_entry(tool: &str, status: AuditStatus, error: Option<&str>) -> AuditEntry {
    AuditEntry {
        ts: chrono::Utc::now().to_rfc3339(),
        tool: tool.to_string(),
        args: json!({"query": "test"}),
        status,
        duration_ms: 42,
        agent_sub: "test-agent".to_string(),
        error: error.map(|s| s.to_string()),
        exit_code: None,
    }
}

/// Helper: write entries to a temp file.
fn write_entries_to_file(file: &std::path::Path, entries: &[AuditEntry]) {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(file)
        .unwrap();
    for entry in entries {
        let line = serde_json::to_string(entry).unwrap();
        writeln!(f, "{}", line).unwrap();
    }
}

fn read_entries_from_file(path: &std::path::Path) -> Vec<AuditEntry> {
    if !path.exists() {
        return Vec::new();
    }
    let content = std::fs::read_to_string(path).unwrap();
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

#[test]
fn test_sanitize_args_redacts_sensitive_keys() {
    let args = json!({
        "query": "hello",
        "api_key": "sk-secret-123",
        "password": "hunter2",
        "auth_token": "bearer-xyz",
        "name": "safe"
    });

    let sanitized = audit::sanitize_args(&args);
    let obj = sanitized.as_object().unwrap();

    assert_eq!(obj["query"], json!("hello"));
    assert_eq!(obj["api_key"], json!("[REDACTED]"));
    assert_eq!(obj["password"], json!("[REDACTED]"));
    assert_eq!(obj["auth_token"], json!("[REDACTED]"));
    assert_eq!(obj["name"], json!("safe"));
}

#[test]
fn test_sanitize_args_truncates_long_values() {
    let long_string = "x".repeat(300);
    let args = json!({"data": long_string});

    let sanitized = audit::sanitize_args(&args);
    let obj = sanitized.as_object().unwrap();
    let data = obj["data"].as_str().unwrap();

    assert!(data.len() < 300);
    assert!(data.ends_with("...[truncated]"));
    assert!(data.starts_with("xxx"));
}

#[test]
fn test_sanitize_args_leaves_short_values_intact() {
    let args = json!({"query": "short", "count": 5});
    let sanitized = audit::sanitize_args(&args);
    assert_eq!(sanitized, args);
}

#[test]
fn test_append_and_tail_roundtrip() {
    let _lock = ENV_LOCK.lock().unwrap();
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_string_lossy().to_string();
    unsafe { std::env::set_var("ATI_AUDIT_FILE", &path) };

    let entry1 = make_entry("web_search", AuditStatus::Ok, None);
    let entry2 = make_entry("github:list_repos", AuditStatus::Error, Some("timeout"));

    audit::append(&entry1).unwrap();
    audit::append(&entry2).unwrap();

    let entries = audit::tail(10).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].tool, "web_search");
    assert_eq!(entries[0].status, AuditStatus::Ok);
    assert_eq!(entries[1].tool, "github:list_repos");
    assert_eq!(entries[1].status, AuditStatus::Error);
    assert_eq!(entries[1].error.as_deref(), Some("timeout"));

    // Tail with limit
    let entries = audit::tail(1).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tool, "github:list_repos");

    unsafe { std::env::remove_var("ATI_AUDIT_FILE") };
}

#[test]
fn test_search_by_tool_exact() {
    let _lock = ENV_LOCK.lock().unwrap();
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_string_lossy().to_string();

    let entries = vec![
        make_entry("web_search", AuditStatus::Ok, None),
        make_entry("github:list_repos", AuditStatus::Ok, None),
        make_entry("web_search", AuditStatus::Error, Some("fail")),
    ];
    write_entries_to_file(tmp.path(), &entries);

    // Read directly from file
    let all = read_entries_from_file(tmp.path());
    let results: Vec<&AuditEntry> = all.iter().filter(|e| e.tool == "web_search").collect();
    assert_eq!(results.len(), 2);

    // Also test via env var
    unsafe { std::env::set_var("ATI_AUDIT_FILE", &path) };
    let results = audit::search(Some("web_search"), None).unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|e| e.tool == "web_search"));
    unsafe { std::env::remove_var("ATI_AUDIT_FILE") };
}

#[test]
fn test_search_by_tool_wildcard() {
    let _lock = ENV_LOCK.lock().unwrap();
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_string_lossy().to_string();

    let entries = vec![
        make_entry("github:list_repos", AuditStatus::Ok, None),
        make_entry("github:search", AuditStatus::Ok, None),
        make_entry("web_search", AuditStatus::Ok, None),
    ];
    write_entries_to_file(tmp.path(), &entries);

    unsafe { std::env::set_var("ATI_AUDIT_FILE", &path) };
    let results = audit::search(Some("github:*"), None).unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|e| e.tool.starts_with("github:")));
    unsafe { std::env::remove_var("ATI_AUDIT_FILE") };
}

#[test]
fn test_search_by_since() {
    let _lock = ENV_LOCK.lock().unwrap();
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_string_lossy().to_string();

    let entries = vec![make_entry("web_search", AuditStatus::Ok, None)];
    write_entries_to_file(tmp.path(), &entries);

    unsafe { std::env::set_var("ATI_AUDIT_FILE", &path) };
    let results = audit::search(None, Some("1h")).unwrap();
    assert_eq!(results.len(), 1);
    unsafe { std::env::remove_var("ATI_AUDIT_FILE") };
}

#[test]
fn test_empty_audit_file_returns_empty() {
    let _lock = ENV_LOCK.lock().unwrap();
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_string_lossy().to_string();
    unsafe { std::env::set_var("ATI_AUDIT_FILE", &path) };

    let entries = audit::tail(10).unwrap();
    assert!(entries.is_empty());

    let results = audit::search(None, None).unwrap();
    assert!(results.is_empty());

    unsafe { std::env::remove_var("ATI_AUDIT_FILE") };
}

#[test]
fn test_nonexistent_audit_file_returns_empty() {
    let _lock = ENV_LOCK.lock().unwrap();
    let unique = format!(
        "/tmp/ati_nonexistent_audit_test_{}.jsonl",
        std::process::id()
    );
    let _ = std::fs::remove_file(&unique);
    unsafe { std::env::set_var("ATI_AUDIT_FILE", &unique) };

    let entries = audit::tail(10).unwrap();
    assert!(entries.is_empty());

    let results = audit::search(None, None).unwrap();
    assert!(results.is_empty());

    unsafe { std::env::remove_var("ATI_AUDIT_FILE") };
}

#[test]
fn test_audit_entry_serialization() {
    let entry = make_entry("test_tool", AuditStatus::Ok, None);
    let json_str = serde_json::to_string(&entry).unwrap();
    let parsed: AuditEntry = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed.tool, "test_tool");
    assert_eq!(parsed.status, AuditStatus::Ok);
    assert!(parsed.error.is_none());
    assert!(parsed.exit_code.is_none());

    // Verify serialized form uses lowercase
    assert!(json_str.contains("\"status\":\"ok\""));
}

#[test]
fn test_audit_entry_with_error_serialization() {
    let entry = make_entry("test_tool", AuditStatus::Error, Some("connection refused"));
    let json_str = serde_json::to_string(&entry).unwrap();
    assert!(json_str.contains("connection refused"));
    assert!(!json_str.contains("exit_code"));
    assert!(json_str.contains("\"status\":\"error\""));

    let parsed: AuditEntry = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed.error.as_deref(), Some("connection refused"));
}

#[test]
fn test_audit_status_backward_compat() {
    // Ensure old JSONL with string status still deserializes
    let json_str = r#"{"ts":"2026-03-01T00:00:00Z","tool":"test","args":{},"status":"ok","duration_ms":10,"agent_sub":"agent"}"#;
    let entry: AuditEntry = serde_json::from_str(json_str).unwrap();
    assert_eq!(entry.status, AuditStatus::Ok);

    let json_str = r#"{"ts":"2026-03-01T00:00:00Z","tool":"test","args":{},"status":"error","duration_ms":10,"agent_sub":"agent"}"#;
    let entry: AuditEntry = serde_json::from_str(json_str).unwrap();
    assert_eq!(entry.status, AuditStatus::Error);
}

#[test]
fn test_sanitize_non_object_value() {
    let val = json!("just a string");
    let sanitized = audit::sanitize_args(&val);
    assert_eq!(sanitized, json!("just a string"));

    let val = json!(42);
    let sanitized = audit::sanitize_args(&val);
    assert_eq!(sanitized, json!(42));
}

#[test]
fn test_malformed_lines_skipped() {
    let _lock = ENV_LOCK.lock().unwrap();
    let mut tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_string_lossy().to_string();

    writeln!(tmp, "not json at all").unwrap();
    let entry = make_entry("good_tool", AuditStatus::Ok, None);
    writeln!(tmp, "{}", serde_json::to_string(&entry).unwrap()).unwrap();
    writeln!(tmp, "{{\"broken\": true}}").unwrap();

    unsafe { std::env::set_var("ATI_AUDIT_FILE", &path) };

    let entries = audit::tail(10).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tool, "good_tool");

    unsafe { std::env::remove_var("ATI_AUDIT_FILE") };
}
