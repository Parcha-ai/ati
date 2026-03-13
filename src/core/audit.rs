use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, Write};
use std::path::PathBuf;

use crate::core::dirs;
use crate::core::scope::matches_wildcard;

const MAX_ARG_VALUE_LEN: usize = 200;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuditStatus {
    Ok,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: String,
    pub tool: String,
    pub args: Value,
    pub status: AuditStatus,
    pub duration_ms: u64,
    pub agent_sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

/// Get the audit log file path.
pub fn audit_file_path() -> PathBuf {
    if let Ok(p) = std::env::var("ATI_AUDIT_FILE") {
        PathBuf::from(p)
    } else {
        dirs::ati_dir().join("audit.jsonl")
    }
}

/// Append an audit entry to the log file.
pub fn append(entry: &AuditEntry) -> Result<(), std::io::Error> {
    let path = audit_file_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    let line = serde_json::to_string(entry)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    writeln!(file, "{}", line)?;
    Ok(())
}

/// Read the last N entries from the audit log.
pub fn tail(n: usize) -> Result<Vec<AuditEntry>, Box<dyn std::error::Error>> {
    let path = audit_file_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = std::fs::File::open(&path)?;
    let reader = std::io::BufReader::new(file);
    let entries: Vec<AuditEntry> = reader
        .lines()
        .filter_map(|l| l.ok())
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(&l).ok())
        .collect();
    let start = entries.len().saturating_sub(n);
    Ok(entries[start..].to_vec())
}

/// Search audit entries by tool pattern and/or time window.
pub fn search(
    tool_pattern: Option<&str>,
    since: Option<&str>,
) -> Result<Vec<AuditEntry>, Box<dyn std::error::Error>> {
    let path = audit_file_path();
    if !path.exists() {
        return Ok(Vec::new());
    }

    let since_ts = since.map(parse_duration_ago).transpose()?;

    let file = std::fs::File::open(&path)?;
    let reader = std::io::BufReader::new(file);
    let entries: Vec<AuditEntry> = reader
        .lines()
        .filter_map(|l| l.ok())
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(&l).ok())
        .filter(|e: &AuditEntry| {
            if let Some(pattern) = tool_pattern {
                if !matches_wildcard(&e.tool, pattern) {
                    return false;
                }
            }
            if let Some(ref cutoff) = since_ts {
                if e.ts.as_str() < cutoff.as_str() {
                    return false;
                }
            }
            true
        })
        .collect();

    Ok(entries)
}

/// Sanitize args for audit: redact sensitive keys, truncate long values.
pub fn sanitize_args(args: &Value) -> Value {
    match args {
        Value::Object(map) => {
            let mut sanitized = serde_json::Map::new();
            for (key, value) in map {
                let key_lower = key.to_lowercase();
                if key_lower.contains("password")
                    || key_lower.contains("secret")
                    || key_lower.contains("token")
                    || key_lower.contains("key")
                    || key_lower.contains("credential")
                    || key_lower.contains("auth")
                {
                    sanitized.insert(key.clone(), Value::String("[REDACTED]".to_string()));
                } else {
                    sanitized.insert(key.clone(), truncate_value(value));
                }
            }
            Value::Object(sanitized)
        }
        other => truncate_value(other),
    }
}

fn truncate_value(value: &Value) -> Value {
    match value {
        Value::String(s) if s.len() > MAX_ARG_VALUE_LEN => {
            Value::String(format!("{}...[truncated]", &s[..MAX_ARG_VALUE_LEN]))
        }
        other => other.clone(),
    }
}

/// Parse a human duration string like "1h", "30m", "7d" into an ISO 8601 timestamp
/// representing that many units ago from now.
fn parse_duration_ago(s: &str) -> Result<String, Box<dyn std::error::Error>> {
    let s = s.trim();
    if s.is_empty() {
        return Err("Empty duration string".into());
    }

    // Split into numeric prefix and unit suffix
    let split_pos = s
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| format!("Invalid duration: '{s}'. Use format like 1h, 30m, 7d"))?;
    let (num_str, unit) = s.split_at(split_pos);

    let count: i64 = num_str
        .parse()
        .map_err(|_| format!("Invalid number in duration: '{s}'"))?;

    let secs_per_unit = dirs::unit_to_secs(unit)
        .ok_or_else(|| format!("Invalid duration unit: '{unit}'. Use s, m, h, or d"))?;

    let seconds = count * secs_per_unit as i64;
    let cutoff = Utc::now() - chrono::Duration::seconds(seconds);
    Ok(cutoff.to_rfc3339())
}
