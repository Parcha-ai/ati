use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::core::dirs;
use crate::core::scope::matches_wildcard;

#[derive(Debug, Clone)]
pub struct RateConfig {
    /// Map from tool pattern (e.g. "tool:github__*") to rate limit
    pub limits: HashMap<String, RateLimit>,
}

#[derive(Debug, Clone)]
pub struct RateLimit {
    pub count: u64,
    pub window_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RateState {
    /// Map from tool pattern to list of call timestamps (Unix seconds)
    pub calls: HashMap<String, Vec<u64>>,
}

#[derive(Debug, thiserror::Error)]
pub enum RateError {
    #[error("Rate limit exceeded for '{pattern}': {count}/{window} (limit: {limit}/{window})")]
    Exceeded {
        pattern: String,
        count: u64,
        limit: u64,
        window: String,
    },
    #[error("Invalid rate spec '{0}': {1}")]
    InvalidSpec(String, String),
    #[error("Rate state I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Parse a rate spec like "10/hour" into a RateLimit.
pub fn parse_rate_spec(spec: &str) -> Result<RateLimit, RateError> {
    let parts: Vec<&str> = spec.split('/').collect();
    if parts.len() != 2 {
        return Err(RateError::InvalidSpec(
            spec.to_string(),
            "expected format: count/unit (e.g. 10/hour)".into(),
        ));
    }
    let count: u64 = parts[0]
        .parse()
        .map_err(|_| RateError::InvalidSpec(spec.to_string(), "invalid count".into()))?;
    let window_secs = dirs::unit_to_secs(parts[1].trim()).ok_or_else(|| {
        RateError::InvalidSpec(spec.to_string(), format!("unknown unit: {}", parts[1]))
    })?;
    Ok(RateLimit { count, window_secs })
}

/// Parse rate claims from JWT AtiNamespace.rate HashMap.
/// Format: {"tool:github__*": "10/hour", "tool:*": "100/hour"}
pub fn parse_rate_config(rate_map: &HashMap<String, String>) -> Result<RateConfig, RateError> {
    let mut limits = HashMap::new();
    for (pattern, spec) in rate_map {
        limits.insert(pattern.clone(), parse_rate_spec(spec)?);
    }
    Ok(RateConfig { limits })
}

/// Check if a tool call is within rate limits and record it.
/// Returns Ok(()) if allowed, Err(RateError::Exceeded) if rate limited.
pub fn check_and_record(tool_name: &str, config: &RateConfig) -> Result<(), RateError> {
    let now = now_secs();
    let mut state = load_state()?;

    for (pattern, limit) in &config.limits {
        // Prepend "tool:" to the tool name for pattern matching against rate patterns
        let tool_scope = format!("tool:{}", tool_name);
        if matches_wildcard(&tool_scope, pattern) {
            let calls = state.calls.entry(pattern.clone()).or_default();

            // Prune expired entries
            let cutoff = now.saturating_sub(limit.window_secs);
            calls.retain(|&ts| ts > cutoff);

            // Check if over limit
            if calls.len() as u64 >= limit.count {
                let count = calls.len() as u64;
                let limit_count = limit.count;
                let window_str = format_window(limit.window_secs);
                let pattern_clone = pattern.clone();
                let _ = calls;
                save_state(&state)?;
                return Err(RateError::Exceeded {
                    pattern: pattern_clone,
                    count,
                    limit: limit_count,
                    window: window_str,
                });
            }

            // Record this call
            calls.push(now);
        }
    }

    save_state(&state)?;
    Ok(())
}

fn format_window(secs: u64) -> String {
    match secs {
        1 => "second".into(),
        60 => "minute".into(),
        3600 => "hour".into(),
        86400 => "day".into(),
        _ => format!("{secs}s"),
    }
}

fn rate_state_path() -> PathBuf {
    dirs::ati_dir().join("rate-state.json")
}

fn load_state() -> Result<RateState, RateError> {
    let path = rate_state_path();
    if !path.exists() {
        return Ok(RateState::default());
    }
    let content = std::fs::read_to_string(&path)?;
    match serde_json::from_str(&content) {
        Ok(state) => Ok(state),
        Err(_) => {
            // Corrupted state file -- reset
            let _ = std::fs::remove_file(&path);
            Ok(RateState::default())
        }
    }
}

/// Save state atomically: write to a temp file, then rename into place.
/// This prevents corruption from concurrent `ati run` invocations.
fn save_state(state: &RateState) -> Result<(), RateError> {
    let path = rate_state_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content =
        serde_json::to_string(state).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let tmp_path = path.with_extension("json.tmp");
    std::fs::write(&tmp_path, content)?;
    std::fs::rename(&tmp_path, &path)?;
    Ok(())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rate_spec_hour() {
        let rl = parse_rate_spec("10/hour").unwrap();
        assert_eq!(rl.count, 10);
        assert_eq!(rl.window_secs, 3600);
    }

    #[test]
    fn test_parse_rate_spec_minute() {
        let rl = parse_rate_spec("5/minute").unwrap();
        assert_eq!(rl.count, 5);
        assert_eq!(rl.window_secs, 60);
    }

    #[test]
    fn test_parse_rate_spec_second() {
        let rl = parse_rate_spec("1/second").unwrap();
        assert_eq!(rl.count, 1);
        assert_eq!(rl.window_secs, 1);
    }

    #[test]
    fn test_parse_rate_spec_day() {
        let rl = parse_rate_spec("100/day").unwrap();
        assert_eq!(rl.count, 100);
        assert_eq!(rl.window_secs, 86400);
    }

    #[test]
    fn test_parse_rate_spec_short_units() {
        assert_eq!(parse_rate_spec("1/s").unwrap().window_secs, 1);
        assert_eq!(parse_rate_spec("1/m").unwrap().window_secs, 60);
        assert_eq!(parse_rate_spec("1/h").unwrap().window_secs, 3600);
        assert_eq!(parse_rate_spec("1/d").unwrap().window_secs, 86400);
        assert_eq!(parse_rate_spec("1/sec").unwrap().window_secs, 1);
        assert_eq!(parse_rate_spec("1/min").unwrap().window_secs, 60);
        assert_eq!(parse_rate_spec("1/hr").unwrap().window_secs, 3600);
    }

    #[test]
    fn test_parse_rate_spec_invalid() {
        assert!(parse_rate_spec("abc/hour").is_err());
        assert!(parse_rate_spec("10").is_err());
        assert!(parse_rate_spec("10/week").is_err());
        assert!(parse_rate_spec("").is_err());
        assert!(parse_rate_spec("10/hour/extra").is_err());
    }

    #[test]
    fn test_parse_rate_config() {
        let mut map = HashMap::new();
        map.insert("tool:github__*".to_string(), "10/hour".to_string());
        map.insert("tool:*".to_string(), "100/hour".to_string());

        let config = parse_rate_config(&map).unwrap();
        assert_eq!(config.limits.len(), 2);
        assert_eq!(config.limits["tool:github__*"].count, 10);
        assert_eq!(config.limits["tool:*"].count, 100);
    }

    // Stateful tests (check_and_record, persistence) are in tests/rate_test.rs
    // to avoid env var races with parallel unit tests.

    #[test]
    fn test_format_window() {
        assert_eq!(format_window(1), "second");
        assert_eq!(format_window(60), "minute");
        assert_eq!(format_window(3600), "hour");
        assert_eq!(format_window(86400), "day");
        assert_eq!(format_window(7200), "7200s");
    }
}
