use serde_json::Value;

/// Format a JSON value as pretty-printed JSON.
pub fn format(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}
