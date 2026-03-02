use serde_json::Value;

/// Format a JSON value as plain text.
///
/// - Strings: printed directly
/// - Objects: key: value pairs, one per line
/// - Arrays: one item per line
/// - Other: JSON representation
pub fn format(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Object(obj) => {
            let mut lines = Vec::new();
            for (k, v) in obj {
                let val_str = match v {
                    Value::String(s) => s.clone(),
                    Value::Null => "null".to_string(),
                    other => other.to_string(),
                };
                lines.push(format!("{k}: {val_str}"));
            }
            lines.join("\n")
        }
        Value::Array(arr) => {
            arr.iter()
                .map(|v| match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
    }
}
