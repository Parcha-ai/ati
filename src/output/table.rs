use comfy_table::{presets::UTF8_FULL_CONDENSED, ContentArrangement, Table};
use serde_json::Value;

/// Format a JSON value as a table.
///
/// Works best with arrays of objects. Falls back to JSON for other types.
pub fn format(value: &Value) -> String {
    match value {
        Value::Array(arr) if !arr.is_empty() && arr[0].is_object() => format_array_of_objects(arr),
        Value::Object(obj) => {
            // Single object → key-value table
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_content_arrangement(ContentArrangement::Dynamic);
            table.set_header(vec!["Key", "Value"]);
            for (k, v) in obj {
                let val_str = match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                table.add_row(vec![k.as_str(), &val_str]);
            }
            table.to_string()
        }
        _ => super::json::format(value),
    }
}

fn format_array_of_objects(arr: &[Value]) -> String {
    // Collect all unique keys for headers
    let mut headers: Vec<String> = Vec::new();
    for item in arr {
        if let Value::Object(obj) = item {
            for key in obj.keys() {
                if !headers.contains(key) {
                    headers.push(key.clone());
                }
            }
        }
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL_CONDENSED);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(&headers);

    for item in arr {
        if let Value::Object(obj) = item {
            let row: Vec<String> = headers
                .iter()
                .map(|h| {
                    obj.get(h)
                        .map(|v| match v {
                            Value::String(s) => s.clone(),
                            Value::Null => "".to_string(),
                            other => other.to_string(),
                        })
                        .unwrap_or_default()
                })
                .collect();
            table.add_row(row);
        }
    }

    table.to_string()
}
