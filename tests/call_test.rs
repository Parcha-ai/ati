use serde_json::{json, Value};
use std::collections::HashMap;

/// Test argument parsing from CLI format
#[test]
fn test_parse_string_args() {
    let args = vec![
        "--query".to_string(),
        "hello world".to_string(),
        "--max_results".to_string(),
        "10".to_string(),
    ];

    let parsed = parse_tool_args(&args).unwrap();
    assert_eq!(parsed.get("query").unwrap(), &json!("hello world"));
    assert_eq!(parsed.get("max_results").unwrap(), &json!(10));
}

#[test]
fn test_parse_boolean_flag() {
    let args = vec!["--verbose".to_string(), "--query".to_string(), "test".to_string()];

    let parsed = parse_tool_args(&args).unwrap();
    assert_eq!(parsed.get("verbose").unwrap(), &json!(true));
    assert_eq!(parsed.get("query").unwrap(), &json!("test"));
}

#[test]
fn test_parse_json_value() {
    let args = vec![
        "--filters".to_string(),
        r#"{"status":"active"}"#.to_string(),
    ];

    let parsed = parse_tool_args(&args).unwrap();
    let filters = parsed.get("filters").unwrap();
    assert!(filters.is_object());
    assert_eq!(filters.get("status").unwrap(), &json!("active"));
}

#[test]
fn test_parse_empty_args() {
    let args: Vec<String> = vec![];
    let parsed = parse_tool_args(&args).unwrap();
    assert!(parsed.is_empty());
}

#[test]
fn test_url_construction() {
    let base_url = "https://api.example.com/v1";
    let endpoint = "/search";
    let url = format!("{}{}", base_url.trim_end_matches('/'), endpoint);
    assert_eq!(url, "https://api.example.com/v1/search");

    // With trailing slash
    let base_url2 = "https://api.example.com/v1/";
    let url2 = format!("{}{}", base_url2.trim_end_matches('/'), endpoint);
    assert_eq!(url2, "https://api.example.com/v1/search");
}

#[test]
fn test_response_jsonpath_extraction() {
    let response = json!({
        "results": [
            {"title": "Result 1", "url": "https://example.com/1"},
            {"title": "Result 2", "url": "https://example.com/2"},
            {"title": "Result 3", "url": "https://example.com/3"}
        ],
        "total": 3
    });

    let path = jsonpath_rust::JsonPath::try_from("$.results[*]").unwrap();
    let results = path.find_slice(&response);

    assert_eq!(results.len(), 3);

    // Verify we can extract to owned values
    let values: Vec<Value> = results.into_iter().map(|v| v.to_data()).collect();
    assert_eq!(values[0].get("title").unwrap(), &json!("Result 1"));
    assert_eq!(values[2].get("url").unwrap(), &json!("https://example.com/3"));
}

#[test]
fn test_response_jsonpath_single_value() {
    let response = json!({
        "data": {
            "count": 42
        }
    });

    let path = jsonpath_rust::JsonPath::try_from("$.data.count").unwrap();
    let results = path.find_slice(&response);

    assert_eq!(results.len(), 1);
    let value = results[0].clone().to_data();
    assert_eq!(value, json!(42));
}

#[test]
fn test_response_jsonpath_no_match() {
    let response = json!({"foo": "bar"});

    let path = jsonpath_rust::JsonPath::try_from("$.nonexistent").unwrap();
    let results = path.find_slice(&response);

    // jsonpath-rust returns a NoValue variant when no match, not an empty vec
    // Our response.rs handles this by calling to_data() which returns Value::default() (Null)
    let values: Vec<Value> = results.into_iter().map(|v| v.to_data()).collect();
    assert!(values.is_empty() || values.iter().all(|v| v.is_null()));
}

#[test]
fn test_table_formatting_array_of_objects() {
    let data = json!([
        {"name": "Alice", "age": 30},
        {"name": "Bob", "age": 25}
    ]);

    let formatted = format_as_table(&data);
    assert!(formatted.contains("Alice"));
    assert!(formatted.contains("Bob"));
    assert!(formatted.contains("name"));
}

#[test]
fn test_text_formatting() {
    let data = json!({"key": "value", "number": 42});
    let formatted = format_as_text(&data);
    assert!(formatted.contains("key: value"));
    assert!(formatted.contains("number: 42"));
}

// --- Helper functions (mirrored from the binary) ---

fn parse_tool_args(args: &[String]) -> Result<HashMap<String, Value>, Box<dyn std::error::Error>> {
    let mut map = HashMap::new();
    let mut i = 0;

    while i < args.len() {
        let arg = &args[i];
        if arg.starts_with("--") {
            let key = arg.trim_start_matches("--").to_string();
            if key.is_empty() {
                return Err("Empty argument key".into());
            }

            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                let val_str = &args[i + 1];
                let value = serde_json::from_str(val_str)
                    .unwrap_or_else(|_| Value::String(val_str.clone()));
                map.insert(key, value);
                i += 2;
            } else {
                map.insert(key, Value::Bool(true));
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    Ok(map)
}

fn format_as_table(value: &Value) -> String {
    use comfy_table::{presets::UTF8_FULL_CONDENSED, Table, ContentArrangement};

    match value {
        Value::Array(arr) if !arr.is_empty() && arr[0].is_object() => {
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
        _ => serde_json::to_string_pretty(value).unwrap(),
    }
}

fn format_as_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Object(obj) => {
            let mut lines = Vec::new();
            for (k, v) in obj {
                let val_str = match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                lines.push(format!("{k}: {val_str}"));
            }
            lines.join("\n")
        }
        _ => serde_json::to_string_pretty(value).unwrap(),
    }
}
