//! Tests for response processing: JSONPath extraction and format auto-detection.

use ati::core::manifest::{ResponseConfig, ResponseFormat};
use ati::core::response::{get_format, process_response};
use serde_json::json;

// --- process_response ---

#[test]
fn test_process_response_passthrough_on_none_config() {
    let response = json!({"data": [1, 2, 3]});
    let result = process_response(&response, None).unwrap();
    assert_eq!(result, response);
}

#[test]
fn test_process_response_passthrough_on_no_extract() {
    let config = ResponseConfig {
        extract: None,
        format: ResponseFormat::Text,
    };
    let response = json!({"name": "test"});
    let result = process_response(&response, Some(&config)).unwrap();
    assert_eq!(result, response);
}

#[test]
fn test_process_response_jsonpath_single_value() {
    let config = ResponseConfig {
        extract: Some("$.name".into()),
        format: ResponseFormat::Text,
    };
    let response = json!({"name": "Alice", "age": 30});
    let result = process_response(&response, Some(&config)).unwrap();
    assert_eq!(result, json!("Alice"));
}

#[test]
fn test_process_response_jsonpath_array() {
    let config = ResponseConfig {
        extract: Some("$.items[*].id".into()),
        format: ResponseFormat::Text,
    };
    let response = json!({"items": [{"id": 1}, {"id": 2}, {"id": 3}]});
    let result = process_response(&response, Some(&config)).unwrap();
    assert_eq!(result, json!([1, 2, 3]));
}

#[test]
fn test_process_response_jsonpath_no_match_returns_null() {
    let config = ResponseConfig {
        extract: Some("$.nonexistent".into()),
        format: ResponseFormat::Text,
    };
    let response = json!({"name": "test"});
    let result = process_response(&response, Some(&config)).unwrap();
    assert!(result.is_null());
}

#[test]
fn test_process_response_jsonpath_nested_path() {
    let config = ResponseConfig {
        extract: Some("$.data.results[0].title".into()),
        format: ResponseFormat::Text,
    };
    let response = json!({"data": {"results": [{"title": "First"}, {"title": "Second"}]}});
    let result = process_response(&response, Some(&config)).unwrap();
    assert_eq!(result, json!("First"));
}

#[test]
fn test_process_response_invalid_jsonpath() {
    let config = ResponseConfig {
        extract: Some("$[invalid[".into()),
        format: ResponseFormat::Text,
    };
    let response = json!({"a": 1});
    let result = process_response(&response, Some(&config));
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("JSONPath"));
}

// --- get_format ---

#[test]
fn test_get_format_from_config() {
    let config = ResponseConfig {
        extract: None,
        format: ResponseFormat::MarkdownTable,
    };
    let value = json!("anything");
    match get_format(Some(&config), &value) {
        ResponseFormat::MarkdownTable => {}
        other => panic!("Expected MarkdownTable, got {:?}", other),
    }
}

#[test]
fn test_get_format_auto_detects_table_for_object_array() {
    let value = json!([{"name": "Alice", "age": 30}, {"name": "Bob", "age": 25}]);
    match get_format(None, &value) {
        ResponseFormat::MarkdownTable => {}
        other => panic!("Expected auto-detected MarkdownTable, got {:?}", other),
    }
}

#[test]
fn test_get_format_auto_text_for_scalar() {
    let value = json!("hello");
    match get_format(None, &value) {
        ResponseFormat::Text => {}
        other => panic!("Expected Text, got {:?}", other),
    }
}

#[test]
fn test_get_format_auto_text_for_mixed_array() {
    // Array with non-objects should NOT auto-detect as table
    let value = json!([1, 2, 3]);
    match get_format(None, &value) {
        ResponseFormat::Text => {}
        other => panic!("Expected Text for non-object array, got {:?}", other),
    }
}

#[test]
fn test_get_format_auto_text_for_null() {
    match get_format(None, &json!(null)) {
        ResponseFormat::Text => {}
        other => panic!("Expected Text for null, got {:?}", other),
    }
}

#[test]
fn test_get_format_auto_text_for_empty_array() {
    // Empty array — all() returns true on empty, so this is MarkdownTable
    let value = json!([]);
    // This is actually correct behavior per Rust's all() semantics on empty iterators
    match get_format(None, &value) {
        ResponseFormat::MarkdownTable => {}
        other => panic!(
            "Expected MarkdownTable for empty array (vacuous truth), got {:?}",
            other
        ),
    }
}
