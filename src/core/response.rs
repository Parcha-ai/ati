use jsonpath_rust::JsonPath;
use serde_json::Value;
use thiserror::Error;

use crate::core::manifest::{ResponseConfig, ResponseFormat};

#[derive(Error, Debug)]
pub enum ResponseError {
    #[error("JSONPath extraction failed: {0}")]
    ExtractionFailed(String),
}

/// Extract and format a response based on the tool's response config.
pub fn process_response(
    response: &Value,
    config: Option<&ResponseConfig>,
) -> Result<Value, ResponseError> {
    let config = match config {
        Some(c) => c,
        None => return Ok(response.clone()), // No config = passthrough
    };

    // Apply JSONPath extraction if specified
    let extracted = match &config.extract {
        Some(path_str) => extract_jsonpath(response, path_str)?,
        None => response.clone(),
    };

    Ok(extracted)
}

/// Apply a JSONPath expression to extract data from a JSON value.
fn extract_jsonpath(value: &Value, path: &str) -> Result<Value, ResponseError> {
    let path = JsonPath::try_from(path)
        .map_err(|e| ResponseError::ExtractionFailed(format!("Invalid JSONPath '{path}': {e}")))?;

    let results = path.find_slice(value);

    if results.is_empty() {
        return Ok(Value::Null);
    }

    // Convert JsonPathValue items to owned Values
    let values: Vec<Value> = results.into_iter().map(|v| v.to_data()).collect();

    if values.len() == 1 {
        Ok(values.into_iter().next().unwrap())
    } else {
        Ok(Value::Array(values))
    }
}

/// Determine the response format from config, with auto-detection fallback.
pub fn get_format(config: Option<&ResponseConfig>, value: &Value) -> ResponseFormat {
    if let Some(config) = config {
        return config.format.clone();
    }

    // Auto-detect: arrays of objects → table, otherwise text
    if let Value::Array(arr) = value {
        if arr.iter().all(|v| v.is_object()) {
            return ResponseFormat::MarkdownTable;
        }
    }

    ResponseFormat::Text
}
