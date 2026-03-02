/// Generic HTTP provider — handles most tools that are simple HTTP calls.
///
/// The actual HTTP execution logic lives in core::http.
/// This module provides the provider-level orchestration:
/// loading the right manifest, checking scopes, executing, formatting.

use serde_json::Value;
use std::collections::HashMap;

use crate::core::{
    http,
    keyring::Keyring,
    manifest::{Provider, Tool},
    response,
};
use crate::output;
use crate::OutputFormat;

/// Execute a tool through the generic HTTP provider.
pub async fn execute(
    provider: &Provider,
    tool: &Tool,
    args: &HashMap<String, Value>,
    keyring: &Keyring,
    output_format: &OutputFormat,
) -> Result<String, Box<dyn std::error::Error>> {
    // Make the HTTP call
    let raw_response = http::execute_tool(provider, tool, args, keyring).await?;

    // Process response (extract via JSONPath if configured)
    let processed = response::process_response(&raw_response, tool.response.as_ref())?;

    // Format output
    let formatted = output::format_output(&processed, output_format);

    Ok(formatted)
}
