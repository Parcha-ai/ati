/// Generic HTTP provider — handles most tools that are simple HTTP calls.
///
/// The actual HTTP execution logic lives in core::http.
/// This module provides the provider-level orchestration:
/// loading the right manifest, checking scopes, executing, formatting.
use serde_json::Value;
use std::collections::HashMap;

use crate::core::auth_generator::{AuthCache, GenContext};
use crate::core::{
    http,
    manifest::{Provider, Tool},
    response,
    secret_resolver::SecretResolver,
};
use crate::output;
use crate::OutputFormat;

/// Execute a tool through the generic HTTP provider.
pub async fn execute(
    provider: &Provider,
    tool: &Tool,
    args: &HashMap<String, Value>,
    keyring: &SecretResolver<'_>,
    output_format: &OutputFormat,
) -> Result<String, Box<dyn std::error::Error>> {
    execute_with_gen(provider, tool, args, keyring, output_format, None, None).await
}

/// Execute a tool through the generic HTTP provider with optional auth generator.
pub async fn execute_with_gen(
    provider: &Provider,
    tool: &Tool,
    args: &HashMap<String, Value>,
    keyring: &SecretResolver<'_>,
    output_format: &OutputFormat,
    gen_ctx: Option<&GenContext>,
    auth_cache: Option<&AuthCache>,
) -> Result<String, Box<dyn std::error::Error>> {
    // Make the HTTP call
    let raw_response =
        http::execute_tool_with_gen(provider, tool, args, keyring, gen_ctx, auth_cache).await?;

    // Process response (extract via JSONPath if configured)
    let processed = response::process_response(&raw_response, tool.response.as_ref())?;

    // Format output
    let formatted = output::format_output(&processed, output_format);

    Ok(formatted)
}
