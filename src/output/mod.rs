pub mod json;
pub mod table;
pub mod text;

use crate::OutputFormat;

/// Format a serde_json::Value according to the selected output format
pub fn format_output(value: &serde_json::Value, format: &OutputFormat) -> String {
    match format {
        OutputFormat::Json => json::format(value),
        OutputFormat::Table => table::format(value),
        OutputFormat::Text => text::format(value),
    }
}
