use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::io::IsTerminal;

use crate::core::manifest::ManifestRegistry;
use crate::{Cli, PlanCommands};

/// A structured plan of tool calls recommended by `ati assist --plan`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub query: String,
    pub steps: Vec<PlanStep>,
    pub created_at: String,
}

/// A single step in a plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStep {
    pub tool: String,
    pub args: HashMap<String, Value>,
    pub description: String,
}

/// Execute: ati plan <subcommand>
pub async fn execute(cli: &Cli, subcmd: &PlanCommands) -> Result<(), Box<dyn std::error::Error>> {
    match subcmd {
        PlanCommands::Execute { file, confirm_each } => {
            execute_plan(cli, file, *confirm_each).await
        }
    }
}

/// Execute a saved plan file.
async fn execute_plan(
    cli: &Cli,
    file: &str,
    confirm_each: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(file)
        .map_err(|e| format!("Cannot read plan file '{file}': {e}"))?;
    let plan: Plan = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid plan JSON in '{file}': {e}"))?;

    tracing::info!(query = %plan.query, steps = plan.steps.len(), "executing plan");

    // Load manifests for tool validation
    let ati_dir = super::common::ati_dir();
    let manifests_dir = ati_dir.join("manifests");
    let registry = ManifestRegistry::load(&manifests_dir)?;

    // Validate all tools exist before running
    for (i, step) in plan.steps.iter().enumerate() {
        if registry.get_tool(&step.tool).is_none() {
            return Err(format!(
                "Step {}: unknown tool '{}'. Run 'ati tool list' to see available tools.",
                i + 1,
                step.tool
            )
            .into());
        }
    }

    let is_tty = std::io::stdin().is_terminal();

    for (i, step) in plan.steps.iter().enumerate() {
        tracing::info!(
            step = i + 1,
            total = plan.steps.len(),
            description = %step.description,
            "executing step"
        );

        // Build CLI args from step
        let mut raw_args = Vec::new();
        for (key, value) in &step.args {
            raw_args.push(format!("--{key}"));
            match value {
                Value::String(s) => raw_args.push(s.clone()),
                other => raw_args.push(other.to_string()),
            }
        }

        if confirm_each && is_tty {
            eprintln!("  ati run {} {}", step.tool, raw_args.join(" "));
            eprint!("  Execute? [Y/n] ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            let input = input.trim().to_lowercase();
            if input == "n" || input == "no" {
                eprintln!("  Skipped.");
                continue;
            }
        }

        // Execute the step
        match super::call::execute(cli, &step.tool, &raw_args).await {
            Ok(()) => {
                eprintln!("  [OK]");
            }
            Err(e) => {
                eprintln!("  [ERROR] {e}");
                if confirm_each && is_tty {
                    eprint!("  Continue with remaining steps? [Y/n] ");
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    let input = input.trim().to_lowercase();
                    if input == "n" || input == "no" {
                        return Err(format!("Plan execution aborted at step {}", i + 1).into());
                    }
                }
            }
        }
    }

    tracing::info!(steps = plan.steps.len(), "plan execution complete");
    Ok(())
}

/// LLM system prompt addition for plan mode.
pub const PLAN_SYSTEM_PROMPT_SUFFIX: &str = r#"

IMPORTANT: You MUST respond with ONLY a JSON object (no markdown, no explanation) in this exact format:
{"steps": [{"tool": "<tool_name>", "args": {"<key>": "<value>"}, "description": "<what this step does>"}]}

Each step should be a concrete tool call. Use real tool names from the available tools list. Include all required parameters with realistic placeholder values. Order steps logically."#;

/// Parse LLM response as a plan. Tries to extract JSON from the response,
/// handling cases where the LLM wraps it in markdown code blocks.
pub fn parse_plan_response(response: &str, query: &str) -> Result<Plan, String> {
    // Try direct JSON parse first
    if let Ok(val) = serde_json::from_str::<Value>(response) {
        return plan_from_value(&val, query);
    }

    // Try extracting from markdown code block
    let json_str = extract_json_from_markdown(response)
        .ok_or_else(|| "LLM response is not valid JSON and no JSON block found".to_string())?;

    let val: Value = serde_json::from_str(json_str)
        .map_err(|e| format!("Failed to parse extracted JSON: {e}"))?;

    plan_from_value(&val, query)
}

fn plan_from_value(val: &Value, query: &str) -> Result<Plan, String> {
    let steps_val = val.get("steps").ok_or("Missing 'steps' key in plan JSON")?;
    let steps_arr = steps_val.as_array().ok_or("'steps' is not an array")?;

    let mut steps = Vec::new();
    for (i, step_val) in steps_arr.iter().enumerate() {
        let tool = step_val
            .get("tool")
            .and_then(|t| t.as_str())
            .ok_or_else(|| format!("Step {}: missing 'tool' field", i + 1))?
            .to_string();
        let description = step_val
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string();
        let args: HashMap<String, Value> = step_val
            .get("args")
            .and_then(|a| serde_json::from_value(a.clone()).ok())
            .unwrap_or_default();

        steps.push(PlanStep {
            tool,
            args,
            description,
        });
    }

    Ok(Plan {
        query: query.to_string(),
        steps,
        created_at: chrono::Utc::now().to_rfc3339(),
    })
}

/// Extract JSON from a markdown code block (```json ... ``` or ``` ... ```).
fn extract_json_from_markdown(text: &str) -> Option<&str> {
    // Look for ```json\n...\n``` or ```\n...\n```
    let start_markers = ["```json\n", "```json\r\n", "```\n", "```\r\n"];
    for marker in &start_markers {
        if let Some(start) = text.find(marker) {
            let json_start = start + marker.len();
            if let Some(end) = text[json_start..].find("```") {
                return Some(text[json_start..json_start + end].trim());
            }
        }
    }
    None
}
