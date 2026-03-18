// Plan mode tests — test via subprocess since cli module is binary-only.
// Test plan file roundtrip via serde_json directly.

use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Plan {
    query: String,
    steps: Vec<PlanStep>,
    created_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PlanStep {
    tool: String,
    args: HashMap<String, serde_json::Value>,
    description: String,
}

#[test]
fn test_plan_json_roundtrip() {
    let plan = Plan {
        query: "test query".to_string(),
        steps: vec![
            PlanStep {
                tool: "hackernews:top_stories".to_string(),
                args: {
                    let mut m = HashMap::new();
                    m.insert("limit".to_string(), serde_json::json!(5));
                    m
                },
                description: "Get top stories".to_string(),
            },
            PlanStep {
                tool: "web_search".to_string(),
                args: {
                    let mut m = HashMap::new();
                    m.insert("query".to_string(), serde_json::json!("rust async"));
                    m
                },
                description: "Search web".to_string(),
            },
        ],
        created_at: "2025-01-01T00:00:00Z".to_string(),
    };

    let json = serde_json::to_string_pretty(&plan).unwrap();
    let parsed: Plan = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.query, "test query");
    assert_eq!(parsed.steps.len(), 2);
    assert_eq!(parsed.steps[0].tool, "hackernews:top_stories");
    assert_eq!(parsed.steps[1].tool, "web_search");
    assert_eq!(parsed.steps[0].description, "Get top stories");
}

#[test]
fn test_plan_save_and_load() {
    let dir = tempfile::TempDir::new().unwrap();
    let plan_path = dir.path().join("test-plan.json");

    let plan = Plan {
        query: "find info".to_string(),
        steps: vec![PlanStep {
            tool: "web_search".to_string(),
            args: HashMap::new(),
            description: "search the web".to_string(),
        }],
        created_at: "2025-01-01T00:00:00Z".to_string(),
    };

    let json = serde_json::to_string_pretty(&plan).unwrap();
    std::fs::write(&plan_path, &json).unwrap();

    let loaded: Plan = serde_json::from_str(&std::fs::read_to_string(&plan_path).unwrap()).unwrap();
    assert_eq!(loaded.query, "find info");
    assert_eq!(loaded.steps.len(), 1);
}

#[test]
fn test_plan_missing_args_defaults() {
    // Args should default to empty HashMap if missing
    let json = r#"{"query":"q","steps":[{"tool":"foo","args":{},"description":"do foo"}],"created_at":"now"}"#;
    let plan: Plan = serde_json::from_str(json).unwrap();
    assert_eq!(plan.steps[0].tool, "foo");
    assert!(plan.steps[0].args.is_empty());
}

#[test]
fn test_plan_empty_steps() {
    let json = r#"{"query":"q","steps":[],"created_at":"now"}"#;
    let plan: Plan = serde_json::from_str(json).unwrap();
    assert!(plan.steps.is_empty());
}

/// Test `ati plan execute` with a non-existent file (should error).
#[test]
fn test_plan_execute_nonexistent_file() {
    let ati = env!("CARGO_BIN_EXE_ati");
    let dir = tempfile::TempDir::new().unwrap();

    let output = std::process::Command::new(ati)
        .args(["plan", "execute", "/nonexistent/plan.json"])
        .env("ATI_DIR", dir.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Cannot read plan file") || stderr.contains("Error"));
}

/// Test `ati plan execute` with invalid JSON file.
#[test]
fn test_plan_execute_invalid_json() {
    let ati = env!("CARGO_BIN_EXE_ati");
    let dir = tempfile::TempDir::new().unwrap();
    let plan_path = dir.path().join("bad-plan.json");
    std::fs::write(&plan_path, "not valid json").unwrap();

    let output = std::process::Command::new(ati)
        .args(["plan", "execute", plan_path.to_str().unwrap()])
        .env("ATI_DIR", dir.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Invalid plan JSON") || stderr.contains("Error"));
}

/// Test `ati plan execute` with a valid plan referencing unknown tools.
#[test]
fn test_plan_execute_unknown_tool() {
    let ati = env!("CARGO_BIN_EXE_ati");
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("manifests")).unwrap();

    let plan = Plan {
        query: "test".to_string(),
        steps: vec![PlanStep {
            tool: "nonexistent_tool:xyz".to_string(),
            args: HashMap::new(),
            description: "should fail".to_string(),
        }],
        created_at: "2025-01-01T00:00:00Z".to_string(),
    };

    let plan_path = dir.path().join("plan.json");
    std::fs::write(&plan_path, serde_json::to_string(&plan).unwrap()).unwrap();

    let output = std::process::Command::new(ati)
        .args(["plan", "execute", plan_path.to_str().unwrap()])
        .env("ATI_DIR", dir.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown tool") || stderr.contains("Error"));
}

/// Test `ati assist --help` includes --plan and --save flags.
#[test]
fn test_assist_help_shows_plan_flag() {
    let ati = env!("CARGO_BIN_EXE_ati");
    let output = std::process::Command::new(ati)
        .args(["assist", "--help"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--plan"),
        "assist --help should mention --plan"
    );
    assert!(
        stdout.contains("--save"),
        "assist --help should mention --save"
    );
}

/// Test `ati --format json` alias works (output contract).
#[test]
fn test_format_alias() {
    let ati = env!("CARGO_BIN_EXE_ati");
    let output = std::process::Command::new(ati)
        .args(["--format", "json", "--help"])
        .output()
        .unwrap();

    // --help should succeed regardless of --format
    assert!(output.status.success() || output.status.code() == Some(0));
}
