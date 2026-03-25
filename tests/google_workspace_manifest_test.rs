#![allow(dead_code)]
use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use tempfile::TempDir;

// --- Types mirrored from the binary (subset needed for CLI provider testing) ---

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
enum AuthType {
    Bearer,
    Header,
    Query,
    Basic,
    #[default]
    None,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[derive(Default)]
enum HttpMethod {
    #[serde(alias = "get", alias = "Get")]
    #[default]
    Get,
    #[serde(alias = "post", alias = "Post")]
    Post,
    #[serde(alias = "put", alias = "Put")]
    Put,
    #[serde(alias = "delete", alias = "Delete")]
    Delete,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct ResponseConfig {
    #[serde(default)]
    extract: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Tool {
    name: String,
    description: String,
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    method: HttpMethod,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    input_schema: Option<serde_json::Value>,
    #[serde(default)]
    response: Option<ResponseConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct Provider {
    name: String,
    description: String,
    #[serde(default)]
    base_url: String,
    #[serde(default)]
    auth_type: AuthType,
    #[serde(default)]
    auth_key_name: Option<String>,
    #[serde(default)]
    internal: bool,
    #[serde(default)]
    handler: String,
    #[serde(default)]
    cli_command: Option<String>,
    #[serde(default)]
    cli_default_args: Vec<String>,
    #[serde(default)]
    cli_env: HashMap<String, String>,
    #[serde(default)]
    cli_timeout_secs: Option<u64>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    skills: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Manifest {
    provider: Provider,
    #[serde(default, rename = "tools")]
    tools: Vec<Tool>,
}

struct ManifestRegistry {
    manifests: Vec<Manifest>,
    tool_index: HashMap<String, (usize, usize)>,
}

impl ManifestRegistry {
    fn load(dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if !dir.is_dir() {
            return Err(format!("Not a directory: {}", dir.display()).into());
        }

        let mut manifests = Vec::new();
        let mut tool_index = HashMap::new();

        let pattern = dir.join("*.toml");
        let entries = glob::glob(pattern.to_str().unwrap())?;

        for entry in entries {
            let path = entry?;
            let contents = std::fs::read_to_string(&path)?;
            let mut manifest: Manifest = toml::from_str(&contents)?;

            // Mirror the auto-register logic for CLI providers
            if manifest.provider.handler == "cli" && manifest.tools.is_empty() {
                manifest.tools.push(Tool {
                    name: manifest.provider.name.clone(),
                    description: manifest.provider.description.clone(),
                    endpoint: String::new(),
                    method: HttpMethod::Get,
                    scope: None,
                    input_schema: None,
                    response: None,
                });
            }

            let mi = manifests.len();
            for (ti, tool) in manifest.tools.iter().enumerate() {
                tool_index.insert(tool.name.clone(), (mi, ti));
            }
            manifests.push(manifest);
        }

        Ok(ManifestRegistry {
            manifests,
            tool_index,
        })
    }

    fn get_tool(&self, name: &str) -> Option<(&Provider, &Tool)> {
        self.tool_index.get(name).map(|(mi, ti)| {
            let m = &self.manifests[*mi];
            (&m.provider, &m.tools[*ti])
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_parse_google_workspace_manifest() {
    let manifest_str = include_str!("../manifests/google-workspace.toml");
    let manifest: Manifest = toml::from_str(manifest_str).unwrap();

    assert_eq!(manifest.provider.name, "google_workspace");
    assert_eq!(manifest.provider.handler, "cli");
    assert_eq!(manifest.provider.cli_command.as_deref(), Some("gws"));
    assert!(manifest.provider.cli_default_args.is_empty());
    assert_eq!(manifest.provider.cli_timeout_secs, Some(120));
    assert!(matches!(manifest.provider.auth_type, AuthType::None));
    assert_eq!(manifest.provider.category.as_deref(), Some("productivity"));
    assert!(!manifest.provider.internal);

    // CLI env should have the credential file reference for headless auth
    assert_eq!(
        manifest
            .provider
            .cli_env
            .get("GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE"),
        Some(&"@{google_workspace_credentials}".to_string())
    );

    // Tags
    assert!(manifest.provider.tags.contains(&"google".to_string()));
    assert!(manifest.provider.tags.contains(&"gmail".to_string()));
    assert!(manifest.provider.tags.contains(&"drive".to_string()));

    // No explicit [[tools]] — should be empty before auto-registration
    assert!(manifest.tools.is_empty());
}

#[test]
fn test_google_workspace_auto_registers_implicit_tool() {
    let dir = TempDir::new().unwrap();
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/manifests/google-workspace.toml"
        ),
        dir.path().join("google-workspace.toml"),
    )
    .unwrap();

    let registry = ManifestRegistry::load(dir.path()).unwrap();

    // Should auto-register an implicit tool named after the provider
    let result = registry.get_tool("google_workspace");
    assert!(
        result.is_some(),
        "implicit tool 'google_workspace' should exist"
    );

    let (provider, tool) = result.unwrap();
    assert_eq!(provider.name, "google_workspace");
    assert_eq!(tool.name, "google_workspace");
    assert_eq!(tool.description, provider.description);
    assert!(tool.endpoint.is_empty());
}

#[test]
fn test_google_workspace_cli_env_uses_file_materialization() {
    let manifest_str = include_str!("../manifests/google-workspace.toml");
    let manifest: Manifest = toml::from_str(manifest_str).unwrap();

    // @{...} syntax means file materialization (temp file, 0600, wiped on drop)
    let cred_val = manifest
        .provider
        .cli_env
        .get("GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE")
        .expect("GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE should be set");

    assert!(
        cred_val.starts_with("@{"),
        "should use @{{}} file materialization syntax, got: {}",
        cred_val
    );
    assert!(
        cred_val.ends_with('}'),
        "should end with }}, got: {}",
        cred_val
    );
}
