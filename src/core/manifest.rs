use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ManifestError {
    #[error("Failed to read manifest file {0}: {1}")]
    Io(String, std::io::Error),
    #[error("Failed to parse manifest {0}: {1}")]
    Parse(String, toml::de::Error),
    #[error("No manifests directory found at {0}")]
    NoDirectory(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    Bearer,
    Header,
    Query,
    Basic,
    None,
}

impl Default for AuthType {
    fn default() -> Self {
        AuthType::None
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Provider {
    pub name: String,
    pub description: String,
    pub base_url: String,
    #[serde(default)]
    pub auth_type: AuthType,
    #[serde(default)]
    pub auth_key_name: Option<String>,
    /// Custom header name for auth_type = "header" (default: "X-Api-Key").
    /// Examples: "X-Finnhub-Token", "X-API-KEY", "Authorization"
    #[serde(default)]
    pub auth_header_name: Option<String>,
    /// Custom query parameter name for auth_type = "query" (default: "api_key").
    #[serde(default)]
    pub auth_query_name: Option<String>,
    #[serde(default)]
    pub internal: bool,
    #[serde(default = "default_handler")]
    pub handler: String,
}

fn default_handler() -> String {
    "http".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    #[serde(alias = "get", alias = "Get")]
    Get,
    #[serde(alias = "post", alias = "Post")]
    Post,
    #[serde(alias = "put", alias = "Put")]
    Put,
    #[serde(alias = "delete", alias = "Delete")]
    Delete,
}

impl Default for HttpMethod {
    fn default() -> Self {
        HttpMethod::Get
    }
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Delete => write!(f, "DELETE"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResponseFormat {
    MarkdownTable,
    Json,
    #[default]
    Text,
    Raw,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ResponseConfig {
    /// JSONPath expression to extract useful content from the API response
    #[serde(default)]
    pub extract: Option<String>,
    /// Output format for the extracted data
    #[serde(default)]
    pub format: ResponseFormat,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Tool {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub method: HttpMethod,
    /// Scope required to use this tool (e.g. "tool:web_search")
    #[serde(default)]
    pub scope: Option<String>,
    /// JSON Schema for tool input
    #[serde(default)]
    pub input_schema: Option<serde_json::Value>,
    /// Response extraction config
    #[serde(default)]
    pub response: Option<ResponseConfig>,
}

/// A parsed manifest file: one provider + multiple tools.
#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub provider: Provider,
    #[serde(rename = "tools")]
    pub tools: Vec<Tool>,
}

/// Registry holding all loaded manifests, with indexes for fast lookup.
pub struct ManifestRegistry {
    manifests: Vec<Manifest>,
    /// tool_name -> (manifest_index, tool_index)
    tool_index: HashMap<String, (usize, usize)>,
}

impl ManifestRegistry {
    /// Load all .toml manifests from a directory.
    pub fn load(dir: &Path) -> Result<Self, ManifestError> {
        if !dir.is_dir() {
            return Err(ManifestError::NoDirectory(dir.display().to_string()));
        }

        let mut manifests = Vec::new();
        let mut tool_index = HashMap::new();

        let pattern = dir.join("*.toml");
        let entries = glob::glob(pattern.to_str().unwrap_or(""))
            .map_err(|e| ManifestError::NoDirectory(e.to_string()))?;

        for entry in entries {
            let path = entry.map_err(|e| ManifestError::Io(format!("{e}"), std::io::Error::other("glob error")))?;
            let contents = std::fs::read_to_string(&path)
                .map_err(|e| ManifestError::Io(path.display().to_string(), e))?;
            let manifest: Manifest = toml::from_str(&contents)
                .map_err(|e| ManifestError::Parse(path.display().to_string(), e))?;

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

    /// Look up a tool by name. Returns the provider and tool definition.
    pub fn get_tool(&self, name: &str) -> Option<(&Provider, &Tool)> {
        self.tool_index.get(name).map(|(mi, ti)| {
            let m = &self.manifests[*mi];
            (&m.provider, &m.tools[*ti])
        })
    }

    /// List all tools across all providers.
    pub fn list_tools(&self) -> Vec<(&Provider, &Tool)> {
        self.manifests
            .iter()
            .flat_map(|m| m.tools.iter().map(move |t| (&m.provider, t)))
            .collect()
    }

    /// List all providers.
    pub fn list_providers(&self) -> Vec<&Provider> {
        self.manifests.iter().map(|m| &m.provider).collect()
    }

    /// List all non-internal tools (excludes providers marked internal=true).
    pub fn list_public_tools(&self) -> Vec<(&Provider, &Tool)> {
        self.manifests
            .iter()
            .filter(|m| !m.provider.internal)
            .flat_map(|m| m.tools.iter().map(move |t| (&m.provider, t)))
            .collect()
    }

    /// Get the number of loaded tools.
    pub fn tool_count(&self) -> usize {
        self.tool_index.len()
    }

    /// Get the number of loaded providers.
    pub fn provider_count(&self) -> usize {
        self.manifests.len()
    }
}
