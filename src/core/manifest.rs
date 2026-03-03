use serde::{Deserialize, Serialize};
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
    Oauth2,
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
    /// Base URL for HTTP providers. Optional for MCP providers.
    #[serde(default)]
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
    /// Optional prefix for auth header value (e.g. "Token ", "Basic ").
    /// Used with auth_type = "header". Value becomes: "{prefix}{key}".
    #[serde(default)]
    pub auth_value_prefix: Option<String>,
    /// Additional headers to include on every request for this provider.
    /// Examples: X-Goog-FieldMask, X-EBAY-C-MARKETPLACE-ID
    #[serde(default)]
    pub extra_headers: HashMap<String, String>,
    /// Token URL for OAuth2 (relative to base_url or absolute)
    #[serde(default)]
    pub oauth2_token_url: Option<String>,
    /// Second key name for OAuth2 client_secret
    #[serde(default)]
    pub auth_secret_name: Option<String>,
    /// If true, send OAuth2 credentials via Basic Auth header instead of form body.
    /// Some providers (e.g. Sovos) require this per RFC 6749 §2.3.1.
    #[serde(default)]
    pub oauth2_basic_auth: bool,
    #[serde(default)]
    pub internal: bool,
    #[serde(default = "default_handler")]
    pub handler: String,

    // --- MCP provider fields (handler = "mcp") ---

    /// MCP transport type: "stdio" or "http"
    #[serde(default)]
    pub mcp_transport: Option<String>,
    /// Command to launch stdio MCP server (e.g., "npx", "uvx")
    #[serde(default)]
    pub mcp_command: Option<String>,
    /// Arguments for stdio command (e.g., ["-y", "@modelcontextprotocol/server-github"])
    #[serde(default)]
    pub mcp_args: Vec<String>,
    /// URL for HTTP/Streamable HTTP MCP server
    #[serde(default)]
    pub mcp_url: Option<String>,
    /// Environment variables to pass to stdio subprocess
    #[serde(default)]
    pub mcp_env: HashMap<String, String>,

    // --- OpenAPI provider fields (handler = "openapi") ---

    /// Path (relative to ~/.ati/specs/) or URL to OpenAPI spec (JSON or YAML)
    #[serde(default)]
    pub openapi_spec: Option<String>,
    /// Only include operations with these tags
    #[serde(default)]
    pub openapi_include_tags: Vec<String>,
    /// Exclude operations with these tags
    #[serde(default)]
    pub openapi_exclude_tags: Vec<String>,
    /// Only include operations with these operationIds
    #[serde(default)]
    pub openapi_include_operations: Vec<String>,
    /// Exclude operations with these operationIds
    #[serde(default)]
    pub openapi_exclude_operations: Vec<String>,
    /// Maximum number of operations to register (for huge APIs)
    #[serde(default)]
    pub openapi_max_operations: Option<usize>,
    /// Per-operationId overrides (hint, tags, description, response_extract, etc.)
    #[serde(default)]
    pub openapi_overrides: HashMap<String, OpenApiToolOverride>,

    // --- Optional metadata fields ---

    /// Provider category for discovery (e.g., "finance", "search", "social")
    #[serde(default)]
    pub category: Option<String>,
}

fn default_handler() -> String {
    "http".to_string()
}

/// Per-operationId overrides for OpenAPI-discovered tools.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct OpenApiToolOverride {
    pub hint: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub examples: Vec<String>,
    pub description: Option<String>,
    pub scope: Option<String>,
    pub response_extract: Option<String>,
    pub response_format: Option<String>,
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

    // --- Optional metadata fields ---

    /// Tags for discovery (e.g., ["search", "real-time"])
    #[serde(default)]
    pub tags: Vec<String>,
    /// Short hint for the LLM on when to use this tool
    #[serde(default)]
    pub hint: Option<String>,
    /// Example invocations
    #[serde(default)]
    pub examples: Vec<String>,
}

/// A parsed manifest file: one provider + multiple tools.
/// For MCP providers, tools may be empty — they're discovered dynamically via tools/list.
#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub provider: Provider,
    #[serde(default, rename = "tools")]
    pub tools: Vec<Tool>,
}

/// A tool discovered from an MCP server via tools/list.
/// Converted into a Tool for the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolDef {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, rename = "inputSchema")]
    pub input_schema: Option<serde_json::Value>,
}

/// Registry holding all loaded manifests, with indexes for fast lookup.
pub struct ManifestRegistry {
    manifests: Vec<Manifest>,
    /// tool_name -> (manifest_index, tool_index)
    tool_index: HashMap<String, (usize, usize)>,
}

impl ManifestRegistry {
    /// Load all .toml manifests from a directory.
    /// OpenAPI providers (handler = "openapi") have their specs loaded and tools auto-registered.
    pub fn load(dir: &Path) -> Result<Self, ManifestError> {
        if !dir.is_dir() {
            return Err(ManifestError::NoDirectory(dir.display().to_string()));
        }

        let mut manifests = Vec::new();
        let mut tool_index = HashMap::new();

        let pattern = dir.join("*.toml");
        let entries = glob::glob(pattern.to_str().unwrap_or(""))
            .map_err(|e| ManifestError::NoDirectory(e.to_string()))?;

        // Resolve specs dir: sibling of manifests dir (e.g., ~/.ati/specs/)
        let specs_dir = dir.parent().map(|p| p.join("specs"));

        for entry in entries {
            let path = entry.map_err(|e| ManifestError::Io(format!("{e}"), std::io::Error::other("glob error")))?;
            let contents = std::fs::read_to_string(&path)
                .map_err(|e| ManifestError::Io(path.display().to_string(), e))?;
            let mut manifest: Manifest = toml::from_str(&contents)
                .map_err(|e| ManifestError::Parse(path.display().to_string(), e))?;

            // For OpenAPI providers, load spec and register tools
            if manifest.provider.is_openapi() {
                if let Some(spec_ref) = &manifest.provider.openapi_spec {
                    match crate::core::openapi::load_and_register(&manifest.provider, spec_ref, specs_dir.as_deref()) {
                        Ok(tools) => {
                            manifest.tools = tools;
                        }
                        Err(e) => {
                            eprintln!(
                                "Warning: failed to load OpenAPI spec for provider '{}': {e}",
                                manifest.provider.name
                            );
                            // Graceful degradation — continue without tools
                        }
                    }
                }
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

    /// Create an empty registry (no manifests loaded).
    pub fn empty() -> Self {
        ManifestRegistry {
            manifests: Vec::new(),
            tool_index: HashMap::new(),
        }
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

    /// List all MCP providers (handler = "mcp").
    pub fn list_mcp_providers(&self) -> Vec<&Provider> {
        self.manifests
            .iter()
            .filter(|m| m.provider.handler == "mcp")
            .map(|m| &m.provider)
            .collect()
    }

    /// List all OpenAPI providers (handler = "openapi").
    pub fn list_openapi_providers(&self) -> Vec<&Provider> {
        self.manifests
            .iter()
            .filter(|m| m.provider.handler == "openapi")
            .map(|m| &m.provider)
            .collect()
    }

    /// Register dynamically discovered MCP tools for a provider.
    /// Tools are prefixed with provider name: "github__read_file".
    pub fn register_mcp_tools(&mut self, provider_name: &str, mcp_tools: Vec<McpToolDef>) {
        // Find the manifest for this provider
        let mi = match self
            .manifests
            .iter()
            .position(|m| m.provider.name == provider_name)
        {
            Some(idx) => idx,
            None => return,
        };

        for mcp_tool in mcp_tools {
            let prefixed_name = format!("{}__{}", provider_name, mcp_tool.name);

            let tool = Tool {
                name: prefixed_name.clone(),
                description: mcp_tool.description.unwrap_or_default(),
                endpoint: String::new(),
                method: HttpMethod::Post,
                scope: Some(format!("tool:{prefixed_name}")),
                input_schema: mcp_tool.input_schema,
                response: None,
                tags: Vec::new(),
                hint: None,
                examples: Vec::new(),
            };

            let ti = self.manifests[mi].tools.len();
            self.manifests[mi].tools.push(tool);
            self.tool_index.insert(prefixed_name, (mi, ti));
        }
    }
}

impl Provider {
    /// Returns true if this provider uses MCP protocol.
    pub fn is_mcp(&self) -> bool {
        self.handler == "mcp"
    }

    /// Returns true if this provider uses OpenAPI spec-based tool discovery.
    pub fn is_openapi(&self) -> bool {
        self.handler == "openapi"
    }

    /// Returns the MCP transport type, defaulting to "stdio".
    pub fn mcp_transport_type(&self) -> &str {
        self.mcp_transport.as_deref().unwrap_or("stdio")
    }
}
