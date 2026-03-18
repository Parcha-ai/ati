use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

/// Separator between provider name and tool name in compound tool identifiers.
/// Example: `"finnhub:quote"`, `"github:search_repositories"`.
pub const TOOL_SEP: char = ':';
pub const TOOL_SEP_STR: &str = ":";

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

    // --- CLI provider fields (handler = "cli") ---
    /// Command to run for CLI providers (e.g., "gsutil", "gh", "kubectl")
    #[serde(default)]
    pub cli_command: Option<String>,
    /// Default args prepended to every invocation
    #[serde(default)]
    pub cli_default_args: Vec<String>,
    /// Environment variables for CLI. ${key} = string from keyring, @{key} = credential file
    #[serde(default)]
    pub cli_env: HashMap<String, String>,
    /// Default timeout in seconds (default: 120)
    #[serde(default)]
    pub cli_timeout_secs: Option<u64>,

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

    // --- Auth generator (dynamic credential generation) ---
    /// Optional auth generator for producing short-lived credentials at call time.
    /// Runs where secrets live (proxy server in proxy mode, local machine in local mode).
    #[serde(default)]
    pub auth_generator: Option<AuthGenerator>,

    // --- Optional metadata fields ---
    /// Provider category for discovery (e.g., "finance", "search", "social")
    #[serde(default)]
    pub category: Option<String>,

    /// Associated skill URLs (git repos) that teach agents how to use this provider's tools.
    /// Each entry is a git URL, optionally with a #fragment for subdirectory.
    #[serde(default)]
    pub skills: Vec<String>,
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

/// Dynamic auth generator configuration — produces short-lived credentials at call time.
///
/// Two types:
/// - `command`: runs an external command, captures stdout as the credential
/// - `script`: writes an inline script to a temp file and runs it via an interpreter
///
/// Variable expansion in `args` and `env` values:
/// - `${key_name}` → keyring lookup
/// - `${JWT_SUB}` → agent's JWT `sub` claim
/// - `${JWT_SCOPE}` → agent's JWT `scope` claim
/// - `${TOOL_NAME}` → tool being invoked
/// - `${TIMESTAMP}` → current unix timestamp
#[derive(Debug, Clone, Deserialize)]
pub struct AuthGenerator {
    #[serde(rename = "type")]
    pub gen_type: AuthGenType,
    /// Command to run (for `type = "command"`)
    pub command: Option<String>,
    /// Arguments for the command
    #[serde(default)]
    pub args: Vec<String>,
    /// Interpreter for inline script (for `type = "script"`, e.g. "python3")
    pub interpreter: Option<String>,
    /// Inline script body (for `type = "script"`)
    pub script: Option<String>,
    /// TTL for cached credentials (0 = no cache)
    #[serde(default)]
    pub cache_ttl_secs: u64,
    /// Output format: "text" (trimmed stdout) or "json" (parsed, fields extracted via `inject`)
    #[serde(default)]
    pub output_format: AuthOutputFormat,
    /// Environment variables for the subprocess (values support `${key}` expansion)
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// For JSON output: map dot-notation JSON paths to injection targets
    #[serde(default)]
    pub inject: HashMap<String, InjectTarget>,
    /// Subprocess timeout in seconds (default: 30)
    #[serde(default = "default_gen_timeout")]
    pub timeout_secs: u64,
}

fn default_gen_timeout() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthGenType {
    Command,
    Script,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthOutputFormat {
    #[default]
    Text,
    Json,
}

/// Target for injecting a JSON-extracted credential value.
#[derive(Debug, Clone, Deserialize)]
pub struct InjectTarget {
    /// Where to inject: "header", "env", or "query"
    #[serde(rename = "type")]
    pub inject_type: String,
    /// Name of the header/env var/query param
    pub name: String,
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

/// A cached (ephemeral) provider, persisted as JSON in `$ATI_DIR/cache/providers/<name>.json`.
/// Used by `ati provider load` to make providers available across process invocations
/// without writing permanent TOML manifests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedProvider {
    pub name: String,
    /// "openapi" or "mcp"
    pub provider_type: String,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub auth_type: String,
    #[serde(default)]
    pub auth_key_name: Option<String>,
    #[serde(default)]
    pub auth_header_name: Option<String>,
    #[serde(default)]
    pub auth_query_name: Option<String>,
    // OpenAPI fields
    #[serde(default)]
    pub spec_content: Option<String>,
    // MCP fields
    #[serde(default)]
    pub mcp_transport: Option<String>,
    #[serde(default)]
    pub mcp_url: Option<String>,
    #[serde(default)]
    pub mcp_command: Option<String>,
    #[serde(default)]
    pub mcp_args: Vec<String>,
    #[serde(default)]
    pub mcp_env: HashMap<String, String>,
    // CLI fields
    #[serde(default)]
    pub cli_command: Option<String>,
    #[serde(default)]
    pub cli_default_args: Vec<String>,
    #[serde(default)]
    pub cli_env: HashMap<String, String>,
    #[serde(default)]
    pub cli_timeout_secs: Option<u64>,
    // MCP/HTTP auth
    #[serde(default)]
    pub auth: Option<String>,
    // Cache metadata
    pub created_at: String,
    pub ttl_seconds: u64,
}

impl CachedProvider {
    /// Returns true if this cached provider has expired.
    pub fn is_expired(&self) -> bool {
        let created = match DateTime::parse_from_rfc3339(&self.created_at) {
            Ok(dt) => dt.with_timezone(&Utc),
            Err(_) => return true, // Can't parse → treat as expired
        };
        let now = Utc::now();
        let elapsed = now.signed_duration_since(created);
        elapsed.num_seconds() as u64 > self.ttl_seconds
    }

    /// Returns the expiry time as an ISO timestamp.
    pub fn expires_at(&self) -> Option<String> {
        let created = DateTime::parse_from_rfc3339(&self.created_at).ok()?;
        let expires = created + chrono::Duration::seconds(self.ttl_seconds as i64);
        Some(expires.to_rfc3339())
    }

    /// Returns remaining TTL in seconds (0 if expired).
    pub fn remaining_seconds(&self) -> u64 {
        let created = match DateTime::parse_from_rfc3339(&self.created_at) {
            Ok(dt) => dt.with_timezone(&Utc),
            Err(_) => return 0,
        };
        let now = Utc::now();
        let elapsed = now.signed_duration_since(created).num_seconds() as u64;
        self.ttl_seconds.saturating_sub(elapsed)
    }

    /// Build a Provider struct from this cached entry.
    pub fn to_provider(&self) -> Provider {
        let auth_type = match self.auth_type.as_str() {
            "bearer" => AuthType::Bearer,
            "header" => AuthType::Header,
            "query" => AuthType::Query,
            "basic" => AuthType::Basic,
            "oauth2" => AuthType::Oauth2,
            _ => AuthType::None,
        };

        let handler = match self.provider_type.as_str() {
            "mcp" => "mcp".to_string(),
            "openapi" => "openapi".to_string(),
            _ => "http".to_string(),
        };

        Provider {
            name: self.name.clone(),
            description: format!("{} (cached)", self.name),
            base_url: self.base_url.clone(),
            auth_type,
            auth_key_name: self.auth_key_name.clone(),
            auth_header_name: self.auth_header_name.clone(),
            auth_query_name: self.auth_query_name.clone(),
            auth_value_prefix: None,
            extra_headers: HashMap::new(),
            oauth2_token_url: None,
            auth_secret_name: None,
            oauth2_basic_auth: false,
            internal: false,
            handler,
            mcp_transport: self.mcp_transport.clone(),
            mcp_command: self.mcp_command.clone(),
            mcp_args: self.mcp_args.clone(),
            mcp_url: self.mcp_url.clone(),
            mcp_env: self.mcp_env.clone(),
            openapi_spec: None,
            openapi_include_tags: Vec::new(),
            openapi_exclude_tags: Vec::new(),
            openapi_include_operations: Vec::new(),
            openapi_exclude_operations: Vec::new(),
            openapi_max_operations: None,
            openapi_overrides: HashMap::new(),
            cli_command: self.cli_command.clone(),
            cli_default_args: self.cli_default_args.clone(),
            cli_env: self.cli_env.clone(),
            cli_timeout_secs: self.cli_timeout_secs,
            auth_generator: None,
            category: None,
            skills: Vec::new(),
        }
    }
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
            let path = entry.map_err(|e| {
                ManifestError::Io(format!("{e}"), std::io::Error::other("glob error"))
            })?;
            let contents = std::fs::read_to_string(&path)
                .map_err(|e| ManifestError::Io(path.display().to_string(), e))?;
            let mut manifest: Manifest = toml::from_str(&contents)
                .map_err(|e| ManifestError::Parse(path.display().to_string(), e))?;

            // For OpenAPI providers, load spec and register tools
            if manifest.provider.is_openapi() {
                if let Some(spec_ref) = &manifest.provider.openapi_spec {
                    match crate::core::openapi::load_and_register(
                        &manifest.provider,
                        spec_ref,
                        specs_dir.as_deref(),
                    ) {
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

            // For CLI providers with no [[tools]], auto-register one implicit tool
            if manifest.provider.is_cli() && manifest.tools.is_empty() {
                manifest.tools.push(Tool {
                    name: manifest.provider.name.clone(),
                    description: manifest.provider.description.clone(),
                    endpoint: String::new(),
                    method: HttpMethod::Get,
                    scope: None,
                    input_schema: None,
                    response: None,
                    tags: Vec::new(),
                    hint: None,
                    examples: Vec::new(),
                });
            }

            let mi = manifests.len();
            for (ti, tool) in manifest.tools.iter().enumerate() {
                tool_index.insert(tool.name.clone(), (mi, ti));
            }
            manifests.push(manifest);
        }

        // Load cached providers from cache/providers/*.json
        // Cache dir is sibling of manifests dir: e.g., ~/.ati/cache/providers/
        if let Some(parent) = dir.parent() {
            let cache_dir = parent.join("cache").join("providers");
            if cache_dir.is_dir() {
                let cache_pattern = cache_dir.join("*.json");
                if let Ok(cache_entries) = glob::glob(cache_pattern.to_str().unwrap_or("")) {
                    for entry in cache_entries {
                        let path = match entry {
                            Ok(p) => p,
                            Err(_) => continue,
                        };
                        let content = match std::fs::read_to_string(&path) {
                            Ok(c) => c,
                            Err(_) => continue,
                        };
                        let cached: CachedProvider = match serde_json::from_str(&content) {
                            Ok(c) => c,
                            Err(_) => continue,
                        };

                        // Skip and delete expired entries
                        if cached.is_expired() {
                            let _ = std::fs::remove_file(&path);
                            continue;
                        }

                        // Skip if a permanent manifest with same provider name already exists
                        if manifests.iter().any(|m| m.provider.name == cached.name) {
                            continue;
                        }

                        let provider = cached.to_provider();

                        let mut cached_tools = Vec::new();
                        if cached.provider_type == "openapi" {
                            if let Some(spec_content) = &cached.spec_content {
                                if let Ok(spec) = crate::core::openapi::parse_spec(spec_content) {
                                    let filters = crate::core::openapi::OpenApiFilters {
                                        include_tags: vec![],
                                        exclude_tags: vec![],
                                        include_operations: vec![],
                                        exclude_operations: vec![],
                                        max_operations: None,
                                    };
                                    let defs = crate::core::openapi::extract_tools(&spec, &filters);
                                    cached_tools = defs
                                        .into_iter()
                                        .map(|def| {
                                            crate::core::openapi::to_ati_tool(
                                                def,
                                                &cached.name,
                                                &HashMap::new(),
                                            )
                                        })
                                        .collect();
                                }
                            }
                        }
                        // MCP providers have empty tools — lazy discovery at run time

                        let mi = manifests.len();
                        for (ti, tool) in cached_tools.iter().enumerate() {
                            tool_index.insert(tool.name.clone(), (mi, ti));
                        }
                        manifests.push(Manifest {
                            provider,
                            tools: cached_tools,
                        });
                    }
                }
            }
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

    /// If `tool_name` has a `<provider>:<name>` prefix matching an MCP provider, return it.
    pub fn find_mcp_provider_for_tool(&self, tool_name: &str) -> Option<&Provider> {
        let prefix = tool_name.split(TOOL_SEP).next()?;
        self.manifests
            .iter()
            .find(|m| m.provider.handler == "mcp" && m.provider.name == prefix)
            .map(|m| &m.provider)
    }

    /// List all OpenAPI providers (handler = "openapi").
    pub fn list_openapi_providers(&self) -> Vec<&Provider> {
        self.manifests
            .iter()
            .filter(|m| m.provider.handler == "openapi")
            .map(|m| &m.provider)
            .collect()
    }

    /// Check if a provider with the given name exists.
    pub fn has_provider(&self, name: &str) -> bool {
        self.manifests.iter().any(|m| m.provider.name == name)
    }

    /// Get tools belonging to a specific provider.
    pub fn tools_by_provider(&self, provider_name: &str) -> Vec<(&Provider, &Tool)> {
        self.manifests
            .iter()
            .filter(|m| m.provider.name == provider_name)
            .flat_map(|m| m.tools.iter().map(move |t| (&m.provider, t)))
            .collect()
    }

    /// List all CLI providers (handler = "cli").
    pub fn list_cli_providers(&self) -> Vec<&Provider> {
        self.manifests
            .iter()
            .filter(|m| m.provider.handler == "cli")
            .map(|m| &m.provider)
            .collect()
    }

    /// Register dynamically discovered MCP tools for a provider.
    /// Tools are prefixed with provider name: `"github:read_file"`.
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
            let prefixed_name = format!("{}{}{}", provider_name, TOOL_SEP_STR, mcp_tool.name);

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

    /// Returns true if this provider uses CLI handler.
    pub fn is_cli(&self) -> bool {
        self.handler == "cli"
    }

    /// Returns the MCP transport type, defaulting to "stdio".
    pub fn mcp_transport_type(&self) -> &str {
        self.mcp_transport.as_deref().unwrap_or("stdio")
    }
}
