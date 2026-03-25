#![allow(dead_code)]
use tempfile::TempDir;

#[test]
fn test_parse_parallel_manifest() {
    let dir = TempDir::new().unwrap();
    let manifest_path = dir.path().join("parallel.toml");

    std::fs::write(
        &manifest_path,
        r#"
[provider]
name = "parallel"
description = "Parallel.ai web search"
base_url = "https://api.parallel.ai/v1"
auth_type = "bearer"
auth_key_name = "parallel_api_key"

[[tools]]
name = "web_search"
description = "Search the web"
endpoint = "/search"
method = "POST"
scope = "tool:web_search"

[tools.input_schema]
type = "object"
required = ["query"]

[tools.input_schema.properties.query]
type = "string"
description = "Search query"
"#,
    )
    .unwrap();

    let manifest: Manifest =
        toml::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();

    assert_eq!(manifest.provider.name, "parallel");
    assert_eq!(manifest.provider.base_url, "https://api.parallel.ai/v1");
    assert!(matches!(manifest.provider.auth_type, AuthType::Bearer));
    assert_eq!(
        manifest.provider.auth_key_name.as_deref(),
        Some("parallel_api_key")
    );
    assert!(!manifest.provider.internal);

    assert_eq!(manifest.tools.len(), 1);
    let tool = &manifest.tools[0];
    assert_eq!(tool.name, "web_search");
    assert_eq!(tool.endpoint, "/search");
    assert_eq!(tool.scope.as_deref(), Some("tool:web_search"));
    assert!(tool.input_schema.is_some());
}

#[test]
fn test_parse_no_auth_manifest() {
    let dir = TempDir::new().unwrap();
    let manifest_path = dir.path().join("pubmed.toml");

    std::fs::write(
        &manifest_path,
        r#"
[provider]
name = "pubmed"
description = "PubMed search"
base_url = "https://eutils.ncbi.nlm.nih.gov"
auth_type = "none"

[[tools]]
name = "search_pubmed"
description = "Search PubMed"
endpoint = "/esearch.fcgi"
method = "GET"
"#,
    )
    .unwrap();

    let manifest: Manifest =
        toml::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();

    assert!(matches!(manifest.provider.auth_type, AuthType::None));
    assert!(manifest.provider.auth_key_name.is_none());
    assert!(matches!(manifest.tools[0].method, HttpMethod::Get));
    assert!(manifest.tools[0].scope.is_none());
}

#[test]
fn test_parse_internal_manifest() {
    let manifest_str = r#"
[provider]
name = "_llm"
description = "LLM for ati help"
base_url = "https://api.cerebras.ai/v1"
auth_type = "bearer"
auth_key_name = "cerebras_api_key"
internal = true

[[tools]]
name = "_chat_completion"
description = "Chat completion"
endpoint = "/chat/completions"
method = "POST"
"#;

    let manifest: Manifest = toml::from_str(manifest_str).unwrap();
    assert!(manifest.provider.internal);
    assert_eq!(manifest.provider.name, "_llm");
}

#[test]
fn test_parse_multiple_tools() {
    let manifest_str = r#"
[provider]
name = "multi"
description = "Multi-tool provider"
base_url = "https://api.example.com"
auth_type = "bearer"
auth_key_name = "example_key"

[[tools]]
name = "tool_one"
description = "First tool"
endpoint = "/one"
method = "GET"
scope = "tool:tool_one"

[[tools]]
name = "tool_two"
description = "Second tool"
endpoint = "/two"
method = "POST"
scope = "tool:tool_two"

[[tools]]
name = "tool_three"
description = "Third tool"
endpoint = "/three"
method = "PUT"
"#;

    let manifest: Manifest = toml::from_str(manifest_str).unwrap();
    assert_eq!(manifest.tools.len(), 3);
    assert_eq!(manifest.tools[0].name, "tool_one");
    assert_eq!(manifest.tools[1].name, "tool_two");
    assert_eq!(manifest.tools[2].name, "tool_three");
    assert!(manifest.tools[2].scope.is_none());
}

#[test]
fn test_load_manifest_directory() {
    let dir = TempDir::new().unwrap();

    // Write two manifests
    std::fs::write(
        dir.path().join("provider_a.toml"),
        r#"
[provider]
name = "provider_a"
description = "Provider A"
base_url = "https://a.example.com"
auth_type = "none"

[[tools]]
name = "tool_a"
description = "Tool A"
endpoint = "/a"
method = "GET"
"#,
    )
    .unwrap();

    std::fs::write(
        dir.path().join("provider_b.toml"),
        r#"
[provider]
name = "provider_b"
description = "Provider B"
base_url = "https://b.example.com"
auth_type = "bearer"
auth_key_name = "b_key"

[[tools]]
name = "tool_b1"
description = "Tool B1"
endpoint = "/b1"
method = "POST"

[[tools]]
name = "tool_b2"
description = "Tool B2"
endpoint = "/b2"
method = "GET"
"#,
    )
    .unwrap();

    let registry = ManifestRegistry::load(dir.path()).unwrap();

    // Should find all 3 tools
    assert!(registry.get_tool("tool_a").is_some());
    assert!(registry.get_tool("tool_b1").is_some());
    assert!(registry.get_tool("tool_b2").is_some());
    assert!(registry.get_tool("nonexistent").is_none());

    // Check provider info is correct
    let (provider, tool) = registry.get_tool("tool_b1").unwrap();
    assert_eq!(provider.name, "provider_b");
    assert_eq!(tool.endpoint, "/b1");
}

#[test]
fn test_invalid_manifest_produces_error() {
    let dir = TempDir::new().unwrap();

    std::fs::write(
        dir.path().join("bad.toml"),
        "this is not valid TOML { { { }}}",
    )
    .unwrap();

    let result = ManifestRegistry::load(dir.path());
    assert!(result.is_err());
}

#[test]
fn test_nonexistent_directory_produces_error() {
    let result = ManifestRegistry::load(std::path::Path::new("/nonexistent/path"));
    assert!(result.is_err());
}

#[test]
fn test_parse_custom_auth_header_name() {
    let manifest_str = r#"
[provider]
name = "finnhub"
description = "Finnhub market data"
base_url = "https://finnhub.io/api/v1"
auth_type = "header"
auth_key_name = "finnhub_api_key"
auth_header_name = "X-Finnhub-Token"

[[tools]]
name = "quote"
description = "Get stock quote"
endpoint = "/quote"
method = "GET"
"#;

    let manifest: Manifest = toml::from_str(manifest_str).unwrap();
    assert!(matches!(manifest.provider.auth_type, AuthType::Header));
    assert_eq!(
        manifest.provider.auth_header_name.as_deref(),
        Some("X-Finnhub-Token")
    );
    assert_eq!(
        manifest.provider.auth_key_name.as_deref(),
        Some("finnhub_api_key")
    );
}

#[test]
fn test_parse_custom_auth_query_name() {
    let manifest_str = r#"
[provider]
name = "fred"
description = "FRED economic data"
base_url = "https://api.stlouisfed.org/fred"
auth_type = "query"
auth_key_name = "fred_api_key"
auth_query_name = "api_key"

[[tools]]
name = "series_search"
description = "Search FRED series"
endpoint = "/series/search"
method = "GET"
"#;

    let manifest: Manifest = toml::from_str(manifest_str).unwrap();
    assert!(matches!(manifest.provider.auth_type, AuthType::Query));
    assert_eq!(
        manifest.provider.auth_query_name.as_deref(),
        Some("api_key")
    );
}

#[test]
fn test_auth_names_default_to_none() {
    let manifest_str = r#"
[provider]
name = "test"
description = "Test"
base_url = "https://test.com"
auth_type = "header"
auth_key_name = "test_key"

[[tools]]
name = "test_tool"
description = "Test"
endpoint = "/test"
"#;

    let manifest: Manifest = toml::from_str(manifest_str).unwrap();
    assert!(manifest.provider.auth_header_name.is_none());
    assert!(manifest.provider.auth_query_name.is_none());
}

#[test]
fn test_response_config_parsing() {
    let manifest_str = r#"
[provider]
name = "test"
description = "Test"
base_url = "https://test.com"
auth_type = "none"

[[tools]]
name = "test_tool"
description = "Test tool"
endpoint = "/test"
method = "GET"

[tools.response]
extract = "$.results[*]"
format = "markdown_table"
"#;

    let manifest: Manifest = toml::from_str(manifest_str).unwrap();
    let response = manifest.tools[0].response.as_ref().unwrap();
    assert_eq!(response.extract.as_deref(), Some("$.results[*]"));
}

// --- Types mirrored from the binary ---

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

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
struct Provider {
    name: String,
    description: String,
    base_url: String,
    #[serde(default)]
    auth_type: AuthType,
    #[serde(default)]
    auth_key_name: Option<String>,
    #[serde(default)]
    auth_header_name: Option<String>,
    #[serde(default)]
    auth_query_name: Option<String>,
    #[serde(default)]
    internal: bool,
    #[serde(default)]
    skills: Vec<String>,
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
#[serde(rename_all = "snake_case")]
enum ResponseFormat {
    MarkdownTable,
    Json,
    #[default]
    Text,
    Raw,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct ResponseConfig {
    #[serde(default)]
    extract: Option<String>,
    #[serde(default)]
    format: ResponseFormat,
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
struct Manifest {
    provider: Provider,
    #[serde(rename = "tools")]
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
            let manifest: Manifest = toml::from_str(&contents)?;

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

#[test]
fn test_parse_provider_skills_field() {
    let manifest_str = r#"
[provider]
name = "finnhub"
description = "Finnhub market data"
base_url = "https://finnhub.io/api/v1"
auth_type = "header"
auth_key_name = "finnhub_api_key"
auth_header_name = "X-Finnhub-Token"
skills = [
    "https://github.com/parcha-ai/ati-skills#finnhub-analysis",
    "https://github.com/example/skills#stock-research",
]

[[tools]]
name = "quote"
description = "Get stock quote"
endpoint = "/quote"
method = "GET"
"#;

    let manifest: Manifest = toml::from_str(manifest_str).unwrap();
    assert_eq!(manifest.provider.skills.len(), 2);
    assert_eq!(
        manifest.provider.skills[0],
        "https://github.com/parcha-ai/ati-skills#finnhub-analysis"
    );
    assert_eq!(
        manifest.provider.skills[1],
        "https://github.com/example/skills#stock-research"
    );
}

#[test]
fn test_parse_provider_skills_default_empty() {
    let manifest_str = r#"
[provider]
name = "simple"
description = "Simple provider"
base_url = "https://api.example.com"
auth_type = "none"

[[tools]]
name = "test"
description = "Test"
endpoint = "/test"
"#;

    let manifest: Manifest = toml::from_str(manifest_str).unwrap();
    assert!(manifest.provider.skills.is_empty());
}

// --- Auth generator TOML parsing tests (use real ATI types) ---

#[test]
fn test_parse_auth_generator_command() {
    let toml_str = r#"
[provider]
name = "brain"
description = "Brain CLI"
base_url = "http://backend:8001/grep"
auth_type = "bearer"

[provider.auth_generator]
type = "command"
command = "python3"
args = ["-c", "print('token-${JWT_SUB}')"]
cache_ttl_secs = 300
output_format = "text"
timeout_secs = 10

[provider.auth_generator.env]
BRAIN_SECRET = "${brain_cli_secret}"

[[tools]]
name = "brain_query"
description = "Query brain"
endpoint = "/query"
method = "POST"
"#;
    let manifest: ati::core::manifest::Manifest = toml::from_str(toml_str).unwrap();
    let gen = manifest.provider.auth_generator.as_ref().unwrap();
    assert!(matches!(
        gen.gen_type,
        ati::core::manifest::AuthGenType::Command
    ));
    assert_eq!(gen.command.as_deref(), Some("python3"));
    assert_eq!(gen.args.len(), 2);
    assert_eq!(gen.cache_ttl_secs, 300);
    assert!(matches!(
        gen.output_format,
        ati::core::manifest::AuthOutputFormat::Text
    ));
    assert_eq!(gen.timeout_secs, 10);
    assert_eq!(gen.env.get("BRAIN_SECRET").unwrap(), "${brain_cli_secret}");
}

#[test]
fn test_parse_auth_generator_script() {
    let toml_str = r#"
[provider]
name = "hmac_api"
description = "HMAC-signed API"
base_url = "https://api.example.com"
auth_type = "header"
auth_header_name = "X-Signature"

[provider.auth_generator]
type = "script"
interpreter = "python3"
script = """
import hmac, hashlib, os
print(hmac.new(os.environ['SECRET'].encode(), b'payload', hashlib.sha256).hexdigest())
"""
cache_ttl_secs = 60
output_format = "text"

[provider.auth_generator.env]
SECRET = "${hmac_secret}"

[[tools]]
name = "hmac_call"
description = "Make HMAC-signed call"
endpoint = "/data"
"#;
    let manifest: ati::core::manifest::Manifest = toml::from_str(toml_str).unwrap();
    let gen = manifest.provider.auth_generator.as_ref().unwrap();
    assert!(matches!(
        gen.gen_type,
        ati::core::manifest::AuthGenType::Script
    ));
    assert_eq!(gen.interpreter.as_deref(), Some("python3"));
    assert!(gen.script.as_ref().unwrap().contains("hmac"));
    assert_eq!(gen.cache_ttl_secs, 60);
}

#[test]
fn test_parse_auth_generator_json_inject() {
    let toml_str = r#"
[provider]
name = "aws_sts"
description = "AWS STS"
base_url = "https://api.aws.example.com"
auth_type = "header"

[provider.auth_generator]
type = "command"
command = "aws"
args = ["sts", "assume-role", "--role-arn", "${aws_role_arn}", "--output", "json"]
cache_ttl_secs = 840
output_format = "json"

[provider.auth_generator.inject]
"Credentials.AccessKeyId" = { type = "header", name = "X-Aws-Access-Key-Id" }
"Credentials.SecretAccessKey" = { type = "env", name = "AWS_SECRET_ACCESS_KEY" }
"Credentials.SessionToken" = { type = "header", name = "X-Aws-Security-Token" }

[[tools]]
name = "aws_call"
description = "AWS API call"
endpoint = "/resource"
"#;
    let manifest: ati::core::manifest::Manifest = toml::from_str(toml_str).unwrap();
    let gen = manifest.provider.auth_generator.as_ref().unwrap();
    assert!(matches!(
        gen.output_format,
        ati::core::manifest::AuthOutputFormat::Json
    ));
    assert_eq!(gen.inject.len(), 3);

    let access_key_target = gen.inject.get("Credentials.AccessKeyId").unwrap();
    assert_eq!(access_key_target.inject_type, "header");
    assert_eq!(access_key_target.name, "X-Aws-Access-Key-Id");

    let secret_target = gen.inject.get("Credentials.SecretAccessKey").unwrap();
    assert_eq!(secret_target.inject_type, "env");
    assert_eq!(secret_target.name, "AWS_SECRET_ACCESS_KEY");
}

#[test]
fn test_parse_no_auth_generator() {
    let toml_str = r#"
[provider]
name = "simple"
description = "No generator"
base_url = "https://api.example.com"
auth_type = "bearer"
auth_key_name = "api_key"

[[tools]]
name = "simple_call"
description = "Simple call"
endpoint = "/data"
"#;
    let manifest: ati::core::manifest::Manifest = toml::from_str(toml_str).unwrap();
    assert!(manifest.provider.auth_generator.is_none());
}

#[test]
fn test_parse_auth_generator_defaults() {
    let toml_str = r#"
[provider]
name = "minimal"
description = "Minimal generator"
base_url = "https://api.example.com"
auth_type = "bearer"

[provider.auth_generator]
type = "command"
command = "echo"
args = ["token"]

[[tools]]
name = "test"
description = "Test"
endpoint = "/test"
"#;
    let manifest: ati::core::manifest::Manifest = toml::from_str(toml_str).unwrap();
    let gen = manifest.provider.auth_generator.as_ref().unwrap();
    assert_eq!(gen.cache_ttl_secs, 0);
    assert!(matches!(
        gen.output_format,
        ati::core::manifest::AuthOutputFormat::Text
    ));
    assert_eq!(gen.timeout_secs, 30); // default
    assert!(gen.env.is_empty());
    assert!(gen.inject.is_empty());
}
