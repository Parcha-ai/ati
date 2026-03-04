use clap::{Parser, Subcommand, ValueEnum};
use std::process;

mod cli;
mod core;
mod output;
mod providers;
mod proxy;
mod security;

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Json,
    Table,
    Text,
}

#[derive(Parser, Debug)]
#[command(
    name = "ati",
    about = "Agent Tools Interface — secure CLI for AI agent tool execution",
    version,
    long_about = "ATI provides secure, scoped access to external tools for AI agents running in sandboxes.\n\
                   Keys are encrypted and never exposed to the agent or environment."
)]
pub struct Cli {
    #[arg(long, value_enum, default_value = "text", global = true)]
    pub output: OutputFormat,

    #[arg(long, global = true, help = "Enable verbose/debug output")]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Execute a tool by name
    Call {
        /// Tool name (e.g. web_search)
        tool_name: String,
        /// Tool arguments as --key value pairs
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// List, inspect, and discover tools
    #[command(subcommand)]
    Tools(ToolsCommands),

    /// Manage skill files (methodology docs for agents)
    #[command(subcommand)]
    Skills(SkillsCommands),

    /// LLM-powered tool discovery — ask what tool to use
    #[command(name = "assist")]
    Assist {
        /// Natural language query describing what you need
        query: String,
    },

    /// OpenAPI spec management — inspect and import API specs
    #[command(subcommand)]
    Openapi(OpenapiCommands),

    /// MCP provider management — add, list, remove MCP manifests
    #[command(subcommand)]
    Mcp(McpCommands),

    /// Authentication and scope information
    #[command(subcommand)]
    Auth(AuthCommands),

    /// JWT token management — keygen, issue, inspect, validate
    #[command(subcommand)]
    Token(TokenCommands),

    /// Initialize ~/.ati/ directory structure
    Init {
        /// Configure for proxy mode (generates JWT secret)
        #[arg(long)]
        proxy: bool,
        /// Use ES256 key pair instead of HS256 secret (requires --proxy)
        #[arg(long)]
        es256: bool,
    },

    /// Manage API keys in ~/.ati/credentials
    #[command(subcommand)]
    Keys(KeysCommands),

    /// Run ATI as a proxy server (holds keys, serves sandbox agents)
    Proxy {
        /// Port to listen on
        #[arg(long, default_value = "8090")]
        port: u16,
        /// Bind address (default: 127.0.0.1; use 0.0.0.0 to listen on all interfaces)
        #[arg(long)]
        bind: Option<String>,
        /// ATI directory (manifests, keyring, scopes)
        #[arg(long)]
        ati_dir: Option<String>,
        /// Load API keys from environment variables instead of keyring.enc
        #[arg(long)]
        env_keys: bool,
    },

    /// Print version information
    Version,
}

#[derive(Subcommand, Debug)]
pub enum ToolsCommands {
    /// List available tools (filtered by your scopes)
    List {
        /// Filter by provider name
        #[arg(long)]
        provider: Option<String>,
    },
    /// Show detailed info about a specific tool
    Info {
        /// Tool name
        name: String,
    },
    /// List loaded providers
    Providers,
    /// Search tools by name, description, or tags
    Search {
        /// Search query (fuzzy matches on name, description, tags, category)
        query: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum SkillsCommands {
    /// List available skills (with optional filters)
    List {
        /// Filter by category binding
        #[arg(long)]
        category: Option<String>,
        /// Filter by provider binding
        #[arg(long)]
        provider: Option<String>,
        /// Filter by tool binding
        #[arg(long)]
        tool: Option<String>,
    },
    /// Show a skill's content (prints SKILL.md)
    Show {
        /// Skill name
        name: String,
        /// Print only skill.toml metadata instead of SKILL.md
        #[arg(long)]
        meta: bool,
        /// Also print reference files
        #[arg(long)]
        refs: bool,
    },
    /// Search skills by name, description, keywords, or tools
    Search {
        /// Search query (fuzzy matches on name, description, keywords, tools)
        query: String,
    },
    /// Show skill.toml metadata and bindings
    Info {
        /// Skill name
        name: String,
    },
    /// Install a skill from a local directory or git
    Install {
        /// Path to skill directory (or multi-skill directory with --all)
        source: String,
        /// Clone from a git repository URL
        #[arg(long)]
        from_git: Option<String>,
        /// Override skill name
        #[arg(long)]
        name: Option<String>,
        /// Install all skills from a multi-skill directory
        #[arg(long)]
        all: bool,
    },
    /// Remove an installed skill
    Remove {
        /// Skill name to remove
        name: String,
    },
    /// Scaffold a new skill directory
    Init {
        /// Skill name
        name: String,
        /// Pre-populate tool bindings (comma-separated)
        #[arg(long, value_delimiter = ',')]
        tools: Vec<String>,
        /// Pre-populate provider binding
        #[arg(long)]
        provider: Option<String>,
    },
    /// Validate a skill's skill.toml and check tool references
    Validate {
        /// Skill name
        name: String,
        /// Also verify tool references exist in manifests
        #[arg(long)]
        check_tools: bool,
    },
    /// Show what skills auto-load for current scopes
    Resolve {
        /// Path to custom scopes.json
        #[arg(long)]
        scopes: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum OpenapiCommands {
    /// Inspect an OpenAPI spec — show operations, auth, base URL
    Inspect {
        /// Path or URL to the OpenAPI spec (JSON or YAML)
        spec: String,
        /// Only show operations with these tags
        #[arg(long)]
        include_tags: Vec<String>,
    },
    /// Import an OpenAPI spec — download to ~/.ati/specs/ and generate manifest
    Import {
        /// Path or URL to the OpenAPI spec (JSON or YAML)
        spec: String,
        /// Provider name for the generated manifest
        #[arg(long)]
        name: String,
        /// Keyring key name for the API key (default: {name}_api_key)
        #[arg(long)]
        auth_key: Option<String>,
        /// Only include operations with these tags
        #[arg(long)]
        include_tags: Vec<String>,
        /// Preview the generated manifest without saving
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum McpCommands {
    /// Add an MCP provider — generates a TOML manifest
    Add {
        /// Provider name (used as manifest filename and tool prefix)
        name: String,
        /// Transport type: http or stdio
        #[arg(long)]
        transport: String,
        /// MCP server URL (required for http transport)
        #[arg(long)]
        url: Option<String>,
        /// Command to run (required for stdio transport)
        #[arg(long)]
        command: Option<String>,
        /// Arguments for the stdio command (repeatable)
        #[arg(long, allow_hyphen_values = true)]
        args: Vec<String>,
        /// Environment variables for stdio as KEY=VALUE (repeatable)
        #[arg(long)]
        env: Vec<String>,
        /// Auth type: none, bearer, header (default: none)
        #[arg(long)]
        auth: Option<String>,
        /// Keyring key name for auth (required for bearer/header auth)
        #[arg(long)]
        auth_key: Option<String>,
        /// Custom header name for header auth
        #[arg(long)]
        auth_header: Option<String>,
        /// Provider description (default: "{name} MCP provider")
        #[arg(long)]
        description: Option<String>,
        /// Provider category
        #[arg(long)]
        category: Option<String>,
    },
    /// List configured MCP providers
    List,
    /// Remove an MCP provider manifest
    Remove {
        /// Provider name to remove
        name: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum KeysCommands {
    /// Store an API key
    Set {
        /// Key name (e.g. myapi_api_key)
        name: String,
        /// Key value (e.g. sk-xxx)
        value: String,
    },
    /// List stored API keys (values masked)
    List,
    /// Remove an API key
    Remove {
        /// Key name to remove
        name: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum AuthCommands {
    /// Show current scopes, agent info, and expiry
    Status,
}

#[derive(Subcommand, Debug)]
pub enum TokenCommands {
    /// Generate an ES256 key pair (or HS256 secret)
    Keygen {
        /// Algorithm: ES256 (default) or HS256
        #[arg(long, default_value = "ES256")]
        algorithm: String,
    },
    /// Issue (sign) a JWT with given claims
    Issue {
        /// Agent identity (JWT sub claim)
        #[arg(long)]
        sub: String,
        /// Space-delimited scopes (JWT scope claim)
        #[arg(long)]
        scope: String,
        /// Time-to-live in seconds (default: 1800 = 30 minutes)
        #[arg(long, default_value = "1800")]
        ttl: u64,
        /// Audience (default: ati-proxy)
        #[arg(long)]
        aud: Option<String>,
        /// Issuer
        #[arg(long)]
        iss: Option<String>,
        /// Path to ES256 private key PEM file
        #[arg(long)]
        key: Option<String>,
        /// HS256 shared secret (hex string)
        #[arg(long)]
        secret: Option<String>,
    },
    /// Decode a JWT without verification (show claims)
    Inspect {
        /// JWT token string
        token: String,
    },
    /// Fully verify a JWT (signature + expiry + audience + issuer)
    Validate {
        /// JWT token string
        token: String,
        /// Path to ES256 public key PEM file
        #[arg(long)]
        key: Option<String>,
        /// HS256 shared secret (hex string)
        #[arg(long)]
        secret: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::Call { tool_name, args } => cli::call::execute(&cli, tool_name, args).await,
        Commands::Tools(subcmd) => cli::tools::execute(&cli, subcmd).await,
        Commands::Skills(subcmd) => cli::skills::execute(&cli, subcmd).await,
        Commands::Assist { query } => cli::help::execute(&cli, query).await,
        Commands::Openapi(subcmd) => cli::openapi::execute(subcmd).await,
        Commands::Mcp(subcmd) => cli::mcp::execute(subcmd),
        Commands::Auth(subcmd) => cli::auth::execute(&cli, subcmd).await,
        Commands::Token(subcmd) => cli::token::execute(subcmd).map_err(|e| e as Box<dyn std::error::Error>),
        Commands::Init { proxy, es256 } => cli::init::execute(*proxy, *es256),
        Commands::Keys(subcmd) => cli::keys::execute(subcmd),
        Commands::Proxy { port, bind, ati_dir, env_keys } => {
            let dir = ati_dir
                .as_deref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(cli::common::ati_dir);
            proxy::server::run(*port, bind.clone(), dir, cli.verbose, *env_keys).await
        }
        Commands::Version => {
            println!("ati {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        if cli.verbose {
            // Print the full error chain
            let mut source = std::error::Error::source(&*e);
            while let Some(cause) = source {
                eprintln!("  caused by: {cause}");
                source = std::error::Error::source(cause);
            }
        }
        process::exit(1);
    }
}
