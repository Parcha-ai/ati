#![allow(dead_code, clippy::too_many_arguments, clippy::type_complexity)]

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
    #[arg(
        long,
        value_enum,
        default_value = "json",
        global = true,
        env = "ATI_OUTPUT",
        alias = "format"
    )]
    pub output: OutputFormat,

    #[arg(
        short = 'J',
        long = "json",
        global = true,
        help = "Shorthand for --output json"
    )]
    pub json: bool,

    #[arg(long, global = true, help = "Enable verbose/debug output")]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Execute a tool by name
    #[command(
        after_help = "Examples:\n  ati run web_search --query \"rust async\"\n  ati run github:search_repositories --query \"ati\" -J\n  ati run get_stock_quote --symbol AAPL --output json"
    )]
    Run {
        /// Tool name (e.g. web_search)
        tool_name: String,
        /// Tool arguments as --key value pairs
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// List, inspect, and discover tools
    #[command(subcommand)]
    Tool(ToolCommands),

    /// Manage skill files (methodology docs for agents)
    #[command(subcommand)]
    Skill(SkillCommands),

    /// Lazily read remote skills from the GCS registry without installing them
    #[command(name = "skillati", subcommand)]
    SkillAti(SkillAtiCommands),

    /// LLM-powered tool discovery — ask what tool to use
    #[command(name = "assist")]
    Assist {
        /// Optional tool/provider scope, followed by the query
        #[arg(trailing_var_arg = true, required = true)]
        args: Vec<String>,
        /// Return a structured plan of tool calls instead of prose
        #[arg(long)]
        plan: bool,
        /// Save the plan to a file (implies --plan)
        #[arg(long)]
        save: Option<String>,
        /// Use local LLM (ollama/llama.cpp) — no API key needed
        #[arg(long)]
        local: bool,
    },

    /// Execute a saved tool plan
    #[command(subcommand)]
    Plan(PlanCommands),

    /// Unified provider management — MCP, OpenAPI, and HTTP providers
    #[command(
        subcommand,
        name = "provider",
        after_help = "Examples:\n  ati provider list\n  ati provider add-mcp serpapi --transport http --url https://mcp.serpapi.com/mcp\n  ati provider import-openapi https://api.example.com/openapi.json --name example\n  ati provider remove old_provider"
    )]
    Provider(ProviderCommands),

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
    Key(KeyCommands),

    /// Query the audit log
    #[command(subcommand)]
    Audit(AuditCommands),

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
}

#[derive(Subcommand, Debug)]
pub enum ToolCommands {
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
    /// Search tools by name, description, or tags
    Search {
        /// Search query (fuzzy matches on name, description, tags, category)
        query: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum SkillCommands {
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
    /// Install a skill from a local directory, git URL, or HTTPS URL
    Install {
        /// Path or URL to skill (git URL, or local directory)
        source: String,
        /// Clone from a git repository URL (deprecated: URLs are auto-detected)
        #[arg(long)]
        from_git: Option<String>,
        /// Override skill name
        #[arg(long)]
        name: Option<String>,
        /// Install all skills from a multi-skill directory
        #[arg(long)]
        all: bool,
        /// Use local LLM (ollama) for manifest generation — zero network calls
        #[arg(long)]
        local: bool,
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
    /// Read skill content for agent consumption (no decoration)
    Read {
        /// Skill name (omit if using --tool)
        name: Option<String>,
        /// Read all skills bound to this tool
        #[arg(long)]
        tool: Option<String>,
        /// Inline reference file contents after SKILL.md
        #[arg(long)]
        with_refs: bool,
    },
    /// Show what skills auto-load for current scopes
    Resolve {
        /// Path to custom scopes.json
        #[arg(long)]
        scopes: Option<String>,
    },
    /// Verify integrity of an installed skill
    Verify {
        /// Skill name
        name: String,
    },
    /// Show diff between installed and source skill
    Diff {
        /// Skill source (URL or path, with optional @SHA)
        source: String,
    },
    /// Update an installed skill from its source
    Update {
        /// Skill name
        name: String,
        /// Force update even if content hash changed
        #[arg(long)]
        force: bool,
    },
    /// View remote skills via the lazy GCS registry
    Fetch {
        /// SkillATI-style subcommands (catalog, read, resources, cat, refs, ref, build-index)
        #[command(subcommand)]
        fetch: SkillAtiCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum SkillAtiCommands {
    /// List remote skills available from the GCS registry
    Catalog {
        /// Optional fuzzy search over remote skill name/description
        #[arg(long)]
        search: Option<String>,
    },
    /// Read SKILL.md for a remote skill from the GCS registry
    Read {
        /// Skill name
        name: String,
    },
    /// List bundled resources for a remote skill without reading file contents
    Resources {
        /// Skill name
        name: String,
        /// Optional resource prefix to filter on, e.g. references/ or scripts/
        #[arg(long)]
        prefix: Option<String>,
    },
    /// Read a skill-relative file path, including nested references, scripts, or assets
    Cat {
        /// Skill name
        name: String,
        /// Skill-relative path, e.g. references/foo.md or ../other-skill/SKILL.md
        path: String,
    },
    /// List available on-demand reference files for a remote skill
    Refs {
        /// Skill name
        name: String,
    },
    /// Read a single reference file for a remote skill
    Ref {
        /// Skill name
        name: String,
        /// Reference file name under references/
        reference: String,
    },
    /// Build a SkillATI catalog manifest from a local skills directory for GCS publishing
    #[command(name = "build-index")]
    BuildIndex {
        /// Directory containing one subdirectory per skill, or a single skill directory
        source_dir: String,
        /// Optional file path to write the manifest JSON to
        #[arg(long = "output-file")]
        output_file: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ProviderCommands {
    /// Add an MCP provider — generates a TOML manifest
    #[command(name = "add-mcp")]
    AddMcp {
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

    /// Add a CLI provider — register a local CLI tool for use through ATI
    #[command(name = "add-cli")]
    AddCli {
        /// Provider name (becomes the tool name for `ati run <name>`)
        name: String,
        /// Path to CLI binary (or name to resolve via PATH)
        #[arg(long)]
        command: String,
        /// Default args prepended to every invocation
        #[arg(long)]
        default_args: Vec<String>,
        /// Environment variables as KEY=VALUE (use ${key} for keyring, @{key} for credential file)
        #[arg(long)]
        env: Vec<String>,
        /// Provider description
        #[arg(long)]
        description: Option<String>,
        /// Provider category
        #[arg(long)]
        category: Option<String>,
        /// Default timeout in seconds (default: 120)
        #[arg(long)]
        timeout: Option<u64>,
    },

    /// Import an OpenAPI spec — download to ~/.ati/specs/ and generate manifest
    #[command(name = "import-openapi")]
    ImportOpenapi {
        /// Path or URL to the OpenAPI spec (JSON or YAML)
        spec: String,
        /// Provider name (derived from spec URL/path if omitted)
        #[arg(long)]
        name: Option<String>,
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

    /// Inspect an OpenAPI spec — show operations, auth, base URL
    #[command(name = "inspect-openapi")]
    InspectOpenapi {
        /// Path or URL to the OpenAPI spec (JSON or YAML)
        spec: String,
        /// Only show operations with these tags
        #[arg(long)]
        include_tags: Vec<String>,
    },

    /// List all configured providers (HTTP, MCP, OpenAPI)
    List,

    /// Remove a provider manifest
    Remove {
        /// Provider name to remove
        name: String,
    },

    /// Show provider details
    Info {
        /// Provider name
        name: String,
    },

    /// Load a provider ephemerally — fetch spec, detect auth, cache for immediate use
    #[command(
        after_help = "Examples:\n  ati provider load https://petstore3.swagger.io/api/v3/openapi.json --name petstore\n  ati provider load --mcp --transport http --url https://mcp.serpapi.com/mcp --name serpapi\n  ati provider load spec.json --name myapi --save"
    )]
    Load {
        /// Path or URL to OpenAPI spec (omit for --mcp mode)
        spec: Option<String>,
        /// Provider name
        #[arg(long)]
        name: String,
        /// Load as MCP provider instead of OpenAPI
        #[arg(long)]
        mcp: bool,
        /// MCP transport: http or stdio
        #[arg(long)]
        transport: Option<String>,
        /// MCP server URL (required for http transport)
        #[arg(long)]
        url: Option<String>,
        /// Command to run (required for stdio transport)
        #[arg(long)]
        command: Option<String>,
        /// Arguments for the stdio command (repeatable)
        #[arg(long, allow_hyphen_values = true)]
        args: Vec<String>,
        /// Environment variables as KEY=VALUE (repeatable, use ${keyring_ref} for secrets)
        #[arg(long)]
        env: Vec<String>,
        /// Auth type override (auto-detected for OpenAPI)
        #[arg(long)]
        auth: Option<String>,
        /// Keyring key name for auth
        #[arg(long)]
        auth_key: Option<String>,
        /// Custom header name for auth (e.g., x-api-key)
        #[arg(long)]
        auth_header: Option<String>,
        /// Custom query parameter name for auth
        #[arg(long)]
        auth_query: Option<String>,
        /// Save permanently (write TOML manifest) instead of caching
        #[arg(long)]
        save: bool,
        /// Cache TTL in seconds (default: 3600 = 1 hour)
        #[arg(long, default_value = "3600")]
        ttl: u64,
    },

    /// Install skills declared in a provider's manifest
    #[command(name = "install-skills")]
    InstallSkills {
        /// Provider name
        name: String,
    },

    /// Remove a cached (ephemeral) provider
    Unload {
        /// Provider name to unload
        name: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum KeyCommands {
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
        /// Rate limits as pattern=spec (e.g. "tool:github:*=10/hour")
        #[arg(long)]
        rate: Vec<String>,
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

#[derive(Subcommand, Debug)]
pub enum AuditCommands {
    /// Show recent audit entries
    Tail {
        /// Number of entries to show (default: 20)
        #[arg(short, long, default_value = "20")]
        n: usize,
    },
    /// Search audit entries
    Search {
        /// Filter by tool name (supports trailing wildcard, e.g. github:*)
        #[arg(long)]
        tool: Option<String>,
        /// Show entries since duration ago (e.g. 1h, 30m, 7d)
        #[arg(long)]
        since: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum PlanCommands {
    /// Execute a saved plan file
    Execute {
        /// Path to the plan JSON file
        file: String,
        /// Confirm each step before executing
        #[arg(long)]
        confirm_each: bool,
    },
}

#[tokio::main]
async fn main() {
    let mut cli = Cli::parse();

    // Resolve -J shorthand: if --json flag is set, override output to JSON
    if cli.json {
        cli.output = OutputFormat::Json;
    }

    cli::common::ensure_ati_dir();

    // Initialize structured logging (and optionally Sentry when compiled with --features sentry).
    let log_mode = match &cli.command {
        Commands::Proxy { .. } => core::logging::LogMode::Proxy,
        _ => core::logging::LogMode::Cli,
    };
    let _sentry_guard = core::logging::init(log_mode, cli.verbose);

    let result = match &cli.command {
        Commands::Run { tool_name, args } => cli::call::execute(&cli, tool_name, args).await,
        Commands::Tool(subcmd) => cli::tools::execute(&cli, subcmd).await,
        Commands::Skill(subcmd) => cli::skills::execute(&cli, subcmd).await,
        Commands::SkillAti(subcmd) => cli::skillati::execute(&cli, subcmd).await,
        Commands::Assist {
            args,
            plan,
            save,
            local,
        } => cli::help::execute_with_plan(&cli, args, *plan, save.as_deref(), *local).await,
        Commands::Plan(subcmd) => cli::plan::execute(&cli, subcmd).await,
        Commands::Provider(subcmd) => cli::provider::execute(&cli, subcmd).await,
        Commands::Auth(subcmd) => cli::auth::execute(&cli, subcmd).await,
        Commands::Token(subcmd) => {
            cli::token::execute(subcmd).map_err(|e| e as Box<dyn std::error::Error>)
        }
        Commands::Init { proxy, es256 } => cli::init::execute(*proxy, *es256),
        Commands::Key(subcmd) => cli::keys::execute(subcmd),
        Commands::Audit(subcmd) => cli::audit::execute(&cli, subcmd),
        Commands::Proxy {
            port,
            bind,
            ati_dir,
            env_keys,
        } => {
            let dir = ati_dir
                .as_deref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(cli::common::ati_dir);
            proxy::server::run(*port, bind.clone(), dir, cli.verbose, *env_keys).await
        }
    };

    if let Err(e) = result {
        let is_json = matches!(cli.output, OutputFormat::Json);
        if is_json {
            let error_json = core::error::format_structured_error(e.as_ref(), cli.verbose);
            eprintln!("{error_json}");
        } else {
            tracing::error!("{e}");
            if cli.verbose {
                let mut source = std::error::Error::source(e.as_ref());
                while let Some(cause) = source {
                    tracing::debug!("  caused by: {cause}");
                    source = std::error::Error::source(cause);
                }
            }
        }
        let exit_code = core::error::exit_code_for_error(e.as_ref());
        process::exit(exit_code);
    }
}
