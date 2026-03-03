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

    /// Authentication and scope information
    #[command(subcommand)]
    Auth(AuthCommands),

    /// Run ATI as a proxy server (holds keys, serves sandbox agents)
    Proxy {
        /// Port to listen on
        #[arg(long, default_value = "8090")]
        port: u16,
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
pub enum AuthCommands {
    /// Show current scopes, agent info, and expiry
    Status,
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
        Commands::Auth(subcmd) => cli::auth::execute(&cli, subcmd).await,
        Commands::Proxy { port, ati_dir, env_keys } => {
            let dir = ati_dir
                .as_deref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| {
                    std::env::var("ATI_DIR")
                        .ok()
                        .map(std::path::PathBuf::from)
                        .unwrap_or_else(|| {
                            std::env::var("HOME")
                                .map(|h| std::path::PathBuf::from(h).join(".ati"))
                                .unwrap_or_else(|_| std::path::PathBuf::from(".ati"))
                        })
                });
            proxy::server::run(*port, dir, cli.verbose, *env_keys).await
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
