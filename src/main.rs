use clap::{Parser, Subcommand, ValueEnum};
use std::process;

mod cli;
mod core;
mod output;
mod providers;
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
    Help {
        /// Natural language query describing what you need
        query: String,
    },

    /// Authentication and scope information
    #[command(subcommand)]
    Auth(AuthCommands),

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
}

#[derive(Subcommand, Debug)]
pub enum SkillsCommands {
    /// List available skills
    List,
    /// Show a skill's content (prints SKILL.md)
    Show {
        /// Skill name (directory name under ~/.ati/skills/)
        name: String,
    },
    /// Save a skill directory to ~/.ati/skills/
    Save {
        /// Path to the skill directory to save
        dir: String,
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
        Commands::Help { query } => cli::help::execute(&cli, query).await,
        Commands::Auth(subcmd) => cli::auth::execute(&cli, subcmd).await,
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
