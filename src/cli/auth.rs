use std::path::PathBuf;

use crate::core::scope::ScopeConfig;
use crate::{AuthCommands, Cli, OutputFormat};

fn ati_dir() -> PathBuf {
    std::env::var("ATI_DIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".ati"))
                .unwrap_or_else(|_| PathBuf::from(".ati"))
        })
}

/// Execute: ati auth <subcommand>
pub async fn execute(
    cli: &Cli,
    subcmd: &AuthCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match subcmd {
        AuthCommands::Status => show_status(cli),
    }
}

fn show_status(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let ati_dir = ati_dir();
    let scopes_path = ati_dir.join("scopes.json");

    if !scopes_path.exists() {
        println!("No scopes configured (running in unrestricted mode)");
        return Ok(());
    }

    let scopes = ScopeConfig::load(&scopes_path)?;

    match cli.output {
        OutputFormat::Json => {
            let info = serde_json::json!({
                "agent_id": scopes.agent_id,
                "job_id": scopes.job_id,
                "tool_scopes": scopes.tool_scope_count(),
                "skill_scopes": scopes.skill_scope_count(),
                "help_enabled": scopes.help_enabled(),
                "expires_at": scopes.expires_at,
                "time_remaining_secs": scopes.time_remaining(),
                "expired": scopes.is_expired(),
            });
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        OutputFormat::Table | OutputFormat::Text => {
            println!("Agent:   {}", scopes.agent_id);
            println!("Job:     {}", scopes.job_id);

            let tool_count = scopes.tool_scope_count();
            let skill_count = scopes.skill_scope_count();
            let help = if scopes.help_enabled() {
                "help enabled"
            } else {
                "help disabled"
            };
            println!("Scopes:  {tool_count} tools, {skill_count} skills, {help}");

            if let Some(remaining) = scopes.time_remaining() {
                if remaining == 0 {
                    println!("Expires: EXPIRED");
                } else {
                    let hours = remaining / 3600;
                    let minutes = (remaining % 3600) / 60;
                    let ts = chrono::DateTime::from_timestamp(scopes.expires_at as i64, 0)
                        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                        .unwrap_or_else(|| "unknown".into());
                    println!("Expires: {ts} ({hours}h {minutes}m remaining)");
                }
            } else {
                println!("Expires: never");
            }

            if scopes.is_expired() {
                eprintln!("\nWarning: Your session has expired. Tool calls will be denied.");
            }
        }
    }

    Ok(())
}
