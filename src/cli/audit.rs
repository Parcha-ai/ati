use crate::core::audit;
use crate::{AuditCommands, Cli, OutputFormat};

pub fn execute(cli: &Cli, subcmd: &AuditCommands) -> Result<(), Box<dyn std::error::Error>> {
    match subcmd {
        AuditCommands::Tail { n } => tail(cli, *n),
        AuditCommands::Search { tool, since } => search(cli, tool.as_deref(), since.as_deref()),
    }
}

fn tail(cli: &Cli, n: usize) -> Result<(), Box<dyn std::error::Error>> {
    let entries = audit::tail(n)?;
    if entries.is_empty() {
        eprintln!("No audit entries found.");
        return Ok(());
    }
    output_entries(cli, &entries);
    Ok(())
}

fn search(
    cli: &Cli,
    tool: Option<&str>,
    since: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let entries = audit::search(tool, since)?;
    if entries.is_empty() {
        eprintln!("No matching audit entries found.");
        return Ok(());
    }
    eprintln!("Found {} entries", entries.len());
    output_entries(cli, &entries);
    Ok(())
}

fn output_entries(cli: &Cli, entries: &[audit::AuditEntry]) {
    match cli.output {
        OutputFormat::Json => {
            let json = serde_json::to_string(&entries).unwrap_or_default();
            println!("{json}");
        }
        _ => {
            for entry in entries {
                let status_marker = if entry.status == audit::AuditStatus::Ok {
                    "OK"
                } else {
                    "ERR"
                };
                let error_info = entry.error.as_deref().unwrap_or("");
                println!(
                    "{} [{}] {} ({}ms) agent={} {}",
                    entry.ts,
                    status_marker,
                    entry.tool,
                    entry.duration_ms,
                    entry.agent_sub,
                    error_info
                );
            }
        }
    }
}
