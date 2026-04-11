use crate::cli::common;
use crate::core::skillati::{
    build_catalog_manifest, default_catalog_index_path, RemoteSkillMeta, SkillAtiActivation,
    SkillAtiClient, SkillAtiError, SkillAtiFile, SkillAtiFileData,
};
use crate::proxy::client as proxy_client;
use crate::{Cli, OutputFormat, SkillAtiCommands};
use std::path::Path;

/// Execute: ati skillati <subcommand>
pub async fn execute(
    cli: &Cli,
    subcmd: &SkillAtiCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    if let SkillAtiCommands::BuildIndex {
        source_dir,
        output_file,
    } = subcmd
    {
        return execute_build_index(cli, source_dir, output_file.as_deref());
    }

    if let Ok(proxy_url) = std::env::var("ATI_PROXY_URL") {
        return execute_via_proxy(cli, subcmd, &proxy_url).await;
    }

    let ati_dir = common::ati_dir();
    let keyring = crate::cli::call::load_keyring(&ati_dir);
    let client = SkillAtiClient::from_env(&keyring)?.ok_or(SkillAtiError::NotConfigured)?;

    match subcmd {
        SkillAtiCommands::Catalog { search } => {
            let mut catalog = client.catalog().await?;
            if let Some(query) = search {
                catalog = SkillAtiClient::filter_catalog(&catalog, query, 25);
            }
            print_catalog(cli, &catalog)?;
        }
        SkillAtiCommands::Read { name } => {
            let activation = client.read_skill(name).await?;
            print_activation(cli, &activation)?;
        }
        SkillAtiCommands::Resources { name, prefix } => {
            let resources = client.list_resources(name, prefix.as_deref()).await?;
            print_resources(cli, name, prefix.as_deref(), &resources)?;
        }
        SkillAtiCommands::Cat { name, path } => {
            let file = client.read_path(name, path).await?;
            print_file(cli, &file)?;
        }
        SkillAtiCommands::Refs { name } => {
            let references = client.list_references(name).await?;
            print_refs(cli, name, &references)?;
        }
        SkillAtiCommands::Ref { name, reference } => {
            let file = client
                .read_path(name, &format!("references/{reference}"))
                .await?;
            print_file(cli, &file)?;
        }
        SkillAtiCommands::BuildIndex { .. } => unreachable!(),
    }

    Ok(())
}

async fn execute_via_proxy(
    cli: &Cli,
    subcmd: &SkillAtiCommands,
    proxy_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match subcmd {
        SkillAtiCommands::Catalog { search } => {
            let response = proxy_client::get_skillati_catalog(proxy_url, search.as_deref()).await?;
            let catalog: Vec<RemoteSkillMeta> =
                serde_json::from_value(response.get("skills").cloned().ok_or_else(|| {
                    "Proxy returned invalid SkillATI catalog response".to_string()
                })?)?;
            print_catalog(cli, &catalog)?;
        }
        SkillAtiCommands::Read { name } => {
            let response = proxy_client::get_skillati_read(proxy_url, name).await?;
            let activation: SkillAtiActivation = serde_json::from_value(response)?;
            print_activation(cli, &activation)?;
        }
        SkillAtiCommands::Resources { name, prefix } => {
            let response =
                proxy_client::get_skillati_resources(proxy_url, name, prefix.as_deref()).await?;
            let resources: Vec<String> =
                serde_json::from_value(response.get("resources").cloned().ok_or_else(|| {
                    "Proxy returned invalid SkillATI resources response".to_string()
                })?)?;
            print_resources(cli, name, prefix.as_deref(), &resources)?;
        }
        SkillAtiCommands::Cat { name, path } => {
            let response = proxy_client::get_skillati_file(proxy_url, name, path).await?;
            let file: SkillAtiFile = serde_json::from_value(response)?;
            print_file(cli, &file)?;
        }
        SkillAtiCommands::Refs { name } => {
            let response = proxy_client::get_skillati_refs(proxy_url, name).await?;
            let references: Vec<String> = serde_json::from_value(
                response
                    .get("references")
                    .cloned()
                    .ok_or_else(|| "Proxy returned invalid SkillATI refs response".to_string())?,
            )?;
            print_refs(cli, name, &references)?;
        }
        SkillAtiCommands::Ref { name, reference } => {
            let response = proxy_client::get_skillati_file(
                proxy_url,
                name,
                &format!("references/{reference}"),
            )
            .await?;
            let file: SkillAtiFile = serde_json::from_value(response)?;
            print_file(cli, &file)?;
        }
        SkillAtiCommands::BuildIndex { .. } => unreachable!(),
    }

    Ok(())
}

fn execute_build_index(
    cli: &Cli,
    source_dir: &str,
    output: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = build_catalog_manifest(Path::new(source_dir))?;
    let json = serde_json::to_string_pretty(&manifest)?;

    if let Some(path) = output {
        std::fs::write(path, &json)?;
        match cli.output {
            OutputFormat::Json => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "output": path,
                        "skills": manifest.skills.len(),
                        "recommended_object": default_catalog_index_path(),
                    }))?
                );
            }
            _ => {
                println!(
                    "Wrote SkillATI catalog manifest for {} skills to {}",
                    manifest.skills.len(),
                    path
                );
                println!(
                    "Recommended GCS object path: {}",
                    default_catalog_index_path()
                );
            }
        }
        return Ok(());
    }

    println!("{json}");
    Ok(())
}

fn print_catalog(cli: &Cli, catalog: &[RemoteSkillMeta]) -> Result<(), Box<dyn std::error::Error>> {
    match cli.output {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({ "skills": catalog }))?
            );
        }
        _ => {
            for skill in catalog {
                println!("{}: {}", skill.name, skill.description);
            }
        }
    }
    Ok(())
}

fn print_activation(
    cli: &Cli,
    activation: &SkillAtiActivation,
) -> Result<(), Box<dyn std::error::Error>> {
    match cli.output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(activation)?);
        }
        _ => {
            println!("{}", render_activation_text(activation));
        }
    }
    Ok(())
}

/// Level-2 preamble — mirrors Claude Code's `getPromptForCommand` text
/// shape (`~/cc/src/skills/loadSkillsDir.ts:345-347`):
///
/// ```text
/// Base directory for this skill: <skill_directory>
///
/// <description, if any>
///
/// <SKILL.md body>
/// ```
///
/// Omits the resource manifest (Level-3 is pulled on demand) and the old
/// `<skill_content>` XML wrapper (Parcha-custom, not in the Anthropic
/// Agent Skills spec).
fn render_activation_text(activation: &SkillAtiActivation) -> String {
    let mut out = format!(
        "Base directory for this skill: {}\n\n",
        activation.skill_directory
    );
    if !activation.description.trim().is_empty() {
        out.push_str(activation.description.trim());
        out.push_str("\n\n");
    }
    out.push_str(activation.content.trim_end());
    out.push('\n');
    out
}

fn print_resources(
    cli: &Cli,
    name: &str,
    prefix: Option<&str>,
    resources: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    match cli.output {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "name": name,
                    "prefix": prefix,
                    "resources": resources,
                }))?
            );
        }
        _ => {
            for resource in resources {
                println!("{resource}");
            }
        }
    }
    Ok(())
}

fn print_refs(
    cli: &Cli,
    name: &str,
    references: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    match cli.output {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "name": name,
                    "references": references,
                }))?
            );
        }
        _ => {
            for reference in references {
                println!("{reference}");
            }
        }
    }
    Ok(())
}

fn print_file(cli: &Cli, file: &SkillAtiFile) -> Result<(), Box<dyn std::error::Error>> {
    match cli.output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(file)?);
        }
        _ => match &file.data {
            SkillAtiFileData::Text { content } => println!("{content}"),
            SkillAtiFileData::Binary { .. } => {
                return Err(format!(
                    "Path '{}' in skill '{}' is binary; rerun with --output json",
                    file.path, file.resolved_skill
                )
                .into());
            }
        },
    }
    Ok(())
}
