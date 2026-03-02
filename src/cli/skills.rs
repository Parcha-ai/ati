use std::path::PathBuf;

use crate::{Cli, OutputFormat, SkillsCommands};

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

/// Execute: ati skills <subcommand>
pub async fn execute(
    cli: &Cli,
    subcmd: &SkillsCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match subcmd {
        SkillsCommands::List => list_skills(cli),
        SkillsCommands::Show { name } => show_skill(cli, name),
        SkillsCommands::Save { dir } => save_skill(cli, dir),
    }
}

fn list_skills(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let skills_dir = ati_dir().join("skills");

    if !skills_dir.exists() {
        println!("No skills directory found at {}", skills_dir.display());
        return Ok(());
    }

    let mut skills = Vec::new();

    for entry in std::fs::read_dir(&skills_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let skill_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();

            // Read first line of SKILL.md as description
            let skill_md = path.join("SKILL.md");
            let description = if skill_md.exists() {
                std::fs::read_to_string(&skill_md)
                    .ok()
                    .and_then(|content| {
                        content
                            .lines()
                            .find(|l| !l.is_empty() && !l.starts_with('#'))
                            .map(|l| l.trim().to_string())
                    })
                    .unwrap_or_default()
            } else {
                String::new()
            };

            skills.push((skill_name, description));
        }
    }

    if skills.is_empty() {
        println!("No skills available.");
        return Ok(());
    }

    match cli.output {
        OutputFormat::Json => {
            let json: Vec<serde_json::Value> = skills
                .iter()
                .map(|(name, desc)| {
                    serde_json::json!({
                        "name": name,
                        "description": desc,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Table | OutputFormat::Text => {
            for (name, desc) in &skills {
                println!("{name:30} {desc}");
            }
        }
    }

    Ok(())
}

fn show_skill(_cli: &Cli, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let skill_dir = ati_dir().join("skills").join(name);
    let skill_md = skill_dir.join("SKILL.md");

    if !skill_md.exists() {
        return Err(format!(
            "Skill '{name}' not found. Run 'ati skills list' to see available skills."
        )
        .into());
    }

    let content = std::fs::read_to_string(&skill_md)?;
    println!("{content}");

    // List reference files if they exist
    let refs_dir = skill_dir.join("references");
    if refs_dir.exists() {
        println!("\n--- References ---");
        for entry in std::fs::read_dir(&refs_dir)? {
            let entry = entry?;
            let fname = entry
                .file_name()
                .to_str()
                .unwrap_or("unknown")
                .to_string();
            println!("  {fname}");
        }
    }

    Ok(())
}

fn save_skill(_cli: &Cli, source_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    let source = PathBuf::from(source_dir);

    if !source.is_dir() {
        return Err(format!("'{source_dir}' is not a directory").into());
    }

    let skill_name = source
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid directory name")?;

    let dest = ati_dir().join("skills").join(skill_name);

    // Create destination directory
    std::fs::create_dir_all(&dest)?;

    // Copy all files recursively
    copy_dir_recursive(&source, &dest)?;

    println!("Saved skill '{skill_name}' to {}", dest.display());
    Ok(())
}

fn copy_dir_recursive(src: &PathBuf, dst: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dst)?;

    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}
