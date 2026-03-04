use std::path::PathBuf;

use super::common;
use crate::core::jwt;
use crate::core::manifest::ManifestRegistry;
use crate::core::scope::ScopeConfig;
use crate::core::skill::{self, SkillRegistry};
use crate::{Cli, OutputFormat, SkillsCommands};

fn skills_dir() -> PathBuf {
    common::ati_dir().join("skills")
}

fn load_registry() -> Result<SkillRegistry, Box<dyn std::error::Error>> {
    Ok(SkillRegistry::load(&skills_dir())?)
}

fn load_manifest_registry() -> Result<ManifestRegistry, Box<dyn std::error::Error>> {
    let manifests_dir = common::ati_dir().join("manifests");
    if manifests_dir.is_dir() {
        Ok(ManifestRegistry::load(&manifests_dir)?)
    } else {
        Ok(ManifestRegistry::empty())
    }
}

fn load_scopes_from_env() -> ScopeConfig {
    match std::env::var("ATI_SESSION_TOKEN") {
        Ok(token) if !token.is_empty() => match jwt::inspect(&token) {
            Ok(claims) => ScopeConfig::from_jwt(&claims),
            Err(_) => ScopeConfig::unrestricted(),
        },
        _ => ScopeConfig::unrestricted(),
    }
}

/// Execute: ati skills <subcommand>
pub async fn execute(
    cli: &Cli,
    subcmd: &SkillsCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check for proxy mode on read-only commands
    if let Ok(proxy_url) = std::env::var("ATI_PROXY_URL") {
        match subcmd {
            SkillsCommands::List { .. }
            | SkillsCommands::Show { .. }
            | SkillsCommands::Search { .. }
            | SkillsCommands::Info { .. }
            | SkillsCommands::Resolve { .. } => {
                return execute_via_proxy(cli, subcmd, &proxy_url).await;
            }
            // Install, Remove, Init, Validate operate locally
            _ => {}
        }
    }

    match subcmd {
        SkillsCommands::List {
            category,
            provider,
            tool,
        } => list_skills(cli, category.as_deref(), provider.as_deref(), tool.as_deref()),
        SkillsCommands::Show { name, meta, refs } => show_skill(cli, name, *meta, *refs),
        SkillsCommands::Search { query } => search_skills(cli, query),
        SkillsCommands::Info { name } => info_skill(cli, name),
        SkillsCommands::Install {
            source,
            from_git,
            name,
            all,
        } => install_skill(cli, source, from_git.as_deref(), name.as_deref(), *all),
        SkillsCommands::Remove { name } => remove_skill(cli, name),
        SkillsCommands::Init {
            name,
            tools,
            provider,
        } => init_skill(cli, name, tools, provider.as_deref()),
        SkillsCommands::Validate { name, check_tools } => validate_skill(cli, name, *check_tools),
        SkillsCommands::Resolve { scopes } => resolve_skills(cli, scopes.as_deref()),
    }
}

// ---------------------------------------------------------------------------
// Proxy mode — forward read-only commands to the proxy server
// ---------------------------------------------------------------------------

async fn execute_via_proxy(
    cli: &Cli,
    subcmd: &SkillsCommands,
    proxy_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let base = proxy_url.trim_end_matches('/');

    match subcmd {
        SkillsCommands::List {
            category,
            provider,
            tool,
        } => {
            let mut url = format!("{base}/skills");
            let mut params = Vec::new();
            if let Some(c) = category {
                params.push(format!("category={c}"));
            }
            if let Some(p) = provider {
                params.push(format!("provider={p}"));
            }
            if let Some(t) = tool {
                params.push(format!("tool={t}"));
            }
            if !params.is_empty() {
                url.push('?');
                url.push_str(&params.join("&"));
            }

            let resp: serde_json::Value = client.get(&url).send().await?.json().await?;
            print_proxy_response(cli, &resp);
        }
        SkillsCommands::Show { name, meta, refs } => {
            let mut url = format!("{base}/skills/{name}");
            let mut params = Vec::new();
            if *meta {
                params.push("meta=true".to_string());
            }
            if *refs {
                params.push("refs=true".to_string());
            }
            if !params.is_empty() {
                url.push('?');
                url.push_str(&params.join("&"));
            }

            let resp: serde_json::Value = client.get(&url).send().await?.json().await?;
            if *meta {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&resp)?
                );
            } else if let Some(content) = resp.get("content").and_then(|c| c.as_str()) {
                println!("{content}");
                if *refs {
                    if let Some(refs_arr) = resp.get("references").and_then(|r| r.as_array()) {
                        if !refs_arr.is_empty() {
                            println!("\n--- References ---");
                            for r in refs_arr {
                                if let Some(name) = r.as_str() {
                                    println!("  {name}");
                                }
                            }
                        }
                    }
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
        }
        SkillsCommands::Search { query } => {
            let url = format!("{base}/skills?search={}", urlencoding(query));
            let resp: serde_json::Value = client.get(&url).send().await?.json().await?;
            print_proxy_response(cli, &resp);
        }
        SkillsCommands::Info { name } => {
            let url = format!("{base}/skills/{name}?meta=true");
            let resp: serde_json::Value = client.get(&url).send().await?.json().await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        SkillsCommands::Resolve { scopes } => {
            let body = if let Some(path) = scopes {
                let content = std::fs::read_to_string(path)?;
                serde_json::from_str::<serde_json::Value>(&content)?
            } else {
                serde_json::json!({"scopes": ["*"]})
            };
            let url = format!("{base}/skills/resolve");
            let resp: serde_json::Value = client.post(&url).json(&body).send().await?.json().await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        _ => unreachable!("Non-proxy commands should not reach here"),
    }

    Ok(())
}

fn print_proxy_response(cli: &Cli, resp: &serde_json::Value) {
    match cli.output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(resp).unwrap_or_default());
        }
        _ => {
            if let Some(arr) = resp.as_array() {
                for item in arr {
                    let name = item.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                    let desc = item.get("description").and_then(|d| d.as_str()).unwrap_or("");
                    let version = item.get("version").and_then(|v| v.as_str()).unwrap_or("");
                    if version.is_empty() {
                        println!("{name:30} {desc}");
                    } else {
                        println!("{name:30} v{version:8} {desc}");
                    }
                }
            } else {
                println!("{}", serde_json::to_string_pretty(resp).unwrap_or_default());
            }
        }
    }
}

/// Minimal URL encoding for query parameters.
fn urlencoding(s: &str) -> String {
    s.replace(' ', "%20")
        .replace('#', "%23")
        .replace('&', "%26")
        .replace('?', "%3F")
}

// ---------------------------------------------------------------------------
// Local command implementations
// ---------------------------------------------------------------------------

fn list_skills(
    cli: &Cli,
    category: Option<&str>,
    provider: Option<&str>,
    tool: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let registry = load_registry()?;

    let skills: Vec<&crate::core::skill::SkillMeta> = if let Some(cat) = category {
        registry.skills_for_category(cat)
    } else if let Some(prov) = provider {
        registry.skills_for_provider(prov)
    } else if let Some(t) = tool {
        registry.skills_for_tool(t)
    } else {
        registry.list_skills().iter().collect()
    };

    if skills.is_empty() {
        println!("No skills found.");
        return Ok(());
    }

    match cli.output {
        OutputFormat::Json => {
            let json: Vec<serde_json::Value> = skills
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "name": s.name,
                        "version": s.version,
                        "description": s.description,
                        "tools": s.tools,
                        "providers": s.providers,
                        "categories": s.categories,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Table => {
            let mut table = comfy_table::Table::new();
            table.set_header(vec!["Name", "Version", "Description", "Tools"]);
            for s in &skills {
                table.add_row(vec![
                    &s.name,
                    &s.version,
                    &s.description,
                    &s.tools.join(", "),
                ]);
            }
            println!("{table}");
        }
        OutputFormat::Text => {
            for s in &skills {
                println!("{:30} v{:8} {}", s.name, s.version, s.description);
            }
        }
    }

    Ok(())
}

fn show_skill(
    cli: &Cli,
    name: &str,
    meta_only: bool,
    show_refs: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let registry = load_registry()?;

    let skill = registry
        .get_skill(name)
        .ok_or_else(|| format!("Skill '{name}' not found. Run 'ati skills list' to see available skills."))?;

    if meta_only {
        match cli.output {
            OutputFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&skill)?);
            }
            _ => {
                println!("Name:        {}", skill.name);
                println!("Version:     {}", skill.version);
                println!("Description: {}", skill.description);
                if let Some(author) = &skill.author {
                    println!("Author:      {author}");
                }
                if !skill.tools.is_empty() {
                    println!("Tools:       {}", skill.tools.join(", "));
                }
                if !skill.providers.is_empty() {
                    println!("Providers:   {}", skill.providers.join(", "));
                }
                if !skill.categories.is_empty() {
                    println!("Categories:  {}", skill.categories.join(", "));
                }
                if !skill.keywords.is_empty() {
                    println!("Keywords:    {}", skill.keywords.join(", "));
                }
                if let Some(hint) = &skill.hint {
                    println!("Hint:        {hint}");
                }
                if !skill.depends_on.is_empty() {
                    println!("Depends on:  {}", skill.depends_on.join(", "));
                }
                if !skill.suggests.is_empty() {
                    println!("Suggests:    {}", skill.suggests.join(", "));
                }
                println!("Directory:   {}", skill.dir.display());
            }
        }
        return Ok(());
    }

    // Show SKILL.md content
    let content = registry.read_content(name)?;
    if content.is_empty() {
        println!("(No SKILL.md content)");
    } else {
        println!("{content}");
    }

    // Show references
    if show_refs {
        let refs = registry.list_references(name)?;
        if !refs.is_empty() {
            println!("\n--- References ---");
            for r in &refs {
                println!("  {r}");
            }
        }
    }

    Ok(())
}

fn search_skills(cli: &Cli, query: &str) -> Result<(), Box<dyn std::error::Error>> {
    let registry = load_registry()?;
    let results = registry.search(query);

    if results.is_empty() {
        println!("No skills match '{query}'.");
        return Ok(());
    }

    match cli.output {
        OutputFormat::Json => {
            let json: Vec<serde_json::Value> = results
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "name": s.name,
                        "version": s.version,
                        "description": s.description,
                        "tools": s.tools,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        _ => {
            for s in &results {
                println!("{:30} {}", s.name, s.description);
                if let Some(hint) = &s.hint {
                    println!("{:30} Hint: {hint}", "");
                }
            }
        }
    }

    Ok(())
}

fn info_skill(cli: &Cli, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Info is just show --meta
    show_skill(cli, name, true, false)
}

fn install_skill(
    _cli: &Cli,
    source: &str,
    from_git: Option<&str>,
    name_override: Option<&str>,
    all: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let dest_base = skills_dir();
    std::fs::create_dir_all(&dest_base)?;

    // Determine source directory
    let source_dir = if let Some(git_url) = from_git {
        // Clone from git to a temp directory
        let tmp_dir = std::env::temp_dir().join(format!("ati-skill-install-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp_dir); // Clean up any previous attempt
        let status = std::process::Command::new("git")
            .args(["clone", "--depth", "1", git_url, tmp_dir.to_str().unwrap()])
            .status()?;
        if !status.success() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(format!("Failed to clone '{git_url}'").into());
        }
        let result = install_from_dir(&tmp_dir, &dest_base, name_override, all);
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return result;
    } else {
        PathBuf::from(source)
    };

    if !source_dir.exists() {
        return Err(format!("Source '{}' does not exist", source_dir.display()).into());
    }

    install_from_dir(&source_dir, &dest_base, name_override, all)?;
    Ok(())
}

fn install_from_dir(
    source: &PathBuf,
    dest_base: &PathBuf,
    name_override: Option<&str>,
    all: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if all {
        // Install all subdirectories that contain skill.toml or SKILL.md
        let mut count = 0;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir()
                && (path.join("skill.toml").exists() || path.join("SKILL.md").exists())
            {
                let skill_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or("Invalid directory name")?;
                validate_skill_name(skill_name)?;
                let dest = dest_base.join(skill_name);
                copy_dir_recursive(&path, &dest)?;
                println!("Installed '{skill_name}'");
                count += 1;
            }
        }
        if count == 0 {
            println!("No skills found in '{}'", source.display());
        } else {
            println!("Installed {count} skill(s).");
        }
    } else {
        // Install single skill
        let skill_name = name_override
            .map(String::from)
            .or_else(|| {
                source
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(String::from)
            })
            .ok_or("Cannot determine skill name")?;

        validate_skill_name(&skill_name)?;

        let dest = dest_base.join(&skill_name);
        std::fs::create_dir_all(&dest)?;
        copy_dir_recursive(source, &dest)?;
        println!("Installed '{skill_name}' to {}", dest.display());
    }

    Ok(())
}

fn remove_skill(_cli: &Cli, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    validate_skill_name(name)?;
    let skill_dir = skills_dir().join(name);
    if !skill_dir.exists() {
        return Err(format!("Skill '{name}' not found.").into());
    }
    std::fs::remove_dir_all(&skill_dir)?;
    println!("Removed skill '{name}'.");
    Ok(())
}

fn init_skill(
    _cli: &Cli,
    name: &str,
    tools: &[String],
    provider: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_skill_name(name)?;
    let skill_dir = skills_dir().join(name);
    if skill_dir.exists() {
        return Err(format!(
            "Skill '{name}' already exists at {}",
            skill_dir.display()
        )
        .into());
    }

    std::fs::create_dir_all(&skill_dir)?;
    std::fs::create_dir_all(skill_dir.join("references"))?;

    // Write skill.toml
    let toml_content = skill::scaffold_skill_toml(name, tools, provider);
    std::fs::write(skill_dir.join("skill.toml"), toml_content)?;

    // Write SKILL.md
    let md_content = skill::scaffold_skill_md(name);
    std::fs::write(skill_dir.join("SKILL.md"), md_content)?;

    println!("Scaffolded skill '{name}' at {}", skill_dir.display());
    println!("  skill.toml  — edit metadata and tool bindings");
    println!("  SKILL.md    — write your methodology guide");
    println!("  references/ — add supporting documentation");

    Ok(())
}

fn validate_skill(
    _cli: &Cli,
    name: &str,
    check_tools: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let registry = load_registry()?;

    let skill = registry
        .get_skill(name)
        .ok_or_else(|| format!("Skill '{name}' not found."))?;

    println!("Skill: {}", skill.name);
    println!("Version: {}", skill.version);

    // Check SKILL.md exists
    let skill_md = skill.dir.join("SKILL.md");
    if skill_md.exists() {
        let content = std::fs::read_to_string(&skill_md)?;
        println!("SKILL.md: {} bytes, {} lines", content.len(), content.lines().count());
    } else {
        println!("SKILL.md: MISSING (recommended)");
    }

    // Validate tool bindings against manifests
    if check_tools {
        let manifest_registry = load_manifest_registry()?;
        let (valid, unknown) = registry.validate_tool_bindings(name, &manifest_registry)?;

        if !valid.is_empty() {
            println!("Valid tool bindings ({}):", valid.len());
            for t in &valid {
                println!("  + {t}");
            }
        }
        if !unknown.is_empty() {
            println!("Unknown tool bindings ({}):", unknown.len());
            for t in &unknown {
                println!("  ! {t} — not found in manifests");
            }
        }
        if valid.is_empty() && unknown.is_empty() && skill.tools.is_empty() {
            println!("No tool bindings defined.");
        }
    } else if !skill.tools.is_empty() {
        println!("Tool bindings: {} (use --check-tools to validate)", skill.tools.len());
    }

    // Check dependencies
    if !skill.depends_on.is_empty() {
        println!("Dependencies:");
        for dep in &skill.depends_on {
            let exists = registry.get_skill(dep).is_some();
            let status = if exists { "installed" } else { "NOT FOUND" };
            println!("  {} — {status}", dep);
        }
    }

    Ok(())
}

fn resolve_skills(cli: &Cli, _scopes_path: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let skill_registry = load_registry()?;
    let manifest_registry = load_manifest_registry()?;
    let scopes = load_scopes_from_env();

    let resolved = skill::resolve_skills(&skill_registry, &manifest_registry, &scopes);

    if resolved.is_empty() {
        println!("No skills auto-resolve for the current scopes.");
        return Ok(());
    }

    match cli.output {
        OutputFormat::Json => {
            let json: Vec<serde_json::Value> = resolved
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "name": s.name,
                        "version": s.version,
                        "description": s.description,
                        "tools": s.tools,
                        "providers": s.providers,
                        "categories": s.categories,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        _ => {
            println!("Skills that auto-load for current scopes:");
            for s in &resolved {
                println!("  {:30} {}", s.name, s.description);
                if !s.tools.is_empty() {
                    println!("  {:30} tools: {}", "", s.tools.join(", "));
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validate that a skill name is safe (no path traversal).
fn validate_skill_name(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if name.is_empty() {
        return Err("Skill name cannot be empty".into());
    }
    if name.contains("..") || name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(format!(
            "Invalid skill name '{}': contains path traversal characters (/, \\, .., or null bytes)",
            name
        )
        .into());
    }
    // Reject names that are just dots
    if name.chars().all(|c| c == '.') {
        return Err(format!("Invalid skill name '{}': must not be only dots", name).into());
    }
    Ok(())
}

fn copy_dir_recursive(
    src: &std::path::Path,
    dst: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dst)?;

    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        // Skip symlinks to prevent following links outside the source directory
        if file_type.is_symlink() {
            eprintln!("Warning: skipping symlink '{}'", src_path.display());
            continue;
        }

        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_skill_name_valid() {
        assert!(validate_skill_name("my-skill").is_ok());
        assert!(validate_skill_name("my_skill_v2").is_ok());
        assert!(validate_skill_name("research-general-overview").is_ok());
    }

    #[test]
    fn test_validate_skill_name_empty() {
        assert!(validate_skill_name("").is_err());
    }

    #[test]
    fn test_validate_skill_name_dotdot() {
        assert!(validate_skill_name("../evil").is_err());
        assert!(validate_skill_name("foo/../bar").is_err());
        assert!(validate_skill_name("..").is_err());
    }

    #[test]
    fn test_validate_skill_name_slash() {
        assert!(validate_skill_name("foo/bar").is_err());
        assert!(validate_skill_name("/absolute").is_err());
    }

    #[test]
    fn test_validate_skill_name_backslash() {
        assert!(validate_skill_name("foo\\bar").is_err());
    }

    #[test]
    fn test_validate_skill_name_null() {
        assert!(validate_skill_name("foo\0bar").is_err());
    }

    #[test]
    fn test_validate_skill_name_only_dots() {
        assert!(validate_skill_name(".").is_err());
        assert!(validate_skill_name("...").is_err());
    }
}
