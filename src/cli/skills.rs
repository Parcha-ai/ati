use std::path::PathBuf;

use super::common;
use crate::core::jwt;
use crate::core::manifest::ManifestRegistry;
use crate::core::scope::ScopeConfig;
use crate::core::skill::{self, SkillRegistry};
use crate::{Cli, OutputFormat, SkillCommands};

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

/// Execute: ati skill <subcommand>
pub async fn execute(cli: &Cli, subcmd: &SkillCommands) -> Result<(), Box<dyn std::error::Error>> {
    // Check for proxy mode on read-only commands
    if let Ok(proxy_url) = std::env::var("ATI_PROXY_URL") {
        match subcmd {
            SkillCommands::List { .. }
            | SkillCommands::Show { .. }
            | SkillCommands::Search { .. }
            | SkillCommands::Info { .. }
            | SkillCommands::Read { .. }
            | SkillCommands::Resolve { .. } => {
                return execute_via_proxy(cli, subcmd, &proxy_url).await;
            }
            // Install, Remove, Init, Validate operate locally
            _ => {}
        }
    }

    match subcmd {
        SkillCommands::List {
            category,
            provider,
            tool,
        } => list_skills(
            cli,
            category.as_deref(),
            provider.as_deref(),
            tool.as_deref(),
        ),
        SkillCommands::Show { name, meta, refs } => show_skill(cli, name, *meta, *refs),
        SkillCommands::Search { query } => search_skills(cli, query),
        SkillCommands::Info { name } => info_skill(cli, name),
        SkillCommands::Install {
            source,
            from_git,
            name,
            all,
            local,
        } => install_skill(cli, source, from_git.as_deref(), name.as_deref(), *all, *local).await,
        SkillCommands::Read {
            name,
            tool,
            with_refs,
        } => read_skill(cli, name.as_deref(), tool.as_deref(), *with_refs),
        SkillCommands::Remove { name } => remove_skill(cli, name),
        SkillCommands::Init {
            name,
            tools,
            provider,
        } => init_skill(cli, name, tools, provider.as_deref()),
        SkillCommands::Validate { name, check_tools } => validate_skill(cli, name, *check_tools),
        SkillCommands::Resolve { scopes } => resolve_skills(cli, scopes.as_deref()),
        SkillCommands::Verify { name } => verify_skill(name),
        SkillCommands::Diff { source } => diff_skill(source).await,
        SkillCommands::Update { name, force } => update_skill(name, *force).await,
    }
}

// ---------------------------------------------------------------------------
// Proxy mode — forward read-only commands to the proxy server
// ---------------------------------------------------------------------------

async fn execute_via_proxy(
    cli: &Cli,
    subcmd: &SkillCommands,
    proxy_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let base = proxy_url.trim_end_matches('/');

    match subcmd {
        SkillCommands::List {
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
        SkillCommands::Show { name, meta, refs } => {
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
                println!("{}", serde_json::to_string_pretty(&resp)?);
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
        SkillCommands::Search { query } => {
            let url = format!("{base}/skills?search={}", urlencoding(query));
            let resp: serde_json::Value = client.get(&url).send().await?.json().await?;
            print_proxy_response(cli, &resp);
        }
        SkillCommands::Info { name } => {
            let url = format!("{base}/skills/{name}?meta=true");
            let resp: serde_json::Value = client.get(&url).send().await?.json().await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        SkillCommands::Read {
            name,
            tool,
            with_refs,
        } => {
            // Read is like show but for agent consumption — delegate to show endpoint
            if let Some(tool_name) = tool {
                // Get all skills for this tool, then fetch each one's content
                let url = format!("{base}/skills?tool={}", urlencoding(tool_name));
                let resp: serde_json::Value = client.get(&url).send().await?.json().await?;
                if let Some(arr) = resp.as_array() {
                    for item in arr {
                        if let Some(skill_name) = item.get("name").and_then(|n| n.as_str()) {
                            let mut detail_url = format!("{base}/skills/{skill_name}");
                            if *with_refs {
                                detail_url.push_str("?refs=true");
                            }
                            let detail: serde_json::Value =
                                client.get(&detail_url).send().await?.json().await?;
                            if let Some(content) = detail.get("content").and_then(|c| c.as_str()) {
                                println!("{content}");
                            }
                        }
                    }
                }
            } else if let Some(skill_name) = name {
                let mut url = format!("{base}/skills/{skill_name}");
                if *with_refs {
                    url.push_str("?refs=true");
                }
                let resp: serde_json::Value = client.get(&url).send().await?.json().await?;
                if let Some(content) = resp.get("content").and_then(|c| c.as_str()) {
                    println!("{content}");
                }
            } else {
                return Err("Either <name> or --tool <tool> is required for 'skill read'.".into());
            }
        }
        SkillCommands::Resolve { scopes } => {
            let body = if let Some(path) = scopes {
                let content = std::fs::read_to_string(path)?;
                serde_json::from_str::<serde_json::Value>(&content)?
            } else {
                serde_json::json!({"scopes": ["*"]})
            };
            let url = format!("{base}/skills/resolve");
            let resp: serde_json::Value =
                client.post(&url).json(&body).send().await?.json().await?;
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
                    let desc = item
                        .get("description")
                        .and_then(|d| d.as_str())
                        .unwrap_or("");
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

    let skill = registry.get_skill(name).ok_or_else(|| {
        format!("Skill '{name}' not found. Run 'ati skill list' to see available skills.")
    })?;

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
                if let Some(license) = &skill.license {
                    println!("License:     {license}");
                }
                if let Some(compat) = &skill.compatibility {
                    println!("Compat:      {compat}");
                }
                if let Some(allowed) = &skill.allowed_tools {
                    println!("Allowed:     {allowed}");
                }
                println!("Format:      {:?}", skill.format);
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
                if !skill.extra_metadata.is_empty() {
                    println!("Metadata:");
                    for (k, v) in &skill.extra_metadata {
                        println!("  {k}: {v}");
                    }
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

/// Read skill content for agent consumption — minimal decoration.
fn read_skill(
    _cli: &Cli,
    name: Option<&str>,
    tool: Option<&str>,
    with_refs: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let registry = load_registry()?;

    let skill_names: Vec<String> = if let Some(tool_name) = tool {
        let skills = registry.skills_for_tool(tool_name);
        if skills.is_empty() {
            return Err(format!("No skills found for tool '{tool_name}'.").into());
        }
        skills.iter().map(|s| s.name.clone()).collect()
    } else if let Some(skill_name) = name {
        vec![skill_name.to_string()]
    } else {
        return Err("Either <name> or --tool <tool> is required for 'skill read'.".into());
    };

    for (i, skill_name) in skill_names.iter().enumerate() {
        if i > 0 {
            println!("\n---\n");
        }
        let content = registry.read_content(skill_name)?;
        if content.is_empty() {
            eprintln!("(No SKILL.md content for '{skill_name}')");
        } else {
            print!("{content}");
            // Ensure trailing newline
            if !content.ends_with('\n') {
                println!();
            }
        }

        if with_refs {
            let refs = registry.list_references(skill_name)?;
            for ref_name in &refs {
                println!("\n--- Reference: {ref_name} ---\n");
                match registry.read_reference(skill_name, ref_name) {
                    Ok(ref_content) => print!("{ref_content}"),
                    Err(e) => eprintln!("(Error reading reference '{ref_name}': {e})"),
                }
            }
        }
    }

    Ok(())
}

/// Install a skill from a git URL. Returns the installed skill name.
/// Used by `ati provider install-skills` to install each declared skill.
pub fn install_skill_from_url(
    url: &str,
    skills_dir: &std::path::Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let (clone_url, subdir) = parse_git_url_fragment(url);

    let tmp_dir = std::env::temp_dir().join(format!("ati-skill-install-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_dir);
    let status = std::process::Command::new("git")
        .args([
            "clone",
            "--depth",
            "1",
            clone_url,
            tmp_dir.to_str().unwrap(),
        ])
        .status()?;
    if !status.success() {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(format!("Failed to clone '{clone_url}'").into());
    }

    let source = if let Some(sub) = subdir {
        let sub_path = tmp_dir.join(sub);
        if !sub_path.exists() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(format!("Subdirectory '{sub}' not found in cloned repo").into());
        }
        sub_path
    } else {
        tmp_dir.clone()
    };

    // Determine skill name from source dir name
    let skill_name = source
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Cannot determine skill name from URL")?
        .to_string();

    validate_skill_name(&skill_name)?;

    let dest = skills_dir.join(&skill_name);
    std::fs::create_dir_all(&dest)?;
    copy_dir_recursive(&source, &dest)?;

    // Install bundled provider.toml if present (sync fallback for non-async callers)
    let manifests_dir = skills_dir.parent().unwrap_or(skills_dir).join("manifests");
    install_bundled_provider(&dest, &manifests_dir)?;

    let _ = std::fs::remove_dir_all(&tmp_dir);
    Ok(skill_name)
}

/// Returns true if a source string looks like a git URL.
fn is_git_url(source: &str) -> bool {
    source.starts_with("https://")
        || source.starts_with("http://")
        || source.starts_with("git@")
        || source.ends_with(".git")
}

/// Parse a git URL with optional #fragment for subdirectory.
/// Returns (clone_url, optional_subdir).
fn parse_git_url_fragment(url: &str) -> (&str, Option<&str>) {
    if let Some(idx) = url.rfind('#') {
        let (base, frag) = url.split_at(idx);
        let subdir = &frag[1..]; // skip the '#'
        if subdir.is_empty() {
            (base, None)
        } else {
            (base, Some(subdir))
        }
    } else {
        (url, None)
    }
}

/// Clone a git repo and install skill(s) from it.
async fn install_from_git(
    git_url: &str,
    dest_base: &PathBuf,
    name_override: Option<&str>,
    all: bool,
    local: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (clone_url, subdir) = parse_git_url_fragment(git_url);

    let tmp_dir = std::env::temp_dir().join(format!("ati-skill-install-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_dir);
    let status = std::process::Command::new("git")
        .args([
            "clone",
            "--depth",
            "1",
            clone_url,
            tmp_dir.to_str().unwrap(),
        ])
        .status()?;
    if !status.success() {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(format!("Failed to clone '{clone_url}'").into());
    }

    let source = if let Some(sub) = subdir {
        let sub_path = tmp_dir.join(sub);
        if !sub_path.exists() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(format!("Subdirectory '{sub}' not found in cloned repo").into());
        }
        sub_path
    } else {
        tmp_dir.clone()
    };

    let result = install_from_dir(&source, dest_base, name_override, all, local).await;
    let _ = std::fs::remove_dir_all(&tmp_dir);
    result
}

/// Clone a git repo with optional SHA checkout and install skill(s) from it.
async fn install_from_git_with_sha(
    git_url: &str,
    pinned_sha: Option<&str>,
    dest_base: &PathBuf,
    name_override: Option<&str>,
    all: bool,
    local: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (clone_url, subdir) = parse_git_url_fragment(git_url);

    let tmp_dir = std::env::temp_dir().join(format!("ati-skill-install-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_dir);

    // If we have a pinned SHA, we need a full clone (not shallow)
    let mut clone_args = vec!["clone"];
    if pinned_sha.is_none() {
        clone_args.extend(["--depth", "1"]);
    }
    clone_args.push(clone_url);
    clone_args.push(tmp_dir.to_str().unwrap());

    let status = std::process::Command::new("git")
        .args(&clone_args)
        .status()?;
    if !status.success() {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(format!("Failed to clone '{clone_url}'").into());
    }

    // Checkout pinned SHA if provided
    if let Some(sha) = pinned_sha {
        let status = std::process::Command::new("git")
            .args(["checkout", sha])
            .current_dir(&tmp_dir)
            .status()?;
        if !status.success() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(format!("Failed to checkout SHA '{sha}'").into());
        }
    }

    let source = if let Some(sub) = subdir {
        let sub_path = tmp_dir.join(sub);
        if !sub_path.exists() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(format!("Subdirectory '{sub}' not found in cloned repo").into());
        }
        sub_path
    } else {
        tmp_dir.clone()
    };

    let result = install_from_dir_with_integrity(
        &source, dest_base, name_override, all, local,
        Some(git_url), pinned_sha,
    ).await;
    let _ = std::fs::remove_dir_all(&tmp_dir);
    result
}

/// Parse a source string with optional @SHA pinning.
/// Only splits on @ if the suffix looks like a hex SHA (7+ hex chars).
fn parse_source_with_sha(source: &str) -> (&str, Option<&str>) {
    if let Some(at_pos) = source.rfind('@') {
        let potential_sha = &source[at_pos + 1..];
        if potential_sha.len() >= 7 && potential_sha.chars().all(|c| c.is_ascii_hexdigit()) {
            return (&source[..at_pos], Some(potential_sha));
        }
    }
    (source, None)
}

async fn install_skill(
    _cli: &Cli,
    source: &str,
    from_git: Option<&str>,
    name_override: Option<&str>,
    all: bool,
    local: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let dest_base = skills_dir();
    std::fs::create_dir_all(&dest_base)?;

    // If --from-git is explicit, use it (backward compat)
    if let Some(git_url) = from_git {
        return install_from_git(git_url, &dest_base, name_override, all, local).await;
    }

    // Parse @SHA pinning from source
    let (source_base, pinned_sha) = parse_source_with_sha(source);

    // Auto-detect git URLs
    if is_git_url(source_base) {
        return install_from_git_with_sha(source_base, pinned_sha, &dest_base, name_override, all, local).await;
    }

    // Local path
    let source_dir = PathBuf::from(source_base);
    if !source_dir.exists() {
        return Err(format!("Source '{}' does not exist", source_dir.display()).into());
    }

    install_from_dir(&source_dir, &dest_base, name_override, all, local).await?;
    Ok(())
}

async fn install_from_dir(
    source: &PathBuf,
    dest_base: &PathBuf,
    name_override: Option<&str>,
    all: bool,
    local: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    install_from_dir_with_integrity(source, dest_base, name_override, all, local, None, None).await
}

async fn install_from_dir_with_integrity(
    source: &PathBuf,
    dest_base: &PathBuf,
    name_override: Option<&str>,
    all: bool,
    local: bool,
    source_url: Option<&str>,
    pinned_sha: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifests_dir = dest_base.parent().unwrap_or(dest_base).join("manifests");

    if all {
        // Install all subdirectories that contain skill.toml or SKILL.md
        let mut count = 0;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && (path.join("skill.toml").exists() || path.join("SKILL.md").exists())
            {
                let skill_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or("Invalid directory name")?;
                validate_skill_name(skill_name)?;
                let dest = dest_base.join(skill_name);
                copy_dir_recursive(&path, &dest)?;
                write_integrity_info(&dest, source_url, pinned_sha)?;
                generate_manifest_from_skill(&dest, &manifests_dir, local).await;
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
        write_integrity_info(&dest, source_url, pinned_sha)?;
        generate_manifest_from_skill(&dest, &manifests_dir, local).await;
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
        return Err(format!("Skill '{name}' already exists at {}", skill_dir.display()).into());
    }

    std::fs::create_dir_all(&skill_dir)?;
    std::fs::create_dir_all(skill_dir.join("references"))?;

    // Write SKILL.md with Anthropic-spec frontmatter
    let description = format!("TODO: Describe what {name} does");
    let md_content = skill::scaffold_skill_md_with_frontmatter(name, &description);
    std::fs::write(skill_dir.join("SKILL.md"), md_content)?;

    // Only write skill.toml if ATI-specific bindings are needed
    let has_bindings = !tools.is_empty() || provider.is_some();
    if has_bindings {
        let toml_content = skill::scaffold_ati_extension_toml(name, tools, provider);
        std::fs::write(skill_dir.join("skill.toml"), toml_content)?;
    }

    println!("Scaffolded skill '{name}' at {}", skill_dir.display());
    println!("  SKILL.md    — metadata in frontmatter + methodology guide");
    if has_bindings {
        println!("  skill.toml  — ATI tool/provider bindings");
    }
    println!("  references/ — add supporting documentation");

    // Warn if name doesn't conform to Anthropic spec
    if !skill::is_anthropic_valid_name(name) {
        eprintln!(
            "Warning: name '{}' does not conform to Anthropic Agent Skills spec",
            name
        );
        eprintln!("  (1-64 chars, lowercase + digits + hyphens, no consecutive hyphens)");
    }

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
    println!("Format: {:?}", skill.format);

    // Anthropic naming validation (warning, not error)
    if !skill::is_anthropic_valid_name(&skill.name) {
        println!(
            "Warning: name '{}' does not conform to Anthropic Agent Skills spec",
            skill.name
        );
        println!("  (1-64 chars, lowercase + digits + hyphens, no consecutive hyphens)");
    }

    // Check SKILL.md exists
    let skill_md = skill.dir.join("SKILL.md");
    if skill_md.exists() {
        let content = std::fs::read_to_string(&skill_md)?;
        println!(
            "SKILL.md: {} bytes, {} lines",
            content.len(),
            content.lines().count()
        );
        if skill.has_frontmatter {
            println!("Frontmatter: present (Anthropic spec)");
        } else {
            println!("Frontmatter: absent");
        }
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
        println!(
            "Tool bindings: {} (use --check-tools to validate)",
            skill.tools.len()
        );
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
// Supply chain integrity
// ---------------------------------------------------------------------------

/// Write integrity information (content hash, source URL, pinned SHA) to skill.toml.
fn write_integrity_info(
    skill_dir: &std::path::Path,
    source_url: Option<&str>,
    pinned_sha: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let skill_md_path = skill_dir.join("SKILL.md");
    if !skill_md_path.exists() {
        return Ok(());
    }

    let content = std::fs::read_to_string(&skill_md_path)?;
    let hash = crate::core::skill::compute_content_hash(&content);

    let toml_path = skill_dir.join("skill.toml");
    let mut toml_content = if toml_path.exists() {
        std::fs::read_to_string(&toml_path)?
    } else {
        String::new()
    };

    // Remove existing [ati.integrity] section if present
    if let Some(start) = toml_content.find("[ati.integrity]") {
        let end = toml_content[start + 1..]
            .find("\n[")
            .map(|pos| start + 1 + pos)
            .unwrap_or(toml_content.len());
        toml_content = format!("{}{}", &toml_content[..start], &toml_content[end..]);
    }

    // Append [ati.integrity] section
    if !toml_content.is_empty() && !toml_content.ends_with('\n') {
        toml_content.push('\n');
    }
    toml_content.push_str("\n[ati.integrity]\n");
    toml_content.push_str(&format!("content_hash = \"{hash}\"\n"));
    if let Some(url) = source_url {
        toml_content.push_str(&format!("source_url = \"{url}\"\n"));
    }
    if let Some(sha) = pinned_sha {
        toml_content.push_str(&format!("pinned_sha = \"{sha}\"\n"));
    }

    std::fs::write(&toml_path, toml_content)?;
    Ok(())
}

/// Read integrity info from skill.toml's [ati.integrity] section.
fn read_integrity_info(
    skill_dir: &std::path::Path,
) -> Result<(Option<String>, Option<String>, Option<String>), Box<dyn std::error::Error>> {
    let toml_path = skill_dir.join("skill.toml");
    if !toml_path.exists() {
        return Ok((None, None, None));
    }

    let toml_content = std::fs::read_to_string(&toml_path)?;
    let toml_val: toml::Value = toml::from_str(&toml_content)?;

    let integrity = toml_val.get("ati").and_then(|a| a.get("integrity"));

    let content_hash = integrity
        .and_then(|i| i.get("content_hash"))
        .and_then(|h| h.as_str())
        .map(|s| s.to_string());
    let source_url = integrity
        .and_then(|i| i.get("source_url"))
        .and_then(|h| h.as_str())
        .map(|s| s.to_string());
    let pinned_sha = integrity
        .and_then(|i| i.get("pinned_sha"))
        .and_then(|h| h.as_str())
        .map(|s| s.to_string());

    Ok((content_hash, source_url, pinned_sha))
}

fn verify_skill(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    validate_skill_name(name)?;
    let skill_dir = skills_dir().join(name);
    if !skill_dir.exists() {
        return Err(format!("Skill '{}' is not installed", name).into());
    }

    let skill_md_path = skill_dir.join("SKILL.md");
    if !skill_md_path.exists() {
        return Err(format!("Skill '{}' has no SKILL.md", name).into());
    }

    let content = std::fs::read_to_string(&skill_md_path)?;
    let current_hash = crate::core::skill::compute_content_hash(&content);

    let (stored_hash, source_url, pinned_sha) = read_integrity_info(&skill_dir)?;

    if let Some(ref url) = source_url {
        println!("Source:  {url}");
    }
    if let Some(ref sha) = pinned_sha {
        println!("Pinned:  {sha}");
    }

    match stored_hash {
        Some(ref stored) if stored == &current_hash => {
            println!(
                "VERIFIED — '{}' integrity OK (SHA-256: {}...)",
                name,
                &current_hash[..16]
            );
            Ok(())
        }
        Some(ref stored) => {
            eprintln!("WARNING — '{}' content has changed!", name);
            eprintln!("  Stored:  {stored}");
            eprintln!("  Current: {current_hash}");
            Err(format!("Integrity check failed for '{}'", name).into())
        }
        None => {
            eprintln!(
                "No integrity hash stored for '{}'. Current SHA-256: {}",
                name, current_hash
            );
            Ok(())
        }
    }
}

async fn diff_skill(source: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (source_base, pinned_sha) = parse_source_with_sha(source);

    // Determine skill name from source
    let (clone_url, subdir) = parse_git_url_fragment(source_base);
    let skill_name = subdir
        .or_else(|| {
            clone_url
                .rsplit('/')
                .next()
                .map(|s| s.trim_end_matches(".git"))
        })
        .ok_or("Cannot determine skill name from source")?;

    let installed_md = skills_dir().join(skill_name).join("SKILL.md");
    if !installed_md.exists() {
        return Err(format!(
            "Skill '{}' is not installed locally. Install it first.",
            skill_name
        )
        .into());
    }

    // Clone source to temp dir
    let tmp_dir = std::env::temp_dir().join(format!("ati-skill-diff-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let mut clone_args = vec!["clone"];
    if pinned_sha.is_none() {
        clone_args.extend(["--depth", "1"]);
    }
    clone_args.push(clone_url);
    clone_args.push(tmp_dir.to_str().unwrap());

    let status = std::process::Command::new("git").args(&clone_args).status()?;
    if !status.success() {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(format!("Failed to clone '{clone_url}'").into());
    }

    if let Some(sha) = pinned_sha {
        let status = std::process::Command::new("git")
            .args(["checkout", sha])
            .current_dir(&tmp_dir)
            .status()?;
        if !status.success() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(format!("Failed to checkout SHA '{sha}'").into());
        }
    }

    let source_md = if let Some(sub) = subdir {
        tmp_dir.join(sub).join("SKILL.md")
    } else {
        tmp_dir.join("SKILL.md")
    };

    if !source_md.exists() {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err("Source does not contain SKILL.md".into());
    }

    let output = std::process::Command::new("diff")
        .arg("-u")
        .arg("--label")
        .arg(format!("installed/{skill_name}/SKILL.md"))
        .arg(&installed_md)
        .arg("--label")
        .arg(format!("source/{skill_name}/SKILL.md"))
        .arg(&source_md)
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.is_empty() {
                println!("No differences found.");
            } else {
                print!("{stdout}");
            }
        }
        Err(_) => {
            // diff not available, fall back to hash comparison
            let installed_content = std::fs::read_to_string(&installed_md)?;
            let source_content = std::fs::read_to_string(&source_md)?;
            let installed_hash = crate::core::skill::compute_content_hash(&installed_content);
            let source_hash = crate::core::skill::compute_content_hash(&source_content);

            if installed_hash == source_hash {
                println!("No differences (hashes match: {}).", &installed_hash[..16]);
            } else {
                println!("Files differ:");
                println!("  Installed: {installed_hash}");
                println!("  Source:    {source_hash}");
            }
        }
    }

    let _ = std::fs::remove_dir_all(&tmp_dir);
    Ok(())
}

async fn update_skill(name: &str, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    validate_skill_name(name)?;
    let skill_dir = skills_dir().join(name);
    if !skill_dir.exists() {
        return Err(format!("Skill '{}' is not installed", name).into());
    }

    let (_, source_url, pinned_sha) = read_integrity_info(&skill_dir)?;

    let source_url = source_url.ok_or_else(|| {
        format!(
            "Skill '{}' has no recorded source URL. Cannot update automatically.\n\
             Re-install with: ati skill install <source>",
            name
        )
    })?;

    // Check current integrity before updating
    let skill_md_path = skill_dir.join("SKILL.md");
    if skill_md_path.exists() {
        let content = std::fs::read_to_string(&skill_md_path)?;
        let current_hash = crate::core::skill::compute_content_hash(&content);
        let (stored_hash, _, _) = read_integrity_info(&skill_dir)?;

        if let Some(ref stored) = stored_hash {
            if stored != &current_hash && !force {
                return Err(format!(
                    "Skill '{}' has local modifications (hash mismatch).\n\
                     Use --force to overwrite, or back up your changes first.\n\
                     Stored:  {}\n\
                     Current: {}",
                    name, stored, current_hash
                )
                .into());
            }
        }
    }

    println!("Updating '{}' from {}", name, source_url);

    // Re-install from source
    let dest_base = skills_dir();
    let sha_ref = pinned_sha.as_deref();

    // Remove old installation
    std::fs::remove_dir_all(&skill_dir)?;

    install_from_git_with_sha(&source_url, sha_ref, &dest_base, Some(name), false, false).await?;

    println!("Updated '{}'.", name);
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

/// Generate a provider manifest from a skill's SKILL.md using an LLM.
/// Provider selection: --local flag or ATI_MANIFEST_PROVIDER=local uses ollama (zero network calls).
/// Otherwise: ATI_MANIFEST_PROVIDER env preference, then CEREBRAS_API_KEY, then ANTHROPIC_API_KEY,
/// then bundled provider.toml, then skip.
/// Silently succeeds if no manifest can be generated (skill still installs fine).
async fn generate_manifest_from_skill(
    skill_dir: &std::path::Path,
    manifests_dir: &std::path::Path,
    use_local: bool,
) {
    // Read SKILL.md — if it doesn't exist, nothing to generate from
    let skill_md_path = skill_dir.join("SKILL.md");
    let skill_md = match std::fs::read_to_string(&skill_md_path) {
        Ok(content) if !content.is_empty() => content,
        _ => return,
    };

    // Read skill.toml for provider hints (providers field)
    let skill_toml_content =
        std::fs::read_to_string(skill_dir.join("skill.toml")).unwrap_or_default();

    // Extract provider name from skill.toml providers = ["fal"] or from skill name
    let provider_name = extract_provider_name(&skill_toml_content).or_else(|| {
        skill_dir
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
    });

    let provider_name = match provider_name {
        Some(name) => name,
        None => return,
    };

    std::fs::create_dir_all(manifests_dir).ok();
    let dest = manifests_dir.join(format!("{provider_name}.toml"));

    if dest.exists() {
        println!("Provider '{provider_name}' already has a manifest, skipping generation.");
        return;
    }

    let env_provider = std::env::var("ATI_MANIFEST_PROVIDER")
        .ok()
        .map(|s| s.to_lowercase());

    // Determine which LLM backend to use
    let want_local = use_local || env_provider.as_deref() == Some("local");

    if want_local {
        // --local is a HARD constraint: use ollama only, error if unavailable
        println!("Generating manifest for '{provider_name}' from SKILL.md (local/ollama)...");
        match call_ollama_for_manifest(&skill_md, &provider_name, &skill_toml_content) {
            Ok(manifest_toml) => {
                if try_write_manifest(&dest, &manifest_toml, &provider_name) {
                    return;
                }
            }
            Err(e) => {
                eprintln!("Error: Local manifest generation failed: {e}");
                eprintln!(
                    "  Is ollama running? Check with: curl http://localhost:11434/v1/models"
                );
                // --local means NO fallback to network — only try bundled provider.toml
            }
        }
    } else {
        // Network-based LLM generation with fallback chain
        let api_key = match env_provider.as_deref() {
            Some("cerebras") => std::env::var("CEREBRAS_API_KEY").ok(),
            Some("anthropic") => std::env::var("ANTHROPIC_API_KEY").ok(),
            _ => std::env::var("CEREBRAS_API_KEY")
                .or_else(|_| std::env::var("ANTHROPIC_API_KEY"))
                .ok(),
        };

        if let Some(key) = api_key {
            println!("Generating manifest for '{provider_name}' from SKILL.md...");
            match call_cerebras_for_manifest(
                &key,
                &provider_name,
                &skill_md,
                &skill_toml_content,
            )
            .await
            {
                Ok(manifest_toml) => {
                    if try_write_manifest(&dest, &manifest_toml, &provider_name) {
                        return;
                    }
                }
                Err(e) => {
                    eprintln!("Warning: LLM manifest generation failed: {e}");
                }
            }
        }
    }

    // Fallback: try bundled provider.toml
    let _ = install_bundled_provider(skill_dir, manifests_dir);
}

/// Try to write a generated manifest TOML to disk.
/// Returns true if written successfully, false otherwise.
fn try_write_manifest(dest: &std::path::Path, manifest_toml: &str, provider_name: &str) -> bool {
    if manifest_toml.contains("[provider]") && manifest_toml.contains("name =") {
        match std::fs::write(dest, manifest_toml) {
            Ok(()) => {
                println!(
                    "Generated manifest for '{provider_name}' at {}",
                    dest.display()
                );
                print_auth_key_hint(manifest_toml);
                true
            }
            Err(e) => {
                eprintln!("Warning: Failed to write generated manifest: {e}");
                false
            }
        }
    } else {
        eprintln!("Warning: LLM output didn't look like a valid manifest, trying fallback.");
        false
    }
}

/// Extract the first provider name from skill.toml's providers = ["..."] field.
fn extract_provider_name(skill_toml: &str) -> Option<String> {
    for line in skill_toml.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("providers") && trimmed.contains('=') {
            // Parse providers = ["fal"] or providers = ["fal", "other"]
            if let Some(bracket_start) = trimmed.find('[') {
                if let Some(bracket_end) = trimmed.find(']') {
                    let inner = &trimmed[bracket_start + 1..bracket_end];
                    let first = inner.split(',').next()?;
                    let name = first.trim().trim_matches('"').trim_matches('\'');
                    if !name.is_empty() {
                        return Some(name.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Print a hint about which API key to set, extracted from the manifest TOML.
fn print_auth_key_hint(manifest_toml: &str) {
    for line in manifest_toml.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("auth_key_name") && trimmed.contains('=') {
            if let Some(val) = trimmed.split('=').nth(1) {
                let key_name = val.trim().trim_matches('"').trim_matches('\'');
                if !key_name.is_empty() {
                    println!(
                        "  Hint: run `ati key set {key_name} <your-key>` to configure credentials."
                    );
                }
            }
            break;
        }
    }
}

const MANIFEST_EXTRACTION_PROMPT: &str = r#"You are an ATI manifest generator. Given a skill's SKILL.md documentation, extract a provider manifest in TOML format.

The manifest must follow this exact structure:

```toml
[provider]
name = "<provider_name>"
description = "<one-line description>"
base_url = "<base URL for API>"
auth_type = "<bearer|header|query|basic|none>"
# Include these ONLY if auth_type requires them:
# auth_key_name = "<keyring key name>"
# auth_header_name = "<header name>"      (if auth_type = "header")
# auth_value_prefix = "<prefix> "         (if auth_type = "header", e.g. "Key " or "Bearer ")
# auth_query_name = "<query param name>"  (if auth_type = "query")
category = "<category>"

[[tools]]
name = "<provider>__<tool_name>"
description = "<what this tool does>"
endpoint = "/<path>"
method = "<GET|POST|PUT|DELETE>"
tags = ["tag1", "tag2"]
[tools.input_schema]
type = "object"
required = ["param1"]
[tools.input_schema.properties.param1]
type = "string"
description = "Description"
# Use "x-ati-param-location" = "path" for URL path params
# Use "x-ati-param-location" = "query" for query string params
# Omit x-ati-param-location for body params (default)
```

Rules:
- Tool names MUST be prefixed with the provider name and double underscore: `<provider>__<tool_name>`
- URL path parameters like `/{id}` MUST have `"x-ati-param-location" = "path"` on the property
- Extract ALL tools/endpoints mentioned in the documentation
- For auth, infer from any API key references, Authorization headers, or token mentions
- Output ONLY the TOML — no markdown fences, no explanation
"#;

/// Call Cerebras (or Anthropic fallback) to extract a manifest from SKILL.md content.
async fn call_cerebras_for_manifest(
    api_key: &str,
    provider_name: &str,
    skill_md: &str,
    skill_toml: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let user_content = format!(
        "Provider name: {provider_name}\n\n## skill.toml\n```\n{skill_toml}\n```\n\n## SKILL.md\n```\n{skill_md}\n```\n\nGenerate the ATI manifest TOML for this provider. Output ONLY the TOML, nothing else."
    );

    // Detect which API to use based on key format
    let is_cerebras = api_key.starts_with("csk-");

    let (url, body) = if is_cerebras {
        (
            "https://api.cerebras.ai/v1/chat/completions".to_string(),
            serde_json::json!({
                "model": "qwen-3-235b-a22b-instruct-2507",
                "messages": [
                    {"role": "system", "content": MANIFEST_EXTRACTION_PROMPT},
                    {"role": "user", "content": user_content}
                ],
                "max_completion_tokens": 4096,
                "temperature": 0.1
            }),
        )
    } else {
        // Anthropic
        let model = std::env::var("ATI_ASSIST_MODEL")
            .unwrap_or_else(|_| "claude-haiku-4-5-20251001".to_string());
        (
            "https://api.anthropic.com/v1/messages".to_string(),
            serde_json::json!({
                "model": model,
                "max_tokens": 4096,
                "system": MANIFEST_EXTRACTION_PROMPT,
                "messages": [
                    {"role": "user", "content": user_content}
                ]
            }),
        )
    };

    let mut req = client.post(&url);
    if is_cerebras {
        req = req.bearer_auth(api_key);
    } else {
        req = req
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json");
    }

    let response = req.json(&body).send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("LLM API error ({status}): {body}").into());
    }

    let resp_body: serde_json::Value = response.json().await?;

    let content = if is_cerebras {
        resp_body
            .pointer("/choices/0/message/content")
            .and_then(|c| c.as_str())
    } else {
        resp_body
            .pointer("/content/0/text")
            .and_then(|c| c.as_str())
    };

    let raw = content.ok_or("No content in LLM response")?.to_string();

    // Strip markdown fences if the LLM wrapped the output
    let cleaned = if raw.contains("```toml") {
        raw.split("```toml")
            .nth(1)
            .and_then(|s| s.split("```").next())
            .unwrap_or(&raw)
            .trim()
            .to_string()
    } else if raw.contains("```") {
        raw.split("```")
            .nth(1)
            .and_then(|s| s.split("```").next())
            .unwrap_or(&raw)
            .trim()
            .to_string()
    } else {
        raw.trim().to_string()
    };

    Ok(cleaned)
}

/// Call a local ollama instance to extract a manifest from SKILL.md content.
/// Uses the OpenAI-compatible `/v1/chat/completions` endpoint.
/// Respects `OLLAMA_HOST` (default: http://localhost:11434) and `ATI_OLLAMA_MODEL` (default: llama3.1).
fn call_ollama_for_manifest(
    skill_md: &str,
    provider_name: &str,
    skill_toml: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let host = std::env::var("OLLAMA_HOST")
        .unwrap_or_else(|_| "http://localhost:11434".to_string());
    let model =
        std::env::var("ATI_OLLAMA_MODEL").unwrap_or_else(|_| "llama3.1".to_string());
    let url = format!("{}/v1/chat/completions", host.trim_end_matches('/'));

    let user_content = format!(
        "Provider name: {provider_name}\n\n## skill.toml\n```\n{skill_toml}\n```\n\n## SKILL.md\n```\n{skill_md}\n```\n\nGenerate the ATI manifest TOML for this provider. Output ONLY the TOML, nothing else."
    );

    let request_body = serde_json::json!({
        "model": model,
        "messages": [
            {"role": "system", "content": MANIFEST_EXTRACTION_PROMPT},
            {"role": "user", "content": user_content}
        ],
        "temperature": 0.1
    });

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    let response = client.post(&url).json(&request_body).send().map_err(|e| {
        format!("Cannot connect to ollama at {host}: {e}")
    })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        return Err(format!("Ollama error ({status}): {body}").into());
    }

    let body: serde_json::Value = response.json()?;
    let raw = body
        .pointer("/choices/0/message/content")
        .and_then(|c| c.as_str())
        .ok_or("No content in ollama response")?
        .to_string();

    // Strip markdown fences if the LLM wrapped the output
    let cleaned = if raw.contains("```toml") {
        raw.split("```toml")
            .nth(1)
            .and_then(|s| s.split("```").next())
            .unwrap_or(&raw)
            .trim()
            .to_string()
    } else if raw.contains("```") {
        raw.split("```")
            .nth(1)
            .and_then(|s| s.split("```").next())
            .unwrap_or(&raw)
            .trim()
            .to_string()
    } else {
        raw.trim().to_string()
    };

    Ok(cleaned)
}

/// Install a bundled provider.toml from a skill directory into the manifests directory.
/// If the provider already exists, skip with a message.
/// Used as a sync fallback when LLM generation is not available.
fn install_bundled_provider(
    skill_dir: &std::path::Path,
    manifests_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let provider_toml = skill_dir.join("provider.toml");
    if !provider_toml.exists() {
        return Ok(());
    }

    let content = std::fs::read_to_string(&provider_toml)?;

    // Extract provider name from [provider] name = "..."
    let provider_name = content
        .lines()
        .find(|line| {
            let trimmed = line.trim();
            trimmed.starts_with("name") && trimmed.contains('=')
        })
        .and_then(|line| {
            let val = line.split('=').nth(1)?.trim();
            let unquoted = val.trim_matches('"').trim_matches('\'');
            if unquoted.is_empty() {
                None
            } else {
                Some(unquoted.to_string())
            }
        })
        .ok_or("Bundled provider.toml has no 'name' field under [provider]")?;

    std::fs::create_dir_all(manifests_dir)?;
    let dest = manifests_dir.join(format!("{provider_name}.toml"));

    if dest.exists() {
        println!("Provider '{provider_name}' already installed, skipping bundled manifest.");
        return Ok(());
    }

    std::fs::copy(&provider_toml, &dest)?;
    println!(
        "Installed bundled provider '{provider_name}' to {}",
        dest.display()
    );
    print_auth_key_hint(&content);

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

    #[test]
    fn test_is_git_url_https() {
        assert!(is_git_url("https://github.com/org/repo"));
        assert!(is_git_url("https://github.com/org/repo#subdir"));
        assert!(is_git_url("http://example.com/repo.git"));
    }

    #[test]
    fn test_is_git_url_ssh() {
        assert!(is_git_url("git@github.com:org/repo.git"));
    }

    #[test]
    fn test_is_git_url_dot_git_suffix() {
        assert!(is_git_url("some-repo.git"));
    }

    #[test]
    fn test_is_git_url_local_paths() {
        assert!(!is_git_url("/home/user/skills/my-skill"));
        assert!(!is_git_url("./my-skill"));
        assert!(!is_git_url("relative/path"));
    }

    #[test]
    fn test_parse_git_url_fragment_with_subdir() {
        let (url, sub) = parse_git_url_fragment("https://github.com/org/repo#finnhub-analysis");
        assert_eq!(url, "https://github.com/org/repo");
        assert_eq!(sub, Some("finnhub-analysis"));
    }

    #[test]
    fn test_parse_git_url_fragment_without_fragment() {
        let (url, sub) = parse_git_url_fragment("https://github.com/org/repo");
        assert_eq!(url, "https://github.com/org/repo");
        assert_eq!(sub, None);
    }

    #[test]
    fn test_parse_git_url_fragment_empty_fragment() {
        let (url, sub) = parse_git_url_fragment("https://github.com/org/repo#");
        assert_eq!(url, "https://github.com/org/repo");
        assert_eq!(sub, None);
    }

    #[test]
    fn test_parse_source_with_sha_full_sha() {
        let (base, sha) = parse_source_with_sha(
            "https://github.com/org/repo#skill@abc1234def5678901234567890abcdef12345678",
        );
        assert_eq!(base, "https://github.com/org/repo#skill");
        assert_eq!(
            sha,
            Some("abc1234def5678901234567890abcdef12345678")
        );
    }

    #[test]
    fn test_parse_source_with_sha_short_sha() {
        let (base, sha) = parse_source_with_sha("https://github.com/org/repo@abc1234");
        assert_eq!(base, "https://github.com/org/repo");
        assert_eq!(sha, Some("abc1234"));
    }

    #[test]
    fn test_parse_source_with_sha_no_sha() {
        let (base, sha) = parse_source_with_sha("https://github.com/org/repo#subdir");
        assert_eq!(base, "https://github.com/org/repo#subdir");
        assert_eq!(sha, None);
    }

    #[test]
    fn test_parse_source_with_sha_at_in_email() {
        // @ in email-style URLs should NOT be treated as SHA
        let (base, sha) = parse_source_with_sha("git@github.com:org/repo.git");
        assert_eq!(base, "git@github.com:org/repo.git");
        assert_eq!(sha, None); // "github.com:org/repo.git" is not hex
    }

    #[test]
    fn test_parse_source_with_sha_too_short() {
        let (base, sha) = parse_source_with_sha("https://github.com/repo@abc");
        assert_eq!(base, "https://github.com/repo@abc");
        assert_eq!(sha, None); // only 3 chars, need 7+
    }
}
