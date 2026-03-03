/// CLI commands for OpenAPI spec management.
///
/// `ati openapi inspect <spec>` — preview operations in a spec
/// `ati openapi import <spec>` — download spec and generate TOML manifest

use std::path::PathBuf;

use crate::core::openapi::{self, OpenApiFilters};
use crate::OpenapiCommands;

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

pub async fn execute(
    subcmd: &OpenapiCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match subcmd {
        OpenapiCommands::Inspect { spec, include_tags } => inspect(spec, include_tags),
        OpenapiCommands::Import {
            spec,
            name,
            auth_key,
            include_tags,
            dry_run,
        } => import(spec, name, auth_key.as_deref(), include_tags, *dry_run),
    }
}

/// Inspect an OpenAPI spec — list operations, auth schemes, base URL.
fn inspect(
    spec_path: &str,
    include_tags: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let content = read_spec_content(spec_path)?;
    let spec = openapi::parse_spec(&content)?;

    // Print spec info
    println!("OpenAPI: {} v{}", spec.info.title, spec.info.version);
    if let Some(desc) = &spec.info.description {
        let short = if desc.len() > 120 {
            format!("{}...", &desc[..117])
        } else {
            desc.clone()
        };
        println!("  {short}");
    }

    if let Some(base_url) = openapi::spec_base_url(&spec) {
        println!("Base URL: {base_url}");
    }

    // Auth detection
    let (auth_type, auth_extra) = openapi::detect_auth(&spec);
    let auth_detail = if auth_extra.is_empty() {
        auth_type.clone()
    } else {
        let extras: Vec<String> = auth_extra.iter().map(|(k, v)| format!("{k}={v}")).collect();
        format!("{auth_type} ({})", extras.join(", "))
    };
    println!("Auth: {auth_detail}");

    // List all operations
    let ops = openapi::list_operations(&spec);

    // Apply tag filter if provided
    let filtered_ops: Vec<_> = if include_tags.is_empty() {
        ops.iter().collect()
    } else {
        ops.iter()
            .filter(|op| op.tags.iter().any(|t| include_tags.contains(t)))
            .collect()
    };

    println!("\nOperations ({}):", filtered_ops.len());

    // Group by tags
    let mut by_tag: std::collections::BTreeMap<String, Vec<&openapi::OperationSummary>> =
        std::collections::BTreeMap::new();

    for op in &filtered_ops {
        if op.tags.is_empty() {
            by_tag.entry("(untagged)".into()).or_default().push(op);
        } else {
            for tag in &op.tags {
                by_tag.entry(tag.clone()).or_default().push(op);
            }
        }
    }

    for (tag, ops) in &by_tag {
        println!("  TAG: {tag} ({} operations)", ops.len());
        for op in ops {
            let desc = if op.description.len() > 50 {
                format!("{}...", &op.description[..47])
            } else {
                op.description.clone()
            };
            println!(
                "    {:<24} {:<7} {:<30} {}",
                op.operation_id, op.method, op.path, desc
            );
        }
    }

    Ok(())
}

/// Import an OpenAPI spec — download to ~/.ati/specs/, generate TOML manifest.
fn import(
    spec_path: &str,
    name: &str,
    auth_key: Option<&str>,
    include_tags: &[String],
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = read_spec_content(spec_path)?;
    let spec = openapi::parse_spec(&content)?;

    // Detect auth
    let (auth_type, auth_extra) = openapi::detect_auth(&spec);

    // Determine base URL
    let base_url = openapi::spec_base_url(&spec).unwrap_or_default();

    // Count operations with tag filter
    let filters = OpenApiFilters {
        include_tags: include_tags.to_vec(),
        exclude_tags: vec![],
        include_operations: vec![],
        exclude_operations: vec![],
        max_operations: None,
    };
    let tools = openapi::extract_tools(&spec, &filters);

    // Build TOML manifest
    let mut toml_lines = Vec::new();
    toml_lines.push("[provider]".into());
    toml_lines.push(format!("name = \"{}\"", name));
    toml_lines.push(format!(
        "description = \"{}\"",
        spec.info.title.replace('"', "\\\"")
    ));
    toml_lines.push("handler = \"openapi\"".into());
    toml_lines.push(format!("base_url = \"{}\"", base_url));

    // Spec file reference (will be stored in ~/.ati/specs/)
    let spec_filename = format!("{name}.json");
    toml_lines.push(format!("openapi_spec = \"{}\"", spec_filename));

    // Auth config
    let default_key_name = format!("{name}_api_key");
    let key_name = auth_key.unwrap_or(&default_key_name);
    toml_lines.push(format!("auth_type = \"{}\"", auth_type));
    if auth_type != "none" {
        toml_lines.push(format!("auth_key_name = \"{}\"", key_name));
    }
    for (k, v) in &auth_extra {
        toml_lines.push(format!("{k} = \"{v}\""));
    }

    // Tag filters
    if !include_tags.is_empty() {
        let tags_str: Vec<String> = include_tags.iter().map(|t| format!("\"{t}\"")).collect();
        toml_lines.push(format!("openapi_include_tags = [{}]", tags_str.join(", ")));
    }

    let toml_content = toml_lines.join("\n") + "\n";

    if dry_run {
        println!("--- Generated manifest ({name}.toml) ---");
        println!("{toml_content}");
        println!("--- Spec: {} ({} operations) ---", spec.info.title, tools.len());
        println!("Would save spec to: ~/.ati/specs/{spec_filename}");
        println!("Would save manifest to: ~/.ati/manifests/{name}.toml");
        return Ok(());
    }

    // Save spec file
    let ati_dir = ati_dir();
    let specs_dir = ati_dir.join("specs");
    std::fs::create_dir_all(&specs_dir)?;
    let spec_dest = specs_dir.join(&spec_filename);

    // Normalize to JSON for consistent parsing
    let spec_json = serde_json::to_string_pretty(&spec)?;
    std::fs::write(&spec_dest, &spec_json)?;
    eprintln!("Saved spec to {}", spec_dest.display());

    // Save manifest
    let manifests_dir = ati_dir.join("manifests");
    std::fs::create_dir_all(&manifests_dir)?;
    let manifest_dest = manifests_dir.join(format!("{name}.toml"));
    std::fs::write(&manifest_dest, &toml_content)?;
    eprintln!("Saved manifest to {}", manifest_dest.display());

    eprintln!(
        "\nImported {} operations from \"{}\"",
        tools.len(),
        spec.info.title
    );
    if auth_type != "none" {
        eprintln!(
            "Remember to add your API key: ati auth set {key_name} <your-key>"
        );
    }

    Ok(())
}

/// Read spec content from a file path or URL.
fn read_spec_content(spec_ref: &str) -> Result<String, Box<dyn std::error::Error>> {
    if spec_ref.starts_with("http://") || spec_ref.starts_with("https://") {
        // Download spec from URL
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        let response = client.get(spec_ref).send()?;
        if !response.status().is_success() {
            return Err(format!(
                "Failed to fetch spec from {}: {}",
                spec_ref,
                response.status()
            )
            .into());
        }
        Ok(response.text()?)
    } else {
        // Read from file
        Ok(std::fs::read_to_string(spec_ref)?)
    }
}
