/// Skill management — structured metadata, registry, and scope-driven resolution.
///
/// Each skill directory contains:
///   - `SKILL.md`    — methodology content with optional YAML frontmatter (Anthropic spec)
///   - `skill.toml`  — optional ATI extension for tool/provider/category bindings
///   - `references/` — optional supporting documentation
///   - `scripts/`    — optional helper scripts
///   - `assets/`     — optional templates, configs, data files
///
/// Metadata priority: YAML frontmatter in SKILL.md > skill.toml > inferred from content.
/// Skills reference manifests (tools, providers, categories), never the reverse.
/// Installing a skill never requires editing existing manifests.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::core::manifest::ManifestRegistry;
use crate::core::scope::ScopeConfig;

#[derive(Error, Debug)]
pub enum SkillError {
    #[error("Failed to read skill file {0}: {1}")]
    Io(String, std::io::Error),
    #[error("Failed to parse skill.toml {0}: {1}")]
    Parse(String, toml::de::Error),
    #[error("Skill not found: {0}")]
    NotFound(String),
    #[error("Skills directory not found: {0}")]
    NoDirectory(String),
    #[error("Invalid skill: {0}")]
    Invalid(String),
}

/// Anthropic Agent Skills spec frontmatter (YAML in SKILL.md).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct AnthropicFrontmatter {
    pub name: Option<String>,
    pub description: Option<String>,
    pub license: Option<String>,
    pub compatibility: Option<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    /// Space-delimited allowed tools string, e.g. "Bash(git:*) Read"
    #[serde(rename = "allowed-tools")]
    pub allowed_tools: Option<String>,
}

/// Parse YAML frontmatter from SKILL.md content.
///
/// Returns `(Some(frontmatter), body)` if `---` delimiters found and YAML parses,
/// or `(None, original_content)` on any failure (graceful fallback).
pub fn parse_frontmatter(content: &str) -> (Option<AnthropicFrontmatter>, &str) {
    let trimmed = content.trim_start();
    if !trimmed.starts_with("---") {
        return (None, content);
    }

    // Find the closing `---` after the opening one
    let after_open = &trimmed[3..];
    // Skip the rest of the opening `---` line
    let after_open = match after_open.find('\n') {
        Some(pos) => &after_open[pos + 1..],
        None => return (None, content),
    };

    match after_open.find("\n---") {
        Some(end_pos) => {
            let yaml_str = &after_open[..end_pos];
            let body_start = &after_open[end_pos + 4..]; // skip \n---
                                                         // Skip rest of closing --- line
            let body = match body_start.find('\n') {
                Some(pos) => &body_start[pos + 1..],
                None => "",
            };

            match serde_yaml::from_str::<AnthropicFrontmatter>(yaml_str) {
                Ok(fm) => (Some(fm), body),
                Err(_) => (None, content), // Malformed YAML → treat as no frontmatter
            }
        }
        None => (None, content),
    }
}

/// Strip YAML frontmatter from SKILL.md content, returning only the body.
pub fn strip_frontmatter(content: &str) -> &str {
    let (_, body) = parse_frontmatter(content);
    body
}

/// Compute SHA-256 hash of content, returning lowercase hex string.
pub fn compute_content_hash(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Validate a skill name against the Anthropic Agent Skills naming rules.
///
/// Rules: 1-64 chars, lowercase letters + digits + hyphens, no consecutive hyphens,
/// must start/end with a letter or digit.
pub fn is_anthropic_valid_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    let bytes = name.as_bytes();
    // Must start and end with alphanumeric
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    if !bytes[bytes.len() - 1].is_ascii_lowercase() && !bytes[bytes.len() - 1].is_ascii_digit() {
        return false;
    }
    // Only lowercase, digits, hyphens; no consecutive hyphens
    let mut prev_hyphen = false;
    for &b in bytes {
        if b == b'-' {
            if prev_hyphen {
                return false;
            }
            prev_hyphen = true;
        } else if b.is_ascii_lowercase() || b.is_ascii_digit() {
            prev_hyphen = false;
        } else {
            return false;
        }
    }
    true
}

/// Skill metadata format — indicates how the metadata was sourced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SkillFormat {
    /// Anthropic spec: YAML frontmatter in SKILL.md
    #[serde(rename = "anthropic")]
    Anthropic,
    /// ATI legacy: skill.toml only
    #[serde(rename = "legacy-toml")]
    LegacyToml,
    /// Inferred: SKILL.md without frontmatter or skill.toml
    #[serde(rename = "inferred")]
    Inferred,
}

/// Structured metadata from `skill.toml` and/or YAML frontmatter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillMeta {
    pub name: String,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub author: Option<String>,

    // --- Tool/provider/category bindings (auto-load when these are in scope) ---
    /// Exact tool names this skill covers (e.g., ["ca_business_sanctions_search"])
    #[serde(default)]
    pub tools: Vec<String>,
    /// Provider names this skill covers (e.g., ["complyadvantage"])
    #[serde(default)]
    pub providers: Vec<String>,
    /// Provider categories this skill covers (e.g., ["compliance"])
    #[serde(default)]
    pub categories: Vec<String>,

    // --- Discovery metadata ---
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub hint: Option<String>,

    // --- Dependencies ---
    /// Skills that must be transitively loaded with this one
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Informational suggestions (not auto-loaded)
    #[serde(default)]
    pub suggests: Vec<String>,

    // --- Anthropic spec fields ---
    /// SPDX license identifier (from frontmatter)
    #[serde(default)]
    pub license: Option<String>,
    /// Compatibility notes (from frontmatter, max 500 chars)
    #[serde(default)]
    pub compatibility: Option<String>,
    /// Arbitrary metadata key-value pairs (from frontmatter `metadata:` block)
    #[serde(default)]
    pub extra_metadata: HashMap<String, String>,
    /// Space-delimited allowed tools (from frontmatter `allowed-tools:`)
    #[serde(default)]
    pub allowed_tools: Option<String>,
    /// Whether the skill has YAML frontmatter in SKILL.md
    #[serde(default)]
    pub has_frontmatter: bool,
    /// How metadata was sourced
    #[serde(default = "default_format")]
    pub format: SkillFormat,

    // --- Supply chain integrity (stored in [ati.integrity] section of skill.toml) ---
    /// Source URL this skill was installed from
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    /// SHA-256 hash of SKILL.md content at install time
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    /// Pinned git SHA (from source@SHA syntax)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_sha: Option<String>,

    // --- Runtime (not in TOML, set after loading) ---
    /// Absolute path to the skill directory
    #[serde(skip)]
    pub dir: PathBuf,
}

impl Default for SkillMeta {
    fn default() -> Self {
        Self {
            name: String::new(),
            version: default_version(),
            description: String::new(),
            author: None,
            tools: Vec::new(),
            providers: Vec::new(),
            categories: Vec::new(),
            keywords: Vec::new(),
            hint: None,
            depends_on: Vec::new(),
            suggests: Vec::new(),
            license: None,
            compatibility: None,
            extra_metadata: HashMap::new(),
            allowed_tools: None,
            has_frontmatter: false,
            format: SkillFormat::Inferred,
            source_url: None,
            content_hash: None,
            pinned_sha: None,
            dir: PathBuf::new(),
        }
    }
}

fn default_format() -> SkillFormat {
    SkillFormat::Inferred
}

fn default_version() -> String {
    "0.1.0".to_string()
}

/// Wrapper for the `[skill]` table in skill.toml.
#[derive(Debug, Deserialize)]
struct SkillToml {
    skill: SkillMeta,
}

/// Registry of all loaded skills with indexes for fast lookup.
pub struct SkillRegistry {
    skills: Vec<SkillMeta>,
    /// skill name → index
    name_index: HashMap<String, usize>,
    /// tool name → skill indices
    tool_index: HashMap<String, Vec<usize>>,
    /// provider name → skill indices
    provider_index: HashMap<String, Vec<usize>>,
    /// category name → skill indices
    category_index: HashMap<String, Vec<usize>>,
    /// Cached files for non-filesystem skills (e.g. GCS).
    /// Key: (skill_name, relative_path), Value: file bytes.
    files_cache: HashMap<(String, String), Vec<u8>>,
}

impl SkillRegistry {
    /// Load all skills from a directory. Each subdirectory is a skill.
    ///
    /// If `skill.toml` exists, parse it for full metadata.
    /// Otherwise, fall back to reading `SKILL.md` for name + description only.
    pub fn load(skills_dir: &Path) -> Result<Self, SkillError> {
        let mut skills = Vec::new();
        let mut name_index = HashMap::new();
        let mut tool_index: HashMap<String, Vec<usize>> = HashMap::new();
        let mut provider_index: HashMap<String, Vec<usize>> = HashMap::new();
        let mut category_index: HashMap<String, Vec<usize>> = HashMap::new();

        if !skills_dir.is_dir() {
            // Not an error — just an empty registry
            return Ok(SkillRegistry {
                skills,
                name_index,
                tool_index,
                provider_index,
                category_index,
                files_cache: HashMap::new(),
            });
        }

        let entries = std::fs::read_dir(skills_dir)
            .map_err(|e| SkillError::Io(skills_dir.display().to_string(), e))?;

        for entry in entries {
            let entry = entry.map_err(|e| SkillError::Io(skills_dir.display().to_string(), e))?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let skill = load_skill_from_dir(&path)?;

            let idx = skills.len();
            name_index.insert(skill.name.clone(), idx);

            for tool in &skill.tools {
                tool_index.entry(tool.clone()).or_default().push(idx);
            }
            for provider in &skill.providers {
                provider_index
                    .entry(provider.clone())
                    .or_default()
                    .push(idx);
            }
            for category in &skill.categories {
                category_index
                    .entry(category.clone())
                    .or_default()
                    .push(idx);
            }

            skills.push(skill);
        }

        Ok(SkillRegistry {
            skills,
            name_index,
            tool_index,
            provider_index,
            category_index,
            files_cache: HashMap::new(),
        })
    }

    /// Merge skills from a remote source (e.g. GCS).
    /// Local skills take precedence on name collision.
    pub fn merge(&mut self, source: crate::core::gcs::GcsSkillSource) {
        let mut added: std::collections::HashSet<String> = std::collections::HashSet::new();

        for skill in source.skills {
            if self.name_index.contains_key(&skill.name) {
                // Local wins — skip this GCS skill entirely
                continue;
            }
            added.insert(skill.name.clone());
            let idx = self.skills.len();
            self.name_index.insert(skill.name.clone(), idx);
            for tool in &skill.tools {
                self.tool_index.entry(tool.clone()).or_default().push(idx);
            }
            for provider in &skill.providers {
                self.provider_index
                    .entry(provider.clone())
                    .or_default()
                    .push(idx);
            }
            for category in &skill.categories {
                self.category_index
                    .entry(category.clone())
                    .or_default()
                    .push(idx);
            }
            self.skills.push(skill);
        }

        // Only merge files for skills that were actually added (not skipped).
        // This preserves "local wins" at the content layer too.
        for ((skill_name, rel_path), data) in source.files {
            if added.contains(&skill_name) {
                self.files_cache.insert((skill_name, rel_path), data);
            }
        }
    }

    /// Get a skill by name.
    pub fn get_skill(&self, name: &str) -> Option<&SkillMeta> {
        self.name_index.get(name).map(|&idx| &self.skills[idx])
    }

    /// List all loaded skills.
    pub fn list_skills(&self) -> &[SkillMeta] {
        &self.skills
    }

    /// Skills that cover a specific tool name.
    pub fn skills_for_tool(&self, tool_name: &str) -> Vec<&SkillMeta> {
        self.tool_index
            .get(tool_name)
            .map(|indices| indices.iter().map(|&i| &self.skills[i]).collect())
            .unwrap_or_default()
    }

    /// Skills that cover a specific provider name.
    pub fn skills_for_provider(&self, provider_name: &str) -> Vec<&SkillMeta> {
        self.provider_index
            .get(provider_name)
            .map(|indices| indices.iter().map(|&i| &self.skills[i]).collect())
            .unwrap_or_default()
    }

    /// Skills that cover a specific category.
    pub fn skills_for_category(&self, category: &str) -> Vec<&SkillMeta> {
        self.category_index
            .get(category)
            .map(|indices| indices.iter().map(|&i| &self.skills[i]).collect())
            .unwrap_or_default()
    }

    /// Search skills by fuzzy matching on name, description, keywords, hint, and tool names.
    pub fn search(&self, query: &str) -> Vec<&SkillMeta> {
        let q = query.to_lowercase();
        let terms: Vec<&str> = q.split_whitespace().collect();

        let mut scored: Vec<(usize, &SkillMeta)> = self
            .skills
            .iter()
            .filter_map(|skill| {
                let mut score = 0usize;
                let name_lower = skill.name.to_lowercase();
                let desc_lower = skill.description.to_lowercase();

                for term in &terms {
                    // Name match (highest weight)
                    if name_lower.contains(term) {
                        score += 10;
                    }
                    // Description match
                    if desc_lower.contains(term) {
                        score += 5;
                    }
                    // Keyword match
                    if skill
                        .keywords
                        .iter()
                        .any(|k| k.to_lowercase().contains(term))
                    {
                        score += 8;
                    }
                    // Tool name match
                    if skill.tools.iter().any(|t| t.to_lowercase().contains(term)) {
                        score += 6;
                    }
                    // Hint match
                    if let Some(hint) = &skill.hint {
                        if hint.to_lowercase().contains(term) {
                            score += 4;
                        }
                    }
                    // Provider match
                    if skill
                        .providers
                        .iter()
                        .any(|p| p.to_lowercase().contains(term))
                    {
                        score += 6;
                    }
                    // Category match
                    if skill
                        .categories
                        .iter()
                        .any(|c| c.to_lowercase().contains(term))
                    {
                        score += 4;
                    }
                }

                if score > 0 {
                    Some((score, skill))
                } else {
                    None
                }
            })
            .collect();

        // Sort by score descending
        scored.sort_by(|a, b| b.0.cmp(&a.0));
        scored.into_iter().map(|(_, skill)| skill).collect()
    }

    /// Read the SKILL.md content for a skill, stripping any YAML frontmatter.
    /// Checks the in-memory files cache first (for GCS skills), then falls back to filesystem.
    pub fn read_content(&self, name: &str) -> Result<String, SkillError> {
        // Check files cache (GCS / remote skills)
        if let Some(bytes) = self
            .files_cache
            .get(&(name.to_string(), "SKILL.md".to_string()))
        {
            let raw = std::str::from_utf8(bytes).unwrap_or("");
            return Ok(strip_frontmatter(raw).to_string());
        }

        // Fall back to filesystem (local skills)
        let skill = self
            .get_skill(name)
            .ok_or_else(|| SkillError::NotFound(name.to_string()))?;
        let skill_md = skill.dir.join("SKILL.md");
        if !skill_md.exists() {
            return Ok(String::new());
        }
        let raw = std::fs::read_to_string(&skill_md)
            .map_err(|e| SkillError::Io(skill_md.display().to_string(), e))?;
        Ok(strip_frontmatter(&raw).to_string())
    }

    /// List reference files for a skill.
    /// Checks files cache first (GCS), then filesystem.
    pub fn list_references(&self, name: &str) -> Result<Vec<String>, SkillError> {
        // Check files cache for references/*
        let prefix = "references/";
        let cached_refs: Vec<String> = self
            .files_cache
            .keys()
            .filter(|(skill, path)| skill == name && path.starts_with(prefix))
            .map(|(_, path)| path.strip_prefix(prefix).unwrap_or(path).to_string())
            .collect();
        if !cached_refs.is_empty() {
            let mut refs = cached_refs;
            refs.sort();
            return Ok(refs);
        }

        // Fall back to filesystem
        let skill = self
            .get_skill(name)
            .ok_or_else(|| SkillError::NotFound(name.to_string()))?;
        let refs_dir = skill.dir.join("references");
        if !refs_dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut refs = Vec::new();
        let entries = std::fs::read_dir(&refs_dir)
            .map_err(|e| SkillError::Io(refs_dir.display().to_string(), e))?;
        for entry in entries {
            let entry = entry.map_err(|e| SkillError::Io(refs_dir.display().to_string(), e))?;
            if let Some(name) = entry.file_name().to_str() {
                refs.push(name.to_string());
            }
        }
        refs.sort();
        Ok(refs)
    }

    /// Read a specific reference file.
    /// Checks files cache first (GCS), then filesystem.
    pub fn read_reference(&self, skill_name: &str, ref_name: &str) -> Result<String, SkillError> {
        // Path traversal protection: reject names with path components
        if ref_name.contains("..")
            || ref_name.contains('/')
            || ref_name.contains('\\')
            || ref_name.contains('\0')
        {
            return Err(SkillError::NotFound(format!(
                "Invalid reference name '{ref_name}' — path traversal not allowed"
            )));
        }

        // Check files cache (GCS / remote skills)
        let cache_key = (skill_name.to_string(), format!("references/{ref_name}"));
        if let Some(bytes) = self.files_cache.get(&cache_key) {
            return std::str::from_utf8(bytes)
                .map(|s| s.to_string())
                .map_err(|e| SkillError::Invalid(format!("invalid UTF-8 in reference: {e}")));
        }

        let skill = self
            .get_skill(skill_name)
            .ok_or_else(|| SkillError::NotFound(skill_name.to_string()))?;
        let refs_dir = skill.dir.join("references");
        let ref_path = refs_dir.join(ref_name);

        // Canonicalize and verify the resolved path is inside the references directory
        if let (Ok(canonical_ref), Ok(canonical_dir)) =
            (ref_path.canonicalize(), refs_dir.canonicalize())
        {
            if !canonical_ref.starts_with(&canonical_dir) {
                return Err(SkillError::NotFound(format!(
                    "Reference '{ref_name}' resolves outside references directory"
                )));
            }
        }

        if !ref_path.exists() {
            return Err(SkillError::NotFound(format!(
                "Reference '{ref_name}' in skill '{skill_name}'"
            )));
        }
        std::fs::read_to_string(&ref_path)
            .map_err(|e| SkillError::Io(ref_path.display().to_string(), e))
    }

    /// Get all files in a skill as a map of relative_path → bytes.
    /// Works for both local (filesystem) and remote (cached) skills.
    pub fn bundle_files(&self, name: &str) -> Result<HashMap<String, Vec<u8>>, SkillError> {
        let _skill = self
            .get_skill(name)
            .ok_or_else(|| SkillError::NotFound(name.to_string()))?;

        let mut files: HashMap<String, Vec<u8>> = HashMap::new();

        // Collect from files_cache (GCS / remote skills)
        for ((skill_name, rel_path), data) in &self.files_cache {
            if skill_name == name {
                files.insert(rel_path.clone(), data.clone());
            }
        }

        // If nothing from cache, read from filesystem
        if files.is_empty() {
            let skill = self.get_skill(name).unwrap();
            if skill.dir.is_dir() {
                collect_dir_files(&skill.dir, &skill.dir, &mut files)?;
            }
        }

        Ok(files)
    }

    /// Number of loaded skills.
    pub fn skill_count(&self) -> usize {
        self.skills.len()
    }

    /// Validate a skill's tool bindings against a ManifestRegistry.
    /// Returns (valid_tools, unknown_tools).
    pub fn validate_tool_bindings(
        &self,
        name: &str,
        manifest_registry: &ManifestRegistry,
    ) -> Result<(Vec<String>, Vec<String>), SkillError> {
        let skill = self
            .get_skill(name)
            .ok_or_else(|| SkillError::NotFound(name.to_string()))?;

        let mut valid = Vec::new();
        let mut unknown = Vec::new();

        for tool_name in &skill.tools {
            if manifest_registry.get_tool(tool_name).is_some() {
                valid.push(tool_name.clone());
            } else {
                unknown.push(tool_name.clone());
            }
        }

        Ok((valid, unknown))
    }
}

/// Resolve which skills should be auto-loaded based on scopes and a ManifestRegistry.
///
/// Resolution cascade:
/// 1. Explicit skill scopes: "skill:X" → load X directly
/// 2. Tool binding: "tool:Y" → skills where tools contains "Y"
/// 3. Provider binding: tool Y belongs to provider P → skills where providers contains "P"
/// 4. Category binding: provider P has category C → skills where categories contains "C"
/// 5. Dependency resolution: loaded skill depends_on Z → transitively load Z
///
/// Wildcard scope (*) = all skills available but not auto-loaded.
pub fn resolve_skills<'a>(
    skill_registry: &'a SkillRegistry,
    manifest_registry: &ManifestRegistry,
    scopes: &ScopeConfig,
) -> Vec<&'a SkillMeta> {
    let mut resolved_indices: Vec<usize> = Vec::new();
    let mut seen: std::collections::HashSet<usize> = std::collections::HashSet::new();

    for scope in &scopes.scopes {
        // 1. Explicit skill scopes
        if let Some(skill_name) = scope.strip_prefix("skill:") {
            if let Some(&idx) = skill_registry.name_index.get(skill_name) {
                if seen.insert(idx) {
                    resolved_indices.push(idx);
                }
            }
        }

        // 2. Tool binding → skills covering that tool
        if let Some(tool_name) = scope.strip_prefix("tool:") {
            if let Some(indices) = skill_registry.tool_index.get(tool_name) {
                for &idx in indices {
                    if seen.insert(idx) {
                        resolved_indices.push(idx);
                    }
                }
            }

            // 3. Provider binding → skills covering the tool's provider
            if let Some((provider, _)) = manifest_registry.get_tool(tool_name) {
                if let Some(indices) = skill_registry.provider_index.get(&provider.name) {
                    for &idx in indices {
                        if seen.insert(idx) {
                            resolved_indices.push(idx);
                        }
                    }
                }

                // 4. Category binding → skills covering the provider's category
                if let Some(category) = &provider.category {
                    if let Some(indices) = skill_registry.category_index.get(category) {
                        for &idx in indices {
                            if seen.insert(idx) {
                                resolved_indices.push(idx);
                            }
                        }
                    }
                }
            }
        }
    }

    // 5. Dependency resolution (transitive)
    let mut i = 0;
    while i < resolved_indices.len() {
        let skill = &skill_registry.skills[resolved_indices[i]];
        for dep_name in &skill.depends_on {
            if let Some(&dep_idx) = skill_registry.name_index.get(dep_name) {
                if seen.insert(dep_idx) {
                    resolved_indices.push(dep_idx);
                }
            }
        }
        i += 1;
    }

    resolved_indices
        .into_iter()
        .map(|idx| &skill_registry.skills[idx])
        .collect()
}

/// Maximum size of skill content injected into LLM system prompts (32 KB).
/// Prevents prompt injection via extremely large SKILL.md files.
const MAX_SKILL_INJECT_SIZE: usize = 32 * 1024;

/// Build a skill context string for LLM system prompts.
/// For each skill: name, description, hint, covered tools.
/// Content is bounded and delimited to mitigate prompt injection.
pub fn build_skill_context(skills: &[&SkillMeta]) -> String {
    if skills.is_empty() {
        return String::new();
    }

    let mut total_size = 0;
    let mut sections = Vec::new();
    for skill in skills {
        let mut section = format!(
            "--- BEGIN SKILL: {} ---\n- **{}**: {}",
            skill.name, skill.name, skill.description
        );
        if let Some(hint) = &skill.hint {
            section.push_str(&format!("\n  Hint: {hint}"));
        }
        if !skill.tools.is_empty() {
            section.push_str(&format!("\n  Covers tools: {}", skill.tools.join(", ")));
        }
        if !skill.suggests.is_empty() {
            section.push_str(&format!(
                "\n  Related skills: {}",
                skill.suggests.join(", ")
            ));
        }
        section.push_str(&format!("\n--- END SKILL: {} ---", skill.name));

        total_size += section.len();
        if total_size > MAX_SKILL_INJECT_SIZE {
            sections.push("(remaining skills truncated due to size limit)".to_string());
            break;
        }
        sections.push(section);
    }
    sections.join("\n\n")
}

// --- Private helpers ---

/// Load a single skill from a directory.
///
/// Priority:
///   (A) SKILL.md with YAML frontmatter → primary source; merge ATI extensions from skill.toml
/// Recursively collect all files in a directory into a map of relative_path → bytes.
fn collect_dir_files(
    base: &Path,
    current: &Path,
    files: &mut HashMap<String, Vec<u8>>,
) -> Result<(), SkillError> {
    let entries =
        std::fs::read_dir(current).map_err(|e| SkillError::Io(current.display().to_string(), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| SkillError::Io(current.display().to_string(), e))?;
        let path = entry.path();
        if path.is_dir() {
            collect_dir_files(base, &path, files)?;
        } else if let Ok(rel) = path.strip_prefix(base) {
            if let Some(rel_str) = rel.to_str() {
                if let Ok(data) = std::fs::read(&path) {
                    files.insert(rel_str.to_string(), data);
                }
            }
        }
    }
    Ok(())
}

///   (B) No frontmatter + skill.toml → current legacy behavior
///   (C) No frontmatter + no skill.toml + SKILL.md exists → infer from content
fn load_skill_from_dir(dir: &Path) -> Result<SkillMeta, SkillError> {
    let skill_toml_path = dir.join("skill.toml");
    let skill_md_path = dir.join("SKILL.md");

    let dir_name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Try to read and parse frontmatter from SKILL.md
    let (frontmatter, _body) = if skill_md_path.exists() {
        let content = std::fs::read_to_string(&skill_md_path)
            .map_err(|e| SkillError::Io(skill_md_path.display().to_string(), e))?;
        let (fm, body) = parse_frontmatter(&content);
        // We need owned body for description inference later
        let body_owned = body.to_string();
        (fm, Some((content, body_owned)))
    } else {
        (None, None)
    };

    if let Some(fm) = frontmatter {
        // --- (A) Frontmatter exists → primary source ---
        let mut meta = SkillMeta {
            name: fm.name.unwrap_or_else(|| dir_name.clone()),
            description: fm.description.unwrap_or_default(),
            license: fm.license,
            compatibility: fm.compatibility,
            extra_metadata: fm.metadata,
            allowed_tools: fm.allowed_tools,
            has_frontmatter: true,
            format: SkillFormat::Anthropic,
            dir: dir.to_path_buf(),
            ..Default::default()
        };

        // Extract author/version from frontmatter metadata if present
        if let Some(author) = meta.extra_metadata.get("author").cloned() {
            meta.author = Some(author);
        }
        if let Some(version) = meta.extra_metadata.get("version").cloned() {
            meta.version = version;
        }

        // Merge ATI-extension fields from skill.toml if it exists
        if skill_toml_path.exists() {
            let contents = std::fs::read_to_string(&skill_toml_path)
                .map_err(|e| SkillError::Io(skill_toml_path.display().to_string(), e))?;
            if let Ok(parsed) = toml::from_str::<SkillToml>(&contents) {
                let ext = parsed.skill;
                // ATI-specific fields not in frontmatter
                meta.tools = ext.tools;
                meta.providers = ext.providers;
                meta.categories = ext.categories;
                meta.keywords = ext.keywords;
                meta.hint = ext.hint;
                meta.depends_on = ext.depends_on;
                meta.suggests = ext.suggests;
            }
        }

        load_integrity_info(&mut meta);
        Ok(meta)
    } else if skill_toml_path.exists() {
        // --- (B) No frontmatter + skill.toml → legacy behavior ---
        let contents = std::fs::read_to_string(&skill_toml_path)
            .map_err(|e| SkillError::Io(skill_toml_path.display().to_string(), e))?;
        let parsed: SkillToml = toml::from_str(&contents)
            .map_err(|e| SkillError::Parse(skill_toml_path.display().to_string(), e))?;
        let mut meta = parsed.skill;
        meta.dir = dir.to_path_buf();
        meta.format = SkillFormat::LegacyToml;
        if meta.name.is_empty() {
            meta.name = dir_name;
        }
        load_integrity_info(&mut meta);
        Ok(meta)
    } else if let Some((_full_content, body)) = _body {
        // --- (C) No frontmatter + no skill.toml + SKILL.md exists → infer ---
        let description = body
            .lines()
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.trim().to_string())
            .unwrap_or_default();

        Ok(SkillMeta {
            name: dir_name,
            description,
            format: SkillFormat::Inferred,
            dir: dir.to_path_buf(),
            ..Default::default()
        })
    } else {
        Err(SkillError::Invalid(format!(
            "Directory '{}' has neither skill.toml nor SKILL.md",
            dir.display()
        )))
    }
}

/// Parse skill metadata from raw SKILL.md content and optional skill.toml content.
///
/// Used by both local filesystem loading and remote sources (GCS).
/// The `name` parameter is the skill directory name (used as fallback if not in metadata).
pub fn parse_skill_metadata(
    name: &str,
    skill_md_content: &str,
    skill_toml_content: Option<&str>,
) -> Result<SkillMeta, SkillError> {
    let (frontmatter, body) = if !skill_md_content.is_empty() {
        let (fm, body) = parse_frontmatter(skill_md_content);
        (fm, Some(body.to_string()))
    } else {
        (None, None)
    };

    if let Some(fm) = frontmatter {
        // (A) Frontmatter exists → primary source
        let mut meta = SkillMeta {
            name: fm.name.unwrap_or_else(|| name.to_string()),
            description: fm.description.unwrap_or_default(),
            license: fm.license,
            compatibility: fm.compatibility,
            extra_metadata: fm.metadata,
            allowed_tools: fm.allowed_tools,
            has_frontmatter: true,
            format: SkillFormat::Anthropic,
            ..Default::default()
        };

        if let Some(author) = meta.extra_metadata.get("author").cloned() {
            meta.author = Some(author);
        }
        if let Some(version) = meta.extra_metadata.get("version").cloned() {
            meta.version = version;
        }

        // Merge ATI extensions from skill.toml if provided
        if let Some(toml_str) = skill_toml_content {
            if let Ok(parsed) = toml::from_str::<SkillToml>(toml_str) {
                let ext = parsed.skill;
                meta.tools = ext.tools;
                meta.providers = ext.providers;
                meta.categories = ext.categories;
                meta.keywords = ext.keywords;
                meta.hint = ext.hint;
                meta.depends_on = ext.depends_on;
                meta.suggests = ext.suggests;
            }
        }

        Ok(meta)
    } else if let Some(toml_str) = skill_toml_content {
        // (B) No frontmatter + skill.toml → legacy
        let parsed: SkillToml = toml::from_str(toml_str)
            .map_err(|e| SkillError::Parse(format!("{name}/skill.toml"), e))?;
        let mut meta = parsed.skill;
        meta.format = SkillFormat::LegacyToml;
        if meta.name.is_empty() {
            meta.name = name.to_string();
        }
        Ok(meta)
    } else if let Some(body) = body {
        // (C) SKILL.md without frontmatter or skill.toml → infer
        let description = body
            .lines()
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.trim().to_string())
            .unwrap_or_default();

        Ok(SkillMeta {
            name: name.to_string(),
            description,
            format: SkillFormat::Inferred,
            ..Default::default()
        })
    } else {
        Err(SkillError::Invalid(format!(
            "Skill '{name}' has neither skill.toml nor SKILL.md content"
        )))
    }
}

/// Read [ati.integrity] section from skill.toml and populate SkillMeta fields.
fn load_integrity_info(meta: &mut SkillMeta) {
    let toml_path = meta.dir.join("skill.toml");
    if !toml_path.exists() {
        return;
    }
    let contents = match std::fs::read_to_string(&toml_path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let parsed: toml::Value = match toml::from_str(&contents) {
        Ok(v) => v,
        Err(_) => return,
    };
    if let Some(integrity) = parsed.get("ati").and_then(|a| a.get("integrity")) {
        meta.content_hash = integrity
            .get("content_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        meta.source_url = integrity
            .get("source_url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        meta.pinned_sha = integrity
            .get("pinned_sha")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
    }
}

/// Generate a skeleton `skill.toml` for a new skill.
pub fn scaffold_skill_toml(name: &str, tools: &[String], provider: Option<&str>) -> String {
    let mut toml = format!(
        r#"[skill]
name = "{name}"
version = "0.1.0"
description = ""
"#
    );

    if !tools.is_empty() {
        let tools_str: Vec<String> = tools.iter().map(|t| format!("\"{t}\"")).collect();
        toml.push_str(&format!("tools = [{}]\n", tools_str.join(", ")));
    } else {
        toml.push_str("tools = []\n");
    }

    if let Some(p) = provider {
        toml.push_str(&format!("providers = [\"{p}\"]\n"));
    } else {
        toml.push_str("providers = []\n");
    }

    toml.push_str(
        r#"categories = []
keywords = []
hint = ""
depends_on = []
suggests = []
"#,
    );

    toml
}

/// Generate a skeleton `SKILL.md` (legacy format without frontmatter).
pub fn scaffold_skill_md(name: &str) -> String {
    let title = name
        .split('-')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().to_string() + c.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    format!(
        r#"# {title} Skill

TODO: Describe what this skill does and when to use it.

## Tools Available

- TODO: List the tools this skill covers

## Decision Tree

1. TODO: Step-by-step methodology

## Examples

TODO: Add example workflows
"#
    )
}

/// Generate a skeleton `SKILL.md` with Anthropic-spec YAML frontmatter.
pub fn scaffold_skill_md_with_frontmatter(name: &str, description: &str) -> String {
    let title = name
        .split('-')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().to_string() + c.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    format!(
        r#"---
name: {name}
description: {description}
metadata:
  version: "0.1.0"
---

# {title} Skill

TODO: Describe what this skill does and when to use it.

## Tools Available

- TODO: List the tools this skill covers

## Decision Tree

1. TODO: Step-by-step methodology

## Examples

TODO: Add example workflows
"#
    )
}

/// Generate an ATI extension `skill.toml` for fields not in the Anthropic spec.
/// Used alongside a SKILL.md with frontmatter.
pub fn scaffold_ati_extension_toml(name: &str, tools: &[String], provider: Option<&str>) -> String {
    let mut toml = format!(
        r#"# ATI extension fields for skill '{name}'
# Core metadata (name, description, license) lives in SKILL.md frontmatter.

[skill]
name = "{name}"
"#
    );

    if !tools.is_empty() {
        let tools_str: Vec<String> = tools.iter().map(|t| format!("\"{t}\"")).collect();
        toml.push_str(&format!("tools = [{}]\n", tools_str.join(", ")));
    } else {
        toml.push_str("tools = []\n");
    }

    if let Some(p) = provider {
        toml.push_str(&format!("providers = [\"{p}\"]\n"));
    } else {
        toml.push_str("providers = []\n");
    }

    toml.push_str(
        r#"categories = []
keywords = []
depends_on = []
suggests = []
"#,
    );

    toml
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn create_test_skill(
        dir: &Path,
        name: &str,
        tools: &[&str],
        providers: &[&str],
        categories: &[&str],
    ) {
        let skill_dir = dir.join(name);
        fs::create_dir_all(&skill_dir).unwrap();

        let tools_toml: Vec<String> = tools.iter().map(|t| format!("\"{t}\"")).collect();
        let providers_toml: Vec<String> = providers.iter().map(|p| format!("\"{p}\"")).collect();
        let categories_toml: Vec<String> = categories.iter().map(|c| format!("\"{c}\"")).collect();

        let toml_content = format!(
            r#"[skill]
name = "{name}"
version = "1.0.0"
description = "Test skill for {name}"
tools = [{tools}]
providers = [{providers}]
categories = [{categories}]
keywords = ["test", "{name}"]
hint = "Use for testing {name}"
depends_on = []
suggests = []
"#,
            tools = tools_toml.join(", "),
            providers = providers_toml.join(", "),
            categories = categories_toml.join(", "),
        );

        fs::write(skill_dir.join("skill.toml"), toml_content).unwrap();
        fs::write(
            skill_dir.join("SKILL.md"),
            format!("# {name}\n\nTest skill content."),
        )
        .unwrap();
    }

    #[test]
    fn test_load_skill_with_toml() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_skill(
            tmp.path(),
            "sanctions",
            &["ca_business_sanctions_search"],
            &["complyadvantage"],
            &["compliance"],
        );

        let registry = SkillRegistry::load(tmp.path()).unwrap();
        assert_eq!(registry.skill_count(), 1);

        let skill = registry.get_skill("sanctions").unwrap();
        assert_eq!(skill.version, "1.0.0");
        assert_eq!(skill.tools, vec!["ca_business_sanctions_search"]);
        assert_eq!(skill.providers, vec!["complyadvantage"]);
        assert_eq!(skill.categories, vec!["compliance"]);
    }

    #[test]
    fn test_load_skill_md_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let skill_dir = tmp.path().join("legacy-skill");
        fs::create_dir_all(&skill_dir).unwrap();
        fs::write(
            skill_dir.join("SKILL.md"),
            "# Legacy Skill\n\nA skill with only SKILL.md, no skill.toml.\n",
        )
        .unwrap();

        let registry = SkillRegistry::load(tmp.path()).unwrap();
        assert_eq!(registry.skill_count(), 1);

        let skill = registry.get_skill("legacy-skill").unwrap();
        assert_eq!(
            skill.description,
            "A skill with only SKILL.md, no skill.toml."
        );
        assert!(skill.tools.is_empty()); // No tool bindings without skill.toml
    }

    #[test]
    fn test_tool_index() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_skill(tmp.path(), "skill-a", &["tool_x", "tool_y"], &[], &[]);
        create_test_skill(tmp.path(), "skill-b", &["tool_y", "tool_z"], &[], &[]);

        let registry = SkillRegistry::load(tmp.path()).unwrap();

        // tool_x → only skill-a
        let skills = registry.skills_for_tool("tool_x");
        assert_eq!(skills.len(), 1);
        assert_eq!(skills[0].name, "skill-a");

        // tool_y → both skills
        let skills = registry.skills_for_tool("tool_y");
        assert_eq!(skills.len(), 2);

        // tool_z → only skill-b
        let skills = registry.skills_for_tool("tool_z");
        assert_eq!(skills.len(), 1);
        assert_eq!(skills[0].name, "skill-b");

        // nonexistent → empty
        assert!(registry.skills_for_tool("nope").is_empty());
    }

    #[test]
    fn test_provider_and_category_index() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_skill(
            tmp.path(),
            "compliance-skill",
            &[],
            &["complyadvantage"],
            &["compliance", "aml"],
        );

        let registry = SkillRegistry::load(tmp.path()).unwrap();

        assert_eq!(registry.skills_for_provider("complyadvantage").len(), 1);
        assert_eq!(registry.skills_for_category("compliance").len(), 1);
        assert_eq!(registry.skills_for_category("aml").len(), 1);
        assert!(registry.skills_for_provider("serpapi").is_empty());
    }

    #[test]
    fn test_search() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_skill(
            tmp.path(),
            "sanctions-screening",
            &["ca_business_sanctions_search"],
            &["complyadvantage"],
            &["compliance"],
        );
        create_test_skill(
            tmp.path(),
            "web-search",
            &["web_search"],
            &["serpapi"],
            &["search"],
        );

        let registry = SkillRegistry::load(tmp.path()).unwrap();

        // Search for "sanctions"
        let results = registry.search("sanctions");
        assert!(!results.is_empty());
        assert_eq!(results[0].name, "sanctions-screening");

        // Search for "web"
        let results = registry.search("web");
        assert!(!results.is_empty());
        assert_eq!(results[0].name, "web-search");

        // Search for something absent
        let results = registry.search("nonexistent");
        assert!(results.is_empty());
    }

    #[test]
    fn test_read_content_and_references() {
        let tmp = tempfile::tempdir().unwrap();
        let skill_dir = tmp.path().join("test-skill");
        let refs_dir = skill_dir.join("references");
        fs::create_dir_all(&refs_dir).unwrap();

        fs::write(
            skill_dir.join("skill.toml"),
            r#"[skill]
name = "test-skill"
description = "Test"
"#,
        )
        .unwrap();
        fs::write(skill_dir.join("SKILL.md"), "# Test\n\nContent here.").unwrap();
        fs::write(refs_dir.join("guide.md"), "Reference guide content").unwrap();

        let registry = SkillRegistry::load(tmp.path()).unwrap();

        let content = registry.read_content("test-skill").unwrap();
        assert!(content.contains("Content here."));

        let refs = registry.list_references("test-skill").unwrap();
        assert_eq!(refs, vec!["guide.md"]);

        let ref_content = registry.read_reference("test-skill", "guide.md").unwrap();
        assert!(ref_content.contains("Reference guide content"));
    }

    #[test]
    fn test_resolve_skills_explicit() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_skill(tmp.path(), "skill-a", &[], &[], &[]);
        create_test_skill(tmp.path(), "skill-b", &[], &[], &[]);

        let skill_reg = SkillRegistry::load(tmp.path()).unwrap();
        let manifest_reg = ManifestRegistry::empty();

        let scopes = ScopeConfig {
            scopes: vec!["skill:skill-a".to_string()],
            sub: String::new(),
            expires_at: 0,
            rate_config: None,
        };

        let resolved = resolve_skills(&skill_reg, &manifest_reg, &scopes);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].name, "skill-a");
    }

    #[test]
    fn test_resolve_skills_by_tool_binding() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_skill(
            tmp.path(),
            "sanctions-skill",
            &["ca_sanctions_search"],
            &[],
            &[],
        );
        create_test_skill(
            tmp.path(),
            "unrelated-skill",
            &["some_other_tool"],
            &[],
            &[],
        );

        let skill_reg = SkillRegistry::load(tmp.path()).unwrap();

        let manifest_reg = ManifestRegistry::empty();

        let scopes = ScopeConfig {
            scopes: vec!["tool:ca_sanctions_search".to_string()],
            sub: String::new(),
            expires_at: 0,
            rate_config: None,
        };

        let resolved = resolve_skills(&skill_reg, &manifest_reg, &scopes);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].name, "sanctions-skill");
    }

    #[test]
    fn test_resolve_skills_with_dependencies() {
        let tmp = tempfile::tempdir().unwrap();

        // Create skill-a that depends on skill-b
        let dir_a = tmp.path().join("skill-a");
        fs::create_dir_all(&dir_a).unwrap();
        fs::write(
            dir_a.join("skill.toml"),
            r#"[skill]
name = "skill-a"
description = "Skill A"
tools = ["tool_a"]
depends_on = ["skill-b"]
"#,
        )
        .unwrap();
        fs::write(dir_a.join("SKILL.md"), "# Skill A").unwrap();

        // Create skill-b (dependency)
        let dir_b = tmp.path().join("skill-b");
        fs::create_dir_all(&dir_b).unwrap();
        fs::write(
            dir_b.join("skill.toml"),
            r#"[skill]
name = "skill-b"
description = "Skill B"
tools = ["tool_b"]
"#,
        )
        .unwrap();
        fs::write(dir_b.join("SKILL.md"), "# Skill B").unwrap();

        let skill_reg = SkillRegistry::load(tmp.path()).unwrap();

        let manifest_tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(manifest_tmp.path()).unwrap();
        let manifest_reg = ManifestRegistry::load(manifest_tmp.path())
            .unwrap_or_else(|_| panic!("cannot load empty manifest dir"));

        let scopes = ScopeConfig {
            scopes: vec!["tool:tool_a".to_string()],
            sub: String::new(),
            expires_at: 0,
            rate_config: None,
        };

        let resolved = resolve_skills(&skill_reg, &manifest_reg, &scopes);
        // Should resolve both skill-a (via tool binding) and skill-b (via dependency)
        assert_eq!(resolved.len(), 2);
        let names: Vec<&str> = resolved.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"skill-a"));
        assert!(names.contains(&"skill-b"));
    }

    #[test]
    fn test_scaffold() {
        let toml = scaffold_skill_toml(
            "my-skill",
            &["tool_a".into(), "tool_b".into()],
            Some("provider_x"),
        );
        assert!(toml.contains("name = \"my-skill\""));
        assert!(toml.contains("\"tool_a\""));
        assert!(toml.contains("\"provider_x\""));

        let md = scaffold_skill_md("my-cool-skill");
        assert!(md.contains("# My Cool Skill Skill"));
    }

    #[test]
    fn test_build_skill_context() {
        let skill = SkillMeta {
            name: "test-skill".to_string(),
            version: "1.0.0".to_string(),
            description: "A test skill".to_string(),
            tools: vec!["tool_a".to_string(), "tool_b".to_string()],
            hint: Some("Use for testing".to_string()),
            suggests: vec!["other-skill".to_string()],
            ..Default::default()
        };

        let ctx = build_skill_context(&[&skill]);
        assert!(ctx.contains("**test-skill**"));
        assert!(ctx.contains("A test skill"));
        assert!(ctx.contains("Use for testing"));
        assert!(ctx.contains("tool_a, tool_b"));
        assert!(ctx.contains("other-skill"));
    }

    #[test]
    fn test_empty_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let registry = SkillRegistry::load(tmp.path()).unwrap();
        assert_eq!(registry.skill_count(), 0);
    }

    #[test]
    fn test_nonexistent_directory() {
        let registry = SkillRegistry::load(Path::new("/nonexistent/path")).unwrap();
        assert_eq!(registry.skill_count(), 0);
    }
}
