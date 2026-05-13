#![allow(dead_code)]
/// Integration tests for the ATI skill management system.
///
/// Tests cover: SkillRegistry loading, tool/provider/category indexes,
/// scope-driven resolution, search, backward compatibility, proxy /skills endpoints.
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tower::ServiceExt;

use ati::core::auth_generator::AuthCache;
use ati::core::keyring::Keyring;
use ati::core::manifest::ManifestRegistry;
use ati::core::scope::ScopeConfig;
use ati::core::skill::{self, SkillFormat, SkillMeta, SkillRegistry};
use ati::proxy::server::{build_router, ProxyState};

// --- Helpers ---

fn create_skill_dir(base: &Path, name: &str, toml_content: &str, md_content: &str) {
    let dir = base.join(name);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("skill.toml"), toml_content).unwrap();
    fs::write(dir.join("SKILL.md"), md_content).unwrap();
}

fn create_manifest_dir(base: &Path, manifest_content: &str) {
    let dir = base.join("manifests");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("test.toml"), manifest_content).unwrap();
}

fn build_test_state(skills_dir: &Path) -> Arc<ProxyState> {
    let skill_registry = SkillRegistry::load(skills_dir).unwrap();
    let manifest_registry = ManifestRegistry::empty();
    Arc::new(ProxyState {
        registry: manifest_registry,
        skill_registry,
        keyring: Keyring::empty(),
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
        db: ati::core::db::DbState::Disabled,
        passthrough: None,
        sig_verify: std::sync::Arc::new(
            ati::core::sig_verify::SigVerifyConfig::build(
                ati::core::sig_verify::SigVerifyMode::Log,
                60,
                ati::core::sig_verify::DEFAULT_EXEMPT_PATHS,
                &ati::core::keyring::Keyring::empty(),
            )
            .unwrap(),
        ),
    })
}

async fn body_json(body: Body) -> Value {
    let bytes = body.collect().await.expect("collect body").to_bytes();
    serde_json::from_slice(&bytes).expect("parse body as JSON")
}

// --- SkillRegistry Loading Tests ---

#[test]
fn test_load_multiple_skills() {
    let tmp = tempfile::tempdir().unwrap();
    let skills_dir = tmp.path();

    create_skill_dir(
        skills_dir,
        "alpha",
        r#"[skill]
name = "alpha"
version = "1.0.0"
description = "Alpha skill"
tools = ["tool_a"]
"#,
        "# Alpha\nAlpha methodology.",
    );

    create_skill_dir(
        skills_dir,
        "beta",
        r#"[skill]
name = "beta"
version = "2.0.0"
description = "Beta skill"
providers = ["provider_b"]
categories = ["finance"]
"#,
        "# Beta\nBeta methodology.",
    );

    let registry = SkillRegistry::load(skills_dir).unwrap();
    assert_eq!(registry.skill_count(), 2);

    let alpha = registry.get_skill("alpha").unwrap();
    assert_eq!(alpha.version, "1.0.0");
    assert_eq!(alpha.tools, vec!["tool_a"]);

    let beta = registry.get_skill("beta").unwrap();
    assert_eq!(beta.version, "2.0.0");
    assert_eq!(beta.providers, vec!["provider_b"]);
    assert_eq!(beta.categories, vec!["finance"]);
}

#[test]
fn test_backward_compat_skill_md_only() {
    let tmp = tempfile::tempdir().unwrap();
    let skills_dir = tmp.path();
    let skill_dir = skills_dir.join("legacy");
    fs::create_dir_all(&skill_dir).unwrap();
    fs::write(
        skill_dir.join("SKILL.md"),
        "# Legacy Skill\n\nThis is a legacy skill with no skill.toml.\n",
    )
    .unwrap();

    let registry = SkillRegistry::load(skills_dir).unwrap();
    assert_eq!(registry.skill_count(), 1);

    let skill = registry.get_skill("legacy").unwrap();
    assert_eq!(skill.name, "legacy");
    assert_eq!(
        skill.description,
        "This is a legacy skill with no skill.toml."
    );
    // No tool bindings without skill.toml
    assert!(skill.tools.is_empty());
    assert!(skill.providers.is_empty());
    assert!(skill.categories.is_empty());
}

// --- Index Tests ---

#[test]
fn test_multi_skill_tool_index() {
    let tmp = tempfile::tempdir().unwrap();
    let skills_dir = tmp.path();

    create_skill_dir(
        skills_dir,
        "screening",
        r#"[skill]
name = "screening"
description = "Screening skill"
tools = ["ca_sanctions_search", "ca_pep_search"]
"#,
        "# Screening",
    );

    create_skill_dir(
        skills_dir,
        "enhanced-screening",
        r#"[skill]
name = "enhanced-screening"
description = "Enhanced screening"
tools = ["ca_sanctions_search", "ca_adverse_media"]
"#,
        "# Enhanced Screening",
    );

    let registry = SkillRegistry::load(skills_dir).unwrap();

    // ca_sanctions_search appears in both skills
    let both = registry.skills_for_tool("ca_sanctions_search");
    assert_eq!(both.len(), 2);

    // ca_pep_search only in screening
    let pep = registry.skills_for_tool("ca_pep_search");
    assert_eq!(pep.len(), 1);
    assert_eq!(pep[0].name, "screening");

    // ca_adverse_media only in enhanced
    let am = registry.skills_for_tool("ca_adverse_media");
    assert_eq!(am.len(), 1);
    assert_eq!(am[0].name, "enhanced-screening");
}

#[test]
fn test_provider_and_category_indexes() {
    let tmp = tempfile::tempdir().unwrap();

    create_skill_dir(
        tmp.path(),
        "compliance",
        r#"[skill]
name = "compliance"
description = "Compliance skill"
providers = ["complyadvantage", "sovos"]
categories = ["compliance", "aml"]
"#,
        "# Compliance",
    );

    let registry = SkillRegistry::load(tmp.path()).unwrap();

    assert_eq!(registry.skills_for_provider("complyadvantage").len(), 1);
    assert_eq!(registry.skills_for_provider("sovos").len(), 1);
    assert_eq!(registry.skills_for_category("compliance").len(), 1);
    assert_eq!(registry.skills_for_category("aml").len(), 1);
    assert!(registry.skills_for_provider("nonexistent").is_empty());
    assert!(registry.skills_for_category("nonexistent").is_empty());
}

// --- Search Tests ---

#[test]
fn test_search_by_keyword() {
    let tmp = tempfile::tempdir().unwrap();

    create_skill_dir(
        tmp.path(),
        "sanctions-screening",
        r#"[skill]
name = "sanctions-screening"
description = "Screen entities against sanctions lists"
keywords = ["OFAC", "SDN", "sanctions"]
"#,
        "# Sanctions",
    );

    create_skill_dir(
        tmp.path(),
        "tin-verify",
        r#"[skill]
name = "tin-verify"
description = "Verify TIN numbers"
keywords = ["IRS", "TIN", "tax"]
"#,
        "# TIN",
    );

    let registry = SkillRegistry::load(tmp.path()).unwrap();

    let results = registry.search("OFAC sanctions");
    assert!(!results.is_empty());
    assert_eq!(results[0].name, "sanctions-screening");

    let results = registry.search("IRS TIN");
    assert!(!results.is_empty());
    assert_eq!(results[0].name, "tin-verify");
}

// --- Scope Resolution Tests ---

#[test]
fn test_resolve_explicit_skill_scope() {
    let tmp = tempfile::tempdir().unwrap();

    create_skill_dir(
        tmp.path(),
        "target",
        r#"[skill]
name = "target"
description = "Target skill"
"#,
        "# Target",
    );

    create_skill_dir(
        tmp.path(),
        "other",
        r#"[skill]
name = "other"
description = "Other skill"
"#,
        "# Other",
    );

    let skill_reg = SkillRegistry::load(tmp.path()).unwrap();
    let manifest_reg = ManifestRegistry::empty();

    let scopes = ScopeConfig {
        scopes: vec!["skill:target".to_string()],
        sub: String::new(),
        expires_at: 0,
        rate_config: None,
    };

    let resolved = skill::resolve_skills(&skill_reg, &manifest_reg, &scopes);
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].name, "target");
}

#[test]
fn test_resolve_by_tool_binding() {
    let tmp = tempfile::tempdir().unwrap();

    create_skill_dir(
        tmp.path(),
        "relevant",
        r#"[skill]
name = "relevant"
description = "Relevant skill"
tools = ["my_tool"]
"#,
        "# Relevant",
    );

    create_skill_dir(
        tmp.path(),
        "unrelated",
        r#"[skill]
name = "unrelated"
description = "Unrelated skill"
tools = ["other_tool"]
"#,
        "# Unrelated",
    );

    let skill_reg = SkillRegistry::load(tmp.path()).unwrap();
    let manifest_reg = ManifestRegistry::empty();

    let scopes = ScopeConfig {
        scopes: vec!["tool:my_tool".to_string()],
        sub: String::new(),
        expires_at: 0,
        rate_config: None,
    };

    let resolved = skill::resolve_skills(&skill_reg, &manifest_reg, &scopes);
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].name, "relevant");
}

#[test]
fn test_resolve_transitive_dependencies() {
    let tmp = tempfile::tempdir().unwrap();

    create_skill_dir(
        tmp.path(),
        "root",
        r#"[skill]
name = "root"
description = "Root skill"
tools = ["root_tool"]
depends_on = ["dep-a"]
"#,
        "# Root",
    );

    create_skill_dir(
        tmp.path(),
        "dep-a",
        r#"[skill]
name = "dep-a"
description = "Dependency A"
depends_on = ["dep-b"]
"#,
        "# Dep A",
    );

    create_skill_dir(
        tmp.path(),
        "dep-b",
        r#"[skill]
name = "dep-b"
description = "Dependency B"
"#,
        "# Dep B",
    );

    let skill_reg = SkillRegistry::load(tmp.path()).unwrap();
    let manifest_reg = ManifestRegistry::empty();

    let scopes = ScopeConfig {
        scopes: vec!["tool:root_tool".to_string()],
        sub: String::new(),
        expires_at: 0,
        rate_config: None,
    };

    let resolved = skill::resolve_skills(&skill_reg, &manifest_reg, &scopes);
    // root (via tool binding) + dep-a (dependency of root) + dep-b (dependency of dep-a)
    assert_eq!(resolved.len(), 3);
    let names: Vec<&str> = resolved.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"root"));
    assert!(names.contains(&"dep-a"));
    assert!(names.contains(&"dep-b"));
}

// --- Proxy Endpoint Tests ---

#[tokio::test]
async fn test_proxy_skills_list() {
    let tmp = tempfile::tempdir().unwrap();
    let skills_dir = tmp.path();

    create_skill_dir(
        skills_dir,
        "skill-1",
        r#"[skill]
name = "skill-1"
version = "1.0.0"
description = "First skill"
tools = ["tool_a"]
categories = ["compliance"]
"#,
        "# Skill 1",
    );

    create_skill_dir(
        skills_dir,
        "skill-2",
        r#"[skill]
name = "skill-2"
version = "2.0.0"
description = "Second skill"
providers = ["serpapi"]
categories = ["search"]
"#,
        "# Skill 2",
    );

    let state = build_test_state(skills_dir);
    let app = build_router(state);

    // GET /skills — list all
    let req = Request::builder()
        .uri("/skills")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 2);
}

#[tokio::test]
async fn test_proxy_skills_filter_by_category() {
    let tmp = tempfile::tempdir().unwrap();
    let skills_dir = tmp.path();

    create_skill_dir(
        skills_dir,
        "compliance-skill",
        r#"[skill]
name = "compliance-skill"
description = "Compliance"
categories = ["compliance"]
"#,
        "# Compliance",
    );

    create_skill_dir(
        skills_dir,
        "search-skill",
        r#"[skill]
name = "search-skill"
description = "Search"
categories = ["search"]
"#,
        "# Search",
    );

    let state = build_test_state(skills_dir);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/skills?category=compliance")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "compliance-skill");
}

#[tokio::test]
async fn test_proxy_skills_search() {
    let tmp = tempfile::tempdir().unwrap();
    let skills_dir = tmp.path();

    create_skill_dir(
        skills_dir,
        "sanctions",
        r#"[skill]
name = "sanctions"
description = "Sanctions screening"
keywords = ["OFAC", "SDN"]
"#,
        "# Sanctions",
    );

    create_skill_dir(
        skills_dir,
        "research",
        r#"[skill]
name = "research"
description = "Web research"
keywords = ["search", "google"]
"#,
        "# Research",
    );

    let state = build_test_state(skills_dir);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/skills?search=OFAC")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "sanctions");
}

#[tokio::test]
async fn test_proxy_skill_detail() {
    let tmp = tempfile::tempdir().unwrap();
    let skills_dir = tmp.path();

    create_skill_dir(
        skills_dir,
        "my-skill",
        r#"[skill]
name = "my-skill"
version = "1.0.0"
description = "My skill"
tools = ["tool_x"]
hint = "Use this skill for X"
"#,
        "# My Skill\n\nDetailed methodology content here.",
    );

    // Add a reference file
    let refs_dir = skills_dir.join("my-skill").join("references");
    fs::create_dir_all(&refs_dir).unwrap();
    fs::write(refs_dir.join("guide.md"), "Reference guide").unwrap();

    let state = build_test_state(skills_dir);
    let app = build_router(state);

    // Get full content
    let req = Request::builder()
        .uri("/skills/my-skill")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    assert_eq!(json["name"], "my-skill");
    assert!(json["content"]
        .as_str()
        .unwrap()
        .contains("Detailed methodology"));
}

#[tokio::test]
async fn test_proxy_skill_detail_meta_only() {
    let tmp = tempfile::tempdir().unwrap();
    let skills_dir = tmp.path();

    create_skill_dir(
        skills_dir,
        "meta-skill",
        r#"[skill]
name = "meta-skill"
version = "3.0.0"
description = "Metadata test"
tools = ["tool_a", "tool_b"]
providers = ["provider_x"]
keywords = ["test"]
"#,
        "# Meta Skill",
    );

    let state = build_test_state(skills_dir);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/skills/meta-skill?meta=true")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    assert_eq!(json["name"], "meta-skill");
    assert_eq!(json["version"], "3.0.0");
    assert_eq!(json["tools"].as_array().unwrap().len(), 2);
    // Content should NOT be in metadata-only response
    assert!(json.get("content").is_none());
}

#[tokio::test]
async fn test_proxy_skill_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let state = build_test_state(tmp.path());
    let app = build_router(state);

    let req = Request::builder()
        .uri("/skills/nonexistent")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_proxy_skills_resolve() {
    let tmp = tempfile::tempdir().unwrap();
    let skills_dir = tmp.path();

    create_skill_dir(
        skills_dir,
        "target-skill",
        r#"[skill]
name = "target-skill"
description = "Target"
tools = ["my_tool"]
"#,
        "# Target",
    );

    create_skill_dir(
        skills_dir,
        "other-skill",
        r#"[skill]
name = "other-skill"
description = "Other"
tools = ["other_tool"]
"#,
        "# Other",
    );

    let state = build_test_state(skills_dir);
    let app = build_router(state);

    let body = serde_json::json!({
        "scopes": ["tool:my_tool"]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/skills/resolve")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "target-skill");
}

// --- Scaffold Tests ---

#[test]
fn test_scaffold_skill_toml() {
    let toml = skill::scaffold_skill_toml(
        "my-skill",
        &["tool_a".to_string(), "tool_b".to_string()],
        Some("provider_x"),
    );
    assert!(toml.contains("name = \"my-skill\""));
    assert!(toml.contains("\"tool_a\""));
    assert!(toml.contains("\"tool_b\""));
    assert!(toml.contains("\"provider_x\""));
    assert!(toml.contains("version = \"0.1.0\""));
}

#[test]
fn test_scaffold_skill_md() {
    let md = skill::scaffold_skill_md("compliance-screening");
    assert!(md.contains("# Compliance Screening Skill"));
    assert!(md.contains("## Tools Available"));
    assert!(md.contains("## Decision Tree"));
}

// --- Health Endpoint Includes Skills ---

#[tokio::test]
async fn test_health_includes_skills_count() {
    let tmp = tempfile::tempdir().unwrap();

    create_skill_dir(
        tmp.path(),
        "test-skill",
        r#"[skill]
name = "test-skill"
description = "Test"
"#,
        "# Test",
    );

    let state = build_test_state(tmp.path());
    let app = build_router(state);

    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    assert_eq!(json["skills"], 1);
}

// --- Build Skill Context ---

#[test]
fn test_build_skill_context_for_llm() {
    let skills = [SkillMeta {
        name: "sanctions".to_string(),
        version: "1.0.0".to_string(),
        description: "Screen against sanctions".to_string(),
        tools: vec!["ca_sanctions_search".to_string()],
        hint: Some("Use when checking sanctions".to_string()),
        ..Default::default()
    }];

    let refs: Vec<&SkillMeta> = skills.iter().collect();
    let ctx = skill::build_skill_context(&refs);

    assert!(ctx.contains("**sanctions**"));
    assert!(ctx.contains("Screen against sanctions"));
    assert!(ctx.contains("ca_sanctions_search"));
    assert!(ctx.contains("Use when checking sanctions"));
}

#[test]
fn test_build_skill_context_empty() {
    let ctx = skill::build_skill_context(&[]);
    assert!(ctx.is_empty());
}

// --- Bundled Provider Tests ---

#[test]
fn test_install_skill_with_bundled_provider() {
    let tmp = tempfile::tempdir().unwrap();
    let ati_dir = tmp.path();
    let skills_dir = ati_dir.join("skills");
    let manifests_dir = ati_dir.join("manifests");
    fs::create_dir_all(&skills_dir).unwrap();

    // Create a source skill directory with provider.toml
    let source = tmp.path().join("source-skill");
    fs::create_dir_all(&source).unwrap();
    fs::write(
        source.join("skill.toml"),
        r#"[skill]
name = "fal-generate"
version = "1.0.0"
description = "Generate images with fal.ai"
tools = ["fal:text_to_image"]
providers = ["fal"]
"#,
    )
    .unwrap();
    fs::write(source.join("SKILL.md"), "# Fal Generate\nUse fal.ai.").unwrap();
    fs::write(
        source.join("provider.toml"),
        r#"[provider]
name = "fal"
base_url = "https://queue.fal.run"
auth_type = "bearer"
auth_key_name = "fal_api_key"

[[tools]]
name = "text_to_image"
endpoint = "/fal-ai/flux/dev"
method = "POST"
"#,
    )
    .unwrap();

    // Use the CLI binary to install the skill
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .args(["skill", "install", source.to_str().unwrap()])
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .output()
        .expect("failed to run ati skill install");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "install failed: {}{}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify skill was installed
    assert!(skills_dir.join("source-skill").join("skill.toml").exists());
    assert!(skills_dir.join("source-skill").join("SKILL.md").exists());

    // Verify provider manifest was installed
    let manifest_path = manifests_dir.join("fal.toml");
    assert!(
        manifest_path.exists(),
        "Bundled provider manifest should be installed at {}",
        manifest_path.display()
    );

    // Verify the content was copied correctly
    let manifest_content = fs::read_to_string(&manifest_path).unwrap();
    assert!(manifest_content.contains("name = \"fal\""));
    assert!(manifest_content.contains("base_url = \"https://queue.fal.run\""));

    // Verify key hint was printed
    assert!(stdout.contains("ati key set fal_api_key"));
}

#[test]
fn test_install_skill_bundled_provider_skip_existing() {
    let tmp = tempfile::tempdir().unwrap();
    let ati_dir = tmp.path();
    let skills_dir = ati_dir.join("skills");
    let manifests_dir = ati_dir.join("manifests");
    fs::create_dir_all(&skills_dir).unwrap();
    fs::create_dir_all(&manifests_dir).unwrap();

    // Pre-create existing provider manifest
    fs::write(
        manifests_dir.join("fal.toml"),
        r#"[provider]
name = "fal"
base_url = "https://existing.example.com"
"#,
    )
    .unwrap();

    // Create a source skill with bundled provider
    let source = tmp.path().join("fal-skill");
    fs::create_dir_all(&source).unwrap();
    fs::write(
        source.join("skill.toml"),
        r#"[skill]
name = "fal-skill"
description = "Fal skill"
"#,
    )
    .unwrap();
    fs::write(source.join("SKILL.md"), "# Fal").unwrap();
    fs::write(
        source.join("provider.toml"),
        r#"[provider]
name = "fal"
base_url = "https://queue.fal.run"
auth_type = "bearer"
auth_key_name = "fal_api_key"
"#,
    )
    .unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .args(["skill", "install", source.to_str().unwrap()])
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .output()
        .expect("failed to run ati skill install");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());

    // Verify the existing manifest was NOT overwritten
    let content = fs::read_to_string(manifests_dir.join("fal.toml")).unwrap();
    assert!(
        content.contains("https://existing.example.com"),
        "Existing provider manifest should not be overwritten"
    );
    assert!(stdout.contains("already installed"));
}

#[test]
fn test_install_skill_without_bundled_provider() {
    let tmp = tempfile::tempdir().unwrap();
    let ati_dir = tmp.path();
    let skills_dir = ati_dir.join("skills");
    let manifests_dir = ati_dir.join("manifests");
    fs::create_dir_all(&skills_dir).unwrap();

    // Create a source skill WITHOUT provider.toml
    let source = tmp.path().join("plain-skill");
    fs::create_dir_all(&source).unwrap();
    fs::write(
        source.join("skill.toml"),
        r#"[skill]
name = "plain-skill"
description = "No provider"
"#,
    )
    .unwrap();
    fs::write(source.join("SKILL.md"), "# Plain").unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .args(["skill", "install", source.to_str().unwrap()])
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .output()
        .expect("failed to run ati skill install");

    assert!(output.status.success());

    // Manifests dir should not exist (nothing to install)
    assert!(
        !manifests_dir.join("plain-skill.toml").exists(),
        "No manifest should be created for skills without provider.toml"
    );
}

// --- Read Skill Tests ---

#[test]
fn test_read_content_by_name() {
    let tmp = tempfile::tempdir().unwrap();
    let skills_dir = tmp.path();

    create_skill_dir(
        skills_dir,
        "my-methodology",
        r#"[skill]
name = "my-methodology"
description = "A methodology skill"
tools = ["tool_x"]
"#,
        "# My Methodology\n\nStep 1: Do the thing.\nStep 2: Verify it worked.\n",
    );

    let registry = SkillRegistry::load(skills_dir).unwrap();
    let content = registry.read_content("my-methodology").unwrap();
    assert!(content.contains("Step 1: Do the thing."));
    assert!(content.contains("Step 2: Verify it worked."));
}

#[test]
fn test_read_content_with_references() {
    let tmp = tempfile::tempdir().unwrap();
    let skills_dir = tmp.path();

    create_skill_dir(
        skills_dir,
        "ref-skill",
        r#"[skill]
name = "ref-skill"
description = "Skill with references"
"#,
        "# Ref Skill\n\nMain content.",
    );

    // Add reference files
    let refs_dir = skills_dir.join("ref-skill").join("references");
    fs::create_dir_all(&refs_dir).unwrap();
    fs::write(refs_dir.join("guide.md"), "Reference guide content").unwrap();
    fs::write(refs_dir.join("examples.md"), "Example content").unwrap();

    let registry = SkillRegistry::load(skills_dir).unwrap();

    let refs = registry.list_references("ref-skill").unwrap();
    assert_eq!(refs.len(), 2);
    assert!(refs.contains(&"examples.md".to_string()));
    assert!(refs.contains(&"guide.md".to_string()));

    let guide = registry.read_reference("ref-skill", "guide.md").unwrap();
    assert_eq!(guide, "Reference guide content");
}

#[test]
fn test_skills_for_tool_multiple() {
    let tmp = tempfile::tempdir().unwrap();
    let skills_dir = tmp.path();

    create_skill_dir(
        skills_dir,
        "skill-a",
        r#"[skill]
name = "skill-a"
description = "First skill for tool_x"
tools = ["tool_x", "tool_y"]
"#,
        "# Skill A\nContent for A.",
    );

    create_skill_dir(
        skills_dir,
        "skill-b",
        r#"[skill]
name = "skill-b"
description = "Second skill for tool_x"
tools = ["tool_x"]
"#,
        "# Skill B\nContent for B.",
    );

    create_skill_dir(
        skills_dir,
        "skill-c",
        r#"[skill]
name = "skill-c"
description = "Unrelated skill"
tools = ["tool_z"]
"#,
        "# Skill C\nContent for C.",
    );

    let registry = SkillRegistry::load(skills_dir).unwrap();

    // tool_x should match skill-a and skill-b
    let tool_x_skills = registry.skills_for_tool("tool_x");
    assert_eq!(tool_x_skills.len(), 2);
    let names: Vec<&str> = tool_x_skills.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"skill-a"));
    assert!(names.contains(&"skill-b"));

    // Read content for each — verify they're distinct
    let content_a = registry.read_content("skill-a").unwrap();
    assert!(content_a.contains("Content for A"));
    let content_b = registry.read_content("skill-b").unwrap();
    assert!(content_b.contains("Content for B"));
}

// --- Anthropic Frontmatter Tests ---

#[test]
fn test_parse_frontmatter_basic() {
    let content = r#"---
name: my-skill
description: A test skill
---

# My Skill

Body content here.
"#;
    let (fm, body) = skill::parse_frontmatter(content);
    let fm = fm.expect("should parse frontmatter");
    assert_eq!(fm.name.unwrap(), "my-skill");
    assert_eq!(fm.description.unwrap(), "A test skill");
    assert!(body.contains("Body content here."));
    assert!(!body.contains("---"));
    assert!(!body.contains("name: my-skill"));
}

#[test]
fn test_parse_frontmatter_with_metadata() {
    let content = r#"---
name: test-skill
description: Testing metadata
license: MIT
compatibility: Requires Python 3.10+
metadata:
  author: test-author
  version: "2.0.0"
allowed-tools: Bash(git:*) Read
---

# Test
"#;
    let (fm, _body) = skill::parse_frontmatter(content);
    let fm = fm.expect("should parse");
    assert_eq!(fm.name.unwrap(), "test-skill");
    assert_eq!(fm.license.unwrap(), "MIT");
    assert_eq!(fm.compatibility.unwrap(), "Requires Python 3.10+");
    assert_eq!(fm.metadata.get("author").unwrap(), "test-author");
    assert_eq!(fm.metadata.get("version").unwrap(), "2.0.0");
    assert_eq!(fm.allowed_tools.unwrap(), "Bash(git:*) Read");
}

#[test]
fn test_parse_frontmatter_none() {
    let content = "# No Frontmatter\n\nJust regular markdown.\n";
    let (fm, body) = skill::parse_frontmatter(content);
    assert!(fm.is_none());
    assert_eq!(body, content);
}

#[test]
fn test_parse_frontmatter_malformed() {
    let content = "---\ninvalid: yaml: [broken\n---\n\n# Body\n";
    let (fm, body) = skill::parse_frontmatter(content);
    assert!(fm.is_none());
    assert_eq!(body, content); // Graceful fallback to original content
}

#[test]
fn test_load_skill_frontmatter_primary() {
    // Frontmatter should win over skill.toml for shared fields (name, description)
    let tmp = tempfile::tempdir().unwrap();
    let skill_dir = tmp.path().join("my-skill");
    fs::create_dir_all(&skill_dir).unwrap();

    fs::write(
        skill_dir.join("SKILL.md"),
        r#"---
name: my-skill
description: From frontmatter
license: Apache-2.0
metadata:
  author: fm-author
  version: "3.0.0"
---

# My Skill

Methodology here.
"#,
    )
    .unwrap();

    // skill.toml provides ATI-specific bindings
    fs::write(
        skill_dir.join("skill.toml"),
        r#"[skill]
name = "my-skill"
description = "From toml (should be overridden)"
tools = ["tool_x", "tool_y"]
providers = ["provider_a"]
keywords = ["test"]
"#,
    )
    .unwrap();

    let registry = SkillRegistry::load(tmp.path()).unwrap();
    let skill = registry.get_skill("my-skill").unwrap();

    // Frontmatter wins for shared fields
    assert_eq!(skill.description, "From frontmatter");
    assert_eq!(skill.license.as_deref(), Some("Apache-2.0"));
    assert_eq!(skill.author.as_deref(), Some("fm-author"));
    assert_eq!(skill.version, "3.0.0");
    assert!(skill.has_frontmatter);
    assert_eq!(skill.format, SkillFormat::Anthropic);

    // ATI extensions come from skill.toml
    assert_eq!(skill.tools, vec!["tool_x", "tool_y"]);
    assert_eq!(skill.providers, vec!["provider_a"]);
    assert_eq!(skill.keywords, vec!["test"]);
}

#[test]
fn test_load_skill_frontmatter_only() {
    // Pure Anthropic skill — no skill.toml at all
    let tmp = tempfile::tempdir().unwrap();
    let skill_dir = tmp.path().join("pure-anthropic");
    fs::create_dir_all(&skill_dir).unwrap();

    fs::write(
        skill_dir.join("SKILL.md"),
        r#"---
name: pure-anthropic
description: A pure Anthropic spec skill
license: MIT
metadata:
  author: test
  version: "1.0.0"
---

# Pure Anthropic

Use this when testing ATI.
"#,
    )
    .unwrap();

    let registry = SkillRegistry::load(tmp.path()).unwrap();
    assert_eq!(registry.skill_count(), 1);

    let skill = registry.get_skill("pure-anthropic").unwrap();
    assert_eq!(skill.name, "pure-anthropic");
    assert_eq!(skill.description, "A pure Anthropic spec skill");
    assert_eq!(skill.license.as_deref(), Some("MIT"));
    assert_eq!(skill.version, "1.0.0");
    assert_eq!(skill.author.as_deref(), Some("test"));
    assert!(skill.has_frontmatter);
    assert_eq!(skill.format, SkillFormat::Anthropic);

    // No ATI bindings (no skill.toml)
    assert!(skill.tools.is_empty());
    assert!(skill.providers.is_empty());
}

#[test]
fn test_read_content_strips_frontmatter() {
    let tmp = tempfile::tempdir().unwrap();
    let skill_dir = tmp.path().join("fm-skill");
    fs::create_dir_all(&skill_dir).unwrap();

    fs::write(
        skill_dir.join("SKILL.md"),
        r#"---
name: fm-skill
description: Has frontmatter
---

# FM Skill

Body content only.
"#,
    )
    .unwrap();

    // Need a skill.toml or frontmatter for loading
    let registry = SkillRegistry::load(tmp.path()).unwrap();
    let content = registry.read_content("fm-skill").unwrap();

    // Content should NOT contain the YAML frontmatter
    assert!(!content.contains("name: fm-skill"));
    assert!(!content.contains("description: Has frontmatter"));
    // But SHOULD contain the body
    assert!(content.contains("# FM Skill"));
    assert!(content.contains("Body content only."));
}

#[test]
fn test_anthropic_name_validation() {
    // Valid names
    assert!(skill::is_anthropic_valid_name("my-skill"));
    assert!(skill::is_anthropic_valid_name("a"));
    assert!(skill::is_anthropic_valid_name("skill-123"));
    assert!(skill::is_anthropic_valid_name("a1b2c3"));

    // Invalid: empty
    assert!(!skill::is_anthropic_valid_name(""));

    // Invalid: uppercase
    assert!(!skill::is_anthropic_valid_name("My-Skill"));

    // Invalid: consecutive hyphens
    assert!(!skill::is_anthropic_valid_name("my--skill"));

    // Invalid: starts with hyphen
    assert!(!skill::is_anthropic_valid_name("-skill"));

    // Invalid: ends with hyphen
    assert!(!skill::is_anthropic_valid_name("skill-"));

    // Invalid: underscores
    assert!(!skill::is_anthropic_valid_name("my_skill"));

    // Invalid: too long (65 chars)
    let long_name = "a".repeat(65);
    assert!(!skill::is_anthropic_valid_name(&long_name));

    // Valid: exactly 64 chars
    let max_name = "a".repeat(64);
    assert!(skill::is_anthropic_valid_name(&max_name));
}

#[test]
fn test_backward_compat_legacy_toml_format() {
    // Existing skill with skill.toml and no frontmatter should load as LegacyToml
    let tmp = tempfile::tempdir().unwrap();

    create_skill_dir(
        tmp.path(),
        "legacy-toml",
        r#"[skill]
name = "legacy-toml"
version = "1.0.0"
description = "A legacy skill"
tools = ["tool_a"]
"#,
        "# Legacy\n\nNo frontmatter here.",
    );

    let registry = SkillRegistry::load(tmp.path()).unwrap();
    let skill = registry.get_skill("legacy-toml").unwrap();
    assert_eq!(skill.format, SkillFormat::LegacyToml);
    assert!(!skill.has_frontmatter);
    assert_eq!(skill.tools, vec!["tool_a"]);
}

#[test]
fn test_backward_compat_inferred_format() {
    // SKILL.md only, no frontmatter, no skill.toml → Inferred
    let tmp = tempfile::tempdir().unwrap();
    let skill_dir = tmp.path().join("inferred-skill");
    fs::create_dir_all(&skill_dir).unwrap();
    fs::write(
        skill_dir.join("SKILL.md"),
        "# Inferred Skill\n\nA skill inferred from content.\n",
    )
    .unwrap();

    let registry = SkillRegistry::load(tmp.path()).unwrap();
    let skill = registry.get_skill("inferred-skill").unwrap();
    assert_eq!(skill.format, SkillFormat::Inferred);
    assert!(!skill.has_frontmatter);
    assert_eq!(skill.description, "A skill inferred from content.");
}

#[tokio::test]
async fn test_proxy_skill_detail_meta_includes_frontmatter_fields() {
    let tmp = tempfile::tempdir().unwrap();
    let skills_dir = tmp.path();

    // Create a skill with frontmatter
    let skill_dir = skills_dir.join("anthropic-skill");
    fs::create_dir_all(&skill_dir).unwrap();
    fs::write(
        skill_dir.join("SKILL.md"),
        r#"---
name: anthropic-skill
description: Anthropic spec skill
license: MIT
allowed-tools: Bash(git:*) Read
---

# Anthropic Skill
"#,
    )
    .unwrap();

    let state = build_test_state(skills_dir);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/skills/anthropic-skill?meta=true")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    assert_eq!(json["name"], "anthropic-skill");
    assert_eq!(json["license"], "MIT");
    assert_eq!(json["allowed_tools"], "Bash(git:*) Read");
    assert_eq!(json["format"], "anthropic");
}
