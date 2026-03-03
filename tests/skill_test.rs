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

use ati::core::keyring::Keyring;
use ati::core::manifest::ManifestRegistry;
use ati::core::scope::ScopeConfig;
use ati::core::skill::{self, SkillMeta, SkillRegistry};
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
        verbose: false,
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
        agent_id: String::new(),
        job_id: String::new(),
        expires_at: 0,
        hmac: None,
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
        agent_id: String::new(),
        job_id: String::new(),
        expires_at: 0,
        hmac: None,
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
        agent_id: String::new(),
        job_id: String::new(),
        expires_at: 0,
        hmac: None,
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
    assert_eq!(
        json["tools"].as_array().unwrap().len(),
        2
    );
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
    let skills = vec![
        SkillMeta {
            name: "sanctions".to_string(),
            version: "1.0.0".to_string(),
            description: "Screen against sanctions".to_string(),
            author: None,
            tools: vec!["ca_sanctions_search".to_string()],
            providers: Vec::new(),
            categories: Vec::new(),
            keywords: Vec::new(),
            hint: Some("Use when checking sanctions".to_string()),
            depends_on: Vec::new(),
            suggests: Vec::new(),
            dir: std::path::PathBuf::new(),
        },
    ];

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
