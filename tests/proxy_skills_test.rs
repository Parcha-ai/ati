//! Tests for the proxy /skills endpoints — list, detail, resolve.
//!
//! These tests verify the skill endpoints through the axum router.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

use ati::core::auth_generator::AuthCache;
use ati::core::keyring::Keyring;
use ati::core::manifest::ManifestRegistry;
use ati::core::skill::SkillRegistry;
use ati::proxy::server::{build_router, ProxyState};

fn build_app_with_skills(
    skills_dir: &std::path::Path,
    manifests_dir: &std::path::Path,
) -> axum::Router {
    let registry = ManifestRegistry::load(manifests_dir).expect("load manifests");
    let skill_registry = SkillRegistry::load(skills_dir).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring: Keyring::empty(),
        verbose: false,
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
    });
    build_router(state)
}

fn create_test_skill(dir: &std::path::Path, name: &str) {
    let skill_dir = dir.join(name);
    std::fs::create_dir_all(&skill_dir).expect("create skill dir");

    let skill_toml = format!(
        r#"[skill]
name = "{name}"
version = "1.0.0"
description = "Test skill for {name}"
author = "test"
tools = ["test_tool"]
providers = ["test_provider"]
categories = ["testing"]
keywords = ["test"]
"#
    );
    std::fs::write(skill_dir.join("skill.toml"), skill_toml).expect("write skill.toml");
    std::fs::write(
        skill_dir.join("SKILL.md"),
        format!("# {name}\n\nTest skill content."),
    )
    .expect("write SKILL.md");
}

/// GET /skills returns list of skills.
#[tokio::test]
async fn test_skills_list_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap();

    let manifest = r#"
[provider]
name = "p"
description = "p"
base_url = "http://unused"
auth_type = "none"

[[tools]]
name = "t"
description = "t"
endpoint = "/"
method = "GET"
"#;
    std::fs::write(manifests_dir.join("p.toml"), manifest).unwrap();

    let skills_dir = dir.path().join("skills");
    std::fs::create_dir_all(&skills_dir).unwrap();

    let app = build_app_with_skills(&skills_dir, &manifests_dir);

    let req = Request::builder()
        .uri("/skills")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = common::body_json(resp.into_body()).await;
    assert!(json.as_array().unwrap().is_empty());
}

/// GET /skills returns populated skills list.
#[tokio::test]
async fn test_skills_list_populated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap();

    let manifest = r#"
[provider]
name = "test_provider"
description = "p"
base_url = "http://unused"
auth_type = "none"

[[tools]]
name = "test_tool"
description = "t"
endpoint = "/"
method = "GET"
"#;
    std::fs::write(manifests_dir.join("p.toml"), manifest).unwrap();

    let skills_dir = dir.path().join("skills");
    std::fs::create_dir_all(&skills_dir).unwrap();
    create_test_skill(&skills_dir, "alpha_skill");
    create_test_skill(&skills_dir, "beta_skill");

    let app = build_app_with_skills(&skills_dir, &manifests_dir);

    let req = Request::builder()
        .uri("/skills")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = common::body_json(resp.into_body()).await;
    let skills = json.as_array().unwrap();
    assert_eq!(skills.len(), 2);
}

/// GET /skills/:name returns skill detail with content.
#[tokio::test]
async fn test_skill_detail() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap();

    std::fs::write(
        manifests_dir.join("p.toml"),
        r#"
[provider]
name = "p"
description = "p"
base_url = "http://unused"
auth_type = "none"
"#,
    )
    .unwrap();

    let skills_dir = dir.path().join("skills");
    std::fs::create_dir_all(&skills_dir).unwrap();
    create_test_skill(&skills_dir, "detail_skill");

    let app = build_app_with_skills(&skills_dir, &manifests_dir);

    let req = Request::builder()
        .uri("/skills/detail_skill")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = common::body_json(resp.into_body()).await;
    assert_eq!(json["name"], "detail_skill");
    assert!(json["content"]
        .as_str()
        .unwrap()
        .contains("Test skill content"));
}

/// GET /skills/:name?meta=true returns full metadata.
#[tokio::test]
async fn test_skill_detail_meta() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap();
    std::fs::write(
        manifests_dir.join("p.toml"),
        r#"
[provider]
name = "p"
description = "p"
base_url = "http://unused"
auth_type = "none"
"#,
    )
    .unwrap();

    let skills_dir = dir.path().join("skills");
    std::fs::create_dir_all(&skills_dir).unwrap();
    create_test_skill(&skills_dir, "meta_skill");

    let app = build_app_with_skills(&skills_dir, &manifests_dir);

    let req = Request::builder()
        .uri("/skills/meta_skill?meta=true")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = common::body_json(resp.into_body()).await;
    assert_eq!(json["name"], "meta_skill");
    assert_eq!(json["version"], "1.0.0");
    assert_eq!(json["author"], "test");
    assert!(json["tools"]
        .as_array()
        .unwrap()
        .contains(&json!("test_tool")));
}

/// GET /skills/:name for nonexistent skill returns 404.
#[tokio::test]
async fn test_skill_detail_not_found() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap();
    std::fs::write(
        manifests_dir.join("p.toml"),
        r#"
[provider]
name = "p"
description = "p"
base_url = "http://unused"
auth_type = "none"
"#,
    )
    .unwrap();

    let skills_dir = dir.path().join("skills");
    std::fs::create_dir_all(&skills_dir).unwrap();

    let app = build_app_with_skills(&skills_dir, &manifests_dir);

    let req = Request::builder()
        .uri("/skills/nonexistent_skill")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let json = common::body_json(resp.into_body()).await;
    assert!(json["error"]
        .as_str()
        .unwrap()
        .contains("nonexistent_skill"));
}

/// POST /skills/resolve returns skills matching given scopes.
#[tokio::test]
async fn test_skills_resolve() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifests_dir = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap();

    std::fs::write(
        manifests_dir.join("p.toml"),
        r#"
[provider]
name = "test_provider"
description = "p"
base_url = "http://unused"
auth_type = "none"

[[tools]]
name = "test_tool"
description = "t"
endpoint = "/"
method = "GET"
"#,
    )
    .unwrap();

    let skills_dir = dir.path().join("skills");
    std::fs::create_dir_all(&skills_dir).unwrap();
    create_test_skill(&skills_dir, "resolve_skill");

    let app = build_app_with_skills(&skills_dir, &manifests_dir);

    let body = json!({
        "scopes": ["tool:test_tool"]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/skills/resolve")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = common::body_json(resp.into_body()).await;
    let skills = json.as_array().unwrap();
    // The skill binds to "test_tool", so it should resolve
    assert!(
        skills.iter().any(|s| s["name"] == "resolve_skill"),
        "resolve_skill should be in resolved skills: {:?}",
        skills
    );
}
