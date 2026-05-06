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
use ati::core::jwt::{self, AtiNamespace, JwtConfig, TokenClaims};
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
        key_store: None,
        admin_token: None,
    });
    build_router(state)
}

fn build_app_with_skills_and_jwt(
    skills_dir: &std::path::Path,
    manifests_dir: &std::path::Path,
) -> axum::Router {
    let registry = ManifestRegistry::load(manifests_dir).expect("load manifests");
    let skill_registry = SkillRegistry::load(skills_dir).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring: Keyring::empty(),
        jwt_config: Some(test_jwt_config()),
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
        key_store: None,
        admin_token: None,
    });
    build_router(state)
}

fn test_jwt_config() -> JwtConfig {
    jwt::config_from_secret(
        b"test-secret-key-32-bytes-long!!!",
        None,
        "ati-proxy".into(),
    )
}

fn issue_test_token(scope: &str) -> String {
    let config = test_jwt_config();
    let now = jwt::now_secs();
    let claims = TokenClaims {
        iss: None,
        sub: "test-agent".into(),
        aud: "ati-proxy".into(),
        iat: now,
        exp: now + 3600,
        jti: None,
        scope: scope.into(),
        ati: Some(AtiNamespace {
            v: 1,
            rate: std::collections::HashMap::new(),
        }),
        job_id: None,
        sandbox_id: None,
    };
    jwt::issue(&claims, &config).unwrap()
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

fn create_test_skill_for_tool(dir: &std::path::Path, name: &str, tool: &str, provider: &str) {
    let skill_dir = dir.join(name);
    std::fs::create_dir_all(&skill_dir).expect("create skill dir");

    let skill_toml = format!(
        r#"[skill]
name = "{name}"
version = "1.0.0"
description = "Test skill for {name}"
author = "test"
tools = ["{tool}"]
providers = ["{provider}"]
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

/// JWT-scoped /skills only exposes visible skills.
#[tokio::test]
async fn test_skills_list_filtered_by_jwt_scopes() {
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
scope = "tool:test_tool"
"#,
    )
    .unwrap();

    let skills_dir = dir.path().join("skills");
    std::fs::create_dir_all(&skills_dir).unwrap();
    create_test_skill(&skills_dir, "visible_skill");

    let app = build_app_with_skills_and_jwt(&skills_dir, &manifests_dir);
    let token = issue_test_token("tool:other_tool");
    let req = Request::builder()
        .uri("/skills")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = common::body_json(resp.into_body()).await;
    assert!(json.as_array().unwrap().is_empty());
}

/// JWT-scoped /skills/:name hides skills outside the caller scopes.
#[tokio::test]
async fn test_skill_detail_hidden_when_out_of_scope() {
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
scope = "tool:test_tool"
"#,
    )
    .unwrap();

    let skills_dir = dir.path().join("skills");
    std::fs::create_dir_all(&skills_dir).unwrap();
    create_test_skill(&skills_dir, "hidden_skill");

    let app = build_app_with_skills_and_jwt(&skills_dir, &manifests_dir);
    let token = issue_test_token("tool:other_tool");
    let req = Request::builder()
        .uri("/skills/hidden_skill")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Legacy underscore JWT scopes still expose skills attached to colon-namespaced tools.
#[tokio::test]
async fn test_skills_list_legacy_underscore_scope_matches_colon_tool() {
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
name = "test_api:get_data"
description = "t"
endpoint = "/"
method = "GET"
scope = "tool:test_api:get_data"
"#,
    )
    .unwrap();

    let skills_dir = dir.path().join("skills");
    std::fs::create_dir_all(&skills_dir).unwrap();
    create_test_skill_for_tool(
        &skills_dir,
        "legacy_visible_skill",
        "test_api:get_data",
        "test_provider",
    );

    let app = build_app_with_skills_and_jwt(&skills_dir, &manifests_dir);
    let token = issue_test_token("tool:test_api_get_data");
    let req = Request::builder()
        .uri("/skills")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let json = common::body_json(resp.into_body()).await;
    let skills = json.as_array().unwrap();
    assert!(skills
        .iter()
        .any(|skill| skill["name"] == "legacy_visible_skill"));
}
