/// Integration tests for ATI scope enforcement.
///
/// Scopes are now carried inside JWT claims, not scopes.json files.
/// These tests verify the ScopeConfig matching logic.
use ati::core::scope::ScopeConfig;

fn make_scopes(scopes: &[&str]) -> ScopeConfig {
    ScopeConfig {
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        sub: "test-agent".into(),
        expires_at: 0,
        rate_config: None,
    }
}

#[test]
fn test_scope_allows_listed_tools() {
    let scopes = make_scopes(&[
        "tool:web_search",
        "tool:web_fetch",
        "tool:patent_search_epo",
    ]);

    assert!(scopes.is_allowed("tool:web_search"));
    assert!(scopes.is_allowed("tool:web_fetch"));
    assert!(scopes.is_allowed("tool:patent_search_epo"));
}

#[test]
fn test_scope_denies_unlisted_tools() {
    let scopes = make_scopes(&["tool:web_search"]);

    assert!(!scopes.is_allowed("tool:patent_search_epo"));
    assert!(!scopes.is_allowed("tool:middesk_us_business_lookup"));
    assert!(!scopes.is_allowed("tool:nonexistent"));
}

#[test]
fn test_empty_scope_always_allowed() {
    let scopes = make_scopes(&["tool:web_search"]);
    assert!(scopes.is_allowed(""));
}

#[test]
fn test_expired_scopes_deny_all() {
    let scopes = ScopeConfig {
        scopes: vec!["tool:web_search".into()],
        sub: "test".into(),
        expires_at: 1, // Expired long ago
        rate_config: None,
    };

    assert!(scopes.is_expired());
    assert!(!scopes.is_allowed("tool:web_search"));
}

#[test]
fn test_zero_expiry_means_no_expiry() {
    let scopes = ScopeConfig {
        scopes: vec!["tool:web_search".into()],
        sub: "test".into(),
        expires_at: 0,
        rate_config: None,
    };

    assert!(!scopes.is_expired());
    assert!(scopes.is_allowed("tool:web_search"));
}

#[test]
fn test_far_future_expiry_not_expired() {
    let scopes = ScopeConfig {
        scopes: vec!["tool:web_search".into()],
        sub: "test".into(),
        expires_at: 4102444800, // Year 2100
        rate_config: None,
    };

    assert!(!scopes.is_expired());
    assert!(scopes.is_allowed("tool:web_search"));
}

#[test]
fn test_check_access_returns_error_for_denied() {
    let scopes = make_scopes(&["tool:web_search"]);

    let result = scopes.check_access("patent_search_epo", "tool:patent_search_epo");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("patent_search_epo"));
}

#[test]
fn test_check_access_returns_error_when_expired() {
    let scopes = ScopeConfig {
        scopes: vec!["tool:web_search".into()],
        sub: "test".into(),
        expires_at: 1,
        rate_config: None,
    };

    let result = scopes.check_access("web_search", "tool:web_search");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("expired"));
}

#[test]
fn test_help_scope() {
    let with_help = make_scopes(&["tool:web_search", "help"]);
    assert!(with_help.help_enabled());

    let without_help = make_scopes(&["tool:web_search"]);
    assert!(!without_help.help_enabled());
}

#[test]
fn test_wildcard_scope() {
    let scopes = ScopeConfig::unrestricted();
    assert!(scopes.is_wildcard());
    assert!(scopes.is_allowed("anything"));
    assert!(scopes.help_enabled());
}

#[test]
fn test_wildcard_suffix_matching() {
    let scopes = make_scopes(&["tool:github:*"]);
    assert!(scopes.is_allowed("tool:github:search_repos"));
    assert!(scopes.is_allowed("tool:github:create_issue"));
    assert!(!scopes.is_allowed("tool:linear:list_issues"));
}

#[test]
fn test_mixed_scope_patterns() {
    let scopes = make_scopes(&["tool:web_search", "tool:github:*", "skill:research-*"]);
    assert!(scopes.is_allowed("tool:web_search"));
    assert!(scopes.is_allowed("tool:github:search_repos"));
    assert!(scopes.is_allowed("skill:research-general-overview"));
    assert!(!scopes.is_allowed("tool:linear:list_issues"));
    assert!(!scopes.is_allowed("skill:patent-analysis"));
}

#[test]
fn test_scope_from_jwt_claims() {
    use ati::core::jwt::{AtiNamespace, TokenClaims};

    let claims = TokenClaims {
        iss: Some("ati-orchestrator".into()),
        sub: "agent-7".into(),
        aud: "ati-proxy".into(),
        iat: 1000000,
        exp: 4102444800, // Year 2100
        jti: None,
        scope: "tool:web_search tool:github:* help".into(),
        ati: Some(AtiNamespace {
            v: 1,
            rate: std::collections::HashMap::new(),
            customer_id: None,
        }),
        job_id: None,
        sandbox_id: None,
    };

    let scopes = ScopeConfig::from_jwt(&claims);
    assert_eq!(scopes.sub, "agent-7");
    assert!(scopes.is_allowed("tool:web_search"));
    assert!(scopes.is_allowed("tool:github:search_repos"));
    assert!(scopes.help_enabled());
    assert!(!scopes.is_allowed("tool:patent_search"));
    assert_eq!(scopes.tool_scope_count(), 2);
}
