use serde_json::json;
use std::io::Write;
use tempfile::TempDir;

#[test]
fn test_scope_allows_listed_tools() {
    let scopes = create_scope_config(vec![
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
    let scopes = create_scope_config(vec!["tool:web_search"]);

    assert!(!scopes.is_allowed("tool:patent_search_epo"));
    assert!(!scopes.is_allowed("tool:middesk_us_business_lookup"));
    assert!(!scopes.is_allowed("tool:nonexistent"));
}

#[test]
fn test_empty_scope_always_allowed() {
    let scopes = create_scope_config(vec!["tool:web_search"]);

    // Empty scope on a tool means "no scope required" = always allowed
    assert!(scopes.is_allowed(""));
}

#[test]
fn test_expired_scopes_deny_all() {
    let scopes = ScopeConfig {
        scopes: vec!["tool:web_search".into()],
        agent_id: "test".into(),
        job_id: "test".into(),
        expires_at: 1, // Expired long ago
        hmac: None,
    };

    assert!(scopes.is_expired());
    assert!(!scopes.is_allowed("tool:web_search"));
}

#[test]
fn test_zero_expiry_means_no_expiry() {
    let scopes = ScopeConfig {
        scopes: vec!["tool:web_search".into()],
        agent_id: "test".into(),
        job_id: "test".into(),
        expires_at: 0,
        hmac: None,
    };

    assert!(!scopes.is_expired());
    assert!(scopes.is_allowed("tool:web_search"));
}

#[test]
fn test_far_future_expiry_not_expired() {
    let scopes = ScopeConfig {
        scopes: vec!["tool:web_search".into()],
        agent_id: "test".into(),
        job_id: "test".into(),
        expires_at: 4102444800, // Year 2100
        hmac: None,
    };

    assert!(!scopes.is_expired());
    assert!(scopes.is_allowed("tool:web_search"));
}

#[test]
fn test_scope_file_loading() {
    let dir = TempDir::new().unwrap();
    let scopes_path = dir.path().join("scopes.json");

    let scopes_json = json!({
        "scopes": ["tool:web_search", "tool:web_fetch", "help"],
        "agent_id": "test-agent",
        "job_id": "job-123",
        "expires_at": 4102444800_u64
    });

    std::fs::write(&scopes_path, serde_json::to_string_pretty(&scopes_json).unwrap()).unwrap();

    let loaded = ScopeConfig::load(&scopes_path).unwrap();
    assert_eq!(loaded.agent_id, "test-agent");
    assert_eq!(loaded.job_id, "job-123");
    assert!(loaded.is_allowed("tool:web_search"));
    assert!(loaded.help_enabled());
    assert_eq!(loaded.tool_scope_count(), 2);
}

#[test]
fn test_check_access_returns_error_for_denied() {
    let scopes = create_scope_config(vec!["tool:web_search"]);

    let result = scopes.check_access("patent_search_epo", "tool:patent_search_epo");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("patent_search_epo"));
}

#[test]
fn test_check_access_returns_error_when_expired() {
    let scopes = ScopeConfig {
        scopes: vec!["tool:web_search".into()],
        agent_id: "test".into(),
        job_id: "test".into(),
        expires_at: 1,
        hmac: None,
    };

    let result = scopes.check_access("web_search", "tool:web_search");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("expired"));
}

#[test]
fn test_help_scope() {
    let with_help = create_scope_config(vec!["tool:web_search", "help"]);
    assert!(with_help.help_enabled());

    let without_help = create_scope_config(vec!["tool:web_search"]);
    assert!(!without_help.help_enabled());
}

#[test]
fn test_wildcard_scope() {
    let scopes = ScopeConfig {
        scopes: vec!["*".into()],
        agent_id: "dev".into(),
        job_id: "dev".into(),
        expires_at: 0,
        hmac: None,
    };

    // Wildcard doesn't affect is_allowed directly (it checks exact match)
    // but filter_tools_by_scope checks is_wildcard()
    assert!(scopes.is_allowed("*"));
}

// --- Helper types (mirrored from the binary) ---

use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
struct ScopeConfig {
    scopes: Vec<String>,
    #[serde(default)]
    agent_id: String,
    #[serde(default)]
    job_id: String,
    #[serde(default)]
    expires_at: u64,
    #[serde(default)]
    hmac: Option<String>,
}

impl ScopeConfig {
    fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config: ScopeConfig = serde_json::from_str(&contents)?;
        Ok(config)
    }

    fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expires_at
    }

    fn is_allowed(&self, tool_scope: &str) -> bool {
        if self.is_expired() {
            return false;
        }
        if tool_scope.is_empty() {
            return true;
        }
        self.scopes.iter().any(|s| s == tool_scope)
    }

    fn check_access(
        &self,
        tool_name: &str,
        tool_scope: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.is_expired() {
            return Err(format!("Scopes have expired (expired at {})", self.expires_at).into());
        }
        if !self.is_allowed(tool_scope) {
            return Err(format!("Access denied: '{}' is not in your scopes", tool_name).into());
        }
        Ok(())
    }

    fn tool_scope_count(&self) -> usize {
        self.scopes.iter().filter(|s| s.starts_with("tool:")).count()
    }

    fn help_enabled(&self) -> bool {
        self.scopes.iter().any(|s| s == "help")
    }
}

fn create_scope_config(scopes: Vec<&str>) -> ScopeConfig {
    ScopeConfig {
        scopes: scopes.into_iter().map(String::from).collect(),
        agent_id: "test".into(),
        job_id: "test".into(),
        expires_at: 0,
        hmac: None,
    }
}
