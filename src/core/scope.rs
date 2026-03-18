//! Scope enforcement for ATI.
//!
//! Scopes are carried inside JWT claims as a space-delimited `scope` string.
//! This module provides matching logic: exact matches, wildcard patterns
//! (`tool:github:*`), and tool filtering.

use crate::core::manifest::{Provider, Tool};
use thiserror::Error;

/// Check if a name matches a pattern with optional wildcard suffix.
///
/// Supports:
/// - Exact match: `"foo"` matches `"foo"`
/// - Wildcard suffix: `"foo*"` matches `"foobar"`
/// - Global wildcard: `"*"` matches everything
pub fn matches_wildcard(name: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern == name {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        if name.starts_with(prefix) {
            return true;
        }
    }
    false
}

#[derive(Error, Debug)]
pub enum ScopeError {
    #[error("Scopes have expired (expired at {0})")]
    Expired(u64),
    #[error("Access denied: '{0}' is not in your scopes")]
    AccessDenied(String),
}

/// Scope configuration — constructed from JWT claims or programmatically.
#[derive(Debug, Clone)]
pub struct ScopeConfig {
    /// Parsed scope strings (e.g. ["tool:web_search", "tool:github:*", "help"]).
    pub scopes: Vec<String>,
    /// Agent identity (from JWT `sub` claim).
    pub sub: String,
    /// Expiry timestamp (from JWT `exp` claim). 0 = no expiry.
    pub expires_at: u64,
    /// Per-tool rate limits parsed from JWT claims.
    pub rate_config: Option<crate::core::rate::RateConfig>,
}

impl ScopeConfig {
    /// Build a ScopeConfig from JWT TokenClaims.
    pub fn from_jwt(claims: &crate::core::jwt::TokenClaims) -> Self {
        let rate_config = claims.ati.as_ref().and_then(|ns| {
            if ns.rate.is_empty() {
                None
            } else {
                crate::core::rate::parse_rate_config(&ns.rate).ok()
            }
        });
        ScopeConfig {
            scopes: claims.scopes(),
            sub: claims.sub.clone(),
            expires_at: claims.exp,
            rate_config,
        }
    }

    /// Create an unrestricted scope config (for dev mode / no JWT set).
    pub fn unrestricted() -> Self {
        ScopeConfig {
            scopes: vec!["*".to_string()],
            sub: "dev".to_string(),
            expires_at: 0,
            rate_config: None,
        }
    }

    /// Check if the scopes have expired.
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expires_at
    }

    /// Check if a specific tool scope is allowed.
    ///
    /// Supports:
    /// - Exact match: `"tool:web_search"` matches `"tool:web_search"`
    /// - Wildcard suffix: `"tool:github:*"` matches `"tool:github:search_repos"`
    /// - Global wildcard: `"*"` matches everything
    /// - Empty tool scope: always allowed (tool has no scope requirement)
    pub fn is_allowed(&self, tool_scope: &str) -> bool {
        if self.is_expired() {
            return false;
        }
        // Empty scope on tool means always allowed
        if tool_scope.is_empty() {
            return true;
        }
        // Check each scope pattern
        for scope in &self.scopes {
            if matches_wildcard(tool_scope, scope) {
                return true;
            }
        }
        false
    }

    /// Check access for a tool, returning an error if denied.
    pub fn check_access(&self, tool_name: &str, tool_scope: &str) -> Result<(), ScopeError> {
        if self.is_expired() {
            return Err(ScopeError::Expired(self.expires_at));
        }
        if !self.is_allowed(tool_scope) {
            return Err(ScopeError::AccessDenied(tool_name.to_string()));
        }
        Ok(())
    }

    /// Get time remaining until expiry, in seconds. Returns None if no expiry.
    pub fn time_remaining(&self) -> Option<u64> {
        if self.expires_at == 0 {
            return None;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now >= self.expires_at {
            Some(0)
        } else {
            Some(self.expires_at - now)
        }
    }

    /// Number of tool scopes (those starting with "tool:").
    pub fn tool_scope_count(&self) -> usize {
        self.scopes
            .iter()
            .filter(|s| s.starts_with("tool:"))
            .count()
    }

    /// Number of skill scopes (those starting with "skill:").
    pub fn skill_scope_count(&self) -> usize {
        self.scopes
            .iter()
            .filter(|s| s.starts_with("skill:"))
            .count()
    }

    /// Check if help is enabled.
    pub fn help_enabled(&self) -> bool {
        self.is_wildcard() || self.scopes.iter().any(|s| s == "help")
    }

    /// Check if this is an unrestricted (wildcard) scope.
    pub fn is_wildcard(&self) -> bool {
        self.scopes.iter().any(|s| s == "*")
    }
}

/// Filter a list of tools to only those allowed by the scope config.
pub fn filter_tools_by_scope<'a>(
    tools: Vec<(&'a Provider, &'a Tool)>,
    scopes: &ScopeConfig,
) -> Vec<(&'a Provider, &'a Tool)> {
    if scopes.is_wildcard() {
        return tools;
    }

    tools
        .into_iter()
        .filter(|(_, tool)| match &tool.scope {
            Some(scope) => scopes.is_allowed(scope),
            None => true, // No scope required = always allowed
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scopes(scopes: &[&str]) -> ScopeConfig {
        ScopeConfig {
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            sub: "test-agent".into(),
            expires_at: 0,
            rate_config: None,
        }
    }

    #[test]
    fn test_exact_match() {
        let config = make_scopes(&["tool:web_search", "tool:web_fetch"]);
        assert!(config.is_allowed("tool:web_search"));
        assert!(config.is_allowed("tool:web_fetch"));
        assert!(!config.is_allowed("tool:patent_search"));
    }

    #[test]
    fn test_wildcard_suffix() {
        let config = make_scopes(&["tool:github:*"]);
        assert!(config.is_allowed("tool:github:search_repos"));
        assert!(config.is_allowed("tool:github:create_issue"));
        assert!(!config.is_allowed("tool:linear:list_issues"));
    }

    #[test]
    fn test_global_wildcard() {
        let config = make_scopes(&["*"]);
        assert!(config.is_allowed("tool:anything"));
        assert!(config.is_allowed("help"));
        assert!(config.is_allowed("skill:whatever"));
    }

    #[test]
    fn test_empty_scope_always_allowed() {
        let config = make_scopes(&["tool:web_search"]);
        assert!(config.is_allowed(""));
    }

    #[test]
    fn test_expired_denies_all() {
        let config = ScopeConfig {
            scopes: vec!["tool:web_search".into()],
            sub: "test".into(),
            expires_at: 1,
            rate_config: None,
        };
        assert!(config.is_expired());
        assert!(!config.is_allowed("tool:web_search"));
    }

    #[test]
    fn test_zero_expiry_means_no_expiry() {
        let config = ScopeConfig {
            scopes: vec!["tool:web_search".into()],
            sub: "test".into(),
            expires_at: 0,
            rate_config: None,
        };
        assert!(!config.is_expired());
        assert!(config.is_allowed("tool:web_search"));
    }

    #[test]
    fn test_check_access_denied() {
        let config = make_scopes(&["tool:web_search"]);
        let result = config.check_access("patent_search", "tool:patent_search");
        assert!(result.is_err());
    }

    #[test]
    fn test_check_access_expired() {
        let config = ScopeConfig {
            scopes: vec!["tool:web_search".into()],
            sub: "test".into(),
            expires_at: 1,
            rate_config: None,
        };
        let result = config.check_access("web_search", "tool:web_search");
        assert!(result.is_err());
    }

    #[test]
    fn test_help_enabled() {
        assert!(make_scopes(&["tool:web_search", "help"]).help_enabled());
        assert!(!make_scopes(&["tool:web_search"]).help_enabled());
        assert!(make_scopes(&["*"]).help_enabled());
    }

    #[test]
    fn test_scope_counts() {
        let config = make_scopes(&["tool:a", "tool:b", "skill:c", "help"]);
        assert_eq!(config.tool_scope_count(), 2);
        assert_eq!(config.skill_scope_count(), 1);
    }

    #[test]
    fn test_unrestricted() {
        let config = ScopeConfig::unrestricted();
        assert!(config.is_wildcard());
        assert!(config.is_allowed("anything"));
        assert!(config.help_enabled());
    }

    #[test]
    fn test_mixed_patterns() {
        let config = make_scopes(&["tool:web_search", "tool:github:*", "skill:research-*"]);
        assert!(config.is_allowed("tool:web_search"));
        assert!(config.is_allowed("tool:github:search_repos"));
        assert!(config.is_allowed("skill:research-general"));
        assert!(!config.is_allowed("tool:linear:list_issues"));
        assert!(!config.is_allowed("skill:patent-analysis"));
    }
}
