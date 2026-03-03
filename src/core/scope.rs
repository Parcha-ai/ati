use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

use crate::core::manifest::{Provider, Tool};

#[derive(Error, Debug)]
pub enum ScopeError {
    #[error("Failed to read scopes file: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to parse scopes file: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("Scopes have expired (expired at {0})")]
    Expired(u64),
    #[error("Access denied: '{0}' is not in your scopes")]
    AccessDenied(String),
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScopeConfig {
    pub scopes: Vec<String>,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub job_id: String,
    #[serde(default)]
    pub expires_at: u64,
    /// HMAC signature for tamper detection (optional)
    #[serde(default)]
    pub hmac: Option<String>,
}

impl ScopeConfig {
    /// Load scopes from a JSON file.
    pub fn load(path: &Path) -> Result<Self, ScopeError> {
        let contents = std::fs::read_to_string(path)?;
        let config: ScopeConfig = serde_json::from_str(&contents)?;
        Ok(config)
    }

    /// Check if the scopes have expired.
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false; // No expiry set
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expires_at
    }

    /// Check if a specific tool scope is allowed.
    pub fn is_allowed(&self, tool_scope: &str) -> bool {
        if self.is_expired() {
            return false;
        }
        // Empty scope on tool means always allowed
        if tool_scope.is_empty() {
            return true;
        }
        // Wildcard scope allows everything
        if self.is_wildcard() {
            return true;
        }
        self.scopes.iter().any(|s| s == tool_scope)
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
        self.scopes.iter().filter(|s| s.starts_with("tool:")).count()
    }

    /// Number of skill scopes (those starting with "skill:").
    pub fn skill_scope_count(&self) -> usize {
        self.scopes.iter().filter(|s| s.starts_with("skill:")).count()
    }

    /// Check if help is enabled.
    pub fn help_enabled(&self) -> bool {
        self.scopes.iter().any(|s| s == "help")
    }

    /// Create an unrestricted scope config (for testing/development).
    pub fn unrestricted() -> Self {
        ScopeConfig {
            scopes: vec!["*".to_string()],
            agent_id: "dev".to_string(),
            job_id: "dev".to_string(),
            expires_at: 0,
            hmac: None,
        }
    }

    /// Check if this is an unrestricted (wildcard) scope.
    fn is_wildcard(&self) -> bool {
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
        .filter(|(_, tool)| {
            match &tool.scope {
                Some(scope) => scopes.is_allowed(scope),
                None => true, // No scope required = always allowed
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_allowed() {
        let config = ScopeConfig {
            scopes: vec!["tool:web_search".into(), "tool:web_fetch".into()],
            agent_id: "test".into(),
            job_id: "test".into(),
            expires_at: 0,
            hmac: None,
        };

        assert!(config.is_allowed("tool:web_search"));
        assert!(config.is_allowed("tool:web_fetch"));
        assert!(!config.is_allowed("tool:patent_search"));
        assert!(config.is_allowed("")); // Empty scope = always allowed
    }

    #[test]
    fn test_scope_expired() {
        let config = ScopeConfig {
            scopes: vec!["tool:web_search".into()],
            agent_id: "test".into(),
            job_id: "test".into(),
            expires_at: 1, // Already expired
            hmac: None,
        };

        assert!(config.is_expired());
        assert!(!config.is_allowed("tool:web_search"));
    }

    #[test]
    fn test_wildcard_scope() {
        let config = ScopeConfig::unrestricted();
        assert!(config.is_wildcard());
    }
}
