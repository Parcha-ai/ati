//! Request-scoped secret resolver.
//!
//! Wraps the operator `Keyring` and optionally carries per-user secrets
//! prefetched from a [`SecretBackend`](super::secret_backend::SecretBackend).
//! The `get()` interface is identical to `Keyring::get()`, so callsites that
//! previously took `&Keyring` compile unchanged after switching to `&SecretResolver`.

use std::collections::HashMap;

use crate::core::keyring::Keyring;
use crate::core::manifest::Provider;

/// Request-scoped secret resolver.
///
/// Resolution order: user-specific secret → operator keyring default.
pub struct SecretResolver<'a> {
    keyring: &'a Keyring,
    user_secrets: HashMap<String, String>,
}

impl<'a> SecretResolver<'a> {
    /// Create a resolver with only the operator keyring (backward compat / local mode).
    pub fn operator_only(keyring: &'a Keyring) -> Self {
        SecretResolver {
            keyring,
            user_secrets: HashMap::new(),
        }
    }

    /// Create a resolver with prefetched per-user secrets.
    pub fn with_user_secrets(keyring: &'a Keyring, user_secrets: HashMap<String, String>) -> Self {
        SecretResolver {
            keyring,
            user_secrets,
        }
    }

    /// Resolve a secret: user-specific first, then operator default.
    pub fn get(&self, key_name: &str) -> Option<&str> {
        self.user_secrets
            .get(key_name)
            .map(|s| s.as_str())
            .or_else(|| self.keyring.get(key_name))
    }

    /// Check if a key exists (user-specific or operator).
    pub fn contains(&self, key_name: &str) -> bool {
        self.user_secrets.contains_key(key_name) || self.keyring.contains(key_name)
    }

    /// List all available key names (deduplicated).
    pub fn key_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.keyring.key_names();
        for k in self.user_secrets.keys() {
            if !names.iter().any(|n| *n == k.as_str()) {
                names.push(k.as_str());
            }
        }
        names
    }

    /// Whether the underlying keyring was loaded from a sealed (ephemeral) source.
    pub fn ephemeral(&self) -> bool {
        self.keyring.ephemeral
    }

    /// Access the underlying operator keyring directly (e.g. for MCP discovery at startup).
    pub fn keyring(&self) -> &Keyring {
        self.keyring
    }
}

/// Extract the key names a provider needs from its auth and env declarations.
///
/// Used to prefetch the right keys from the secret backend before executing a tool.
pub fn keys_needed(provider: &Provider) -> Vec<String> {
    let mut keys = Vec::new();

    // Static auth key
    if let Some(ref key_name) = provider.auth_key_name {
        keys.push(key_name.clone());
    }

    // OAuth2 secret
    if let Some(ref secret_name) = provider.auth_secret_name {
        keys.push(secret_name.clone());
    }

    // CLI env vars: extract key refs from ${key} and @{key} patterns
    for value in provider.cli_env.values() {
        extract_key_refs(value, &mut keys);
    }

    // MCP env vars: same ${key} pattern
    for value in provider.mcp_env.values() {
        extract_key_refs(value, &mut keys);
    }

    keys.sort();
    keys.dedup();
    keys
}

/// Extract `${key_name}` and `@{key_name}` references from an env value string.
fn extract_key_refs(value: &str, keys: &mut Vec<String>) {
    let mut remaining = value;
    while let Some(start) = remaining.find("${") {
        let rest = &remaining[start + 2..];
        if let Some(end) = rest.find('}') {
            keys.push(rest[..end].to_string());
            remaining = &rest[end + 1..];
        } else {
            break;
        }
    }
    // Also check @{key} (credential file materialization)
    remaining = value;
    while let Some(start) = remaining.find("@{") {
        let rest = &remaining[start + 2..];
        if let Some(end) = rest.find('}') {
            keys.push(rest[..end].to_string());
            remaining = &rest[end + 1..];
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keyring() -> Keyring {
        Keyring::empty()
    }

    #[test]
    fn operator_only_delegates_to_keyring() {
        let kr = test_keyring();
        let resolver = SecretResolver::operator_only(&kr);
        assert!(resolver.get("nonexistent").is_none());
    }

    #[test]
    fn user_secrets_override_operator() {
        let kr = test_keyring();
        let mut user = HashMap::new();
        user.insert("api_key".to_string(), "user_value".to_string());
        let resolver = SecretResolver::with_user_secrets(&kr, user);
        assert_eq!(resolver.get("api_key"), Some("user_value"));
    }

    #[test]
    fn fallback_to_operator_when_user_missing() {
        // Keyring::empty() has no keys, so fallback also returns None
        let kr = test_keyring();
        let user = HashMap::new();
        let resolver = SecretResolver::with_user_secrets(&kr, user);
        assert!(resolver.get("api_key").is_none());
    }

    #[test]
    fn contains_checks_both() {
        let kr = test_keyring();
        let mut user = HashMap::new();
        user.insert("user_key".to_string(), "val".to_string());
        let resolver = SecretResolver::with_user_secrets(&kr, user);
        assert!(resolver.contains("user_key"));
        assert!(!resolver.contains("missing"));
    }

    #[test]
    fn extract_key_refs_from_env_values() {
        let mut keys = Vec::new();
        extract_key_refs("prefix_${api_key}_suffix", &mut keys);
        extract_key_refs("@{credentials_file}", &mut keys);
        extract_key_refs("no_refs_here", &mut keys);
        assert_eq!(keys, vec!["api_key", "credentials_file"]);
    }

    #[test]
    fn keys_needed_extracts_all_ref_types() {
        let mut keys = Vec::new();
        // auth_key_name style
        keys.push("main_key".to_string());
        // CLI env ${ref}
        extract_key_refs("${cli_token}", &mut keys);
        // MCP env ${ref}
        extract_key_refs("${mcp_secret}", &mut keys);
        keys.sort();
        keys.dedup();
        assert!(keys.contains(&"main_key".to_string()));
        assert!(keys.contains(&"cli_token".to_string()));
        assert!(keys.contains(&"mcp_secret".to_string()));
    }
}
