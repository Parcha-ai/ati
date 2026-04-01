use std::path::PathBuf;

use crate::core::jwt;
use crate::core::scope::ScopeConfig;

/// Resolve the ATI directory path.
///
/// Re-exports from `core::dirs::ati_dir()` — the canonical implementation.
pub fn ati_dir() -> PathBuf {
    crate::core::dirs::ati_dir()
}

/// Silently create ~/.ati/ with subdirectories on first use.
/// No-ops if the directory structure already exists.
pub fn ensure_ati_dir() {
    let dir = ati_dir();
    if !dir.join("manifests").exists() {
        let _ = std::fs::create_dir_all(dir.join("manifests"));
        let _ = std::fs::create_dir_all(dir.join("specs"));
        let _ = std::fs::create_dir_all(dir.join("skills"));
        let config = dir.join("config.toml");
        if !config.exists() {
            let _ = std::fs::write(&config, "# ATI configuration\n");
        }
    }
}

/// Load scopes for local-mode commands.
///
/// Semantics:
/// - If JWT validation is configured, ATI_SESSION_TOKEN must be present and valid.
/// - If JWT validation is not configured, local mode stays unrestricted for dev use.
pub fn load_local_scopes_from_env() -> Result<ScopeConfig, Box<dyn std::error::Error>> {
    let jwt_config = jwt::config_from_env()?;
    let token = std::env::var("ATI_SESSION_TOKEN")
        .ok()
        .filter(|token| !token.is_empty());

    match jwt_config {
        Some(config) => {
            let token = token.ok_or(
                "ATI_SESSION_TOKEN is required because JWT validation is configured locally.",
            )?;
            let claims = jwt::validate(&token, &config)
                .map_err(|e| format!("Invalid ATI_SESSION_TOKEN: {e}"))?;
            Ok(ScopeConfig::from_jwt(&claims))
        }
        None => {
            tracing::debug!(
                "JWT validation is not configured locally — running in unrestricted dev mode"
            );
            Ok(ScopeConfig::unrestricted())
        }
    }
}
