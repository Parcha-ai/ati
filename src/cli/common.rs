use std::path::PathBuf;

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
