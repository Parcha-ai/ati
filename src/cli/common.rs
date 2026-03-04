use std::path::PathBuf;

/// Resolve the ATI directory path.
///
/// Priority: ATI_DIR env var > $HOME/.ati > fallback to .ati
pub fn ati_dir() -> PathBuf {
    std::env::var("ATI_DIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".ati"))
                .unwrap_or_else(|_| PathBuf::from(".ati"))
        })
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
