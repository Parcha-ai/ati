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
