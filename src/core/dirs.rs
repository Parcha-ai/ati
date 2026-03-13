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

/// Map a duration unit string to seconds.
///
/// Supports both short and long forms:
/// `"s"`, `"sec"`, `"second"` → 1
/// `"m"`, `"min"`, `"minute"` → 60
/// `"h"`, `"hr"`, `"hour"` → 3600
/// `"d"`, `"day"` → 86400
pub fn unit_to_secs(unit: &str) -> Option<u64> {
    match unit {
        "s" | "sec" | "second" => Some(1),
        "m" | "min" | "minute" => Some(60),
        "h" | "hr" | "hour" => Some(3600),
        "d" | "day" => Some(86400),
        _ => None,
    }
}
