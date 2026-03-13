//! Tests for the dirs module — ATI directory resolution and unit-to-seconds conversion.

use ati::core::dirs::{ati_dir, unit_to_secs};
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

// --- unit_to_secs ---

#[test]
fn test_unit_to_secs_seconds() {
    assert_eq!(unit_to_secs("s"), Some(1));
    assert_eq!(unit_to_secs("sec"), Some(1));
    assert_eq!(unit_to_secs("second"), Some(1));
}

#[test]
fn test_unit_to_secs_minutes() {
    assert_eq!(unit_to_secs("m"), Some(60));
    assert_eq!(unit_to_secs("min"), Some(60));
    assert_eq!(unit_to_secs("minute"), Some(60));
}

#[test]
fn test_unit_to_secs_hours() {
    assert_eq!(unit_to_secs("h"), Some(3600));
    assert_eq!(unit_to_secs("hr"), Some(3600));
    assert_eq!(unit_to_secs("hour"), Some(3600));
}

#[test]
fn test_unit_to_secs_days() {
    assert_eq!(unit_to_secs("d"), Some(86400));
    assert_eq!(unit_to_secs("day"), Some(86400));
}

#[test]
fn test_unit_to_secs_unknown() {
    assert_eq!(unit_to_secs("week"), None);
    assert_eq!(unit_to_secs("year"), None);
    assert_eq!(unit_to_secs(""), None);
    assert_eq!(unit_to_secs("ms"), None);
}

// --- ati_dir ---

#[test]
fn test_ati_dir_from_env() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::set_var("ATI_DIR", "/custom/ati");
    let dir = ati_dir();
    std::env::remove_var("ATI_DIR");
    assert_eq!(dir, std::path::PathBuf::from("/custom/ati"));
}

#[test]
fn test_ati_dir_from_home() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::remove_var("ATI_DIR");
    // HOME should be set in CI and dev
    let dir = ati_dir();
    assert!(
        dir.to_str().unwrap().ends_with(".ati"),
        "Expected path ending in .ati, got: {:?}",
        dir
    );
}
