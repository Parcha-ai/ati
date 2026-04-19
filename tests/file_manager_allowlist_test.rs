//! Tests for the download host allowlist (`ATI_DOWNLOAD_ALLOWLIST`).
//!
//! These mutate a process-wide env var and so are serialized via a Mutex.

use ati::core::file_manager::{enforce_download_allowlist, FileManagerError};
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn with_allowlist<F: FnOnce()>(value: Option<&str>, f: F) {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    let prior = std::env::var("ATI_DOWNLOAD_ALLOWLIST").ok();
    match value {
        Some(v) => std::env::set_var("ATI_DOWNLOAD_ALLOWLIST", v),
        None => std::env::remove_var("ATI_DOWNLOAD_ALLOWLIST"),
    }
    f();
    match prior {
        Some(v) => std::env::set_var("ATI_DOWNLOAD_ALLOWLIST", v),
        None => std::env::remove_var("ATI_DOWNLOAD_ALLOWLIST"),
    }
}

#[test]
fn allowlist_unset_permits_any_host() {
    with_allowlist(None, || {
        assert!(enforce_download_allowlist("https://example.com/x").is_ok());
        assert!(enforce_download_allowlist("https://anywhere.test/y").is_ok());
    });
}

#[test]
fn allowlist_empty_value_permits_any_host() {
    with_allowlist(Some(""), || {
        assert!(enforce_download_allowlist("https://example.com/x").is_ok());
    });
    with_allowlist(Some("  ,  "), || {
        assert!(enforce_download_allowlist("https://example.com/x").is_ok());
    });
}

#[test]
fn allowlist_exact_host_match() {
    with_allowlist(Some("v3b.fal.media"), || {
        assert!(enforce_download_allowlist("https://v3b.fal.media/x").is_ok());
        let err =
            enforce_download_allowlist("https://evil.com/x").expect_err("evil.com must be denied");
        assert!(matches!(err, FileManagerError::HostNotAllowed { .. }));
    });
}

#[test]
fn allowlist_subdomain_wildcard() {
    with_allowlist(Some("*.fal.media"), || {
        assert!(enforce_download_allowlist("https://v3b.fal.media/x").is_ok());
        assert!(enforce_download_allowlist("https://cdn.fal.media/y").is_ok());
        assert!(enforce_download_allowlist("https://fal.media/z").is_ok());
        assert!(enforce_download_allowlist("https://evil.com/x").is_err());
        // Suffix-collision tricks must NOT match
        assert!(enforce_download_allowlist("https://evilfal.media/x").is_err());
    });
}

#[test]
fn allowlist_multiple_patterns() {
    with_allowlist(
        Some("v3b.fal.media, *.googleapis.com, raw.githubusercontent.com"),
        || {
            assert!(enforce_download_allowlist("https://v3b.fal.media/x").is_ok());
            assert!(enforce_download_allowlist("https://storage.googleapis.com/x").is_ok());
            assert!(
                enforce_download_allowlist("https://raw.githubusercontent.com/x/y/main/file")
                    .is_ok()
            );
            assert!(enforce_download_allowlist("https://evil.com/x").is_err());
        },
    );
}

#[test]
fn allowlist_is_case_insensitive() {
    with_allowlist(Some("V3B.FAL.MEDIA"), || {
        assert!(enforce_download_allowlist("https://v3b.fal.media/x").is_ok());
        assert!(enforce_download_allowlist("https://V3B.FAL.MEDIA/x").is_ok());
    });
}

#[test]
fn allowlist_invalid_url_rejected() {
    with_allowlist(Some("anything.com"), || {
        let err = enforce_download_allowlist("not a url at all").unwrap_err();
        assert!(matches!(err, FileManagerError::InvalidUrl(_)));
    });
}
