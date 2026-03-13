//! Tests for SSRF (Server-Side Request Forgery) protection.
//!
//! Validates that `validate_url_not_private()` correctly blocks requests
//! to private/internal network addresses when ATI_SSRF_PROTECTION is enabled.

use ati::core::http::validate_url_not_private;
use std::sync::Mutex;

// Serialize tests that mutate ATI_SSRF_PROTECTION env var
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn with_ssrf_mode(mode: &str, f: impl FnOnce()) {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::set_var("ATI_SSRF_PROTECTION", mode);
    f();
    std::env::remove_var("ATI_SSRF_PROTECTION");
}

// --- Enforcement mode ("1" / "true") ---

#[test]
fn test_ssrf_blocks_loopback_127() {
    with_ssrf_mode("1", || {
        assert!(validate_url_not_private("http://127.0.0.1/api").is_err());
        assert!(validate_url_not_private("http://127.0.0.2:8080/data").is_err());
    });
}

#[test]
fn test_ssrf_blocks_10_private() {
    with_ssrf_mode("1", || {
        assert!(validate_url_not_private("http://10.0.0.1/internal").is_err());
        assert!(validate_url_not_private("http://10.255.255.255/api").is_err());
    });
}

#[test]
fn test_ssrf_blocks_172_private() {
    with_ssrf_mode("1", || {
        assert!(validate_url_not_private("http://172.16.0.1/api").is_err());
        assert!(validate_url_not_private("http://172.31.255.255/api").is_err());
    });
}

#[test]
fn test_ssrf_blocks_192_168_private() {
    with_ssrf_mode("1", || {
        assert!(validate_url_not_private("http://192.168.1.1/api").is_err());
        assert!(validate_url_not_private("http://192.168.0.100:3000/data").is_err());
    });
}

#[test]
fn test_ssrf_blocks_link_local() {
    with_ssrf_mode("1", || {
        assert!(validate_url_not_private("http://169.254.169.254/metadata").is_err());
    });
}

#[test]
fn test_ssrf_blocks_unspecified() {
    with_ssrf_mode("1", || {
        assert!(validate_url_not_private("http://0.0.0.0/api").is_err());
    });
}

#[test]
fn test_ssrf_blocks_cgnat() {
    with_ssrf_mode("1", || {
        assert!(validate_url_not_private("http://100.64.0.1/api").is_err());
        assert!(validate_url_not_private("http://100.127.255.255/api").is_err());
    });
}

#[test]
fn test_ssrf_blocks_localhost_hostname() {
    with_ssrf_mode("1", || {
        assert!(validate_url_not_private("http://localhost/api").is_err());
        assert!(validate_url_not_private("http://localhost:8080/api").is_err());
    });
}

#[test]
fn test_ssrf_blocks_internal_hostnames() {
    with_ssrf_mode("1", || {
        assert!(validate_url_not_private("http://metadata.google.internal/v1").is_err());
        assert!(validate_url_not_private("http://myservice.internal/api").is_err());
        assert!(validate_url_not_private("http://printer.local/status").is_err());
    });
}

#[test]
fn test_ssrf_allows_public_ips() {
    with_ssrf_mode("1", || {
        assert!(validate_url_not_private("https://8.8.8.8/dns").is_ok());
        assert!(validate_url_not_private("https://1.1.1.1/api").is_ok());
        assert!(validate_url_not_private("https://api.example.com/v1").is_ok());
    });
}

#[test]
fn test_ssrf_allows_public_hostnames() {
    with_ssrf_mode("1", || {
        assert!(validate_url_not_private("https://api.github.com/repos").is_ok());
        assert!(validate_url_not_private("https://finnhub.io/api/v1").is_ok());
    });
}

// --- Warn mode ---

#[test]
fn test_ssrf_warn_mode_allows_private() {
    with_ssrf_mode("warn", || {
        // Warn mode should allow but not error
        assert!(validate_url_not_private("http://127.0.0.1/api").is_ok());
        assert!(validate_url_not_private("http://10.0.0.1/api").is_ok());
        assert!(validate_url_not_private("http://localhost/api").is_ok());
    });
}

// --- Disabled mode (default) ---

#[test]
fn test_ssrf_disabled_allows_everything() {
    with_ssrf_mode("", || {
        assert!(validate_url_not_private("http://127.0.0.1/api").is_ok());
        assert!(validate_url_not_private("http://10.0.0.1/api").is_ok());
        assert!(validate_url_not_private("http://localhost/api").is_ok());
    });
}

// --- Edge cases ---

#[test]
fn test_ssrf_empty_url() {
    with_ssrf_mode("1", || {
        assert!(validate_url_not_private("").is_ok());
    });
}

#[test]
fn test_ssrf_https_private() {
    with_ssrf_mode("1", || {
        assert!(validate_url_not_private("https://192.168.1.1/api").is_err());
        assert!(validate_url_not_private("https://localhost/api").is_err());
    });
}

#[test]
fn test_ssrf_url_with_port() {
    with_ssrf_mode("1", || {
        assert!(validate_url_not_private("http://127.0.0.1:9090/api").is_err());
        assert!(validate_url_not_private("http://10.0.0.5:443/api").is_err());
    });
}

#[test]
fn test_ssrf_case_insensitive_hostname() {
    with_ssrf_mode("1", || {
        assert!(validate_url_not_private("http://LOCALHOST/api").is_err());
        assert!(validate_url_not_private("http://Metadata.Google.Internal/v1").is_err());
    });
}

#[test]
fn test_ssrf_true_mode_case_insensitive() {
    with_ssrf_mode("TRUE", || {
        assert!(validate_url_not_private("http://127.0.0.1/api").is_err());
    });
    with_ssrf_mode("True", || {
        assert!(validate_url_not_private("http://10.0.0.1/api").is_err());
    });
}

#[test]
fn test_ssrf_172_outside_private_range() {
    with_ssrf_mode("1", || {
        // 172.32.x.x is NOT private (private is 172.16-31.x.x)
        assert!(validate_url_not_private("http://172.32.0.1/api").is_ok());
        assert!(validate_url_not_private("http://172.15.255.255/api").is_ok());
    });
}

#[test]
fn test_ssrf_100_outside_cgnat_range() {
    with_ssrf_mode("1", || {
        // 100.128+ is NOT CGNAT (CGNAT is 100.64-127.x.x)
        assert!(validate_url_not_private("http://100.128.0.1/api").is_ok());
        assert!(validate_url_not_private("http://100.63.255.255/api").is_ok());
    });
}
