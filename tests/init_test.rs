/// Integration tests for `ati init`.

use assert_cmd::Command;
use tempfile::TempDir;

fn ati_cmd() -> Command {
    let mut cmd = Command::cargo_bin("ati").unwrap();
    cmd.env("RUST_LOG", "");
    cmd
}

#[test]
fn test_init_creates_directory_structure() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");

    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["init"])
        .assert()
        .success()
        .stderr(predicates::str::contains("Initialized"))
        .stderr(predicates::str::contains("manifests/"))
        .stderr(predicates::str::contains("specs/"))
        .stderr(predicates::str::contains("skills/"))
        .stderr(predicates::str::contains("config.toml"))
        .stderr(predicates::str::contains("Next steps:"));

    assert!(ati_dir.join("manifests").is_dir());
    assert!(ati_dir.join("specs").is_dir());
    assert!(ati_dir.join("skills").is_dir());
    assert!(ati_dir.join("config.toml").is_file());
}

#[test]
fn test_init_is_idempotent() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");

    // Run init twice
    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["init"])
        .assert()
        .success();

    // Read config.toml content
    let config1 = std::fs::read_to_string(ati_dir.join("config.toml")).unwrap();

    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["init"])
        .assert()
        .success();

    // config.toml should not be overwritten
    let config2 = std::fs::read_to_string(ati_dir.join("config.toml")).unwrap();
    assert_eq!(config1, config2);
}

#[test]
fn test_init_proxy_hs256() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");

    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["init", "--proxy"])
        .assert()
        .success();

    let config = std::fs::read_to_string(ati_dir.join("config.toml")).unwrap();
    assert!(config.contains("HS256"), "config should mention HS256");
    assert!(config.contains("[proxy.jwt]"), "config should have jwt section");
    assert!(config.contains("secret = "), "config should have a secret");
}

#[test]
fn test_init_proxy_es256() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");

    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["init", "--proxy", "--es256"])
        .assert()
        .success();

    assert!(ati_dir.join("jwt-private.pem").is_file());
    assert!(ati_dir.join("jwt-public.pem").is_file());

    let config = std::fs::read_to_string(ati_dir.join("config.toml")).unwrap();
    assert!(config.contains("ES256"), "config should mention ES256");

    // Check private key has restricted permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(ati_dir.join("jwt-private.pem")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
}
