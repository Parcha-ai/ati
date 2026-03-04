/// Integration tests for `ati keys set/list/remove`.

use assert_cmd::Command;
use tempfile::TempDir;

fn ati_cmd() -> Command {
    let mut cmd = Command::cargo_bin("ati").unwrap();
    cmd.env("RUST_LOG", "");
    cmd
}

#[test]
fn test_keys_set_creates_credentials_file() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");

    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["keys", "set", "my_api_key", "sk-test-12345"])
        .assert()
        .success()
        .stderr(predicates::str::contains("Saved my_api_key"));

    let creds_path = ati_dir.join("credentials");
    assert!(creds_path.is_file());

    let content: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&creds_path).unwrap()).unwrap();
    assert_eq!(content["my_api_key"], "sk-test-12345");

    // Check 0600 permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(&creds_path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn test_keys_list_shows_masked_values() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");

    // Set a key first
    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["keys", "set", "my_api_key", "sk-test-12345"])
        .assert()
        .success();

    // List should show masked value
    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["keys", "list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("my_api_key"))
        .stdout(predicates::str::contains("sk-t...2345"));
}

#[test]
fn test_keys_list_empty() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(&ati_dir).unwrap();

    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["keys", "list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("No keys stored"));
}

#[test]
fn test_keys_remove() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");

    // Set two keys
    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["keys", "set", "key_a", "value_a"])
        .assert()
        .success();

    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["keys", "set", "key_b", "value_b"])
        .assert()
        .success();

    // Remove one
    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["keys", "remove", "key_a"])
        .assert()
        .success()
        .stderr(predicates::str::contains("Removed key_a"));

    // Verify removal
    let content: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(ati_dir.join("credentials")).unwrap(),
    )
    .unwrap();
    assert!(content.get("key_a").is_none());
    assert_eq!(content["key_b"], "value_b");
}

#[test]
fn test_keys_remove_nonexistent() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    std::fs::create_dir_all(&ati_dir).unwrap();
    std::fs::write(ati_dir.join("credentials"), "{}").unwrap();

    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["keys", "remove", "nonexistent"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("not found"));
}

#[test]
fn test_keys_set_overwrites_existing() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");

    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["keys", "set", "my_key", "old_value"])
        .assert()
        .success();

    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["keys", "set", "my_key", "new_value"])
        .assert()
        .success();

    let content: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(ati_dir.join("credentials")).unwrap(),
    )
    .unwrap();
    assert_eq!(content["my_key"], "new_value");
}

#[test]
fn test_keys_set_without_init_creates_dir() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join("nested").join(".ati");

    // Should auto-create the directory
    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["keys", "set", "auto_key", "auto_val"])
        .assert()
        .success();

    assert!(ati_dir.join("credentials").is_file());
}

/// Test the keyring credential cascade in `ati call`:
/// credentials file should be picked up when keyring.enc is absent.
#[test]
fn test_call_uses_credentials_cascade() {
    let dir = TempDir::new().unwrap();
    let ati_dir = dir.path().join(".ati");
    let manifests_dir = ati_dir.join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap();

    // Write a minimal manifest with auth_type = none (so we don't need real keys to test tool lookup)
    let manifest = r#"
[provider]
name = "test_provider"
description = "Test provider"
base_url = "http://localhost:1"
auth_type = "none"

[[tools]]
name = "test_tool"
endpoint = "/test"
method = "GET"
description = "Test tool"
"#;
    std::fs::write(manifests_dir.join("test.toml"), manifest).unwrap();

    // Write credentials file
    std::fs::write(
        ati_dir.join("credentials"),
        r#"{"my_key":"my_value"}"#,
    )
    .unwrap();

    // ati call should work (will fail on actual HTTP but should find the tool via cascade)
    // We just test verbose mode prints "credentials (plaintext)"
    ati_cmd()
        .env("ATI_DIR", ati_dir.to_str().unwrap())
        .args(["--verbose", "call", "test_tool"])
        .assert()
        .stderr(predicates::str::contains("credentials (plaintext)"));
}
