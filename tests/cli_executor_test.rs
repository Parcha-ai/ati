use std::collections::HashMap;
use std::path::Path;

use ati::core::cli_executor;
use ati::core::keyring::Keyring;
use ati::core::manifest::{AuthType, ManifestRegistry, Provider};

/// Build a minimal CLI provider for tests.
fn make_cli_provider(
    name: &str,
    command: &str,
    default_args: Vec<String>,
    cli_env: HashMap<String, String>,
    timeout: Option<u64>,
) -> Provider {
    Provider {
        name: name.to_string(),
        description: format!("{name} CLI test"),
        base_url: String::new(),
        auth_type: AuthType::None,
        auth_key_name: None,
        auth_header_name: None,
        auth_query_name: None,
        auth_value_prefix: None,
        extra_headers: HashMap::new(),
        oauth2_token_url: None,
        auth_secret_name: None,
        oauth2_basic_auth: false,
        oauth_resource: None,
        oauth_scopes: Vec::new(),
        internal: false,
        handler: "cli".to_string(),
        mcp_transport: None,
        mcp_command: None,
        mcp_args: Vec::new(),
        mcp_url: None,
        mcp_env: HashMap::new(),
        openapi_spec: None,
        openapi_include_tags: Vec::new(),
        openapi_exclude_tags: Vec::new(),
        openapi_include_operations: Vec::new(),
        openapi_exclude_operations: Vec::new(),
        openapi_max_operations: None,
        openapi_overrides: HashMap::new(),
        cli_command: Some(command.to_string()),
        cli_default_args: default_args,
        cli_env,
        cli_timeout_secs: timeout,
        cli_output_args: Vec::new(),
        cli_output_positional: HashMap::new(),
        upload_destinations: HashMap::new(),
        upload_default_destination: None,
        auth_generator: None,
        category: None,
        skills: Vec::new(),
    }
}

/// Build a test keyring from a JSON string.
fn make_keyring(json: &str) -> Keyring {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("creds");
    std::fs::write(&path, json).unwrap();
    Keyring::load_credentials(&path).unwrap()
}

// ---------------------------------------------------------------------------
// Basic execution tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cli_echo() {
    let provider = make_cli_provider("myecho", "echo", vec![], HashMap::new(), None);
    let keyring = Keyring::empty();
    let result = cli_executor::execute(&provider, &["hello".into(), "world".into()], &keyring)
        .await
        .unwrap();
    assert_eq!(result.as_str().unwrap(), "hello world");
}

#[tokio::test]
async fn test_cli_echo_with_default_args() {
    let provider = make_cli_provider("myecho", "echo", vec!["-n".into()], HashMap::new(), None);
    let keyring = Keyring::empty();
    let result = cli_executor::execute(&provider, &["hello".into()], &keyring)
        .await
        .unwrap();
    assert_eq!(result.as_str().unwrap(), "hello");
}

#[tokio::test]
async fn test_cli_json_output() {
    let provider = make_cli_provider("jsonecho", "echo", vec![], HashMap::new(), None);
    let keyring = Keyring::empty();
    let result =
        cli_executor::execute(&provider, &[r#"{"key":"value","num":42}"#.into()], &keyring)
            .await
            .unwrap();
    // Should be parsed as JSON, not a string
    assert!(result.is_object());
    assert_eq!(result["key"], "value");
    assert_eq!(result["num"], 42);
}

#[tokio::test]
async fn test_cli_nonzero_exit() {
    let provider = make_cli_provider("failing", "false", vec![], HashMap::new(), None);
    let keyring = Keyring::empty();
    let err = cli_executor::execute(&provider, &[], &keyring)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("exited with code"), "error was: {msg}");
}

#[tokio::test]
async fn test_cli_timeout() {
    let provider = make_cli_provider("sleeper", "sleep", vec![], HashMap::new(), Some(1));
    let keyring = Keyring::empty();
    let err = cli_executor::execute(&provider, &["60".into()], &keyring)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("timed out"), "error was: {msg}");
}

#[tokio::test]
async fn test_cli_missing_command() {
    let provider = make_cli_provider(
        "bad",
        "nonexistent_binary_xyz_abc",
        vec![],
        HashMap::new(),
        None,
    );
    let keyring = Keyring::empty();
    let err = cli_executor::execute(&provider, &[], &keyring)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("spawn") || msg.contains("No such file"),
        "error was: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Environment variable injection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cli_env_var_injection() {
    let mut cli_env = HashMap::new();
    cli_env.insert("MY_SECRET".into(), "${test_key}".into());
    let provider = make_cli_provider("envtest", "printenv", vec![], cli_env, None);
    let keyring = make_keyring(r#"{"test_key":"secret_value_123"}"#);
    let result = cli_executor::execute(&provider, &["MY_SECRET".into()], &keyring)
        .await
        .unwrap();
    assert_eq!(result.as_str().unwrap(), "secret_value_123");
}

#[tokio::test]
async fn test_cli_env_var_missing_key() {
    let mut cli_env = HashMap::new();
    cli_env.insert("FOO".into(), "${nonexistent_key}".into());
    let provider = make_cli_provider("envtest", "echo", vec![], cli_env, None);
    let keyring = Keyring::empty();
    let err = cli_executor::execute(&provider, &[], &keyring)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("Missing keyring key"), "error was: {msg}");
}

// ---------------------------------------------------------------------------
// Credential file materialization
// ---------------------------------------------------------------------------

#[test]
fn test_credential_file_dev_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let cf = cli_executor::materialize_credential_file("mykey", "content123", false, tmp.path())
        .unwrap();
    assert_eq!(cf.path, tmp.path().join(".creds/mykey"));
    assert_eq!(std::fs::read_to_string(&cf.path).unwrap(), "content123");
}

#[test]
fn test_credential_file_permissions() {
    let tmp = tempfile::tempdir().unwrap();
    let cf =
        cli_executor::materialize_credential_file("permkey", "data", false, tmp.path()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&cf.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "credential file mode should be 0600");
    }
    drop(cf);
}

#[test]
fn test_credential_file_cleanup_ephemeral() {
    let tmp = tempfile::tempdir().unwrap();
    let path;
    {
        let cf = cli_executor::materialize_credential_file("ephkey", "secret", true, tmp.path())
            .unwrap();
        path = cf.path.clone();
        assert!(path.exists(), "file should exist before drop");
    }
    assert!(!path.exists(), "ephemeral file should be wiped on drop");
}

#[test]
fn test_credential_file_persists_dev_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let path;
    {
        let cf =
            cli_executor::materialize_credential_file("devkey", "data", false, tmp.path()).unwrap();
        path = cf.path.clone();
        assert!(path.exists());
    }
    // In dev mode, file persists after drop
    assert!(path.exists(), "dev mode file should persist after drop");
}

#[test]
fn test_credential_file_prod_unique_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let cf1 = cli_executor::materialize_credential_file("key", "val1", true, tmp.path()).unwrap();
    let cf2 = cli_executor::materialize_credential_file("key", "val2", true, tmp.path()).unwrap();
    assert_ne!(cf1.path, cf2.path, "prod mode should use unique paths");
}

#[test]
fn test_resolve_cli_env() {
    let keyring = make_keyring(r#"{"api_key":"KEY123","cred_data":"FILE_CONTENT"}"#);
    let tmp = tempfile::tempdir().unwrap();

    let mut env = HashMap::new();
    env.insert("API_KEY".into(), "${api_key}".into());
    env.insert("CRED_FILE".into(), "@{cred_data}".into());
    env.insert("PLAIN".into(), "plain_value".into());

    let (resolved, cred_files) =
        cli_executor::resolve_cli_env(&env, &keyring, false, tmp.path()).unwrap();

    assert_eq!(resolved["API_KEY"], "KEY123");
    assert_eq!(resolved["PLAIN"], "plain_value");
    // CRED_FILE should be a path to a file containing FILE_CONTENT
    let cred_path = &resolved["CRED_FILE"];
    assert!(
        Path::new(cred_path).exists(),
        "credential file should exist at {cred_path}"
    );
    assert_eq!(std::fs::read_to_string(cred_path).unwrap(), "FILE_CONTENT");
    assert_eq!(cred_files.len(), 1);
}

// ---------------------------------------------------------------------------
// Manifest / tool registration tests
// ---------------------------------------------------------------------------

#[test]
fn test_cli_tool_shows_in_registry() {
    let tmp = tempfile::tempdir().unwrap();
    let manifests_dir = tmp.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap();

    // Write a CLI manifest with NO [[tools]] section
    let manifest = r#"
[provider]
name = "myecho"
description = "Test echo CLI"
handler = "cli"
cli_command = "echo"
auth_type = "none"
"#;
    std::fs::write(manifests_dir.join("myecho.toml"), manifest).unwrap();

    let registry = ManifestRegistry::load(&manifests_dir).unwrap();

    // Should have auto-registered one tool named "myecho"
    let tool = registry.get_tool("myecho");
    assert!(tool.is_some(), "CLI tool should be auto-registered");
    let (provider, tool) = tool.unwrap();
    assert_eq!(provider.handler, "cli");
    assert_eq!(tool.name, "myecho");
    assert_eq!(tool.description, "Test echo CLI");
}

#[test]
fn test_cli_provider_add_generates_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    let manifests_dir = tmp.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap();

    // Write a manifest manually following the add-cli format
    let toml_content = toml::to_string_pretty(&toml::toml! {
        [provider]
        name = "testcli"
        description = "Test CLI provider"
        handler = "cli"
        cli_command = "echo"
        auth_type = "none"
    })
    .unwrap();
    let path = manifests_dir.join("testcli.toml");
    std::fs::write(&path, &toml_content).unwrap();

    // Load and verify
    let registry = ManifestRegistry::load(&manifests_dir).unwrap();
    let (prov, _tool) = registry.get_tool("testcli").unwrap();
    assert_eq!(prov.handler, "cli");
    assert_eq!(prov.cli_command.as_deref(), Some("echo"));
}

#[test]
fn test_cli_provider_with_env_and_timeout() {
    let tmp = tempfile::tempdir().unwrap();
    let manifests_dir = tmp.path().join("manifests");
    std::fs::create_dir_all(&manifests_dir).unwrap();

    let manifest = r#"
[provider]
name = "gcs"
description = "Google Cloud Storage"
handler = "cli"
cli_command = "gsutil"
cli_timeout_secs = 60
auth_type = "none"

[provider.cli_env]
GOOGLE_APPLICATION_CREDENTIALS = "@{gcp_credentials}"
CLOUDSDK_CORE_PROJECT = "${gcp_project_id}"
"#;
    std::fs::write(manifests_dir.join("gcs.toml"), manifest).unwrap();

    let registry = ManifestRegistry::load(&manifests_dir).unwrap();
    let (prov, _) = registry.get_tool("gcs").unwrap();
    assert_eq!(prov.cli_timeout_secs, Some(60));
    assert_eq!(prov.cli_env.len(), 2);
    assert_eq!(
        prov.cli_env.get("GOOGLE_APPLICATION_CREDENTIALS").unwrap(),
        "@{gcp_credentials}"
    );
}

// ---------------------------------------------------------------------------
// Subprocess binary tests (assert_cmd)
// ---------------------------------------------------------------------------

#[test]
fn test_add_cli_help() {
    let cmd = assert_cmd::Command::cargo_bin("ati")
        .unwrap()
        .args(["provider", "add-cli", "--help"])
        .assert()
        .success();
    let output = String::from_utf8_lossy(&cmd.get_output().stdout);
    assert!(output.contains("CLI"), "help should mention CLI");
    assert!(
        output.contains("--command"),
        "help should show --command flag"
    );
}

#[test]
fn test_add_cli_creates_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    assert_cmd::Command::cargo_bin("ati")
        .unwrap()
        .env("ATI_DIR", tmp.path())
        .args([
            "provider",
            "add-cli",
            "testecho",
            "--command",
            "echo",
            "--description",
            "Test echo",
        ])
        .assert()
        .success();

    let manifest_path = tmp.path().join("manifests/testecho.toml");
    assert!(manifest_path.exists(), "manifest should be created");
    let content = std::fs::read_to_string(&manifest_path).unwrap();
    assert!(
        content.contains("handler = \"cli\""),
        "should be cli handler"
    );
    assert!(
        content.contains("cli_command = \"echo\""),
        "should have correct command"
    );
}

// ---------------------------------------------------------------------------
// Output capture (cli_output_args / cli_output_positional)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cli_output_args_named_flag_captures_file() {
    // Use `sh -c 'echo "bytes" > $1' _ --output PATH` style by wrapping with sh.
    // Simpler: use a tiny shell script that writes to whatever --output points at.
    let tmp = tempfile::tempdir().unwrap();
    let script = tmp.path().join("writer.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\n\
         # Find --output and write payload there\n\
         while [ $# -gt 0 ]; do\n\
           if [ \"$1\" = \"--output\" ]; then\n\
             shift\n\
             printf 'captured-bytes-%s' \"$BB_MARKER\" > \"$1\"\n\
             exit 0\n\
           fi\n\
           shift\n\
         done\n\
         exit 2\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let agent_path = tmp
        .path()
        .join("sandbox-out.bin")
        .to_string_lossy()
        .to_string();

    let mut env = HashMap::new();
    env.insert("BB_MARKER".to_string(), "ABC".to_string());
    let mut provider = make_cli_provider("writer", script.to_str().unwrap(), vec![], env, None);
    provider.cli_output_args = vec!["--output".to_string()];

    let keyring = Keyring::empty();
    let result = cli_executor::execute(
        &provider,
        &["--output".to_string(), agent_path.clone()],
        &keyring,
    )
    .await
    .unwrap();

    // Agent-facing path should NOT have been written (that's a sandbox path —
    // the proxy substituted a temp and captured the bytes back into the response).
    assert!(
        !std::path::Path::new(&agent_path).exists(),
        "proxy must not write to the agent's original path"
    );

    // Response has the envelope
    let outputs = result.get("outputs").and_then(|v| v.as_object()).unwrap();
    let entry = outputs
        .get(&agent_path)
        .expect("expected original path key");
    let b64 = entry
        .get("content_base64")
        .and_then(|v| v.as_str())
        .unwrap();
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let bytes = B64.decode(b64).unwrap();
    assert_eq!(bytes, b"captured-bytes-ABC");
    assert_eq!(
        entry.get("size_bytes").unwrap().as_u64().unwrap(),
        bytes.len() as u64
    );
}

#[tokio::test]
async fn test_cli_output_positional_rewrites_path() {
    // Script that writes a PNG-like payload to its LAST positional arg.
    let tmp = tempfile::tempdir().unwrap();
    let script = tmp.path().join("shot.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\n\
         # Expect: browse screenshot <path>\n\
         [ \"$1\" = \"browse\" ] || exit 2\n\
         [ \"$2\" = \"screenshot\" ] || exit 2\n\
         printf 'PNG-HEADER' > \"$3\"\n\
         echo 'wrote screenshot to '$3\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let agent_path = tmp.path().join("shot.png").to_string_lossy().to_string();

    let mut provider = make_cli_provider(
        "fakebb",
        script.to_str().unwrap(),
        vec![],
        HashMap::new(),
        None,
    );
    provider
        .cli_output_positional
        .insert("browse screenshot".to_string(), 0);

    let keyring = Keyring::empty();
    let result = cli_executor::execute(
        &provider,
        &["browse".into(), "screenshot".into(), agent_path.clone()],
        &keyring,
    )
    .await
    .unwrap();

    assert!(!std::path::Path::new(&agent_path).exists());
    let outputs = result.get("outputs").and_then(|v| v.as_object()).unwrap();
    let entry = outputs.get(&agent_path).expect("path key missing");
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let b64 = entry
        .get("content_base64")
        .and_then(|v| v.as_str())
        .unwrap();
    assert_eq!(B64.decode(b64).unwrap(), b"PNG-HEADER");
    assert_eq!(
        entry.get("content_type").and_then(|v| v.as_str()),
        Some("image/png")
    );

    let stdout = result.get("stdout").and_then(|v| v.as_str()).unwrap();
    assert!(
        stdout.starts_with("wrote screenshot to"),
        "stdout preserved: {stdout}"
    );
}

#[tokio::test]
async fn test_cli_output_missing_file_returns_error() {
    // Script exits 0 but never writes the output file.
    let tmp = tempfile::tempdir().unwrap();
    let script = tmp.path().join("noop.sh");
    std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut provider = make_cli_provider(
        "noop",
        script.to_str().unwrap(),
        vec![],
        HashMap::new(),
        None,
    );
    provider.cli_output_args = vec!["--output".to_string()];

    let keyring = Keyring::empty();
    let err = cli_executor::execute(
        &provider,
        &[
            "--output".to_string(),
            tmp.path().join("missing.bin").to_string_lossy().to_string(),
        ],
        &keyring,
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("was not produced"), "unexpected error: {msg}");
}

#[tokio::test]
async fn test_cli_no_capture_preserves_legacy_shape() {
    // No cli_output_args configured → response stays a plain string as before.
    let provider = make_cli_provider("myecho", "echo", vec![], HashMap::new(), None);
    let keyring = Keyring::empty();
    let result = cli_executor::execute(&provider, &["hello".into()], &keyring)
        .await
        .unwrap();
    assert_eq!(result.as_str().unwrap(), "hello");
    assert!(result.get("outputs").is_none());
}

#[tokio::test]
async fn test_cli_output_nonzero_exit_still_cleans_temp() {
    // Script: write to output, then fail with exit 7. Temp must be deleted.
    let tmp = tempfile::tempdir().unwrap();
    let script = tmp.path().join("fail.sh");
    std::fs::write(&script, "#!/bin/sh\nprintf 'partial' > \"$2\"\nexit 7\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    // Use a unique extension so we only see THIS test's temp files (other
    // parallel tests in the same binary also create `.ati-cli-out-*` temps).
    let agent_path = tmp
        .path()
        .join("agent.cleanup-marker-xyz")
        .to_string_lossy()
        .to_string();
    let mut provider = make_cli_provider(
        "fail",
        script.to_str().unwrap(),
        vec![],
        HashMap::new(),
        None,
    );
    provider.cli_output_args = vec!["--output".to_string()];

    let keyring = Keyring::empty();
    let err = cli_executor::execute(
        &provider,
        &["--output".to_string(), agent_path.clone()],
        &keyring,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("exited with code 7"));
    // Agent path untouched
    assert!(!std::path::Path::new(&agent_path).exists());
    // No leftover proxy-side temp files with our unique extension marker.
    let temp_dir = std::env::temp_dir();
    let leftovers: Vec<_> = std::fs::read_dir(&temp_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let s = name.to_string_lossy();
            s.starts_with(".ati-cli-out-") && s.ends_with(".cleanup-marker-xyz")
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "proxy temp not cleaned up: {leftovers:?}"
    );
}

#[test]
fn test_apply_output_captures_equals_form() {
    use ati::core::cli_executor::apply_output_captures;
    let mut provider = make_cli_provider("t", "echo", vec![], HashMap::new(), None);
    provider.cli_output_args = vec!["--output".to_string()];

    let (rewritten, captures) =
        apply_output_captures(&provider, &["--output=/tmp/real.bin".to_string()]).unwrap();
    assert_eq!(captures.len(), 1);
    assert_eq!(captures[0].original_path, "/tmp/real.bin");
    assert!(rewritten[0].starts_with("--output="));
    assert_ne!(rewritten[0], "--output=/tmp/real.bin");
}

/// Regression: when both cli_output_args and cli_output_positional are
/// configured (as the bb manifest does), step 1's named-flag rewrite must
/// consume the slot so step 2's positional rewrite doesn't pick up the
/// already-substituted temp path as a new "output."
#[test]
fn test_apply_output_captures_no_double_rewrite_when_both_configured() {
    use ati::core::cli_executor::apply_output_captures;
    let mut provider = make_cli_provider("bb_clone", "true", vec![], HashMap::new(), None);
    provider.cli_output_args = vec!["--output".to_string(), "-o".to_string()];
    provider
        .cli_output_positional
        .insert("browse screenshot".to_string(), 0);

    // Named-flag form on a subcommand that ALSO has a positional output rule.
    let raw_args = vec![
        "browse".to_string(),
        "screenshot".to_string(),
        "--output".to_string(),
        "/tmp/shot.png".to_string(),
    ];
    let (rewritten, captures) = apply_output_captures(&provider, &raw_args).unwrap();

    // Exactly one capture, pointing at the agent's original path.
    assert_eq!(
        captures.len(),
        1,
        "expected single capture, got {captures:?}"
    );
    assert_eq!(captures[0].original_path, "/tmp/shot.png");

    // The arg following --output is the rewritten temp path.
    assert_eq!(rewritten[0], "browse");
    assert_eq!(rewritten[1], "screenshot");
    assert_eq!(rewritten[2], "--output");
    assert_ne!(
        rewritten[3], "/tmp/shot.png",
        "named-flag value should have been rewritten to a temp path"
    );
    assert!(
        rewritten[3].contains(".ati-cli-out-"),
        "rewritten value should be a temp path: {}",
        rewritten[3]
    );
}

/// Variant: positional form on the same provider config — the positional
/// rewrite still kicks in (no --output flag → step 1 finds nothing → step 2
/// handles the bare path).
#[test]
fn test_apply_output_captures_positional_still_works_when_both_configured() {
    use ati::core::cli_executor::apply_output_captures;
    let mut provider = make_cli_provider("bb_clone", "true", vec![], HashMap::new(), None);
    provider.cli_output_args = vec!["--output".to_string(), "-o".to_string()];
    provider
        .cli_output_positional
        .insert("browse screenshot".to_string(), 0);

    let raw_args = vec![
        "browse".to_string(),
        "screenshot".to_string(),
        "/tmp/positional.png".to_string(),
    ];
    let (rewritten, captures) = apply_output_captures(&provider, &raw_args).unwrap();
    assert_eq!(captures.len(), 1);
    assert_eq!(captures[0].original_path, "/tmp/positional.png");
    assert_ne!(rewritten[2], "/tmp/positional.png");
}
