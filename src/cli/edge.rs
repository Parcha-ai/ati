//! `ati edge` — operator commands for the edge VM deployment.
//!
//! Two subcommands today (more may land in later PRs):
//!
//! - `bootstrap-keyring` — pull credentials from a 1Password item and write
//!   `<ati_dir>/keyring.enc` + `<ati_dir>/.keyring-key`. Used on a fresh VM
//!   install.
//! - `rotate-keyring` — same pull + write, but atomically replaces an existing
//!   keyring (tempfile + `rename(2)`) and then SIGHUPs the running `ati`
//!   service so the new secret takes effect without a restart.
//!
//! Both shell out to the `op` CLI rather than embedding 1Password's API
//! client — operators already have `op` configured on the VM (via the service
//! account token at `/etc/op-service-account-token`), and shelling out keeps
//! the binary footprint minimal.
//!
//! ## 1Password item shape
//!
//! Expected `op item get --format json` shape:
//!
//! ```json
//! {
//!   "fields": [
//!     { "label": "browserbase_api_key", "value": "bb_live_..." },
//!     { "label": "grafana_cloud_otlp_auth", "value": "..." },
//!     { "label": "sandbox_signing_shared_secret", "value": "deadbeef..." }
//!   ]
//! }
//! ```
//!
//! Field `label` becomes the keyring entry name. Fields without a `value`
//! (e.g. notes, references) are skipped silently.

use base64::Engine;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::core::keyring::{encrypt_keyring, generate_session_key};

/// Execute `ati edge <subcommand>`.
pub fn execute(subcmd: &crate::EdgeCommands) -> Result<(), Box<dyn std::error::Error>> {
    match subcmd {
        crate::EdgeCommands::BootstrapKeyring {
            vault,
            item,
            ati_dir,
            op_path,
            op_token_file,
        } => bootstrap_keyring(
            vault,
            item,
            ati_dir.as_deref(),
            op_path.as_deref(),
            op_token_file.as_deref(),
        ),
        crate::EdgeCommands::RotateKeyring {
            vault,
            item,
            ati_dir,
            op_path,
            op_token_file,
            service,
            no_signal,
        } => rotate_keyring(
            vault,
            item,
            ati_dir.as_deref(),
            op_path.as_deref(),
            op_token_file.as_deref(),
            service,
            *no_signal,
        ),
    }
}

fn resolve_ati_dir(cli_override: Option<&str>) -> PathBuf {
    match cli_override {
        Some(p) => PathBuf::from(p),
        None => super::common::ati_dir(),
    }
}

fn resolve_op_path(cli_override: Option<&str>) -> String {
    cli_override.unwrap_or("op").to_string()
}

fn bootstrap_keyring(
    vault: &str,
    item: &str,
    ati_dir_override: Option<&str>,
    op_path_override: Option<&str>,
    op_token_file: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ati_dir = resolve_ati_dir(ati_dir_override);
    std::fs::create_dir_all(&ati_dir)?;

    let plaintext = fetch_keyring_json(
        vault,
        item,
        &resolve_op_path(op_path_override),
        op_token_file,
    )?;
    let key_path = ati_dir.join(".keyring-key");
    let session_key = load_or_generate_session_key(&key_path)?;
    let encrypted = encrypt_keyring(&session_key, &plaintext)?;
    let keyring_path = ati_dir.join("keyring.enc");
    atomic_write(&keyring_path, &encrypted)?;
    println!(
        "wrote {} ({} bytes) and {} (session key)",
        keyring_path.display(),
        encrypted.len(),
        key_path.display()
    );
    Ok(())
}

fn rotate_keyring(
    vault: &str,
    item: &str,
    ati_dir_override: Option<&str>,
    op_path_override: Option<&str>,
    op_token_file: Option<&str>,
    service: &str,
    no_signal: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let ati_dir = resolve_ati_dir(ati_dir_override);
    let keyring_path = ati_dir.join("keyring.enc");
    let key_path = ati_dir.join(".keyring-key");

    if !keyring_path.exists() {
        return Err(format!(
            "no existing keyring at {} — run `ati edge bootstrap-keyring` first",
            keyring_path.display()
        )
        .into());
    }
    if !key_path.exists() {
        return Err(format!(
            "no session key at {} — keyring was bootstrapped without the persistent session key. \
             Re-run `ati edge bootstrap-keyring` to regenerate it (it'll write a fresh \
             .keyring-key and re-encrypt keyring.enc with it).",
            key_path.display()
        )
        .into());
    }

    let session_key = read_persistent_key(&key_path)?;
    let plaintext = fetch_keyring_json(
        vault,
        item,
        &resolve_op_path(op_path_override),
        op_token_file,
    )?;
    let encrypted = encrypt_keyring(&session_key, &plaintext)?;
    atomic_write(&keyring_path, &encrypted)?;
    println!(
        "rotated {} ({} bytes)",
        keyring_path.display(),
        encrypted.len()
    );

    if no_signal {
        println!("--no-signal set; skipping SIGHUP to {service}");
        return Ok(());
    }

    match find_service_pid(service) {
        Ok(Some(pid)) => match send_sighup(pid) {
            Ok(()) => {
                println!("SIGHUP sent to {service} (pid {pid})");
                Ok(())
            }
            Err(e) => Err(format!("SIGHUP to {service} (pid {pid}) failed: {e}").into()),
        },
        Ok(None) => {
            // Service not running — successful rotation, but the live proxy
            // (if any) won't pick up the new secret until it restarts. Print
            // a warning, don't fail: the operator might be rotating before
            // first start.
            eprintln!("warning: service '{service}' has no active MainPID — proxy will read the new keyring on next start");
            Ok(())
        }
        Err(e) => Err(format!("could not query service '{service}': {e}").into()),
    }
}

// --- 1Password integration -----------------------------------------------

/// Shape returned by `op item get --format json` for the items we care about.
/// We only need fields with labels + values; the rest is ignored.
#[derive(Debug, Deserialize)]
struct OpItem {
    fields: Vec<OpField>,
}

#[derive(Debug, Deserialize)]
struct OpField {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

/// Run `op item get --vault <vault> <item> --format json`, parse the response,
/// and return a JSON object suitable for `Keyring::encrypt_keyring`. The
/// returned bytes are the pretty-printed JSON shape:
///
/// ```json
/// { "browserbase_api_key": "...", "sandbox_signing_shared_secret": "..." }
/// ```
///
/// (Same shape that `Keyring::load_credentials` parses.)
fn fetch_keyring_json(
    vault: &str,
    item: &str,
    op_path: &str,
    op_token_file: Option<&str>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Optionally read the 1Password service-account token from a file and
    // pass it to `op` via env var. Used by the systemd timer with
    // LoadCredential=: the file lives at $CREDENTIALS_DIRECTORY/op-token
    // and we read its CONTENTS into the env var op expects (NOT the path —
    // Greptile P1 on PR #97 flagged the previous `%d/op-token`
    // substitution as setting the env var to a path string).
    let mut cmd = Command::new(op_path);
    if let Some(path) = op_token_file {
        let token = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read --op-token-file '{path}': {e}"))?;
        cmd.env("OP_SERVICE_ACCOUNT_TOKEN", token.trim());
    }
    let output = cmd
        .arg("item")
        .arg("get")
        .arg("--vault")
        .arg(vault)
        .arg(item)
        .arg("--format")
        .arg("json")
        .output()
        .map_err(|e| format!("failed to spawn '{op_path}': {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "`{op_path} item get` failed (exit {}): {}",
            output.status, stderr
        )
        .into());
    }
    let parsed: OpItem = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("could not parse `op` output as JSON: {e}"))?;
    let map: std::collections::BTreeMap<String, String> = parsed
        .fields
        .into_iter()
        .filter_map(|f| match (f.label, f.value) {
            (Some(l), Some(v)) if !l.is_empty() => Some((l, v)),
            _ => None,
        })
        .collect();
    if map.is_empty() {
        return Err(format!(
            "1Password item '{item}' in vault '{vault}' has no labeled fields with values"
        )
        .into());
    }
    Ok(serde_json::to_vec_pretty(&map)?)
}

// --- Persistent session key handling -------------------------------------

/// Load the persistent session key from `<ati_dir>/.keyring-key`. If absent,
/// generate one and write it before returning. Format mirrors
/// `Keyring::load_local`: base64-encoded 32 bytes, single line, mode 0600.
fn load_or_generate_session_key(path: &Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if path.exists() {
        return read_persistent_key(path);
    }
    let key = generate_session_key();
    let encoded = base64::engine::general_purpose::STANDARD.encode(key);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    atomic_write(path, encoded.as_bytes())?;
    set_mode_0600(path)?;
    Ok(key)
}

fn read_persistent_key(path: &Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(raw.trim())?;
    if decoded.len() != 32 {
        return Err(format!(
            "session key at {} is not 32 bytes after base64-decode (got {})",
            path.display(),
            decoded.len()
        )
        .into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

// --- Filesystem helpers --------------------------------------------------

/// Atomic write: tempfile in same dir + `rename(2)`. Required for keyring
/// rotation — a half-written file is worse than a stale one.
pub(crate) fn atomic_write(target: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    let parent = target
        .parent()
        .ok_or_else(|| std::io::Error::other(format!("no parent dir for {}", target.display())))?;
    std::fs::create_dir_all(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    use std::io::Write;
    tmp.write_all(contents)?;
    tmp.as_file().sync_all()?;
    tmp.persist(target)
        .map_err(|e: tempfile::PersistError| e.error)?;
    Ok(())
}

#[cfg(unix)]
fn set_mode_0600(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}
#[cfg(not(unix))]
fn set_mode_0600(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

// --- systemd / signal helpers --------------------------------------------

/// Return the MainPID of a running systemd service, or `Ok(None)` if it's
/// inactive. Uses `systemctl show -p MainPID --value <service>` which prints
/// just the number (or `0` for inactive services).
fn find_service_pid(service: &str) -> Result<Option<i32>, std::io::Error> {
    let out = Command::new("systemctl")
        .arg("show")
        .arg("-p")
        .arg("MainPID")
        .arg("--value")
        .arg(service)
        .output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "systemctl exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let pid_str = String::from_utf8_lossy(&out.stdout);
    let pid_str = pid_str.trim();
    let pid: i32 = pid_str
        .parse()
        .map_err(|_| std::io::Error::other(format!("unparseable MainPID '{pid_str}'")))?;
    if pid == 0 {
        Ok(None)
    } else {
        Ok(Some(pid))
    }
}

#[cfg(unix)]
fn send_sighup(pid: i32) -> Result<(), std::io::Error> {
    // Defense-in-depth (Greptile P3 nit on PR #97): refuse to deliver SIGHUP
    // to anything but a normal positive PID. systemd returns 0 for inactive
    // services (handled by find_service_pid → Ok(None) before we reach here),
    // -1 is the broadcast-to-all sentinel for libc::kill, and other small
    // negative values target whole process groups. None of those are
    // appropriate for "signal the running ati proxy."
    if pid <= 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing to signal PID {pid}: only positive PIDs allowed"),
        ));
    }
    let ret = unsafe { libc::kill(pid, libc::SIGHUP) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
#[cfg(not(unix))]
fn send_sighup(_pid: i32) -> Result<(), std::io::Error> {
    Err(std::io::Error::other(
        "SIGHUP delivery requires a unix platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn atomic_write_creates_then_replaces_in_place() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("file");
        atomic_write(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        atomic_write(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
    }

    #[test]
    fn atomic_write_creates_parent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nested/deeper/file");
        atomic_write(&path, b"x").unwrap();
        assert!(path.exists());
    }

    #[test]
    fn load_or_generate_creates_key_when_missing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".keyring-key");
        let key = load_or_generate_session_key(&path).unwrap();
        assert_eq!(key.len(), 32);
        assert!(path.exists());
        // Second call returns the SAME key (load, don't regenerate).
        let key2 = load_or_generate_session_key(&path).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn read_persistent_key_rejects_wrong_length() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("k");
        atomic_write(
            &path,
            base64::engine::general_purpose::STANDARD
                .encode([0u8; 16])
                .as_bytes(),
        )
        .unwrap();
        let err = read_persistent_key(&path).unwrap_err();
        assert!(err.to_string().contains("not 32 bytes"));
    }

    /// Build a fake `op` shim that echoes a known JSON payload. Used by the
    /// fetch / bootstrap tests so we don't depend on the real 1Password CLI.
    ///
    /// Each shim gets a unique filename so callers can stand up multiple
    /// shims in the same TempDir (e.g. v1 + v2 in the rotate test).
    fn fake_op_shim(dir: &Path, payload: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("op-shim-{n}"));
        let script = format!("#!/bin/sh\ncat <<'EOF'\n{payload}\nEOF\n");
        std::fs::write(&path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    }

    #[test]
    fn fetch_keyring_json_parses_op_output() {
        let dir = TempDir::new().unwrap();
        let payload = r#"{
            "fields": [
                { "label": "browserbase_api_key", "value": "bb_live_X" },
                { "label": "sandbox_signing_shared_secret", "value": "deadbeef" },
                { "label": "ignored_no_value" },
                { "value": "ignored_no_label" }
            ]
        }"#;
        let op = fake_op_shim(dir.path(), payload);
        let bytes = fetch_keyring_json("Vault", "Item", op.to_str().unwrap(), None).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.get("browserbase_api_key").unwrap(), "bb_live_X");
        assert_eq!(
            obj.get("sandbox_signing_shared_secret").unwrap(),
            "deadbeef"
        );
        assert_eq!(
            obj.len(),
            2,
            "fields without label or value must be dropped"
        );
    }

    #[test]
    fn fetch_keyring_json_errors_on_empty_item() {
        let dir = TempDir::new().unwrap();
        let payload = r#"{ "fields": [] }"#;
        let op = fake_op_shim(dir.path(), payload);
        let err = fetch_keyring_json("V", "I", op.to_str().unwrap(), None).unwrap_err();
        assert!(err.to_string().contains("no labeled fields"));
    }

    #[test]
    fn fetch_keyring_json_errors_on_op_failure() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("op-failing");
        std::fs::write(&path, "#!/bin/sh\necho 'auth required' 1>&2\nexit 1\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let err = fetch_keyring_json("V", "I", path.to_str().unwrap(), None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("op"), "{msg}");
    }

    #[test]
    fn bootstrap_keyring_writes_decryptable_blob() {
        // End-to-end: shim → bootstrap_keyring → Keyring::load_local should
        // round-trip the credentials.
        let dir = TempDir::new().unwrap();
        let payload = r#"{
            "fields": [
                { "label": "alpha", "value": "1" },
                { "label": "beta",  "value": "2" }
            ]
        }"#;
        let op = fake_op_shim(dir.path(), payload);
        bootstrap_keyring(
            "Vault",
            "Item",
            Some(dir.path().to_str().unwrap()),
            Some(op.to_str().unwrap()),
            None,
        )
        .unwrap();
        // Decrypt the way the proxy would on cold start.
        let keyring_path = dir.path().join("keyring.enc");
        assert!(keyring_path.exists());
        let kr = crate::core::keyring::Keyring::load_local(&keyring_path, dir.path()).unwrap();
        assert_eq!(kr.get("alpha"), Some("1"));
        assert_eq!(kr.get("beta"), Some("2"));
    }

    #[test]
    fn rotate_keyring_replaces_in_place_and_returns_old_key() {
        // After bootstrap + rotate, the same .keyring-key file is reused (no
        // session-key churn — that would break a running proxy that already
        // mlock'd the old key). The encrypted blob, however, changes.
        let dir = TempDir::new().unwrap();
        let op_v1 = fake_op_shim(dir.path(), r#"{"fields":[{"label":"k","value":"v1"}]}"#);
        bootstrap_keyring(
            "V",
            "I",
            Some(dir.path().to_str().unwrap()),
            Some(op_v1.to_str().unwrap()),
            None,
        )
        .unwrap();
        let key_before = std::fs::read(dir.path().join(".keyring-key")).unwrap();
        let enc_before = std::fs::read(dir.path().join("keyring.enc")).unwrap();

        let op_v2 = fake_op_shim(dir.path(), r#"{"fields":[{"label":"k","value":"v2"}]}"#);
        rotate_keyring(
            "V",
            "I",
            Some(dir.path().to_str().unwrap()),
            Some(op_v2.to_str().unwrap()),
            None,
            "ati", // service name — won't exist on test host
            true,  // --no-signal: don't try to SIGHUP a nonexistent service
        )
        .unwrap();
        let key_after = std::fs::read(dir.path().join(".keyring-key")).unwrap();
        let enc_after = std::fs::read(dir.path().join("keyring.enc")).unwrap();
        assert_eq!(
            key_before, key_after,
            "session key must NOT churn on rotation"
        );
        assert_ne!(
            enc_before, enc_after,
            "encrypted blob must change after rotation"
        );

        // Decrypt and confirm new value.
        let kr =
            crate::core::keyring::Keyring::load_local(&dir.path().join("keyring.enc"), dir.path())
                .unwrap();
        assert_eq!(kr.get("k"), Some("v2"));
    }

    #[test]
    fn send_sighup_refuses_zero_or_negative_pid() {
        // Greptile P3 nit on PR #97. systemd's `MainPID=0` for inactive
        // services is already handled in find_service_pid; this is
        // defense-in-depth against any other path that calls send_sighup
        // directly with a bogus PID.
        #[cfg(unix)]
        {
            for bad in &[0, -1, -42] {
                let err = send_sighup(*bad).expect_err("must reject non-positive PID");
                assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
                let msg = err.to_string();
                assert!(msg.contains(&bad.to_string()), "got: {msg}");
            }
        }
    }

    #[test]
    fn rotate_keyring_errors_when_no_bootstrap() {
        let dir = TempDir::new().unwrap();
        let op = fake_op_shim(dir.path(), r#"{"fields":[{"label":"k","value":"v"}]}"#);
        let err = rotate_keyring(
            "V",
            "I",
            Some(dir.path().to_str().unwrap()),
            Some(op.to_str().unwrap()),
            None,
            "ati",
            true,
        )
        .unwrap_err();
        assert!(err.to_string().contains("bootstrap-keyring"));
    }
}
