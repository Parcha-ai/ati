//! Lightweight check that the shipped `deploy/examples/vm/` templates are
//! syntactically valid — manifests parse via the real loader, the Caddyfile
//! is plausible, and the systemd units have the directives ATI needs.
//!
//! These tests are intentionally narrow. We don't run Caddy, haproxy,
//! verdaccio, or systemd here — that's the operator's job. We just refuse
//! to ship broken templates that wouldn't compile/parse at all.

use ati::core::manifest::ManifestRegistry;
use std::path::PathBuf;
use tempfile::TempDir;

/// Path to `deploy/examples/vm/` relative to the workspace root.
fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("deploy")
        .join("examples")
        .join("vm")
}

#[test]
fn example_manifests_parse() {
    // Copy every .toml in deploy/examples/vm/manifests/ into a tempdir
    // (so the loader doesn't pick up other manifests next to the test)
    // and load via the real ManifestRegistry.
    let src_dir = examples_dir().join("manifests");
    assert!(src_dir.is_dir(), "{} missing", src_dir.display());

    let tmp = TempDir::new().unwrap();
    let dest_dir = tmp.path().join("manifests");
    std::fs::create_dir_all(&dest_dir).unwrap();
    for entry in std::fs::read_dir(&src_dir).unwrap() {
        let entry = entry.unwrap();
        if entry.path().extension().and_then(|e| e.to_str()) == Some("toml") {
            let target = dest_dir.join(entry.file_name());
            std::fs::copy(entry.path(), target).unwrap();
        }
    }

    let registry = ManifestRegistry::load(&dest_dir).expect("example manifests must load");
    // file_manager virtual provider is always present + our example.
    let names: Vec<_> = registry
        .list_providers()
        .iter()
        .map(|p| p.name.clone())
        .collect();
    assert!(
        names.iter().any(|n| n == "example-service"),
        "expected example-service provider; got {names:?}"
    );
}

#[test]
fn caddyfile_template_has_terminator_pattern() {
    // Sanity check: thin TLS terminator → 127.0.0.1:8080. If we
    // accidentally publish a Caddyfile with path-based routing or
    // header-rewriting, that's a regression to the parcha-proxy era
    // we're explicitly leaving behind.
    let caddyfile =
        std::fs::read_to_string(examples_dir().join("caddy/Caddyfile")).expect("Caddyfile present");
    assert!(
        caddyfile.contains("reverse_proxy 127.0.0.1:8080"),
        "expected thin TLS terminator pattern; got:\n{caddyfile}"
    );
    // Negative: no header_up, no path-based handlers, no forward_auth —
    // those are the ATI-internal concerns we DON'T want Caddy to do.
    for forbidden in &["header_up ", "forward_auth", "handle /"] {
        assert!(
            !caddyfile.contains(*forbidden),
            "Caddyfile must not contain `{forbidden}` (those moved into ATI itself); got:\n{caddyfile}"
        );
    }
}

#[test]
fn systemd_unit_runs_proxy_with_passthrough_enabled() {
    let unit = std::fs::read_to_string(examples_dir().join("systemd/ati.service"))
        .expect("ati.service present");
    for required in &[
        "ati proxy",
        "--enable-passthrough",
        "--sig-verify-mode log",
        "--ati-dir /var/lib/ati",
        "User=ati",
    ] {
        assert!(
            unit.contains(*required),
            "ati.service must contain `{required}`; got:\n{unit}"
        );
    }
}

#[test]
fn rotate_keyring_timer_and_service_pair_up() {
    let service =
        std::fs::read_to_string(examples_dir().join("systemd/ati-rotate-keyring.service"))
            .expect("rotate-keyring service present");
    let timer = std::fs::read_to_string(examples_dir().join("systemd/ati-rotate-keyring.timer"))
        .expect("rotate-keyring timer present");
    assert!(service.contains("ati edge rotate-keyring"));
    assert!(timer.contains("OnCalendar"));

    // Greptile P1 regression guard on PR #97. The original unit set
    //   Environment=OP_SERVICE_ACCOUNT_TOKEN=%d/op-token
    // which substitutes a FILE PATH into the env var, not the token's
    // contents. op authentication would fail on every rotation. The fix
    // is to pass `--op-token-file %d/op-token` so the binary reads the
    // file at runtime and exports the value into op's env explicitly.
    assert!(
        service.contains("--op-token-file %d/op-token"),
        "rotate-keyring service must use --op-token-file with the credentials \
         directory path (NOT Environment=OP_SERVICE_ACCOUNT_TOKEN=%d/op-token, \
         which would set the env var to a file path string); got:\n{service}"
    );
    assert!(
        !service.contains("Environment=OP_SERVICE_ACCOUNT_TOKEN="),
        "rotate-keyring service must NOT set OP_SERVICE_ACCOUNT_TOKEN via \
         Environment= — that would forward the literal `%d/op-token` path \
         instead of the token value; got:\n{service}"
    );
    assert!(
        service.contains("LoadCredential=op-token:"),
        "rotate-keyring service must still use LoadCredential= so systemd \
         restricts the token file's visibility to this unit; got:\n{service}"
    );
}

#[test]
fn readme_targets_manifests_to_ati_dir_manifests() {
    // Greptile P1 regression guard on PR #97. The original README told
    // operators to copy manifests to /etc/ati/manifests/, but the proxy
    // resolves them as `<ati_dir>/manifests/` = /var/lib/ati/manifests/.
    //
    // The fixed README does still MENTION /etc/ati/manifests/ once, in a
    // "NOT this path" warning. We allow that single mention but require
    // that the canonical /var/lib/ati/manifests/ appears more often.
    let readme = std::fs::read_to_string(examples_dir().join("README.md")).expect("README present");
    let canonical_count = readme.matches("/var/lib/ati/manifests").count();
    let wrong_count = readme.matches("/etc/ati/manifests").count();
    assert!(
        canonical_count >= 2,
        "README must point manifests at /var/lib/ati/manifests/ in setup AND ops sections (found {canonical_count} mention(s))"
    );
    assert!(
        wrong_count <= 1,
        "README mentions /etc/ati/manifests/ {wrong_count} times; only a single \"NOT this path\" \
         warning is allowed — operators must not be told to copy manifests there"
    );
}

#[test]
fn ati_service_comment_documents_correct_manifest_dir() {
    let unit = std::fs::read_to_string(examples_dir().join("systemd/ati.service"))
        .expect("ati.service present");
    assert!(
        !unit.contains("/etc/ati/manifests"),
        "ati.service must not reference /etc/ati/manifests; got:\n{unit}"
    );
    assert!(
        unit.contains("/var/lib/ati"),
        "ati.service must reference /var/lib/ati as the ATI dir; got:\n{unit}"
    );
}

#[test]
fn haproxy_example_is_l4_redis_only() {
    let cfg = std::fs::read_to_string(examples_dir().join("haproxy/haproxy.cfg.example"))
        .expect("haproxy");
    assert!(cfg.contains("mode tcp"), "Redis fan-out must be L4");
    assert!(
        cfg.contains("ssl verify none sni"),
        "TLS upstream with SNI required"
    );
}

#[test]
fn verdaccio_example_listens_on_loopback() {
    let cfg =
        std::fs::read_to_string(examples_dir().join("verdaccio/config.yaml.example")).expect("vd");
    assert!(
        cfg.contains("127.0.0.1:4873"),
        "verdaccio must listen on loopback only — public exposure happens through ATI passthrough"
    );
}
