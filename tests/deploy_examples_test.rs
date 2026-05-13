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
    // Sanity check: thin TLS terminator → 127.0.0.1:8080 on the vhost
    // block. If we accidentally publish a Caddyfile with path-based
    // routing or header-rewriting, that's a regression to the
    // parcha-proxy era we're explicitly leaving behind.
    let caddyfile =
        std::fs::read_to_string(examples_dir().join("caddy/Caddyfile")).expect("Caddyfile present");
    assert!(
        caddyfile.contains("reverse_proxy 127.0.0.1:8080"),
        "expected thin TLS terminator pattern (vhost block); got:\n{caddyfile}"
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
fn rotate_keyring_service_uses_runtime_directory_not_lock_file() {
    // Greptile review on PR #97 flagged that
    //   ConditionPathExists=!/var/lib/ati/.rotation-in-progress
    // can silently skip the unit forever if a crash leaves the lock
    // file orphaned. systemd's RuntimeDirectory= is auto-cleaned on
    // unit stop (even after a crash), so we use that instead.
    let service =
        std::fs::read_to_string(examples_dir().join("systemd/ati-rotate-keyring.service"))
            .expect("rotate-keyring service present");
    // Look for ConditionPathExists=! at the start of a line (an active
    // directive), not inside a comment.
    let has_active_cond = service
        .lines()
        .any(|l| l.trim_start().starts_with("ConditionPathExists=!"));
    assert!(
        !has_active_cond,
        "rotate-keyring service must NOT use ConditionPathExists=! \
         (silent-skip-on-orphan footgun); use RuntimeDirectory= instead. Got:\n{service}"
    );
    assert!(
        service.contains("RuntimeDirectory=ati-rotate-keyring"),
        "rotate-keyring service must use RuntimeDirectory= for crash-safe \
         lock management. Got:\n{service}"
    );
    assert!(
        !service.contains(".rotation-in-progress"),
        "no manual lockfile should remain in the unit. Got:\n{service}"
    );
}

#[test]
fn caddyfile_default_is_https_redirect_not_plain_proxy() {
    // Greptile review 3 on PR #97 (P1): the prior version of this
    // Caddyfile reverse-proxied :80 plaintext by default. Combined with
    // the recommended `--sig-verify-mode log` 24h soak window, that left
    // passthrough routes (LLM gateway, browser API, git storage) wide
    // open to anyone on the network — log mode never returns 403.
    //
    // The fix: make HTTPS redirect (308) the active :80 block, and move
    // the plain-HTTP fallback into a commented opt-in for IP-only
    // egress deployments (Daytona CIDR allowlist), with an explicit
    // requirement that those run sig-verify-mode=enforce.
    let caddyfile =
        std::fs::read_to_string(examples_dir().join("caddy/Caddyfile")).expect("Caddyfile");

    // The redirect must be the ACTIVE (uncommented) :80 directive.
    // Greptile's "documents the alternative" framing wasn't strong
    // enough — operators who copy-paste don't read comments.
    let active_lines: Vec<&str> = caddyfile
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect();
    let active = active_lines.join("\n");
    assert!(
        active.contains("redir https://{host}{uri} 308"),
        "Caddyfile :80 MUST default to a 308 HTTPS redirect, not a \
         plaintext reverse_proxy. The plain-HTTP variant lives in a \
         commented opt-in block. Got active lines:\n{active}"
    );
    assert!(
        !active.contains(":80 {\n\treverse_proxy") && !active.contains(":80 {\n    reverse_proxy"),
        "Caddyfile :80 must NOT plaintext-reverse_proxy by default. \
         Got active lines:\n{active}"
    );

    // The plain-HTTP fallback must still be DOCUMENTED (as a commented
    // block) so operators on Daytona-style IP-only egress know how to
    // opt in.
    assert!(
        caddyfile.contains("Daytona") || caddyfile.contains("IP address"),
        "Caddyfile must explain when the plain-HTTP opt-in is needed. \
         Got:\n{caddyfile}"
    );
    assert!(
        caddyfile.contains("enforce"),
        "Caddyfile plain-HTTP opt-in must require sig-verify-mode=enforce. \
         Got:\n{caddyfile}"
    );
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
