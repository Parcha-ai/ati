use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

fn ati_cmd() -> Command {
    let mut cmd = Command::cargo_bin("ati").unwrap();
    cmd.env_remove("RUST_LOG");
    cmd
}

#[test]
fn skill_fetch_in_proxy_mode_fails_cleanly_instead_of_panicking() {
    ati_cmd()
        .env("ATI_PROXY_URL", "http://127.0.0.1:9")
        .args(["skill", "fetch", "catalog"])
        .assert()
        .failure()
        .stderr(contains("Proxy request failed").or(contains("Connection refused")))
        .stderr(predicates::str::contains("Non-proxy commands should not reach here").not());
}
