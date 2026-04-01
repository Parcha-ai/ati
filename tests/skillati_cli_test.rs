use assert_cmd::Command;
use predicates::str::contains;
use std::fs;

#[test]
fn skillati_build_index_writes_manifest_file() {
    let dir = tempfile::tempdir().unwrap();
    let skill_dir = dir.path().join("demo-skill");
    fs::create_dir_all(&skill_dir).unwrap();
    fs::write(
        skill_dir.join("SKILL.md"),
        "# Demo Skill

Details",
    )
    .unwrap();
    fs::write(
        skill_dir.join("skill.toml"),
        r#"[skill]
name="demo-skill"
description="Demo"
"#,
    )
    .unwrap();

    let output = dir.path().join("catalog.json");

    Command::new(env!("CARGO_BIN_EXE_ati"))
        .args(&[
            "skill",
            "fetch",
            "build-index",
            skill_dir.to_str().unwrap(),
            "--output-file",
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(contains("\"skills\": 1"));

    let manifest = fs::read_to_string(&output).unwrap();
    assert!(manifest.contains("\"name\": \"demo-skill\""));
}

#[test]
fn skillati_build_index_prints_json_when_no_output_file() {
    let dir = tempfile::tempdir().unwrap();
    let skill_dir = dir.path().join("demo-skill-2");
    fs::create_dir_all(&skill_dir).unwrap();
    fs::write(
        skill_dir.join("SKILL.md"),
        "# Demo Skill 2

Details",
    )
    .unwrap();
    fs::write(
        skill_dir.join("skill.toml"),
        r#"[skill]
name="demo-skill-2"
description="Demo 2"
"#,
    )
    .unwrap();

    Command::new(env!("CARGO_BIN_EXE_ati"))
        .args(&["skill", "fetch", "build-index", skill_dir.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("\"name\": \"demo-skill-2\""));
}
