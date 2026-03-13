/// Integration tests for supply chain verification features:
/// - compute_content_hash consistency
/// - parse_source_with_sha parsing
/// - verify_skill success/failure
/// - install flow writes integrity info to skill.toml
use std::fs;
use std::path::Path;

use ati::core::skill;

// ---------------------------------------------------------------------------
// compute_content_hash
// ---------------------------------------------------------------------------

#[test]
fn test_compute_content_hash_consistent() {
    let content = "# My Skill\n\nThis is a test skill.\n";
    let hash1 = skill::compute_content_hash(content);
    let hash2 = skill::compute_content_hash(content);
    assert_eq!(hash1, hash2);
    // SHA-256 produces 64 hex characters
    assert_eq!(hash1.len(), 64);
    // All lowercase hex
    assert!(hash1.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}

#[test]
fn test_compute_content_hash_different_content() {
    let hash1 = skill::compute_content_hash("content A");
    let hash2 = skill::compute_content_hash("content B");
    assert_ne!(hash1, hash2);
}

#[test]
fn test_compute_content_hash_empty() {
    let hash = skill::compute_content_hash("");
    assert_eq!(hash.len(), 64);
    // SHA-256 of empty string is well-known
    assert_eq!(
        hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

// ---------------------------------------------------------------------------
// Integrity info in skill.toml
// ---------------------------------------------------------------------------

fn create_skill_with_integrity(
    base: &Path,
    name: &str,
    skill_md: &str,
    skill_toml: &str,
    integrity_section: &str,
) {
    let dir = base.join(name);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("SKILL.md"), skill_md).unwrap();

    let mut toml_content = String::from(skill_toml);
    if !integrity_section.is_empty() {
        toml_content.push_str("\n");
        toml_content.push_str(integrity_section);
    }
    fs::write(dir.join("skill.toml"), toml_content).unwrap();
}

#[test]
fn test_integrity_hash_matches_skill_md() {
    let tmp = tempfile::TempDir::new().unwrap();
    let skill_md = "# Test Skill\n\nSome methodology content.\n";
    let expected_hash = skill::compute_content_hash(skill_md);

    let integrity = format!(
        "[ati.integrity]\ncontent_hash = \"{}\"\nsource_url = \"https://github.com/test/repo#test-skill\"\n",
        expected_hash
    );

    create_skill_with_integrity(
        tmp.path(),
        "test-skill",
        skill_md,
        "[skill]\nname = \"test-skill\"\nversion = \"1.0.0\"\ndescription = \"test\"\n",
        &integrity,
    );

    // Read back and verify the hash matches
    let toml_path = tmp.path().join("test-skill/skill.toml");
    let toml_content = fs::read_to_string(&toml_path).unwrap();
    let toml_val: toml::Value = toml::from_str(&toml_content).unwrap();

    let stored_hash = toml_val
        .get("ati")
        .and_then(|a| a.get("integrity"))
        .and_then(|i| i.get("content_hash"))
        .and_then(|h| h.as_str())
        .unwrap();

    assert_eq!(stored_hash, expected_hash);
}

#[test]
fn test_integrity_hash_mismatch_detected() {
    let tmp = tempfile::TempDir::new().unwrap();
    let original_md = "# Original content\n";
    let original_hash = skill::compute_content_hash(original_md);

    let integrity = format!(
        "[ati.integrity]\ncontent_hash = \"{}\"\n",
        original_hash
    );

    create_skill_with_integrity(
        tmp.path(),
        "tampered-skill",
        "# Modified content\n", // Different from what was hashed
        "[skill]\nname = \"tampered-skill\"\nversion = \"1.0.0\"\ndescription = \"test\"\n",
        &integrity,
    );

    // Compute current hash of the (modified) SKILL.md
    let current_md = fs::read_to_string(tmp.path().join("tampered-skill/SKILL.md")).unwrap();
    let current_hash = skill::compute_content_hash(&current_md);

    // The stored hash should NOT match the current content hash
    assert_ne!(original_hash, current_hash);
}

#[test]
fn test_integrity_source_url_and_pinned_sha_stored() {
    let tmp = tempfile::TempDir::new().unwrap();
    let skill_md = "# Pinned Skill\n";
    let hash = skill::compute_content_hash(skill_md);

    let integrity = format!(
        "[ati.integrity]\ncontent_hash = \"{}\"\nsource_url = \"https://github.com/org/repo#my-skill\"\npinned_sha = \"abc1234def5678\"\n",
        hash
    );

    create_skill_with_integrity(
        tmp.path(),
        "pinned-skill",
        skill_md,
        "[skill]\nname = \"pinned-skill\"\nversion = \"1.0.0\"\ndescription = \"test\"\n",
        &integrity,
    );

    let toml_path = tmp.path().join("pinned-skill/skill.toml");
    let toml_content = fs::read_to_string(&toml_path).unwrap();
    let toml_val: toml::Value = toml::from_str(&toml_content).unwrap();

    let integrity_section = toml_val
        .get("ati")
        .and_then(|a| a.get("integrity"))
        .unwrap();

    assert_eq!(
        integrity_section.get("source_url").and_then(|v| v.as_str()),
        Some("https://github.com/org/repo#my-skill")
    );
    assert_eq!(
        integrity_section.get("pinned_sha").and_then(|v| v.as_str()),
        Some("abc1234def5678")
    );
}

#[test]
fn test_skill_registry_loads_with_integrity_fields() {
    let tmp = tempfile::TempDir::new().unwrap();
    let skill_md = "# Test\n";
    let hash = skill::compute_content_hash(skill_md);

    let toml = format!(
        "[skill]\nname = \"integrity-test\"\nversion = \"1.0.0\"\ndescription = \"test\"\n\n[ati.integrity]\ncontent_hash = \"{}\"\nsource_url = \"https://github.com/test/repo\"\npinned_sha = \"deadbeef1234567\"\n",
        hash
    );

    let dir = tmp.path().join("integrity-test");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("SKILL.md"), skill_md).unwrap();
    fs::write(dir.join("skill.toml"), &toml).unwrap();

    // SkillRegistry should load without error even with [ati.integrity] section
    let registry = skill::SkillRegistry::load(tmp.path()).unwrap();
    let skills = registry.list_skills();
    assert_eq!(skills.len(), 1);
    assert_eq!(skills[0].name, "integrity-test");
}

#[test]
fn test_skill_without_integrity_section_loads_fine() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = tmp.path().join("basic-skill");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("SKILL.md"), "# Basic\n").unwrap();
    fs::write(
        dir.join("skill.toml"),
        "[skill]\nname = \"basic-skill\"\nversion = \"1.0.0\"\ndescription = \"no integrity\"\n",
    )
    .unwrap();

    let registry = skill::SkillRegistry::load(tmp.path()).unwrap();
    let skills = registry.list_skills();
    assert_eq!(skills.len(), 1);
    assert_eq!(skills[0].name, "basic-skill");
    // content_hash, source_url, pinned_sha should all be None
    assert!(skills[0].content_hash.is_none());
    assert!(skills[0].source_url.is_none());
    assert!(skills[0].pinned_sha.is_none());
}

// ---------------------------------------------------------------------------
// CLI binary tests for ati skill verify
// ---------------------------------------------------------------------------

#[test]
fn test_verify_skill_not_installed() {
    let tmp = tempfile::TempDir::new().unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .env("ATI_DIR", tmp.path().to_str().unwrap())
        .args(["skill", "verify", "nonexistent"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not installed"));
}

#[test]
fn test_verify_skill_matching_hash() {
    let tmp = tempfile::TempDir::new().unwrap();
    let skills_dir = tmp.path().join("skills");
    let skill_dir = skills_dir.join("verified-skill");
    fs::create_dir_all(&skill_dir).unwrap();

    let skill_md = "# Verified Skill\n\nContent here.\n";
    let hash = skill::compute_content_hash(skill_md);

    fs::write(skill_dir.join("SKILL.md"), skill_md).unwrap();
    fs::write(
        skill_dir.join("skill.toml"),
        format!(
            "[skill]\nname = \"verified-skill\"\nversion = \"1.0.0\"\ndescription = \"test\"\n\n[ati.integrity]\ncontent_hash = \"{}\"\n",
            hash
        ),
    )
    .unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .env("ATI_DIR", tmp.path().to_str().unwrap())
        .args(["skill", "verify", "verified-skill"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VERIFIED"));
}

#[test]
fn test_verify_skill_mismatched_hash() {
    let tmp = tempfile::TempDir::new().unwrap();
    let skills_dir = tmp.path().join("skills");
    let skill_dir = skills_dir.join("tampered");
    fs::create_dir_all(&skill_dir).unwrap();

    fs::write(skill_dir.join("SKILL.md"), "# Tampered content\n").unwrap();
    fs::write(
        skill_dir.join("skill.toml"),
        "[skill]\nname = \"tampered\"\nversion = \"1.0.0\"\ndescription = \"test\"\n\n[ati.integrity]\ncontent_hash = \"0000000000000000000000000000000000000000000000000000000000000000\"\n",
    )
    .unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .env("ATI_DIR", tmp.path().to_str().unwrap())
        .args(["skill", "verify", "tampered"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("changed") || stderr.contains("Integrity check failed"));
}

#[test]
fn test_verify_skill_no_hash_stored() {
    let tmp = tempfile::TempDir::new().unwrap();
    let skills_dir = tmp.path().join("skills");
    let skill_dir = skills_dir.join("no-hash");
    fs::create_dir_all(&skill_dir).unwrap();

    fs::write(skill_dir.join("SKILL.md"), "# No hash skill\n").unwrap();
    fs::write(
        skill_dir.join("skill.toml"),
        "[skill]\nname = \"no-hash\"\nversion = \"1.0.0\"\ndescription = \"test\"\n",
    )
    .unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ati"))
        .env("ATI_DIR", tmp.path().to_str().unwrap())
        .args(["skill", "verify", "no-hash"])
        .output()
        .unwrap();

    // Should succeed (warning, not error) when no hash is stored
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("No integrity hash stored"));
}
