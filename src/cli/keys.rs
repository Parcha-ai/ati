use std::collections::BTreeMap;
use std::path::Path;

use super::common;

/// Execute: ati keys <subcommand>
pub fn execute(subcmd: &crate::KeysCommands) -> Result<(), Box<dyn std::error::Error>> {
    match subcmd {
        crate::KeysCommands::Set { name, value } => set_key(name, value),
        crate::KeysCommands::List => list_keys(),
        crate::KeysCommands::Remove { name } => remove_key(name),
    }
}

fn credentials_path() -> std::path::PathBuf {
    common::ati_dir().join("credentials")
}

fn load_credentials(path: &Path) -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let data = std::fs::read_to_string(path)?;
    let map: BTreeMap<String, String> = serde_json::from_str(&data)?;
    Ok(map)
}

fn save_credentials(
    path: &Path,
    keys: &BTreeMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(keys)?;
    std::fs::write(path, json)?;

    // Set file permissions to 0600 (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }

    Ok(())
}

fn set_key(name: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = credentials_path();
    let mut keys = load_credentials(&path)?;
    keys.insert(name.to_string(), value.to_string());
    save_credentials(&path, &keys)?;
    eprintln!("Saved {name}");
    Ok(())
}

fn list_keys() -> Result<(), Box<dyn std::error::Error>> {
    let path = credentials_path();
    let keys = load_credentials(&path)?;

    if keys.is_empty() {
        println!("No keys stored. Run `ati keys set <name> <value>` to add one.");
        return Ok(());
    }

    for (name, value) in &keys {
        println!("{:<30} {}", name, mask(value));
    }
    Ok(())
}

fn remove_key(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = credentials_path();
    let mut keys = load_credentials(&path)?;

    if keys.remove(name).is_none() {
        return Err(format!("Key '{name}' not found.").into());
    }

    save_credentials(&path, &keys)?;
    eprintln!("Removed {name}");
    Ok(())
}

/// Mask a secret value: show first 4 and last 4 characters with ... in between.
/// For short values (<=10 chars), show just the first 2 and last 2.
fn mask(value: &str) -> String {
    let len = value.len();
    if len <= 4 {
        return "*".repeat(len);
    }
    if len <= 10 {
        format!("{}...{}", &value[..2], &value[len - 2..])
    } else {
        format!("{}...{}", &value[..4], &value[len - 4..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_long() {
        assert_eq!(mask("sk-1234567890abcdef"), "sk-1...cdef");
    }

    #[test]
    fn test_mask_medium() {
        assert_eq!(mask("secret1234"), "se...34");
    }

    #[test]
    fn test_mask_short() {
        assert_eq!(mask("abc"), "***");
    }

    #[test]
    fn test_credentials_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("credentials");

        let mut keys = BTreeMap::new();
        keys.insert("api_key".to_string(), "secret123".to_string());
        keys.insert("other_key".to_string(), "other_val".to_string());

        save_credentials(&path, &keys).unwrap();

        let loaded = load_credentials(&path).unwrap();
        assert_eq!(loaded.get("api_key").unwrap(), "secret123");
        assert_eq!(loaded.get("other_key").unwrap(), "other_val");

        // Check file permissions on unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }
}
