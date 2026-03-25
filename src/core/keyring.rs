use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, Aes256Gcm, Nonce,
};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroize;

use crate::security::{memory, sealed_file};

#[derive(Error, Debug)]
pub enum KeyringError {
    #[error("Failed to read session key: {0}")]
    SealedFile(#[from] sealed_file::SealedFileError),
    #[error("Failed to read keyring file: {0}")]
    Io(#[from] std::io::Error),
    #[error("Decryption failed — wrong key or corrupted keyring")]
    DecryptionFailed,
    #[error("Invalid keyring format — expected JSON object")]
    InvalidFormat(#[from] serde_json::Error),
    #[error("Keyring file too small (need at least nonce + tag)")]
    TooSmall,
}

/// Holds decrypted API keys in memory. Keys are mlock'd and zeroized on drop.
pub struct Keyring {
    keys: HashMap<String, String>,
    /// Raw bytes pointer and length for mlock/munlock
    _raw_json: Vec<u8>,
    /// Whether keys were loaded from a sealed source (one-shot key).
    /// When true, credential files should be wiped after each use.
    pub ephemeral: bool,
}

impl Keyring {
    /// Load the keyring: read sealed key file, decrypt keyring.enc, mlock memory.
    ///
    /// The session key file is deleted immediately after reading.
    pub fn load(keyring_path: &Path) -> Result<Self, KeyringError> {
        // Read and delete the session key
        let session_key = sealed_file::read_and_delete_key()?;

        // Read encrypted keyring
        let encrypted = std::fs::read(keyring_path)?;

        // Decrypt
        let decrypted = decrypt_keyring(&session_key, &encrypted)?;

        // mlock the decrypted bytes (best-effort)
        if let Err(warning) = memory::mlock(decrypted.as_ptr(), decrypted.len()) {
            tracing::warn!("{warning}");
        }
        let _ = memory::madvise_dontdump(decrypted.as_ptr(), decrypted.len());

        // Parse JSON into HashMap
        let keys: HashMap<String, String> = serde_json::from_slice(&decrypted)?;

        Ok(Keyring {
            keys,
            _raw_json: decrypted,
            ephemeral: true,
        })
    }

    /// Load from an already-known session key (for testing or orchestrator use).
    pub fn load_with_key(
        keyring_path: &Path,
        session_key: &[u8; 32],
    ) -> Result<Self, KeyringError> {
        let encrypted = std::fs::read(keyring_path)?;
        let decrypted = decrypt_keyring(session_key, &encrypted)?;

        if let Err(warning) = memory::mlock(decrypted.as_ptr(), decrypted.len()) {
            tracing::warn!("{warning}");
        }
        let _ = memory::madvise_dontdump(decrypted.as_ptr(), decrypted.len());

        let keys: HashMap<String, String> = serde_json::from_slice(&decrypted)?;

        Ok(Keyring {
            keys,
            _raw_json: decrypted,
            ephemeral: true,
        })
    }

    /// Get a key by name (e.g. "parallel_api_key").
    pub fn get(&self, key_name: &str) -> Option<&str> {
        self.keys.get(key_name).map(|s| s.as_str())
    }

    /// Check if the keyring contains a specific key.
    pub fn contains(&self, key_name: &str) -> bool {
        self.keys.contains_key(key_name)
    }

    /// List all key names (not values).
    pub fn key_names(&self) -> Vec<&str> {
        self.keys.keys().map(|s| s.as_str()).collect()
    }

    /// Load from a plaintext credentials file (JSON object: {"key_name": "value", ...}).
    ///
    /// Used in local mode where `~/.ati/credentials` stores keys as plaintext JSON
    /// with 0600 permissions (same approach as AWS CLI, gh, Docker, Stripe).
    pub fn load_credentials(path: &Path) -> Result<Self, KeyringError> {
        let data = std::fs::read(path)?;
        let keys: HashMap<String, String> = serde_json::from_slice(&data)?;
        Ok(Keyring {
            keys,
            _raw_json: Vec::new(),
            ephemeral: false,
        })
    }

    /// Load keyring.enc using a persistent key stored alongside the ATI directory.
    ///
    /// Looks for `<ati_dir>/.keyring-key` (base64-encoded 32-byte key).
    /// Unlike the sealed key in `/run/ati/.key`, this key is NOT deleted after reading —
    /// it's for proxy servers with persistent storage.
    pub fn load_local(keyring_path: &Path, ati_dir: &Path) -> Result<Self, KeyringError> {
        let persistent_key_path = ati_dir.join(".keyring-key");

        let contents = std::fs::read_to_string(&persistent_key_path).map_err(KeyringError::Io)?;

        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, contents.trim())
                .map_err(|_| KeyringError::DecryptionFailed)?;

        if decoded.len() != 32 {
            return Err(KeyringError::DecryptionFailed);
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);

        let mut kr = Self::load_with_key(keyring_path, &key)?;
        kr.ephemeral = false;
        Ok(kr)
    }

    /// Create a keyring from environment variables with `ATI_KEY_` prefix.
    ///
    /// Scans all env vars matching `ATI_KEY_*`, strips the prefix, lowercases the name.
    /// Example: `ATI_KEY_FINNHUB_API_KEY=abc123` → key name `finnhub_api_key`.
    pub fn from_env() -> Self {
        let mut keys = HashMap::new();
        for (name, value) in std::env::vars() {
            if let Some(key_name) = name.strip_prefix("ATI_KEY_") {
                if !value.is_empty() {
                    keys.insert(key_name.to_lowercase(), value);
                }
            }
        }
        Keyring {
            keys,
            _raw_json: Vec::new(),
            ephemeral: false,
        }
    }

    /// Create an empty keyring (for tools with auth_type = none).
    pub fn empty() -> Self {
        Keyring {
            keys: HashMap::new(),
            _raw_json: Vec::new(),
            ephemeral: false,
        }
    }

    /// Merge another keyring's keys into this one (other's keys take precedence).
    pub fn merge(&mut self, other: &Keyring) {
        for (k, v) in &other.keys {
            self.keys.insert(k.clone(), v.clone());
        }
    }

    /// Number of keys in the keyring.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the keyring has no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl Drop for Keyring {
    fn drop(&mut self) {
        // Zeroize all key values
        for value in self.keys.values_mut() {
            value.zeroize();
        }
        // Save ptr/len before zeroizing — Vec::zeroize() sets len to 0,
        // which would cause the is_empty() check to skip munlock.
        let ptr = self._raw_json.as_ptr();
        let len = self._raw_json.len();
        // Zeroize raw JSON bytes
        self._raw_json.zeroize();
        // Unlock memory (using saved len, not post-zeroize len)
        if len > 0 {
            memory::munlock(ptr, len);
        }
    }
}

// --- Encryption / Decryption ---

/// AES-256-GCM nonce size (96 bits = 12 bytes)
const NONCE_SIZE: usize = 12;

/// Decrypt a keyring blob. Format: [12-byte nonce][ciphertext+tag]
fn decrypt_keyring(session_key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>, KeyringError> {
    if encrypted.len() < NONCE_SIZE + 16 {
        // Minimum: nonce (12) + GCM tag (16)
        return Err(KeyringError::TooSmall);
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher =
        Aes256Gcm::new_from_slice(session_key).map_err(|_| KeyringError::DecryptionFailed)?;

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| KeyringError::DecryptionFailed)
}

/// Encrypt a keyring (for keygen tooling / orchestrator).
/// Returns the encrypted blob: [12-byte nonce][ciphertext+tag]
pub fn encrypt_keyring(session_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, KeyringError> {
    let cipher =
        Aes256Gcm::new_from_slice(session_key).map_err(|_| KeyringError::DecryptionFailed)?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| KeyringError::DecryptionFailed)?;

    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Generate a random 256-bit session key.
pub fn generate_session_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    use rand::RngCore;
    OsRng.fill_bytes(&mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let session_key = generate_session_key();
        let plaintext = br#"{"parallel_api_key":"test123","epo_api_key":"test456"}"#;

        let encrypted = encrypt_keyring(&session_key, plaintext).unwrap();
        let decrypted = decrypt_keyring(&session_key, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = generate_session_key();
        let key2 = generate_session_key();
        let plaintext = br#"{"key":"value"}"#;

        let encrypted = encrypt_keyring(&key1, plaintext).unwrap();
        let result = decrypt_keyring(&key2, &encrypted);

        assert!(result.is_err());
    }

    #[test]
    fn test_too_small_fails() {
        let key = generate_session_key();
        let result = decrypt_keyring(&key, &[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_credentials() {
        let dir = tempfile::TempDir::new().unwrap();
        let creds_path = dir.path().join("credentials");
        std::fs::write(&creds_path, r#"{"my_api_key":"secret123","other":"val"}"#).unwrap();

        let kr = Keyring::load_credentials(&creds_path).unwrap();
        assert_eq!(kr.get("my_api_key"), Some("secret123"));
        assert_eq!(kr.get("other"), Some("val"));
        assert_eq!(kr.len(), 2);
        assert!(!kr.is_empty());
    }

    #[test]
    fn test_load_credentials_empty() {
        let dir = tempfile::TempDir::new().unwrap();
        let creds_path = dir.path().join("credentials");
        std::fs::write(&creds_path, "{}").unwrap();

        let kr = Keyring::load_credentials(&creds_path).unwrap();
        assert_eq!(kr.len(), 0);
        assert!(kr.is_empty());
    }

    #[test]
    fn test_from_env_ati_key_prefix() {
        // Set some ATI_KEY_ env vars for the test
        std::env::set_var("ATI_KEY_TEST_API_KEY", "test_value_123");
        std::env::set_var("ATI_KEY_ANOTHER_KEY", "another_val");

        let kr = Keyring::from_env();
        assert_eq!(kr.get("test_api_key"), Some("test_value_123"));
        assert_eq!(kr.get("another_key"), Some("another_val"));

        // Clean up
        std::env::remove_var("ATI_KEY_TEST_API_KEY");
        std::env::remove_var("ATI_KEY_ANOTHER_KEY");
    }

    #[test]
    fn test_merge() {
        let dir = tempfile::TempDir::new().unwrap();
        let creds1 = dir.path().join("c1");
        let creds2 = dir.path().join("c2");
        std::fs::write(&creds1, r#"{"a":"1","b":"2"}"#).unwrap();
        std::fs::write(&creds2, r#"{"b":"overridden","c":"3"}"#).unwrap();

        let mut kr1 = Keyring::load_credentials(&creds1).unwrap();
        let kr2 = Keyring::load_credentials(&creds2).unwrap();
        kr1.merge(&kr2);

        assert_eq!(kr1.get("a"), Some("1"));
        assert_eq!(kr1.get("b"), Some("overridden"));
        assert_eq!(kr1.get("c"), Some("3"));
        assert_eq!(kr1.len(), 3);
    }
}
