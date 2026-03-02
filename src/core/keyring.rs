use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, AeadCore, Nonce,
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
            eprintln!("Warning: {warning}");
        }
        let _ = memory::madvise_dontdump(decrypted.as_ptr(), decrypted.len());

        // Parse JSON into HashMap
        let keys: HashMap<String, String> = serde_json::from_slice(&decrypted)?;

        Ok(Keyring {
            keys,
            _raw_json: decrypted,
        })
    }

    /// Load from an already-known session key (for testing or orchestrator use).
    pub fn load_with_key(keyring_path: &Path, session_key: &[u8; 32]) -> Result<Self, KeyringError> {
        let encrypted = std::fs::read(keyring_path)?;
        let decrypted = decrypt_keyring(session_key, &encrypted)?;

        if let Err(warning) = memory::mlock(decrypted.as_ptr(), decrypted.len()) {
            eprintln!("Warning: {warning}");
        }
        let _ = memory::madvise_dontdump(decrypted.as_ptr(), decrypted.len());

        let keys: HashMap<String, String> = serde_json::from_slice(&decrypted)?;

        Ok(Keyring {
            keys,
            _raw_json: decrypted,
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

    /// Create an empty keyring (for tools with auth_type = none).
    pub fn empty() -> Self {
        Keyring {
            keys: HashMap::new(),
            _raw_json: Vec::new(),
        }
    }
}

impl Drop for Keyring {
    fn drop(&mut self) {
        // Zeroize all key values
        for value in self.keys.values_mut() {
            value.zeroize();
        }
        // Zeroize raw JSON bytes
        self._raw_json.zeroize();
        // Unlock memory
        if !self._raw_json.is_empty() {
            memory::munlock(self._raw_json.as_ptr(), self._raw_json.len());
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

    let cipher = Aes256Gcm::new_from_slice(session_key)
        .map_err(|_| KeyringError::DecryptionFailed)?;

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| KeyringError::DecryptionFailed)
}

/// Encrypt a keyring (for keygen tooling / orchestrator).
/// Returns the encrypted blob: [12-byte nonce][ciphertext+tag]
pub fn encrypt_keyring(session_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, KeyringError> {
    let cipher = Aes256Gcm::new_from_slice(session_key)
        .map_err(|_| KeyringError::DecryptionFailed)?;

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
}
