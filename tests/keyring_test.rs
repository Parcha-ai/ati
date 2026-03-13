use std::collections::HashMap;
use std::io::Write;
use tempfile::TempDir;

// We test via the binary's lib-like API by importing the crate
// Since ati is a binary, we test the core functions directly

#[test]
fn test_encrypt_decrypt_roundtrip() {
    // Generate a session key
    let session_key = generate_session_key();

    // Create a test keyring
    let mut keys = HashMap::new();
    keys.insert("parallel_api_key".to_string(), "pk_test_12345".to_string());
    keys.insert("epo_api_key".to_string(), "epo_secret_67890".to_string());
    keys.insert(
        "cerebras_api_key".to_string(),
        "csk-abc123def456".to_string(),
    );

    let plaintext = serde_json::to_vec(&keys).unwrap();

    // Encrypt
    let encrypted = encrypt_keyring(&session_key, &plaintext);
    assert!(encrypted.is_ok(), "Encryption should succeed");
    let encrypted = encrypted.unwrap();

    // Encrypted data should be different from plaintext
    assert_ne!(encrypted, plaintext);
    // Should be larger (nonce + tag overhead)
    assert!(encrypted.len() > plaintext.len());

    // Decrypt
    let decrypted = decrypt_keyring(&session_key, &encrypted);
    assert!(decrypted.is_ok(), "Decryption should succeed");
    let decrypted = decrypted.unwrap();

    // Should match original
    assert_eq!(decrypted, plaintext);

    // Parse back to HashMap
    let recovered: HashMap<String, String> = serde_json::from_slice(&decrypted).unwrap();
    assert_eq!(recovered.get("parallel_api_key").unwrap(), "pk_test_12345");
    assert_eq!(recovered.get("epo_api_key").unwrap(), "epo_secret_67890");
}

#[test]
fn test_wrong_key_fails_decryption() {
    let key1 = generate_session_key();
    let key2 = generate_session_key();

    let plaintext = br#"{"test_key":"secret_value"}"#;
    let encrypted = encrypt_keyring(&key1, plaintext).unwrap();

    // Decrypting with wrong key should fail
    let result = decrypt_keyring(&key2, &encrypted);
    assert!(result.is_err(), "Decryption with wrong key should fail");
}

#[test]
fn test_tampered_ciphertext_fails() {
    let session_key = generate_session_key();
    let plaintext = br#"{"key":"value"}"#;

    let mut encrypted = encrypt_keyring(&session_key, plaintext).unwrap();

    // Tamper with the ciphertext (flip a byte after the nonce)
    if encrypted.len() > 15 {
        encrypted[14] ^= 0xFF;
    }

    let result = decrypt_keyring(&session_key, &encrypted);
    assert!(
        result.is_err(),
        "Tampered ciphertext should fail authentication"
    );
}

#[test]
fn test_keyring_file_roundtrip() {
    let dir = TempDir::new().unwrap();
    let session_key = generate_session_key();

    // Create keyring
    let keys: HashMap<String, String> = [("api_key".into(), "secret123".into())].into();
    let plaintext = serde_json::to_vec(&keys).unwrap();
    let encrypted = encrypt_keyring(&session_key, &plaintext).unwrap();

    // Write keyring.enc
    let keyring_path = dir.path().join("keyring.enc");
    std::fs::write(&keyring_path, &encrypted).unwrap();

    // Write session key as base64
    let key_path = dir.path().join(".key");
    let key_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &session_key);
    std::fs::write(&key_path, &key_b64).unwrap();

    // Verify key file exists
    assert!(key_path.exists());

    // Read and delete key (simulating sealed_file behavior)
    let contents = std::fs::read_to_string(&key_path).unwrap();
    std::fs::remove_file(&key_path).unwrap();

    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, contents.trim())
            .unwrap();

    assert_eq!(decoded.len(), 32);
    assert!(!key_path.exists(), "Key file should be deleted");

    // Decrypt keyring
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&decoded);
    let encrypted_data = std::fs::read(&keyring_path).unwrap();
    let decrypted = decrypt_keyring(&key_array, &encrypted_data).unwrap();
    let recovered: HashMap<String, String> = serde_json::from_slice(&decrypted).unwrap();
    assert_eq!(recovered.get("api_key").unwrap(), "secret123");
}

#[test]
fn test_too_small_encrypted_data() {
    let key = generate_session_key();
    // Data smaller than nonce + tag
    let result = decrypt_keyring(&key, &[0u8; 10]);
    assert!(result.is_err());
}

#[test]
fn test_empty_keyring() {
    let session_key = generate_session_key();
    let plaintext = br#"{}"#;
    let encrypted = encrypt_keyring(&session_key, plaintext).unwrap();
    let decrypted = decrypt_keyring(&session_key, &encrypted).unwrap();
    let recovered: HashMap<String, String> = serde_json::from_slice(&decrypted).unwrap();
    assert!(recovered.is_empty());
}

// --- Helper functions (duplicated from the binary since we can't import) ---

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, Aes256Gcm, Nonce,
};
use base64;
use rand::RngCore;

const NONCE_SIZE: usize = 12;

fn generate_session_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

fn encrypt_keyring(
    session_key: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = Aes256Gcm::new_from_slice(session_key)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| format!("{e}"))?;

    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decrypt_keyring(
    session_key: &[u8; 32],
    encrypted: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if encrypted.len() < NONCE_SIZE + 16 {
        return Err("Too small".into());
    }
    let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(session_key)?;
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {e}").into())
}
