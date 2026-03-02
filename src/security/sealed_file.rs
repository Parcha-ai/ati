use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SealedFileError {
    #[error("Key file not found at {0} — was it already consumed?")]
    NotFound(String),
    #[error("Permission denied reading key file: {0}")]
    PermissionDenied(String),
    #[error("Invalid base64 in key file: {0}")]
    InvalidBase64(#[from] base64::DecodeError),
    #[error("Invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Default path for the session key sealed file
pub const DEFAULT_KEY_PATH: &str = "/run/ati/.key";

/// Read the session key from a sealed file, then immediately delete the file.
///
/// The key file contains a base64-encoded 256-bit (32 byte) session key.
/// After reading, the file is unlink()'d so it can never be read again.
///
/// Also checks ATI_KEY_FILE env var as an override (for testing).
pub fn read_and_delete_key() -> Result<[u8; 32], SealedFileError> {
    let key_path = std::env::var("ATI_KEY_FILE")
        .unwrap_or_else(|_| DEFAULT_KEY_PATH.to_string());

    read_and_delete_key_from(Path::new(&key_path))
}

/// Read session key from a specific path, then delete the file.
pub fn read_and_delete_key_from(path: &Path) -> Result<[u8; 32], SealedFileError> {
    // Read the file
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(SealedFileError::NotFound(path.display().to_string()));
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(SealedFileError::PermissionDenied(path.display().to_string()));
        }
        Err(e) => return Err(SealedFileError::Io(e)),
    };

    // Immediately delete the file
    if let Err(e) = std::fs::remove_file(path) {
        // Log warning but don't fail — we already have the key
        eprintln!("Warning: could not delete key file {}: {e}", path.display());
    }

    // Decode base64
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        contents.trim(),
    )?;

    // Validate length
    if decoded.len() != 32 {
        return Err(SealedFileError::InvalidKeyLength(decoded.len()));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}
