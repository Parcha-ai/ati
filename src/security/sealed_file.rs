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
    let key_path = std::env::var("ATI_KEY_FILE").unwrap_or_else(|_| DEFAULT_KEY_PATH.to_string());

    read_and_delete_key_from(Path::new(&key_path))
}

/// Read session key from a specific path, then delete the file.
///
/// Uses open-then-unlink-then-read pattern to eliminate the TOCTOU window:
/// 1. Open the file (get fd)
/// 2. Unlink the file from the filesystem (no other process can open it)
/// 3. Read contents from the fd (still valid after unlink)
pub fn read_and_delete_key_from(path: &Path) -> Result<[u8; 32], SealedFileError> {
    use std::io::Read;

    // Step 1: Open the file (get fd)
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(SealedFileError::NotFound(path.display().to_string()));
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(SealedFileError::PermissionDenied(
                path.display().to_string(),
            ));
        }
        Err(e) => return Err(SealedFileError::Io(e)),
    };

    // Step 2: Unlink the file BEFORE reading — closes the TOCTOU window.
    // After unlink, the file is invisible to other processes but our fd is still valid.
    if let Err(e) = std::fs::remove_file(path) {
        tracing::warn!(path = %path.display(), error = %e, "could not delete key file");
    }

    // Step 3: Read contents from the fd (file data persists until last fd is closed)
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    // Decode base64
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, contents.trim())?;

    // Validate length
    if decoded.len() != 32 {
        return Err(SealedFileError::InvalidKeyLength(decoded.len()));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}
