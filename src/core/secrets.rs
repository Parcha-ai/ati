//! Envelope encryption for secrets-at-rest.
//!
//! Every row in `ati_provider_credentials`, `ati_oauth_tokens`, and
//! `ati_oauth_clients` (when a `client_secret` is issued) stores its plaintext
//! sealed with a **per-row data encryption key (DEK)** — a random AES-256 key
//! that was used exactly once to encrypt this one row. The DEK itself is then
//! **wrapped** (encrypted) by a master **key encryption key (KEK)** that lives
//! outside the database. Only the wrapped DEK is persisted.
//!
//! ```text
//!   plaintext  --AES-256-GCM-SIV(DEK, nonce)-->  ciphertext  +  nonce
//!         DEK  --AES-Key-Wrap-256(KEK)-------->  wrapped_dek
//!         KEK  --comes from $ATI_MASTER_KEY----- (never in DB)
//! ```
//!
//! ## Why this shape
//!
//! - **KEK rotation is cheap.** Rotating the master key requires unwrapping
//!   every row's small (40-byte) wrapped DEK with the old KEK and rewrapping
//!   with the new KEK. The (potentially large) ciphertext is never touched.
//!   A separate `rewrap` admin job handles this in batches.
//!
//! - **Compromised DB without compromised KEK is useless.** An attacker who
//!   exfiltrates `ati_*` rows sees only wrapped DEKs + ciphertexts; without
//!   the KEK they can't unwrap. The KEK lives in a Northflank-managed env var
//!   (`ATI_MASTER_KEY`), separate failure domain from PG.
//!
//! - **AES-256-GCM-SIV chosen over plain AES-256-GCM.** SIV (Synthetic IV) is
//!   misuse-resistant: nonce reuse degrades to a one-time pad equivalence
//!   instead of catastrophic key recovery. With per-row DEKs we generate a
//!   fresh DEK + nonce on every seal, so the nonce-reuse risk is essentially
//!   zero, but SIV is free belt-and-suspenders insurance.
//!
//! - **AES-Key-Wrap (RFC 3394) over GCM for key wrapping.** AES-KW is
//!   deterministic — wrapping the same DEK twice with the same KEK produces
//!   the same wrapped output. That makes idempotent rewrap-after-rotation
//!   easy to reason about. AES-KW also bakes in an integrity tag (the
//!   constant `0xA6...A6` initial value) so a tampered wrapped DEK fails
//!   unwrap loudly.
//!
//! ## Key versioning
//!
//! The KEK is identified by a short version string (`m1`, `m2`, …) carried
//! per-row in `kek_id`. New writes use the currently-active version
//! (`ATI_MASTER_KEY_ACTIVE`). Reads use the version recorded on the row —
//! both active and retired versions stay available for unwrap until a
//! background `rewrap` job has migrated every row.
//!
//! Construct a `LocalKek` from the environment:
//!
//! ```text
//!   ATI_MASTER_KEY_m1=<base64 32 bytes>   # required
//!   ATI_MASTER_KEY_m2=<base64 32 bytes>   # optional, post-rotation
//!   ATI_MASTER_KEY_ACTIVE=m1              # which version new writes use
//! ```
//!
//! For convenience a single `ATI_MASTER_KEY=<base64 32 bytes>` env var is
//! accepted at first deploy — it's loaded as version `m1` and `ATI_MASTER_KEY_ACTIVE`
//! defaults to `m1`.

use std::collections::HashMap;

use aes_gcm_siv::aead::{Aead, KeyInit as AeadKeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use aes_kw::{KeyInit as KwKeyInit, KwAes256};
use base64::Engine as _;
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;
use zeroize::Zeroizing;

/// Length of an AES-256 key (the DEK and the KEK).
const KEY_LEN: usize = 32;
/// Length of an AES-GCM-SIV nonce.
const NONCE_LEN: usize = 12;
/// Length of an AES-KW wrapped 32-byte key: input + 8-byte IV.
const WRAPPED_DEK_LEN: usize = KEY_LEN + 8;

#[derive(Debug, Error)]
pub enum SecretsError {
    #[error("secrets.config: {0}")]
    Config(String),
    #[error("secrets.key_version_not_found: '{0}' not configured")]
    KeyVersionNotFound(String),
    #[error("secrets.wrap_failed: {0}")]
    WrapFailed(String),
    #[error("secrets.unwrap_failed: {0}")]
    UnwrapFailed(String),
    #[error("secrets.seal_failed: {0}")]
    SealFailed(String),
    #[error("secrets.open_failed: {0}")]
    OpenFailed(String),
    #[error("secrets.rng: {0}")]
    Rng(String),
}

/// A versioned key-encryption-key, used to wrap per-row DEKs.
///
/// Implementations carry one or more `(kek_id -> 32-byte KEK)` mappings plus
/// a single "active" id used for new writes. Unwrap accepts any id that's
/// currently loaded — that way rotation works without a service window.
pub trait Kek: Send + Sync {
    /// The version identifier (e.g. `"m1"`) that new writes should record.
    fn active_kek_id(&self) -> &str;
    /// Wrap a DEK with the active KEK. Returns the wrapped DEK bytes (40 bytes
    /// for a 32-byte DEK) and the kek_id that was used.
    fn wrap(&self, dek: &[u8; KEY_LEN]) -> Result<(Vec<u8>, String), SecretsError>;
    /// Unwrap a wrapped DEK using the KEK identified by `kek_id`. Errors with
    /// `KeyVersionNotFound` if the version isn't loaded, or `UnwrapFailed`
    /// if AES-KW's integrity check rejects the wrapped bytes.
    fn unwrap(
        &self,
        wrapped_dek: &[u8],
        kek_id: &str,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, SecretsError>;
}

/// In-process KEK derived from environment variables. The master key bytes
/// live mlock-able on the heap — see `Zeroizing` — and are zeroed on drop.
pub struct LocalKek {
    versions: HashMap<String, Zeroizing<[u8; KEY_LEN]>>,
    active: String,
}

impl std::fmt::Debug for LocalKek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material — even in debug output. List the version
        // ids we hold so operators can sanity-check "did rotation load?" but
        // give the bytes a placeholder.
        f.debug_struct("LocalKek")
            .field("active", &self.active)
            .field(
                "versions",
                &self
                    .versions
                    .keys()
                    .map(|k| (k.as_str(), "<redacted>"))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl LocalKek {
    /// Construct a KEK from a single 32-byte master key plus a chosen id.
    /// Useful for tests and for the single-version bootstrap case.
    pub fn from_bytes(active_id: impl Into<String>, key: [u8; KEY_LEN]) -> Self {
        let id = active_id.into();
        let mut versions = HashMap::new();
        versions.insert(id.clone(), Zeroizing::new(key));
        Self {
            versions,
            active: id,
        }
    }

    /// Add an additional retired (or pre-rotation) key version. Returns
    /// `self` for fluent construction.
    pub fn with_version(mut self, id: impl Into<String>, key: [u8; KEY_LEN]) -> Self {
        self.versions.insert(id.into(), Zeroizing::new(key));
        self
    }

    /// Load a KEK from process environment.
    ///
    /// Resolution rules:
    /// 1. If `ATI_MASTER_KEY_ACTIVE` is set, treat it as the active id and
    ///    load every `ATI_MASTER_KEY_<id>` env var found. Also load the
    ///    bare `ATI_MASTER_KEY` as id `m1` if present — this makes the
    ///    migration path from single-version to multi-version painless
    ///    (an operator who adds `ATI_MASTER_KEY_ACTIVE=m1` without yet
    ///    renaming the existing variable still boots cleanly).
    /// 2. Otherwise, if `ATI_MASTER_KEY` is set, load it as id `m1` and use
    ///    `m1` as the active id. (Single-version bootstrap shortcut.)
    /// 3. Otherwise, `Err(Config)` — caller decides whether DB mode is even
    ///    being requested.
    ///
    /// All key values are base64-decoded (URL-safe or standard, padding
    /// tolerated). Anything that doesn't decode to exactly 32 bytes errors
    /// loudly so a typo in NF's UI fails fast at startup, not later.
    pub fn from_env() -> Result<Self, SecretsError> {
        Self::from_env_with(&std::env::vars().collect::<HashMap<_, _>>())
    }

    /// Internal helper that accepts an explicit env map — makes tests
    /// trivial without mutating process env.
    pub fn from_env_with(env: &HashMap<String, String>) -> Result<Self, SecretsError> {
        let active_explicit = env.get("ATI_MASTER_KEY_ACTIVE").cloned();
        let single = env.get("ATI_MASTER_KEY").cloned();

        if let Some(active) = active_explicit {
            let mut versions = HashMap::new();
            let prefix = "ATI_MASTER_KEY_";

            // Honor the bare `ATI_MASTER_KEY` in multi-version mode so an
            // operator migrating from the single-key shortcut doesn't have
            // to rename the env var atomically with adding ACTIVE. Loads
            // as id "m1" — chosen to match the default the single-key
            // branch below uses, so the wrapped_dek rows from a previous
            // single-version boot stay decodable.
            if let Some(bare) = env.get("ATI_MASTER_KEY") {
                let bytes = decode_master_key(bare).map_err(|e| {
                    SecretsError::Config(format!(
                        "ATI_MASTER_KEY (bare) is not a valid 32-byte base64 key: {e}"
                    ))
                })?;
                versions.insert("m1".to_string(), Zeroizing::new(bytes));
            }

            for (k, v) in env {
                if let Some(id) = k.strip_prefix(prefix) {
                    if id == "ACTIVE" {
                        continue;
                    }
                    // `ATI_MASTER_KEY_<id>` is interpreted as a KEK version
                    // key. If you're seeing this error for a variable that
                    // wasn't meant to be a KEK (e.g. an unrelated
                    // ATI_MASTER_KEY_PATH set by your orchestrator), rename
                    // the variable so it doesn't collide with the
                    // `ATI_MASTER_KEY_*` namespace.
                    let bytes = decode_master_key(v).map_err(|e| {
                        SecretsError::Config(format!(
                            "{prefix}{id} is interpreted as a KEK version but \
                             could not be parsed as a 32-byte base64 key: {e} \
                             (rename the variable if it wasn't meant as a KEK)"
                        ))
                    })?;
                    versions.insert(id.to_string(), Zeroizing::new(bytes));
                }
            }

            if !versions.contains_key(&active) {
                let hint = if env.get("ATI_MASTER_KEY").is_some() && active != "m1" {
                    format!(
                        " (bare ATI_MASTER_KEY is loaded as id 'm1'; \
                         either set ATI_MASTER_KEY_ACTIVE=m1 or also \
                         set ATI_MASTER_KEY_{active})"
                    )
                } else {
                    String::new()
                };
                return Err(SecretsError::Config(format!(
                    "ATI_MASTER_KEY_ACTIVE='{active}' but no ATI_MASTER_KEY_{active} env var loaded{hint}"
                )));
            }
            Ok(Self { versions, active })
        } else if let Some(value) = single {
            let bytes = decode_master_key(&value).map_err(|e| {
                SecretsError::Config(format!(
                    "ATI_MASTER_KEY is not a valid 32-byte base64 key: {e}"
                ))
            })?;
            Ok(Self::from_bytes("m1", bytes))
        } else {
            Err(SecretsError::Config(
                "no ATI_MASTER_KEY or ATI_MASTER_KEY_<id> env var set".into(),
            ))
        }
    }
}

fn decode_master_key(value: &str) -> Result<[u8; KEY_LEN], String> {
    let trimmed = value.trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
        .map_err(|e| format!("base64 decode: {e}"))?;
    if decoded.len() != KEY_LEN {
        return Err(format!(
            "expected 32 bytes after base64 decode, got {}",
            decoded.len()
        ));
    }
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&decoded);
    Ok(out)
}

impl Kek for LocalKek {
    fn active_kek_id(&self) -> &str {
        &self.active
    }

    fn wrap(&self, dek: &[u8; KEY_LEN]) -> Result<(Vec<u8>, String), SecretsError> {
        let kek_bytes: &[u8; KEY_LEN] = self
            .versions
            .get(&self.active)
            .map(|z| &**z)
            .ok_or_else(|| SecretsError::KeyVersionNotFound(self.active.clone()))?;
        let kw = KwAes256::new(kek_bytes.into());
        let mut buf = [0u8; WRAPPED_DEK_LEN];
        kw.wrap_key(dek.as_slice(), &mut buf)
            .map_err(|e| SecretsError::WrapFailed(format!("aes-kw: {e:?}")))?;
        Ok((buf.to_vec(), self.active.clone()))
    }

    fn unwrap(
        &self,
        wrapped_dek: &[u8],
        kek_id: &str,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, SecretsError> {
        let kek_bytes: &[u8; KEY_LEN] = self
            .versions
            .get(kek_id)
            .map(|z| &**z)
            .ok_or_else(|| SecretsError::KeyVersionNotFound(kek_id.to_string()))?;
        if wrapped_dek.len() != WRAPPED_DEK_LEN {
            return Err(SecretsError::UnwrapFailed(format!(
                "wrapped_dek wrong length: {} (expected {})",
                wrapped_dek.len(),
                WRAPPED_DEK_LEN
            )));
        }
        let kw = KwAes256::new(kek_bytes.into());
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        kw.unwrap_key(wrapped_dek, out.as_mut())
            .map_err(|e| SecretsError::UnwrapFailed(format!("aes-kw: {e:?}")))?;
        Ok(out)
    }
}

/// A persisted envelope: ciphertext, nonce, the wrapped DEK that decrypts it,
/// and the KEK version id needed to unwrap the DEK.
///
/// Stored in PG across four columns (`ciphertext BYTEA`, `nonce BYTEA`,
/// `wrapped_dek BYTEA`, `kek_id TEXT`) so future schema changes can carry
/// additional metadata without touching the encrypted payload.
#[derive(Clone, PartialEq, Eq)]
pub struct EnvelopeBlob {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
    pub wrapped_dek: Vec<u8>,
    pub kek_id: String,
}

impl std::fmt::Debug for EnvelopeBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the byte payloads. `wrapped_dek` in particular is the most
        // sensitive field — an attacker holding it plus a leaked KEK can
        // recover plaintext. Print sizes and `kek_id` only so traces still
        // tell you "did the data make it to the database" without leaking
        // anything that could be exfiltrated by a misconfigured logger.
        f.debug_struct("EnvelopeBlob")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("nonce_len", &self.nonce.len())
            .field("wrapped_dek_len", &self.wrapped_dek.len())
            .field("kek_id", &self.kek_id)
            .finish()
    }
}

/// Seal `plaintext` into an `EnvelopeBlob`.
///
/// Generates a fresh per-row DEK + nonce from `ring::SystemRandom`, encrypts
/// with AES-256-GCM-SIV (12-byte nonce, 16-byte tag appended to ciphertext),
/// wraps the DEK with the active KEK via AES-KW, and bundles everything.
///
/// `aad` is associated data — bound into the AEAD tag so a tampered or
/// row-swapped payload fails integrity check. Callers should pass a stable
/// row identifier (`provider_name:key_name:customer_id` or similar) so a
/// ciphertext copied between rows fails to decrypt.
pub fn seal(plaintext: &[u8], aad: &[u8], kek: &dyn Kek) -> Result<EnvelopeBlob, SecretsError> {
    let rng = SystemRandom::new();

    // 1. Generate the per-row DEK.
    let mut dek_bytes = Zeroizing::new([0u8; KEY_LEN]);
    rng.fill(dek_bytes.as_mut())
        .map_err(|e| SecretsError::Rng(format!("dek fill: {e}")))?;

    // 2. Generate the nonce.
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|e| SecretsError::Rng(format!("nonce fill: {e}")))?;

    // 3. Encrypt the plaintext under the DEK.
    let dek_ref: &[u8; KEY_LEN] = &dek_bytes;
    let cipher = Aes256GcmSiv::new(dek_ref.into());
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), payload)
        .map_err(|e| SecretsError::SealFailed(format!("aes-gcm-siv: {e}")))?;

    // 4. Wrap the DEK with the active KEK.
    let (wrapped_dek, kek_id) = kek.wrap(&dek_bytes)?;

    Ok(EnvelopeBlob {
        ciphertext,
        nonce: nonce_bytes,
        wrapped_dek,
        kek_id,
    })
}

/// Open an `EnvelopeBlob` back to plaintext.
///
/// `aad` must exactly match what was passed at seal time, or the AEAD tag
/// verification will fail and we return `OpenFailed`.
pub fn open(
    blob: &EnvelopeBlob,
    aad: &[u8],
    kek: &dyn Kek,
) -> Result<Zeroizing<Vec<u8>>, SecretsError> {
    // 1. Unwrap the DEK.
    let dek = kek.unwrap(&blob.wrapped_dek, &blob.kek_id)?;

    // 2. Decrypt.
    let dek_ref: &[u8; KEY_LEN] = &dek;
    let cipher = Aes256GcmSiv::new(dek_ref.into());
    let payload = Payload {
        msg: &blob.ciphertext,
        aad,
    };
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&blob.nonce), payload)
        .map_err(|e| SecretsError::OpenFailed(format!("aes-gcm-siv: {e}")))?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_key(byte: u8) -> [u8; KEY_LEN] {
        [byte; KEY_LEN]
    }

    #[test]
    fn roundtrip_basic() {
        let kek = LocalKek::from_bytes("m1", fixed_key(0x42));
        let plaintext = b"sk_live_abc123_super_secret_token";
        let aad = b"particle:particle_api_key:";

        let blob = seal(plaintext, aad, &kek).unwrap();
        assert_eq!(blob.kek_id, "m1");
        assert_eq!(blob.nonce.len(), NONCE_LEN);
        assert_eq!(blob.wrapped_dek.len(), WRAPPED_DEK_LEN);
        assert_ne!(&blob.ciphertext[..], &plaintext[..], "should be encrypted");

        let opened = open(&blob, aad, &kek).unwrap();
        assert_eq!(&opened[..], &plaintext[..]);
    }

    #[test]
    fn fresh_seal_uses_fresh_dek_and_nonce() {
        let kek = LocalKek::from_bytes("m1", fixed_key(0x42));
        let plaintext = b"same plaintext both times";
        let aad = b"same aad too";

        let blob_a = seal(plaintext, aad, &kek).unwrap();
        let blob_b = seal(plaintext, aad, &kek).unwrap();

        // Per-row DEK and per-seal nonce both randomized → ciphertexts and
        // wrapped_deks must both diverge for two identical inputs.
        assert_ne!(blob_a.ciphertext, blob_b.ciphertext);
        assert_ne!(blob_a.wrapped_dek, blob_b.wrapped_dek);
        assert_ne!(blob_a.nonce, blob_b.nonce);
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let kek = LocalKek::from_bytes("m1", fixed_key(0x42));
        let mut blob = seal(b"hello", b"aad", &kek).unwrap();
        blob.ciphertext[0] ^= 0x01;
        let err = open(&blob, b"aad", &kek).unwrap_err();
        assert!(matches!(err, SecretsError::OpenFailed(_)), "got: {err:?}");
    }

    #[test]
    fn tampered_wrapped_dek_rejected() {
        let kek = LocalKek::from_bytes("m1", fixed_key(0x42));
        let mut blob = seal(b"hello", b"aad", &kek).unwrap();
        blob.wrapped_dek[0] ^= 0x01;
        let err = open(&blob, b"aad", &kek).unwrap_err();
        // AES-KW's RFC-3394 integrity check rejects modified wrapped key.
        assert!(matches!(err, SecretsError::UnwrapFailed(_)), "got: {err:?}");
    }

    #[test]
    fn aad_mismatch_rejected() {
        let kek = LocalKek::from_bytes("m1", fixed_key(0x42));
        let blob = seal(b"hello", b"row-1", &kek).unwrap();
        // Pretend a ciphertext got copy-pasted onto a different row.
        let err = open(&blob, b"row-2", &kek).unwrap_err();
        assert!(matches!(err, SecretsError::OpenFailed(_)), "got: {err:?}");
    }

    #[test]
    fn unwrap_with_retired_version_still_works() {
        // Build a KEK with two versions; active = m2, but seal under m1.
        let kek_m1_only = LocalKek::from_bytes("m1", fixed_key(0x11));
        let blob = seal(b"old data", b"aad", &kek_m1_only).unwrap();
        assert_eq!(blob.kek_id, "m1");

        // Now construct a multi-version KEK: m2 active, m1 retired but loaded.
        let multi = LocalKek::from_bytes("m2", fixed_key(0x22)).with_version("m1", fixed_key(0x11));
        let opened = open(&blob, b"aad", &multi).unwrap();
        assert_eq!(&opened[..], b"old data");
    }

    #[test]
    fn unknown_kek_id_errors() {
        let kek = LocalKek::from_bytes("m1", fixed_key(0x42));
        let mut blob = seal(b"hello", b"aad", &kek).unwrap();
        blob.kek_id = "m99".to_string();
        let err = open(&blob, b"aad", &kek).unwrap_err();
        assert!(
            matches!(err, SecretsError::KeyVersionNotFound(_)),
            "got: {err:?}"
        );
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let kek = LocalKek::from_bytes("m1", fixed_key(0x42));
        let blob = seal(b"", b"aad", &kek).unwrap();
        let opened = open(&blob, b"aad", &kek).unwrap();
        assert!(opened.is_empty());
    }

    #[test]
    fn large_plaintext_roundtrips() {
        let kek = LocalKek::from_bytes("m1", fixed_key(0x42));
        let plaintext = vec![0xab; 64 * 1024];
        let blob = seal(&plaintext, b"aad", &kek).unwrap();
        let opened = open(&blob, b"aad", &kek).unwrap();
        assert_eq!(opened.len(), plaintext.len());
        assert_eq!(&opened[..], &plaintext[..]);
    }

    #[test]
    fn from_env_single_master_key_shortcut() {
        let mut env = HashMap::new();
        let raw = [0xCD; KEY_LEN];
        env.insert(
            "ATI_MASTER_KEY".into(),
            base64::engine::general_purpose::STANDARD.encode(raw),
        );
        let kek = LocalKek::from_env_with(&env).unwrap();
        assert_eq!(kek.active_kek_id(), "m1");
        // Roundtrip to confirm key bytes loaded correctly.
        let blob = seal(b"x", b"", &kek).unwrap();
        assert_eq!(&open(&blob, b"", &kek).unwrap()[..], b"x");
    }

    #[test]
    fn from_env_multi_version() {
        let mut env = HashMap::new();
        env.insert(
            "ATI_MASTER_KEY_m1".into(),
            base64::engine::general_purpose::STANDARD.encode([0x11; KEY_LEN]),
        );
        env.insert(
            "ATI_MASTER_KEY_m2".into(),
            base64::engine::general_purpose::STANDARD.encode([0x22; KEY_LEN]),
        );
        env.insert("ATI_MASTER_KEY_ACTIVE".into(), "m2".into());
        let kek = LocalKek::from_env_with(&env).unwrap();
        assert_eq!(kek.active_kek_id(), "m2");

        // New seals are tagged m2.
        let blob = seal(b"x", b"", &kek).unwrap();
        assert_eq!(blob.kek_id, "m2");

        // But m1 is still usable for reads (simulate by manually building
        // a blob under m1 and confirming open works).
        let kek_m1_only = LocalKek::from_bytes("m1", [0x11; KEY_LEN]);
        let blob_m1 = seal(b"old", b"", &kek_m1_only).unwrap();
        let opened = open(&blob_m1, b"", &kek).unwrap();
        assert_eq!(&opened[..], b"old");
    }

    #[test]
    fn from_env_active_without_matching_key_errors() {
        let mut env = HashMap::new();
        env.insert("ATI_MASTER_KEY_ACTIVE".into(), "m9".into());
        let err = LocalKek::from_env_with(&env).unwrap_err();
        assert!(matches!(err, SecretsError::Config(_)));
    }

    #[test]
    fn from_env_missing_errors() {
        let env = HashMap::new();
        let err = LocalKek::from_env_with(&env).unwrap_err();
        assert!(matches!(err, SecretsError::Config(_)));
    }

    #[test]
    fn from_env_bad_base64_errors() {
        let mut env = HashMap::new();
        env.insert("ATI_MASTER_KEY".into(), "not-valid-base64!!!".into());
        let err = LocalKek::from_env_with(&env).unwrap_err();
        assert!(matches!(err, SecretsError::Config(_)));
    }

    #[test]
    fn from_env_wrong_length_errors() {
        let mut env = HashMap::new();
        env.insert(
            "ATI_MASTER_KEY".into(),
            base64::engine::general_purpose::STANDARD.encode([0; 16]),
        );
        let err = LocalKek::from_env_with(&env).unwrap_err();
        assert!(matches!(err, SecretsError::Config(_)));
    }

    #[test]
    fn url_safe_base64_accepted() {
        // URL-safe base64 has `-` and `_` instead of `+` and `/`.
        // Build a key that contains bytes which produce those characters.
        let raw: [u8; KEY_LEN] = [
            0xfb, 0xff, 0xee, 0xfb, 0xff, 0xee, 0xfb, 0xff, 0xee, 0xfb, 0xff, 0xee, 0xfb, 0xff,
            0xee, 0xfb, 0xff, 0xee, 0xfb, 0xff, 0xee, 0xfb, 0xff, 0xee, 0xfb, 0xff, 0xee, 0xfb,
            0xff, 0xee, 0xfb, 0xff,
        ];
        let encoded_url = base64::engine::general_purpose::URL_SAFE.encode(raw);
        assert!(
            encoded_url.contains('-') || encoded_url.contains('_'),
            "test setup: expected URL-safe encoding to differ from standard"
        );
        let mut env = HashMap::new();
        env.insert("ATI_MASTER_KEY".into(), encoded_url);
        LocalKek::from_env_with(&env).expect("URL-safe base64 should be accepted");
    }

    // --- Greptile PR #91 follow-ups ----------------------------------------

    #[test]
    fn bare_master_key_honored_in_multi_version_mode() {
        // Operator is mid-migration from single-version to multi-version:
        // they've added ATI_MASTER_KEY_ACTIVE=m1 but haven't renamed the
        // existing ATI_MASTER_KEY yet. Booting should not fail; the bare
        // key gets adopted as id "m1" so prior wrapped_dek rows still
        // decode.
        let mut env = HashMap::new();
        env.insert(
            "ATI_MASTER_KEY".into(),
            base64::engine::general_purpose::STANDARD.encode([0x11; KEY_LEN]),
        );
        env.insert("ATI_MASTER_KEY_ACTIVE".into(), "m1".into());
        let kek = LocalKek::from_env_with(&env).expect("bare key should be picked up");
        assert_eq!(kek.active_kek_id(), "m1");

        // The bare key bytes must actually be what 'm1' resolves to —
        // round-trip through seal/open to prove it.
        let blob = seal(b"hello", b"aad", &kek).unwrap();
        let opened = open(&blob, b"aad", &kek).unwrap();
        assert_eq!(&opened[..], b"hello");
    }

    #[test]
    fn bare_master_key_overridden_by_explicit_m1_in_multi_version() {
        // If both ATI_MASTER_KEY (bare) and ATI_MASTER_KEY_m1 are set,
        // the explicit version wins. This is the "clean migration done"
        // state — bare key was left in place but the explicit value is
        // the source of truth.
        let mut env = HashMap::new();
        env.insert(
            "ATI_MASTER_KEY".into(),
            base64::engine::general_purpose::STANDARD.encode([0xAA; KEY_LEN]),
        );
        env.insert(
            "ATI_MASTER_KEY_m1".into(),
            base64::engine::general_purpose::STANDARD.encode([0xBB; KEY_LEN]),
        );
        env.insert("ATI_MASTER_KEY_ACTIVE".into(), "m1".into());
        let kek = LocalKek::from_env_with(&env).unwrap();

        // Seal with the resolved kek, then decode with a single-version
        // KEK that only knows the [0xBB; 32] bytes — should succeed.
        let blob = seal(b"x", b"y", &kek).unwrap();
        let bb_only = LocalKek::from_bytes("m1", [0xBB; KEY_LEN]);
        assert_eq!(
            &open(&blob, b"y", &bb_only).unwrap()[..],
            b"x",
            "explicit ATI_MASTER_KEY_m1 must shadow bare ATI_MASTER_KEY"
        );
    }

    #[test]
    fn unrelated_prefix_var_error_mentions_kek_interpretation() {
        // If an orchestrator injects ATI_MASTER_KEY_PATH=/some/path the
        // parser will try to base64-decode "/some/path" and fail. The
        // error message must make it obvious that the variable is being
        // interpreted as a KEK version so the operator knows to rename
        // it rather than wonder why their PATH is being base64-decoded.
        let mut env = HashMap::new();
        env.insert(
            "ATI_MASTER_KEY_m1".into(),
            base64::engine::general_purpose::STANDARD.encode([0x11; KEY_LEN]),
        );
        env.insert("ATI_MASTER_KEY_ACTIVE".into(), "m1".into());
        env.insert("ATI_MASTER_KEY_PATH".into(), "/some/path".into());

        let err = LocalKek::from_env_with(&env).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("KEK version"),
            "error message should mention 'KEK version' so operators understand why the variable was parsed; got: {msg}"
        );
        assert!(
            msg.contains("ATI_MASTER_KEY_PATH"),
            "error should name the offending variable; got: {msg}"
        );
    }

    #[test]
    fn active_without_matching_key_hints_at_bare_when_present() {
        // Edge case of the migration: operator sets ATI_MASTER_KEY_ACTIVE=m2
        // intending to introduce a new version, but the bare key is still
        // m1. The error message should remind them that bare is m1 so they
        // don't waste time wondering where their key went.
        let mut env = HashMap::new();
        env.insert(
            "ATI_MASTER_KEY".into(),
            base64::engine::general_purpose::STANDARD.encode([0x11; KEY_LEN]),
        );
        env.insert("ATI_MASTER_KEY_ACTIVE".into(), "m2".into());
        let err = LocalKek::from_env_with(&env).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("m1") && msg.contains("ATI_MASTER_KEY_m2"),
            "error should hint that bare ATI_MASTER_KEY is m1; got: {msg}"
        );
    }

    #[test]
    fn envelope_blob_debug_redacts_payloads() {
        // The wrapped_dek field is the most sensitive thing in the blob;
        // it must never appear in {:?} output (or any tracing span that
        // grabs the struct). LocalKek already redacts; mirror here.
        let kek = LocalKek::from_bytes("m1", [0x42; KEY_LEN]);
        let blob = seal(b"the quick brown fox", b"aad", &kek).unwrap();
        let dbg = format!("{:?}", blob);

        // Lengths and kek_id are fine to surface; raw byte contents
        // (ciphertext / wrapped_dek as hex or arrays) are not.
        assert!(dbg.contains("EnvelopeBlob"), "got: {dbg}");
        assert!(dbg.contains("kek_id"), "got: {dbg}");
        assert!(dbg.contains("wrapped_dek_len"), "got: {dbg}");
        // Sanity: blob has real bytes, so if Debug were derived, we'd see
        // numeric byte arrays. The redacted impl never prints them.
        assert!(
            !dbg.contains(&format!("{:?}", blob.wrapped_dek)),
            "wrapped_dek bytes leaked into Debug output: {dbg}"
        );
        assert!(
            !dbg.contains(&format!("{:?}", blob.ciphertext)),
            "ciphertext bytes leaked into Debug output: {dbg}"
        );
    }
}
