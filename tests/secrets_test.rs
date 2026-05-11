//! Integration tests for `ati::core::secrets`.
//!
//! Mirrors what a downstream caller (the future `provider_store` /
//! `resolver` in PR #91 / #92) would touch — public surface only, env-var
//! driven construction, no internal helpers.

use std::collections::HashMap;

use ati::core::secrets::{open, seal, EnvelopeBlob, Kek, LocalKek, SecretsError};
use base64::Engine as _;

fn key_b64(byte: u8) -> String {
    base64::engine::general_purpose::STANDARD.encode([byte; 32])
}

#[test]
fn env_to_seal_to_open_full_path() {
    // Operator boots the proxy with one master key.
    let mut env = HashMap::new();
    env.insert("ATI_MASTER_KEY".to_string(), key_b64(0x77));

    let kek = LocalKek::from_env_with(&env).expect("load kek");
    assert_eq!(kek.active_kek_id(), "m1");

    let plaintext = b"sk-particle-real-token-do-not-leak";
    let aad = b"particle:particle_api_key:cust_alpha";
    let blob = seal(plaintext, aad, &kek).unwrap();

    // The wire-format you'd persist:
    let _ciphertext: &[u8] = &blob.ciphertext;
    let _nonce: &[u8] = &blob.nonce;
    let _wrapped: &[u8] = &blob.wrapped_dek;
    let _kek_id: &str = &blob.kek_id;

    let opened = open(&blob, aad, &kek).unwrap();
    assert_eq!(&opened[..], &plaintext[..]);
}

#[test]
fn rotation_workflow() {
    // Pre-rotation: only m1 is loaded.
    let mut env = HashMap::new();
    env.insert("ATI_MASTER_KEY_m1".to_string(), key_b64(0x11));
    env.insert("ATI_MASTER_KEY_ACTIVE".to_string(), "m1".to_string());
    let kek_v1 = LocalKek::from_env_with(&env).unwrap();
    let blob_v1 = seal(b"old data", b"r1", &kek_v1).unwrap();
    assert_eq!(blob_v1.kek_id, "m1");

    // Rotation step: add m2, mark active.
    env.insert("ATI_MASTER_KEY_m2".to_string(), key_b64(0x22));
    env.insert("ATI_MASTER_KEY_ACTIVE".to_string(), "m2".to_string());
    let kek_post = LocalKek::from_env_with(&env).unwrap();
    assert_eq!(kek_post.active_kek_id(), "m2");

    // Pre-rotation ciphertext still decrypts under the multi-version KEK.
    let opened = open(&blob_v1, b"r1", &kek_post).unwrap();
    assert_eq!(&opened[..], b"old data");

    // New seals are tagged m2.
    let blob_v2 = seal(b"new data", b"r2", &kek_post).unwrap();
    assert_eq!(blob_v2.kek_id, "m2");
    let opened_new = open(&blob_v2, b"r2", &kek_post).unwrap();
    assert_eq!(&opened_new[..], b"new data");
}

#[test]
fn cross_row_replay_rejected() {
    // The classic envelope-encryption gotcha: an attacker who can write to
    // one row in the DB shouldn't be able to copy the ciphertext+nonce+
    // wrapped_dek triple from row A onto row B and have it decrypt to A's
    // plaintext when row B's `aad` is checked. AEAD's AAD binding prevents
    // exactly this.
    let mut env = HashMap::new();
    env.insert("ATI_MASTER_KEY".to_string(), key_b64(0xAA));
    let kek = LocalKek::from_env_with(&env).unwrap();

    let blob_row_a = seal(b"row-a-secret", b"row-a", &kek).unwrap();

    // Pretend it got copy-pasted to row B (different aad).
    let attempted = open(&blob_row_a, b"row-b", &kek);
    assert!(matches!(attempted, Err(SecretsError::OpenFailed(_))));
}

#[test]
fn unwrap_with_wrong_kek_rejected() {
    // Two operators with two different master keys. Operator A's ciphertext
    // must not decrypt under operator B's KEK.
    let mut env_a = HashMap::new();
    env_a.insert("ATI_MASTER_KEY".to_string(), key_b64(0x01));
    let kek_a = LocalKek::from_env_with(&env_a).unwrap();

    let mut env_b = HashMap::new();
    env_b.insert("ATI_MASTER_KEY".to_string(), key_b64(0x02));
    let kek_b = LocalKek::from_env_with(&env_b).unwrap();

    let blob = seal(b"A's secret", b"aad", &kek_a).unwrap();
    // Both KEKs use id "m1" by default, so unwrap finds a key, but it's
    // the wrong one — AES-KW's integrity check rejects.
    let err = open(&blob, b"aad", &kek_b).unwrap_err();
    assert!(matches!(err, SecretsError::UnwrapFailed(_)), "got: {err:?}");
}

#[test]
fn blob_struct_clone_eq_works() {
    // Sanity: EnvelopeBlob derives Clone + PartialEq, which the store layer
    // will rely on for "is this what we already have?" idempotency checks.
    let mut env = HashMap::new();
    env.insert("ATI_MASTER_KEY".to_string(), key_b64(0x55));
    let kek = LocalKek::from_env_with(&env).unwrap();
    let blob: EnvelopeBlob = seal(b"x", b"y", &kek).unwrap();
    let cloned = blob.clone();
    assert_eq!(blob, cloned);
}
