//! CLI subcommands for JWT token management.
//!
//! ati token keygen       — Generate an ES256 key pair
//! ati token issue        — Sign a JWT with given claims
//! ati token inspect      — Decode a JWT without verification
//! ati token validate     — Fully verify a JWT

use std::collections::HashMap;

use crate::core::jwt::{self, AtiNamespace, TokenClaims};
use crate::TokenCommands;

/// Execute: ati token <subcommand>
pub fn execute(subcmd: &TokenCommands) -> Result<(), Box<dyn std::error::Error>> {
    match subcmd {
        TokenCommands::Keygen { algorithm } => keygen(algorithm),
        TokenCommands::Issue {
            sub,
            scope,
            ttl,
            aud,
            iss,
            key,
            secret,
            rate,
        } => issue(
            sub,
            scope,
            *ttl,
            aud.as_deref(),
            iss.as_deref(),
            key.as_deref(),
            secret.as_deref(),
            rate,
        ),
        TokenCommands::Inspect { token } => inspect(token),
        TokenCommands::Validate { token, key, secret } => {
            validate(token, key.as_deref(), secret.as_deref())
        }
    }
}

fn keygen(algorithm: &str) -> Result<(), Box<dyn std::error::Error>> {
    match algorithm.to_uppercase().as_str() {
        "ES256" => {
            // Generate ES256 key pair using openssl command (ring doesn't expose key generation directly)
            // We'll use the `ring` crate's ECDSA key generation
            use base64::Engine;
            use ring::signature::KeyPair;

            let rng = ring::rand::SystemRandom::new();
            let pkcs8_bytes = ring::signature::EcdsaKeyPair::generate_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                &rng,
            )
            .map_err(|e| format!("Key generation failed: {e}"))?;

            // Output the private key in PKCS#8 PEM format
            let b64 = base64::engine::general_purpose::STANDARD.encode(pkcs8_bytes.as_ref());
            let private_pem = format_pem("PRIVATE KEY", &b64);

            // Extract the public key from the private key
            let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                pkcs8_bytes.as_ref(),
                &rng,
            )
            .map_err(|e| format!("Failed to load generated key: {e}"))?;

            let public_key_bytes = key_pair.public_key().as_ref();

            // Wrap in SubjectPublicKeyInfo DER structure for P-256
            let spki_der = wrap_ec_public_key_spki(public_key_bytes);
            let pub_b64 = base64::engine::general_purpose::STANDARD.encode(&spki_der);
            let public_pem = format_pem("PUBLIC KEY", &pub_b64);

            eprintln!("Generated ES256 key pair");
            eprintln!("=== Private Key (keep secret — for token issuance only) ===");
            println!("{private_pem}");
            eprintln!("=== Public Key (distribute — for token validation) ===");
            println!("{public_pem}");

            eprintln!("Save the private key to a file and set ATI_JWT_PRIVATE_KEY=<path>");
            eprintln!("Save the public key to a file and set ATI_JWT_PUBLIC_KEY=<path>");
        }
        "HS256" => {
            // Generate a random 256-bit secret
            let mut secret = [0u8; 32];
            use ring::rand::SecureRandom;
            let rng = ring::rand::SystemRandom::new();
            rng.fill(&mut secret)
                .map_err(|e| format!("Random generation failed: {e}"))?;

            let hex = hex::encode(secret);
            eprintln!("Generated HS256 shared secret");
            println!("{hex}");
            eprintln!("Set ATI_JWT_SECRET=<secret above>");
        }
        _ => {
            return Err(format!("Unsupported algorithm: {algorithm}. Use ES256 or HS256.").into());
        }
    }

    Ok(())
}

fn issue(
    sub: &str,
    scope: &str,
    ttl: u64,
    aud: Option<&str>,
    iss: Option<&str>,
    key_path: Option<&str>,
    secret_hex: Option<&str>,
    rate_args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let now = jwt::now_secs();

    let mut rate_map = HashMap::new();
    for arg in rate_args {
        let parts: Vec<&str> = arg.splitn(2, '=').collect();
        if parts.len() == 2 {
            rate_map.insert(parts[0].to_string(), parts[1].to_string());
        } else {
            return Err(format!(
                "Invalid rate spec '{}': expected pattern=count/unit (e.g. tool:github:*=10/hour)",
                arg
            )
            .into());
        }
    }

    let claims = TokenClaims {
        iss: iss
            .map(String::from)
            .or_else(|| std::env::var("ATI_JWT_ISSUER").ok()),
        sub: sub.to_string(),
        aud: aud.unwrap_or("ati-proxy").to_string(),
        iat: now,
        exp: now + ttl,
        jti: Some(uuid::Uuid::new_v4().to_string()),
        scope: scope.to_string(),
        ati: Some(AtiNamespace {
            v: 1,
            rate: rate_map,
        }),
    };

    // Build config from explicit args or env
    let config = if let Some(path) = key_path {
        let pem =
            std::fs::read(path).map_err(|e| format!("Cannot read private key {path}: {e}"))?;
        jwt::config_from_pem(
            &pem, // Use private key PEM as both for now — we just need encoding
            Some(&pem),
            jsonwebtoken::Algorithm::ES256,
            claims.iss.clone(),
            claims.aud.clone(),
        )?
    } else if let Some(hex_str) = secret_hex {
        let secret_bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex secret: {e}"))?;
        jwt::config_from_secret(&secret_bytes, claims.iss.clone(), claims.aud.clone())
    } else {
        // Try env
        jwt::config_from_env()?
            .ok_or("No signing key available. Provide --key <path>, --secret <hex>, or set ATI_JWT_PRIVATE_KEY / ATI_JWT_SECRET.")?
    };

    let token = jwt::issue(&claims, &config)?;
    println!("{token}");

    if atty_stderr() {
        eprintln!("Token issued (sub={sub}, scope={scope}, ttl={ttl}s)");
        eprintln!("Set: export ATI_SESSION_TOKEN=<token above>");
    }

    Ok(())
}

fn inspect(token: &str) -> Result<(), Box<dyn std::error::Error>> {
    let claims = jwt::inspect(token)?;

    let json = serde_json::json!({
        "iss": claims.iss,
        "sub": claims.sub,
        "aud": claims.aud,
        "iat": claims.iat,
        "exp": claims.exp,
        "jti": claims.jti,
        "scope": claims.scope,
        "scopes": claims.scopes(),
        "ati": claims.ati,
    });

    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}

fn validate(
    token: &str,
    key_path: Option<&str>,
    secret_hex: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = if let Some(path) = key_path {
        let pem = std::fs::read(path).map_err(|e| format!("Cannot read public key {path}: {e}"))?;
        let audience = std::env::var("ATI_JWT_AUDIENCE").unwrap_or_else(|_| "ati-proxy".into());
        let issuer = std::env::var("ATI_JWT_ISSUER").ok();
        jwt::config_from_pem(&pem, None, jsonwebtoken::Algorithm::ES256, issuer, audience)?
    } else if let Some(hex_str) = secret_hex {
        let secret_bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex secret: {e}"))?;
        let audience = std::env::var("ATI_JWT_AUDIENCE").unwrap_or_else(|_| "ati-proxy".into());
        let issuer = std::env::var("ATI_JWT_ISSUER").ok();
        jwt::config_from_secret(&secret_bytes, issuer, audience)
    } else {
        jwt::config_from_env()?
            .ok_or("No validation key available. Provide --key <path>, --secret <hex>, or set ATI_JWT_PUBLIC_KEY / ATI_JWT_SECRET.")?
    };

    match jwt::validate(token, &config) {
        Ok(claims) => {
            tracing::info!(
                sub = %claims.sub,
                scope = %claims.scope,
                exp = claims.exp,
                "VALID"
            );
            Ok(())
        }
        Err(e) => {
            tracing::error!("INVALID — {e}");
            std::process::exit(1);
        }
    }
}

/// Check if stderr is a terminal (for pretty output vs piping).
fn atty_stderr() -> bool {
    use std::io::IsTerminal;
    std::io::stderr().is_terminal()
}

/// Format base64 content as PEM.
fn format_pem(label: &str, b64: &str) -> String {
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

/// Wrap raw EC public key bytes (uncompressed point) in SubjectPublicKeyInfo DER.
/// This produces a standard SPKI structure for P-256 EC keys.
fn wrap_ec_public_key_spki(public_key_bytes: &[u8]) -> Vec<u8> {
    // OID for EC public key: 1.2.840.10045.2.1
    // OID for P-256 curve: 1.2.840.10045.3.1.7
    let ec_oid: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    let p256_oid: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

    // AlgorithmIdentifier SEQUENCE
    let alg_id_content_len = ec_oid.len() + p256_oid.len();
    let mut alg_id = vec![0x30]; // SEQUENCE tag
    push_der_length(&mut alg_id, alg_id_content_len);
    alg_id.extend_from_slice(ec_oid);
    alg_id.extend_from_slice(p256_oid);

    // BIT STRING wrapping the public key
    let bit_string_content_len = 1 + public_key_bytes.len(); // 1 byte for unused bits count
    let mut bit_string = vec![0x03]; // BIT STRING tag
    push_der_length(&mut bit_string, bit_string_content_len);
    bit_string.push(0x00); // 0 unused bits
    bit_string.extend_from_slice(public_key_bytes);

    // Outer SEQUENCE (SubjectPublicKeyInfo)
    let total_content_len = alg_id.len() + bit_string.len();
    let mut spki = vec![0x30]; // SEQUENCE tag
    push_der_length(&mut spki, total_content_len);
    spki.extend_from_slice(&alg_id);
    spki.extend_from_slice(&bit_string);

    spki
}

/// Push DER length encoding.
fn push_der_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len < 256 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xff) as u8);
    }
}
