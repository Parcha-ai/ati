use std::path::Path;

use super::common;

/// Execute: ati init [--proxy [--es256]]
pub fn execute(proxy: bool, es256: bool) -> Result<(), Box<dyn std::error::Error>> {
    let ati_dir = common::ati_dir();
    init_directory(&ati_dir, proxy, es256)
}

fn init_directory(
    ati_dir: &Path,
    proxy: bool,
    es256: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create directory structure
    let dirs = ["manifests", "specs", "skills"];
    for dir in &dirs {
        std::fs::create_dir_all(ati_dir.join(dir))?;
    }

    // Write config.toml — always overwrite when --proxy is specified (explicit user action),
    // only create default if it doesn't exist yet.
    let config_path = ati_dir.join("config.toml");
    if proxy {
        let config_content = if es256 {
            generate_es256_config(ati_dir)?
        } else {
            generate_hs256_config()?
        };
        std::fs::write(&config_path, config_content)?;
    } else if !config_path.exists() {
        std::fs::write(&config_path, default_config())?;
    }

    eprintln!("Initialized {}/", ati_dir.display());
    eprintln!("  manifests/");
    eprintln!("  specs/");
    eprintln!("  skills/");
    eprintln!("  config.toml");

    eprintln!();
    eprintln!("Next steps:");
    eprintln!("  ati key set <name> <value>            Add an API key");
    eprintln!("  ati provider import-openapi <url>     Import an API spec");

    Ok(())
}

fn default_config() -> String {
    r#"# ATI configuration
# See https://github.com/Parcha-ai/ati for documentation.

# [proxy]
# port = 8090
# bind = "127.0.0.1"
"#
    .to_string()
}

fn generate_hs256_config() -> Result<String, Box<dyn std::error::Error>> {
    // Generate a random 256-bit secret
    let mut secret = [0u8; 32];
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    rng.fill(&mut secret)
        .map_err(|e| format!("Random generation failed: {e}"))?;

    let hex_secret = hex::encode(secret);

    Ok(format!(
        r#"# ATI configuration — proxy mode (HS256)

[proxy]
port = 8090
bind = "127.0.0.1"

[proxy.jwt]
algorithm = "HS256"
secret = "{hex_secret}"

# Issue tokens with:
#   ati token issue --sub agent-1 --scope "tool:* help" --secret {hex_secret}
"#
    ))
}

fn generate_es256_config(ati_dir: &Path) -> Result<String, Box<dyn std::error::Error>> {
    use base64::Engine;
    use ring::signature::KeyPair;

    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rng,
    )
    .map_err(|e| format!("Key generation failed: {e}"))?;

    // Write private key PEM
    let priv_b64 = base64::engine::general_purpose::STANDARD.encode(pkcs8_bytes.as_ref());
    let private_pem = format_pem("PRIVATE KEY", &priv_b64);
    let priv_path = ati_dir.join("jwt-private.pem");
    std::fs::write(&priv_path, &private_pem)?;

    // Set 0600 on private key
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // Extract public key
    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8_bytes.as_ref(),
        &rng,
    )
    .map_err(|e| format!("Failed to load generated key: {e}"))?;

    let public_key_bytes = key_pair.public_key().as_ref();
    let spki_der = wrap_ec_public_key_spki(public_key_bytes);
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode(&spki_der);
    let public_pem = format_pem("PUBLIC KEY", &pub_b64);
    let pub_path = ati_dir.join("jwt-public.pem");
    std::fs::write(&pub_path, &public_pem)?;

    eprintln!("  jwt-private.pem  (keep secret)");
    eprintln!("  jwt-public.pem   (distribute for validation)");

    Ok(format!(
        r#"# ATI configuration — proxy mode (ES256)

[proxy]
port = 8090
bind = "127.0.0.1"

[proxy.jwt]
algorithm = "ES256"
private_key = "jwt-private.pem"
public_key = "jwt-public.pem"

# Issue tokens with:
#   ati token issue --sub agent-1 --scope "tool:* help" --key {}/jwt-private.pem
"#,
        ati_dir.display()
    ))
}

fn format_pem(label: &str, b64: &str) -> String {
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

fn wrap_ec_public_key_spki(public_key_bytes: &[u8]) -> Vec<u8> {
    let ec_oid: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    let p256_oid: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

    let alg_id_content_len = ec_oid.len() + p256_oid.len();
    let mut alg_id = vec![0x30];
    push_der_length(&mut alg_id, alg_id_content_len);
    alg_id.extend_from_slice(ec_oid);
    alg_id.extend_from_slice(p256_oid);

    let bit_string_content_len = 1 + public_key_bytes.len();
    let mut bit_string = vec![0x03];
    push_der_length(&mut bit_string, bit_string_content_len);
    bit_string.push(0x00);
    bit_string.extend_from_slice(public_key_bytes);

    let total_content_len = alg_id.len() + bit_string.len();
    let mut spki = vec![0x30];
    push_der_length(&mut spki, total_content_len);
    spki.extend_from_slice(&alg_id);
    spki.extend_from_slice(&bit_string);

    spki
}

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
