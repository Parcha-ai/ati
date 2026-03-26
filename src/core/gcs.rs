//! GCS (Google Cloud Storage) client for the ATI skill registry.
//!
//! Uses the GCS JSON API directly via `reqwest` — no additional crate dependencies.
//! Authentication is via service account JSON (the same `gcp_credentials` key
//! already stored in the ATI keyring).

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;
use thiserror::Error;

use crate::core::skill::{self, SkillMeta};

#[derive(Error, Debug)]
pub enum GcsError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Auth error: {0}")]
    Auth(String),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("JWT signing error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("GCS API error ({status}): {message}")]
    Api { status: u16, message: String },
    #[error("Invalid service account JSON: {0}")]
    InvalidCredentials(String),
}

// ---------------------------------------------------------------------------
// Service account credentials
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
    #[serde(default = "default_token_uri")]
    token_uri: String,
}

fn default_token_uri() -> String {
    "https://oauth2.googleapis.com/token".into()
}

struct CachedToken {
    token: String,
    expires_at: u64,
}

// ---------------------------------------------------------------------------
// GCS client
// ---------------------------------------------------------------------------

/// Minimal GCS client using the JSON API. Authenticates via service account JWT.
pub struct GcsClient {
    bucket: String,
    http: reqwest::Client,
    service_account: ServiceAccount,
    token: Mutex<Option<CachedToken>>,
}

impl GcsClient {
    /// Create a new GCS client from a bucket name and service account JSON string.
    pub fn new(bucket: String, service_account_json: &str) -> Result<Self, GcsError> {
        let sa: ServiceAccount = serde_json::from_str(service_account_json)
            .map_err(|e| GcsError::InvalidCredentials(e.to_string()))?;

        if sa.client_email.is_empty() || sa.private_key.is_empty() {
            return Err(GcsError::InvalidCredentials(
                "client_email and private_key are required".into(),
            ));
        }

        Ok(Self {
            bucket,
            http: reqwest::Client::new(),
            service_account: sa,
            token: Mutex::new(None),
        })
    }

    /// Get a valid access token, refreshing if expired.
    async fn access_token(&self) -> Result<String, GcsError> {
        // Check cached token
        {
            let guard = self.token.lock().unwrap();
            if let Some(ref cached) = *guard {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if now < cached.expires_at {
                    return Ok(cached.token.clone());
                }
            }
        }

        // Mint a new token via service account JWT → OAuth2 exchange
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = serde_json::json!({
            "iss": self.service_account.client_email,
            "scope": "https://www.googleapis.com/auth/devstorage.read_only",
            "aud": self.service_account.token_uri,
            "iat": now,
            "exp": now + 3600,
        });

        let key =
            jsonwebtoken::EncodingKey::from_rsa_pem(self.service_account.private_key.as_bytes())
                .map_err(|e| GcsError::Auth(format!("invalid RSA key: {e}")))?;

        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let assertion = jsonwebtoken::encode(&header, &claims, &key)?;

        // Exchange JWT for access token
        let resp = self
            .http
            .post(&self.service_account.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &assertion),
            ])
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(GcsError::Api {
                status,
                message: body,
            });
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: Option<u64>,
        }

        let token_resp: TokenResponse = resp.json().await?;
        let expires_at = now + token_resp.expires_in.unwrap_or(3600) - 300; // 5 min buffer

        let access_token = token_resp.access_token.clone();

        // Cache it
        {
            let mut guard = self.token.lock().unwrap();
            *guard = Some(CachedToken {
                token: token_resp.access_token,
                expires_at,
            });
        }

        Ok(access_token)
    }

    /// List top-level "directories" (prefixes) in the bucket.
    /// Returns skill names like `["fal-generate", "compliance-screening", ...]`.
    pub async fn list_skill_names(&self) -> Result<Vec<String>, GcsError> {
        let token = self.access_token().await?;
        let url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o?delimiter=/",
            self.bucket
        );

        let resp = self.http.get(&url).bearer_auth(&token).send().await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(GcsError::Api {
                status,
                message: body,
            });
        }

        #[derive(Deserialize)]
        struct ListResponse {
            #[serde(default)]
            prefixes: Vec<String>,
        }

        let list: ListResponse = resp.json().await?;
        Ok(list
            .prefixes
            .into_iter()
            .map(|p| p.trim_end_matches('/').to_string())
            .filter(|p| !p.is_empty())
            .collect())
    }

    /// List all objects under a prefix (recursive).
    /// Returns relative paths like `["SKILL.md", "skill.toml", "scripts/generate.sh"]`.
    pub async fn list_objects(&self, prefix: &str) -> Result<Vec<String>, GcsError> {
        let token = self.access_token().await?;
        let full_prefix = format!("{}/", prefix.trim_end_matches('/'));
        let mut all_objects = Vec::new();
        let mut page_token: Option<String> = None;

        loop {
            let mut url = format!(
                "https://storage.googleapis.com/storage/v1/b/{}/o?prefix={}",
                self.bucket,
                urlencoded(&full_prefix)
            );
            if let Some(ref pt) = page_token {
                url.push_str(&format!("&pageToken={}", urlencoded(pt)));
            }

            let resp = self.http.get(&url).bearer_auth(&token).send().await?;

            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                return Err(GcsError::Api {
                    status,
                    message: body,
                });
            }

            #[derive(Deserialize)]
            struct ListResponse {
                #[serde(default)]
                items: Vec<ObjectItem>,
                #[serde(rename = "nextPageToken")]
                next_page_token: Option<String>,
            }

            #[derive(Deserialize)]
            struct ObjectItem {
                name: String,
            }

            let list: ListResponse = resp.json().await?;

            for item in list.items {
                // Strip the prefix to get relative path
                if let Some(rel) = item.name.strip_prefix(&full_prefix) {
                    if !rel.is_empty() {
                        all_objects.push(rel.to_string());
                    }
                }
            }

            match list.next_page_token {
                Some(pt) => page_token = Some(pt),
                None => break,
            }
        }

        Ok(all_objects)
    }

    /// Read a single object as bytes.
    pub async fn get_object(&self, path: &str) -> Result<Vec<u8>, GcsError> {
        let token = self.access_token().await?;
        let url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o/{}?alt=media",
            self.bucket,
            urlencoded(path)
        );

        let resp = self.http.get(&url).bearer_auth(&token).send().await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(GcsError::Api {
                status,
                message: body,
            });
        }

        Ok(resp.bytes().await?.to_vec())
    }

    /// Read a single object as UTF-8 text.
    pub async fn get_object_text(&self, path: &str) -> Result<String, GcsError> {
        let bytes = self.get_object(path).await?;
        String::from_utf8(bytes).map_err(|e| GcsError::Auth(format!("invalid UTF-8: {e}")))
    }
}

/// Minimal URL encoding for GCS object names.
fn urlencoded(s: &str) -> String {
    s.replace('%', "%25")
        .replace(' ', "%20")
        .replace('/', "%2F")
        .replace('?', "%3F")
        .replace('#', "%23")
        .replace('&', "%26")
        .replace('=', "%3D")
}

// ---------------------------------------------------------------------------
// GCS skill source — loads all skills from a bucket into memory
// ---------------------------------------------------------------------------

/// Skills loaded from a GCS bucket, with all files cached in memory.
pub struct GcsSkillSource {
    /// Parsed skill metadata.
    pub skills: Vec<SkillMeta>,
    /// All files keyed by (skill_name, relative_path).
    pub files: HashMap<(String, String), Vec<u8>>,
}

impl GcsSkillSource {
    /// Load all skills from a GCS bucket.
    ///
    /// Enumerates top-level "directories" as skill names, then fetches
    /// all files in each skill directory. Parses SKILL.md + skill.toml
    /// for metadata using the same logic as local skill loading.
    pub async fn load(client: &GcsClient) -> Result<Self, GcsError> {
        let skill_names = client.list_skill_names().await?;
        let mut skills = Vec::new();
        let mut files: HashMap<(String, String), Vec<u8>> = HashMap::new();

        for name in &skill_names {
            // List all files in this skill
            let objects = client.list_objects(name).await?;

            // Fetch all files
            for rel_path in &objects {
                let full_path = format!("{}/{}", name, rel_path);
                match client.get_object(&full_path).await {
                    Ok(data) => {
                        files.insert((name.clone(), rel_path.clone()), data);
                    }
                    Err(e) => {
                        tracing::warn!(
                            skill = %name,
                            path = %rel_path,
                            error = %e,
                            "failed to fetch skill file from GCS"
                        );
                    }
                }
            }

            // Parse metadata from cached files
            let skill_md = files
                .get(&(name.clone(), "SKILL.md".to_string()))
                .and_then(|b| std::str::from_utf8(b).ok())
                .unwrap_or("");

            let skill_toml = files
                .get(&(name.clone(), "skill.toml".to_string()))
                .and_then(|b| std::str::from_utf8(b).ok());

            match skill::parse_skill_metadata(name, skill_md, skill_toml) {
                Ok(meta) => skills.push(meta),
                Err(e) => {
                    tracing::warn!(skill = %name, error = %e, "failed to parse GCS skill metadata");
                }
            }
        }

        Ok(GcsSkillSource { skills, files })
    }

    /// Number of skills loaded.
    pub fn skill_count(&self) -> usize {
        self.skills.len()
    }
}
