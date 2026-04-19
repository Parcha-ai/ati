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
    #[error("Invalid UTF-8 in GCS object: {0}")]
    Utf8(String),
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
    scope: String,
}

impl GcsClient {
    /// Create a new read-only GCS client (used by the skill registry loader).
    pub fn new(bucket: String, service_account_json: &str) -> Result<Self, GcsError> {
        Self::new_with_scope(
            bucket,
            service_account_json,
            "https://www.googleapis.com/auth/devstorage.read_only",
        )
    }

    /// Create a read/write GCS client (used by the file_manager upload tool).
    pub fn new_read_write(bucket: String, service_account_json: &str) -> Result<Self, GcsError> {
        Self::new_with_scope(
            bucket,
            service_account_json,
            "https://www.googleapis.com/auth/devstorage.read_write",
        )
    }

    fn new_with_scope(
        bucket: String,
        service_account_json: &str,
        scope: &str,
    ) -> Result<Self, GcsError> {
        let sa: ServiceAccount = serde_json::from_str(service_account_json)
            .map_err(|e| GcsError::InvalidCredentials(e.to_string()))?;

        if sa.client_email.is_empty() || sa.private_key.is_empty() {
            return Err(GcsError::InvalidCredentials(
                "client_email and private_key are required".into(),
            ));
        }

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(GcsError::Http)?;

        Ok(Self {
            bucket,
            http,
            service_account: sa,
            token: Mutex::new(None),
            scope: scope.to_string(),
        })
    }

    /// Bucket name this client targets.
    pub fn bucket(&self) -> &str {
        &self.bucket
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
            "scope": self.scope,
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
        let url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o?delimiter=/",
            self.bucket
        );

        let resp = self.get_with_retry(&url).await?;

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

            let resp = self.get_with_retry(&url).await?;

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
        let url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o/{}?alt=media",
            self.bucket,
            urlencoded(path)
        );

        let resp = self.get_with_retry(&url).await?;

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
        String::from_utf8(bytes).map_err(|e| GcsError::Utf8(e.to_string()))
    }

    /// Upload bytes to `<bucket>/<object_name>` using the GCS JSON simple upload API.
    /// Returns the public-style URL `https://storage.googleapis.com/<bucket>/<object_name>`.
    /// The object is *not* made public — the URL only resolves if the bucket grants
    /// public read access, which is the proxy-operator's responsibility to configure.
    pub async fn upload_object(
        &self,
        object_name: &str,
        bytes: Vec<u8>,
        content_type: &str,
    ) -> Result<String, GcsError> {
        let url = format!(
            "https://storage.googleapis.com/upload/storage/v1/b/{}/o?uploadType=media&name={}",
            self.bucket,
            urlencoded(object_name)
        );

        // Retry 429/5xx up to 3 times with exponential backoff — matches the
        // pattern used by `get_with_retry`. Uploads are idempotent with the
        // JSON simple-upload API (each call fully replaces the object at
        // `name=`), so retrying on transient failures is safe.
        //
        // `bytes::Bytes` is Arc-backed, so cloning across retries is O(1) —
        // the alternative is a 1 GB memcpy per attempt on large uploads.
        let body = bytes::Bytes::from(bytes);
        let mut last_err: Option<GcsError> = None;
        for attempt in 0..3 {
            let token = self.access_token().await?;
            match self
                .http
                .post(&url)
                .bearer_auth(&token)
                .header(reqwest::header::CONTENT_TYPE, content_type)
                .body(body.clone())
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status == 429 || status >= 500 {
                        let body = resp.text().await.unwrap_or_default();
                        last_err = Some(GcsError::Api {
                            status,
                            message: body,
                        });
                        let delay = std::time::Duration::from_millis(500 * (1 << attempt));
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    if !resp.status().is_success() {
                        let body = resp.text().await.unwrap_or_default();
                        return Err(GcsError::Api {
                            status,
                            message: body,
                        });
                    }
                    // Success — return the canonical public URL. Path-style so
                    // object names with `/` segments round-trip cleanly.
                    return Ok(format!(
                        "https://storage.googleapis.com/{}/{}",
                        self.bucket,
                        object_name
                            .split('/')
                            .map(percent_encode_segment)
                            .collect::<Vec<_>>()
                            .join("/")
                    ));
                }
                Err(e) => {
                    last_err = Some(GcsError::Http(e));
                    let delay = std::time::Duration::from_millis(500 * (1 << attempt));
                    tokio::time::sleep(delay).await;
                }
            }
        }
        Err(last_err.expect("loop body sets last_err on every failure path"))
    }

    /// Retry-aware wrapper for GET requests. Retries on 429/5xx up to 3 times with backoff.
    async fn get_with_retry(&self, url: &str) -> Result<reqwest::Response, GcsError> {
        let mut last_err = None;
        for attempt in 0..3 {
            let token = self.access_token().await?;
            match self.http.get(url).bearer_auth(&token).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status == 429 || status >= 500 {
                        let body = resp.text().await.unwrap_or_default();
                        last_err = Some(GcsError::Api {
                            status,
                            message: body,
                        });
                        let delay = std::time::Duration::from_millis(500 * (1 << attempt));
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    last_err = Some(GcsError::Http(e));
                    let delay = std::time::Duration::from_millis(500 * (1 << attempt));
                    tokio::time::sleep(delay).await;
                }
            }
        }
        Err(last_err.unwrap())
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

// `percent_encode_segment` used to live here; it was an exact duplicate of
// `core::http::percent_encode_path_segment`. Import that instead.
use crate::core::http::percent_encode_path_segment as percent_encode_segment;

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
    /// Load all skills from a GCS bucket concurrently.
    ///
    /// Enumerates top-level "directories" as skill names, then fetches
    /// all files in each skill directory with bounded concurrency.
    pub async fn load(client: &GcsClient) -> Result<Self, GcsError> {
        use futures::stream::{self, StreamExt};

        let skill_names = client.list_skill_names().await?;
        tracing::debug!(count = skill_names.len(), "discovered skills in GCS bucket");

        // Load all skills concurrently (up to 50 at a time)
        let results: Vec<_> = stream::iter(skill_names)
            .map(|name| async move { Self::load_one_skill(client, &name).await })
            .buffer_unordered(50)
            .collect()
            .await;

        let mut skills = Vec::new();
        let mut files: HashMap<(String, String), Vec<u8>> = HashMap::new();

        for result in results {
            match result {
                Ok((meta, skill_files)) => {
                    skills.push(meta);
                    files.extend(skill_files);
                }
                Err((name, e)) => {
                    tracing::warn!(skill = %name, error = %e, "failed to load GCS skill");
                }
            }
        }

        Ok(GcsSkillSource { skills, files })
    }

    /// Load a single skill: list its files, fetch them concurrently, parse metadata.
    async fn load_one_skill(
        client: &GcsClient,
        name: &str,
    ) -> Result<(SkillMeta, Vec<((String, String), Vec<u8>)>), (String, String)> {
        use futures::stream::{self, StreamExt};

        let objects = client
            .list_objects(name)
            .await
            .map_err(|e| (name.to_string(), e.to_string()))?;

        // Fetch all files in this skill concurrently
        let file_results: Vec<_> = stream::iter(objects)
            .map(|rel_path| {
                let full_path = format!("{}/{}", name, rel_path);
                let name = name.to_string();
                async move {
                    match client.get_object(&full_path).await {
                        Ok(data) => Some(((name, rel_path), data)),
                        Err(e) => {
                            tracing::warn!(path = %full_path, error = %e, "failed to fetch file");
                            None
                        }
                    }
                }
            })
            .buffer_unordered(20)
            .collect()
            .await;

        let file_entries: Vec<((String, String), Vec<u8>)> =
            file_results.into_iter().flatten().collect();

        // Parse metadata
        let skill_md = file_entries
            .iter()
            .find(|((_, p), _)| p == "SKILL.md")
            .and_then(|(_, data)| std::str::from_utf8(data).ok())
            .unwrap_or("");

        let skill_toml = file_entries
            .iter()
            .find(|((_, p), _)| p == "skill.toml")
            .and_then(|(_, data)| std::str::from_utf8(data).ok());

        let meta = skill::parse_skill_metadata(name, skill_md, skill_toml)
            .map_err(|e| (name.to_string(), e.to_string()))?;

        Ok((meta, file_entries))
    }

    /// Number of skills loaded.
    pub fn skill_count(&self) -> usize {
        self.skills.len()
    }
}
