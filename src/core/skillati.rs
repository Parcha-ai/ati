use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine;
use chrono::Utc;
use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::gcs::{GcsClient, GcsError};
use crate::core::secret_resolver::SecretResolver;
use crate::core::skill::{is_anthropic_valid_name, parse_skill_metadata, strip_frontmatter};

const GCS_CREDENTIAL_KEY: &str = "gcp_credentials";
const DEFAULT_CATALOG_INDEX_PATH: &str = "_skillati/catalog.v1.json";
const DEFAULT_CATALOG_INDEX_CANDIDATES: &[&str] = &[
    DEFAULT_CATALOG_INDEX_PATH,
    "_skillati/catalog.json",
    "skillati-catalog.json",
];
const FALLBACK_CATALOG_CONCURRENCY: usize = 24;

#[derive(Error, Debug)]
pub enum SkillAtiError {
    #[error("SkillATI is not configured (set ATI_SKILL_REGISTRY=gcs://<bucket> or ATI_SKILL_REGISTRY=proxy)")]
    NotConfigured,
    #[error("Unsupported skill registry URL: {0}")]
    UnsupportedRegistry(String),
    #[error("GCS credentials not found in keyring: {0}")]
    MissingCredentials(&'static str),
    #[error("ATI_PROXY_URL must be set when ATI_SKILL_REGISTRY=proxy")]
    ProxyUrlRequired,
    #[error("Skill '{0}' not found")]
    SkillNotFound(String),
    #[error("Path '{path}' not found in skill '{skill}'")]
    PathNotFound { skill: String, path: String },
    #[error("Invalid skill-relative path '{0}'")]
    InvalidPath(String),
    #[error(transparent)]
    Gcs(#[from] GcsError),
    #[error("Proxy request failed: {0}")]
    ProxyRequest(String),
    #[error("Proxy returned invalid response: {0}")]
    ProxyResponse(String),
}

#[derive(Error, Debug)]
pub enum SkillAtiBuildError {
    #[error("Source directory not found: {0}")]
    MissingSource(String),
    #[error("Failed to read {0}: {1}")]
    Io(String, #[source] std::io::Error),
    #[error("Failed to parse skill metadata for {0}: {1}")]
    Metadata(String, String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteSkillMeta {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub skill_directory: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keywords: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkillAtiCatalogEntry {
    #[serde(flatten)]
    pub meta: RemoteSkillMeta,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
    #[serde(default, skip)]
    pub resources_complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkillAtiCatalogManifest {
    #[serde(default = "default_catalog_version")]
    pub version: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub generated_at: String,
    pub skills: Vec<SkillAtiCatalogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkillAtiActivation {
    pub name: String,
    pub skill_directory: String,
    pub content: String,
    pub resources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SkillAtiFileData {
    Text { content: String },
    Binary { encoding: String, content: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkillAtiFile {
    pub requested_skill: String,
    pub resolved_skill: String,
    pub path: String,
    #[serde(flatten)]
    pub data: SkillAtiFileData,
}

enum SkillAtiTransport {
    Gcs(GcsClient),
    Proxy {
        http: Client,
        base_url: String,
        token: Option<String>,
    },
}

pub struct SkillAtiClient {
    transport: SkillAtiTransport,
    bytes_cache: Mutex<HashMap<(String, String), Vec<u8>>>,
    resources_cache: Mutex<HashMap<String, Vec<String>>>,
    catalog_cache: Mutex<Option<Vec<SkillAtiCatalogEntry>>>,
}

impl SkillAtiClient {
    pub fn from_env(keyring: &SecretResolver<'_>) -> Result<Option<Self>, SkillAtiError> {
        match std::env::var("ATI_SKILL_REGISTRY") {
            Ok(url) if !url.trim().is_empty() => Ok(Some(Self::from_registry_url(&url, keyring)?)),
            _ => Ok(None),
        }
    }

    pub fn from_registry_url(
        registry_url: &str,
        keyring: &SecretResolver<'_>,
    ) -> Result<Self, SkillAtiError> {
        if registry_url.trim() == "proxy" {
            let base_url = std::env::var("ATI_PROXY_URL")
                .ok()
                .filter(|u| !u.trim().is_empty())
                .ok_or(SkillAtiError::ProxyUrlRequired)?;
            let base_url = base_url.trim_end_matches('/').to_string();
            let token = std::env::var("ATI_SESSION_TOKEN")
                .ok()
                .filter(|t| !t.trim().is_empty());
            let http = Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| SkillAtiError::ProxyRequest(e.to_string()))?;
            return Ok(Self {
                transport: SkillAtiTransport::Proxy {
                    http,
                    base_url,
                    token,
                },
                bytes_cache: Mutex::new(HashMap::new()),
                resources_cache: Mutex::new(HashMap::new()),
                catalog_cache: Mutex::new(None),
            });
        }

        let bucket = registry_url
            .strip_prefix("gcs://")
            .ok_or_else(|| SkillAtiError::UnsupportedRegistry(registry_url.to_string()))?;

        let cred_json = keyring
            .get(GCS_CREDENTIAL_KEY)
            .ok_or(SkillAtiError::MissingCredentials(GCS_CREDENTIAL_KEY))?;

        let gcs = GcsClient::new(bucket.to_string(), cred_json)?;
        Ok(Self {
            transport: SkillAtiTransport::Gcs(gcs),
            bytes_cache: Mutex::new(HashMap::new()),
            resources_cache: Mutex::new(HashMap::new()),
            catalog_cache: Mutex::new(None),
        })
    }

    /// Build an authenticated request to the proxy.
    fn proxy_request(
        http: &Client,
        method: reqwest::Method,
        url: &str,
        token: Option<&str>,
    ) -> reqwest::RequestBuilder {
        let mut req = http.request(method, url);
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        req
    }

    /// Fetch the catalog from the proxy's /skillati/catalog endpoint.
    async fn proxy_catalog(
        http: &Client,
        base_url: &str,
        token: Option<&str>,
    ) -> Result<Vec<SkillAtiCatalogEntry>, SkillAtiError> {
        let url = format!("{base_url}/skillati/catalog");
        let resp = Self::proxy_request(http, reqwest::Method::GET, &url, token)
            .send()
            .await
            .map_err(|e| SkillAtiError::ProxyRequest(e.to_string()))?;

        let status = resp.status().as_u16();
        let body = resp
            .text()
            .await
            .map_err(|e| SkillAtiError::ProxyRequest(e.to_string()))?;

        if status != 200 {
            return Err(SkillAtiError::ProxyResponse(format!(
                "HTTP {status}: {body}"
            )));
        }

        #[derive(Deserialize)]
        struct CatalogResp {
            skills: Vec<RemoteSkillMeta>,
        }
        let parsed: CatalogResp =
            serde_json::from_str(&body).map_err(|e| SkillAtiError::ProxyResponse(e.to_string()))?;

        Ok(parsed
            .skills
            .into_iter()
            .map(|meta| SkillAtiCatalogEntry {
                meta,
                resources: Vec::new(),
                resources_complete: false,
            })
            .collect())
    }

    /// Fetch SKILL.md bytes from the proxy's /skillati/:name endpoint.
    async fn proxy_read_skill_md(
        http: &Client,
        base_url: &str,
        token: Option<&str>,
        name: &str,
    ) -> Result<Vec<u8>, SkillAtiError> {
        let url = format!("{base_url}/skillati/{name}");
        let resp = Self::proxy_request(http, reqwest::Method::GET, &url, token)
            .send()
            .await
            .map_err(|e| SkillAtiError::ProxyRequest(e.to_string()))?;

        let status = resp.status().as_u16();
        let body = resp
            .text()
            .await
            .map_err(|e| SkillAtiError::ProxyRequest(e.to_string()))?;

        match status {
            404 => return Err(SkillAtiError::SkillNotFound(name.to_string())),
            200 => {}
            _ => {
                return Err(SkillAtiError::ProxyResponse(format!(
                    "HTTP {status}: {body}"
                )))
            }
        }

        // Response is a SkillAtiActivation JSON — extract the content field
        #[derive(Deserialize)]
        struct ActivationResp {
            content: String,
        }
        let parsed: ActivationResp =
            serde_json::from_str(&body).map_err(|e| SkillAtiError::ProxyResponse(e.to_string()))?;

        Ok(parsed.content.into_bytes())
    }

    /// Fetch a file from the proxy's /skillati/:name/file?path=... endpoint.
    async fn proxy_read_file(
        http: &Client,
        base_url: &str,
        token: Option<&str>,
        name: &str,
        path: &str,
    ) -> Result<Vec<u8>, SkillAtiError> {
        if path == "SKILL.md" {
            return Self::proxy_read_skill_md(http, base_url, token, name).await;
        }

        let url = format!("{base_url}/skillati/{name}/file");
        let resp = Self::proxy_request(http, reqwest::Method::GET, &url, token)
            .query(&[("path", path)])
            .send()
            .await
            .map_err(|e| SkillAtiError::ProxyRequest(e.to_string()))?;

        let status = resp.status().as_u16();
        let body = resp
            .text()
            .await
            .map_err(|e| SkillAtiError::ProxyRequest(e.to_string()))?;

        match status {
            404 => {
                return Err(SkillAtiError::PathNotFound {
                    skill: name.to_string(),
                    path: path.to_string(),
                })
            }
            200 => {}
            _ => {
                return Err(SkillAtiError::ProxyResponse(format!(
                    "HTTP {status}: {body}"
                )))
            }
        }

        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum FileDataResp {
            Text { content: String },
            Binary { content: String },
        }
        let parsed: FileDataResp =
            serde_json::from_str(&body).map_err(|e| SkillAtiError::ProxyResponse(e.to_string()))?;

        match parsed {
            FileDataResp::Text { content } => Ok(content.into_bytes()),
            FileDataResp::Binary { content } => base64::engine::general_purpose::STANDARD
                .decode(content)
                .map_err(|e| SkillAtiError::ProxyResponse(e.to_string())),
        }
    }

    /// List resources from the proxy's /skillati/:name/resources endpoint.
    async fn proxy_list_resources(
        http: &Client,
        base_url: &str,
        token: Option<&str>,
        name: &str,
    ) -> Result<Vec<String>, SkillAtiError> {
        let url = format!("{base_url}/skillati/{name}/resources");
        let resp = Self::proxy_request(http, reqwest::Method::GET, &url, token)
            .send()
            .await
            .map_err(|e| SkillAtiError::ProxyRequest(e.to_string()))?;

        let status = resp.status().as_u16();
        let body = resp
            .text()
            .await
            .map_err(|e| SkillAtiError::ProxyRequest(e.to_string()))?;

        match status {
            404 => return Err(SkillAtiError::SkillNotFound(name.to_string())),
            200 => {}
            _ => {
                return Err(SkillAtiError::ProxyResponse(format!(
                    "HTTP {status}: {body}"
                )))
            }
        }

        #[derive(Deserialize)]
        struct ResourcesResp {
            resources: Vec<String>,
        }
        let parsed: ResourcesResp =
            serde_json::from_str(&body).map_err(|e| SkillAtiError::ProxyResponse(e.to_string()))?;

        Ok(parsed.resources)
    }

    pub async fn catalog(&self) -> Result<Vec<RemoteSkillMeta>, SkillAtiError> {
        Ok(self
            .catalog_entries()
            .await?
            .into_iter()
            .map(|entry| entry.meta)
            .collect())
    }

    pub fn filter_catalog(
        catalog: &[RemoteSkillMeta],
        query: &str,
        limit: usize,
    ) -> Vec<RemoteSkillMeta> {
        let query = query.trim().to_lowercase();
        if query.is_empty() {
            return catalog.iter().take(limit).cloned().collect();
        }

        let terms: Vec<&str> = query.split_whitespace().collect();
        let mut scored: Vec<(usize, &RemoteSkillMeta)> = catalog
            .iter()
            .map(|skill| {
                let haystack = search_haystack(skill);
                let score = terms
                    .iter()
                    .filter(|term| haystack.contains(**term))
                    .count();
                (score, skill)
            })
            .filter(|(score, skill)| *score > 0 || search_haystack(skill).contains(&query))
            .collect();

        scored.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| a.1.name.to_lowercase().cmp(&b.1.name.to_lowercase()))
        });

        scored
            .into_iter()
            .take(limit)
            .map(|(_, skill)| skill.clone())
            .collect()
    }

    pub async fn read_skill(&self, name: &str) -> Result<SkillAtiActivation, SkillAtiError> {
        let raw = self.read_text(name, "SKILL.md").await?;
        let resources = self.list_resources(name, None).await?;
        Ok(SkillAtiActivation {
            name: name.to_string(),
            skill_directory: skill_directory(name),
            content: strip_frontmatter(&raw).to_string(),
            resources,
        })
    }

    pub async fn list_resources(
        &self,
        name: &str,
        prefix: Option<&str>,
    ) -> Result<Vec<String>, SkillAtiError> {
        let resources = self.list_all_resources(name).await?;
        let normalized_prefix = match prefix {
            Some(value) if !value.trim().is_empty() => Some(normalize_prefix(value)?),
            _ => None,
        };

        let filtered = match normalized_prefix {
            Some(prefix) => resources
                .into_iter()
                .filter(|path| path == &prefix || path.starts_with(&format!("{prefix}/")))
                .collect(),
            None => resources,
        };

        Ok(filtered)
    }

    pub async fn read_path(
        &self,
        requested_skill: &str,
        requested_path: &str,
    ) -> Result<SkillAtiFile, SkillAtiError> {
        let (resolved_skill, resolved_path) =
            resolve_requested_path(requested_skill, requested_path)?;
        let bytes = self.read_bytes(&resolved_skill, &resolved_path).await?;

        let data = match String::from_utf8(bytes.clone()) {
            Ok(text) => SkillAtiFileData::Text { content: text },
            Err(_) => SkillAtiFileData::Binary {
                encoding: "base64".to_string(),
                content: base64::engine::general_purpose::STANDARD.encode(bytes),
            },
        };

        Ok(SkillAtiFile {
            requested_skill: requested_skill.to_string(),
            resolved_skill,
            path: resolved_path,
            data,
        })
    }

    pub async fn list_references(&self, name: &str) -> Result<Vec<String>, SkillAtiError> {
        let refs = self.list_resources(name, Some("references")).await?;
        Ok(refs
            .into_iter()
            .filter_map(|path| path.strip_prefix("references/").map(str::to_string))
            .collect())
    }

    pub async fn read_reference(
        &self,
        name: &str,
        reference: &str,
    ) -> Result<String, SkillAtiError> {
        let path = format!("references/{reference}");
        let file = self.read_path(name, &path).await?;
        match file.data {
            SkillAtiFileData::Text { content } => Ok(content),
            SkillAtiFileData::Binary { .. } => Err(SkillAtiError::InvalidPath(path)),
        }
    }

    async fn catalog_entries(&self) -> Result<Vec<SkillAtiCatalogEntry>, SkillAtiError> {
        if let Some(cached) = self.catalog_cache.lock().unwrap().clone() {
            return Ok(cached);
        }

        let entries = match &self.transport {
            SkillAtiTransport::Proxy {
                http,
                base_url,
                token,
            } => Self::proxy_catalog(http, base_url, token.as_deref()).await?,
            SkillAtiTransport::Gcs(_) => match self.load_catalog_index().await? {
                Some(entries) => entries,
                None => self.load_catalog_fallback().await?,
            },
        };

        self.catalog_cache.lock().unwrap().replace(entries.clone());
        Ok(entries)
    }

    async fn load_catalog_index(&self) -> Result<Option<Vec<SkillAtiCatalogEntry>>, SkillAtiError> {
        let gcs = match &self.transport {
            SkillAtiTransport::Gcs(gcs) => gcs,
            SkillAtiTransport::Proxy { .. } => {
                unreachable!("load_catalog_index called on proxy transport")
            }
        };
        for candidate in catalog_index_candidates() {
            match gcs.get_object_text(&candidate).await {
                Ok(raw) => match serde_json::from_str::<SkillAtiCatalogManifest>(&raw) {
                    Ok(mut manifest) => {
                        for entry in &mut manifest.skills {
                            normalize_catalog_entry(entry);
                            entry.resources_complete = true;
                        }
                        manifest.skills.sort_by(|a, b| {
                            a.meta.name.to_lowercase().cmp(&b.meta.name.to_lowercase())
                        });
                        tracing::debug!(
                            path = %candidate,
                            skills = manifest.skills.len(),
                            "loaded SkillATI catalog index"
                        );
                        return Ok(Some(manifest.skills));
                    }
                    Err(err) => {
                        tracing::warn!(
                            path = %candidate,
                            error = %err,
                            "SkillATI catalog index was invalid, falling back"
                        );
                    }
                },
                Err(GcsError::Api { status: 404, .. }) => continue,
                Err(err) => return Err(SkillAtiError::Gcs(err)),
            }
        }

        Ok(None)
    }

    async fn load_catalog_fallback(&self) -> Result<Vec<SkillAtiCatalogEntry>, SkillAtiError> {
        let gcs = match &self.transport {
            SkillAtiTransport::Gcs(gcs) => gcs,
            SkillAtiTransport::Proxy { .. } => {
                unreachable!("load_catalog_fallback called on proxy transport")
            }
        };
        let mut names = gcs.list_skill_names().await?;
        names.sort();

        let mut entries: Vec<SkillAtiCatalogEntry> = stream::iter(names.into_iter())
            .map(|name| async move {
                let raw = self.read_text(&name, "SKILL.md").await?;
                let parsed = parse_skill_metadata(&name, &raw, None)
                    .map_err(|e| SkillAtiError::InvalidPath(e.to_string()))?;
                Ok::<SkillAtiCatalogEntry, SkillAtiError>(SkillAtiCatalogEntry {
                    meta: remote_skill_meta_from_parts(
                        &name,
                        parsed.description,
                        parsed.keywords,
                        parsed.tools,
                        parsed.providers,
                        parsed.categories,
                    ),
                    resources: Vec::new(),
                    resources_complete: false,
                })
            })
            .buffer_unordered(FALLBACK_CATALOG_CONCURRENCY)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        entries.sort_by(|a, b| a.meta.name.to_lowercase().cmp(&b.meta.name.to_lowercase()));
        Ok(entries)
    }

    async fn list_all_resources(&self, name: &str) -> Result<Vec<String>, SkillAtiError> {
        if let Some(cached) = self.resources_cache.lock().unwrap().get(name).cloned() {
            return Ok(cached);
        }

        // For proxy transport, fetch directly from proxy
        if let SkillAtiTransport::Proxy {
            http,
            base_url,
            token,
        } = &self.transport
        {
            let resources =
                Self::proxy_list_resources(http, base_url, token.as_deref(), name).await?;
            self.resources_cache
                .lock()
                .unwrap()
                .insert(name.to_string(), resources.clone());
            return Ok(resources);
        }

        if let Some(indexed) = self
            .catalog_entries()
            .await?
            .into_iter()
            .find(|entry| entry.meta.name == name && entry.resources_complete)
        {
            self.resources_cache
                .lock()
                .unwrap()
                .insert(name.to_string(), indexed.resources.clone());
            return Ok(indexed.resources);
        }

        self.ensure_skill_exists(name).await?;

        let gcs = match &self.transport {
            SkillAtiTransport::Gcs(gcs) => gcs,
            SkillAtiTransport::Proxy { .. } => unreachable!(),
        };
        let mut resources = gcs.list_objects(name).await?;
        resources.retain(|path| is_visible_resource(path));
        resources.sort();
        resources.dedup();

        self.resources_cache
            .lock()
            .unwrap()
            .insert(name.to_string(), resources.clone());
        Ok(resources)
    }

    async fn ensure_skill_exists(&self, name: &str) -> Result<(), SkillAtiError> {
        self.read_bytes(name, "SKILL.md").await.map(|_| ())
    }

    async fn read_text(&self, name: &str, relative_path: &str) -> Result<String, SkillAtiError> {
        let bytes = self.read_bytes(name, relative_path).await?;
        String::from_utf8(bytes).map_err(|e| match &self.transport {
            SkillAtiTransport::Gcs(_) => SkillAtiError::Gcs(GcsError::Utf8(e.to_string())),
            SkillAtiTransport::Proxy { .. } => SkillAtiError::ProxyResponse(format!(
                "invalid UTF-8 in {name}/{relative_path}: {e}"
            )),
        })
    }

    async fn read_bytes(&self, name: &str, relative_path: &str) -> Result<Vec<u8>, SkillAtiError> {
        let cache_key = (name.to_string(), relative_path.to_string());
        if let Some(cached) = self.bytes_cache.lock().unwrap().get(&cache_key).cloned() {
            return Ok(cached);
        }

        let bytes = match &self.transport {
            SkillAtiTransport::Proxy {
                http,
                base_url,
                token,
            } => {
                Self::proxy_read_file(http, base_url, token.as_deref(), name, relative_path).await?
            }
            SkillAtiTransport::Gcs(gcs) => {
                let gcs_path = format!("{name}/{relative_path}");
                gcs.get_object(&gcs_path)
                    .await
                    .map_err(|e| map_gcs_error(name, relative_path, e))?
            }
        };

        self.bytes_cache
            .lock()
            .unwrap()
            .insert(cache_key, bytes.clone());
        Ok(bytes)
    }
}

pub fn build_catalog_manifest(
    source_dir: &Path,
) -> Result<SkillAtiCatalogManifest, SkillAtiBuildError> {
    if !source_dir.exists() {
        return Err(SkillAtiBuildError::MissingSource(
            source_dir.display().to_string(),
        ));
    }

    let mut skill_dirs = discover_skill_dirs(source_dir)?;
    skill_dirs.sort();

    let mut skills = Vec::new();
    for skill_dir in skill_dirs {
        skills.push(build_catalog_entry_from_dir(&skill_dir)?);
    }

    skills.sort_by(|a, b| a.meta.name.to_lowercase().cmp(&b.meta.name.to_lowercase()));
    Ok(SkillAtiCatalogManifest {
        version: default_catalog_version(),
        generated_at: Utc::now().to_rfc3339(),
        skills,
    })
}

pub fn default_catalog_index_path() -> &'static str {
    DEFAULT_CATALOG_INDEX_PATH
}

fn default_catalog_version() -> u32 {
    1
}

fn catalog_index_candidates() -> Vec<String> {
    match std::env::var("ATI_SKILL_REGISTRY_INDEX_OBJECT") {
        Ok(value) => {
            let candidates: Vec<String> = value
                .split(',')
                .map(str::trim)
                .filter(|candidate| !candidate.is_empty())
                .map(str::to_string)
                .collect();
            if candidates.is_empty() {
                DEFAULT_CATALOG_INDEX_CANDIDATES
                    .iter()
                    .map(|candidate| candidate.to_string())
                    .collect()
            } else {
                candidates
            }
        }
        Err(_) => DEFAULT_CATALOG_INDEX_CANDIDATES
            .iter()
            .map(|candidate| candidate.to_string())
            .collect(),
    }
}

fn build_catalog_entry_from_dir(
    skill_dir: &Path,
) -> Result<SkillAtiCatalogEntry, SkillAtiBuildError> {
    let dir_name = skill_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| SkillAtiBuildError::MissingSource(skill_dir.display().to_string()))?
        .to_string();

    let skill_md_path = skill_dir.join("SKILL.md");
    let skill_md = fs::read_to_string(&skill_md_path)
        .map_err(|err| SkillAtiBuildError::Io(skill_md_path.display().to_string(), err))?;
    let skill_toml_path = skill_dir.join("skill.toml");
    let skill_toml =
        if skill_toml_path.exists() {
            Some(fs::read_to_string(&skill_toml_path).map_err(|err| {
                SkillAtiBuildError::Io(skill_toml_path.display().to_string(), err)
            })?)
        } else {
            None
        };

    let parsed = parse_skill_metadata(&dir_name, &skill_md, skill_toml.as_deref())
        .map_err(|err| SkillAtiBuildError::Metadata(dir_name.clone(), err.to_string()))?;
    let resources = collect_visible_resources(skill_dir, skill_dir)?;

    Ok(SkillAtiCatalogEntry {
        meta: remote_skill_meta_from_parts(
            &dir_name,
            parsed.description,
            parsed.keywords,
            parsed.tools,
            parsed.providers,
            parsed.categories,
        ),
        resources,
        resources_complete: true,
    })
}

fn discover_skill_dirs(source_dir: &Path) -> Result<Vec<PathBuf>, SkillAtiBuildError> {
    if source_dir.join("SKILL.md").is_file() {
        return Ok(vec![source_dir.to_path_buf()]);
    }

    let mut skill_dirs = Vec::new();
    let entries = fs::read_dir(source_dir)
        .map_err(|err| SkillAtiBuildError::Io(source_dir.display().to_string(), err))?;

    for entry in entries {
        let entry =
            entry.map_err(|err| SkillAtiBuildError::Io(source_dir.display().to_string(), err))?;
        let path = entry.path();
        if path.is_dir() && path.join("SKILL.md").is_file() {
            skill_dirs.push(path);
        }
    }

    Ok(skill_dirs)
}

fn collect_visible_resources(
    root: &Path,
    current: &Path,
) -> Result<Vec<String>, SkillAtiBuildError> {
    let mut resources = Vec::new();
    let entries = fs::read_dir(current)
        .map_err(|err| SkillAtiBuildError::Io(current.display().to_string(), err))?;

    for entry in entries {
        let entry =
            entry.map_err(|err| SkillAtiBuildError::Io(current.display().to_string(), err))?;
        let path = entry.path();
        let file_name = entry.file_name();
        if file_name.to_string_lossy().starts_with('.') {
            continue;
        }

        if path.is_dir() {
            resources.extend(collect_visible_resources(root, &path)?);
            continue;
        }

        let relative = path
            .strip_prefix(root)
            .map_err(|_| SkillAtiBuildError::MissingSource(path.display().to_string()))?
            .to_string_lossy()
            .replace('\\', "/");

        if is_visible_resource(&relative) {
            resources.push(relative);
        }
    }

    resources.sort();
    resources.dedup();
    Ok(resources)
}

fn remote_skill_meta_from_parts(
    name: &str,
    description: String,
    mut keywords: Vec<String>,
    mut tools: Vec<String>,
    mut providers: Vec<String>,
    mut categories: Vec<String>,
) -> RemoteSkillMeta {
    dedup_sort_casefold(&mut keywords);
    dedup_sort_casefold(&mut tools);
    dedup_sort_casefold(&mut providers);
    dedup_sort_casefold(&mut categories);

    RemoteSkillMeta {
        name: name.to_string(),
        description,
        skill_directory: skill_directory(name),
        keywords,
        tools,
        providers,
        categories,
    }
}

fn normalize_catalog_entry(entry: &mut SkillAtiCatalogEntry) {
    if entry.meta.skill_directory.trim().is_empty() {
        entry.meta.skill_directory = skill_directory(&entry.meta.name);
    }
    dedup_sort_casefold(&mut entry.meta.keywords);
    dedup_sort_casefold(&mut entry.meta.tools);
    dedup_sort_casefold(&mut entry.meta.providers);
    dedup_sort_casefold(&mut entry.meta.categories);
    entry.resources.retain(|path| is_visible_resource(path));
    entry.resources.sort();
    entry.resources.dedup();
}

fn dedup_sort_casefold(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| {
        let normalized = value.trim().to_lowercase();
        !normalized.is_empty() && seen.insert(normalized)
    });
    values.sort_by_key(|value| value.to_lowercase());
}

fn search_haystack(skill: &RemoteSkillMeta) -> String {
    let mut parts = vec![skill.name.to_lowercase(), skill.description.to_lowercase()];
    if !skill.keywords.is_empty() {
        parts.push(skill.keywords.join(" ").to_lowercase());
    }
    if !skill.tools.is_empty() {
        parts.push(skill.tools.join(" ").to_lowercase());
    }
    if !skill.providers.is_empty() {
        parts.push(skill.providers.join(" ").to_lowercase());
    }
    if !skill.categories.is_empty() {
        parts.push(skill.categories.join(" ").to_lowercase());
    }
    parts.join(" ")
}

fn map_gcs_error(skill: &str, relative_path: &str, error: GcsError) -> SkillAtiError {
    match error {
        GcsError::Api { status: 404, .. } if relative_path == "SKILL.md" => {
            SkillAtiError::SkillNotFound(skill.to_string())
        }
        GcsError::Api { status: 404, .. } => SkillAtiError::PathNotFound {
            skill: skill.to_string(),
            path: relative_path.to_string(),
        },
        other => SkillAtiError::Gcs(other),
    }
}

fn skill_directory(name: &str) -> String {
    format!("skillati://{name}")
}

fn is_visible_resource(path: &str) -> bool {
    !path.is_empty()
        && !path.ends_with('/')
        && path != "SKILL.md"
        && path != "skill.toml"
        && !path.starts_with('.')
}

fn normalize_prefix(prefix: &str) -> Result<String, SkillAtiError> {
    let prefix = trim_leading_current_dir(prefix);
    if prefix.is_empty() {
        return Err(SkillAtiError::InvalidPath(prefix.to_string()));
    }
    normalize_within_skill(prefix)
}

fn resolve_requested_path(
    requested_skill: &str,
    requested_path: &str,
) -> Result<(String, String), SkillAtiError> {
    let requested_path = trim_leading_current_dir(requested_path);
    validate_raw_path(requested_path)?;

    if requested_path == ".." {
        return Err(SkillAtiError::InvalidPath(requested_path.to_string()));
    }

    if let Some(rest) = requested_path.strip_prefix("../") {
        let segments: Vec<&str> = rest
            .split('/')
            .filter(|segment| !segment.is_empty() && *segment != ".")
            .collect();
        if segments.len() < 2 {
            return Err(SkillAtiError::InvalidPath(requested_path.to_string()));
        }

        let sibling_skill = segments[0];
        if !is_anthropic_valid_name(sibling_skill) {
            return Err(SkillAtiError::InvalidPath(requested_path.to_string()));
        }

        let normalized_path = normalize_within_skill(&segments[1..].join("/"))?;
        return Ok((sibling_skill.to_string(), normalized_path));
    }

    Ok((
        requested_skill.to_string(),
        normalize_within_skill(requested_path)?,
    ))
}

fn trim_leading_current_dir(path: &str) -> &str {
    let mut trimmed = path.trim();
    while let Some(rest) = trimmed.strip_prefix("./") {
        trimmed = rest;
    }
    trimmed
}

fn validate_raw_path(path: &str) -> Result<(), SkillAtiError> {
    if path.trim().is_empty() || path.contains('\0') || path.contains('\\') || path.starts_with('/')
    {
        return Err(SkillAtiError::InvalidPath(path.to_string()));
    }
    Ok(())
}

fn normalize_within_skill(path: &str) -> Result<String, SkillAtiError> {
    validate_raw_path(path)?;

    let mut stack: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if stack.pop().is_none() {
                    return Err(SkillAtiError::InvalidPath(path.to_string()));
                }
            }
            value => stack.push(value),
        }
    }

    if stack.is_empty() {
        return Err(SkillAtiError::InvalidPath(path.to_string()));
    }

    Ok(stack.join("/"))
}

#[cfg(test)]
mod tests {
    use super::{
        build_catalog_manifest, catalog_index_candidates, collect_visible_resources,
        default_catalog_index_path, is_visible_resource, map_gcs_error, normalize_within_skill,
        remote_skill_meta_from_parts, resolve_requested_path, search_haystack, skill_directory,
        SkillAtiCatalogEntry, SkillAtiError,
    };
    use crate::core::gcs::GcsError;
    use std::fs;

    #[test]
    fn skill_directory_uses_virtual_scheme() {
        assert_eq!(skill_directory("demo-skill"), "skillati://demo-skill");
    }

    #[test]
    fn normalize_within_skill_rejects_invalid_paths() {
        assert_eq!(
            normalize_within_skill("references/guide.md").unwrap(),
            "references/guide.md"
        );
        assert_eq!(
            normalize_within_skill("./references/./guide.md").unwrap(),
            "references/guide.md"
        );
        assert!(normalize_within_skill("../escape.md").is_err());
        assert!(normalize_within_skill("references/../../escape.md").is_err());
        assert!(normalize_within_skill(r"references\guide.md").is_err());
    }

    #[test]
    fn resolve_requested_path_supports_sibling_skills() {
        assert_eq!(
            resolve_requested_path("react-component-builder", "../ui-design-system/SKILL.md")
                .unwrap(),
            ("ui-design-system".to_string(), "SKILL.md".to_string())
        );
        assert_eq!(
            resolve_requested_path(
                "react-component-builder",
                "../ui-design-system/references/core-principles.md"
            )
            .unwrap(),
            (
                "ui-design-system".to_string(),
                "references/core-principles.md".to_string()
            )
        );
        assert!(matches!(
            resolve_requested_path("a", "../../etc/passwd"),
            Err(SkillAtiError::InvalidPath(_))
        ));
        assert!(matches!(
            resolve_requested_path("a", "../bad name/SKILL.md"),
            Err(SkillAtiError::InvalidPath(_))
        ));
    }

    #[test]
    fn visible_resources_filter_internal_files_and_dirs() {
        assert!(is_visible_resource("references/guide.md"));
        assert!(is_visible_resource("assets/logo.png"));
        assert!(!is_visible_resource("SKILL.md"));
        assert!(!is_visible_resource("skill.toml"));
        assert!(!is_visible_resource("references/"));
    }

    #[test]
    fn map_404_for_skill_md_becomes_skill_not_found() {
        let err = map_gcs_error(
            "demo-skill",
            "SKILL.md",
            GcsError::Api {
                status: 404,
                message: "nope".into(),
            },
        );
        assert!(matches!(err, SkillAtiError::SkillNotFound(name) if name == "demo-skill"));
    }

    #[test]
    fn map_404_for_other_paths_becomes_path_not_found() {
        let err = map_gcs_error(
            "demo-skill",
            "references/guide.md",
            GcsError::Api {
                status: 404,
                message: "nope".into(),
            },
        );
        assert!(
            matches!(err, SkillAtiError::PathNotFound { skill, path } if skill == "demo-skill" && path == "references/guide.md")
        );
    }

    #[test]
    fn search_haystack_includes_keywords_and_bindings() {
        let meta = remote_skill_meta_from_parts(
            "demo-skill",
            "Great for UI panels".to_string(),
            vec!["dashboard".into()],
            vec!["render_panel".into()],
            vec!["frontend".into()],
            vec!["design".into()],
        );
        let haystack = search_haystack(&meta);
        assert!(haystack.contains("dashboard"));
        assert!(haystack.contains("render_panel"));
        assert!(haystack.contains("frontend"));
        assert!(haystack.contains("design"));
    }

    #[test]
    fn env_override_for_catalog_index_candidates_is_supported() {
        unsafe {
            std::env::set_var(
                "ATI_SKILL_REGISTRY_INDEX_OBJECT",
                "custom/one.json, custom/two.json",
            );
        }
        assert_eq!(
            catalog_index_candidates(),
            vec!["custom/one.json".to_string(), "custom/two.json".to_string()]
        );
        unsafe {
            std::env::remove_var("ATI_SKILL_REGISTRY_INDEX_OBJECT");
        }
        assert_eq!(default_catalog_index_path(), "_skillati/catalog.v1.json");
    }

    #[test]
    fn build_catalog_manifest_collects_nested_resources() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        let skill = root.join("demo-skill");
        fs::create_dir_all(skill.join("references/components")).unwrap();
        fs::write(skill.join("SKILL.md"), "# Demo Skill\n\nUseful demo.\n").unwrap();
        fs::write(
            skill.join("skill.toml"),
            "[skill]\nname=\"demo-skill\"\nkeywords=[\"demo\"]\n",
        )
        .unwrap();
        fs::write(
            skill.join("references/components/example.md"),
            "nested reference",
        )
        .unwrap();

        let manifest = build_catalog_manifest(&root).unwrap();
        assert_eq!(manifest.skills.len(), 1);
        assert_eq!(manifest.skills[0].meta.name, "demo-skill");
        assert_eq!(
            manifest.skills[0].resources,
            vec!["references/components/example.md".to_string()]
        );
        assert!(manifest.skills[0].resources_complete);
    }

    #[test]
    fn collect_visible_resources_skips_internal_files() {
        let tmp = tempfile::tempdir().unwrap();
        let skill = tmp.path().join("demo-skill");
        fs::create_dir_all(skill.join("references")).unwrap();
        fs::write(skill.join("SKILL.md"), "x").unwrap();
        fs::write(skill.join("skill.toml"), "x").unwrap();
        fs::write(skill.join(".hidden"), "x").unwrap();
        fs::write(skill.join("references/guide.md"), "x").unwrap();

        let resources = collect_visible_resources(&skill, &skill).unwrap();
        assert_eq!(resources, vec!["references/guide.md".to_string()]);
    }

    #[test]
    fn catalog_entry_sorts_and_dedups_resources() {
        let mut entry = SkillAtiCatalogEntry {
            meta: remote_skill_meta_from_parts(
                "demo-skill",
                "".into(),
                vec!["b".into(), "a".into(), "A".into()],
                vec![],
                vec![],
                vec![],
            ),
            resources: vec![
                "references/b.md".into(),
                "SKILL.md".into(),
                "references/a.md".into(),
                "references/a.md".into(),
            ],
            resources_complete: false,
        };

        super::normalize_catalog_entry(&mut entry);
        assert_eq!(entry.meta.keywords, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(
            entry.resources,
            vec!["references/a.md".to_string(), "references/b.md".to_string()]
        );
    }
}
