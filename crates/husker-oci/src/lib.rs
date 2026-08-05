//! Pull OCI/Docker images from a registry and flatten their layers into a
//! directory tree that can be turned into a bootable husker rootfs.
//!
//! The registry client speaks the OCI distribution HTTP API directly (anonymous
//! pull token, manifest/manifest-list negotiation, config + layer blobs) using
//! `reqwest`, so husker stays self-contained without a heavyweight OCI library.

use std::path::{Path, PathBuf};

use serde::Deserialize;

mod flatten;
mod reference;

pub use flatten::{WhiteoutKind, classify_entry, flatten_layers};
pub use reference::{ImageReference, strip_oci_scheme};

#[derive(Debug, thiserror::Error)]
pub enum OciError {
    #[error("invalid image reference '{0}': {1}")]
    InvalidReference(String, String),
    #[error("registry request failed: {0}")]
    Http(String),
    #[error("registry returned {status} for {url}: {body}")]
    Status {
        status: u16,
        url: String,
        body: String,
    },
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("malformed registry response: {0}")]
    Malformed(String),
    #[error("layer extraction failed: {0}")]
    Extract(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// The runtime configuration extracted from an image's config blob: what the
/// container would run and with what environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageConfig {
    /// `Entrypoint` from the OCI config (may be empty).
    pub entrypoint: Vec<String>,
    /// `Cmd` from the OCI config (may be empty).
    pub cmd: Vec<String>,
    /// `Env` entries as `KEY=VALUE` strings.
    pub env: Vec<String>,
    /// `WorkingDir`, if set.
    pub working_dir: Option<String>,
}

impl ImageConfig {
    /// The effective argv the container would exec: entrypoint followed by cmd.
    /// Empty when the image declares neither (caller should fall back to a shell).
    pub fn argv(&self) -> Vec<String> {
        let mut v = self.entrypoint.clone();
        v.extend(self.cmd.iter().cloned());
        v
    }
}

/// A pulled image: its runtime config plus the raw (gzip-compressed) layer
/// blobs in application order (base layer first).
pub struct PulledImage {
    pub config: ImageConfig,
    pub layers: Vec<Vec<u8>>,
}

// ── OCI config blob parsing ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RawConfigBlob {
    #[serde(default)]
    config: RawInnerConfig,
}

#[derive(Debug, Default, Deserialize)]
struct RawInnerConfig {
    #[serde(rename = "Entrypoint", default)]
    entrypoint: Option<Vec<String>>,
    #[serde(rename = "Cmd", default)]
    cmd: Option<Vec<String>>,
    #[serde(rename = "Env", default)]
    env: Option<Vec<String>>,
    #[serde(rename = "WorkingDir", default)]
    working_dir: Option<String>,
}

/// Parse the runtime config out of an OCI/Docker image config blob (JSON).
pub fn parse_image_config(blob: &[u8]) -> Result<ImageConfig, OciError> {
    let raw: RawConfigBlob = serde_json::from_slice(blob)
        .map_err(|e| OciError::Malformed(format!("config blob: {e}")))?;
    Ok(ImageConfig {
        entrypoint: raw.config.entrypoint.unwrap_or_default(),
        cmd: raw.config.cmd.unwrap_or_default(),
        env: raw.config.env.unwrap_or_default(),
        working_dir: raw.config.working_dir.filter(|s| !s.is_empty()),
    })
}

// ── Registry client ─────────────────────────────────────────────────────────

const ACCEPT_MANIFESTS: &str = "application/vnd.docker.distribution.manifest.v2+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.oci.image.index.v1+json";

#[derive(Debug, Deserialize)]
struct Manifest {
    config: Descriptor,
    #[serde(default)]
    layers: Vec<Descriptor>,
}

#[derive(Debug, Deserialize)]
struct Descriptor {
    digest: String,
    #[serde(default)]
    size: u64,
}

/// Cap on total compressed layer bytes for a single import, bounding memory and
/// download time against hostile or accidental giant images.
const MAX_PULL_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct ManifestIndex {
    manifests: Vec<IndexEntry>,
}

#[derive(Debug, Deserialize)]
struct IndexEntry {
    digest: String,
    #[serde(default)]
    platform: Option<Platform>,
}

#[derive(Debug, Deserialize)]
struct Platform {
    #[serde(default)]
    architecture: String,
    #[serde(default)]
    os: String,
}

/// Pull an image reference for the given target architecture (e.g. `"amd64"`),
/// returning its runtime config and compressed layer blobs.
pub async fn pull_image(reference: &str, arch: &str) -> Result<PulledImage, OciError> {
    let r = ImageReference::parse(reference)?;
    let client = reqwest::Client::builder()
        .user_agent("husker-oci")
        .connect_timeout(std::time::Duration::from_secs(15))
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| OciError::Http(e.to_string()))?;

    let token = fetch_pull_token(&client, &r).await?;

    // Fetch the manifest; resolve a manifest list/index to the arch-specific one.
    let (body, media_type) = get_manifest(&client, &r, &r.reference, &token).await?;
    let manifest: Manifest = if is_index(&media_type, &body) {
        let index: ManifestIndex = serde_json::from_slice(&body)
            .map_err(|e| OciError::Malformed(format!("manifest index: {e}")))?;
        let digest = select_arch_digest(&index, arch)
            .ok_or_else(|| OciError::Unsupported(format!("image has no linux/{arch} manifest")))?;
        let (m, _) = get_manifest(&client, &r, &digest, &token).await?;
        serde_json::from_slice(&m).map_err(|e| OciError::Malformed(format!("manifest: {e}")))?
    } else {
        serde_json::from_slice(&body).map_err(|e| OciError::Malformed(format!("manifest: {e}")))?
    };

    // Bound the total download (declared layer sizes) before fetching anything.
    let declared: u64 = manifest.layers.iter().map(|l| l.size).sum();
    if declared > MAX_PULL_BYTES {
        return Err(OciError::Unsupported(format!(
            "image layers total {declared} bytes, over the {MAX_PULL_BYTES}-byte import limit"
        )));
    }

    let config_blob = get_blob(&client, &r, &manifest.config.digest, &token).await?;
    let config = parse_image_config(&config_blob)?;

    let mut layers = Vec::with_capacity(manifest.layers.len());
    let mut downloaded: u64 = 0;
    for layer in &manifest.layers {
        // gzip and zstd layers are both flattened (codec detected by magic bytes
        // in husker_oci::flatten); other codecs are rejected there.
        let blob = get_blob(&client, &r, &layer.digest, &token).await?;
        // Guard against a registry that under-declares sizes in the manifest.
        downloaded += blob.len() as u64;
        if downloaded > MAX_PULL_BYTES {
            return Err(OciError::Unsupported(format!(
                "image exceeded the {MAX_PULL_BYTES}-byte import limit while downloading"
            )));
        }
        layers.push(blob);
    }

    Ok(PulledImage { config, layers })
}

/// Whether a manifest response is a multi-arch index/list (vs a single image).
fn is_index(media_type: &str, body: &[u8]) -> bool {
    if media_type.contains("manifest.list") || media_type.contains("image.index") {
        return true;
    }
    // Fall back to structural detection when the registry omits the type.
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("manifests").map(|m| m.is_array()))
        .unwrap_or(false)
}

/// Pick the digest of the `linux/<arch>` manifest from an index.
fn select_arch_digest(index: &ManifestIndex, arch: &str) -> Option<String> {
    index
        .manifests
        .iter()
        .find(|e| {
            e.platform
                .as_ref()
                .is_some_and(|p| p.os == "linux" && p.architecture == arch)
        })
        .map(|e| e.digest.clone())
}

async fn fetch_pull_token(
    client: &reqwest::Client,
    r: &ImageReference,
) -> Result<String, OciError> {
    let (token_url, service) = r.auth_endpoint();
    let url = format!(
        "{token_url}?service={service}&scope=repository:{repo}:pull",
        repo = r.repository
    );
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| OciError::Http(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        // A missing token endpoint (404) can mean the registry allows anonymous
        // pulls; any other failure (401/403/429/5xx) is real and must surface
        // rather than masquerade as a confusing later 401.
        if status.as_u16() == 404 {
            return Ok(String::new());
        }
        let body: String = resp
            .text()
            .await
            .unwrap_or_default()
            .chars()
            .take(200)
            .collect();
        return Err(OciError::Status {
            status: status.as_u16(),
            url,
            body,
        });
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| OciError::Malformed(format!("token response: {e}")))?;
    Ok(v.get("token")
        .or_else(|| v.get("access_token"))
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string())
}

async fn get_manifest(
    client: &reqwest::Client,
    r: &ImageReference,
    reference: &str,
    token: &str,
) -> Result<(Vec<u8>, String), OciError> {
    let url = format!(
        "{}/v2/{}/manifests/{reference}",
        r.registry_base(),
        r.repository
    );
    let mut req = client.get(&url).header("Accept", ACCEPT_MANIFESTS);
    if !token.is_empty() {
        req = req.bearer_auth(token);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| OciError::Http(e.to_string()))?;
    let status = resp.status();
    let media_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = resp
        .bytes()
        .await
        .map_err(|e| OciError::Http(e.to_string()))?
        .to_vec();
    if !status.is_success() {
        return Err(OciError::Status {
            status: status.as_u16(),
            url,
            body: String::from_utf8_lossy(&body).chars().take(200).collect(),
        });
    }
    Ok((body, media_type))
}

async fn get_blob(
    client: &reqwest::Client,
    r: &ImageReference,
    digest: &str,
    token: &str,
) -> Result<Vec<u8>, OciError> {
    let url = format!("{}/v2/{}/blobs/{digest}", r.registry_base(), r.repository);
    let mut req = client.get(&url);
    if !token.is_empty() {
        req = req.bearer_auth(token);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| OciError::Http(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(OciError::Status {
            status: status.as_u16(),
            url,
            body: String::new(),
        });
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| OciError::Http(e.to_string()))?
        .to_vec();
    verify_digest(digest, &bytes)?;
    Ok(bytes)
}

/// Verify a blob matches its `sha256:...` content digest.
fn verify_digest(digest: &str, bytes: &[u8]) -> Result<(), OciError> {
    use sha2::{Digest, Sha256};
    let Some(expected) = digest.strip_prefix("sha256:") else {
        // Fail closed: we only verify sha256, so refuse any other algorithm
        // rather than processing an unverified blob.
        return Err(OciError::Unsupported(format!(
            "unsupported digest algorithm (only sha256 is verified): {digest}"
        )));
    };
    let actual = hex_lower(&Sha256::digest(bytes));
    if actual != expected {
        return Err(OciError::Malformed(format!(
            "blob digest mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Convenience: pull `reference` and flatten its layers into `dest_dir`,
/// returning the image's runtime config. `dest_dir` is created if absent.
pub async fn pull_and_flatten(
    reference: &str,
    arch: &str,
    dest_dir: &Path,
) -> Result<ImageConfig, OciError> {
    let image = pull_image(reference, arch).await?;
    let dest: PathBuf = dest_dir.to_path_buf();
    let layers = image.layers;
    // Extraction is blocking filesystem work; keep it off the async reactor.
    tokio::task::spawn_blocking(move || flatten_layers(&layers, &dest))
        .await
        .map_err(|e| OciError::Extract(format!("join: {e}")))??;
    Ok(image.config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_image_config_extracts_entrypoint_cmd_env() {
        let blob = br#"{
            "architecture": "amd64",
            "config": {
                "Entrypoint": ["/bin/myapp"],
                "Cmd": ["--serve"],
                "Env": ["PATH=/usr/bin", "FOO=bar"],
                "WorkingDir": "/app"
            }
        }"#;
        let cfg = parse_image_config(blob).unwrap();
        assert_eq!(cfg.entrypoint, vec!["/bin/myapp"]);
        assert_eq!(cfg.cmd, vec!["--serve"]);
        assert_eq!(cfg.env, vec!["PATH=/usr/bin", "FOO=bar"]);
        assert_eq!(cfg.working_dir.as_deref(), Some("/app"));
        assert_eq!(cfg.argv(), vec!["/bin/myapp", "--serve"]);
    }

    #[test]
    fn parse_image_config_defaults_when_absent() {
        let cfg = parse_image_config(br#"{"config":{}}"#).unwrap();
        assert!(cfg.entrypoint.is_empty());
        assert!(cfg.cmd.is_empty());
        assert!(cfg.working_dir.is_none());
        assert!(cfg.argv().is_empty());
    }

    #[test]
    fn select_arch_digest_picks_linux_arch() {
        let index = ManifestIndex {
            manifests: vec![
                IndexEntry {
                    digest: "sha256:arm".into(),
                    platform: Some(Platform {
                        architecture: "arm64".into(),
                        os: "linux".into(),
                    }),
                },
                IndexEntry {
                    digest: "sha256:amd".into(),
                    platform: Some(Platform {
                        architecture: "amd64".into(),
                        os: "linux".into(),
                    }),
                },
            ],
        };
        assert_eq!(
            select_arch_digest(&index, "amd64").as_deref(),
            Some("sha256:amd")
        );
        assert_eq!(select_arch_digest(&index, "riscv64"), None);
    }

    #[test]
    fn verify_digest_detects_mismatch() {
        // sha256 of "hello" is well-known; a wrong digest must be rejected.
        assert!(verify_digest("sha256:deadbeef", b"hello").is_err());
        // A non-sha256 algorithm fails closed rather than skipping verification.
        assert!(verify_digest("md5:whatever", b"hello").is_err());
    }
}
