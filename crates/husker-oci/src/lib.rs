//! Pull OCI/Docker images from a registry and flatten their layers into a
//! directory tree that can be turned into a bootable husker rootfs.
//!
//! The registry client speaks the OCI distribution HTTP API directly (anonymous
//! pull token, manifest/manifest-list negotiation, config + layer blobs) using
//! `reqwest`, so husker stays self-contained without a heavyweight OCI library.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

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
    /// A registry response outside the 2xx range. `detail` is the OCI error
    /// document's codes and messages when the body carries one and the HTTP
    /// reason phrase otherwise, never the body itself.
    #[error("registry returned {status} for {url}: {detail}")]
    Status {
        status: u16,
        url: String,
        detail: String,
    },
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("malformed registry response: {0}")]
    Malformed(String),
    #[error("image is larger than the {limit}-byte download limit")]
    DownloadTooLarge { limit: u64 },
    #[error("image unpacks to more than the {limit}-byte limit")]
    UnpackedTooLarge { limit: u64 },
    #[error("layer extraction failed: {0}")]
    Extract(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Caps on one import, chosen by the caller: the bytes downloaded from the
/// registry (config and layers together, as served) and the archive bytes the
/// layers may unpack to between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportLimits {
    pub max_download_bytes: u64,
    pub max_unpacked_bytes: u64,
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

/// A pulled image: its runtime config plus the compressed layer blobs, spooled
/// to files in application order (base layer first).
pub struct PulledImage {
    pub config: ImageConfig,
    pub layers: Vec<PathBuf>,
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

/// The most a token response may be; a real one is a few hundred bytes.
const MAX_TOKEN_BYTES: usize = 64 * 1024;

/// The most a manifest or index may be. The OCI distribution spec has
/// registries reject manifests above 4 MiB, so a larger one is not an image.
const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;

/// How much of an error body is read to look for the OCI error document.
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

/// Bytes received from the registry for one image, charged as they arrive.
struct PullBudget {
    used: u64,
    limit: u64,
}

impl PullBudget {
    fn new(limit: u64) -> Self {
        Self { used: 0, limit }
    }

    fn charge(&mut self, bytes: u64) -> Result<(), OciError> {
        self.used = self.used.saturating_add(bytes);
        if self.used > self.limit {
            return Err(OciError::DownloadTooLarge { limit: self.limit });
        }
        Ok(())
    }
}

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
/// returning its runtime config and the paths of its compressed layer blobs,
/// spooled under `spool_dir` (created if absent) so that no layer is held in
/// memory. The config blob and the layers together may not exceed
/// `max_download_bytes`: the manifest's declared sizes are checked before any
/// fetch, and the bytes actually received are charged as they arrive, so a
/// registry that under-declares sizes is still cut off at the limit. A pull
/// that fails removes every spool file it wrote.
pub async fn pull_image(
    reference: &str,
    arch: &str,
    spool_dir: &Path,
    max_download_bytes: u64,
) -> Result<PulledImage, OciError> {
    let r = ImageReference::parse(reference)?;
    let client = reqwest::Client::builder()
        .user_agent("husker-oci")
        .connect_timeout(std::time::Duration::from_secs(15))
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| OciError::Http(e.to_string()))?;

    // Public registries need not have a token endpoint. For example, Google's
    // Artifact Registry serves public manifests anonymously, while /token is
    // an unrelated HTML page. Ask for the manifest before trying authentication;
    // only an authentication challenge warrants a token request.
    let (token, (body, media_type)) = match get_manifest(&client, &r, &r.reference, "").await {
        Ok(manifest) => (String::new(), manifest),
        Err(OciError::Status { status: 401, .. }) => {
            let token = fetch_pull_token(&client, &r).await?;
            let manifest = get_manifest(&client, &r, &r.reference, &token).await?;
            (token, manifest)
        }
        Err(error) => return Err(error),
    };

    // Resolve a manifest list/index to the arch-specific manifest.
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

    // Refuse an image whose manifest already declares more than the limit
    // before fetching anything. The declared sizes are the registry's claim,
    // not a bound, so the bytes received are charged again below.
    let declared = manifest
        .layers
        .iter()
        .fold(manifest.config.size, |sum, l| sum.saturating_add(l.size));
    if declared > max_download_bytes {
        return Err(OciError::DownloadTooLarge {
            limit: max_download_bytes,
        });
    }
    let mut budget = PullBudget::new(max_download_bytes);

    let mut config_blob = Vec::new();
    download_blob(
        &client,
        &r,
        &manifest.config.digest,
        &token,
        &mut config_blob,
        &mut budget,
    )
    .await?;
    let config = parse_image_config(&config_blob)?;

    tokio::fs::create_dir_all(spool_dir).await?;
    let mut layers = Vec::with_capacity(manifest.layers.len());
    for (index, layer) in manifest.layers.iter().enumerate() {
        // gzip and zstd layers are both flattened (codec detected by magic bytes
        // in husker_oci::flatten); other codecs are rejected there. Spool files
        // are named by position, never by the manifest's digest string, so a
        // hostile manifest cannot choose a path. The path is recorded before
        // the download so that a partial file is unwound with the rest.
        let path = spool_dir.join(format!("layer-{index}"));
        layers.push(path.clone());
        if let Err(e) = spool_blob(&client, &r, &layer.digest, &token, &path, &mut budget).await {
            for path in &layers {
                // The pull error is the one to report; a spool file that
                // cannot be removed changes nothing about it.
                let _ = tokio::fs::remove_file(path).await;
            }
            return Err(e);
        }
    }

    Ok(PulledImage { config, layers })
}

/// Download one blob into a new file at `path`.
async fn spool_blob(
    client: &reqwest::Client,
    r: &ImageReference,
    digest: &str,
    token: &str,
    path: &Path,
    budget: &mut PullBudget,
) -> Result<(), OciError> {
    let mut file =
        tokio::io::BufWriter::with_capacity(1024 * 1024, tokio::fs::File::create(path).await?);
    download_blob(client, r, digest, token, &mut file, budget).await?;
    file.flush().await?;
    Ok(())
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
    let mut resp = client
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
        return Err(registry_error(status, url, resp).await);
    }
    let body = read_body(&mut resp, MAX_TOKEN_BYTES, "token response").await?;
    let v: serde_json::Value = serde_json::from_slice(&body)
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
    let mut resp = req
        .send()
        .await
        .map_err(|e| OciError::Http(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(registry_error(status, url, resp).await);
    }
    let media_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = read_body(&mut resp, MAX_MANIFEST_BYTES, "manifest").await?;
    Ok((body, media_type))
}

/// Stream a blob into `sink`, charging its bytes to `budget` as they arrive and
/// checking the sha256 digest once the body ends. A digest with any other
/// algorithm is refused before the request is made.
async fn download_blob<W: tokio::io::AsyncWrite + Unpin>(
    client: &reqwest::Client,
    r: &ImageReference,
    digest: &str,
    token: &str,
    sink: &mut W,
    budget: &mut PullBudget,
) -> Result<(), OciError> {
    let expected = expected_sha256(digest)?;
    let url = format!("{}/v2/{}/blobs/{digest}", r.registry_base(), r.repository);
    let mut req = client.get(&url);
    if !token.is_empty() {
        req = req.bearer_auth(token);
    }
    let mut resp = req
        .send()
        .await
        .map_err(|e| OciError::Http(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(registry_error(status, url, resp).await);
    }
    let mut hasher = Sha256::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| OciError::Http(e.to_string()))?
    {
        budget.charge(chunk.len() as u64)?;
        hasher.update(&chunk);
        sink.write_all(&chunk).await?;
    }
    verify_sha256(expected, &hasher.finalize())
}

/// Read at most `max` bytes of a response body. A longer body is an error, so
/// a registry cannot make the client buffer an unbounded document.
async fn read_body(
    resp: &mut reqwest::Response,
    max: usize,
    what: &str,
) -> Result<Vec<u8>, OciError> {
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| OciError::Http(e.to_string()))?
    {
        if body.len() + chunk.len() > max {
            return Err(OciError::Malformed(format!(
                "{what} larger than {max} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Turn a failed registry response into `OciError::Status` without echoing
/// its body: only the OCI error document's codes and messages are kept, and a
/// body that carries none (or cannot be read) yields the HTTP reason phrase.
async fn registry_error(
    status: reqwest::StatusCode,
    url: String,
    mut resp: reqwest::Response,
) -> OciError {
    let body = read_body(&mut resp, MAX_ERROR_BODY_BYTES, "error body")
        .await
        .unwrap_or_default();
    OciError::Status {
        status: status.as_u16(),
        url,
        detail: registry_error_detail(status, &body),
    }
}

/// The detail reported for a failed registry response: `code: message` for each
/// entry of the OCI error document (`{"errors":[{"code":..,"message":..}]}`),
/// bounded in count and length and stripped of control characters, or the
/// status's reason phrase when the body is not such a document.
fn registry_error_detail(status: reqwest::StatusCode, body: &[u8]) -> String {
    const MAX_ENTRIES: usize = 3;
    const MAX_CODE_CHARS: usize = 64;
    const MAX_MESSAGE_CHARS: usize = 200;

    #[derive(Deserialize)]
    struct Document {
        #[serde(default)]
        errors: Vec<Entry>,
    }
    #[derive(Deserialize)]
    struct Entry {
        #[serde(default)]
        code: String,
        #[serde(default)]
        message: String,
    }

    let entries: Vec<String> = serde_json::from_slice::<Document>(body)
        .map(|d| d.errors)
        .unwrap_or_default()
        .iter()
        .take(MAX_ENTRIES)
        .filter_map(|e| {
            let code = printable_prefix(&e.code, MAX_CODE_CHARS);
            let message = printable_prefix(&e.message, MAX_MESSAGE_CHARS);
            match (code.is_empty(), message.is_empty()) {
                (true, true) => None,
                (false, true) => Some(code),
                (true, false) => Some(message),
                (false, false) => Some(format!("{code}: {message}")),
            }
        })
        .collect();
    if entries.is_empty() {
        return status
            .canonical_reason()
            .unwrap_or("no reason given")
            .to_string();
    }
    entries.join("; ")
}

/// At most `max` characters of a registry-supplied string, control characters
/// dropped so it cannot carry terminal escapes or line breaks into a log.
fn printable_prefix(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect::<String>()
        .trim()
        .to_string()
}

/// The hex digest a `sha256:<hex>` descriptor expects. Only sha256 is
/// verified, so any other algorithm is refused before its blob is fetched
/// rather than processed unverified.
fn expected_sha256(digest: &str) -> Result<&str, OciError> {
    digest.strip_prefix("sha256:").ok_or_else(|| {
        OciError::Unsupported(format!(
            "unsupported digest algorithm (only sha256 is verified): {digest}"
        ))
    })
}

/// Compare the hex digest a descriptor expects with the hash of the bytes
/// received.
fn verify_sha256(expected: &str, actual: &[u8]) -> Result<(), OciError> {
    let actual = hex_lower(actual);
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

/// Pull `reference`, spooling its blobs under `spool_dir`, and flatten the
/// layers into `dest_dir` (created if absent) under `limits`, returning the
/// image's runtime config. Each spooled layer is unlinked as soon as it is
/// open, so the spool frees itself layer by layer and holds nothing once this
/// returns, whatever the outcome.
pub async fn pull_and_flatten(
    reference: &str,
    arch: &str,
    spool_dir: &Path,
    dest_dir: &Path,
    limits: ImportLimits,
) -> Result<ImageConfig, OciError> {
    let image = pull_image(reference, arch, spool_dir, limits.max_download_bytes).await?;
    let dest: PathBuf = dest_dir.to_path_buf();
    let layers = image.layers;
    // Extraction is blocking filesystem work; keep it off the async reactor.
    tokio::task::spawn_blocking(move || {
        // Open, then unlink: the descriptor keeps the bytes until the layer
        // has been applied and the file is dropped. Every path is unlinked
        // before the first failure is reported.
        let opened: Vec<std::io::Result<_>> = layers
            .iter()
            .map(|path| {
                let file = std::fs::File::open(path);
                let removed = std::fs::remove_file(path);
                file.and_then(|f| removed.map(|()| std::io::BufReader::new(f)))
            })
            .collect();
        let readers = opened.into_iter().collect::<Result<Vec<_>, _>>()?;
        flatten_layers(readers, &dest, limits.max_unpacked_bytes)
    })
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
    fn digest_checks_fail_closed() {
        // A non-sha256 algorithm is refused rather than skipped.
        assert!(expected_sha256("md5:whatever").is_err());
        assert_eq!(expected_sha256("sha256:abc").unwrap(), "abc");
        // sha256 of "hello" is well-known; a wrong digest must be rejected.
        let hello = Sha256::digest(b"hello");
        assert!(verify_sha256("deadbeef", &hello).is_err());
        verify_sha256(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            &hello,
        )
        .unwrap();
    }

    #[test]
    fn pull_budget_cuts_off_past_the_limit() {
        let mut budget = PullBudget::new(100);
        budget.charge(60).unwrap();
        budget.charge(40).unwrap();
        assert!(matches!(
            budget.charge(1),
            Err(OciError::DownloadTooLarge { limit: 100 })
        ));
    }

    #[test]
    fn registry_error_detail_reports_the_oci_error_document() {
        let body = br#"{"errors":[
            {"code":"UNAUTHORIZED","message":"authentication required","detail":{"x":1}},
            {"code":"DENIED"},
            {"message":"just a message"}
        ]}"#;
        assert_eq!(
            registry_error_detail(reqwest::StatusCode::UNAUTHORIZED, body),
            "UNAUTHORIZED: authentication required; DENIED; just a message"
        );
    }

    #[test]
    fn registry_error_detail_never_echoes_an_unstructured_body() {
        let html = b"<html><body>Please visit evil.example</body></html>";
        assert_eq!(
            registry_error_detail(reqwest::StatusCode::UNAUTHORIZED, html),
            "Unauthorized"
        );
        assert_eq!(
            registry_error_detail(reqwest::StatusCode::BAD_GATEWAY, b""),
            "Bad Gateway"
        );
        // An error document with no usable entry falls back the same way.
        assert_eq!(
            registry_error_detail(reqwest::StatusCode::NOT_FOUND, br#"{"errors":[{}]}"#),
            "Not Found"
        );
    }

    #[test]
    fn registry_error_detail_bounds_and_cleans_each_entry() {
        let long = "m".repeat(500);
        let body = format!(
            r#"{{"errors":[{{"code":"A\u001b[31m\nB","message":"{long}"}},{{"code":"2"}},{{"code":"3"}},{{"code":"4"}}]}}"#
        );
        let detail = registry_error_detail(reqwest::StatusCode::FORBIDDEN, body.as_bytes());
        assert!(
            detail.starts_with("A[31mB: "),
            "control characters dropped: {detail}"
        );
        assert!(!detail.contains('\u{1b}') && !detail.contains('\n'));
        assert!(detail.contains("; 2; 3"), "{detail}");
        assert!(!detail.contains("; 4"), "at most three entries: {detail}");
        let message = detail
            .split(": ")
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        assert_eq!(message.len(), 200, "message capped at 200 characters");
    }
}
