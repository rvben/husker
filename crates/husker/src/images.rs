use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

const GITHUB_API_USER_AGENT: &str = concat!("husker/", env!("CARGO_PKG_VERSION"));

/// Prefix used on image-release tags produced by `build-images.yml`.
/// A separate prefix keeps the images releases out of the semver "latest"
/// channel used by `pip install husker` binaries.
const IMAGES_TAG_PREFIX: &str = "images-";

#[derive(Debug, Clone)]
pub struct DownloadSpec {
    pub url: String,
    pub expected_sha256: String,
    pub dest: PathBuf,
}

/// Parse an Alpine-style `SHA256SUMS` manifest: one entry per line as
/// `<sha256>  <filename>`. Lines with fewer than two whitespace-delimited
/// tokens are silently skipped. Filenames with embedded whitespace are
/// not supported — the Alpine convention does not use them.
pub fn parse_manifest(contents: &str) -> HashMap<String, String> {
    contents
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let sha = parts.next()?;
            let name = parts.next()?;
            Some((name.to_string(), sha.to_string()))
        })
        .collect()
}

pub async fn fetch_and_verify(spec: DownloadSpec) -> Result<()> {
    let client = reqwest::Client::builder()
        .build()
        .context("building http client")?;

    let mut resp = client
        .get(&spec.url)
        .send()
        .await
        .with_context(|| format!("GET {}", spec.url))?
        .error_for_status()
        .with_context(|| format!("GET {}", spec.url))?;

    if let Some(parent) = spec.dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating parent dir {}", parent.display()))?;
    }

    let tmp = spec.dest.with_file_name(format!(
        "{}.part",
        spec.dest.file_name().unwrap_or_default().to_string_lossy()
    ));
    let mut file = tokio::fs::File::create(&tmp)
        .await
        .with_context(|| format!("opening {}", tmp.display()))?;

    let mut hasher = Sha256::new();
    while let Some(chunk) = resp.chunk().await.context("reading response chunk")? {
        hasher.update(&chunk);
        file.write_all(&chunk).await.context("writing chunk")?;
    }
    file.flush().await.context("flushing download")?;
    drop(file);

    let got = hex::encode(hasher.finalize());
    if got != spec.expected_sha256 {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(anyhow!(
            "sha256 mismatch for {}: expected {}, got {}",
            spec.dest.display(),
            spec.expected_sha256,
            got,
        ));
    }

    tokio::fs::rename(&tmp, &spec.dest)
        .await
        .with_context(|| format!("renaming {} -> {}", tmp.display(), spec.dest.display()))?;
    Ok(())
}

pub async fn fetch_manifest(base_url: &str) -> Result<HashMap<String, String>> {
    let url = format!("{}/SHA256SUMS", base_url.trim_end_matches('/'));
    let body = reqwest::get(&url)
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("GET {url}"))?
        .text()
        .await
        .with_context(|| format!("reading body {url}"))?;
    Ok(parse_manifest(&body))
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
}

/// Turn the user-configured `images_base_url` into a concrete
/// `…/releases/download/<tag>` base URL. If the input already pins a
/// specific release, return it unchanged. Otherwise treat it as a GitHub
/// repo URL and ask the API for the newest release whose tag starts with
/// `images-`.
pub async fn resolve_download_base(config_url: &str) -> Result<String> {
    let trimmed = config_url.trim_end_matches('/');
    if trimmed.contains("/releases/download/") {
        return Ok(trimmed.to_string());
    }

    let repo_url = trimmed
        .trim_end_matches("/releases/latest/download")
        .trim_end_matches("/releases/latest")
        .trim_end_matches("/releases");
    let repo_path = repo_url
        .strip_prefix("https://github.com/")
        .or_else(|| repo_url.strip_prefix("http://github.com/"))
        .ok_or_else(|| {
            anyhow!(
                "cannot resolve images release from {config_url}: expected \
                 a github.com repo URL or a /releases/download/<tag> URL"
            )
        })?;

    let api_url = format!("https://api.github.com/repos/{repo_path}/releases?per_page=100");
    let client = reqwest::Client::builder()
        .user_agent(GITHUB_API_USER_AGENT)
        .build()
        .context("building http client")?;
    let releases: Vec<GithubRelease> = client
        .get(&api_url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .with_context(|| format!("GET {api_url}"))?
        .error_for_status()
        .with_context(|| format!("GET {api_url}"))?
        .json()
        .await
        .with_context(|| format!("parsing JSON from {api_url}"))?;

    let tag = releases
        .into_iter()
        .map(|r| r.tag_name)
        .filter(|t| t.starts_with(IMAGES_TAG_PREFIX))
        .max()
        .ok_or_else(|| {
            anyhow!(
                "no '{IMAGES_TAG_PREFIX}*' release found at https://github.com/{repo_path} — \
                 the first default images release may not be published yet"
            )
        })?;

    Ok(format!(
        "https://github.com/{repo_path}/releases/download/{tag}"
    ))
}
