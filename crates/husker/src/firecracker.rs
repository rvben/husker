#![cfg(all(target_os = "linux", feature = "linux-net"))]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use flate2::read::GzDecoder;
use futures_util::StreamExt;
use tar::Archive;

pub const FIRECRACKER_VERSION: &str = "v1.10.1";

fn binary_name() -> String {
    format!(
        "firecracker-{}-{}",
        FIRECRACKER_VERSION,
        std::env::consts::ARCH
    )
}

pub fn firecracker_download_url() -> String {
    format!(
        "https://github.com/firecracker-microvm/firecracker/releases/download/{v}/{n}.tgz",
        v = FIRECRACKER_VERSION,
        n = binary_name(),
    )
}

/// Download the pinned Firecracker release, extract the `firecracker` binary,
/// and install it at `data_dir/bin/firecracker`. Returns the installed path.
///
/// SHA-256 verification is intentionally out of scope for v0.1.0; the release
/// tarball is fetched directly from the official Firecracker GitHub release.
pub async fn install(data_dir: &Path) -> Result<PathBuf> {
    let url = firecracker_download_url();
    let bin_dir = data_dir.join("bin");
    tokio::fs::create_dir_all(&bin_dir)
        .await
        .with_context(|| format!("creating {}", bin_dir.display()))?;
    let dest = bin_dir.join("firecracker");

    eprintln!("Downloading {url}");
    let response = reqwest::get(&url)
        .await
        .with_context(|| format!("GET {url}"))?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "download failed: HTTP {} for {url}",
            response.status()
        ));
    }

    // Collect into memory — Firecracker tgz is ~2 MiB, fine for v0.1.0.
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        body.extend_from_slice(&chunk.context("reading response chunk")?);
    }

    // Build the expected entry name so it can be captured into the closure.
    let target_name = binary_name();

    // Extract on a blocking pool — tar+flate2 are synchronous.
    let dest_clone = dest.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let gz = GzDecoder::new(&body[..]);
        let mut archive = Archive::new(gz);
        for entry in archive.entries().context("iterating tar")? {
            let mut entry = entry.context("reading tar entry")?;
            let path = entry.path().context("entry path")?;
            let is_match = path
                .file_name()
                .and_then(|s| s.to_str())
                .map(|s| s == target_name)
                .unwrap_or(false);
            if !is_match {
                continue;
            }
            entry
                .unpack(&dest_clone)
                .with_context(|| format!("unpacking to {}", dest_clone.display()))?;
            let mut perms = std::fs::metadata(&dest_clone)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&dest_clone, perms)?;
            return Ok(());
        }
        Err(anyhow!("{target_name} not found in {url}"))
    })
    .await
    .context("extraction task join")??;

    Ok(dest)
}
