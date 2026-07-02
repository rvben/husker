#![cfg(all(target_os = "linux", feature = "linux-net"))]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use flate2::read::GzDecoder;
use futures_util::StreamExt;
use tar::Archive;

// `husker fork` overrides the host TAP name on `/snapshot/load` via the
// `network_overrides` field, added in Firecracker 1.12.0 (PR #4731), so the
// pinned binary must be >= 1.12.0. Pin a recent stable.
pub const FIRECRACKER_VERSION: &str = "v1.16.0";

// SHA-256 of the pinned release tarballs, taken from the official per-asset
// `firecracker-v1.16.0-<arch>.tgz.sha256.txt` published on the GitHub release.
// The downloaded tarball is verified against these before it is extracted and
// executed as the hypervisor process for every VM. Update both when bumping
// FIRECRACKER_VERSION.
const FIRECRACKER_SHA256_X86_64: &str =
    "bd04e26952d4e158085778c6230a0b383d2619c319182e27eaa9d61a212e92d6";
const FIRECRACKER_SHA256_AARCH64: &str =
    "531c713cdbc37d4b8bc2533d851aabc0267096afa1768086a37672abb668efd7";

/// Pinned tarball checksum for the current architecture, or `None` on an arch
/// Firecracker does not ship (in which case the download URL would 404 anyway).
fn expected_tarball_sha256() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Some(FIRECRACKER_SHA256_X86_64),
        "aarch64" => Some(FIRECRACKER_SHA256_AARCH64),
        _ => None,
    }
}

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

/// Download the pinned Firecracker release, verify it against the pinned
/// SHA-256, extract the `firecracker` binary, and install it at
/// `data_dir/bin/firecracker`. Returns the installed path.
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

    // Collect into memory — Firecracker tgz is ~2 MiB.
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        body.extend_from_slice(&chunk.context("reading response chunk")?);
    }

    // Verify the download against the pinned checksum BEFORE extracting and
    // executing it. This binary becomes the hypervisor process for every VM, so a
    // substituted tarball (compromised release/CDN, or a MITM on a host with
    // broken TLS validation) must be rejected rather than run.
    let Some(expected) = expected_tarball_sha256() else {
        return Err(anyhow!(
            "no pinned firecracker checksum for architecture {}",
            std::env::consts::ARCH
        ));
    };
    let got = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&body);
        hex::encode(hasher.finalize())
    };
    if got != expected {
        return Err(anyhow!(
            "firecracker download checksum mismatch for {url}: expected {expected}, got {got}"
        ));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_checksums_are_well_formed() {
        for sha in [FIRECRACKER_SHA256_X86_64, FIRECRACKER_SHA256_AARCH64] {
            assert_eq!(sha.len(), 64, "sha256 must be 64 hex chars: {sha}");
            assert!(
                sha.chars().all(|c| c.is_ascii_hexdigit()),
                "non-hex in {sha}"
            );
        }
    }

    #[test]
    fn expected_checksum_present_for_supported_arch() {
        // Firecracker ships x86_64 and aarch64 only; both must be pinned.
        if matches!(std::env::consts::ARCH, "x86_64" | "aarch64") {
            assert!(expected_tarball_sha256().is_some());
        }
    }
}
