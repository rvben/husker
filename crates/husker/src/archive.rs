//! Strict readers for downloaded executables and files returned by guests.
//! Archive creation and OCI layer application have separate format contracts.

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use async_compression::tokio::bufread::GzipDecoder;
use tar_codec::{Archive as _, Member, MemberPayload as _, TarArchive};
use tokio::io::{AsyncReadExt as _, Take};

/// Limit both compressed downloads and the complete decompressed release tar.
pub const MAX_FIRECRACKER_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;

/// Default compressed guest-output transfer limit (256 MiB).
pub const DEFAULT_MAX_OUTPUT_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
/// Default expanded tar limit, including headers and padding (1 GiB).
pub const DEFAULT_MAX_OUTPUT_BYTES: u64 = 1024 * 1024 * 1024;

/// Per-retrieval byte budgets. These bound logical archive bytes, not filesystem
/// allocation; small files and filesystem metadata can consume additional space.
#[derive(Clone, Copy, Debug)]
pub struct OutputLimits {
    pub max_archive_bytes: u64,
    pub max_expanded_bytes: u64,
}

impl Default for OutputLimits {
    fn default() -> Self {
        Self {
            max_archive_bytes: DEFAULT_MAX_OUTPUT_ARCHIVE_BYTES,
            max_expanded_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        }
    }
}

type GzipStream<'a> = Take<GzipDecoder<&'a [u8]>>;

fn gzip(bytes: &[u8], limit: u64) -> GzipStream<'_> {
    GzipDecoder::new(bytes).take(limit + 1)
}

/// Consume padding and the gzip trailer, rejecting hidden archives and bad CRCs.
async fn finish_gzip(reader: &mut GzipStream<'_>) -> Result<()> {
    let mut padding = [0; 8192];
    loop {
        let n = reader
            .read(&mut padding)
            .await
            .context("reading gzip trailer")?;
        if n == 0 {
            break;
        }
        ensure!(
            padding[..n].iter().all(|&b| b == 0),
            "nonzero data after tar end marker"
        );
    }
    ensure!(
        reader.limit() != 0,
        "decompressed archive exceeds its size limit"
    );
    ensure!(
        reader.get_ref().get_ref().is_empty(),
        "data after gzip stream"
    );
    Ok(())
}

fn relative_path(path: &str) -> Result<PathBuf> {
    let mut result = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(name) => result.push(name),
            Component::CurDir => {}
            _ => bail!("unsafe archive path: {path}"),
        }
    }
    Ok(result)
}

/// Read exactly one regular executable from a verified Firecracker release.
/// Parsing completes before the caller can install anything. Links, duplicate
/// binaries, malformed later entries, and trailing compressed data are errors.
pub async fn firecracker_binary(bytes: Vec<u8>, binary_name: String) -> Result<Vec<u8>> {
    // tar-codec's lending futures need not be Send. Keep them on a blocking
    // worker's local executor, also keeping decompression off runtime workers.
    tokio::task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(read_firecracker(&bytes, &binary_name))
    })
    .await
    .context("release archive task")?
}

async fn read_firecracker(bytes: &[u8], binary_name: &str) -> Result<Vec<u8>> {
    ensure!(
        bytes.len() as u64 <= MAX_FIRECRACKER_ARCHIVE_BYTES,
        "release download exceeds its size limit"
    );
    let mut reader = gzip(bytes, MAX_FIRECRACKER_ARCHIVE_BYTES);
    let mut binary = None;
    {
        let mut members = TarArchive::new(&mut reader).members();
        let mut chunk = Vec::new();
        while let Some(member) = members.next().await.context("reading release archive")? {
            relative_path(&member.metadata().path)?;
            match member {
                Member::File {
                    metadata,
                    size,
                    mut payload,
                    ..
                } => {
                    if Path::new(&metadata.path).file_name() == Some(binary_name.as_ref()) {
                        ensure!(
                            binary.is_none(),
                            "duplicate {binary_name} in release archive"
                        );
                        ensure!(
                            size > 0 && size <= MAX_FIRECRACKER_ARCHIVE_BYTES,
                            "invalid executable size"
                        );
                        let mut data = Vec::new();
                        while payload.next_chunk(&mut chunk, 64 * 1024).await? {
                            data.extend_from_slice(&chunk);
                        }
                        binary = Some(data);
                    } else {
                        payload.skip().await?;
                    }
                }
                Member::Directory { .. } => {}
                _ => bail!("release archive must contain only regular files and directories"),
            }
        }
    }
    finish_gzip(&mut reader).await?;
    binary.with_context(|| format!("{binary_name} not found in release archive"))
}

/// Copy guest outputs over a working directory using capability-confined
/// extraction. Validate the complete tar and gzip before changing the tree.
/// Safe native symlinks and archive-local hard links are retained; special
/// files and paths escaping the destination are rejected rather than skipped.
/// As with tar-codec itself, callers must ensure exclusive access to `dst`.
pub async fn extract_outputs(bytes: Vec<u8>, dst: PathBuf) -> Result<Vec<String>> {
    extract_outputs_with_limits(bytes, dst, OutputLimits::default()).await
}

/// Extract with explicit compressed and expanded byte budgets. Limit failures
/// are detected in preflight, before any destination files are changed.
pub async fn extract_outputs_with_limits(
    bytes: Vec<u8>,
    dst: PathBuf,
    limits: OutputLimits,
) -> Result<Vec<String>> {
    ensure!(
        limits.max_archive_bytes > 0,
        "output archive limit must be positive"
    );
    ensure!(
        limits.max_expanded_bytes > 0 && limits.max_expanded_bytes < u64::MAX,
        "expanded output limit must be between 1 and {} bytes",
        u64::MAX - 1
    );
    ensure!(
        bytes.len() as u64 <= limits.max_archive_bytes,
        "compressed guest outputs exceed --max-output-archive-bytes ({} bytes)",
        limits.max_archive_bytes
    );
    tokio::task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(extract_outputs_local(&bytes, &dst, limits))
    })
    .await
    .context("guest archive task")?
}

async fn extract_outputs_local(
    bytes: &[u8],
    dst: &Path,
    limits: OutputLimits,
) -> Result<Vec<String>> {
    // Outputs can be large. Stream payload validation without buffering their
    // expanded contents; the transfer already holds the compressed archive.
    let mut reader = gzip(bytes, limits.max_expanded_bytes);
    let validation = validate_outputs(&mut reader).await;
    ensure!(
        reader.limit() != 0,
        "expanded guest outputs exceed --max-output-bytes ({} bytes, including tar headers and padding)",
        limits.max_expanded_bytes
    );
    let written = validation?;

    let policy = tar_codec::extract::ExtractPolicy::default().link_policy(
        tar_codec::extract::LinkPolicy::default()
            // Guest tar can coalesce identical inodes. tar-codec only permits
            // hard-link targets established within this archive, under dst.
            .allow_hard_links(true)
            // This flag affects symbolic-link targets only; hard links still
            // cannot alias pre-existing working-tree files.
            .allow_ambient_targets(true),
    );
    TarArchive::new(gzip(bytes, limits.max_expanded_bytes))
        .extract_in(dst, policy)
        .await
        .context("extracting guest outputs")?;
    Ok(written)
}

async fn validate_outputs(reader: &mut GzipStream<'_>) -> Result<Vec<String>> {
    let mut written = Vec::new();
    {
        let mut members = TarArchive::new(&mut *reader).members();
        while let Some(member) = members
            .next()
            .await
            .context("reading guest output archive")?
        {
            let path = relative_path(&member.metadata().path)?;
            match member {
                Member::File { payload, .. } => {
                    ensure!(!path.as_os_str().is_empty(), "empty output file path");
                    written.push(path.to_string_lossy().into_owned());
                    payload.skip().await?;
                }
                Member::HardLink { payload, .. } => payload.skip().await?,
                Member::Directory { .. } | Member::SymbolicLink { .. } => {}
                Member::Special { .. } => bail!("special files are not supported in guest outputs"),
            }
        }
    }
    finish_gzip(reader).await?;
    Ok(written)
}
