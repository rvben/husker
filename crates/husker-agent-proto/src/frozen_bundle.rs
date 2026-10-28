//! Frozen bundle v1: canonical uncompressed USTAR containing regular files only.
//! Never call a general-purpose archive unpacker on factory inputs. Decode and
//! authenticate the complete archive before creating any destination files.
use std::collections::BTreeMap;
use std::io::{self, Read};

use sha2::{Digest, Sha256};

pub const MAX_BUNDLE_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_BUNDLE_FILES: usize = 8192;
pub const MAX_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;

pub fn excluded_bundle_component(part: &str) -> bool {
    matches!(
        part,
        ".git"
            | ".ssh"
            | ".aws"
            | ".azure"
            | ".config"
            | ".codex"
            | ".claude"
            | ".gnupg"
            | ".kube"
            | ".docker"
            | ".netrc"
            | ".npmrc"
            | ".pypirc"
            | ".gitconfig"
            | ".git-credentials"
            | "credentials.json"
            | "auth.json"
    ) || part == ".env"
        || part.starts_with(".env.")
}

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("invalid frozen bundle: {0}")]
    Invalid(&'static str),
    #[error("frozen bundle I/O: {0}")]
    Io(#[from] io::Error),
}

/// This is a denylist for common credential material, not a secret scanner.
/// Operators must still review what they choose to freeze.
pub fn safe_bundle_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 255
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && !path.split('/').any(|part| {
            part.is_empty() || matches!(part, "." | "..") || excluded_bundle_component(part)
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleFile {
    pub data: Vec<u8>,
    pub executable: bool,
}

#[derive(Debug)]
pub struct CollectedArtifact {
    pub data: Vec<u8>,
    pub digest: String,
}

/// Private fields mean extraction can consume only fully validated inputs.
#[derive(Debug, Clone)]
pub struct FrozenBundle {
    files: BTreeMap<String, BundleFile>,
    bytes: Vec<u8>,
    digest: String,
}

impl FrozenBundle {
    pub fn from_files(files: BTreeMap<String, BundleFile>) -> Result<Self, BundleError> {
        validate_files(&files)?;
        let bytes = encode(&files)?;
        let digest = digest(&bytes);
        Ok(Self {
            files,
            bytes,
            digest,
        })
    }

    /// Expected identity is supplied by the frozen execution specification,
    /// rather than trusted from an upload's self-reported digest.
    pub fn decode(
        bytes: Vec<u8>,
        expected_digest: &str,
        expected_size: u64,
    ) -> Result<Self, BundleError> {
        if bytes.len() > MAX_BUNDLE_BYTES || bytes.len() as u64 != expected_size {
            return Err(BundleError::Invalid(
                "size mismatch or archive exceeds 32 MiB",
            ));
        }
        if digest(&bytes) != expected_digest {
            return Err(BundleError::Invalid("digest mismatch"));
        }
        let mut archive = tar::Archive::new(bytes.as_slice());
        let mut files = BTreeMap::new();
        let mut expanded = 0usize;
        for entry in archive.entries()?.raw(true) {
            let mut entry = entry?;
            if files.len() >= MAX_BUNDLE_FILES || !entry.header().entry_type().is_file() {
                return Err(BundleError::Invalid("only bounded regular files allowed"));
            }
            let path = String::from_utf8(entry.path_bytes().to_vec())
                .map_err(|_| BundleError::Invalid("paths must be UTF-8"))?;
            if !safe_bundle_path(&path) || files.contains_key(&path) {
                return Err(BundleError::Invalid("unsafe or duplicate path"));
            }
            let size = usize::try_from(entry.size())
                .map_err(|_| BundleError::Invalid("file size overflow"))?;
            expanded = expanded
                .checked_add(size)
                .ok_or(BundleError::Invalid("size overflow"))?;
            if expanded > MAX_BUNDLE_BYTES {
                return Err(BundleError::Invalid("expanded archive exceeds 32 MiB"));
            }
            let executable = match entry.header().mode()? {
                0o644 => false,
                0o755 => true,
                _ => return Err(BundleError::Invalid("file mode must be 0644 or 0755")),
            };
            let mut data = Vec::with_capacity(size);
            entry.read_to_end(&mut data)?;
            if data.len() != size {
                return Err(BundleError::Invalid("incomplete file"));
            }
            files.insert(path, BundleFile { data, executable });
        }
        validate_files(&files)?;
        // Exact re-encoding rejects PAX/GNU extensions, alternate ownership,
        // timestamps, ordering, padding, trailing archives and hidden metadata.
        if encode(&files)? != bytes {
            return Err(BundleError::Invalid(
                "archive is not canonical frozen bundle v1",
            ));
        }
        Ok(Self {
            files,
            digest: expected_digest.into(),
            bytes,
        })
    }

    pub fn files(&self) -> &BTreeMap<String, BundleFile> {
        &self.files
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn validate_files(files: &BTreeMap<String, BundleFile>) -> Result<(), BundleError> {
    if files.len() > MAX_BUNDLE_FILES {
        return Err(BundleError::Invalid("more than 8192 files"));
    }
    let mut archive_size = 1024usize;
    for (path, file) in files {
        if file.data.len() > MAX_BUNDLE_BYTES {
            return Err(BundleError::Invalid("file exceeds 32 MiB"));
        }
        if !safe_bundle_path(path) {
            return Err(BundleError::Invalid("unsafe path"));
        }
        for (index, _) in path.match_indices('/') {
            if files.contains_key(&path[..index]) {
                return Err(BundleError::Invalid("file used as a parent directory"));
            }
        }
        archive_size = archive_size
            .checked_add(512 + file.data.len().div_ceil(512) * 512)
            .ok_or(BundleError::Invalid("size overflow"))?;
        if archive_size > MAX_BUNDLE_BYTES {
            return Err(BundleError::Invalid("archive exceeds 32 MiB"));
        }
    }
    Ok(())
}

fn encode(files: &BTreeMap<String, BundleFile>) -> Result<Vec<u8>, BundleError> {
    let mut archive = tar::Builder::new(Vec::new());
    for (path, file) in files {
        let mut header = tar::Header::new_ustar();
        header.set_path(path)?; // No GNU long-name fallback.
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(file.data.len() as u64);
        header.set_mode(if file.executable { 0o755 } else { 0o644 });
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        archive.append(&header, file.data.as_slice())?;
    }
    Ok(archive.into_inner()?)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[path = "frozen_bundle_fs.rs"]
mod filesystem;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use filesystem::collect_declared_artifact;
