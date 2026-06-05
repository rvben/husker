//! Storage utilities for validating kernels/rootfs images and cloning VM root disks.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("rootfs not found: {0}")]
    RootfsNotFound(PathBuf),
    #[error("kernel not found: {0}")]
    KernelNotFound(PathBuf),
    #[error("{0}")]
    InvalidKernel(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("command failed: {0}")]
    CommandFailed(String),
}

pub type StorageFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Abstraction for storage backends used to prepare VM root disks.
pub trait StorageDriver: Send + Sync {
    fn name(&self) -> &'static str;

    fn clone_rootfs<'a>(
        &'a self,
        source: &'a Path,
        dest: &'a Path,
    ) -> StorageFuture<'a, Result<(), StorageError>>;
}

/// Default local storage driver backed by reflink-or-copy filesystem cloning.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalStorageDriver;

impl StorageDriver for LocalStorageDriver {
    fn name(&self) -> &'static str {
        "local-reflink"
    }

    fn clone_rootfs<'a>(
        &'a self,
        source: &'a Path,
        dest: &'a Path,
    ) -> StorageFuture<'a, Result<(), StorageError>> {
        Box::pin(async move { clone_rootfs_impl(source, dest).await })
    }
}

pub fn default_storage_driver() -> Arc<dyn StorageDriver> {
    Arc::new(LocalStorageDriver)
}

/// Manages rootfs images and kernel files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Base directory for storing images and kernels.
    pub data_dir: PathBuf,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("/var/lib/husker"),
        }
    }
}

impl StorageConfig {
    pub fn images_dir(&self) -> PathBuf {
        self.data_dir.join("images")
    }

    pub fn kernels_dir(&self) -> PathBuf {
        self.data_dir.join("kernels")
    }

    pub fn vm_dir(&self, vm_name: &str) -> PathBuf {
        self.data_dir.join("vms").join(vm_name)
    }
}

/// Create a copy-on-write clone of a rootfs for a VM.
///
/// Uses reflink (clonefile on macOS/APFS, FICLONE on Linux/btrfs/XFS) when the
/// filesystem supports it, falling back to a regular copy otherwise.
pub async fn clone_rootfs(source: &Path, dest: &Path) -> Result<(), StorageError> {
    let driver = LocalStorageDriver;
    driver.clone_rootfs(source, dest).await
}

async fn clone_rootfs_impl(source: &Path, dest: &Path) -> Result<(), StorageError> {
    if !source.exists() {
        return Err(StorageError::RootfsNotFound(source.to_owned()));
    }

    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let src = source.to_owned();
    let dst = dest.to_owned();
    tokio::task::spawn_blocking(move || reflink_copy::reflink_or_copy(&src, &dst))
        .await
        .map_err(|e| StorageError::CommandFailed(format!("spawn_blocking join: {e}")))?
        .map_err(StorageError::Io)?;

    Ok(())
}

/// Validate that a kernel file exists and looks reasonable.
///
/// On macOS (Apple Virtualization.framework), the kernel must be an
/// uncompressed ARM64 Image — compressed vmlinuz/bzImage kernels cause
/// an opaque "failed to start" error from VZ.
pub fn validate_kernel(path: &Path) -> Result<(), StorageError> {
    if !path.exists() {
        return Err(StorageError::KernelNotFound(path.to_owned()));
    }

    #[cfg(target_os = "macos")]
    validate_kernel_format(path)?;

    Ok(())
}

/// Check that a kernel is an uncompressed ARM64 Image, not a compressed
/// vmlinuz/bzImage which VZLinuxBootLoader cannot handle.
#[cfg(target_os = "macos")]
fn validate_kernel_format(path: &Path) -> Result<(), StorageError> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(StorageError::Io)?;
    let mut header = [0u8; 64];
    let n = file.read(&mut header).map_err(StorageError::Io)?;

    if n < 64 {
        return Err(StorageError::InvalidKernel(format!(
            "kernel too small ({n} bytes): {}",
            path.display()
        )));
    }

    // ARM64 Image magic: 0x644d5241 ("ARM\x64") at offset 56
    let magic = u32::from_le_bytes([header[56], header[57], header[58], header[59]]);
    if magic == 0x644d_5241 {
        return Ok(());
    }

    // PE32+ / EFI stub (compressed vmlinuz): starts with "MZ"
    if header[0] == b'M' && header[1] == b'Z' {
        return Err(StorageError::InvalidKernel(format!(
            "kernel is a compressed vmlinuz (PE32+/EFI stub): {}\n\
             Apple Virtualization.framework requires an uncompressed ARM64 Image.\n\
             Use the uncompressed 'Image' file instead of 'vmlinuz'.",
            path.display()
        )));
    }

    Err(StorageError::InvalidKernel(format!(
        "kernel does not appear to be an ARM64 Image (magic: {magic:#010x}): {}\n\
         Apple Virtualization.framework requires an uncompressed ARM64 kernel Image.",
        path.display()
    )))
}

/// Validate that a rootfs image exists.
pub fn validate_rootfs(path: &Path) -> Result<(), StorageError> {
    if !path.exists() {
        return Err(StorageError::RootfsNotFound(path.to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_kernel_missing_file() {
        let result = validate_kernel(Path::new("/nonexistent/vmlinux"));
        assert!(matches!(result, Err(StorageError::KernelNotFound(_))));
    }

    #[test]
    fn validate_rootfs_missing_file() {
        let result = validate_rootfs(Path::new("/nonexistent/rootfs.ext4"));
        assert!(matches!(result, Err(StorageError::RootfsNotFound(_))));
    }

    #[test]
    fn storage_config_default_data_dir_is_stable() {
        let cfg = StorageConfig::default();
        assert_eq!(cfg.data_dir, PathBuf::from("/var/lib/husker"));
    }

    #[test]
    fn validate_rootfs_existing_file_ok() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        assert!(validate_rootfs(tmp.path()).is_ok());
    }

    #[cfg(target_os = "macos")]
    mod macos_kernel_validation {
        use super::*;

        fn write_temp_file(content: &[u8]) -> (tempfile::NamedTempFile, PathBuf) {
            use std::io::Write;
            let mut f = tempfile::NamedTempFile::new().unwrap();
            f.write_all(content).unwrap();
            let path = f.path().to_path_buf();
            (f, path)
        }

        #[test]
        fn accepts_valid_arm64_image() {
            // Build a 64-byte header with ARM64 magic at offset 56
            let mut header = [0u8; 64];
            let magic = 0x644d_5241u32.to_le_bytes();
            header[56..60].copy_from_slice(&magic);
            let (_f, path) = write_temp_file(&header);
            assert!(validate_kernel(&path).is_ok());
        }

        #[test]
        fn rejects_compressed_vmlinuz() {
            // PE32+/EFI stub starts with "MZ"
            let mut header = [0u8; 64];
            header[0] = b'M';
            header[1] = b'Z';
            let (_f, path) = write_temp_file(&header);
            let err = validate_kernel(&path).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("compressed vmlinuz"),
                "expected vmlinuz error, got: {msg}"
            );
            assert!(msg.contains("uncompressed"));
        }

        #[test]
        fn rejects_unknown_kernel_format() {
            let header = [0xFFu8; 64];
            let (_f, path) = write_temp_file(&header);
            let err = validate_kernel(&path).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("does not appear to be an ARM64 Image"),
                "expected format error, got: {msg}"
            );
        }

        #[test]
        fn rejects_too_small_kernel() {
            let (_f, path) = write_temp_file(&[0u8; 32]);
            let err = validate_kernel(&path).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("too small"), "expected size error, got: {msg}");
        }
    }
}
