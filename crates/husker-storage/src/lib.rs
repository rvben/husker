//! Storage utilities for validating kernels/rootfs images and cloning VM root disks.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use tracing::warn;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("rootfs not found: {0}")]
    RootfsNotFound(PathBuf),
    #[error("kernel not found: {0}")]
    KernelNotFound(PathBuf),
    #[error("{0}")]
    InvalidKernel(String),
    #[error("invalid cloud image: {0}")]
    InvalidCloudImage(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("command failed: {0}")]
    CommandFailed(String),
    #[error("volume image error: {0}")]
    VolumeImage(String),
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
    // `reflink_or_copy` returns `None` when the reflink (copy-on-write) clone
    // succeeded and `Some(bytes)` when it had to fall back to a full byte copy
    // because the filesystem lacks reflink support (e.g. ext4).
    let copied = tokio::task::spawn_blocking(move || reflink_copy::reflink_or_copy(&src, &dst))
        .await
        .map_err(|e| StorageError::CommandFailed(format!("spawn_blocking join: {e}")))?
        .map_err(StorageError::Io)?;

    if should_warn_reflink_fallback(copied, &REFLINK_FALLBACK_WARNED) {
        warn!(
            dest = %dest.display(),
            bytes = copied.unwrap_or(0),
            "rootfs clone fell back to a full byte copy: the data directory's filesystem \
             does not support reflink (copy-on-write), so every microVM pays a full copy of \
             the rootfs image. Host the data directory on XFS or btrfs for instant clones."
        );
    }

    Ok(())
}

/// Static guard so the reflink-fallback warning is emitted at most once per
/// process rather than on every clone.
static REFLINK_FALLBACK_WARNED: AtomicBool = AtomicBool::new(false);

/// Decide whether to emit the reflink-fallback warning.
///
/// Returns `true` at most once for a given `warned` flag, and only when the
/// clone fell back to a full copy (`copied` is `Some`). A reflink success
/// (`None`) never warns.
fn should_warn_reflink_fallback(copied: Option<u64>, warned: &AtomicBool) -> bool {
    if copied.is_none() {
        return false;
    }
    // The first caller to flip false -> true wins the single warning.
    warned
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

/// Grow a disk image to `new_size_bytes` using `qemu-img resize`.
///
/// Used for cloud-image VMs: clone the base qcow2 (via `clone_rootfs`) then grow it
/// so cloud-init's growpart/resizefs can expand the guest filesystem on first boot.
/// `qemu-img resize` only grows by default; pass a size >= the image's virtual size.
pub async fn resize_disk(path: &Path, new_size_bytes: u64) -> Result<(), StorageError> {
    let output = tokio::process::Command::new("qemu-img")
        .arg("resize")
        .arg(path)
        // qemu-img interprets a bare integer (no suffix) as a byte count.
        .arg(new_size_bytes.to_string())
        .output()
        .await
        .map_err(StorageError::Io)?;
    if !output.status.success() {
        return Err(StorageError::CommandFailed(format!(
            "qemu-img resize {} {new_size_bytes} failed: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
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

/// Validate that a cloud image exists and is a qcow2 file (the UEFI boot path
/// attaches it with format=qcow2, so anything else fails inside QEMU later
/// with a much less useful error).
pub fn validate_cloud_image(path: &Path) -> Result<(), StorageError> {
    use std::io::Read;
    if !path.exists() {
        return Err(StorageError::InvalidCloudImage(format!(
            "file not found: {}",
            path.display()
        )));
    }
    let mut file = std::fs::File::open(path).map_err(StorageError::Io)?;
    let mut magic = [0u8; 4];
    let n = file.read(&mut magic).map_err(StorageError::Io)?;
    // qcow2 magic: "QFI\xfb"
    if n < 4 || magic != [0x51, 0x46, 0x49, 0xfb] {
        return Err(StorageError::InvalidCloudImage(format!(
            "not a qcow2 image (bad magic): {}",
            path.display()
        )));
    }
    Ok(())
}

/// Create a sparse ext4 volume image at `path` with the given size.
///
/// The file is first created as a sparse file (only metadata occupies disk
/// space until data is written) and then formatted with `mkfs.ext4 -F -q`.
/// If mkfs fails the partial file is removed to avoid leaving a half-made
/// volume on disk.
///
/// `path` must not already exist; returns `StorageError::VolumeImage` if it does.
pub async fn create_volume_image(path: &Path, size_bytes: u64) -> Result<(), StorageError> {
    if path.exists() {
        return Err(StorageError::VolumeImage(format!(
            "volume image already exists: {}",
            path.display()
        )));
    }

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // Create a sparse file of the requested size.
    {
        let file = std::fs::File::create(path)?;
        file.set_len(size_bytes)?;
    }

    // Format with mkfs.ext4.
    let output = tokio::process::Command::new("mkfs.ext4")
        .arg("-F")
        .arg("-q")
        .arg(path)
        .output()
        .await;

    match output {
        Err(e) => {
            // mkfs not found or failed to spawn; clean up and propagate.
            let _ = std::fs::remove_file(path);
            Err(StorageError::VolumeImage(format!(
                "mkfs.ext4 spawn failed: {e}"
            )))
        }
        Ok(out) if !out.status.success() => {
            let _ = std::fs::remove_file(path);
            Err(StorageError::VolumeImage(format!(
                "mkfs.ext4 {} failed: {}",
                path.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
        Ok(_) => Ok(()),
    }
}

/// Validate that a volume image file exists at `path`.
///
/// Used at attach time to confirm the image has not been deleted outside husker.
pub fn validate_volume(path: &Path) -> Result<(), StorageError> {
    if !path.exists() {
        return Err(StorageError::VolumeImage(format!(
            "volume image not found: {}",
            path.display()
        )));
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

    #[test]
    fn reflink_fallback_warns_once_only_on_full_copy() {
        let warned = AtomicBool::new(false);

        // A reflink success (None) must never warn and must not consume the flag.
        assert!(!should_warn_reflink_fallback(None, &warned));
        assert!(!warned.load(Ordering::SeqCst));

        // The first full-copy fallback warns and latches the flag.
        assert!(should_warn_reflink_fallback(Some(8_589_934_592), &warned));
        assert!(warned.load(Ordering::SeqCst));

        // Subsequent fallbacks do not warn again (no log spam per clone).
        assert!(!should_warn_reflink_fallback(Some(1024), &warned));
        assert!(!should_warn_reflink_fallback(Some(0), &warned));

        // A later reflink success still never warns.
        assert!(!should_warn_reflink_fallback(None, &warned));
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

    // These are fast, hermetic tests (tempdir + one qemu-img invocation), so they
    // run by default rather than being #[ignore]d like the VM-boot e2e tests: when
    // qemu-img is present (CI) they provide real coverage, and they skip cleanly on
    // dev hosts that lack it.
    fn qemu_img_available() -> bool {
        std::process::Command::new("qemu-img")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[tokio::test]
    async fn resize_disk_grows_a_raw_file() {
        if !qemu_img_available() {
            eprintln!("skipping resize_disk_grows_a_raw_file: qemu-img not installed");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let disk = dir.path().join("d.raw");
        tokio::fs::write(&disk, vec![0u8; 1024 * 1024])
            .await
            .unwrap();
        resize_disk(&disk, 8 * 1024 * 1024).await.unwrap();
        let len = tokio::fs::metadata(&disk).await.unwrap().len();
        assert_eq!(
            len,
            8 * 1024 * 1024,
            "raw disk should grow to the requested size"
        );
    }

    #[tokio::test]
    async fn resize_disk_errors_on_missing_file() {
        if !qemu_img_available() {
            eprintln!("skipping resize_disk_errors_on_missing_file: qemu-img not installed");
            return;
        }
        let err = resize_disk(std::path::Path::new("/no/such/disk.qcow2"), 1 << 30)
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::CommandFailed(_)), "got {err:?}");
    }

    #[test]
    fn validate_cloud_image_accepts_qcow2_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("img.qcow2");
        let mut data = vec![0u8; 512];
        data[..4].copy_from_slice(&[0x51, 0x46, 0x49, 0xfb]);
        std::fs::write(&path, &data).unwrap();
        assert!(validate_cloud_image(&path).is_ok());
    }

    #[test]
    fn validate_cloud_image_rejects_non_qcow2() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("img.raw");
        std::fs::write(&path, vec![0u8; 512]).unwrap();
        assert!(matches!(
            validate_cloud_image(&path),
            Err(StorageError::InvalidCloudImage(_))
        ));
    }

    #[test]
    fn validate_cloud_image_rejects_missing_file() {
        assert!(validate_cloud_image(Path::new("/nonexistent/img.qcow2")).is_err());
    }

    // ── Volume image helpers ─────────────────────────────────────────

    fn mkfs_ext4_available() -> bool {
        std::process::Command::new("which")
            .arg("mkfs.ext4")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[tokio::test]
    async fn create_volume_image_creates_sparse_file_and_formats() {
        if !mkfs_ext4_available() {
            eprintln!("skipping create_volume_image test: mkfs.ext4 not found (macOS dev host)");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.img");
        let size = 64 * 1024 * 1024; // 64 MiB

        create_volume_image(&path, size).await.unwrap();

        // The file must exist and report the correct apparent size.
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(
            meta.len(),
            size,
            "volume image should have the requested apparent size"
        );
    }

    #[tokio::test]
    async fn create_volume_image_refuses_existing_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exists.img");
        std::fs::write(&path, b"preexisting").unwrap();

        let err = create_volume_image(&path, 64 * 1024 * 1024)
            .await
            .unwrap_err();
        assert!(
            matches!(err, StorageError::VolumeImage(_)),
            "expected VolumeImage error for existing path, got: {err:?}"
        );
    }

    #[test]
    fn validate_volume_accepts_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vol.img");
        std::fs::write(&path, b"data").unwrap();
        assert!(validate_volume(&path).is_ok());
    }

    #[test]
    fn validate_volume_rejects_missing_file() {
        let err = validate_volume(Path::new("/nonexistent/vol.img")).unwrap_err();
        assert!(
            matches!(err, StorageError::VolumeImage(_)),
            "expected VolumeImage error, got: {err:?}"
        );
    }
}
