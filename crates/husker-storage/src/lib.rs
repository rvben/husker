//! Storage utilities for validating kernels/rootfs images and cloning VM root disks.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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
    #[error("qemu-img error: {0}")]
    QemuImg(String),
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
    /// Base directory for bulk, reflink-participating data (images, vms, volumes,
    /// suspend, kernels). Becomes a dedicated mount after `setup storage`.
    pub data_dir: PathBuf,
    /// Directory for the live state DB, runtime sockets, and the daemon lock.
    /// Defaults equal to `data_dir`; relocated by `setup storage`.
    pub state_dir: PathBuf,
}

impl Default for StorageConfig {
    fn default() -> Self {
        let data_dir = PathBuf::from("/var/lib/husker");
        Self {
            state_dir: data_dir.clone(),
            data_dir,
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

    pub fn volumes_dir(&self) -> PathBuf {
        self.data_dir.join("volumes")
    }

    pub fn vms_dir(&self) -> PathBuf {
        self.data_dir.join("vms")
    }

    pub fn db_path(&self) -> PathBuf {
        self.state_dir.join("husker.db")
    }

    pub fn runtime_dir(&self) -> PathBuf {
        self.state_dir.join("run")
    }

    pub fn lock_path(&self) -> PathBuf {
        self.state_dir.join("husker.lock")
    }

    pub fn sentinel_path(&self) -> PathBuf {
        self.data_dir.join(".husker-storage-volume")
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
    let result =
        tokio::task::spawn_blocking(move || reflink_copy::reflink_or_copy(&src, &dst)).await;
    let copied = match result {
        Ok(Ok(copied)) => copied,
        // A failed clone can leave a partial/zero-length dest behind that a
        // later op would mistake for a valid rootfs; remove it before
        // propagating so the crate never leaves a half-made image on disk.
        // EXCEPT when reflink_or_copy refused to overwrite a pre-existing
        // destination (AlreadyExists): that file is not ours and deleting it
        // would be data loss (export_image clones to user-supplied paths).
        Ok(Err(io_err)) => {
            if io_err.kind() != std::io::ErrorKind::AlreadyExists {
                let _ = tokio::fs::remove_file(dest).await;
            }
            return Err(StorageError::Io(io_err));
        }
        Err(join_err) => {
            let _ = tokio::fs::remove_file(dest).await;
            return Err(StorageError::CommandFailed(format!(
                "spawn_blocking join: {join_err}"
            )));
        }
    };

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

/// Result of probing whether a data directory supports copy-on-write clones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReflinkStatus {
    /// The filesystem performed a copy-on-write reflink clone.
    Supported,
    /// The clone fell back to a full byte copy (e.g. ext4).
    FullCopy,
}

/// Counter for unique probe file names within a process.
static PROBE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Probe whether cloning from `images_dir` to `vms_dir` reflinks or falls back
/// to a full copy, by performing a real `reflink_or_copy` between the two dirs.
///
/// Creates the dirs if missing and removes both temp files before returning.
/// This exercises the exact production clone mechanism, so the verdict cannot
/// diverge from real `clone_rootfs` behavior.
pub fn probe_reflink(images_dir: &Path, vms_dir: &Path) -> std::io::Result<ReflinkStatus> {
    std::fs::create_dir_all(images_dir)?;
    std::fs::create_dir_all(vms_dir)?;
    let seq = PROBE_SEQ.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let src = images_dir.join(format!(".husker-reflink-probe-{pid}-{seq}.src"));
    let dst = vms_dir.join(format!(".husker-reflink-probe-{pid}-{seq}.dst"));
    std::fs::write(&src, b"husker reflink probe")?;
    let result = reflink_copy::reflink_or_copy(&src, &dst);
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
    match result {
        // None => reflink succeeded; Some(bytes) => fell back to a full copy.
        Ok(None) => Ok(ReflinkStatus::Supported),
        Ok(Some(_)) => Ok(ReflinkStatus::FullCopy),
        Err(e) => Err(e),
    }
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

/// Grow a raw ext4 rootfs image to `new_size_bytes` offline.
///
/// Used for plain-rootfs VMs (`--disk-size` with a catalog/OCI image), which
/// have no cloud-init to grow the filesystem on first boot: extend the file
/// (sparse, so the growth costs no host disk until written), then run
/// `e2fsck -fp` + `resize2fs` to grow the filesystem into it. Both tools ship
/// in e2fsprogs, the same package that provides the `mkfs.ext4` used at
/// import time. Shrinking is refused.
pub async fn grow_rootfs_ext4(path: &Path, new_size_bytes: u64) -> Result<(), StorageError> {
    let current = tokio::fs::metadata(path)
        .await
        .map_err(StorageError::Io)?
        .len();
    if new_size_bytes < current {
        return Err(StorageError::CommandFailed(format!(
            "disk_size {new_size_bytes} bytes is smaller than the rootfs image \
             ({current} bytes); shrinking is not supported"
        )));
    }
    if new_size_bytes == current {
        return Ok(());
    }
    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .await
        .map_err(StorageError::Io)?;
    file.set_len(new_size_bytes)
        .await
        .map_err(StorageError::Io)?;
    drop(file);

    // resize2fs refuses a filesystem that has not been checked since its last
    // mount; -f forces the check, -p auto-fixes. Exit code 1 means "errors
    // corrected", which is fine for a freshly cloned image.
    let fsck = tokio::process::Command::new("e2fsck")
        .arg("-fp")
        .arg(path)
        .output()
        .await
        .map_err(|e| {
            StorageError::CommandFailed(format!(
                "e2fsck not runnable ({e}); growing a rootfs image needs e2fsprogs"
            ))
        })?;
    if !matches!(fsck.status.code(), Some(0) | Some(1)) {
        return Err(StorageError::CommandFailed(format!(
            "e2fsck {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&fsck.stderr).trim()
        )));
    }
    let resize = tokio::process::Command::new("resize2fs")
        .arg(path)
        .output()
        .await
        .map_err(|e| {
            StorageError::CommandFailed(format!(
                "resize2fs not runnable ({e}); growing a rootfs image needs e2fsprogs"
            ))
        })?;
    if !resize.status.success() {
        return Err(StorageError::CommandFailed(format!(
            "resize2fs {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&resize.stderr).trim()
        )));
    }
    Ok(())
}

/// Virtual size of a qcow2 image in bytes, via `qemu-img info`.
///
/// Returns the number of bytes the guest OS sees as the disk's capacity,
/// regardless of how much host space the qcow2 file actually occupies.
pub async fn qcow2_virtual_size(path: &Path) -> Result<u64, StorageError> {
    if !path.exists() {
        return Err(StorageError::InvalidCloudImage(format!(
            "cloud image not found: {}",
            path.display()
        )));
    }
    let out = tokio::process::Command::new("qemu-img")
        .args(["info", "--output=json"])
        .arg(path)
        .output()
        .await
        .map_err(|e| StorageError::QemuImg(format!("qemu-img spawn failed: {e}")))?;
    if !out.status.success() {
        return Err(StorageError::QemuImg(format!(
            "qemu-img info failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| StorageError::QemuImg(format!("qemu-img info parse: {e}")))?;
    v["virtual-size"]
        .as_u64()
        .ok_or_else(|| StorageError::QemuImg("qemu-img info: no virtual-size".into()))
}

/// Convert a qcow2 image to a sparse raw file.
///
/// Apple Virtualization.framework attaches raw disk images only; this is the
/// clone step for macOS cloud-image VMs. A partial output file is removed on
/// failure so no corrupt image is left on disk.
pub fn convert_qcow2_to_raw(src: &Path, dest: &Path) -> Result<(), StorageError> {
    if !src.exists() {
        return Err(StorageError::InvalidCloudImage(format!(
            "cloud image not found: {}",
            src.display()
        )));
    }
    let out = std::process::Command::new("qemu-img")
        .args(["convert", "-f", "qcow2", "-O", "raw"])
        .arg(src)
        .arg(dest)
        .output()
        .map_err(|e| {
            StorageError::QemuImg(format!(
                "qemu-img spawn failed: {e} (install with: brew install qemu)"
            ))
        })?;
    if !out.status.success() {
        let _ = std::fs::remove_file(dest);
        return Err(StorageError::QemuImg(format!(
            "qemu-img convert failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
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

/// Create a sparse file of `size_bytes` at `path`, failing if it already exists.
///
/// Uses `create_new` (O_EXCL) so two concurrent builders for the same path
/// cannot clobber each other: an existing path yields the friendly
/// `VolumeImage` "already exists" error rather than a raw I/O error, and the
/// loser of a race never truncates the winner's file.
fn create_sparse_file(path: &Path, size_bytes: u64) -> Result<(), StorageError> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                StorageError::VolumeImage(format!(
                    "volume image already exists: {}",
                    path.display()
                ))
            } else {
                StorageError::Io(e)
            }
        })?;
    file.set_len(size_bytes)?;
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
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // Create a sparse file of the requested size (fails if it already exists).
    create_sparse_file(path, size_bytes)?;

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

/// Build an ext4 image at `path` populated from the directory tree `src_dir`,
/// using `mkfs.ext4 -d`. `size_bytes` must be large enough to hold the tree
/// plus filesystem overhead. The partial image is removed on failure.
///
/// `path` must not already exist.
pub async fn build_ext4_from_dir(
    src_dir: &Path,
    path: &Path,
    size_bytes: u64,
) -> Result<(), StorageError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    create_sparse_file(path, size_bytes)?;
    let output = tokio::process::Command::new("mkfs.ext4")
        .arg("-F")
        .arg("-q")
        .arg("-d")
        .arg(src_dir)
        .arg(path)
        .output()
        .await;
    match output {
        Err(e) => {
            let _ = std::fs::remove_file(path);
            Err(StorageError::VolumeImage(format!(
                "mkfs.ext4 -d spawn failed: {e}"
            )))
        }
        Ok(out) if !out.status.success() => {
            let _ = std::fs::remove_file(path);
            Err(StorageError::VolumeImage(format!(
                "mkfs.ext4 -d {} failed: {}",
                path.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
        Ok(_) => Ok(()),
    }
}

/// Total apparent size of all regular files under `dir`, for sizing an ext4
/// image built from it. Best-effort: unreadable entries are skipped.
pub fn dir_apparent_size(dir: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in rd.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                stack.push(entry.path());
            } else if ft.is_file()
                && let Ok(meta) = entry.metadata()
            {
                total += meta.len();
            }
        }
    }
    total
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

    // ── qemu-img helpers ─────────────────────────────────────────────

    #[tokio::test]
    async fn qcow2_virtual_size_reads_size() {
        if !qemu_img_available() {
            eprintln!("skipping: qemu-img not installed");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("t.qcow2");
        let status = std::process::Command::new("qemu-img")
            .args(["create", "-f", "qcow2", img.to_str().unwrap(), "64M"])
            .status()
            .unwrap();
        assert!(status.success());
        let size = qcow2_virtual_size(&img).await.unwrap();
        assert_eq!(size, 64 * 1024 * 1024);
    }

    #[test]
    fn convert_qcow2_to_raw_produces_raw() {
        if !qemu_img_available() {
            eprintln!("skipping: qemu-img not installed");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("s.qcow2");
        std::process::Command::new("qemu-img")
            .args(["create", "-f", "qcow2", src.to_str().unwrap(), "8M"])
            .status()
            .unwrap();
        let dest = dir.path().join("d.raw");
        convert_qcow2_to_raw(&src, &dest).unwrap();
        let meta = std::fs::metadata(&dest).unwrap();
        assert_eq!(meta.len(), 8 * 1024 * 1024, "raw file has virtual size");
    }

    #[test]
    fn convert_qcow2_to_raw_missing_source_errors() {
        let dir = tempfile::tempdir().unwrap();
        let err = convert_qcow2_to_raw(&dir.path().join("absent.qcow2"), &dir.path().join("d.raw"));
        assert!(err.is_err());
    }

    #[test]
    fn state_dir_derives_db_and_runtime_paths() {
        let cfg = StorageConfig {
            data_dir: PathBuf::from("/data"),
            state_dir: PathBuf::from("/state"),
        };
        assert_eq!(cfg.db_path(), PathBuf::from("/state/husker.db"));
        assert_eq!(cfg.runtime_dir(), PathBuf::from("/state/run"));
        assert_eq!(cfg.lock_path(), PathBuf::from("/state/husker.lock"));
        assert_eq!(cfg.vms_dir(), PathBuf::from("/data/vms"));
        assert_eq!(
            cfg.sentinel_path(),
            PathBuf::from("/data/.husker-storage-volume")
        );
        // Default keeps state_dir equal to data_dir (no behavior change).
        let def = StorageConfig::default();
        assert_eq!(def.state_dir, def.data_dir);
    }

    #[test]
    fn probe_reflink_returns_a_definite_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let images = dir.path().join("images");
        let vms = dir.path().join("vms");
        // Must classify (Supported on CoW fs, FullCopy on ext4/tmpfs); never error.
        let status = probe_reflink(&images, &vms).expect("probe must not error");
        assert!(matches!(
            status,
            ReflinkStatus::Supported | ReflinkStatus::FullCopy
        ));
        // Probe must leave no temp files behind.
        let leftover_images: Vec<_> = std::fs::read_dir(&images).unwrap().collect();
        let leftover_vms: Vec<_> = std::fs::read_dir(&vms).unwrap().collect();
        assert!(leftover_images.is_empty(), "probe left files in images dir");
        assert!(leftover_vms.is_empty(), "probe left files in vms dir");
    }
}
