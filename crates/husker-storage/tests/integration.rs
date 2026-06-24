use std::path::PathBuf;

use husker_storage::{
    LocalStorageDriver, StorageConfig, StorageDriver, StorageError, clone_rootfs,
    default_storage_driver,
};
use tempfile::tempdir;

// ── StorageConfig path helpers ──────────────────────────────────────

#[test]
fn images_dir_returns_expected_path() {
    let config = StorageConfig {
        data_dir: PathBuf::from("/var/lib/husker"),
    };
    assert_eq!(config.images_dir(), PathBuf::from("/var/lib/husker/images"));
}

#[test]
fn kernels_dir_returns_expected_path() {
    let config = StorageConfig {
        data_dir: PathBuf::from("/var/lib/husker"),
    };
    assert_eq!(
        config.kernels_dir(),
        PathBuf::from("/var/lib/husker/kernels")
    );
}

#[test]
fn vm_dir_returns_expected_path() {
    let config = StorageConfig {
        data_dir: PathBuf::from("/data"),
    };
    assert_eq!(config.vm_dir("my-vm"), PathBuf::from("/data/vms/my-vm"));
}

// ── clone_rootfs ────────────────────────────────────────────────────

#[tokio::test]
async fn clone_rootfs_successful() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.ext4");
    let dest = dir.path().join("dest.ext4");

    let content = b"fake rootfs content for testing";
    std::fs::write(&source, content).unwrap();

    clone_rootfs(&source, &dest).await.unwrap();

    let result = std::fs::read(&dest).unwrap();
    assert_eq!(result, content);
}

#[tokio::test]
async fn clone_rootfs_creates_parent_directories() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.ext4");
    let dest = dir.path().join("nested/deep/dir/dest.ext4");

    std::fs::write(&source, b"content").unwrap();

    clone_rootfs(&source, &dest).await.unwrap();

    assert!(dest.exists());
    assert_eq!(std::fs::read(&dest).unwrap(), b"content");
}

#[tokio::test]
async fn clone_rootfs_source_not_found() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("nonexistent.ext4");
    let dest = dir.path().join("dest.ext4");

    let err = clone_rootfs(&source, &dest).await.unwrap_err();
    assert!(matches!(err, StorageError::RootfsNotFound(_)));
}

#[tokio::test]
async fn clone_rootfs_fails_when_dest_exists() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.ext4");
    let dest = dir.path().join("dest.ext4");

    std::fs::write(&source, b"new content").unwrap();
    std::fs::write(&dest, b"old content").unwrap();

    // reflink_or_copy does not overwrite existing files
    let err = clone_rootfs(&source, &dest).await.unwrap_err();
    assert!(matches!(err, StorageError::Io(_)));
    // The pre-existing destination is not ours: a failed clone must leave it
    // untouched (export_image clones to user-supplied paths, so deleting it
    // here would be silent data loss).
    assert_eq!(std::fs::read(&dest).unwrap(), b"old content");
}

#[tokio::test]
async fn clone_rootfs_large_file() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("large.ext4");
    let dest = dir.path().join("large-clone.ext4");

    // 10 MiB file with recognizable pattern
    let data: Vec<u8> = (0..10 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    std::fs::write(&source, &data).unwrap();

    clone_rootfs(&source, &dest).await.unwrap();

    let result = std::fs::read(&dest).unwrap();
    assert_eq!(result.len(), data.len());
    assert_eq!(result, data);
}

#[test]
fn default_storage_driver_name_is_stable() {
    let driver = default_storage_driver();
    assert_eq!(driver.name(), "local-reflink");
}

#[tokio::test]
async fn local_storage_driver_trait_clone_rootfs() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.ext4");
    let dest = dir.path().join("dest.ext4");
    std::fs::write(&source, b"driver content").unwrap();

    let driver = LocalStorageDriver;
    driver.clone_rootfs(&source, &dest).await.unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"driver content");
}
