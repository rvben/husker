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
        state_dir: PathBuf::from("/var/lib/husker"),
    };
    assert_eq!(config.images_dir(), PathBuf::from("/var/lib/husker/images"));
}

#[test]
fn kernels_dir_returns_expected_path() {
    let config = StorageConfig {
        data_dir: PathBuf::from("/var/lib/husker"),
        state_dir: PathBuf::from("/var/lib/husker"),
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
        state_dir: PathBuf::from("/data"),
    };
    assert_eq!(config.vm_dir("my-vm"), PathBuf::from("/data/vms/my-vm"));
}

// ── grow_rootfs_ext4 ────────────────────────────────────────────────

#[tokio::test]
async fn grow_rootfs_ext4_refuses_shrink() {
    let dir = tempdir().unwrap();
    let img = dir.path().join("img.ext4");
    std::fs::write(&img, vec![0u8; 1024 * 1024]).unwrap();

    let err = husker_storage::grow_rootfs_ext4(&img, 1024)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("shrinking is not supported"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn grow_rootfs_ext4_same_size_is_a_noop() {
    let dir = tempdir().unwrap();
    let img = dir.path().join("img.ext4");
    std::fs::write(&img, vec![0u8; 1024 * 1024]).unwrap();

    // Equal size returns before any e2fsprogs invocation, so this passes on
    // hosts without the tools too.
    husker_storage::grow_rootfs_ext4(&img, 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(std::fs::metadata(&img).unwrap().len(), 1024 * 1024);
}

/// End-to-end grow of a real ext4 image. Skips quietly on hosts without
/// e2fsprogs (e.g. stock macOS); Linux CI and dev hosts exercise it.
#[tokio::test]
async fn grow_rootfs_ext4_grows_a_real_filesystem() {
    for tool in ["mkfs.ext4", "e2fsck", "resize2fs"] {
        if std::process::Command::new(tool).arg("-V").output().is_err() {
            eprintln!("skipping: {tool} not available on this host");
            return;
        }
    }

    let dir = tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("hello.txt"), b"hello").unwrap();
    let img = dir.path().join("img.ext4");
    husker_storage::build_ext4_from_dir(&tree, &img, 8 * 1024 * 1024)
        .await
        .unwrap();

    husker_storage::grow_rootfs_ext4(&img, 16 * 1024 * 1024)
        .await
        .unwrap();

    assert_eq!(std::fs::metadata(&img).unwrap().len(), 16 * 1024 * 1024);
    // The grown filesystem must still be clean (e2fsck -fn = read-only check).
    let fsck = std::process::Command::new("e2fsck")
        .args(["-fn"])
        .arg(&img)
        .output()
        .unwrap();
    assert!(
        fsck.status.success(),
        "e2fsck after grow: {}",
        String::from_utf8_lossy(&fsck.stderr)
    );
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
