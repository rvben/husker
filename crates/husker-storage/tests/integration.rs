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

// ── refresh_guest_agent ─────────────────────────────────────────────

/// True when every e2fsprogs tool these tests drive is present. Skips quietly
/// on hosts without them (e.g. stock macOS); Linux CI and dev hosts run them.
fn e2fsprogs_available() -> bool {
    for tool in ["mkfs.ext4", "debugfs"] {
        if std::process::Command::new(tool).arg("-V").output().is_err() {
            eprintln!("skipping: {tool} not available on this host");
            return false;
        }
    }
    true
}

/// Build an ext4 image whose `/usr/local/bin/husker-agent` holds `agent`,
/// installed the way a real import leaves it: root-owned and executable.
///
/// The mode and ownership are set inside the image rather than on the host
/// tree, because these tests do not run as root and `mkfs.ext4 -d` carries the
/// host file's ownership through. Without this the fixture would model an
/// image husker never produces, and every test built on it would be measuring
/// the wrong thing.
async fn image_with_agent(dir: &std::path::Path, agent: &[u8]) -> PathBuf {
    let tree = dir.join("tree");
    let bin = tree.join("usr/local/bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join("husker-agent"), agent).unwrap();
    let img = dir.join("rootfs.ext4");
    husker_storage::build_ext4_from_dir(&tree, &img, 8 * 1024 * 1024)
        .await
        .unwrap();

    for field in ["mode 0100755", "uid 0", "gid 0"] {
        let out = std::process::Command::new("debugfs")
            .arg("-w")
            .arg("-R")
            .arg(format!(
                "set_inode_field {} {field}",
                husker_storage::GUEST_AGENT_PATH
            ))
            .arg(&img)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "fixture setup ({field}): {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    // Positive control: the fixture must actually start out bootable, or a
    // test asserting "no repair happened" proves nothing.
    let stat = std::process::Command::new("debugfs")
        .arg("-R")
        .arg(format!("stat {}", husker_storage::GUEST_AGENT_PATH))
        .arg(&img)
        .output()
        .unwrap();
    let stat = String::from_utf8_lossy(&stat.stdout);
    assert!(
        stat.contains("Mode:  0755") && stat.contains("User:     0   Group:     0"),
        "fixture must model a real import: root-owned and executable, got: {stat}"
    );
    img
}

/// Read a file back out of an ext4 image, independently of the code under test.
fn dump_from_image(img: &std::path::Path, guest_path: &str) -> Option<Vec<u8>> {
    let out = img.with_extension("dumped");
    let _ = std::fs::remove_file(&out);
    std::process::Command::new("debugfs")
        .arg("-R")
        .arg(format!("dump {guest_path} {}", out.display()))
        .arg(img)
        .output()
        .unwrap();
    std::fs::read(&out).ok()
}

#[tokio::test]
async fn refresh_guest_agent_replaces_a_stale_agent() {
    if !e2fsprogs_available() {
        return;
    }
    let dir = tempdir().unwrap();
    let img = image_with_agent(dir.path(), b"stale-agent-bytes").await;

    let outcome =
        husker_storage::refresh_guest_agent(&img, b"current-agent-bytes-which-are-longer")
            .await
            .unwrap();

    assert_eq!(outcome, husker_storage::AgentRefresh::Replaced);
    assert_eq!(
        dump_from_image(&img, husker_storage::GUEST_AGENT_PATH).as_deref(),
        Some(&b"current-agent-bytes-which-are-longer"[..]),
        "the image must carry the new agent"
    );
    // A fresh inode defaults to a non-executable mode, which would leave the
    // guest unable to exec its init.
    let stat = std::process::Command::new("debugfs")
        .arg("-R")
        .arg(format!("stat {}", husker_storage::GUEST_AGENT_PATH))
        .arg(&img)
        .output()
        .unwrap();
    let stat = String::from_utf8_lossy(&stat.stdout);
    assert!(
        stat.contains("Mode:  0755"),
        "agent must stay executable, got: {stat}"
    );
    assert!(
        stat.contains("User:     0   Group:     0"),
        "agent must stay root-owned, got: {stat}"
    );
}

#[tokio::test]
async fn refresh_guest_agent_is_a_noop_when_the_agent_matches() {
    if !e2fsprogs_available() {
        return;
    }
    let dir = tempdir().unwrap();
    let img = image_with_agent(dir.path(), b"identical-agent").await;
    let before = std::fs::read(&img).unwrap();

    let outcome = husker_storage::refresh_guest_agent(&img, b"identical-agent")
        .await
        .unwrap();

    assert_eq!(outcome, husker_storage::AgentRefresh::UpToDate);
    assert_eq!(
        std::fs::read(&img).unwrap(),
        before,
        "an up-to-date image must not be rewritten at all"
    );
}

/// Matching bytes are not enough to call an agent up to date. A rootfs built
/// by hand can carry the current agent at a mode the guest cannot exec, and
/// reporting that as nothing-to-do hands the VM an init it cannot start. The
/// refresh must notice and repair it.
#[tokio::test]
async fn refresh_guest_agent_repairs_a_matching_agent_with_an_unbootable_mode() {
    if !e2fsprogs_available() {
        return;
    }
    let dir = tempdir().unwrap();
    let img = image_with_agent(dir.path(), b"current-agent").await;
    // Break only the mode, leaving the bytes exactly right.
    let broken = std::process::Command::new("debugfs")
        .arg("-w")
        .arg("-R")
        .arg(format!(
            "set_inode_field {} mode 0100644",
            husker_storage::GUEST_AGENT_PATH
        ))
        .arg(&img)
        .output()
        .unwrap();
    assert!(
        broken.status.success(),
        "setup: {}",
        String::from_utf8_lossy(&broken.stderr)
    );

    let outcome = husker_storage::refresh_guest_agent(&img, b"current-agent")
        .await
        .unwrap();

    assert_eq!(
        outcome,
        husker_storage::AgentRefresh::Replaced,
        "a non-executable agent must be repaired, not reported as up to date"
    );
    let stat = std::process::Command::new("debugfs")
        .arg("-R")
        .arg(format!("stat {}", husker_storage::GUEST_AGENT_PATH))
        .arg(&img)
        .output()
        .unwrap();
    let stat = String::from_utf8_lossy(&stat.stdout);
    assert!(
        stat.contains("Mode:  0755"),
        "the repaired agent must be executable, got: {stat}"
    );
    assert_eq!(
        dump_from_image(&img, husker_storage::GUEST_AGENT_PATH).as_deref(),
        Some(&b"current-agent"[..]),
        "the repair must not disturb the agent's contents"
    );
}

/// An image husker did not build has no agent to refresh. That is not a
/// failure and must not be reported as one, nor silently turned into a write
/// that invents a file the image's own init knows nothing about.
#[tokio::test]
async fn refresh_guest_agent_reports_absent_when_the_image_has_no_agent() {
    if !e2fsprogs_available() {
        return;
    }
    let dir = tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("hello.txt"), b"hello").unwrap();
    let img = dir.path().join("rootfs.ext4");
    husker_storage::build_ext4_from_dir(&tree, &img, 8 * 1024 * 1024)
        .await
        .unwrap();

    let outcome = husker_storage::refresh_guest_agent(&img, b"current-agent")
        .await
        .unwrap();

    assert_eq!(outcome, husker_storage::AgentRefresh::Absent);
    assert_eq!(
        dump_from_image(&img, husker_storage::GUEST_AGENT_PATH),
        None,
        "an image without an agent must not be given one"
    );
}

/// Negative control for the "no agent in the image" path: an image debugfs
/// cannot read produces the same empty dump as one that genuinely has no
/// agent, so without a readability check a broken image would be reported as
/// Absent and the refresh silently skipped.
#[tokio::test]
async fn refresh_guest_agent_reports_skipped_for_an_unreadable_image() {
    if !e2fsprogs_available() {
        return;
    }
    let dir = tempdir().unwrap();
    let img = dir.path().join("rootfs.ext4");
    std::fs::write(&img, vec![0x5au8; 2 * 1024 * 1024]).unwrap();

    let outcome = husker_storage::refresh_guest_agent(&img, b"current-agent")
        .await
        .unwrap();

    match outcome {
        husker_storage::AgentRefresh::Skipped(reason) => {
            assert!(
                reason.contains("could not read"),
                "unexpected skip reason: {reason}"
            );
        }
        other => panic!("an unreadable image must not be reported as {other:?}"),
    }
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
