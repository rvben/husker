use std::path::PathBuf;

use husker_storage::{
    CloudDiskFormat, CloudDiskRequest, LocalStorageDriver, RootDiskRequest, StorageConfig,
    StorageDriver, StorageError, clone_rootfs, default_storage_driver,
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
    assert!(matches!(
        err,
        StorageError::DiskTooSmall {
            requested: 1024,
            current: 1_048_576
        }
    ));
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
    for tool in ["mkfs.ext4", "debugfs", "dumpe2fs", "e2fsck"] {
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

// ── replay_ext4_journal ─────────────────────────────────────────────

fn run_e2fs(tool: &str, args: &[&str], img: &std::path::Path) -> std::process::Output {
    std::process::Command::new(tool)
        .args(args)
        .arg(img)
        .output()
        .unwrap()
}

fn needs_recovery(img: &std::path::Path) -> bool {
    let out = run_e2fs("dumpe2fs", &["-h"], img);
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("Filesystem features:"))
        .expect("dumpe2fs must report the filesystem features")
        .split_whitespace()
        .any(|feature| feature == "needs_recovery")
}

/// Leave `img` the way a guest that was stopped without unmounting leaves its
/// root filesystem: a committed journal transaction holding the agent's inode
/// as it is now, not yet written back. The kernel replays it at the next
/// mount, putting that inode back over whatever an offline edit wrote there.
fn leave_pending_journal_over_agent(img: &std::path::Path) {
    let imap = run_e2fs(
        "debugfs",
        &["-R", &format!("imap {}", husker_storage::GUEST_AGENT_PATH)],
        img,
    );
    let imap = String::from_utf8_lossy(&imap.stdout);
    let block: u64 = imap
        .split("located at block ")
        .nth(1)
        .and_then(|rest| rest.split(',').next())
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or_else(|| panic!("debugfs imap gave no block: {imap}"));
    let stats = run_e2fs("dumpe2fs", &["-h"], img);
    let block_size: u64 = String::from_utf8_lossy(&stats.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("Block size:"))
        .and_then(|n| n.trim().parse().ok())
        .expect("dumpe2fs must report the block size");

    let bytes = std::fs::read(img).unwrap();
    let start = (block * block_size) as usize;
    let snapshot = img.with_extension("inode-block");
    std::fs::write(&snapshot, &bytes[start..start + block_size as usize]).unwrap();
    let script = img.with_extension("journal.debugfs");
    std::fs::write(
        &script,
        format!("jo\njw -b {block} {}\njc\n", snapshot.display()),
    )
    .unwrap();
    let out = run_e2fs("debugfs", &["-w", "-f", script.to_str().unwrap()], img);
    assert!(
        out.status.success(),
        "fixture setup: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Positive control: without a pending journal the tests below would pass
    // on code that ignores it.
    assert!(
        needs_recovery(img),
        "fixture must leave a journal pending replay"
    );
}

/// Replay the journal the way the guest kernel does when it mounts the root
/// filesystem, independently of the code under test.
fn mount_time_replay(img: &std::path::Path) {
    let out = run_e2fs("e2fsck", &["-fy", "-E", "journal_only"], img);
    assert!(
        matches!(out.status.code(), Some(0) | Some(1)),
        "replay: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The agent refresh edits the image with debugfs, which ignores the journal.
/// Over a pending journal the readback check passes and the guest kernel's
/// replay then restores the old inode at mount: its size and blocks come back
/// over the new agent and init is cut short. The refresh must leave an image
/// whose agent is the new one after that replay.
#[tokio::test]
async fn refresh_guest_agent_survives_the_journal_replay_at_guest_mount() {
    if !e2fsprogs_available() {
        return;
    }
    let dir = tempdir().unwrap();
    let old_agent = vec![b'o'; 20_000];
    let img = image_with_agent(dir.path(), &old_agent).await;
    leave_pending_journal_over_agent(&img);

    let outcome = husker_storage::refresh_guest_agent(&img, b"current-agent")
        .await
        .unwrap();
    assert_eq!(outcome, husker_storage::AgentRefresh::Replaced);

    mount_time_replay(&img);
    let booted = dump_from_image(&img, husker_storage::GUEST_AGENT_PATH)
        .expect("the agent must survive the replay");
    assert!(
        booted == b"current-agent",
        "the guest must boot the refreshed agent, not the inode the journal held: \
         {} bytes after replay, expected {}",
        booted.len(),
        b"current-agent".len()
    );
}

#[tokio::test]
async fn replay_ext4_journal_replays_a_pending_journal() {
    if !e2fsprogs_available() {
        return;
    }
    let dir = tempdir().unwrap();
    let img = image_with_agent(dir.path(), b"agent").await;
    leave_pending_journal_over_agent(&img);

    let outcome = husker_storage::replay_ext4_journal(&img).await.unwrap();

    assert_eq!(outcome, husker_storage::JournalReplay::Replayed);
    assert!(
        !needs_recovery(&img),
        "the journal must no longer be pending"
    );
    let check = run_e2fs("e2fsck", &["-fn"], &img);
    assert_eq!(
        check.status.code(),
        Some(0),
        "the replayed filesystem must be consistent: {}",
        String::from_utf8_lossy(&check.stdout)
    );
}

/// A digest taken of a clean image must still name it afterwards, so a clean
/// image is not written at all.
#[tokio::test]
async fn replay_ext4_journal_leaves_a_clean_image_byte_identical() {
    if !e2fsprogs_available() {
        return;
    }
    let dir = tempdir().unwrap();
    let img = image_with_agent(dir.path(), b"agent").await;
    let before = std::fs::read(&img).unwrap();

    let outcome = husker_storage::replay_ext4_journal(&img).await.unwrap();

    assert_eq!(outcome, husker_storage::JournalReplay::Clean);
    assert_eq!(std::fs::read(&img).unwrap(), before);
}

/// Something that is not an ext4 filesystem has no readable journal state, and
/// calling it clean would let it be edited or published as one.
#[tokio::test]
async fn replay_ext4_journal_refuses_an_unreadable_image() {
    if !e2fsprogs_available() {
        return;
    }
    let dir = tempdir().unwrap();
    let img = dir.path().join("rootfs.ext4");
    std::fs::write(&img, vec![0x5au8; 2 * 1024 * 1024]).unwrap();

    let err = husker_storage::replay_ext4_journal(&img).await.unwrap_err();

    assert!(
        err.to_string()
            .contains("could not read the ext4 superblock"),
        "{err}"
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

#[tokio::test]
async fn root_disk_preparation_owns_clone_and_optional_steps() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.ext4");
    let destination = dir.path().join("vm/rootfs.ext4");
    std::fs::write(&source, b"rootfs").unwrap();

    let refresh = LocalStorageDriver
        .prepare_root_disk(RootDiskRequest {
            source: &source,
            destination: &destination,
            size_bytes: None,
            guest_agent: &[],
        })
        .await
        .unwrap();

    assert_eq!(refresh, None);
    assert_eq!(std::fs::read(destination).unwrap(), b"rootfs");
}

#[tokio::test]
async fn root_disk_preparation_removes_clone_when_resize_fails() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.ext4");
    let destination = dir.path().join("vm/rootfs.ext4");
    std::fs::write(&source, b"rootfs").unwrap();

    let error = LocalStorageDriver
        .prepare_root_disk(RootDiskRequest {
            source: &source,
            destination: &destination,
            size_bytes: Some(1),
            guest_agent: &[],
        })
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        StorageError::DiskTooSmall {
            requested: 1,
            current: 6
        }
    ));
    assert!(
        !destination.exists(),
        "a failed preparation must not leave a bootable-looking disk"
    );
}

#[tokio::test]
async fn cloud_disk_preparation_validates_before_creating_destination() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("not-qcow2.img");
    let destination = dir.path().join("vm/disk.qcow2");
    std::fs::write(&source, b"not a cloud image").unwrap();

    let error = LocalStorageDriver
        .prepare_cloud_disk(CloudDiskRequest {
            source: &source,
            destination: &destination,
            size_bytes: None,
            format: CloudDiskFormat::Qcow2,
        })
        .await
        .unwrap_err();

    assert!(matches!(error, StorageError::InvalidCloudImage(_)));
    assert!(!destination.exists());
    assert!(!destination.parent().unwrap().exists());
}

#[tokio::test]
async fn cloud_disk_preparation_never_overwrites_an_existing_destination() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.qcow2");
    let destination = dir.path().join("disk.qcow2");
    std::fs::write(&source, [0x51, 0x46, 0x49, 0xfb]).unwrap();
    std::fs::write(&destination, b"owned by another operation").unwrap();

    let error = LocalStorageDriver
        .prepare_cloud_disk(CloudDiskRequest {
            source: &source,
            destination: &destination,
            size_bytes: None,
            format: CloudDiskFormat::Qcow2,
        })
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        StorageError::Io(ref io) if io.kind() == std::io::ErrorKind::AlreadyExists
    ));
    assert_eq!(
        std::fs::read(destination).unwrap(),
        b"owned by another operation"
    );
}
