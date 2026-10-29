use husker_agent_proto::frozen_bundle::{
    BundleFile, FrozenBundle, MAX_BUNDLE_BYTES, MAX_BUNDLE_FILES,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn files() -> BTreeMap<String, BundleFile> {
    BTreeMap::from([
        (
            "src/check.sh".into(),
            BundleFile {
                data: b"#!/bin/sh\nexit 0\n".to_vec(),
                executable: true,
            },
        ),
        (
            "Cargo.toml".into(),
            BundleFile {
                data: vec![0, 255, 128],
                executable: false,
            },
        ),
    ])
}
fn decode(bytes: Vec<u8>) -> Result<FrozenBundle, husker_agent_proto::frozen_bundle::BundleError> {
    let identity = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    let size = bytes.len() as u64;
    FrozenBundle::decode(bytes, &identity, size)
}
fn raw_archive(path: &str, kind: tar::EntryType, mode: u32) -> Vec<u8> {
    let mut header = tar::Header::new_ustar();
    // Write unchecked input to exercise the decoder, not tar's path validator.
    header.as_mut_bytes()[..100].fill(0);
    header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
    header.set_entry_type(kind);
    header.set_mode(mode);
    header.set_size(1);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    let mut archive = tar::Builder::new(Vec::new());
    archive.append(&header, b"x".as_slice()).unwrap();
    archive.into_inner().unwrap()
}

#[test]
fn binary_modes_order_identity_and_empty_bundle_roundtrip() {
    let bundle = FrozenBundle::from_files(files()).unwrap();
    let parsed = decode(bundle.bytes().to_vec()).unwrap();
    assert_eq!(parsed.files(), &files());
    assert_eq!(parsed.digest(), bundle.digest());
    assert_eq!(
        bundle.bytes(),
        FrozenBundle::from_files(files()).unwrap().bytes()
    );
    let empty = FrozenBundle::from_files(BTreeMap::new()).unwrap();
    assert_eq!(empty.bytes().len(), 1024);
    assert!(decode(empty.bytes().to_vec()).unwrap().files().is_empty());
    let path = format!("{}/{}", "p".repeat(150), "f".repeat(100));
    let long = BTreeMap::from([(
        path,
        BundleFile {
            data: vec![],
            executable: false,
        },
    )]);
    assert_eq!(
        decode(
            FrozenBundle::from_files(long.clone())
                .unwrap()
                .bytes()
                .to_vec()
        )
        .unwrap()
        .files(),
        &long
    );
}

#[test]
fn digest_and_size_are_checked_before_decoding() {
    let bundle = FrozenBundle::from_files(files()).unwrap();
    let mut changed = bundle.bytes().to_vec();
    changed[512] ^= 1;
    assert!(FrozenBundle::decode(changed, bundle.digest(), bundle.bytes().len() as u64).is_err());
    assert!(FrozenBundle::decode(bundle.bytes().to_vec(), bundle.digest(), 1).is_err());
}

#[test]
fn rejects_traversal_absolute_normalization_and_credentials() {
    for path in [
        "../escape",
        "/escape",
        "a/../../escape",
        "a//b",
        "./b",
        "a/./b",
        "a\\b",
        ".git/config",
        "nested/.ssh/id",
        ".env",
        ".env.local",
        ".config/tool/token",
        "a\nb",
    ] {
        assert!(
            decode(raw_archive(path, tar::EntryType::Regular, 0o644)).is_err(),
            "{path}"
        );
        assert!(
            FrozenBundle::from_files(BTreeMap::from([(
                path.into(),
                BundleFile {
                    data: vec![],
                    executable: false
                }
            )]))
            .is_err()
        );
    }
}

#[test]
fn rejects_links_devices_extensions_directories_and_privileged_modes() {
    for kind in [
        tar::EntryType::Link,
        tar::EntryType::Symlink,
        tar::EntryType::Char,
        tar::EntryType::Block,
        tar::EntryType::Fifo,
        tar::EntryType::Directory,
        tar::EntryType::GNULongName,
        tar::EntryType::XHeader,
        tar::EntryType::GNUSparse,
    ] {
        assert!(
            decode(raw_archive("file", kind, 0o644)).is_err(),
            "{kind:?}"
        );
    }
    for mode in [0o4755, 0o2755, 0o777, 0o600, 0] {
        assert!(decode(raw_archive("file", tar::EntryType::Regular, mode)).is_err());
    }
}

#[test]
fn rejects_duplicates_prefix_collisions_trailing_bytes_and_metadata() {
    let one = raw_archive("file", tar::EntryType::Regular, 0o644);
    let mut duplicate = one[..1024].to_vec();
    duplicate.extend_from_slice(&one);
    assert!(decode(duplicate).is_err());
    let mut trailing = one.clone();
    trailing.push(0);
    assert!(decode(trailing).is_err());
    let mut padding = one.clone();
    padding[513] = 1;
    assert!(decode(padding).is_err());
    let mut header = tar::Header::from_byte_slice(&one[..512]).clone();
    header.set_uid(1000);
    header.set_cksum();
    let mut metadata = one.clone();
    metadata[..512].copy_from_slice(header.as_bytes());
    assert!(decode(metadata).is_err());
    for len in [0, 1, 511, 512, 513, 1024, 1535] {
        assert!(decode(one[..len].to_vec()).is_err(), "length {len}");
    }
    let mut tree = files();
    tree.insert(
        "src".into(),
        BundleFile {
            data: vec![],
            executable: false,
        },
    );
    assert!(FrozenBundle::from_files(tree).is_err());
}

#[test]
fn rejects_oversized_files_archive_and_entry_count() {
    let big = BTreeMap::from([(
        "big".into(),
        BundleFile {
            data: vec![0; MAX_BUNDLE_BYTES],
            executable: false,
        },
    )]);
    assert!(FrozenBundle::from_files(big).is_err());
    let many = (0..=MAX_BUNDLE_FILES)
        .map(|i| {
            (
                format!("f{i}"),
                BundleFile {
                    data: vec![],
                    executable: false,
                },
            )
        })
        .collect();
    assert!(FrozenBundle::from_files(many).is_err());
    let mut header = tar::Header::new_ustar();
    header.set_path("huge").unwrap();
    header.set_size(u64::MAX);
    header.set_mode(0o644);
    header.set_cksum();
    assert!(decode(header.as_bytes().to_vec()).is_err());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod filesystem {
    use super::*;
    use std::fs::{self, File};
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn freeze_extract_and_refreeze_preserve_only_selected_bytes_and_modes() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("src")).unwrap();
        for (path, entry) in files() {
            fs::write(source.join(&path), entry.data).unwrap();
            fs::set_permissions(
                source.join(path),
                fs::Permissions::from_mode(if entry.executable { 0o755 } else { 0o644 }),
            )
            .unwrap();
        }
        for excluded in [".git", ".ssh", ".codex", ".config"] {
            fs::create_dir(source.join(excluded)).unwrap();
            fs::write(
                source.join(excluded).join("synthetic-secret"),
                b"never transfer",
            )
            .unwrap();
        }
        fs::write(source.join(".env"), b"synthetic-secret").unwrap();
        let bundle = FrozenBundle::freeze_directory(&File::open(&source).unwrap()).unwrap();
        assert_eq!(bundle.files(), &files());
        let parent = File::open(temp.path()).unwrap();
        let extracted = bundle.extract_new_directory(&parent, "workspace").unwrap();
        assert_eq!(
            FrozenBundle::freeze_directory(&extracted).unwrap().digest(),
            bundle.digest()
        );
        assert!(!temp.path().join("workspace/.git").exists());
        assert!(bundle.extract_new_directory(&parent, "workspace").is_err());
        assert!(bundle.extract_new_directory(&parent, "../escape").is_err());
    }

    #[test]
    fn freeze_rejects_file_directory_links_hardlinks_and_fifo_without_blocking() {
        for kind in ["file", "directory", "hardlink", "fifo"] {
            let temp = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            fs::write(outside.path().join("synthetic"), b"foreign bytes").unwrap();
            match kind {
                "file" => {
                    symlink(outside.path().join("synthetic"), temp.path().join("bad")).unwrap()
                }
                "directory" => symlink(outside.path(), temp.path().join("bad")).unwrap(),
                "hardlink" => {
                    fs::hard_link(outside.path().join("synthetic"), temp.path().join("bad"))
                        .unwrap()
                }
                _ => {
                    let path =
                        std::ffi::CString::new(temp.path().join("bad").to_str().unwrap()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
                }
            }
            assert!(
                FrozenBundle::freeze_directory(&File::open(temp.path()).unwrap()).is_err(),
                "{kind}"
            );
        }
    }

    #[test]
    fn extraction_refuses_existing_symlink_without_touching_target() {
        let temp = tempfile::tempdir().unwrap();
        let foreign = tempfile::tempdir().unwrap();
        symlink(foreign.path(), temp.path().join("workspace")).unwrap();
        let bundle = FrozenBundle::from_files(files()).unwrap();
        assert!(
            bundle
                .extract_new_directory(&File::open(temp.path()).unwrap(), "workspace")
                .is_err()
        );
        assert_eq!(fs::read_dir(foreign.path()).unwrap().count(), 0);
    }

    #[test]
    fn declared_artifact_export_is_binary_safe_bounded_and_refuses_parent_links() {
        use husker_agent_proto::frozen_bundle::collect_declared_artifact;
        let temp = tempfile::tempdir().unwrap();
        let foreign = tempfile::tempdir().unwrap();
        let data = vec![0, 255, 128];
        fs::write(temp.path().join("artifact"), &data).unwrap();
        fs::write(temp.path().join("undeclared"), b"not selected").unwrap();
        let root = File::open(temp.path()).unwrap();
        let result = collect_declared_artifact(&root, "artifact", 3).unwrap();
        assert_eq!(result.data, data);
        assert_eq!(
            result.digest,
            format!("sha256:{}", hex::encode(Sha256::digest(&data)))
        );
        assert!(collect_declared_artifact(&root, "artifact", 2).is_err());
        assert!(collect_declared_artifact(&root, "../escape", 3).is_err());
        assert!(collect_declared_artifact(&root, "artifact", 0).is_err());
        symlink(temp.path().join("artifact"), temp.path().join("link")).unwrap();
        assert!(collect_declared_artifact(&root, "link", 3).is_err());
        fs::write(foreign.path().join("synthetic"), b"foreign").unwrap();
        symlink(foreign.path(), temp.path().join("parent")).unwrap();
        assert!(collect_declared_artifact(&root, "parent/synthetic", 100).is_err());
        fs::hard_link(temp.path().join("artifact"), temp.path().join("hardlink")).unwrap();
        assert!(collect_declared_artifact(&root, "hardlink", 3).is_err());
    }

    #[test]
    fn renamed_open_root_is_still_the_frozen_and_extracted_destination() {
        let temp = tempfile::tempdir().unwrap();
        let foreign = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("root")).unwrap();
        let root = File::open(temp.path().join("root")).unwrap();
        fs::rename(temp.path().join("root"), temp.path().join("original")).unwrap();
        symlink(foreign.path(), temp.path().join("root")).unwrap();
        let bundle = FrozenBundle::from_files(files()).unwrap();
        let extracted = bundle.extract_new_directory(&root, "workspace").unwrap();
        assert_eq!(
            FrozenBundle::freeze_directory(&extracted).unwrap().digest(),
            bundle.digest()
        );
        assert!(temp.path().join("original/workspace/Cargo.toml").is_file());
        assert_eq!(fs::read_dir(foreign.path()).unwrap().count(), 0);
    }
}

// These tiny fixtures were emitted by the Rust CLI, and the Python assembler
// must match them byte-for-byte. Keep both sides on the same frozen-wire seam.
#[test]
fn lifecycle_payload_fixtures_are_canonical_frozen_v1() {
    let source =
        decode(include_bytes!("../../../tests/fixtures/lifecycle-source.frozen.tar").to_vec())
            .unwrap();
    assert_eq!(source.files().len(), 2);
    assert_eq!(source.files()["factory-lifecycle-probe"].data, b"probe\n");
    assert!(source.files()["factory-lifecycle-probe"].executable);
    let acceptance =
        decode(include_bytes!("../../../tests/fixtures/lifecycle-acceptance.frozen.tar").to_vec())
            .unwrap();
    assert_eq!(acceptance.files().len(), 1);
    assert_eq!(
        acceptance.files()["frozen-sentinel"].data,
        b"factory-boundary-sentinel-v1\n"
    );
    assert!(!acceptance.files()["frozen-sentinel"].executable);
}
