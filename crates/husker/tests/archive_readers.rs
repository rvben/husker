use std::io::Write as _;
use std::path::Path;

use flate2::{Compression, write::GzEncoder};
use husker::archive::{extract_outputs, firecracker_binary};

const BINARY: &str = "firecracker-v1.16.0-x86_64";

fn gzip(tar: &[u8]) -> Vec<u8> {
    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
    gzip.write_all(tar).unwrap();
    gzip.finish().unwrap()
}

fn append(builder: &mut tar::Builder<Vec<u8>>, path: &str, data: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o755);
    builder.append_data(&mut header, path, data).unwrap();
}

fn tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, data) in files {
        append(&mut builder, path, data);
    }
    builder.into_inner().unwrap()
}

#[tokio::test]
async fn release_reader_consumes_all_payload_chunks_and_ignores_other_binaries() {
    let binary = vec![0x7f; 150_000];
    let tar = tar(&[
        ("release/jailer", b"other"),
        (&format!("release/{BINARY}"), &binary),
    ]);
    assert_eq!(
        firecracker_binary(gzip(&tar), BINARY.into()).await.unwrap(),
        binary
    );
}

#[tokio::test]
async fn release_reader_rejects_duplicates_links_and_missing_binary() {
    let duplicate = tar(&[(BINARY, b"first"), (BINARY, b"second")]);
    assert!(
        firecracker_binary(gzip(&duplicate), BINARY.into())
            .await
            .is_err()
    );
    assert!(
        firecracker_binary(gzip(&tar(&[("jailer", b"other")])), BINARY.into())
            .await
            .is_err()
    );

    let mut builder = tar::Builder::new(Vec::new());
    let mut link = tar::Header::new_gnu();
    link.set_entry_type(tar::EntryType::Symlink);
    link.set_size(0);
    link.set_mode(0o755);
    builder
        .append_link(&mut link, BINARY, "/etc/passwd")
        .unwrap();
    assert!(
        firecracker_binary(gzip(&builder.into_inner().unwrap()), BINARY.into())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn release_reader_rejects_corruption_after_the_matching_binary() {
    let mut damaged = tar(&[(BINARY, b"binary"), ("later", b"other")]);
    damaged[1024] ^= 1; // Corrupt the later header, preserving the first member.
    assert!(
        firecracker_binary(gzip(&damaged), BINARY.into())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn both_readers_reject_bad_gzip_trailers_hidden_archives_and_extra_streams() {
    let good_tar = tar(&[(BINARY, b"binary")]);
    let good = gzip(&good_tar);
    let mut bad_crc = good.clone();
    let trailer = bad_crc.len() - 8;
    bad_crc[trailer] ^= 1;
    let truncated = good[..good.len() - 3].to_vec();
    let mut extra_stream = good.clone();
    extra_stream.extend_from_slice(&gzip(b"hidden"));
    let mut hidden_tar = good_tar.clone();
    hidden_tar.extend_from_slice(&tar(&[("hidden", b"data")]));
    for bytes in [bad_crc, truncated, extra_stream, gzip(&hidden_tar)] {
        assert!(
            firecracker_binary(bytes.clone(), BINARY.into())
                .await
                .is_err()
        );
        let dir = tempfile::tempdir().unwrap();
        assert!(extract_outputs(bytes, dir.path().into()).await.is_err());
        assert!(
            !dir.path().join(BINARY).exists(),
            "invalid input must be rejected before writes"
        );
    }
}

#[tokio::test]
async fn guest_outputs_overwrite_files_preserve_executable_intent_and_long_names() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("old"), b"old").unwrap();
    let long = format!("out/{}/app", "a".repeat(140));
    let bytes = gzip(&tar(&[("./old", b"new"), (&long, b"executable")]));
    let paths = extract_outputs(bytes, dir.path().into()).await.unwrap();
    assert_eq!(paths, ["old", &long]);
    assert_eq!(std::fs::read(dir.path().join("old")).unwrap(), b"new");
    assert_eq!(
        std::fs::read(dir.path().join(&long)).unwrap(),
        b"executable"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_ne!(
            std::fs::metadata(dir.path().join(long))
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0
        );
    }
}

#[tokio::test]
async fn guest_outputs_accept_pax_paths() {
    let path = format!("out/{}/file", "long".repeat(40));
    let mut builder = tar::Builder::new(Vec::new());
    builder
        .append_pax_extensions([("path", path.as_bytes())])
        .unwrap();
    let mut header = tar::Header::new_ustar();
    header.set_size(3);
    header.set_mode(0o644);
    builder
        .append_data(&mut header, "placeholder", &b"pax"[..])
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let paths = extract_outputs(gzip(&builder.into_inner().unwrap()), dir.path().into())
        .await
        .unwrap();
    assert_eq!(paths.as_slice(), std::slice::from_ref(&path));
    assert_eq!(std::fs::read(dir.path().join(path)).unwrap(), b"pax");
}

#[tokio::test]
async fn guest_outputs_reject_unsafe_paths_and_devices_before_writing_files() {
    for path in ["../escape", "/absolute"] {
        let mut bytes = tar(&[("first", b"okay"), ("bad", b"bad")]);
        // Write a hostile name directly: tar::Builder refuses to produce it.
        let header = tar::Header::from_byte_slice(&bytes[1024..1536]);
        let mut header = header.clone();
        header.as_mut_bytes()[..100].fill(0);
        header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
        header.set_cksum();
        bytes[1024..1536].copy_from_slice(header.as_bytes());
        let dir = tempfile::tempdir().unwrap();
        assert!(
            extract_outputs(gzip(&bytes), dir.path().into())
                .await
                .is_err()
        );
        assert!(!dir.path().join("first").exists());
        assert!(
            firecracker_binary(gzip(&bytes), "first".into())
                .await
                .is_err()
        );
    }
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Fifo);
    header.set_size(0);
    header.set_mode(0o644);
    builder.append_data(&mut header, "pipe", &[][..]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    assert!(
        extract_outputs(gzip(&builder.into_inner().unwrap()), dir.path().into())
            .await
            .is_err()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn guest_outputs_keep_contained_links_but_cannot_follow_host_escape_links() {
    let mut builder = tar::Builder::new(Vec::new());
    append(&mut builder, "out/app", b"binary");
    for (path, target, kind) in [
        ("out/symlink", "app", tar::EntryType::Symlink),
        ("out/hardlink", "out/app", tar::EntryType::Link),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_size(0);
        header.set_mode(0o755);
        builder.append_link(&mut header, path, target).unwrap();
    }
    let dir = tempfile::tempdir().unwrap();
    extract_outputs(gzip(&builder.into_inner().unwrap()), dir.path().into())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_link(dir.path().join("out/symlink")).unwrap(),
        Path::new("app")
    );
    assert_eq!(
        std::fs::read(dir.path().join("out/hardlink")).unwrap(),
        b"binary"
    );

    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("keep"), b"host").unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();
    assert!(
        extract_outputs(gzip(&tar(&[("escape/keep", b"guest")])), dir.path().into())
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(outside.path().join("keep")).unwrap(), b"host");
}

#[cfg(unix)]
#[tokio::test]
async fn guest_outputs_reject_archived_links_to_host_files() {
    let outside = tempfile::tempdir().unwrap();
    let host_file = outside.path().join("keep");
    std::fs::write(&host_file, b"host").unwrap();
    for kind in [tar::EntryType::Symlink, tar::EntryType::Link] {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_mode(0o644);
        header.set_size(0);
        let target = if kind.is_symlink() {
            outside.path()
        } else {
            &host_file
        };
        builder.append_link(&mut header, "link", target).unwrap();
        append(&mut builder, "link/keep", b"guest");
        let dir = tempfile::tempdir().unwrap();
        assert!(
            extract_outputs(gzip(&builder.into_inner().unwrap()), dir.path().into())
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&host_file).unwrap(), b"host");
    }
}

#[tokio::test]
async fn hard_links_cannot_alias_preexisting_working_tree_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("original"), b"keep").unwrap();
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Link);
    header.set_mode(0o644);
    header.set_size(0);
    builder
        .append_link(&mut header, "alias", "original")
        .unwrap();
    append(&mut builder, "alias", b"replace");
    assert!(
        extract_outputs(gzip(&builder.into_inner().unwrap()), dir.path().into())
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(dir.path().join("original")).unwrap(), b"keep");
}

/// Explicit compatibility rehearsal against downloaded, checksum-verified
/// upstream release archives; no network requests are made by the test.
#[tokio::test]
#[ignore = "requires HUSKER_TEST_FIRECRACKER_TGZ and HUSKER_TEST_FIRECRACKER_NAME"]
async fn published_firecracker_release_compatibility() {
    let path = std::env::var("HUSKER_TEST_FIRECRACKER_TGZ").unwrap();
    let name = std::env::var("HUSKER_TEST_FIRECRACKER_NAME").unwrap();
    let bytes = std::fs::read(path).unwrap();
    let binary = firecracker_binary(bytes, name).await.unwrap();
    assert!(binary.starts_with(b"\x7fELF"));
}
