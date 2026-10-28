//! Canonical digest of workspace Rust sources and Cargo manifests/lockfile.
//! This records declared build inputs, not compiler or supply-chain attestation.
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

fn collect(directory: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    for item in std::fs::read_dir(directory)? {
        let item = item?;
        let metadata = item.path().symlink_metadata()?;
        let name = item.file_name();
        if metadata.is_dir() {
            if name != "target" && name != ".git" {
                collect(&item.path(), files)?;
            }
        } else if name == "Cargo.toml" || item.path().extension().is_some_and(|ext| ext == "rs") {
            if !metadata.is_file() {
                return Err(io::Error::other("source input is not a regular file"));
            }
            files.push(item.path());
        } else if metadata.file_type().is_symlink() {
            return Err(io::Error::other("symlink in workspace crate tree"));
        }
    }
    Ok(())
}

pub fn source_digest(root: &Path) -> io::Result<(String, Vec<PathBuf>)> {
    let mut files = vec![root.join("Cargo.toml"), root.join("Cargo.lock")];
    collect(&root.join("crates"), &mut files)?;
    // PathBuf ordering compares components: "a/src" precedes "a-b/src".
    // Canonical manifest order instead compares complete serialized paths.
    files.sort_by(|left, right| left.as_os_str().cmp(right.as_os_str()));
    let mut hash = Sha256::new();
    hash.update(b"husker-workspace-rust-source-v1\0");
    for path in &files {
        let relative = path.strip_prefix(root).map_err(io::Error::other)?;
        let name = relative
            .to_str()
            .ok_or_else(|| io::Error::other("non-UTF-8 source path"))?;
        let metadata = path.symlink_metadata()?;
        if !metadata.is_file() || metadata.len() > 32 * 1024 * 1024 {
            return Err(io::Error::other(
                "regular source input bounded to 32 MiB required",
            ));
        }
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name.as_bytes());
        hash.update(metadata.len().to_be_bytes());
        let mut file = std::fs::File::open(path)?;
        let mut read = 0u64;
        let mut buffer = [0; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            read += count as u64;
            if read > metadata.len() {
                return Err(io::Error::other("source input grew during digest"));
            }
            hash.update(&buffer[..count]);
        }
        let after = file.metadata()?;
        if read != metadata.len()
            || after.len() != metadata.len()
            || after.modified()? != metadata.modified()?
        {
            return Err(io::Error::other("source input changed during digest"));
        }
    }
    let mut digest = String::with_capacity(64);
    for byte in hash.finalize() {
        write!(&mut digest, "{byte:02x}").expect("writing to String is infallible");
    }
    Ok((digest, files))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifest_order_compares_complete_paths_instead_of_path_components() {
        let root = tempfile::tempdir().unwrap();
        for directory in ["crates/a/src", "crates/a-b/src"] {
            std::fs::create_dir_all(root.path().join(directory)).unwrap();
            std::fs::write(root.path().join(directory).join("lib.rs"), "source").unwrap();
        }
        std::fs::write(root.path().join("Cargo.toml"), "manifest").unwrap();
        std::fs::write(root.path().join("Cargo.lock"), "lock").unwrap();
        let (_, paths) = source_digest(root.path()).unwrap();
        let names: Vec<_> = paths
            .iter()
            .map(|path| path.strip_prefix(root.path()).unwrap().to_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "Cargo.lock",
                "Cargo.toml",
                "crates/a-b/src/lib.rs",
                "crates/a/src/lib.rs"
            ]
        );
    }
    #[test]
    fn digest_binds_source_names_contents_and_lockfile_without_local_reports() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("crates/vmm/src")).unwrap();
        std::fs::write(root.path().join("Cargo.toml"), "manifest").unwrap();
        std::fs::write(root.path().join("Cargo.lock"), "lock").unwrap();
        let source = root.path().join("crates/vmm/src/lib.rs");
        std::fs::write(&source, "first").unwrap();
        let first = source_digest(root.path()).unwrap().0;
        let copied = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(copied.path().join("crates/vmm/src")).unwrap();
        for relative in ["Cargo.toml", "Cargo.lock", "crates/vmm/src/lib.rs"] {
            std::fs::copy(root.path().join(relative), copied.path().join(relative)).unwrap();
        }
        assert_eq!(first, source_digest(copied.path()).unwrap().0);
        std::fs::write(root.path().join("DESIGN.md"), "private report").unwrap();
        assert_eq!(first, source_digest(root.path()).unwrap().0);
        std::fs::write(&source, "other").unwrap();
        let other = source_digest(root.path()).unwrap().0;
        assert_ne!(first, other);
        std::fs::rename(&source, source.with_file_name("other.rs")).unwrap();
        let renamed = source_digest(root.path()).unwrap().0;
        assert_ne!(other, renamed);
        std::fs::write(root.path().join("Cargo.lock"), "new lock").unwrap();
        assert_ne!(renamed, source_digest(root.path()).unwrap().0);
    }

    #[test]
    fn source_symlinks_and_oversized_files_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("crates/vmm/src")).unwrap();
        std::fs::write(root.path().join("Cargo.toml"), "manifest").unwrap();
        std::fs::write(root.path().join("Cargo.lock"), "lock").unwrap();
        let source = root.path().join("crates/vmm/src/lib.rs");
        std::os::unix::fs::symlink(root.path().join("Cargo.toml"), &source).unwrap();
        assert!(source_digest(root.path()).is_err());
        std::fs::remove_file(&source).unwrap();
        std::fs::File::create(&source)
            .unwrap()
            .set_len(32 * 1024 * 1024 + 1)
            .unwrap();
        assert!(source_digest(root.path()).is_err());
    }
}
