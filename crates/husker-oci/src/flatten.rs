//! Flatten OCI image layers into a single directory tree, honouring overlay
//! whiteouts (`.wh.<name>` deletions and `.wh..wh..opq` opaque directories).

use std::fs;
use std::path::{Component, Path, PathBuf};

use flate2::read::GzDecoder;

use crate::OciError;

/// What a tar entry means when flattening overlay layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhiteoutKind {
    /// A normal file/dir/symlink to unpack.
    Regular,
    /// A `.wh.<name>` marker: delete the named path from lower layers.
    Whiteout,
    /// A `.wh..wh..opq` marker: clear the contents of the containing directory.
    OpaqueDir,
}

/// Classify a tar entry path. For `Whiteout`/`OpaqueDir` the returned string is
/// the path (relative to the rootfs) to delete or clear; for `Regular` it is the
/// entry path unchanged.
pub fn classify_entry(path: &str) -> (WhiteoutKind, String) {
    let p = Path::new(path);
    let file_name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let parent = p
        .parent()
        .map(|x| x.to_string_lossy().to_string())
        .unwrap_or_default();

    if file_name == ".wh..wh..opq" {
        (WhiteoutKind::OpaqueDir, parent)
    } else if let Some(name) = file_name.strip_prefix(".wh.") {
        let target = if parent.is_empty() {
            name.to_string()
        } else {
            format!("{parent}/{name}")
        };
        (WhiteoutKind::Whiteout, target)
    } else {
        (WhiteoutKind::Regular, path.to_string())
    }
}

/// Flatten gzip-compressed layer blobs (base layer first) into `dest`, applying
/// each layer's overlay whiteouts in order.
pub fn flatten_layers(layers: &[Vec<u8>], dest: &Path) -> Result<(), OciError> {
    fs::create_dir_all(dest)?;
    for layer in layers {
        apply_layer(layer, dest)?;
    }
    Ok(())
}

/// Decompress a layer blob, detecting the codec by magic bytes: gzip (`1f 8b`)
/// or zstd (`28 b5 2f fd`). Anything else is rejected. zstd uses the pure-Rust
/// `ruzstd` decoder (no C dependency).
fn decompress_layer(blob: &[u8]) -> Result<Box<dyn std::io::Read + '_>, OciError> {
    if blob.starts_with(&[0x1f, 0x8b]) {
        Ok(Box::new(GzDecoder::new(blob)))
    } else if blob.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        let decoder = ruzstd::decoding::StreamingDecoder::new(blob)
            .map_err(|e| OciError::Extract(format!("zstd decode: {e}")))?;
        Ok(Box::new(decoder))
    } else {
        Err(OciError::Extract(
            "unsupported layer compression (expected gzip or zstd)".into(),
        ))
    }
}

fn apply_layer(blob: &[u8], dest: &Path) -> Result<(), OciError> {
    let reader = decompress_layer(blob)?;
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.set_overwrite(true);
    let real_dest = fs::canonicalize(dest)?;

    for entry in archive
        .entries()
        .map_err(|e| OciError::Extract(e.to_string()))?
    {
        let mut entry = entry.map_err(|e| OciError::Extract(e.to_string()))?;
        let path = entry
            .path()
            .map_err(|e| OciError::Extract(e.to_string()))?
            .to_string_lossy()
            .to_string();

        if !is_safe_relative(&path) {
            return Err(OciError::Extract(format!(
                "unsafe layer entry path: {path}"
            )));
        }

        match classify_entry(&path) {
            (WhiteoutKind::Regular, _) => {
                // `unpack_in` refuses to escape `dest` and returns false if it did.
                entry
                    .unpack_in(dest)
                    .map_err(|e| OciError::Extract(format!("unpack {path}: {e}")))?;
            }
            (WhiteoutKind::Whiteout, target) => {
                if let Some(target) = resolve_inside_rootfs(dest, &real_dest, Path::new(&target))? {
                    remove_path(&target);
                }
            }
            (WhiteoutKind::OpaqueDir, dir) => {
                if dir.is_empty() {
                    clear_dir(dest);
                } else if let Some(dir) = resolve_inside_rootfs(dest, &real_dest, Path::new(&dir))?
                {
                    clear_dir(&dir);
                }
            }
        }
    }
    Ok(())
}

/// Resolve the directory containing `relative` (a whiteout target or an opaque
/// directory) and re-join the final component, so a whiteout acts on the same
/// place a regular entry of the same layer would land. Intermediate symlinks
/// that stay inside the rootfs are followed, exactly as `tar` does for regular
/// entries; one that leads outside rejects the layer, because an untrusted
/// image must never delete host files. The final component is deliberately
/// not resolved: `remove_path` and `clear_dir` refuse to traverse a symlink
/// there. `None` means the containing directory does not exist, so there is
/// nothing to delete.
fn resolve_inside_rootfs(
    dest: &Path,
    real_dest: &Path,
    relative: &Path,
) -> Result<Option<PathBuf>, OciError> {
    let Some(name) = relative.file_name() else {
        return Ok(None);
    };
    let parent = dest.join(relative.parent().unwrap_or(Path::new("")));
    let real_parent = match fs::canonicalize(&parent) {
        Ok(p) => p,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(None);
        }
        Err(e) => {
            return Err(OciError::Extract(format!(
                "resolve layer entry {}: {e}",
                relative.display()
            )));
        }
    };
    if !real_parent.starts_with(real_dest) {
        return Err(OciError::Extract(format!(
            "layer entry {} resolves outside the rootfs",
            relative.display()
        )));
    }
    Ok(Some(real_parent.join(name)))
}

/// Reject absolute paths and any `..`/root/prefix component (path traversal).
fn is_safe_relative(path: &str) -> bool {
    let p = Path::new(path);
    !p.is_absolute()
        && p.components().all(|c| {
            !matches!(
                c,
                Component::ParentDir | Component::Prefix(_) | Component::RootDir
            )
        })
}

/// Remove `p`, never following a symlink: a symlink (even to a directory) is
/// unlinked, only a real directory is recursed into. OCI images are untrusted,
/// so a symlinked path must not let a whiteout delete outside the rootfs.
fn remove_path(p: &Path) {
    match fs::symlink_metadata(p) {
        Ok(meta) if meta.file_type().is_dir() => {
            let _ = fs::remove_dir_all(p);
        }
        Ok(_) => {
            let _ = fs::remove_file(p);
        }
        Err(_) => {}
    }
}

/// Clear the contents of `d` only when it is a real directory; a symlink in the
/// whiteout's place is never traversed (it could point outside the rootfs).
fn clear_dir(d: &Path) {
    match fs::symlink_metadata(d) {
        Ok(meta) if meta.file_type().is_dir() => {
            if let Ok(rd) = fs::read_dir(d) {
                for e in rd.flatten() {
                    remove_path(&e.path());
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn classify_regular_whiteout_and_opaque() {
        assert_eq!(
            classify_entry("etc/hosts"),
            (WhiteoutKind::Regular, "etc/hosts".to_string())
        );
        assert_eq!(
            classify_entry("etc/.wh.hosts"),
            (WhiteoutKind::Whiteout, "etc/hosts".to_string())
        );
        assert_eq!(
            classify_entry(".wh.toplevel"),
            (WhiteoutKind::Whiteout, "toplevel".to_string())
        );
        assert_eq!(
            classify_entry("var/cache/.wh..wh..opq"),
            (WhiteoutKind::OpaqueDir, "var/cache".to_string())
        );
    }

    #[test]
    fn is_safe_relative_rejects_traversal() {
        assert!(is_safe_relative("a/b/c"));
        assert!(!is_safe_relative("/etc/passwd"));
        assert!(!is_safe_relative("../escape"));
        assert!(!is_safe_relative("a/../../b"));
    }

    /// Build a one-file gzipped tar layer in memory.
    fn gz_layer(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            for (name, data) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, name, *data).unwrap();
            }
            builder.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar_buf).unwrap();
        gz.finish().unwrap()
    }

    /// Build a one-file zstd-compressed tar layer in memory.
    fn zstd_layer(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            for (name, data) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, name, *data).unwrap();
            }
            builder.finish().unwrap();
        }
        zstd::encode_all(&tar_buf[..], 0).unwrap()
    }

    #[test]
    fn flatten_applies_a_zstd_layer() {
        // Modern docker buildx defaults to zstd; husker must flatten it like gzip.
        let layer = zstd_layer(&[("app/hello.txt", b"zstd-content")]);
        let dir = tempfile::tempdir().unwrap();
        flatten_layers(&[layer], dir.path()).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("app/hello.txt")).unwrap(),
            "zstd-content"
        );
    }

    #[test]
    fn whiteout_of_symlink_does_not_delete_through_it() {
        // An untrusted layer could place a symlink to somewhere outside the
        // rootfs, then a later layer whiteout it. Removing the whiteout target
        // must unlink the symlink, never traverse it.
        let outside = tempfile::tempdir().unwrap();
        let precious = outside.path().join("precious.txt");
        fs::write(&precious, b"keep").unwrap();

        let dest = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dest.path().join("link")).unwrap();

        remove_path(&dest.path().join("link"));
        assert!(
            !dest.path().join("link").exists(),
            "the symlink itself is removed"
        );
        assert!(
            precious.exists(),
            "files behind the symlink must not be deleted"
        );

        // clear_dir on a symlinked path must also refuse to traverse it.
        std::os::unix::fs::symlink(outside.path(), dest.path().join("link2")).unwrap();
        clear_dir(&dest.path().join("link2"));
        assert!(precious.exists(), "clear_dir must not traverse a symlink");
    }

    /// Build a gzipped tar layer whose first entry is the symlink
    /// `link_name -> target`, followed by regular files.
    fn gz_layer_with_symlink(link_name: &str, target: &Path, files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Symlink);
            link.set_size(0);
            link.set_mode(0o777);
            builder.append_link(&mut link, link_name, target).unwrap();
            for (name, data) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, name, *data).unwrap();
            }
            builder.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar_buf).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn whiteout_does_not_delete_through_an_intermediate_symlink() {
        // Layer 1 plants `a -> <outside the rootfs>`; layer 2 whiteouts
        // `a/precious.txt`. Resolving the whiteout path through the symlink
        // would delete a host file.
        let outside = tempfile::tempdir().unwrap();
        let precious = outside.path().join("precious.txt");
        fs::write(&precious, b"keep").unwrap();

        let lower = gz_layer_with_symlink("a", outside.path(), &[]);
        let upper = gz_layer(&[("a/.wh.precious.txt", b"")]);

        let dest = tempfile::tempdir().unwrap();
        let err = flatten_layers(&[lower, upper], dest.path()).unwrap_err();
        assert!(
            err.to_string().contains("resolves outside the rootfs"),
            "the escaping layer is rejected, got: {err}"
        );
        assert!(
            precious.exists(),
            "a whiteout under a symlinked directory must not reach outside the rootfs"
        );
    }

    #[test]
    fn whiteout_follows_a_symlink_that_stays_inside_the_rootfs() {
        // Positive control for the escape check: `a -> b` inside the rootfs is
        // followed, so `a/.wh.x` deletes `b/x` exactly where a regular entry
        // `a/x` from the same layer would have landed.
        let lower = gz_layer_with_symlink(
            "a",
            Path::new("b"),
            &[("b/x.txt", b"gone"), ("b/keep.txt", b"keep")],
        );
        let upper = gz_layer(&[("a/.wh.x.txt", b"")]);

        let dest = tempfile::tempdir().unwrap();
        flatten_layers(&[lower, upper], dest.path()).unwrap();
        assert!(
            !dest.path().join("b/x.txt").exists(),
            "whiteout applied through the inner symlink"
        );
        assert!(
            dest.path().join("b/keep.txt").exists(),
            "siblings untouched"
        );
    }

    #[test]
    fn whiteout_under_a_missing_directory_is_a_no_op() {
        let only = gz_layer(&[("nope/.wh.x.txt", b""), ("ok.txt", b"ok")]);
        let dest = tempfile::tempdir().unwrap();
        flatten_layers(&[only], dest.path()).unwrap();
        assert_eq!(
            fs::read_to_string(dest.path().join("ok.txt")).unwrap(),
            "ok"
        );
    }

    #[test]
    fn opaque_marker_does_not_clear_through_an_intermediate_symlink() {
        // Same shape with an opaque-directory marker: `a/sub/.wh..wh..opq`
        // where `a` is a symlink must not empty the real directory it points at.
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir(outside.path().join("sub")).unwrap();
        let precious = outside.path().join("sub").join("precious.txt");
        fs::write(&precious, b"keep").unwrap();

        let lower = gz_layer_with_symlink("a", outside.path(), &[]);
        let upper = gz_layer(&[("a/sub/.wh..wh..opq", b"")]);

        let dest = tempfile::tempdir().unwrap();
        let err = flatten_layers(&[lower, upper], dest.path()).unwrap_err();
        assert!(
            err.to_string().contains("resolves outside the rootfs"),
            "the escaping layer is rejected, got: {err}"
        );
        assert!(
            precious.exists(),
            "an opaque marker under a symlinked directory must not clear a host directory"
        );
    }

    #[test]
    fn flatten_applies_layers_and_whiteouts() {
        let base = gz_layer(&[("app/keep.txt", b"keep"), ("app/gone.txt", b"old")]);
        // Second layer overwrites keep.txt and whiteouts gone.txt.
        let top = gz_layer(&[("app/keep.txt", b"new"), ("app/.wh.gone.txt", b"")]);

        let dir = tempfile::tempdir().unwrap();
        flatten_layers(&[base, top], dir.path()).unwrap();

        assert_eq!(
            fs::read_to_string(dir.path().join("app/keep.txt")).unwrap(),
            "new",
            "upper layer overwrites the file"
        );
        assert!(
            !dir.path().join("app/gone.txt").exists(),
            "whiteout removes the lower-layer file"
        );
    }
}
