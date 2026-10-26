//! Every Apple VZ disk image attachment must be created with explicit
//! `Cached` caching and `Fsync` synchronization.
//!
//! The default attachment modes corrupt re-reads of sparse raw images on
//! APFS: the guest boots cleanly, then minutes later evicted pages come back
//! as zeros (random segfaults, a deaf sshd, EIO from the agent) while the host
//! file stays intact. The compiler cannot tell the two initializers apart, so
//! this guard reads the crate's sources as text. It therefore runs on every
//! platform the suite runs on, not only where the Apple VZ modules compile.

use std::path::{Path, PathBuf};

const CRATE_SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
const ATTACHMENT: &str = "VZDiskImageStorageDeviceAttachment";
const EXPLICIT_MODES_INITIALIZER: &str =
    "initWithURL_readOnly_cachingMode_synchronizationMode_error";
const DEFAULT_MODES_INITIALIZER: &str = "initWithURL_readOnly_error";
const REQUIRED_MODES: [&str; 2] = [
    "VZDiskImageCachingMode::Cached",
    "VZDiskImageSynchronizationMode::Fsync",
];

/// Every `.rs` file under the crate's `src/`, in a stable order.
fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn sources() -> Vec<(PathBuf, String)> {
    let mut paths = Vec::new();
    rust_sources(Path::new(CRATE_SRC), &mut paths);
    paths
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            (path, text)
        })
        .collect()
}

/// One attachment construction: where it is and the full call text, from the
/// initializer name through the closing parenthesis of its argument list.
struct Site {
    file: PathBuf,
    line: usize,
    call: String,
}

fn attachment_sites(file: &Path, source: &str) -> Vec<Site> {
    let prefix = format!("{ATTACHMENT}::initWith");
    source
        .match_indices(&prefix)
        .map(|(start, _)| {
            let call_start = start + ATTACHMENT.len() + "::".len();
            Site {
                file: file.to_path_buf(),
                line: source[..start].matches('\n').count() + 1,
                call: balanced_call(&source[call_start..]).to_string(),
            }
        })
        .collect()
}

/// The call text up to the parenthesis that closes its argument list, so
/// nested calls such as `alloc()` in the first argument do not cut it short.
fn balanced_call(text: &str) -> &str {
    let open = text
        .find('(')
        .expect("an attachment initializer is followed by its argument list");
    let mut depth = 0usize;
    for (offset, c) in text[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return &text[..open + offset + 1];
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced argument list in {text:?}");
}

#[test]
fn every_disk_image_attachment_uses_explicit_cached_and_fsync_modes() {
    let sources = sources();
    let sites: Vec<Site> = sources
        .iter()
        .flat_map(|(path, text)| attachment_sites(path, text))
        .collect();

    // Positive control: the scanner must still see the known attachment sites
    // in both Apple VZ modules, or a rename could silence this guard.
    for module in ["apple_vz.rs", "apple_vz_macos.rs"] {
        assert!(
            sites
                .iter()
                .any(|site| site.file.file_name().is_some_and(|name| name == module)),
            "no {ATTACHMENT} construction found in {module}; the guard no longer sees the sites it protects"
        );
    }

    for site in &sites {
        let at = format!("{}:{}", site.file.display(), site.line);
        assert!(
            site.call
                .starts_with(&format!("{EXPLICIT_MODES_INITIALIZER}(")),
            "{at}: a disk image attachment must be built with {EXPLICIT_MODES_INITIALIZER}, \
             the default modes corrupt sparse images on APFS:\n{}",
            site.call
        );
        for mode in REQUIRED_MODES {
            assert!(
                site.call.contains(mode),
                "{at}: a disk image attachment must pass {mode}:\n{}",
                site.call
            );
        }
    }
}

#[test]
fn the_default_modes_initializer_is_never_named() {
    for (path, text) in sources() {
        if let Some(offset) = text.find(DEFAULT_MODES_INITIALIZER) {
            let line = text[..offset].matches('\n').count() + 1;
            panic!(
                "{}:{line}: {DEFAULT_MODES_INITIALIZER} leaves the attachment on the default \
                 caching and synchronization modes, which corrupt sparse images on APFS; use \
                 {EXPLICIT_MODES_INITIALIZER} with {} and {}",
                path.display(),
                REQUIRED_MODES[0],
                REQUIRED_MODES[1]
            );
        }
        let alias = format!("{ATTACHMENT} as ");
        if let Some(offset) = text.find(&alias) {
            let line = text[..offset].matches('\n').count() + 1;
            panic!(
                "{}:{line}: {ATTACHMENT} is imported under another name, which would hide its \
                 constructions from the attachment mode guard",
                path.display()
            );
        }
    }
}
