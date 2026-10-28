//! Descriptor-relative Unix operations: directory replacements cannot redirect
//! reads or extraction through symlinks. Callers supply a trusted open root.
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use super::{
    BundleError, BundleFile, CollectedArtifact, FrozenBundle, MAX_ARTIFACT_BYTES, MAX_BUNDLE_BYTES,
    MAX_BUNDLE_FILES, excluded_bundle_component, safe_bundle_path,
};

fn component(name: &str) -> Result<CString, BundleError> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(BundleError::Invalid("single directory component required"));
    }
    CString::new(name).map_err(|_| BundleError::Invalid("NUL in filename"))
}

fn open(parent: &File, name: &str, flags: i32) -> Result<File, BundleError> {
    let name = component(name)?;
    // SAFETY: valid borrowed descriptor and NUL-terminated component. Returned
    // descriptor is adopted exactly once and never follows a symlink.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn mkdir(parent: &File, name: &str) -> Result<(), BundleError> {
    let name = component(name)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

/// Export exactly one declared regular file without following links in any
/// component. Bounded reads and post-read metadata checks detect changes.
pub fn collect_declared_artifact(
    root: &File,
    path: &str,
    max_bytes: usize,
) -> Result<CollectedArtifact, BundleError> {
    if !safe_bundle_path(path) || max_bytes == 0 || max_bytes > MAX_ARTIFACT_BYTES {
        return Err(BundleError::Invalid(
            "invalid declared artifact path or limit",
        ));
    }
    let mut directory = root.try_clone()?;
    let mut parts = path.split('/').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_some() {
            directory = open(&directory, part, libc::O_RDONLY | libc::O_DIRECTORY)?;
        } else {
            let mut file = open(&directory, part, libc::O_RDONLY | libc::O_NONBLOCK)?;
            let before = file.metadata()?;
            if !before.is_file() || before.nlink() != 1 || before.len() > max_bytes as u64 {
                return Err(BundleError::Invalid(
                    "artifact is linked, special or oversized",
                ));
            }
            let mut data = Vec::with_capacity(before.len() as usize);
            (&mut file)
                .take(max_bytes as u64 + 1)
                .read_to_end(&mut data)?;
            let after = file.metadata()?;
            if data.len() as u64 != before.len()
                || before.len() != after.len()
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
                || before.mode() != after.mode()
                || after.nlink() != 1
            {
                return Err(BundleError::Invalid("artifact changed during collection"));
            }
            return Ok(CollectedArtifact {
                digest: super::digest(&data),
                data,
            });
        }
    }
    Err(BundleError::Invalid("empty artifact path"))
}

fn names(directory: &File) -> Result<Vec<String>, BundleError> {
    // Open a fresh directory description; dup would share readdir's offset.
    let dot = CString::new(".").expect("static component");
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(error.into());
    }
    struct Directory(*mut libc::DIR);
    impl Drop for Directory {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let stream = Directory(stream);
    let mut result = Vec::new();
    loop {
        // readdir is permitted to leave errno untouched at EOF.
        #[cfg(target_os = "linux")]
        unsafe {
            *libc::__errno_location() = 0;
        }
        #[cfg(target_os = "macos")]
        unsafe {
            *libc::__error() = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error.into());
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }
            .to_str()
            .map_err(|_| BundleError::Invalid("filenames must be UTF-8"))?;
        if name != "." && name != ".." {
            if result.len() >= MAX_BUNDLE_FILES {
                return Err(BundleError::Invalid("directory entry limit exceeded"));
            }
            result.push(name.to_owned());
        }
    }
    result.sort();
    Ok(result)
}

fn walk(
    directory: &File,
    prefix: &str,
    files: &mut BTreeMap<String, BundleFile>,
    budget: &mut usize,
    entries: &mut usize,
    ignored: &[String],
) -> Result<(), BundleError> {
    if !directory.metadata()?.is_dir() {
        return Err(BundleError::Invalid("root must be a directory"));
    }
    for name in names(directory)? {
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if ignored.contains(&path) {
            continue;
        }
        // Omit known credentials and configuration directories deliberately.
        // Everything else that is unsafe is rejected rather than normalized.
        if excluded_bundle_component(&name) {
            continue;
        }
        if !safe_bundle_path(&path) {
            return Err(BundleError::Invalid("unsafe or overlong path"));
        }
        *entries += 1;
        if *entries > MAX_BUNDLE_FILES {
            return Err(BundleError::Invalid("tree entry limit exceeded"));
        }
        let mut file = open(directory, &name, libc::O_RDONLY | libc::O_NONBLOCK)?;
        let before = file.metadata()?;
        if before.is_dir() {
            walk(&file, &path, files, budget, entries, ignored)?;
        } else if before.is_file() && before.nlink() == 1 {
            let size = usize::try_from(before.len())
                .map_err(|_| BundleError::Invalid("file too large"))?;
            if size > MAX_BUNDLE_BYTES {
                return Err(BundleError::Invalid("file exceeds 32 MiB"));
            }
            *budget = budget
                .checked_add(512 + size.div_ceil(512) * 512)
                .ok_or(BundleError::Invalid("size overflow"))?;
            if *budget > MAX_BUNDLE_BYTES {
                return Err(BundleError::Invalid("archive exceeds 32 MiB"));
            }
            let mut data = Vec::with_capacity(size);
            (&mut file).take(size as u64 + 1).read_to_end(&mut data)?;
            let after = file.metadata()?;
            if data.len() != size
                || before.len() != after.len()
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
                || before.mode() != after.mode()
                || after.nlink() != 1
            {
                return Err(BundleError::Invalid("source changed while being frozen"));
            }
            files.insert(
                path,
                BundleFile {
                    data,
                    executable: before.mode() & 0o111 != 0,
                },
            );
        } else {
            return Err(BundleError::Invalid("links and special files forbidden"));
        }
    }
    Ok(())
}

impl FrozenBundle {
    /// Publish to a new file under a trusted open directory. Existing files and
    /// symlinks are refused; the file and parent directory are synced.
    pub fn write_new_file(&self, parent: &File, name: &str) -> Result<(), BundleError> {
        let mut file = open(parent, name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
        file.write_all(self.bytes())?;
        file.sync_all()?;
        parent.sync_all()?;
        Ok(())
    }

    /// Copies only the selected directory, excludes credential paths, rejects
    /// symlinks/hardlinks/special files, and observes the tree twice to detect
    /// changes during capture. This is not a transaction against a hostile host
    /// writer that can change and restore bytes between observations.
    pub fn freeze_directory(root: &File) -> Result<Self, BundleError> {
        Self::freeze_directory_excluding(root, &[])
    }

    /// Re-inventory frozen source after checks, excluding only operator-declared
    /// initially empty build/output directories. Callers must reject exclusions
    /// overlapping the initial source bundle before executing commands.
    pub fn freeze_directory_excluding(
        root: &File,
        ignored: &[String],
    ) -> Result<Self, BundleError> {
        if ignored.len() > 16 || ignored.iter().any(|path| !safe_bundle_path(path)) {
            return Err(BundleError::Invalid("invalid inventory exclusions"));
        }
        fn snapshot(
            root: &File,
            ignored: &[String],
        ) -> Result<BTreeMap<String, BundleFile>, BundleError> {
            let mut files = BTreeMap::new();
            walk(root, "", &mut files, &mut 1024, &mut 0, ignored)?;
            Ok(files)
        }
        let first = snapshot(root, ignored)?;
        if first != snapshot(root, ignored)? {
            return Err(BundleError::Invalid(
                "source tree changed while being frozen",
            ));
        }
        Self::from_files(first)
    }

    /// Creates a NEW private directory under an already-open trusted parent.
    /// Refuses existing destinations. No tar metadata, owner, links or special
    /// files are applied. On failure a partial private tree may remain; callers
    /// must not execute it and must destroy the disposable workspace.
    /// Caller owns subsequent uid/gid and read-only acceptance enforcement.
    pub fn extract_new_directory(&self, parent: &File, name: &str) -> Result<File, BundleError> {
        mkdir(parent, name)?;
        let root = open(parent, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        for (path, entry) in &self.files {
            let mut directory = root.try_clone()?;
            let mut parts = path.split('/').peekable();
            while let Some(part) = parts.next() {
                if parts.peek().is_some() {
                    match mkdir(&directory, part) {
                        Ok(()) => {}
                        Err(BundleError::Io(error))
                            if error.kind() == io::ErrorKind::AlreadyExists => {}
                        Err(error) => return Err(error),
                    }
                    directory = open(&directory, part, libc::O_RDONLY | libc::O_DIRECTORY)?;
                } else {
                    let mut file = open(
                        &directory,
                        part,
                        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                    )?;
                    file.write_all(&entry.data)?;
                    file.set_permissions(std::fs::Permissions::from_mode(if entry.executable {
                        0o755
                    } else {
                        0o644
                    }))?;
                    file.sync_all()?;
                    directory.sync_all()?;
                }
            }
        }
        root.sync_all()?;
        parent.sync_all()?;
        Ok(root)
    }
}
