//! Descriptor-relative Unix operations: directory replacements cannot redirect
//! reads or extraction through symlinks. Callers supply a trusted open root.
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::{File, Metadata};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
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
            (flags | libc::O_CLOEXEC) | libc::O_NOFOLLOW,
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

/// Everything about an open file that must be identical before and after it is
/// read for the read to count as a consistent snapshot.
#[derive(PartialEq, Eq)]
struct Stamp {
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
    mode: u32,
    nlink: u64,
}

impl Stamp {
    fn of(metadata: &Metadata) -> Self {
        Self {
            len: metadata.len(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
            mode: metadata.mode(),
            nlink: metadata.nlink(),
        }
    }
}

/// Reads at most `limit` bytes and refuses the result unless it has exactly the
/// length `before` reported and the file's metadata is unchanged afterwards.
fn read_stable(
    file: &mut File,
    before: &Metadata,
    limit: u64,
    changed: &'static str,
) -> Result<Vec<u8>, BundleError> {
    let mut data = Vec::with_capacity(before.len() as usize);
    file.take(limit).read_to_end(&mut data)?;
    if data.len() as u64 != before.len() {
        return Err(BundleError::Invalid(changed));
    }
    if Stamp::of(before) != Stamp::of(&file.metadata()?) {
        return Err(BundleError::Invalid(changed));
    }
    Ok(data)
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
            let data = read_stable(
                &mut file,
                &before,
                max_bytes as u64 + 1,
                "artifact changed during collection",
            )?;
            return Ok(CollectedArtifact {
                digest: super::digest(&data),
                data,
            });
        }
    }
    Err(BundleError::Invalid("empty artifact path"))
}

fn open_fresh_directory(directory: &File) -> Result<File, BundleError> {
    // Open a fresh directory description; dup would share readdir's offset.
    let dot = CString::new(".").expect("static component");
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            dot.as_ptr(),
            libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn names(directory: &File) -> Result<Vec<String>, BundleError> {
    let descriptor = open_fresh_directory(directory)?;
    let stream = unsafe { libc::fdopendir(descriptor.as_raw_fd()) };
    if stream.is_null() {
        return Err(io::Error::last_os_error().into());
    }
    // fdopendir owns the descriptor only after it succeeds.
    let _fd = descriptor.into_raw_fd();
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
            let data = read_stable(
                &mut file,
                &before,
                size as u64 + 1,
                "source changed while being frozen",
            )?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::time::Duration;

    const ISOLATED_ENV: &str = "HUSKER_FROZEN_BUNDLE_FS_ISOLATED";

    fn invalid<T>(result: Result<T, BundleError>) -> &'static str {
        match result {
            Err(BundleError::Invalid(message)) => message,
            Err(other) => panic!("expected an invalid-bundle error, got {other}"),
            Ok(_) => panic!("expected an invalid-bundle error, got success"),
        }
    }

    fn os_error<T>(result: Result<T, BundleError>) -> i32 {
        match result {
            Err(BundleError::Io(error)) => error.raw_os_error().expect("an OS error"),
            Err(other) => panic!("expected an I/O error, got {other}"),
            Ok(_) => panic!("expected an I/O error, got success"),
        }
    }

    fn directory(path: &std::path::Path) -> File {
        File::open(path).unwrap()
    }

    fn file_of(data: &[u8], executable: bool) -> BundleFile {
        BundleFile {
            data: data.to_vec(),
            executable,
        }
    }

    /// Re-runs the calling test alone in a fresh process so it can manipulate
    /// process-wide descriptor state. Returns true inside that child.
    fn isolated(name: &str) -> bool {
        if std::env::var_os(ISOLATED_ENV).is_some_and(|value| value == name) {
            return true;
        }
        let filter = format!(
            "{}::{name}",
            module_path!().split_once("::").expect("crate prefix").1
        );
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &filter, "--test-threads=1", "--nocapture"])
            .env(ISOLATED_ENV, name)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        false
    }

    #[test]
    fn component_accepts_exactly_one_plain_name() {
        for name in ["a", "file.txt", ".hidden"] {
            assert_eq!(component(name).unwrap().to_str().unwrap(), name);
        }
        for name in ["", ".", "..", "a/b", "/", "a/"] {
            assert_eq!(
                invalid(component(name)),
                "single directory component required",
                "{name:?}"
            );
        }
        assert_eq!(invalid(component("a\0b")), "NUL in filename");
    }

    #[test]
    fn open_always_sets_close_on_exec_and_never_follows_links() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("target"), b"x").unwrap();
        symlink(temp.path().join("target"), temp.path().join("link")).unwrap();
        let parent = directory(temp.path());

        let plain = open(&parent, "target", libc::O_RDONLY).unwrap();
        let flags = unsafe { libc::fcntl(plain.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        let redundant = open(&parent, "target", libc::O_RDONLY | libc::O_CLOEXEC).unwrap();
        let flags = unsafe { libc::fcntl(redundant.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);

        assert!(open(&parent, "link", libc::O_RDONLY).is_err());
        assert!(open(&parent, "link", libc::O_RDONLY | libc::O_NOFOLLOW).is_err());
    }

    #[test]
    fn open_accepts_descriptor_zero() {
        if !isolated("open_accepts_descriptor_zero") {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("f"), b"x").unwrap();
        let parent = directory(temp.path());
        assert_eq!(unsafe { libc::close(0) }, 0);
        let file = open(&parent, "f", libc::O_RDONLY).unwrap();
        assert_eq!(file.as_raw_fd(), 0);
    }

    #[test]
    fn directory_open_is_close_on_exec_before_fdopendir_can_set_the_flag() {
        let temp = tempfile::tempdir().unwrap();
        let parent = directory(temp.path());
        let descriptor = open_fresh_directory(&parent).unwrap();
        assert!(descriptor.metadata().unwrap().is_dir());
        let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn names_lists_sorted_entries_without_dot_entries() {
        let temp = tempfile::tempdir().unwrap();
        for name in ["c", "a", "b"] {
            fs::write(temp.path().join(name), b"").unwrap();
        }
        fs::create_dir(temp.path().join("sub")).unwrap();
        assert_eq!(
            names(&directory(temp.path())).unwrap(),
            ["a", "b", "c", "sub"]
        );
    }

    #[test]
    fn names_reports_the_error_for_a_non_directory() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("file"), b"").unwrap();
        assert_eq!(
            os_error(names(&directory(&temp.path().join("file")))),
            libc::ENOTDIR
        );
    }

    #[test]
    fn names_works_when_the_lowest_descriptor_is_zero() {
        if !isolated("names_works_when_the_lowest_descriptor_is_zero") {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("f"), b"").unwrap();
        let parent = directory(temp.path());
        assert_eq!(unsafe { libc::close(0) }, 0);
        assert_eq!(names(&parent).unwrap(), ["f"]);
    }

    #[test]
    fn names_releases_its_directory_stream() {
        if !isolated("names_releases_its_directory_stream") {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("f"), b"").unwrap();
        let parent = directory(temp.path());
        // The lowest unused descriptor only moves up if descriptors leak.
        let lowest_free = || unsafe {
            let fd = libc::dup(0);
            libc::close(fd);
            fd
        };
        let before = lowest_free();
        for _ in 0..50 {
            names(&parent).unwrap();
        }
        assert_eq!(lowest_free(), before);
    }

    #[test]
    fn collect_validates_path_and_limit_independently_of_the_file() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join(".env"), b"x").unwrap();
        fs::write(temp.path().join("empty"), b"").unwrap();
        fs::write(temp.path().join("small"), b"abc").unwrap();
        let root = directory(temp.path());
        let message = "invalid declared artifact path or limit";

        // Each file exists and would otherwise be collectable.
        assert_eq!(
            invalid(collect_declared_artifact(&root, ".env", 3)),
            message
        );
        assert_eq!(
            invalid(collect_declared_artifact(&root, "empty", 0)),
            message
        );
        assert_eq!(
            invalid(collect_declared_artifact(
                &root,
                "small",
                MAX_ARTIFACT_BYTES + 1
            )),
            message
        );

        assert_eq!(
            collect_declared_artifact(&root, "empty", 1).unwrap().data,
            b""
        );
        assert_eq!(
            collect_declared_artifact(&root, "small", MAX_ARTIFACT_BYTES)
                .unwrap()
                .data,
            b"abc"
        );
    }

    #[test]
    fn collect_refuses_linked_special_and_oversized_files_with_one_reason() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("file"), b"abc").unwrap();
        fs::hard_link(temp.path().join("file"), temp.path().join("twin")).unwrap();
        fs::create_dir(temp.path().join("dir")).unwrap();
        fs::write(temp.path().join("big"), b"abcd").unwrap();
        let root = directory(temp.path());
        let message = "artifact is linked, special or oversized";

        assert_eq!(
            invalid(collect_declared_artifact(&root, "twin", 100)),
            message
        );
        assert_eq!(
            invalid(collect_declared_artifact(&root, "file", 100)),
            message
        );
        assert_eq!(
            invalid(collect_declared_artifact(&root, "dir", 100)),
            message
        );
        fs::remove_file(temp.path().join("twin")).unwrap();
        assert_eq!(invalid(collect_declared_artifact(&root, "big", 3)), message);
        assert_eq!(
            collect_declared_artifact(&root, "big", 4).unwrap().data,
            b"abcd"
        );
    }

    #[test]
    fn collect_rejects_a_non_directory_parent_without_blocking() {
        let temp = tempfile::tempdir().unwrap();
        let fifo = std::ffi::CString::new(temp.path().join("pipe").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let root = directory(temp.path());
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(os_error(collect_declared_artifact(&root, "pipe/leaf", 8)));
        });
        let error = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("opening a FIFO as a parent directory must not block");
        assert_eq!(error, libc::ENOTDIR);
    }

    #[test]
    fn collect_rejects_a_fifo_artifact_without_blocking() {
        let temp = tempfile::tempdir().unwrap();
        let fifo = std::ffi::CString::new(temp.path().join("pipe").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let root = directory(temp.path());
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(invalid(collect_declared_artifact(&root, "pipe", 8)));
        });
        let message = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("opening a FIFO artifact must not block");
        assert_eq!(message, "artifact is linked, special or oversized");
    }

    #[test]
    fn freeze_rejects_a_fifo_without_blocking() {
        let temp = tempfile::tempdir().unwrap();
        let fifo = std::ffi::CString::new(temp.path().join("pipe").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let root = directory(temp.path());
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(invalid(FrozenBundle::freeze_directory(&root)));
        });
        let message = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("opening a FIFO while freezing must not block");
        assert_eq!(message, "links and special files forbidden");
    }

    #[test]
    fn read_stable_returns_the_bytes_of_an_unchanged_file() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("f"), b"abc").unwrap();
        let mut file = open(&directory(temp.path()), "f", libc::O_RDONLY).unwrap();
        let before = file.metadata().unwrap();
        assert_eq!(read_stable(&mut file, &before, 4, "moved").unwrap(), b"abc");
    }

    #[test]
    fn read_stable_detects_growth_shrinkage_and_metadata_changes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("f");
        let parent = directory(temp.path());
        let attempt = |mutate: &dyn Fn()| {
            fs::write(&path, b"abc").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            let mut file = open(&parent, "f", libc::O_RDONLY).unwrap();
            let before = file.metadata().unwrap();
            mutate();
            read_stable(&mut file, &before, 4, "moved")
        };

        assert_eq!(
            invalid(attempt(&|| fs::write(&path, b"abcd").unwrap())),
            "moved"
        );
        assert_eq!(
            invalid(attempt(&|| fs::write(&path, b"ab").unwrap())),
            "moved"
        );
        // Same length, so only the metadata comparison can notice.
        assert_eq!(
            invalid(attempt(&|| {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap()
            })),
            "moved"
        );
        assert_eq!(
            invalid(attempt(&|| fs::write(&path, b"xyz").unwrap())),
            "moved"
        );
        let twin = temp.path().join("twin");
        assert_eq!(
            invalid(attempt(&|| fs::hard_link(&path, &twin).unwrap())),
            "moved"
        );
        // A read cut short by the limit is also not a consistent snapshot.
        fs::remove_file(&twin).unwrap();
        fs::write(&path, b"abc").unwrap();
        let mut file = open(&parent, "f", libc::O_RDONLY).unwrap();
        let before = file.metadata().unwrap();
        assert_eq!(
            invalid(read_stable(&mut file, &before, 2, "moved")),
            "moved"
        );
    }

    #[test]
    fn write_new_file_publishes_exact_bytes_and_refuses_existing_targets() {
        let temp = tempfile::tempdir().unwrap();
        let bundle = FrozenBundle::from_files(BTreeMap::from([(
            "a".to_string(),
            file_of(b"payload", false),
        )]))
        .unwrap();
        let parent = directory(temp.path());
        bundle.write_new_file(&parent, "out.tar").unwrap();
        assert_eq!(
            fs::read(temp.path().join("out.tar")).unwrap(),
            bundle.bytes()
        );

        assert!(bundle.write_new_file(&parent, "out.tar").is_err());
        fs::write(temp.path().join("target"), b"keep").unwrap();
        symlink(temp.path().join("target"), temp.path().join("link")).unwrap();
        assert!(bundle.write_new_file(&parent, "link").is_err());
        assert_eq!(fs::read(temp.path().join("target")).unwrap(), b"keep");
        assert!(bundle.write_new_file(&parent, "x/y").is_err());
    }

    #[test]
    fn freeze_limits_the_number_of_exclusions() {
        let temp = tempfile::tempdir().unwrap();
        let root = directory(temp.path());
        let paths = |count: usize| (0..count).map(|i| format!("out{i}")).collect::<Vec<_>>();
        let message = "invalid inventory exclusions";

        assert!(FrozenBundle::freeze_directory_excluding(&root, &paths(16)).is_ok());
        assert_eq!(
            invalid(FrozenBundle::freeze_directory_excluding(&root, &paths(17))),
            message
        );
        for unsafe_path in [".env", "../up", "a//b", ""] {
            assert_eq!(
                invalid(FrozenBundle::freeze_directory_excluding(
                    &root,
                    &[unsafe_path.to_string()]
                )),
                message,
                "{unsafe_path:?}"
            );
        }
    }

    #[test]
    fn freeze_omits_only_the_declared_exclusions() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("target")).unwrap();
        fs::write(temp.path().join("target/artifact"), b"build output").unwrap();
        fs::write(temp.path().join("keep"), b"source").unwrap();
        let bundle = FrozenBundle::freeze_directory_excluding(
            &directory(temp.path()),
            &["target".to_string()],
        )
        .unwrap();
        assert_eq!(
            bundle.files(),
            &BTreeMap::from([("keep".to_string(), file_of(b"source", false))])
        );
    }

    #[test]
    fn freeze_counts_directories_and_files_against_the_entry_limit() {
        let temp = tempfile::tempdir().unwrap();
        // Two directories plus 8190 files is exactly MAX_BUNDLE_FILES entries,
        // spread out so no single directory trips the per-directory limit.
        let per_directory = (MAX_BUNDLE_FILES - 2) / 2;
        for dir in ["d0", "d1"] {
            fs::create_dir(temp.path().join(dir)).unwrap();
            for i in 0..per_directory {
                fs::write(temp.path().join(dir).join(format!("f{i}")), b"").unwrap();
            }
        }
        let root = directory(temp.path());
        let bundle = FrozenBundle::freeze_directory(&root).unwrap();
        assert_eq!(bundle.files().len(), 2 * per_directory);

        fs::write(temp.path().join("d0/extra"), b"").unwrap();
        assert_eq!(
            invalid(FrozenBundle::freeze_directory(&root)),
            "tree entry limit exceeded"
        );
    }

    #[test]
    fn freeze_stops_at_the_file_that_exhausts_the_budget() {
        let temp = tempfile::tempdir().unwrap();
        for name in ["a", "b"] {
            let file = File::create(temp.path().join(name)).unwrap();
            file.set_len(17 * 1024 * 1024).unwrap();
        }
        // Sorted after the two files; reaching it would report a different error.
        symlink("a", temp.path().join("c")).unwrap();
        assert_eq!(
            invalid(FrozenBundle::freeze_directory(&directory(temp.path()))),
            "archive exceeds 32 MiB"
        );
    }

    #[test]
    fn freeze_budget_is_exact_at_the_archive_limit() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("big");
        let root = directory(temp.path());
        let sparse = |len: usize| {
            let file = fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&path)
                .unwrap();
            file.set_len(len as u64).unwrap();
        };
        // 1024 end-of-archive bytes, one 512-byte header, and block padding.
        let largest_block_multiple = MAX_BUNDLE_BYTES - 1024 - 512;

        sparse(largest_block_multiple);
        let bundle = FrozenBundle::freeze_directory(&root).unwrap();
        assert_eq!(bundle.bytes().len(), MAX_BUNDLE_BYTES);

        sparse(largest_block_multiple + 1);
        assert_eq!(
            invalid(FrozenBundle::freeze_directory(&root)),
            "archive exceeds 32 MiB"
        );
        sparse(MAX_BUNDLE_BYTES);
        assert_eq!(
            invalid(FrozenBundle::freeze_directory(&root)),
            "archive exceeds 32 MiB"
        );
        sparse(MAX_BUNDLE_BYTES + 1);
        assert_eq!(
            invalid(FrozenBundle::freeze_directory(&root)),
            "file exceeds 32 MiB"
        );
    }

    #[test]
    fn extract_creates_shared_parents_once_with_declared_modes() {
        let temp = tempfile::tempdir().unwrap();
        let files = BTreeMap::from([
            ("a/one".to_string(), file_of(b"1", false)),
            ("a/two".to_string(), file_of(b"2", true)),
            ("a/b/c/deep".to_string(), file_of(b"3", false)),
            ("top".to_string(), file_of(b"4", true)),
        ]);
        let bundle = FrozenBundle::from_files(files.clone()).unwrap();
        let extracted = bundle
            .extract_new_directory(&directory(temp.path()), "ws")
            .unwrap();
        for (path, expected) in &files {
            let on_disk = temp.path().join("ws").join(path);
            assert_eq!(fs::read(&on_disk).unwrap(), expected.data, "{path}");
            let mode = fs::metadata(&on_disk).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode,
                if expected.executable { 0o755 } else { 0o644 },
                "{path}"
            );
        }
        assert_eq!(
            FrozenBundle::freeze_directory(&extracted).unwrap().digest(),
            bundle.digest()
        );
    }

    #[test]
    fn extract_fails_instead_of_ignoring_a_parent_that_is_a_file() {
        // Bypasses validation to model a conflicting layout; extraction must
        // still refuse rather than write through the file.
        let temp = tempfile::tempdir().unwrap();
        let bundle = FrozenBundle {
            files: BTreeMap::from([
                ("a".to_string(), file_of(b"file", false)),
                ("a/b".to_string(), file_of(b"nested", false)),
            ]),
            bytes: Vec::new(),
            digest: String::new(),
        };
        assert!(
            bundle
                .extract_new_directory(&directory(temp.path()), "ws")
                .is_err()
        );
        assert_eq!(fs::read(temp.path().join("ws/a")).unwrap(), b"file");
    }
}
