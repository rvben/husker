//! On-disk layout of a macOS guest image bundle.
//!
//! A macOS guest cannot be described by a single disk file the way a Linux
//! rootfs can: Apple VZ also needs the hardware model the OS was installed for
//! and the auxiliary storage (boot loader NVRAM) written during installation.
//! A bundle is a directory holding all of them plus a JSON manifest:
//!
//! ```text
//! <bundle>/
//!   bundle.json           manifest (see [`MacOsBundleManifest`])
//!   disk.img              raw, sparse APFS boot disk
//!   aux.img               VZMacAuxiliaryStorage
//!   hardware-model.bin    VZMacHardwareModel.dataRepresentation
//!   machine-identifier.bin VZMacMachineIdentifier.dataRepresentation (installer's)
//! ```
//!
//! VMs never boot the bundle in place. Each VM gets its own copy-on-write clone
//! of `disk.img` and `aux.img` and a fresh machine identifier, because Apple VZ
//! requires concurrently running VMs to have distinct identifiers.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::VmmError;

/// Current bundle manifest format.
pub const MACOS_BUNDLE_FORMAT: u32 = 1;

pub const MANIFEST_FILE: &str = "bundle.json";
pub const DISK_FILE: &str = "disk.img";
pub const AUX_FILE: &str = "aux.img";
pub const HARDWARE_MODEL_FILE: &str = "hardware-model.bin";
pub const MACHINE_IDENTIFIER_FILE: &str = "machine-identifier.bin";

/// The manifest stored as `bundle.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsBundleManifest {
    pub format: u32,
    /// macOS build installed on the disk, e.g. `25A354`.
    pub build: String,
    /// macOS version installed on the disk, e.g. `26.0.1`.
    pub os_version: String,
    /// Virtual size of `disk.img`.
    pub disk_size_bytes: u64,
    /// Minimum vCPUs the installed hardware model supports.
    pub min_cpus: u32,
    /// Minimum memory the installed hardware model supports.
    pub min_memory_mib: u32,
    /// Whether `husker macos provision` installed the guest agent.
    #[serde(default)]
    pub agent_provisioned: bool,
}

/// A macOS bundle directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacOsBundle {
    dir: PathBuf,
}

/// A held lock on a bundle directory, from [`MacOsBundle::try_lock`].
///
/// Dropping it unlocks explicitly rather than only closing the descriptor:
/// a child process forked meanwhile holds a copy of the descriptor until it
/// execs, and an flock lives as long as any copy does, so a bare close could
/// leave the bundle locked after its holder is done with it.
#[derive(Debug)]
pub struct BundleLock {
    dir: std::fs::File,
}

impl BundleLock {
    /// The locked bundle directory, for operations that must not re-resolve
    /// its path.
    pub fn dir(&self) -> &std::fs::File {
        &self.dir
    }
}

impl Drop for BundleLock {
    fn drop(&mut self) {
        let _ = self.dir.unlock();
    }
}

impl MacOsBundle {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.dir.join(MANIFEST_FILE)
    }

    pub fn disk_path(&self) -> PathBuf {
        self.dir.join(DISK_FILE)
    }

    pub fn aux_path(&self) -> PathBuf {
        self.dir.join(AUX_FILE)
    }

    pub fn hardware_model_path(&self) -> PathBuf {
        self.dir.join(HARDWARE_MODEL_FILE)
    }

    pub fn machine_identifier_path(&self) -> PathBuf {
        self.dir.join(MACHINE_IDENTIFIER_FILE)
    }

    pub fn read_manifest(&self) -> Result<MacOsBundleManifest, VmmError> {
        let path = self.manifest_path();
        let bytes = std::fs::read(&path).map_err(|e| {
            VmmError::InvalidConfig(format!(
                "{} is not a macOS bundle: cannot read {}: {e}",
                self.dir.display(),
                path.display()
            ))
        })?;
        let manifest: MacOsBundleManifest = serde_json::from_slice(&bytes).map_err(|e| {
            VmmError::InvalidConfig(format!(
                "invalid macOS bundle manifest {}: {e}",
                path.display()
            ))
        })?;
        if manifest.format != MACOS_BUNDLE_FORMAT {
            return Err(VmmError::InvalidConfig(format!(
                "macOS bundle {} has format {}, this husker reads format {MACOS_BUNDLE_FORMAT}",
                self.dir.display(),
                manifest.format
            )));
        }
        Ok(manifest)
    }

    /// Write the manifest atomically, so a crash never leaves a truncated
    /// `bundle.json` that makes the bundle unreadable. See
    /// [`Self::write_manifest_in`].
    pub fn write_manifest(&self, manifest: &MacOsBundleManifest) -> Result<(), VmmError> {
        let dir = std::fs::File::open(&self.dir).map_err(|e| self.manifest_error(e))?;
        self.write_dir_manifest(&dir, manifest)
    }

    /// Write the manifest into the directory `lock` holds, never
    /// re-resolving the bundle's path: a privileged caller whose bundle path
    /// is swapped for a symlink mid-run still writes only into the directory
    /// it locked.
    ///
    /// The bytes go to an exclusively created temporary file, which is
    /// renamed over `bundle.json`. Neither step follows a symlink, so a link
    /// planted in the bundle cannot redirect the write. When running as root
    /// (`husker macos provision`), the file is handed to the directory's
    /// owner through its descriptor before the rename, so the unprivileged
    /// daemon can keep managing the bundle.
    pub fn write_manifest_in(
        &self,
        lock: &BundleLock,
        manifest: &MacOsBundleManifest,
    ) -> Result<(), VmmError> {
        self.write_dir_manifest(lock.dir(), manifest)
    }

    fn write_dir_manifest(
        &self,
        dir: &std::fs::File,
        manifest: &MacOsBundleManifest,
    ) -> Result<(), VmmError> {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::fs::MetadataExt;

        let err = |e: std::io::Error| self.manifest_error(e);
        let last = || err(std::io::Error::last_os_error());
        let bytes = serde_json::to_vec_pretty(manifest)
            .map_err(|e| VmmError::ProcessError(format!("serialize macOS manifest: {e}")))?;
        let tmp_name = CString::new(format!(".{MANIFEST_FILE}.tmp")).expect("no NUL byte");
        let final_name = CString::new(MANIFEST_FILE).expect("no NUL byte");
        let dirfd = dir.as_raw_fd();

        // A leftover from an interrupted write, or a planted link: unlinkat
        // never follows a symlink.
        // SAFETY: `dirfd` is open for the duration of the call and the name
        // is NUL-terminated.
        if unsafe { libc::unlinkat(dirfd, tmp_name.as_ptr(), 0) } != 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(err(e));
            }
        }
        // SAFETY: as above.
        let fd = unsafe {
            libc::openat(
                dirfd,
                tmp_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o644 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(last());
        }
        // SAFETY: `fd` was just returned by openat and is owned by nobody else.
        let mut file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
        let written = (|| {
            std::io::Write::write_all(&mut file, &bytes).map_err(err)?;
            // SAFETY: the descriptor is open for the duration of the call.
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o644) } != 0 {
                return Err(last());
            }
            // SAFETY: geteuid has no preconditions.
            if unsafe { libc::geteuid() } == 0 {
                let owner = dir.metadata().map_err(err)?;
                // SAFETY: the descriptor is open for the duration of the call.
                if unsafe { libc::fchown(file.as_raw_fd(), owner.uid(), owner.gid()) } != 0 {
                    return Err(last());
                }
            }
            file.sync_all().map_err(err)?;
            // SAFETY: `dirfd` is open and both names are NUL-terminated.
            if unsafe { libc::renameat(dirfd, tmp_name.as_ptr(), dirfd, final_name.as_ptr()) } != 0
            {
                return Err(last());
            }
            Ok(())
        })();
        if written.is_err() {
            // SAFETY: as above.
            unsafe { libc::unlinkat(dirfd, tmp_name.as_ptr(), 0) };
        }
        written
    }

    fn manifest_error(&self, e: std::io::Error) -> VmmError {
        VmmError::ProcessError(format!(
            "write macOS manifest in {}: {e}",
            self.dir.display()
        ))
    }

    /// Take a lock on the bundle directory without waiting: shared while a
    /// VM clones the bundle's disks, exclusive while `husker macos provision`
    /// rewrites them, so a VM never boots from a half-provisioned disk.
    /// Returns `None` when a conflicting lock is held.
    pub fn try_lock(&self, exclusive: bool) -> Result<Option<BundleLock>, VmmError> {
        let dir = std::fs::File::open(&self.dir)
            .map_err(|e| VmmError::ProcessError(format!("open {}: {e}", self.dir.display())))?;
        let locked = if exclusive {
            dir.try_lock()
        } else {
            dir.try_lock_shared()
        };
        match locked {
            Ok(()) => Ok(Some(BundleLock { dir })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(e)) => Err(VmmError::ProcessError(format!(
                "lock {}: {e}",
                self.dir.display()
            ))),
        }
    }

    /// Check that the manifest parses and every artifact a boot needs exists.
    pub fn validate(&self) -> Result<MacOsBundleManifest, VmmError> {
        let manifest = self.read_manifest()?;
        for path in [
            self.disk_path(),
            self.aux_path(),
            self.hardware_model_path(),
        ] {
            if !path.is_file() {
                return Err(VmmError::InvalidConfig(format!(
                    "macOS bundle {} is incomplete: {} is missing",
                    self.dir.display(),
                    path.display()
                )));
            }
        }
        Ok(manifest)
    }
}

/// vCPUs a macOS guest gets when the request does not say (raised to the
/// image's minimum when that is higher).
pub const DEFAULT_MACOS_VCPUS: u32 = 4;
/// Memory a macOS guest gets when the request does not say (raised to the
/// image's minimum when that is higher).
pub const DEFAULT_MACOS_MEMORY_MIB: u32 = 8192;

/// The vCPUs and memory to boot a bundle's VM with. See [`resolve_shape`].
pub fn vm_shape(
    manifest: &MacOsBundleManifest,
    vcpu_count: Option<u32>,
    mem_size_mib: Option<u32>,
) -> Result<(u32, u32), VmmError> {
    resolve_shape(
        &manifest.os_version,
        manifest.min_cpus,
        manifest.min_memory_mib,
        vcpu_count,
        mem_size_mib,
    )
}

/// The vCPUs and memory for a macOS VM: an unset value takes the default,
/// raised to the image's minimum, while an explicit value below the minimum
/// is an error rather than silently raised.
pub fn resolve_shape(
    os_version: &str,
    min_cpus: u32,
    min_memory_mib: u32,
    vcpu_count: Option<u32>,
    mem_size_mib: Option<u32>,
) -> Result<(u32, u32), VmmError> {
    let vcpu_count = vcpu_count.unwrap_or_else(|| DEFAULT_MACOS_VCPUS.max(min_cpus));
    let mem_size_mib = mem_size_mib.unwrap_or_else(|| DEFAULT_MACOS_MEMORY_MIB.max(min_memory_mib));
    if vcpu_count < min_cpus {
        return Err(VmmError::InvalidConfig(format!(
            "macOS {os_version} needs at least {min_cpus} vCPUs, requested {vcpu_count}"
        )));
    }
    if mem_size_mib < min_memory_mib {
        return Err(VmmError::InvalidConfig(format!(
            "macOS {os_version} needs at least {min_memory_mib} MiB of memory, requested {mem_size_mib}"
        )));
    }
    Ok((vcpu_count, mem_size_mib))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> MacOsBundleManifest {
        MacOsBundleManifest {
            format: MACOS_BUNDLE_FORMAT,
            build: "25A354".into(),
            os_version: "26.0.1".into(),
            disk_size_bytes: 64 << 30,
            min_cpus: 2,
            min_memory_mib: 4096,
            agent_provisioned: false,
        }
    }

    fn complete_bundle(dir: &Path) -> MacOsBundle {
        let bundle = MacOsBundle::new(dir);
        bundle.write_manifest(&manifest()).unwrap();
        for path in [
            bundle.disk_path(),
            bundle.aux_path(),
            bundle.hardware_model_path(),
        ] {
            std::fs::write(path, b"x").unwrap();
        }
        bundle
    }

    #[test]
    fn manifest_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = complete_bundle(dir.path());
        assert_eq!(bundle.read_manifest().unwrap(), manifest());
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().starts_with(".bundle.json"))
            .collect();
        assert!(
            entries.is_empty(),
            "the temp file is renamed into place: {entries:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_manifest_is_replaced_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        let bundle_dir = dir.path().join("bundle");
        std::fs::create_dir(&bundle_dir).unwrap();
        // Both the manifest and the temp name an older writer used are links
        // to a file outside the bundle.
        std::os::unix::fs::symlink(&victim, bundle_dir.join(MANIFEST_FILE)).unwrap();
        std::os::unix::fs::symlink(&victim, bundle_dir.join(".bundle.json.tmp")).unwrap();

        let bundle = MacOsBundle::new(&bundle_dir);
        bundle.write_manifest(&manifest()).unwrap();

        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        let written = std::fs::symlink_metadata(bundle.manifest_path()).unwrap();
        assert!(
            written.is_file(),
            "the link itself is replaced by a regular file"
        );
        assert_eq!(bundle.read_manifest().unwrap(), manifest());
    }

    #[test]
    fn bundle_locks_exclude_provisioning_while_a_vm_clones() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = MacOsBundle::new(dir.path());

        let clone_a = bundle.try_lock(false).unwrap().expect("first shared lock");
        let clone_b = bundle
            .try_lock(false)
            .unwrap()
            .expect("shared locks coexist");
        assert!(
            bundle.try_lock(true).unwrap().is_none(),
            "provision waits for clones"
        );
        drop(clone_a);
        drop(clone_b);

        let provision = bundle.try_lock(true).unwrap().expect("free bundle locks");
        assert!(
            bundle.try_lock(false).unwrap().is_none(),
            "clones wait for provision"
        );
        assert!(
            bundle.try_lock(true).unwrap().is_none(),
            "one provision at a time"
        );
        drop(provision);
        assert!(bundle.try_lock(false).unwrap().is_some());
    }

    #[test]
    fn the_manifest_lands_in_the_locked_directory_after_its_path_is_swapped() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("img");
        std::fs::create_dir(&path).unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let bundle = MacOsBundle::new(&path);
        let lock = bundle.try_lock(true).unwrap().unwrap();

        let moved = root.path().join("moved");
        std::fs::rename(&path, &moved).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
        bundle.write_manifest_in(&lock, &manifest()).unwrap();

        assert!(moved.join(MANIFEST_FILE).is_file());
        assert!(!elsewhere.join(MANIFEST_FILE).exists());
    }

    #[test]
    fn validate_accepts_a_complete_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = complete_bundle(dir.path());
        assert_eq!(bundle.validate().unwrap(), manifest());
    }

    #[test]
    fn validate_names_each_missing_artifact() {
        for missing in [DISK_FILE, AUX_FILE, HARDWARE_MODEL_FILE] {
            let dir = tempfile::tempdir().unwrap();
            let bundle = complete_bundle(dir.path());
            std::fs::remove_file(dir.path().join(missing)).unwrap();
            let err = bundle.validate().unwrap_err().to_string();
            assert!(err.contains(missing), "{missing}: {err}");
        }
    }

    #[test]
    fn a_directory_without_a_manifest_is_not_a_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let err = MacOsBundle::new(dir.path()).validate().unwrap_err();
        assert!(err.to_string().contains("is not a macOS bundle"), "{err}");
    }

    #[test]
    fn an_unknown_format_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = complete_bundle(dir.path());
        bundle
            .write_manifest(&MacOsBundleManifest {
                format: MACOS_BUNDLE_FORMAT + 1,
                ..manifest()
            })
            .unwrap();
        let err = bundle.read_manifest().unwrap_err().to_string();
        assert!(err.contains("format 2"), "{err}");
    }

    #[test]
    fn manifests_without_the_agent_flag_default_to_unprovisioned() {
        let json = r#"{"format":1,"build":"b","os_version":"v","disk_size_bytes":1,
                       "min_cpus":2,"min_memory_mib":4096}"#;
        let parsed: MacOsBundleManifest = serde_json::from_str(json).unwrap();
        assert!(!parsed.agent_provisioned);
    }

    #[test]
    fn vm_shape_must_meet_both_minimums() {
        let m = manifest();
        assert_eq!(vm_shape(&m, Some(2), Some(4096)).unwrap(), (2, 4096));
        assert_eq!(vm_shape(&m, Some(8), Some(16384)).unwrap(), (8, 16384));
        let cpu = vm_shape(&m, Some(1), Some(8192)).unwrap_err().to_string();
        assert!(cpu.contains("at least 2 vCPUs"), "{cpu}");
        let mem = vm_shape(&m, Some(4), Some(4095)).unwrap_err().to_string();
        assert!(mem.contains("at least 4096 MiB"), "{mem}");
    }

    #[test]
    fn unset_shape_takes_the_defaults_raised_to_the_minimums() {
        assert_eq!(
            resolve_shape("27.0", 2, 4096, None, None).unwrap(),
            (DEFAULT_MACOS_VCPUS, DEFAULT_MACOS_MEMORY_MIB)
        );
        assert_eq!(
            resolve_shape("27.0", 6, 12288, None, None).unwrap(),
            (6, 12288)
        );
    }
}
