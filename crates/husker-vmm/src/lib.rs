//! VMM abstraction and backend-neutral types for Firecracker, Apple VZ, and QEMU/KVM.

pub mod firecracker;
pub mod vsock;

#[cfg(unix)]
pub mod fd_stream;

#[cfg(unix)]
pub mod qmp;

#[cfg(unix)]
pub mod qemu;

pub mod cgroup;

#[cfg(target_os = "linux")]
pub mod dispatch;
#[cfg(target_os = "linux")]
pub use dispatch::{LinuxDispatchBackend, LinuxVsockStream};

#[cfg(target_os = "macos")]
pub mod apple_vz;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

/// Kernel parameters that suppress probes for legacy hardware no direct-kernel
/// guest can have.
///
/// The i8042 PS/2 controller probe sits on a timeout waiting for a keyboard that
/// a microVM never exposes. Measured on an Intel N100 (husker01, 2026-07-20):
/// time to `Run /bin/sh as init process` drops from a median 1.019s to 0.525s
/// with these four parameters, i.e. ~0.49s and 46% of guest kernel boot, with no
/// other change. The guest kernel still compiles the driver in, so this is the
/// cmdline half of the fix; removing `CONFIG_SERIO_I8042` would make it moot.
///
/// Applies to direct-kernel boots only. Cloud images boot their own bootloader
/// and do not take a husker-built cmdline.
pub const LEGACY_PROBE_SUPPRESSION: &str = "i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd";

/// A host directory shared into the guest over virtiofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostShare {
    pub host: PathBuf,
    pub guest: String,
    pub read_only: bool,
    /// Stable virtiofs device tag (e.g. "fs0"); the guest mounts by tag.
    pub tag: String,
}

/// Configuration for creating a new VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    pub name: String,
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub kernel_args: Option<String>,
    pub initrd_path: Option<PathBuf>,
    pub vsock_cid: u32,
    pub tap_device: Option<String>,
    pub guest_mac: Option<String>,
    /// Which backend should run this VM. `None` lets the dispatcher use its
    /// default; single-backend backends ignore it.
    #[serde(default)]
    pub vmm: Option<VmmKind>,
    /// How this VM boots. Defaults to direct-kernel for back-compat.
    #[serde(default)]
    pub boot: BootMode,
    /// NoCloud cloud-init seed image (raw vfat). Attached as a virtio disk for
    /// UEFI cloud-image boot; `None` for direct-kernel VMs.
    #[serde(default)]
    pub seed_path: Option<PathBuf>,
    /// Attach a virtio memory balloon device at boot. When `true` the backend
    /// installs the device so the balloon size can be changed at runtime via
    /// `set_balloon`. Defaults to `false` for back-compat.
    #[serde(default)]
    pub balloon: bool,
    /// Optional second virtio disk (the persistent volume). The guest sees it
    /// as `/dev/vdb` in both direct-kernel and UEFI/cloud-image boot modes.
    /// `None` omits the drive; core sets this when a volume is attached.
    #[serde(default)]
    pub volume_path: Option<PathBuf>,
    /// Host directories to share into the guest over virtiofs. Empty by default;
    /// each entry becomes a virtiofs device with the entry's `tag`.
    #[serde(default)]
    pub host_shares: Vec<HostShare>,
}

/// Runtime information about a VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmInfo {
    pub id: Uuid,
    pub name: String,
    pub state: VmState,
    pub pid: Option<u32>,
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    pub vsock_cid: u32,
}

/// Which VMM backend runs a VM. The canonical backend identity used by the
/// per-VM dispatcher; the wire/persistence layer carries its lowercase string form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VmmKind {
    Firecracker,
    Qemu,
}

impl std::fmt::Display for VmmKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            VmmKind::Firecracker => "firecracker",
            VmmKind::Qemu => "qemu",
        })
    }
}

impl std::str::FromStr for VmmKind {
    type Err = VmmError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "firecracker" | "fc" => Ok(VmmKind::Firecracker),
            "qemu" | "kvm" => Ok(VmmKind::Qemu),
            other => Err(VmmError::InvalidConfig(format!("unknown vmm '{other}'"))),
        }
    }
}

/// Optional features a VMM backend may support.
///
/// husker's Linux backend multiplexes Firecracker and QEMU per VM, so support
/// for a feature is a property of the VM's backend *kind*, not of the single
/// active [`VmmBackend`] object. Callers therefore resolve capabilities from the
/// persisted backend string via [`Capabilities::for_backend`] and check them
/// before starting an operation that a backend cannot finish (e.g. pausing a VM
/// for suspend), failing fast instead of hitting [`VmmError::Unsupported`]
/// mid-flight.
///
/// The default is conservative: an unknown backend advertises nothing optional.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Capabilities {
    /// `snapshot_vm` / `restore_vm` are implemented (full-state suspend/resume
    /// to disk). Firecracker only; QEMU and Apple VZ return `Unsupported`.
    pub snapshot: bool,
    /// Forking a suspended VM from its snapshot (`RestoreTarget::Fork`) is
    /// supported. Firecracker only; requires `snapshot`.
    pub fork: bool,
}

impl Capabilities {
    /// Static capabilities for a backend identified by its persisted kind string
    /// (`"firecracker"`, `"qemu"`, `"apple_vz"`). Unrecognised kinds get the
    /// conservative default so callers fail closed.
    pub fn for_backend(kind: &str) -> Capabilities {
        match kind {
            "firecracker" => Capabilities {
                snapshot: true,
                fork: true,
            },
            _ => Capabilities::default(),
        }
    }
}

/// How the guest boots. `DirectKernel` is husker's microVM default (host-supplied
/// kernel + initrd + appended cmdline). `Uefi` boots the disk's own bootloader via
/// OVMF firmware and carries the firmware paths it needs. `Efi` is for Apple VZ
/// where the Virtualization framework supplies the firmware and only a per-VM NVRAM
/// file is needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum BootMode {
    #[default]
    #[serde(rename = "direct")]
    DirectKernel,
    Uefi {
        /// Read-only OVMF code image (e.g. `/usr/share/OVMF/OVMF_CODE_4M.fd`).
        ovmf_code: PathBuf,
        /// OVMF variable-store template; the backend copies it per VM (writable).
        ovmf_vars_template: PathBuf,
    },
    /// EFI boot with a per-VM variable store (Apple VZ; firmware comes from
    /// the Virtualization framework, only the NVRAM file is ours).
    Efi { variable_store: PathBuf },
}

impl BootMode {
    /// Stable lowercase tag for persistence/display (`"direct"` / `"uefi"` / `"efi"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            BootMode::DirectKernel => "direct",
            BootMode::Uefi { .. } => "uefi",
            BootMode::Efi { .. } => "efi",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VmState {
    Creating,
    Running,
    Paused,
    Stopped,
    Failed,
}

impl std::fmt::Display for VmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmState::Creating => write!(f, "creating"),
            VmState::Running => write!(f, "running"),
            VmState::Paused => write!(f, "paused"),
            VmState::Stopped => write!(f, "stopped"),
            VmState::Failed => write!(f, "failed"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VmmError {
    #[error("VM not found: {0}")]
    VmNotFound(Uuid),
    #[error("VM already exists: {0}")]
    VmAlreadyExists(String),
    #[error("VMM process error: {0}")]
    ProcessError(String),
    #[error("API error: {0}")]
    ApiError(String),
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported operation: {0}")]
    Unsupported(String),
}

/// Return the last `max_lines` lines of a file (trailing whitespace trimmed),
/// or `None` if the file is missing, unreadable, or empty. Used to fold boot
/// diagnostics into create-failure error messages.
pub(crate) fn tail_lines(path: &std::path::Path, max_lines: usize) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let trimmed = content.trim_end();
    if trimmed.is_empty() {
        return None;
    }
    let lines: Vec<&str> = trimmed.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    Some(lines[start..].join("\n"))
}

/// Append guest-serial and backend boot-log tails (if present) to an error message.
pub(crate) fn append_log_tails(
    msg: &mut String,
    serial_tail: Option<String>,
    boot_tail: Option<String>,
    boot_label: &str,
) {
    if let Some(s) = serial_tail {
        msg.push_str(&format!("\n--- guest serial (tail) ---\n{s}"));
    }
    if let Some(b) = boot_tail {
        msg.push_str(&format!("\n--- {boot_label} (tail) ---\n{b}"));
    }
}

/// Runtime-only filesystem layout of a full-state snapshot's artifacts.
///
/// Derived on demand from a directory; not serialized (the manifest is written
/// separately as JSON by the core orchestration layer).
#[derive(Debug, Clone)]
pub struct SnapshotPaths {
    /// Directory holding the artifacts.
    pub dir: PathBuf,
    /// Guest RAM image.
    pub memory: PathBuf,
    /// vCPU + device state.
    pub vmstate: PathBuf,
    /// Backend/version metadata for restore compatibility checks.
    pub manifest: PathBuf,
}

impl SnapshotPaths {
    /// Derive the standard artifact paths inside `dir`.
    pub fn in_dir(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        Self {
            memory: dir.join("memory"),
            vmstate: dir.join("vmstate"),
            manifest: dir.join("manifest.json"),
            dir,
        }
    }
}

/// Backend-specific metadata captured at snapshot time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMeta {
    /// Backend that produced the snapshot, e.g. `"firecracker"`.
    pub backend: String,
    /// VMM version string, for restore compatibility checks.
    pub vmm_version: String,
}

/// Identity under which `restore_vm` brings a VM back up.
///
/// `Resume` restores the original VM in place (same id/name/CID). `Fork` brings
/// up a *new* VM from a source's snapshot, giving it a fresh host identity.
#[derive(Debug, Clone)]
pub enum RestoreTarget {
    /// Restore the original VM under its existing identity.
    Resume {
        id: Uuid,
        name: String,
        vcpu_count: u32,
        mem_size_mib: u32,
        vsock_cid: u32,
    },
    /// Bring up a fork: a new VM restored from a source's snapshot.
    ///
    /// A Firecracker snapshot embeds the source's absolute disk path, and
    /// `/snapshot/load` only overrides the network. So the fork is bound to its
    /// own host TAP via a network override, while the embedded source rootfs path
    /// is temporarily aliased to the fork's reflink clone for the duration of the
    /// load (then undone) so the fork runs on its own writable disk. The source's
    /// memory file is mapped copy-on-write, so restoring from it does not disturb
    /// the (still-suspended) source.
    Fork {
        /// New VM id for the fork.
        id: Uuid,
        /// New VM name.
        name: String,
        vcpu_count: u32,
        mem_size_mib: u32,
        /// Guest CID, inherited from the snapshot (kept stable for FC restore).
        vsock_cid: u32,
        /// Fresh host TAP the fork's NIC is rebound to (snapshot network override).
        tap_device: String,
        /// The source rootfs path embedded in the snapshot (aliased during load).
        source_rootfs: PathBuf,
        /// The fork's reflink clone that the alias points at.
        fork_rootfs: PathBuf,
    },
}

/// Trait abstracting over different VMM implementations.
///
/// Each backend (Firecracker, Apple VZ) implements this trait.
/// Uses desugared async methods with `Send` bounds for compatibility with
/// multi-threaded runtimes. Implementations can use `async fn` syntax.
pub trait VmmBackend: Send + Sync {
    /// The stream type returned by vsock connections.
    type VsockStream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Create and boot a new VM with the given configuration.
    fn create_vm(
        &self,
        config: VmConfig,
    ) -> impl std::future::Future<Output = Result<VmInfo, VmmError>> + Send;

    /// Stop a running VM gracefully.
    fn stop_vm(&self, id: Uuid) -> impl std::future::Future<Output = Result<(), VmmError>> + Send;

    /// Force-kill a VM.
    fn destroy_vm(
        &self,
        id: Uuid,
    ) -> impl std::future::Future<Output = Result<(), VmmError>> + Send;

    /// Get information about a VM.
    fn vm_info(
        &self,
        id: Uuid,
    ) -> impl std::future::Future<Output = Result<VmInfo, VmmError>> + Send;

    /// Pause a running VM (if supported).
    fn pause_vm(&self, id: Uuid) -> impl std::future::Future<Output = Result<(), VmmError>> + Send;

    /// Resume a paused VM (if supported).
    fn resume_vm(&self, id: Uuid)
    -> impl std::future::Future<Output = Result<(), VmmError>> + Send;

    /// Capture full guest state (RAM + vCPU + devices) to `dst`.
    ///
    /// The caller MUST pause the VM first (`pause_vm`); backends do not pause
    /// implicitly. Returns backend metadata for the manifest.
    ///
    /// Defaults to `Unsupported`; only Firecracker implements snapshotting today.
    fn snapshot_vm(
        &self,
        _id: Uuid,
        _dst: &SnapshotPaths,
    ) -> impl std::future::Future<Output = Result<SnapshotMeta, VmmError>> + Send {
        async {
            Err(VmmError::Unsupported(
                "snapshot_vm not supported by this backend".into(),
            ))
        }
    }

    /// Restore a VM from a full-state snapshot.
    ///
    /// Defaults to `Unsupported`; only Firecracker implements restore today.
    fn restore_vm(
        &self,
        _src: &SnapshotPaths,
        _target: RestoreTarget,
    ) -> impl std::future::Future<Output = Result<VmInfo, VmmError>> + Send {
        async {
            Err(VmmError::Unsupported(
                "restore_vm not supported by this backend".into(),
            ))
        }
    }

    /// Connect to a VM's vsock at the given port.
    ///
    /// Returns an async stream that can be used for bidirectional communication
    /// with the guest. The connection method is backend-specific:
    /// - Firecracker: UDS proxy with CONNECT handshake
    /// - Apple VZ: VZVirtioSocketDevice connectToPort
    fn vsock_connect(
        &self,
        id: Uuid,
        port: u32,
    ) -> impl std::future::Future<Output = Result<Self::VsockStream, VmmError>> + Send;

    /// Resize the VM's memory balloon to `amount_mib` (the balloon target:
    /// memory reclaimed from the guest). Errors if the VM was created
    /// without `balloon` or the backend does not support ballooning.
    fn set_balloon(
        &self,
        id: Uuid,
        amount_mib: u32,
    ) -> impl std::future::Future<Output = Result<(), VmmError>> + Send;

    /// The capability-defining backend kind for this daemon: `"firecracker"`,
    /// `"qemu"`, or `"apple_vz"`. Used to resolve [`Capabilities::for_backend`]
    /// when advertising what the running daemon can do. The Linux dispatch
    /// backend always has Firecracker available and reports `"firecracker"`.
    ///
    /// Defaults to `"unknown"` (conservative: advertises no optional
    /// capabilities) for backends that do not declare a kind.
    fn backend_kind(&self) -> &'static str {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::{Capabilities, VmmKind, tail_lines};
    use std::io::Write;

    #[test]
    fn capabilities_for_backend_maps_each_kind() {
        // Firecracker is the only husker backend that implements full-state
        // snapshot/restore and fork today.
        let fc = Capabilities::for_backend("firecracker");
        assert!(fc.snapshot);
        assert!(fc.fork);
        // QEMU and Apple VZ return Unsupported from snapshot_vm/restore_vm.
        assert!(!Capabilities::for_backend("qemu").snapshot);
        assert!(!Capabilities::for_backend("qemu").fork);
        assert!(!Capabilities::for_backend("apple_vz").snapshot);
        assert!(!Capabilities::for_backend("apple_vz").fork);
    }

    #[test]
    fn capabilities_for_unknown_backend_is_conservative() {
        // An unrecognised kind advertises nothing optional, so callers fail
        // closed rather than attempting an operation the backend can't finish.
        assert_eq!(Capabilities::for_backend("xen"), Capabilities::default());
        assert!(!Capabilities::default().snapshot);
    }

    #[test]
    fn vmm_kind_parse_and_display() {
        use std::str::FromStr;
        assert_eq!(VmmKind::from_str("qemu").unwrap(), VmmKind::Qemu);
        assert_eq!(
            VmmKind::from_str("FireCracker").unwrap(),
            VmmKind::Firecracker
        );
        assert!(VmmKind::from_str("xen").is_err());
        assert_eq!(VmmKind::Qemu.to_string(), "qemu");
    }

    #[test]
    fn tail_lines_missing_file_is_none() {
        assert!(tail_lines(std::path::Path::new("/no/such/file"), 10).is_none());
    }

    #[test]
    fn tail_lines_empty_file_is_none() {
        let f = tempfile::NamedTempFile::new().unwrap();
        assert!(tail_lines(f.path(), 10).is_none());
    }

    #[test]
    fn tail_lines_returns_last_n() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "a\nb\nc\nd\ne").unwrap(); // no trailing newline
        assert_eq!(tail_lines(f.path(), 2).unwrap(), "d\ne");
    }

    #[test]
    fn tail_lines_fewer_than_n_returns_all() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "only line").unwrap();
        assert_eq!(tail_lines(f.path(), 20).unwrap(), "only line");
    }

    #[test]
    fn boot_mode_default_is_direct_kernel() {
        use super::BootMode;
        assert_eq!(BootMode::default(), BootMode::DirectKernel);
        assert_eq!(BootMode::DirectKernel.as_str(), "direct");
        let uefi = BootMode::Uefi {
            ovmf_code: "/usr/share/OVMF/OVMF_CODE_4M.fd".into(),
            ovmf_vars_template: "/usr/share/OVMF/OVMF_VARS_4M.fd".into(),
        };
        assert_eq!(uefi.as_str(), "uefi");
    }

    #[test]
    fn vm_config_boot_defaults_when_absent_in_json() {
        use super::{BootMode, VmConfig};
        // A JSON document without `boot` deserializes to DirectKernel (back-compat).
        let json = r#"{
            "name": "v", "vcpu_count": 1, "mem_size_mib": 128,
            "kernel_path": "/k", "rootfs_path": "/r",
            "kernel_args": null, "initrd_path": null,
            "vsock_cid": 3, "tap_device": null, "guest_mac": null
        }"#;
        let cfg: VmConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.boot, BootMode::DirectKernel);
        assert!(!cfg.balloon, "balloon defaults to false");
        assert!(cfg.volume_path.is_none(), "volume_path defaults to None");
    }

    #[test]
    fn boot_mode_serde_tag_matches_as_str() {
        use super::BootMode;
        let direct = serde_json::to_value(BootMode::DirectKernel).unwrap();
        assert_eq!(direct["mode"], "direct");
        let uefi = serde_json::to_value(BootMode::Uefi {
            ovmf_code: "/c".into(),
            ovmf_vars_template: "/v".into(),
        })
        .unwrap();
        assert_eq!(uefi["mode"], "uefi");
    }

    #[test]
    fn boot_mode_efi_serde_round_trip() {
        use super::BootMode;
        let mode = BootMode::Efi {
            variable_store: std::path::PathBuf::from("/tmp/nvram.bin"),
        };
        let json = serde_json::to_string(&mode).unwrap();
        assert!(json.contains("\"efi\""), "tagged as efi: {json}");
        let back: BootMode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, mode);
    }

    #[test]
    fn boot_mode_efi_as_str_is_efi() {
        use super::BootMode;
        let efi = BootMode::Efi {
            variable_store: "/tmp/nvram.bin".into(),
        };
        assert_eq!(efi.as_str(), "efi");
    }

    #[test]
    fn vmconfig_default_has_no_host_shares() {
        use super::{BootMode, VmConfig};
        let c = VmConfig {
            name: "test".into(),
            vcpu_count: 1,
            mem_size_mib: 128,
            kernel_path: "/k".into(),
            rootfs_path: "/r".into(),
            kernel_args: None,
            initrd_path: None,
            vsock_cid: 3,
            tap_device: None,
            guest_mac: None,
            vmm: None,
            boot: BootMode::DirectKernel,
            seed_path: None,
            balloon: false,
            volume_path: None,
            host_shares: Vec::new(),
        };
        assert!(c.host_shares.is_empty());
    }

    #[test]
    fn host_share_holds_tag_and_ro() {
        use super::HostShare;
        let s = HostShare {
            host: "/srv/work".into(),
            guest: "/work".into(),
            read_only: true,
            tag: "fs0".into(),
        };
        assert_eq!(s.tag, "fs0");
        assert!(s.read_only);
    }

    #[test]
    fn snapshot_paths_derives_standard_names() {
        use super::SnapshotPaths;
        let p = SnapshotPaths::in_dir("/data/suspend/abc");
        assert_eq!(p.dir, std::path::PathBuf::from("/data/suspend/abc"));
        assert_eq!(
            p.memory,
            std::path::PathBuf::from("/data/suspend/abc/memory")
        );
        assert_eq!(
            p.vmstate,
            std::path::PathBuf::from("/data/suspend/abc/vmstate")
        );
        assert_eq!(
            p.manifest,
            std::path::PathBuf::from("/data/suspend/abc/manifest.json")
        );
    }
}
