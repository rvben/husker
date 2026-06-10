//! VMM abstraction and backend-neutral types for Firecracker, Apple VZ, and QEMU/KVM.

pub mod firecracker;
pub mod vsock;

#[cfg(unix)]
pub mod fd_stream;

#[cfg(unix)]
pub mod qmp;

#[cfg(unix)]
pub mod qemu;

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

/// How the guest boots. `DirectKernel` is husker's microVM default (host-supplied
/// kernel + initrd + appended cmdline). `Uefi` boots the disk's own bootloader via
/// OVMF firmware and carries the firmware paths it needs.
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
}

impl BootMode {
    /// Stable lowercase tag for persistence/display (`"direct"` / `"uefi"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            BootMode::DirectKernel => "direct",
            BootMode::Uefi { .. } => "uefi",
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
}

#[cfg(test)]
mod tests {
    use super::{VmmKind, tail_lines};
    use std::io::Write;

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
}
