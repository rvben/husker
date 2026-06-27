//! Core orchestration layer for VM lifecycle, agent connectivity, and recovery logic.

pub mod agent_client;

/// Userspace TCP port-forward proxy, used on backends without host nftables (macOS/VZ).
#[cfg(not(feature = "linux-net"))]
mod port_proxy;

#[cfg(feature = "linux-net")]
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use husker_vmm::{RestoreTarget, SnapshotPaths, VmmBackend};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use uuid::Uuid;

pub use husker_state::{
    HostGroupRecord, ImageRecord, PoolRecord, SecretRecord, ServiceRecord, SnapshotRecord,
    VmRecord, VolumeRecord,
};
pub use husker_vmm::{VmInfo, VmState};

pub use agent_client::{AgentClient, AgentConnection, AgentError, ExecResult, ShellEvent};

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("VM not found: {0}")]
    VmNotFound(String),
    #[error("VM '{name}' is {actual}, expected {expected}")]
    InvalidState {
        name: String,
        actual: String,
        expected: String,
    },
    #[error("VM already exists: {0}")]
    VmAlreadyExists(String),
    #[error("host group not found: {0}")]
    HostGroupNotFound(String),
    #[error("host group already exists: {0}")]
    HostGroupAlreadyExists(String),
    #[error("service not found: {0}")]
    ServiceNotFound(String),
    #[error("service already exists: {0}")]
    ServiceAlreadyExists(String),
    #[error("pool not found: {0}")]
    PoolNotFound(String),
    #[error("pool already exists: {0}")]
    PoolAlreadyExists(String),
    #[error("snapshot not found: {0}")]
    SnapshotNotFound(String),
    #[error("snapshot already exists: {0}")]
    SnapshotAlreadyExists(String),
    #[error("image not found: {0}")]
    ImageNotFound(String),
    #[error("image already exists: {0}")]
    ImageAlreadyExists(String),
    #[error("volume not found: {0}")]
    VolumeNotFound(String),
    #[error("volume already exists: {0}")]
    VolumeAlreadyExists(String),
    #[error("volume '{volume}' is attached to VM '{vm}'")]
    VolumeAttached { volume: String, vm: String },
    #[error("secret not found: {0}")]
    SecretNotFound(String),
    #[error("secret already exists: {0}")]
    SecretAlreadyExists(String),
    #[error("secret crypto error: {0}")]
    SecretCrypto(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("host port {0} is already in use")]
    PortForwardConflict(u16),
    #[error(
        "permission denied binding host port {0}; privileged ports (<1024) require elevated permissions"
    )]
    PortForwardDenied(u16),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("service operation failed: {0}")]
    ServiceOperationFailed(String),
    #[error("VMM error: {0}")]
    Vmm(#[from] husker_vmm::VmmError),
    #[cfg(feature = "linux-net")]
    #[error("network error: {0}")]
    Network(#[from] husker_net::NetError),
    #[error("cloud-init seed error: {0}")]
    CloudInit(#[from] husker_cloudinit::CloudInitError),
    #[error("storage error: {0}")]
    Storage(#[from] husker_storage::StorageError),
    #[error("state error: {0}")]
    State(#[from] husker_state::StateError),
    #[error("agent error: {0}")]
    Agent(#[from] AgentError),
}

/// Parameters for creating a new VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CreateVmRequest {
    pub name: String,
    /// Kernel for direct-kernel boot. Required unless `cloud_image` is set.
    #[serde(default)]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    pub kernel_path: Option<PathBuf>,
    /// Root filesystem for direct-kernel boot. Required unless `cloud_image` is set.
    #[serde(default)]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    pub rootfs_path: Option<PathBuf>,
    pub vcpu_count: Option<u32>,
    pub mem_size_mib: Option<u32>,
    /// Path to an initramfs/initrd image (needed for kernels with modular drivers).
    #[serde(default)]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    pub initrd_path: Option<PathBuf>,
    /// Userdata script to execute after VM boots.
    #[serde(default)]
    pub userdata: Option<String>,
    /// Environment variables to pass to the userdata script.
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// Backend to run this VM on: "firecracker" (default) or "qemu". Omit to
    /// use the daemon's configured default.
    #[serde(default)]
    pub vmm: Option<String>,
    /// Boot a stock cloud image (qcow2) as a full UEFI VM. Holds the base image
    /// path on the host. Implies the QEMU backend; `kernel_path`/`rootfs_path` are ignored.
    #[serde(default)]
    pub cloud_image: Option<String>,
    /// Grow the cloud-image disk to this many bytes before boot (cloud-image only).
    #[serde(default)]
    pub disk_size: Option<u64>,
    /// SSH public keys to authorize for the cloud image's default user via
    /// cloud-init (cloud-image only; ignored for direct-kernel boot).
    #[serde(default)]
    pub ssh_authorized_keys: Vec<String>,
    /// Opt the VM into a virtio memory balloon device. When true, the balloon
    /// device is installed at boot and `set_balloon` can resize it at runtime.
    #[serde(default)]
    pub balloon: bool,
    /// Named persistent volume to attach as the second disk (/dev/vdb in the guest).
    /// Exactly one VM may hold a given volume at a time.
    #[serde(default)]
    pub volume: Option<String>,
    /// Network mode: "nat" (default) or "bridged". Bridged requires a cloud image
    /// and a configured `lan_bridge`; the VM's TAP is attached directly to the
    /// host LAN bridge and DHCP assigns its address.
    #[serde(default)]
    pub network: Option<String>,
    /// Host directories to share into the guest over virtiofs.
    /// Each entry is a `host:guest[:ro]` spec (e.g. `/srv/work:/build:ro`).
    /// Supported on Linux with the direct-kernel boot path only.
    #[serde(default)]
    pub mounts: Vec<String>,
}

/// Parameters for creating a host group.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CreateHostGroupRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// Parameters for creating a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CreateServiceRequest {
    pub name: String,
    #[serde(default)]
    pub host_group: Option<String>,
    #[serde(default)]
    pub desired_instances: Option<u32>,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    pub rootfs_path: Option<PathBuf>,
    #[serde(default)]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    pub kernel_path: Option<PathBuf>,
    #[serde(default)]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    pub initrd_path: Option<PathBuf>,
    #[serde(default)]
    pub vcpu_count: Option<u32>,
    #[serde(default)]
    pub mem_size_mib: Option<u32>,
    #[serde(default)]
    pub userdata: Option<String>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// Boot a stock cloud image. When set, `kernel_path` and `rootfs_path` are optional.
    #[serde(default)]
    pub cloud_image: Option<String>,
    /// Grow the cloud-image disk to this many bytes (cloud-image only).
    #[serde(default)]
    pub disk_size: Option<u64>,
    /// Opt each instance into a virtio memory balloon device.
    #[serde(default)]
    pub balloon: bool,
    /// Named persistent volume to attach to each instance as the second disk.
    #[serde(default)]
    pub volume: Option<String>,
}

/// Parameters for creating a hot pool: a pre-warmed, suspended template VM that
/// `run`/`job` fork fresh VMs from. Direct-kernel / Firecracker only.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CreatePoolRequest {
    pub name: String,
    #[serde(default)]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    pub rootfs_path: Option<PathBuf>,
    #[serde(default)]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    pub kernel_path: Option<PathBuf>,
    #[serde(default)]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    pub initrd_path: Option<PathBuf>,
    #[serde(default)]
    pub vcpu_count: Option<u32>,
    #[serde(default)]
    pub mem_size_mib: Option<u32>,
}

/// Parameters for creating a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CreateSnapshotRequest {
    pub name: String,
    pub vm: String,
}

/// Parameters for restoring a snapshot into a new VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct RestoreSnapshotRequest {
    pub name: String,
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub kernel_path: PathBuf,
    pub vcpu_count: Option<u32>,
    pub mem_size_mib: Option<u32>,
    #[serde(default)]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    pub initrd_path: Option<PathBuf>,
    #[serde(default)]
    pub userdata: Option<String>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
}

/// Parameters for importing an image into husker's image catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ImportImageRequest {
    pub name: String,
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub source_path: PathBuf,
    #[serde(default)]
    pub format: Option<String>,
    /// Image kind: "rootfs" (default) or "cloud-image" (qcow2 for UEFI boot).
    #[serde(default)]
    pub kind: Option<String>,
}

/// Parameters for exporting a catalog image.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ExportImageRequest {
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub destination_path: PathBuf,
}

/// Result payload returned after exporting an image.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ExportImageResult {
    pub name: String,
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub destination_path: PathBuf,
    pub size_bytes: u64,
}

/// Parameters for creating a persistent volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CreateVolumeRequest {
    pub name: String,
    /// Disk size in bytes. The image is created as a sparse ext4 file of this size.
    pub size_bytes: u64,
}

/// Parameters for creating a secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CreateSecretRequest {
    pub name: String,
    pub value: String,
}

/// Parameters for rotating an existing secret's value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct RotateSecretRequest {
    pub value: String,
}

/// Public metadata for a secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct SecretMetadata {
    pub id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Decrypted secret payload returned by reveal operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct RevealedSecret {
    pub name: String,
    pub value: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Maximum length of a user-supplied resource name (VM, snapshot, image, …).
const MAX_RESOURCE_NAME_LEN: usize = 64;

/// Validate a user-supplied resource name before it is used in any host
/// filesystem path or persisted identifier.
///
/// Names must be 1-64 ASCII characters from `[A-Za-z0-9._-]`, may not start
/// with `.`, and may not contain path separators, NULs, or whitespace. This
/// prevents path traversal (`../escape`) and accidental collision with hidden
/// files or path metacharacters when names are joined with `data_dir`.
fn validate_resource_name(kind: &str, name: &str) -> Result<(), CoreError> {
    if name.is_empty() {
        return Err(CoreError::InvalidArgument(format!(
            "{kind} name cannot be empty"
        )));
    }
    if name.len() > MAX_RESOURCE_NAME_LEN {
        return Err(CoreError::InvalidArgument(format!(
            "{kind} name exceeds maximum length of {MAX_RESOURCE_NAME_LEN}"
        )));
    }
    if name.starts_with('.') {
        return Err(CoreError::InvalidArgument(format!(
            "{kind} name '{name}' cannot start with '.'"
        )));
    }
    for ch in name.chars() {
        let allowed = ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.');
        if !allowed {
            return Err(CoreError::InvalidArgument(format!(
                "{kind} name '{name}' contains invalid character; allowed: [A-Za-z0-9._-]"
            )));
        }
    }
    Ok(())
}

/// Map an OCI/Docker reference to a deterministic catalog image name, so repeat
/// `run`/`job` of the same reference reuse the cached import. Characters not
/// allowed in a resource name become `-` (e.g. `python:3.12-alpine` ->
/// `python-3.12-alpine`, `ghcr.io/o/r:v1` -> `ghcr.io-o-r-v1`).
fn oci_ref_to_catalog_name(reference: &str) -> String {
    reference
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Whether a `run`/`job` rootfs argument is path-shaped (so a typo'd path is
/// reported as a missing file, not mistaken for an image reference).
fn looks_like_path(arg: &str) -> bool {
    arg.starts_with('/') || arg.starts_with("./") || arg.starts_with("../")
}

/// Build the canonical instance name for a service ordinal.
fn instance_name(service: &str, ordinal: u32) -> String {
    format!("{service}-{ordinal}")
}

/// Validate the worst-case generated instance name `<service>-<desired-1>` fits the
/// resource-name limit. No-op when `desired_instances == 0` (no instances created).
fn validate_service_instance_names(name: &str, desired_instances: u32) -> Result<(), CoreError> {
    if desired_instances > 0 {
        validate_resource_name(
            "service instance",
            &instance_name(name, desired_instances - 1),
        )?;
    }
    Ok(())
}

/// True if `candidate` is a better survivor than `current` for the same ordinal:
/// prefer `running`, then oldest `created_at`, then lowest `id`.
fn better_survivor(candidate: &VmRecord, current: &VmRecord) -> bool {
    let rank = |s: &str| if s == "running" { 0 } else { 1 };
    match rank(&candidate.state).cmp(&rank(&current.state)) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => match candidate.created_at.cmp(&current.created_at) {
            std::cmp::Ordering::Less => true,
            std::cmp::Ordering::Greater => false,
            std::cmp::Ordering::Equal => candidate.id < current.id,
        },
    }
}

/// Validate a user-supplied host filesystem path before the daemon opens it.
///
/// Rejects relative paths, `..` components, and paths whose final component is
/// a symlink. Running as root, the daemon should not be tricked into reading
/// or writing arbitrary files on behalf of an authenticated caller.
fn validate_host_path(kind: &str, path: &Path) -> Result<(), CoreError> {
    if !path.is_absolute() {
        return Err(CoreError::InvalidArgument(format!(
            "{kind} path must be absolute, got {}",
            path.display()
        )));
    }
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(CoreError::InvalidArgument(format!(
                "{kind} path must not contain '..' segments: {}",
                path.display()
            )));
        }
    }
    match path.symlink_metadata() {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(CoreError::InvalidArgument(format!(
                "{kind} path must not be a symlink: {}",
                path.display()
            )));
        }
        _ => {}
    }
    Ok(())
}

/// Parse a `host:guest[:ro]` mount spec into a [`husker_vmm::HostShare`].
///
/// Rules:
/// - `host` (part 0) must be a non-empty absolute path.
/// - `guest` defaults to `/mnt/<basename of host>` when omitted.
/// - A 2-part spec whose second part is exactly `ro` is treated as `host + read-only`
///   with the default guest path. A caller who wants both a custom guest path and
///   read-only access must supply all three parts: `host:guest:ro`.
/// - `tag` is derived as `format!("fs{index}")`.
pub fn parse_mount_spec(spec: &str, index: usize) -> Result<husker_vmm::HostShare, String> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    let host_str = parts[0];
    if host_str.is_empty() {
        return Err(format!("mount spec '{spec}': host path is empty"));
    }
    if !host_str.starts_with('/') {
        return Err(format!(
            "mount spec '{spec}': host path must be absolute, got '{host_str}'"
        ));
    }
    if host_str.split('/').any(|seg| seg == "..") {
        return Err(format!(
            "mount spec '{spec}': host path must not contain '..' components"
        ));
    }
    let tag = format!("fs{index}");
    let default_guest = || {
        let basename = std::path::Path::new(host_str)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("share");
        format!("/mnt/{basename}")
    };
    match parts.as_slice() {
        [_host] => Ok(husker_vmm::HostShare {
            host: host_str.into(),
            guest: default_guest(),
            read_only: false,
            tag,
        }),
        [_host, second] if *second == "ro" => Ok(husker_vmm::HostShare {
            host: host_str.into(),
            guest: default_guest(),
            read_only: true,
            tag,
        }),
        [_host, guest] => {
            if guest.is_empty() {
                return Err(format!("mount spec '{spec}': guest path is empty"));
            }
            if !guest.starts_with('/') {
                return Err(format!(
                    "mount spec '{spec}': guest path must be absolute, got '{guest}'"
                ));
            }
            Ok(husker_vmm::HostShare {
                host: host_str.into(),
                guest: guest.to_string(),
                read_only: false,
                tag,
            })
        }
        [_host, guest, trailing] => {
            if guest.is_empty() {
                return Err(format!("mount spec '{spec}': guest path is empty"));
            }
            if !guest.starts_with('/') {
                return Err(format!(
                    "mount spec '{spec}': guest path must be absolute, got '{guest}'"
                ));
            }
            if *trailing != "ro" {
                return Err(format!(
                    "mount spec '{spec}': trailing option must be 'ro', got '{trailing}'"
                ));
            }
            Ok(husker_vmm::HostShare {
                host: host_str.into(),
                guest: guest.to_string(),
                read_only: true,
                tag,
            })
        }
        _ => Err(format!("mount spec '{spec}': invalid format")),
    }
}

/// Tracks resources allocated during VM creation for rollback on failure.
#[derive(Default)]
struct AllocatedResources {
    #[cfg(feature = "linux-net")]
    guest_ip: Option<Ipv4Addr>,
    cid: Option<u32>,
    #[cfg(feature = "linux-net")]
    tap_name: Option<String>,
    vm_dir: Option<PathBuf>,
    vm_id: Option<Uuid>,
}

/// Service ownership stamped onto an instance VM at creation time.
#[derive(Debug, Clone, Copy)]
pub struct ServiceTag {
    pub service_id: Uuid,
    pub ordinal: u32,
}

/// Result of one reconcile pass over a single service.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReconcileOutcome {
    pub created: Vec<String>,
    pub destroyed: Vec<String>,
    /// (instance_name, error_message) for instances that could not be created/destroyed.
    pub failed: Vec<(String, String)>,
}

/// SIGKILL a VM's recorded VMM process if it is still alive and still *this*
/// VM's process.
///
/// Both backends embed the VM id in their argv (firecracker `--api-sock
/// <runtime>/<id>.sock`; qemu `-qmp`/`-serial`/`-pidfile` `<runtime>/<id>.*`), so
/// the id in the live `/proc/<pid>/cmdline` confirms the pid is this VM's VMM and
/// not an unrelated process that recycled it. A dead or recycled pid is never
/// touched. Linux-only (uses /proc + signals). Returns whether a process was
/// killed.
#[cfg(target_os = "linux")]
fn reap_vmm_if_orphaned(id: Uuid, pid: u32) -> bool {
    let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    cmdline.contains(&id.to_string()) && unsafe { libc::kill(pid as i32, libc::SIGKILL) } == 0
}

#[cfg(not(target_os = "linux"))]
fn reap_vmm_if_orphaned(_id: Uuid, _pid: u32) -> bool {
    false
}

/// Kill VMM child processes orphaned by a previous daemon that exited without
/// cleanup (SIGKILL/OOM/power loss). At startup, any VM still marked
/// `running`/`paused` in the DB is an orphan (a clean shutdown drains + marks
/// them stopped). Both Firecracker and QEMU are foreground children that survive
/// an uncleaned daemon exit (`kill_on_drop` only fires on a graceful drop and
/// there is no death signal), so each is SIGKILLed via [`reap_vmm_if_orphaned`],
/// which only touches a pid whose live cmdline still names this VM. Must run
/// BEFORE mark_stale_vms_stopped. Returns the number reaped.
#[cfg(target_os = "linux")]
pub fn reap_orphaned_vmms(state: &husker_state::StateStore) -> usize {
    let vms = match state.list_vms() {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "reaper: failed to list VMs");
            return 0;
        }
    };
    let mut reaped = 0;
    for vm in vms {
        if vm.state != "running" && vm.state != "paused" {
            continue;
        }
        let Some(pid) = vm.pid else { continue };
        if reap_vmm_if_orphaned(vm.id, pid) {
            reaped += 1;
            warn!(pid, vm = %vm.name, "reaped orphaned VMM process from a prior daemon");
        }
    }
    reaped
}

/// Core orchestrator that ties together all subsystems.
pub struct HuskerCore<B: VmmBackend> {
    vmm: B,
    state: husker_state::StateStore,
    #[cfg(feature = "linux-net")]
    ip_allocator: husker_net::IpAllocator,
    storage: husker_storage::StorageConfig,
    storage_driver: Arc<dyn husker_storage::StorageDriver>,
    #[cfg(feature = "linux-net")]
    ovmf_code_path: PathBuf,
    #[cfg(feature = "linux-net")]
    ovmf_vars_template_path: PathBuf,
    embedded_agent: &'static [u8],
    #[cfg(feature = "linux-net")]
    bridge_name: String,
    #[cfg(feature = "linux-net")]
    lan_bridge: Option<String>,
    #[cfg(feature = "linux-net")]
    dns_servers: Vec<String>,
    /// Backend kind to persist when a create request omits `--vmm`. Mirrors the
    /// dispatcher's configured default so the record reflects the backend that
    /// actually runs the VM. Defaults to Firecracker.
    #[cfg(feature = "linux-net")]
    default_vmm_kind: husker_vmm::VmmKind,
    /// Default kernel the daemon uses when a create request omits kernel_path.
    /// Wired from the daemon config so remote clients do not need to send
    /// client-local paths that cannot exist on the daemon host.
    default_kernel: Option<PathBuf>,
    /// Default rootfs the daemon uses when a create request omits rootfs_path.
    default_rootfs: Option<PathBuf>,
    /// Default initrd the daemon uses when a create request omits initrd_path.
    default_initrd: Option<PathBuf>,
    runtime_dir: PathBuf,
    /// Per-VM-name locks guarding the create/destroy critical section.
    vm_name_locks: std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Per-service reconcile locks; serialize concurrent reconciles of the same service.
    reconcile_locks: std::sync::Mutex<std::collections::HashMap<Uuid, Arc<tokio::sync::Mutex<()>>>>,
    /// Userspace TCP port-forward proxies, keyed by VM (macOS, no host nftables).
    #[cfg(not(feature = "linux-net"))]
    port_proxy: Arc<crate::port_proxy::PortProxy<crate::port_proxy::ActiveDialer>>,
}

/// Per-attempt timeout for agent connect+ping in readiness loops.
const AGENT_PING_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Lines of guest serial console appended to a boot/agent-readiness failure.
const BOOT_FAILURE_SERIAL_TAIL_LINES: usize = 20;

/// Default agent-readiness wait (seconds) for direct-kernel microVMs.
pub const DEFAULT_READY_TIMEOUT_SECS: u64 = 120;

/// Default agent-readiness wait (seconds) for UEFI/cloud VMs, which boot much
/// slower than microVMs (OVMF firmware + GRUB + full distro init + cloud-init
/// installing and starting the agent).
pub const UEFI_READY_TIMEOUT_SECS: u64 = 180;

/// Boot-mode-aware default readiness timeout. `boot_mode` is the persisted
/// `VmRecord.boot_mode` value ("direct", "uefi", or "efi"); unknown values
/// use the direct-kernel default. Both "uefi" (Linux/QEMU cloud-image) and
/// "efi" (macOS/VZ cloud-image) run full cloud-init on first boot and need
/// the extended timeout.
pub fn default_ready_timeout(boot_mode: &str) -> std::time::Duration {
    let secs = if boot_mode == "uefi" || boot_mode == "efi" {
        UEFI_READY_TIMEOUT_SECS
    } else {
        DEFAULT_READY_TIMEOUT_SECS
    };
    std::time::Duration::from_secs(secs)
}

/// Resolve the backend kind to persist for a new VM.
///
/// husker's Linux dispatcher resolves an omitted `--vmm` to the daemon's
/// configured default, so the persisted `VmRecord.vmm` must reflect that same
/// resolution rather than a hardcoded assumption. Otherwise capability gating
/// (suspend) and restore backend-matching read the wrong kind for a VM created
/// without `--vmm` on a QEMU-default daemon. Cloud-image boot is QEMU-only and
/// overrides the default.
#[cfg(feature = "linux-net")]
fn resolve_vmm_kind(
    req_vmm: Option<&str>,
    is_cloud: bool,
    default: husker_vmm::VmmKind,
) -> Result<husker_vmm::VmmKind, CoreError> {
    if is_cloud {
        return Ok(husker_vmm::VmmKind::Qemu);
    }
    match req_vmm {
        Some(s) => s.parse::<husker_vmm::VmmKind>().map_err(CoreError::Vmm),
        None => Ok(default),
    }
}

/// Append the agent-supervisor boot tokens to a direct-kernel cmdline when the
/// booting image declares a `boot_init` (set by `import-oci`). A user-supplied
/// explicit `init=` already on the cmdline wins and is left untouched.
#[cfg(feature = "linux-net")]
fn apply_boot_init(base: &str, boot_init: Option<&str>) -> String {
    match boot_init {
        Some(path) if !base.split_whitespace().any(|t| t.starts_with("init=")) => {
            format!("{base} init={path} husker.init=1")
        }
        _ => base.to_string(),
    }
}

/// Write the husker agent and its OCI runtime config into an imported rootfs and
/// point `/sbin/init` at the agent, so the microVM boots into the agent as PID 1
/// regardless of the base image. The initramfs `switch_root`s into `/sbin/init`;
/// the agent then detects `husker.init=1` and runs the supervisor (mounts,
/// kernel modules, networking), making the boot path identical for busybox,
/// debian-slim, and distroless images alike.
#[cfg(feature = "linux-net")]
fn inject_guest_runtime(
    dir: &std::path::Path,
    agent: &[u8],
    oci_config: &husker_agent_proto::OciRuntimeConfig,
) -> Result<(), CoreError> {
    use std::os::unix::fs::PermissionsExt;

    // Resolve `rel` under `dir` without following any symlink: a symlink (or
    // plain file) in a parent position is replaced with a real directory. OCI
    // images are untrusted and the daemon runs as root, so an injected path must
    // never be redirected (e.g. via `usr/local/bin -> /etc`) outside the rootfs.
    fn safe_target(dir: &std::path::Path, rel: &str) -> Result<std::path::PathBuf, CoreError> {
        let comps: Vec<&str> = rel.split('/').filter(|c| !c.is_empty()).collect();
        let (dirs, file) = comps.split_at(comps.len().saturating_sub(1));
        let mut cur = dir.to_path_buf();
        for d in dirs {
            cur = cur.join(d);
            match std::fs::symlink_metadata(&cur) {
                Ok(m) if m.file_type().is_dir() => {}
                Ok(_) => {
                    std::fs::remove_file(&cur)
                        .or_else(|_| std::fs::remove_dir_all(&cur))
                        .map_err(|e| CoreError::Io(format!("replace {}: {e}", cur.display())))?;
                    std::fs::create_dir(&cur)
                        .map_err(|e| CoreError::Io(format!("mkdir {}: {e}", cur.display())))?;
                }
                Err(_) => std::fs::create_dir(&cur)
                    .map_err(|e| CoreError::Io(format!("mkdir {}: {e}", cur.display())))?,
            }
        }
        Ok(cur.join(file.first().copied().unwrap_or("")))
    }

    let write = |rel: &str, bytes: &[u8], mode: u32| -> Result<(), CoreError> {
        let target = safe_target(dir, rel)?;
        // Unlink any existing symlink/file at the target before writing (no follow).
        let _ = std::fs::remove_file(&target);
        std::fs::write(&target, bytes)
            .map_err(|e| CoreError::Io(format!("write {}: {e}", target.display())))?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode))
            .map_err(|e| CoreError::Io(format!("chmod {}: {e}", target.display())))?;
        Ok(())
    };

    write("usr/local/bin/husker-agent", agent, 0o755)?;

    // The runtime config the agent applies on exec: the image's PATH/env and
    // working directory, so a bare `python3` resolves and `$PWD` matches the
    // image's WorkingDir. Always written (even when empty) so the agent can tell
    // an imported OCI rootfs from the baseline rootfs.
    let config_json = serde_json::to_vec_pretty(oci_config)
        .map_err(|e| CoreError::Io(format!("serialize oci config: {e}")))?;
    write("etc/husker/oci-config.json", &config_json, 0o644)?;

    // Boot every imported image via the agent supervisor: the initramfs
    // `switch_root`s into `/sbin/init`, so replace whatever the image ships
    // there with a symlink to the agent. `safe_target` already replaced any
    // symlinked parent with a real directory; unlink any leaf init first so the
    // symlink is created in-rootfs (never followed off it).
    let sbin_init = safe_target(dir, "sbin/init")?;
    let _ = std::fs::remove_file(&sbin_init);
    std::os::unix::fs::symlink("/usr/local/bin/husker-agent", &sbin_init)
        .map_err(|e| CoreError::Io(format!("symlink {}: {e}", sbin_init.display())))?;
    Ok(())
}

impl<B: VmmBackend> HuskerCore<B> {
    /// Create a new HuskerCore with Linux networking (bridge + TAP + nftables).
    #[cfg(feature = "linux-net")]
    pub fn new(
        vmm: B,
        state: husker_state::StateStore,
        ip_allocator: husker_net::IpAllocator,
        storage: husker_storage::StorageConfig,
        bridge_name: String,
        dns_servers: Vec<String>,
        runtime_dir: PathBuf,
    ) -> Self {
        Self {
            vmm,
            state,
            ip_allocator,
            storage,
            storage_driver: husker_storage::default_storage_driver(),
            ovmf_code_path: PathBuf::from("/usr/share/OVMF/OVMF_CODE_4M.fd"),
            ovmf_vars_template_path: PathBuf::from("/usr/share/OVMF/OVMF_VARS_4M.fd"),
            embedded_agent: &[],
            bridge_name,
            lan_bridge: None,
            dns_servers,
            default_vmm_kind: husker_vmm::VmmKind::Firecracker,
            default_kernel: None,
            default_rootfs: None,
            default_initrd: None,
            runtime_dir,
            vm_name_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
            reconcile_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Create a new HuskerCore without host networking.
    ///
    /// On macOS, the Virtualization.framework handles networking internally
    /// via VZNATNetworkDeviceAttachment.
    #[cfg(not(feature = "linux-net"))]
    pub fn new(
        vmm: B,
        state: husker_state::StateStore,
        storage: husker_storage::StorageConfig,
        runtime_dir: PathBuf,
    ) -> Self {
        Self {
            vmm,
            state,
            storage,
            storage_driver: husker_storage::default_storage_driver(),
            embedded_agent: &[],
            default_kernel: None,
            default_rootfs: None,
            default_initrd: None,
            runtime_dir,
            vm_name_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
            reconcile_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
            port_proxy: Arc::new(crate::port_proxy::PortProxy::new(
                crate::port_proxy::ActiveDialer::default(),
            )),
        }
    }

    /// Provide the embedded guest agent used to build cloud-init seeds. Empty (the
    /// default) disables cloud-image support with a clear error at create time.
    pub fn with_embedded_agent(mut self, agent: &'static [u8]) -> Self {
        self.embedded_agent = agent;
        self
    }

    /// Set the default kernel/rootfs/initrd the daemon uses when a create request
    /// omits them. Wire these from the daemon's config so a remote client can create
    /// VMs without sending client-local paths (which don't exist on the daemon). Each
    /// is used only when the request omits the corresponding path.
    pub fn with_default_images(
        mut self,
        kernel: Option<PathBuf>,
        rootfs: Option<PathBuf>,
        initrd: Option<PathBuf>,
    ) -> Self {
        self.default_kernel = kernel;
        self.default_rootfs = rootfs;
        self.default_initrd = initrd;
        self
    }

    /// Set the default backend kind used when a create request omits `--vmm`.
    /// Wire this from the same daemon config value the dispatcher uses so the
    /// persisted record matches the backend that runs the VM.
    #[cfg(feature = "linux-net")]
    pub fn with_default_vmm_kind(mut self, kind: husker_vmm::VmmKind) -> Self {
        self.default_vmm_kind = kind;
        self
    }

    /// Override the OVMF firmware paths used for UEFI/cloud-image boot.
    /// Defaults target the Ubuntu/Debian `ovmf` package layout.
    #[cfg(feature = "linux-net")]
    pub fn with_uefi_firmware(mut self, code: PathBuf, vars_template: PathBuf) -> Self {
        self.ovmf_code_path = code;
        self.ovmf_vars_template_path = vars_template;
        self
    }

    /// Set the host LAN bridge name for bridged networking.
    ///
    /// When set, VMs created with `network: "bridged"` have their TAP enslaved
    /// to this bridge instead of the husker NAT bridge. The bridge must be
    /// pre-created and have a DHCP server on the attached network segment.
    #[cfg(feature = "linux-net")]
    pub fn with_lan_bridge(mut self, bridge: Option<String>) -> Self {
        self.lan_bridge = bridge;
        self
    }

    fn vm_name_lock(&self, name: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self.vm_name_locks.lock().expect("vm_name_locks poisoned");
        map.entry(name.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    fn reconcile_lock(&self, id: Uuid) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self
            .reconcile_locks
            .lock()
            .expect("reconcile_locks poisoned");
        map.entry(id)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Create and boot a new VM.
    ///
    /// Allocates network, storage, and VMM resources. On failure, all
    /// partially allocated resources are rolled back. A stopped or failed VM
    /// with the same name is automatically replaced.
    pub async fn create_vm(&self, req: CreateVmRequest) -> Result<VmRecord, CoreError> {
        self.create_vm_record(req, None, true).await
    }

    /// Resolve a `run`/`job` rootfs argument to a host path. Accepts a literal
    /// path (used as-is), a catalog image name (resolved to its file), or an
    /// OCI/Docker reference (auto-imported on first use, then cached). A bare
    /// unknown name is a clear error rather than a confusing missing-file one.
    async fn resolve_rootfs_arg(
        &self,
        arg: &std::path::Path,
    ) -> Result<std::path::PathBuf, CoreError> {
        // An existing file is a literal path.
        if arg.is_file() {
            return Ok(arg.to_path_buf());
        }
        let s = arg.to_string_lossy().to_string();
        // A path-shaped argument that does not exist: leave it for the rootfs
        // validator to report clearly (don't treat a mistyped path as an image).
        if looks_like_path(&s) {
            return Ok(arg.to_path_buf());
        }
        // A known catalog image name.
        if let Ok(img) = self.state.get_image_by_name(&s) {
            return Ok(std::path::PathBuf::from(img.file_path));
        }
        // An OCI/Docker reference (`repo:tag` or `host/path[:tag]`): import + cache.
        if s.contains(':') || s.contains('/') {
            let name = oci_ref_to_catalog_name(&s);
            if let Ok(img) = self.state.get_image_by_name(&name) {
                return Ok(std::path::PathBuf::from(img.file_path));
            }
            info!(reference = %s, name = %name, "auto-importing OCI image for run/job");
            let rec = self.import_oci_image(&name, &s).await?;
            return Ok(std::path::PathBuf::from(rec.file_path));
        }
        // A bare name that is not a path and not in the catalog.
        Err(CoreError::InvalidArgument(format!(
            "'{s}' is not a rootfs path, a catalog image, or an OCI reference; \
             pass a path, a catalog image name, or a reference like 'repo:tag'"
        )))
    }

    /// Internal/advanced: prefer `create_vm`. Used by the reconciler to stamp service ownership.
    ///
    /// `tags` stamps service ownership atomically onto the new VM record.
    /// `replace_existing_stopped` controls whether an existing stopped/failed
    /// same-named VM is auto-replaced (public API: true; reconciler: false to
    /// avoid clobbering a foreign stopped VM).
    pub async fn create_vm_record(
        &self,
        mut req: CreateVmRequest,
        tags: Option<ServiceTag>,
        replace_existing_stopped: bool,
    ) -> Result<VmRecord, CoreError> {
        validate_resource_name("vm", &req.name)?;
        info!(name = %req.name, "creating VM");

        let _name_guard = self.vm_name_lock(&req.name).lock_owned().await;

        // If a stopped VM with this name exists, replace it automatically when
        // the caller allows it. Running or paused VMs must be explicitly
        // destroyed first.
        if let Ok(existing) = self.state.get_vm_by_name(&req.name) {
            if replace_existing_stopped
                && (existing.state == "stopped" || existing.state == "failed")
            {
                info!(name = %req.name, "replacing stopped VM");
                self.destroy_vm_inner(&existing).await?;
            } else {
                return Err(CoreError::VmAlreadyExists(req.name));
            }
        }

        if req.cloud_image.is_none() {
            // Fill daemon defaults for any path the client omitted. A remote client
            // sends only the paths the user explicitly specified; the daemon fills the
            // rest from its own configured defaults so the paths are valid on the
            // daemon host, not the client host.
            if req.kernel_path.is_none() {
                req.kernel_path = self.default_kernel.clone();
            }
            if req.rootfs_path.is_none() {
                req.rootfs_path = self.default_rootfs.clone();
            }
            // Resolve a catalog image name or an OCI/Docker reference in the rootfs
            // argument to a real host path (auto-importing an OCI ref on first use),
            // so `husker run myimg` / `husker job python:3.12-alpine` work without
            // knowing the on-disk catalog layout.
            if let Some(rootfs) = req.rootfs_path.take() {
                req.rootfs_path = Some(self.resolve_rootfs_arg(&rootfs).await?);
            }
            let kernel = req.kernel_path.as_deref().ok_or_else(|| {
                CoreError::InvalidArgument(
                    "no kernel specified and the daemon has no default kernel; \
                     pass --kernel, or run `husker images pull` on the daemon host"
                        .into(),
                )
            })?;
            let rootfs = req.rootfs_path.as_deref().ok_or_else(|| {
                CoreError::InvalidArgument(
                    "no rootfs specified and the daemon has no default rootfs; \
                     pass a rootfs path, or run `husker images pull` on the daemon host"
                        .into(),
                )
            })?;
            husker_storage::validate_kernel(kernel)?;
            husker_storage::validate_rootfs(rootfs)?;
        }

        let mut resources = AllocatedResources::default();
        match self.try_create_vm(req, tags, &mut resources).await {
            Ok(record) => {
                info!(name = %record.name, id = %record.id, "VM created");
                Ok(record)
            }
            Err(e) => {
                warn!(error = %e, "VM creation failed, rolling back");
                self.rollback_create(resources).await;
                Err(e)
            }
        }
    }

    /// Inner create logic that tracks allocated resources for rollback.
    #[cfg(feature = "linux-net")]
    async fn try_create_vm(
        &self,
        req: CreateVmRequest,
        tags: Option<ServiceTag>,
        resources: &mut AllocatedResources,
    ) -> Result<VmRecord, CoreError> {
        // Validate + default the network mode before touching any host resources.
        let network_mode = validate_network_mode(req.network.as_deref())?;

        // Bridged mode preconditions: must have a cloud image and a configured LAN bridge.
        // These checks run before any resource allocation so tests can verify them in-memory.
        if network_mode == "bridged" {
            if req.cloud_image.is_none() {
                return Err(CoreError::InvalidArgument(
                    "bridged networking requires --cloud-image \
                     (microVM guests have no DHCP client)"
                        .into(),
                ));
            }
            if self.lan_bridge.is_none() {
                return Err(CoreError::InvalidArgument(
                    "bridged networking requires the lan_bridge config option".into(),
                ));
            }
        }

        // NAT mode: allocate a static IP. Bridged mode: skip allocation; the LAN DHCP
        // server assigns the address. The rollback field stays None so unwind skips it.
        let guest_ip = if network_mode == "nat" {
            let ip = self.ip_allocator.allocate()?;
            resources.guest_ip = Some(ip);
            Some(ip)
        } else {
            None
        };

        let cid = self.state.allocate_cid()?;
        resources.cid = Some(cid);

        let tap_name = format!("husker{cid}");
        let mac = husker_net::generate_mac(cid);

        // Computed for the NAT branches below; bridged mode never applies them.
        let gateway = self.ip_allocator.gateway();
        let netmask = husker_net::prefix_len_to_netmask(self.ip_allocator.prefix_len());

        if let Some(ip) = guest_ip {
            debug!(tap = %tap_name, %ip, %gateway, cid, "NAT resources allocated");
        } else {
            debug!(tap = %tap_name, cid, "bridged resources allocated (no IP)");
        }

        husker_net::create_tap(&tap_name).await?;
        resources.tap_name = Some(tap_name.clone());

        // Attach the TAP to the appropriate bridge: the LAN bridge for bridged mode,
        // or the husker NAT bridge for NAT mode.
        let attach_bridge = if network_mode == "bridged" {
            self.lan_bridge
                .as_deref()
                .expect("lan_bridge checked above")
        } else {
            &self.bridge_name
        };
        husker_net::attach_to_bridge(&tap_name, attach_bridge).await?;

        let vm_dir = self.storage.vm_dir(&req.name);
        if vm_dir.exists() {
            warn!(name = %req.name, "removing stale VM directory from incomplete cleanup");
            if let Err(e) = tokio::fs::remove_dir_all(&vm_dir).await {
                warn!(dir = %vm_dir.display(), error = %e, "failed to remove stale VM directory");
            }
        }
        // Register the VM directory for rollback before any disk is created, so a
        // partially-prepared disk (e.g. cloud clone succeeds but resize fails) is
        // still cleaned up on failure.
        resources.vm_dir = Some(vm_dir.clone());

        // Resolve the named volume before disk setup so the cloud-init seed can
        // reflect the correct mount_volume value in a single pass. The
        // exclusivity check (find_vm_by_volume) runs here right before the
        // VmRecord insert; there is a small TOCTOU window between this check
        // and the insert, but at homelab scale that race is acceptable.
        let volume_attachment = self.resolve_volume_attachment(&req.volume)?;
        if let Some((ref vol_name, _)) = volume_attachment
            && let Some(holder) = self.state.find_vm_by_volume(vol_name)?
        {
            return Err(CoreError::InvalidArgument(format!(
                "volume '{vol_name}' is already attached to VM '{}'",
                holder.name
            )));
        }
        let mount_volume = volume_attachment.is_some();

        // Choose the boot disk + mode. A cloud image boots via UEFI/OVMF from a cloned
        // qcow2; the default path boots a host kernel from a raw ext4 rootfs.
        // cloud_source_path: the resolved source image (catalog path or user path) used as
        // rootfs_path provenance in the VmRecord for cloud VMs; None for direct-kernel boot.
        let (disk_path, boot, is_cloud, seed_path, cloud_source_path) = if let Some(image) =
            req.cloud_image.as_ref()
        {
            // Resolve --cloud-image: an existing host path wins; otherwise it
            // names a catalog image of kind "cloud-image".
            let image_path = {
                let as_path = std::path::Path::new(image);
                if as_path.exists() {
                    as_path.to_path_buf()
                } else {
                    let rec = self.state.get_image_by_name(image).map_err(|e| match e {
                        husker_state::StateError::ImageNotFoundByName(_) => {
                            CoreError::InvalidArgument(format!(
                                "cloud image '{image}' is neither an existing file nor a \
                                 catalog image (register one with `husker image import \
                                 --kind cloud-image`)"
                            ))
                        }
                        other => CoreError::State(other),
                    })?;
                    if rec.kind != "cloud-image" {
                        return Err(CoreError::InvalidArgument(format!(
                            "catalog image '{image}' has kind '{}', not 'cloud-image'",
                            rec.kind
                        )));
                    }
                    PathBuf::from(rec.file_path)
                }
            };
            // Cloud-image boot is QEMU-only. Reject an explicit non-QEMU backend request.
            if let Some(v) = req.vmm.as_deref() {
                let kind = v.parse::<husker_vmm::VmmKind>().map_err(CoreError::Vmm)?;
                if kind != husker_vmm::VmmKind::Qemu {
                    return Err(CoreError::InvalidArgument(
                        "cloud-image boot requires the QEMU backend (--vmm qemu)".into(),
                    ));
                }
            }
            // The seed delivers the guest agent; fail fast (before cloning) if the
            // daemon was built without one.
            if self.embedded_agent.is_empty() {
                return Err(CoreError::InvalidArgument(
                    "cloud-image support needs the embedded guest agent; build the daemon with \
                     `make build-agent` (or set HUSKER_EMBED_AGENT_BIN) first"
                        .into(),
                ));
            }
            let disk = vm_dir.join("disk.qcow2");
            let boot = prepare_cloud_disk(
                self.storage_driver.as_ref(),
                &image_path,
                req.disk_size,
                &disk,
                &self.ovmf_code_path,
                &self.ovmf_vars_template_path,
            )
            .await?;
            // Build the NoCloud seed. For NAT mode, inject a static network config so
            // cloud-init does not stall waiting for DHCP before the agent comes up.
            // For bridged mode, omit network-config entirely: cloud-init falls back to
            // DHCP on all NICs, and the LAN DHCP server assigns the address.
            let seed_network = if network_mode == "nat" {
                Some(husker_cloudinit::NetworkConfig {
                    ip: guest_ip.expect("NAT mode always has a guest_ip"),
                    prefix_len: self.ip_allocator.prefix_len(),
                    gateway,
                    dns: self.dns_servers.clone(),
                })
            } else {
                None
            };
            let seed = husker_cloudinit::build_seed(&husker_cloudinit::SeedSpec {
                agent: self.embedded_agent,
                hostname: req.name.clone(),
                instance_id: req.name.clone(),
                ssh_authorized_keys: req.ssh_authorized_keys.clone(),
                network: seed_network,
                mount_volume,
            })
            .map_err(seed_error_to_core)?;
            let seed_path = vm_dir.join("seed.img");
            tokio::fs::write(&seed_path, &seed)
                .await
                .map_err(|e| CoreError::Storage(husker_storage::StorageError::Io(e)))?;
            (disk, boot, true, Some(seed_path), Some(image_path))
        } else {
            let rootfs = req.rootfs_path.as_deref().ok_or_else(|| {
                CoreError::InvalidArgument("rootfs_path is required for direct-kernel boot".into())
            })?;
            let vm_rootfs = vm_dir.join("rootfs.ext4");
            self.storage_driver.clone_rootfs(rootfs, &vm_rootfs).await?;
            (
                vm_rootfs,
                husker_vmm::BootMode::DirectKernel,
                false,
                None,
                None,
            )
        };

        // resolv.conf injection loop-mounts the ext4 rootfs; skip it for qcow2 cloud
        // images, which are not ext4. Cloud images configure DNS via cloud-init at boot.
        if !is_cloud && !self.dns_servers.is_empty() {
            inject_resolv_conf(&disk_path, &self.dns_servers).await?;
        }

        // Resolve the backend kind once and persist it, so the record reflects the
        // backend the dispatcher actually runs (an omitted `--vmm` resolves to the
        // daemon default, not a hardcoded Firecracker).
        let resolved_vmm_kind =
            resolve_vmm_kind(req.vmm.as_deref(), is_cloud, self.default_vmm_kind)?;

        // For direct-kernel boot: resolve the kernel now (validation already ran in
        // create_vm_record; try_create_vm may also be called from tests that skip it).
        let (config_kernel_path, record_kernel_path, record_rootfs_path) = if is_cloud {
            // Cloud VMs boot via UEFI; kernel_path is unused in VmConfig for that path.
            // Persist an empty kernel_path and the resolved source image path as rootfs
            // provenance so callers can trace which catalog/host image backed this VM.
            let source = cloud_source_path
                .expect("cloud_source_path is Some when is_cloud")
                .to_string_lossy()
                .into_owned();
            (PathBuf::new(), String::new(), source)
        } else {
            let kernel = req.kernel_path.as_deref().ok_or_else(|| {
                CoreError::InvalidArgument("kernel_path is required for direct-kernel boot".into())
            })?;
            let rootfs = req.rootfs_path.as_deref().ok_or_else(|| {
                CoreError::InvalidArgument("rootfs_path is required for direct-kernel boot".into())
            })?;
            (
                kernel.to_path_buf(),
                kernel.to_string_lossy().into_owned(),
                rootfs.to_string_lossy().into_owned(),
            )
        };

        let volume_path = volume_attachment.as_ref().map(|(_, p)| p.clone());

        // If the booting rootfs is a catalog image with a boot_init (an OCI image
        // imported by `import-oci`), boot it via the agent supervisor. Looked up
        // by the source rootfs path so it works however the image was referenced.
        let boot_init = if is_cloud {
            None
        } else {
            self.state.list_images().ok().and_then(|imgs| {
                imgs.into_iter()
                    .find(|i| i.file_path == record_rootfs_path)
                    .and_then(|i| i.boot_init)
            })
        };

        // Resolve initrd: prefer explicit path, then daemon default (if it exists on
        // the daemon host), then the conventional data-dir location as a last resort.
        // Resolved before kernel_args so the root= flag reflects the actual initrd state.
        let initrd_path = req
            .initrd_path
            .clone()
            .or_else(|| self.default_initrd.clone().filter(|p| p.exists()))
            .or_else(|| {
                let conventional = self.storage.data_dir.join("kernels/initramfs-virt.gz");
                conventional.exists().then_some(conventional)
            });

        // Parse and validate host-mount specs. Each spec is validated for path
        // safety here; the API layer enforces the allowlist before forwarding.
        let mut host_shares: Vec<husker_vmm::HostShare> = Vec::new();
        for (i, spec) in req.mounts.iter().enumerate() {
            let share = parse_mount_spec(spec, i).map_err(CoreError::InvalidArgument)?;
            validate_host_path("mount", &share.host)?;
            host_shares.push(share);
        }

        // NAT direct-kernel VMs pass the static IP as a kernel boot parameter.
        // Cloud VMs (NAT and bridged) use cloud-init for network; kernel_args is None.
        let kernel_args = if is_cloud {
            None
        } else {
            // Direct-kernel boots are always NAT (bridged requires cloud image).
            // Without an initrd the kernel must mount root itself; append root=/dev/vda rw.
            let root = if initrd_path.is_none() {
                " root=/dev/vda rw"
            } else {
                ""
            };
            let base = format!(
                "console=ttyS0 reboot=k panic=1 pci=off{root} \
                 ip={ip}::{gateway}:{netmask}::eth0:off",
                ip = guest_ip.expect("direct-kernel boot is always NAT")
            );
            let mut args = apply_boot_init(&base, boot_init.as_deref());
            // Append one token per virtiofs share; the guest init reads these to
            // determine which tags to mount and where.
            for share in &host_shares {
                let ro_suffix = if share.read_only { ":ro" } else { "" };
                args.push_str(&format!(
                    " husker.share={}={}{}",
                    share.tag, share.guest, ro_suffix
                ));
            }
            Some(args)
        };

        let vm_config = husker_vmm::VmConfig {
            name: req.name.clone(),
            vcpu_count: req.vcpu_count.unwrap_or(1),
            mem_size_mib: req.mem_size_mib.unwrap_or(128),
            kernel_path: config_kernel_path,
            rootfs_path: disk_path,
            kernel_args,
            initrd_path,
            vsock_cid: cid,
            tap_device: Some(tap_name.clone()),
            guest_mac: Some(mac),
            vmm: Some(resolved_vmm_kind),
            boot,
            seed_path,
            balloon: req.balloon,
            volume_path,
            host_shares,
        };

        let info = self.vmm.create_vm(vm_config).await?;
        resources.vm_id = Some(info.id);

        let userdata_status = req.userdata.as_ref().map(|_| "pending".to_string());
        let now = chrono::Utc::now();

        // NAT: persist the allocated IP and gateway; bridged: both stay None (DHCP-assigned).
        let (record_guest_ip, record_host_ip) = if network_mode == "nat" {
            (guest_ip.map(|ip| ip.to_string()), Some(gateway.to_string()))
        } else {
            (None, None)
        };

        let record = VmRecord {
            id: info.id,
            name: req.name,
            state: info.state.to_string(),
            pid: info.pid,
            vcpu_count: info.vcpu_count,
            mem_size_mib: info.mem_size_mib,
            vsock_cid: cid,
            tap_device: Some(tap_name),
            host_ip: record_host_ip,
            guest_ip: record_guest_ip,
            kernel_path: record_kernel_path,
            rootfs_path: record_rootfs_path,
            created_at: now,
            updated_at: now,
            userdata: req.userdata,
            userdata_status,
            userdata_env: if req.env.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&req.env).expect("env serializes to JSON"))
            },
            service_id: tags.map(|t| t.service_id),
            service_ordinal: tags.map(|t| t.ordinal),
            vmm: resolved_vmm_kind.to_string(),
            boot_mode: if is_cloud {
                "uefi".to_string()
            } else {
                "direct".to_string()
            },
            balloon: req.balloon,
            volume: volume_attachment.map(|(vol_name, _)| vol_name),
            network: network_mode.to_string(),
        };

        self.state.insert_vm(&record).map_err(|e| match e {
            husker_state::StateError::VmAlreadyExists(name) => CoreError::VmAlreadyExists(name),
            other => CoreError::State(other),
        })?;

        Ok(record)
    }

    /// Inner create logic without host networking.
    ///
    /// Networking is handled by the VMM backend (e.g. VZ NAT). Supports both
    /// direct-kernel boot and cloud-image (qcow2-to-raw + EFI) boot.
    #[cfg(not(feature = "linux-net"))]
    async fn try_create_vm(
        &self,
        req: CreateVmRequest,
        tags: Option<ServiceTag>,
        resources: &mut AllocatedResources,
    ) -> Result<VmRecord, CoreError> {
        // Validate the network mode field even though only "nat" is meaningful here,
        // so callers get a clear error for unknown values.
        let network_mode = validate_network_mode(req.network.as_deref())?;

        // Bridged mode is a Linux-only feature (requires TAP + host bridge management).
        if network_mode == "bridged" {
            return Err(CoreError::InvalidArgument(
                "bridged networking is only supported on Linux".into(),
            ));
        }

        let cid = self.state.allocate_cid()?;
        resources.cid = Some(cid);

        debug!(cid, "resources allocated");

        let vm_dir = self.storage.vm_dir(&req.name);
        if vm_dir.exists() {
            warn!(name = %req.name, "removing stale VM directory from incomplete cleanup");
            if let Err(e) = tokio::fs::remove_dir_all(&vm_dir).await {
                warn!(dir = %vm_dir.display(), error = %e, "failed to remove stale VM directory");
            }
        }

        if let Some(image) = req.cloud_image.as_ref() {
            // --volume with --cloud-image is not yet supported on macOS.
            if req.volume.is_some() {
                return Err(CoreError::InvalidArgument(
                    "--volume with --cloud-image is not yet supported on macOS".into(),
                ));
            }

            // Resolve --cloud-image: an existing host path wins; otherwise it
            // names a catalog image of kind "cloud-image".
            let image_path = {
                let as_path = std::path::Path::new(image);
                if as_path.exists() {
                    as_path.to_path_buf()
                } else {
                    let rec = self.state.get_image_by_name(image).map_err(|e| match e {
                        husker_state::StateError::ImageNotFoundByName(_) => {
                            CoreError::InvalidArgument(format!(
                                "cloud image '{image}' is neither an existing file nor a \
                                 catalog image (register one with `husker image import \
                                 --kind cloud-image`)"
                            ))
                        }
                        other => CoreError::State(other),
                    })?;
                    if rec.kind != "cloud-image" {
                        return Err(CoreError::InvalidArgument(format!(
                            "catalog image '{image}' has kind '{}', not 'cloud-image'",
                            rec.kind
                        )));
                    }
                    PathBuf::from(rec.file_path)
                }
            };

            // Validate the qcow2 magic before any disk I/O.
            husker_storage::validate_cloud_image(&image_path)?;

            // The seed delivers the guest agent; fail fast (before disk conversion)
            // if this build has no embedded agent.
            if self.embedded_agent.is_empty() {
                return Err(CoreError::InvalidArgument(
                    "cloud-image VMs need the embedded guest agent; this build has none \
                     (Apple Silicon builds embed it; rebuild via make install)"
                        .into(),
                ));
            }

            // Guard against shrinking: if the caller requests a disk_size smaller
            // than the image's virtual size, reject before starting the conversion.
            if let Some(size) = req.disk_size {
                let virtual_size = husker_storage::qcow2_virtual_size(&image_path).await?;
                if size < virtual_size {
                    return Err(CoreError::InvalidArgument(format!(
                        "--disk-size {size} is smaller than the image's virtual size \
                         {virtual_size}"
                    )));
                }
            }

            // Register the VM directory for rollback before creating any disk files,
            // so a partial conversion is cleaned up on failure.
            tokio::fs::create_dir_all(&vm_dir)
                .await
                .map_err(|e| CoreError::Storage(husker_storage::StorageError::Io(e)))?;
            resources.vm_dir = Some(vm_dir.clone());

            // Convert the source qcow2 to a raw disk image. Apple Virtualization.framework
            // requires raw images; qemu-img convert is blocking (it reads GBs of data), so
            // it runs on the blocking thread pool.
            let disk = vm_dir.join("disk.raw");
            let src = image_path.clone();
            let dst = disk.clone();
            tokio::task::spawn_blocking(move || husker_storage::convert_qcow2_to_raw(&src, &dst))
                .await
                .map_err(|e| {
                    CoreError::Storage(husker_storage::StorageError::QemuImg(format!(
                        "spawn_blocking join error: {e}"
                    )))
                })??;

            if let Some(size) = req.disk_size {
                husker_storage::resize_disk(&disk, size).await?;
            }

            // Build the NoCloud seed. VZ NAT assigns addresses via DHCP, so omit
            // network-config and let cloud-init's fallback DHCP client handle it.
            let seed = husker_cloudinit::build_seed(&husker_cloudinit::SeedSpec {
                agent: self.embedded_agent,
                hostname: req.name.clone(),
                instance_id: req.name.clone(),
                ssh_authorized_keys: req.ssh_authorized_keys.clone(),
                network: None,
                mount_volume: false,
            })
            .map_err(seed_error_to_core)?;
            let seed_path = vm_dir.join("seed.img");
            tokio::fs::write(&seed_path, &seed)
                .await
                .map_err(|e| CoreError::Storage(husker_storage::StorageError::Io(e)))?;

            let boot = husker_vmm::BootMode::Efi {
                variable_store: vm_dir.join("nvram.bin"),
            };
            let boot_mode_str = boot.as_str().to_string();

            // For cloud VMs: kernel_path is unused by EFI boot; record it as empty
            // (mirrors the Linux cloud path). rootfs_path records the source image
            // for provenance (which catalog/host image backed this VM).
            let record_rootfs_path = image_path.to_string_lossy().into_owned();

            let vm_config = husker_vmm::VmConfig {
                name: req.name.clone(),
                vcpu_count: req.vcpu_count.unwrap_or(1),
                mem_size_mib: req.mem_size_mib.unwrap_or(128),
                kernel_path: PathBuf::new(),
                rootfs_path: disk,
                kernel_args: None,
                initrd_path: None,
                vsock_cid: cid,
                tap_device: None,
                guest_mac: None,
                vmm: None,
                boot,
                seed_path: Some(seed_path),
                balloon: req.balloon,
                volume_path: None,
                host_shares: vec![],
            };

            let info = self.vmm.create_vm(vm_config).await?;
            resources.vm_id = Some(info.id);

            let userdata_status = req.userdata.as_ref().map(|_| "pending".to_string());
            let now = chrono::Utc::now();
            let record = VmRecord {
                id: info.id,
                name: req.name,
                state: info.state.to_string(),
                pid: info.pid,
                vcpu_count: info.vcpu_count,
                mem_size_mib: info.mem_size_mib,
                vsock_cid: cid,
                tap_device: None,
                host_ip: None,
                guest_ip: None,
                kernel_path: String::new(),
                rootfs_path: record_rootfs_path,
                created_at: now,
                updated_at: now,
                userdata: req.userdata,
                userdata_status,
                userdata_env: if req.env.is_empty() {
                    None
                } else {
                    Some(serde_json::to_string(&req.env).expect("env serializes to JSON"))
                },
                service_id: tags.map(|t| t.service_id),
                service_ordinal: tags.map(|t| t.ordinal),
                vmm: "apple_vz".to_string(),
                boot_mode: boot_mode_str,
                balloon: req.balloon,
                volume: None,
                network: network_mode.to_string(),
            };

            self.state.insert_vm(&record).map_err(|e| match e {
                husker_state::StateError::VmAlreadyExists(name) => CoreError::VmAlreadyExists(name),
                other => CoreError::State(other),
            })?;

            return Ok(record);
        }

        // ── Direct-kernel boot ───────────────────────────────────────────────

        let kernel = req.kernel_path.as_deref().ok_or_else(|| {
            CoreError::InvalidArgument("kernel_path is required for direct-kernel boot".into())
        })?;
        let rootfs = req.rootfs_path.as_deref().ok_or_else(|| {
            CoreError::InvalidArgument("rootfs_path is required for direct-kernel boot".into())
        })?;
        let vm_rootfs = vm_dir.join("rootfs.ext4");
        self.storage_driver.clone_rootfs(rootfs, &vm_rootfs).await?;
        resources.vm_dir = Some(vm_dir);

        // Resolve the named volume to its image path. The exclusivity check runs
        // here, right before the VmRecord insert; there is a small TOCTOU window
        // between this check and the insert, but at homelab scale that race is
        // acceptable.
        let volume_attachment = self.resolve_volume_attachment(&req.volume)?;
        if let Some((ref vol_name, _)) = volume_attachment
            && let Some(holder) = self.state.find_vm_by_volume(vol_name)?
        {
            return Err(CoreError::InvalidArgument(format!(
                "volume '{vol_name}' is already attached to VM '{}'",
                holder.name
            )));
        }

        // Resolve initrd: prefer explicit path, then daemon default (if it exists on
        // the daemon host), then the conventional data-dir location as a last resort.
        let initrd_path = req
            .initrd_path
            .clone()
            .or_else(|| self.default_initrd.clone().filter(|p| p.exists()))
            .or_else(|| {
                let conventional = self.storage.data_dir.join("kernels/initramfs-virt.gz");
                conventional.exists().then_some(conventional)
            });

        let kernel_str = kernel.to_string_lossy().into_owned();
        let rootfs_str = rootfs.to_string_lossy().into_owned();
        let volume_path = volume_attachment.as_ref().map(|(_, p)| p.clone());
        let vm_config = husker_vmm::VmConfig {
            name: req.name.clone(),
            vcpu_count: req.vcpu_count.unwrap_or(1),
            mem_size_mib: req.mem_size_mib.unwrap_or(128),
            kernel_path: kernel.to_path_buf(),
            rootfs_path: vm_rootfs,
            kernel_args: Some("console=hvc0 root=/dev/vda rw init=/sbin/init".into()),
            initrd_path,
            vsock_cid: cid,
            tap_device: None,
            guest_mac: None,
            vmm: None,
            boot: husker_vmm::BootMode::DirectKernel,
            seed_path: None,
            balloon: req.balloon,
            volume_path,
            host_shares: vec![],
        };

        let info = self.vmm.create_vm(vm_config).await?;
        resources.vm_id = Some(info.id);

        let userdata_status = req.userdata.as_ref().map(|_| "pending".to_string());
        let now = chrono::Utc::now();
        let record = VmRecord {
            id: info.id,
            name: req.name,
            state: info.state.to_string(),
            pid: info.pid,
            vcpu_count: info.vcpu_count,
            mem_size_mib: info.mem_size_mib,
            vsock_cid: cid,
            tap_device: None,
            host_ip: None,
            guest_ip: None,
            kernel_path: kernel_str,
            rootfs_path: rootfs_str,
            created_at: now,
            updated_at: now,
            userdata: req.userdata,
            userdata_status,
            userdata_env: if req.env.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&req.env).expect("env serializes to JSON"))
            },
            service_id: tags.map(|t| t.service_id),
            service_ordinal: tags.map(|t| t.ordinal),
            vmm: "apple_vz".to_string(),
            boot_mode: "direct".to_string(),
            balloon: req.balloon,
            volume: volume_attachment.map(|(vol_name, _)| vol_name),
            network: network_mode.to_string(),
        };

        self.state.insert_vm(&record).map_err(|e| match e {
            husker_state::StateError::VmAlreadyExists(name) => CoreError::VmAlreadyExists(name),
            other => CoreError::State(other),
        })?;

        Ok(record)
    }

    /// Roll back partially allocated resources in reverse order.
    async fn rollback_create(&self, resources: AllocatedResources) {
        if let Some(vm_id) = resources.vm_id {
            debug!(%vm_id, "rolling back: destroying VM");
            if let Err(e) = self.vmm.destroy_vm(vm_id).await {
                warn!(%vm_id, error = %e, "rollback: failed to destroy VM");
            }
        }
        if let Some(ref dir) = resources.vm_dir {
            debug!(dir = %dir.display(), "rolling back: removing VM directory");
            if let Err(e) = tokio::fs::remove_dir_all(dir).await {
                warn!(dir = %dir.display(), error = %e, "rollback: failed to remove VM directory");
            }
        }
        #[cfg(feature = "linux-net")]
        if let Some(ref tap) = resources.tap_name {
            debug!(tap, "rolling back: removing TAP");
            if let Err(e) = husker_net::remove_all_port_forwards(tap, &self.bridge_name).await {
                warn!(tap, error = %e, "rollback: failed to remove port forwards");
            }
            if let Err(e) = husker_net::delete_tap(tap).await {
                warn!(tap, error = %e, "rollback: failed to delete TAP device");
            }
        }
        if let Some(cid) = resources.cid {
            debug!(cid, "rolling back: releasing CID");
            if let Err(e) = self.state.release_cid(cid) {
                warn!(cid, error = %e, "rollback: failed to release CID");
            }
        }
        #[cfg(feature = "linux-net")]
        if let Some(guest_ip) = resources.guest_ip {
            debug!(%guest_ip, "rolling back: releasing IP");
            if let Err(e) = self.ip_allocator.release(guest_ip) {
                warn!(%guest_ip, error = %e, "rollback: failed to release IP");
            }
        }
    }

    /// Stop a running or paused VM.
    ///
    /// Idempotent: stopping an already stopped VM is a no-op.
    pub async fn stop_vm(&self, name: &str) -> Result<(), CoreError> {
        info!(%name, "stopping VM");
        // Hold the per-VM name lock for the whole stop so a concurrent
        // add/remove of a userspace port forward cannot interleave with the
        // teardown below (macOS).
        #[cfg(not(feature = "linux-net"))]
        let _stop_guard = self.vm_name_lock(name).lock_owned().await;
        let record = self.lookup_vm(name)?;
        match record.state.as_str() {
            "running" | "paused" => {}
            "stopped" => {
                debug!(%name, "VM already stopped; stop is a no-op");
                return Ok(());
            }
            "suspended" => {
                // The process is already gone; discard the slot and mark stopped.
                let _ = tokio::fs::remove_dir_all(self.suspend_slot_dir(record.id)).await;
                self.state.update_vm_state(record.id, "stopped")?;
                return Ok(());
            }
            _ => {
                return Err(CoreError::InvalidState {
                    name: name.into(),
                    actual: record.state,
                    expected: "running or paused".into(),
                });
            }
        }
        self.vmm.stop_vm(record.id).await?;
        self.state.update_vm_state(record.id, "stopped")?;
        // macOS userspace forwards are bound to the running instance: tear them
        // down on stop. The name lock acquired above is still held.
        #[cfg(not(feature = "linux-net"))]
        {
            self.port_proxy.stop_all(record.id);
            self.state.delete_port_forwards_for_vm(record.id)?;
        }
        Ok(())
    }

    /// Pause a running VM.
    ///
    /// Idempotent: pausing an already paused VM is a no-op.
    pub async fn pause_vm(&self, name: &str) -> Result<(), CoreError> {
        info!(%name, "pausing VM");
        let record = self.lookup_vm(name)?;
        match record.state.as_str() {
            "running" => {}
            "paused" => {
                debug!(%name, "VM already paused; pause is a no-op");
                return Ok(());
            }
            _ => {
                return Err(CoreError::InvalidState {
                    name: name.into(),
                    actual: record.state,
                    expected: "running".into(),
                });
            }
        }
        self.vmm.pause_vm(record.id).await?;
        self.state.update_vm_state(record.id, "paused")?;
        Ok(())
    }

    /// Durable per-VM suspend slot: `<data_dir>/suspend/<vm_id>/`.
    fn suspend_slot_dir(&self, id: Uuid) -> PathBuf {
        self.storage.data_dir.join("suspend").join(id.to_string())
    }

    /// Suspend a VM to disk: pause, capture full state, terminate the process.
    ///
    /// Networking (TAP/IP/CID) and the VM's rootfs are intentionally preserved so
    /// `resume_vm` can restore the same identity in place. Idempotent.
    pub async fn suspend_vm(&self, name: &str) -> Result<(), CoreError> {
        info!(%name, "suspending VM");
        // Serialize against a concurrent resume/fork of this VM: fork moves the
        // source's rootfs aside during `/snapshot/load` and reuses its vsock path,
        // so suspend/resume/fork on one name must not interleave. `fork_vm` takes
        // this same lock on the source name.
        let _guard = self.vm_name_lock(name).lock_owned().await;
        let record = self.lookup_vm(name)?;
        match record.state.as_str() {
            "running" | "paused" => {}
            "suspended" => {
                debug!(%name, "VM already suspended; suspend is a no-op");
                return Ok(());
            }
            _ => {
                return Err(CoreError::InvalidState {
                    name: name.into(),
                    actual: record.state,
                    expected: "running or paused".into(),
                });
            }
        }

        // Fail fast before pausing: only backends with full-state snapshot can be
        // suspended. Otherwise a QEMU/Apple VZ VM would be paused, hit
        // `Unsupported` at snapshot time, and have to be un-paused again.
        if !husker_vmm::Capabilities::for_backend(&record.vmm).snapshot {
            return Err(CoreError::Vmm(husker_vmm::VmmError::Unsupported(format!(
                "backend '{}' does not support suspend (full-state snapshot)",
                record.vmm
            ))));
        }

        let paused_by_us = record.state == "running";
        let original_state = record.state.clone();

        // Persist the transient "suspending" state up front, BEFORE pausing or
        // capturing anything. A crash anywhere in the capture window then leaves a
        // "suspending" VM that startup `reconcile_suspended_vms` resolves from the
        // on-disk slot (a complete slot -> "suspended", an incomplete one ->
        // "stopped"), instead of a "running"/"paused" row that startup downgrades
        // to "stopped" even though a complete, resumable slot exists on disk.
        self.state.update_vm_state(record.id, "suspending")?;

        let slot = self.suspend_slot_dir(record.id);
        let paths = SnapshotPaths::in_dir(&slot);

        // Capture the full state (pause -> snapshot -> manifest). On any failure,
        // roll the DB state back to what it was and resume the VMM if we paused it,
        // so a failed suspend is a no-op for the caller.
        let capture = async {
            if paused_by_us {
                self.vmm.pause_vm(record.id).await?;
            }
            tokio::fs::create_dir_all(&slot)
                .await
                .map_err(|e| CoreError::Io(format!("create suspend slot: {e}")))?;
            let meta = self.vmm.snapshot_vm(record.id, &paths).await?;
            let manifest = serde_json::json!({
                "kind": "full",
                "backend": meta.backend,
                "vmm_version": meta.vmm_version,
                "vcpu_count": record.vcpu_count,
                "mem_size_mib": record.mem_size_mib,
                "vsock_cid": record.vsock_cid,
                "rootfs_path": record.rootfs_path,
            });
            write_file_atomic(
                &paths.manifest,
                &serde_json::to_vec_pretty(&manifest).expect("manifest serializes"),
            )
            .await
            .map_err(|e| CoreError::Io(format!("write suspend manifest: {e}")))?;
            Ok::<(), CoreError>(())
        };
        if let Err(e) = capture.await {
            let _ = tokio::fs::remove_dir_all(&slot).await;
            if paused_by_us {
                let _ = self.vmm.resume_vm(record.id).await;
            }
            let _ = self.state.update_vm_state(record.id, &original_state);
            return Err(e);
        }

        // The slot is complete and durable; freeing the memory and the final state
        // write are both covered by reconcile (state is already "suspending").
        self.vmm.destroy_vm(record.id).await?;
        self.state.update_vm_state(record.id, "suspended")?;
        info!(%name, "VM suspended");
        Ok(())
    }

    /// Recover VMs interrupted mid-suspend on a previous daemon run.
    ///
    /// A VM in the transient `"suspending"` state was past its snapshot + manifest
    /// write (so its guest memory may already be freed) when the daemon stopped.
    /// If a complete suspend slot is on disk the VM is resumable, so finish the
    /// transition to `"suspended"`; otherwise the capture never completed and the
    /// memory state is unrecoverable, so fall back to `"stopped"` (the rootfs is
    /// intact, so the VM can be re-run). Returns the number of VMs reconciled.
    /// Call at daemon startup, before serving requests.
    pub async fn reconcile_suspended_vms(&self) -> Result<usize, CoreError> {
        let mut reconciled = 0;
        for vm in self.state.list_vms()? {
            if vm.state != "suspending" {
                continue;
            }
            // A hard crash between the snapshot write and destroy_vm can leave the
            // pre-crash firecracker alive (reparented), still bound to this VM's
            // rootfs/vsock/CID/TAP. Reap it before trusting the slot, so a later
            // resume/fork cannot race a surviving VMM over the same resources.
            // (`reap_orphaned_vmms` does not: it targets running/paused, not
            // suspending.)
            if let Some(pid) = vm.pid
                && reap_vmm_if_orphaned(vm.id, pid)
            {
                warn!(pid, vm = %vm.name, "reaped firecracker orphaned by an interrupted suspend");
            }
            let paths = SnapshotPaths::in_dir(self.suspend_slot_dir(vm.id));
            let slot_complete = tokio::fs::try_exists(&paths.manifest)
                .await
                .unwrap_or(false)
                && tokio::fs::try_exists(&paths.memory).await.unwrap_or(false)
                && tokio::fs::try_exists(&paths.vmstate).await.unwrap_or(false);
            let recovered_to = if slot_complete {
                "suspended"
            } else {
                let _ = tokio::fs::remove_dir_all(self.suspend_slot_dir(vm.id)).await;
                "stopped"
            };
            self.state.update_vm_state(vm.id, recovered_to)?;
            warn!(vm = %vm.name, recovered_to, "reconciled interrupted suspend");
            reconciled += 1;
        }
        Ok(reconciled)
    }

    /// Recover source rootfs disks left stranded by a fork that crashed mid-load
    /// on a prior daemon run. Such a fork leaves the source's `rootfs.ext4` as a
    /// stale symlink to the fork clone, with the real disk in a
    /// `rootfs.ext4.fork-src-bak` backup. Restore each one before any resume can
    /// open the stale symlink and boot the source against the wrong disk. Run at
    /// daemon startup. Returns the number recovered.
    pub fn recover_stranded_fork_rootfs(&self) -> usize {
        let vms = match self.state.list_vms() {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "failed to list VMs for stranded-fork rootfs recovery");
                return 0;
            }
        };
        let mut recovered = 0;
        for vm in vms {
            let rootfs = self.storage.vm_dir(&vm.name).join("rootfs.ext4");
            match husker_vmm::firecracker::recover_aliased_rootfs(&rootfs) {
                Ok(true) => {
                    warn!(vm = %vm.name, "recovered source rootfs stranded by an interrupted fork");
                    recovered += 1;
                }
                Ok(false) => {}
                Err(e) => {
                    warn!(vm = %vm.name, error = %e, "failed to recover stranded fork source rootfs")
                }
            }
        }
        recovered
    }

    /// Restore a suspended VM in place (same id/IP/CID/MAC).
    async fn restore_from_suspend(&self, record: &VmRecord) -> Result<(), CoreError> {
        let slot = self.suspend_slot_dir(record.id);
        let paths = SnapshotPaths::in_dir(&slot);

        let manifest_bytes = tokio::fs::read(&paths.manifest)
            .await
            .map_err(|e| CoreError::Io(format!("suspend slot missing manifest: {e}")))?;
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| CoreError::InvalidArgument(format!("invalid suspend manifest: {e}")))?;
        let backend = manifest
            .get("backend")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if backend != record.vmm {
            return Err(CoreError::InvalidArgument(format!(
                "suspend snapshot backend '{backend}' does not match VM backend '{}'",
                record.vmm
            )));
        }

        let target = RestoreTarget::Resume {
            id: record.id,
            name: record.name.clone(),
            vcpu_count: record.vcpu_count,
            mem_size_mib: record.mem_size_mib,
            vsock_cid: record.vsock_cid,
        };
        self.vmm.restore_vm(&paths, target).await?;
        self.state.update_vm_state(record.id, "running")?;

        let _ = tokio::fs::remove_dir_all(&slot).await;
        Ok(())
    }

    /// Resume a paused or suspended VM.
    ///
    /// - `paused`: un-pauses the running VMM process.
    /// - `suspended`: restores full VM state from the suspend slot on disk.
    /// - `running`: idempotent no-op.
    pub async fn resume_vm(&self, name: &str) -> Result<(), CoreError> {
        info!(%name, "resuming VM");
        // Serialize against a concurrent fork/suspend of this VM (see `suspend_vm`):
        // restoring a suspended source must not interleave with a fork that has the
        // source's rootfs aliased to a clone during `/snapshot/load`.
        let _guard = self.vm_name_lock(name).lock_owned().await;
        let record = self.lookup_vm(name)?;
        match record.state.as_str() {
            "paused" => {
                self.vmm.resume_vm(record.id).await?;
                self.state.update_vm_state(record.id, "running")?;
            }
            "suspended" => {
                self.restore_from_suspend(&record).await?;
            }
            "running" => {
                debug!(%name, "VM already running; resume is a no-op");
            }
            _ => {
                return Err(CoreError::InvalidState {
                    name: name.into(),
                    actual: record.state,
                    expected: "paused or suspended".into(),
                });
            }
        }
        Ok(())
    }

    /// Fork a suspended VM into a new running VM with a fresh host identity.
    ///
    /// Clones the source's rootfs (reflink, copy-on-write), restores a new
    /// Firecracker VM from the source's snapshot (the memory file is mapped
    /// copy-on-write, so the source is untouched), binds it to a freshly
    /// allocated TAP/IP/MAC, and re-homes the guest's network in place via the
    /// agent. The source stays suspended.
    ///
    /// Limitations (v1): NAT-mode, Firecracker-backed, volume-free sources only.
    /// The fork reuses the source's vsock path, so (a) only one running fork per
    /// source at a time and the source must stay suspended while a fork of it
    /// runs, and (b) forks are ephemeral - destroy them rather than suspending
    /// them (a forked VM's snapshot still embeds the source's vsock path, which a
    /// plain resume cannot reconstruct). A volume-backed source is rejected
    /// because the snapshot embeds the source's writable volume disk, which the
    /// fork would otherwise share.
    #[cfg(feature = "linux-net")]
    pub async fn fork_vm(&self, source_name: &str, fork_name: &str) -> Result<VmRecord, CoreError> {
        info!(%source_name, %fork_name, "forking VM");
        if source_name == fork_name {
            return Err(CoreError::InvalidArgument(
                "fork name must differ from the source name".into(),
            ));
        }
        // Serialize forks of the same source (the rootfs alias moves the source's
        // disk aside during load) and guard the new name against a racing create.
        let _src_guard = self.vm_name_lock(source_name).lock_owned().await;
        let _fork_guard = self.vm_name_lock(fork_name).lock_owned().await;

        let source = self.lookup_vm(source_name)?;
        if source.state != "suspended" {
            return Err(CoreError::InvalidState {
                name: source_name.into(),
                actual: source.state,
                expected: "suspended".into(),
            });
        }
        if !husker_vmm::Capabilities::for_backend(&source.vmm).fork {
            return Err(CoreError::Vmm(husker_vmm::VmmError::Unsupported(format!(
                "backend '{}' does not support fork",
                source.vmm
            ))));
        }
        if source.network != "nat" {
            return Err(CoreError::InvalidArgument(
                "fork is only supported for NAT-mode VMs".into(),
            ));
        }
        // The snapshot embeds the source's writable volume disk, and the fork only
        // clones the rootfs, so a fork would silently share (and corrupt) the
        // source's volume. Reject volume-backed sources.
        if source.volume.is_some() {
            return Err(CoreError::InvalidArgument(
                "cannot fork a VM with an attached volume (the fork would share the \
                 source's writable volume)"
                    .into(),
            ));
        }
        if self.lookup_vm(fork_name).is_ok() {
            return Err(CoreError::VmAlreadyExists(fork_name.into()));
        }

        let mut resources = AllocatedResources::default();
        match self.try_fork_vm(&source, fork_name, &mut resources).await {
            Ok(rec) => {
                info!(%source_name, %fork_name, "VM forked");
                Ok(rec)
            }
            Err(e) => {
                // Log the reason server-side: fork failures previously surfaced
                // only in the HTTP 500 body, leaving the daemon journal silent.
                warn!(%source_name, %fork_name, error = %e, "fork failed; rolling back");
                self.rollback_create(resources).await;
                Err(e)
            }
        }
    }

    /// Inner fork logic that tracks allocated resources for rollback.
    #[cfg(feature = "linux-net")]
    async fn try_fork_vm(
        &self,
        source: &VmRecord,
        fork_name: &str,
        resources: &mut AllocatedResources,
    ) -> Result<VmRecord, CoreError> {
        // Fresh host identity for the fork. `cid` is the fork's host-side id: it
        // names the TAP (`husker{cid}`) and derives the MAC, and is what we
        // persist. The guest's internal vsock CID stays the source's (baked in
        // the snapshot), which is harmless because host->guest agent connections
        // are Unix-socket-path based, not CID-addressed.
        let guest_ip = self.ip_allocator.allocate()?;
        resources.guest_ip = Some(guest_ip);
        let cid = self.state.allocate_cid()?;
        resources.cid = Some(cid);
        let tap_name = format!("husker{cid}");
        let mac = husker_net::generate_mac(cid);
        let gateway = self.ip_allocator.gateway();
        let prefix_len = self.ip_allocator.prefix_len();

        // Create the TAP (Firecracker binds it during restore) but do NOT attach it
        // to the bridge yet: the fork resumes with the source's IP and MAC, so
        // bridging it before the guest is re-homed would put a duplicate identity on
        // the shared L2. It joins the bridge only after ReconfigureNetwork below.
        husker_net::create_tap(&tap_name).await?;
        resources.tap_name = Some(tap_name.clone());

        // Clone the source's live rootfs into the fork's dir (reflink CoW).
        let fork_dir = self.storage.vm_dir(fork_name);
        if fork_dir.exists() {
            let _ = tokio::fs::remove_dir_all(&fork_dir).await;
        }
        tokio::fs::create_dir_all(&fork_dir)
            .await
            .map_err(|e| CoreError::Io(format!("create fork dir: {e}")))?;
        resources.vm_dir = Some(fork_dir.clone());
        let source_rootfs = self.storage.vm_dir(&source.name).join("rootfs.ext4");
        let fork_rootfs = fork_dir.join("rootfs.ext4");
        self.storage_driver
            .clone_rootfs(&source_rootfs, &fork_rootfs)
            .await?;

        // Restore the fork from the source's snapshot, bound to its own TAP and
        // its own vsock UDS path (via FC `vsock_override`), so the source can be
        // forked many times concurrently without a host-socket collision.
        let fork_id = Uuid::new_v4();
        let src_snapshot = SnapshotPaths::in_dir(self.suspend_slot_dir(source.id));
        let info = self
            .vmm
            .restore_vm(
                &src_snapshot,
                RestoreTarget::Fork {
                    id: fork_id,
                    name: fork_name.into(),
                    vcpu_count: source.vcpu_count,
                    mem_size_mib: source.mem_size_mib,
                    vsock_cid: cid,
                    tap_device: tap_name.clone(),
                    source_rootfs,
                    fork_rootfs,
                },
            )
            .await?;
        resources.vm_id = Some(info.id);

        // Re-home the guest's network identity (new MAC + IP + gateway + DNS) live.
        self.reconfigure_fork_network(info.id, &guest_ip, prefix_len, gateway, &mac)
            .await?;

        // Now that the guest carries its own MAC and IP, join it to the bridge.
        husker_net::attach_to_bridge(&tap_name, &self.bridge_name).await?;

        // Persist the fork as a running VM.
        let now = chrono::Utc::now();
        let record = VmRecord {
            id: fork_id,
            name: fork_name.into(),
            state: "running".into(),
            pid: info.pid,
            vcpu_count: source.vcpu_count,
            mem_size_mib: source.mem_size_mib,
            vsock_cid: cid,
            tap_device: Some(tap_name),
            host_ip: Some(gateway.to_string()),
            guest_ip: Some(guest_ip.to_string()),
            kernel_path: source.kernel_path.clone(),
            rootfs_path: source.rootfs_path.clone(),
            created_at: now,
            updated_at: now,
            userdata: None,
            userdata_status: None,
            userdata_env: None,
            service_id: None,
            service_ordinal: None,
            vmm: source.vmm.clone(),
            boot_mode: source.boot_mode.clone(),
            balloon: false,
            volume: None,
            network: "nat".into(),
        };
        self.state.insert_vm(&record).map_err(|e| match e {
            husker_state::StateError::VmAlreadyExists(name) => CoreError::VmAlreadyExists(name),
            other => CoreError::State(other),
        })?;
        Ok(record)
    }

    /// Connect to a just-restored fork's agent and apply its new network identity.
    /// The agent was already running when the source was suspended, so it returns
    /// with the snapshot; retry briefly to race the vsock rebind.
    #[cfg(feature = "linux-net")]
    async fn reconfigure_fork_network(
        &self,
        fork_id: Uuid,
        guest_ip: &std::net::Ipv4Addr,
        prefix_len: u8,
        gateway: std::net::Ipv4Addr,
        mac: &str,
    ) -> Result<(), CoreError> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let attempt = async {
                let stream = self
                    .vmm
                    .vsock_connect(fork_id, husker_agent_proto::AGENT_VSOCK_PORT)
                    .await?;
                let mut conn = crate::agent_client::AgentConnection::new(stream);
                conn.reconfigure_network(
                    "eth0",
                    &guest_ip.to_string(),
                    prefix_len,
                    &gateway.to_string(),
                    Some(mac),
                    &self.dns_servers,
                )
                .await?;
                Ok::<(), CoreError>(())
            }
            .await;
            match attempt {
                Ok(()) => return Ok(()),
                // The agent connected but did not understand the reconfigure
                // request (EOF / wrong reply): it predates `ReconfigureNetwork`
                // and is too old for fork. Retrying for the full 10s deadline
                // cannot help, so fail fast with an actionable message instead of
                // an opaque "unexpected response from agent" after a long stall.
                Err(CoreError::Agent(AgentError::UnexpectedResponse)) => {
                    return Err(CoreError::InvalidArgument(
                        "fork requires live network reconfiguration, but the guest \
                         agent does not support it; rebuild the source VM's rootfs \
                         with a current husker-agent, then suspend it again before \
                         forking"
                            .into(),
                    ));
                }
                Err(e) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(e);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                }
            }
        }
    }

    /// Fork is only available on Linux (Firecracker); the macOS/Apple VZ build
    /// has no snapshot support, so this rejects rather than silently no-opping.
    #[cfg(not(feature = "linux-net"))]
    pub async fn fork_vm(
        &self,
        _source_name: &str,
        _fork_name: &str,
    ) -> Result<VmRecord, CoreError> {
        Err(CoreError::Vmm(husker_vmm::VmmError::Unsupported(
            "fork is only supported on Linux (Firecracker)".into(),
        )))
    }

    /// Destroy a VM and clean up all associated resources.
    ///
    /// If the VM is already stopped or the VMM backend no longer tracks it
    /// (e.g. after a daemon restart), the VMM destroy step is skipped and
    /// only state/storage cleanup is performed.
    pub async fn destroy_vm(&self, name: &str) -> Result<(), CoreError> {
        let record = self.lookup_vm(name)?;
        let _name_guard = self.vm_name_lock(name).lock_owned().await;
        self.destroy_vm_inner(&record).await
    }

    /// Destroy a VM without acquiring the name lock.
    ///
    /// Callers MUST already hold the per-VM-name lock. Used internally by
    /// `create_vm_record` when replacing a stopped VM atomically within the
    /// same critical section.
    async fn destroy_vm_inner(&self, record: &VmRecord) -> Result<(), CoreError> {
        let name = record.name.as_str();
        info!(%name, "destroying VM");

        match self.vmm.destroy_vm(record.id).await {
            Ok(()) => {}
            Err(husker_vmm::VmmError::VmNotFound(_)) => {
                debug!(%name, "VM not in VMM backend, cleaning up state only");
            }
            Err(e) => return Err(e.into()),
        }

        // Clean up network resources. Port forwards live in two places:
        // 1. nftables rules in the kernel (removed by remove_all_port_forwards)
        // 2. SQLite records in the state store (removed by delete_port_forwards_for_vm)
        // Both must be cleaned up. Deleting the TAP automatically detaches it
        // from the bridge.
        #[cfg(feature = "linux-net")]
        {
            if let Some(ref tap) = record.tap_device {
                if let Err(e) = husker_net::remove_all_port_forwards(tap, &self.bridge_name).await {
                    warn!(%name, tap, error = %e, "failed to remove port forwards during destroy");
                }
                if let Err(e) = husker_net::delete_tap(tap).await {
                    warn!(%name, tap, error = %e, "failed to delete TAP device during destroy");
                }
            }

            if let Some(ref guest_ip_str) = record.guest_ip
                && let Ok(guest_ip) = guest_ip_str.parse::<Ipv4Addr>()
                && let Err(e) = self.ip_allocator.release(guest_ip)
            {
                warn!(%name, %guest_ip, error = %e, "failed to release IP during destroy");
            }
        }

        self.state.release_cid(record.vsock_cid)?;
        // Abort any macOS userspace port-forward listeners before dropping the
        // rows. (`destroy_vm` already holds the per-VM name lock.)
        #[cfg(not(feature = "linux-net"))]
        self.port_proxy.stop_all(record.id);
        self.state.delete_port_forwards_for_vm(record.id)?;

        let vm_dir = self.storage.vm_dir(&record.name);
        if let Err(e) = tokio::fs::remove_dir_all(&vm_dir).await {
            warn!(%name, dir = %vm_dir.display(), error = %e, "failed to remove VM directory during destroy");
        }

        let serial_log = self.runtime_dir.join(format!("{}.serial.log", record.id));
        if let Err(e) = remove_file_best_effort(&serial_log).await {
            warn!(%name, path = %serial_log.display(), error = %e, "failed to remove serial log during destroy");
        }

        // The userdata log is optional (only VMs with userdata have one), so
        // its absence is not worth a warning.
        let userdata_log = self.runtime_dir.join(format!("{}.userdata.log", record.id));
        let _ = remove_file_best_effort(&userdata_log).await;

        let boot_log = self.runtime_dir.join(format!("{}.boot.log", record.id));
        if let Err(e) = remove_file_best_effort(&boot_log).await {
            warn!(%name, path = %boot_log.display(), error = %e, "failed to remove boot log during destroy");
        }

        let suspend_slot = self.suspend_slot_dir(record.id);
        if let Err(e) = tokio::fs::remove_dir_all(&suspend_slot).await
            && e.kind() != std::io::ErrorKind::NotFound
        {
            warn!(%name, dir = %suspend_slot.display(), error = %e, "failed to remove suspend slot during destroy");
        }

        self.state.delete_vm(record.id)?;
        info!(%name, "VM destroyed");
        Ok(())
    }

    /// List all VMs.
    pub fn list_vms(&self) -> Result<Vec<VmRecord>, CoreError> {
        Ok(self.state.list_vms()?)
    }

    /// The capability-defining backend kind of this daemon's VMM backend
    /// (e.g. `"firecracker"`, `"apple_vz"`). Used to advertise daemon
    /// capabilities over the API.
    pub fn backend_kind(&self) -> &'static str {
        self.vmm.backend_kind()
    }

    /// List all VMs with their state refreshed against the backend.
    ///
    /// Detects guest-initiated shutdowns (process exited without the daemon
    /// observing it). Prefer this for user-facing reads; use `list_vms` for
    /// internal callers that do not need a liveness check (e.g. the health
    /// endpoint, which is called on a tight monitoring loop and can tolerate
    /// VM counts lagging one reconcile interval).
    ///
    /// Note: guest-IP discovery runs serially per VM. In the worst case (N
    /// running EFI VMs all lacking IPs, all with slow or unresponsive agents)
    /// this adds up to N x 2 seconds of latency (two 1-second timeouts per VM).
    pub async fn list_vms_refreshed(&self) -> Result<Vec<VmRecord>, CoreError> {
        let vms = self.state.list_vms()?;
        let mut out = Vec::with_capacity(vms.len());
        for vm in &vms {
            let mut refreshed = self.refresh_vm_liveness(vm).await;
            self.discover_guest_ip(&mut refreshed).await;
            out.push(refreshed);
        }
        Ok(out)
    }

    /// Get info about a specific VM.
    pub fn get_vm(&self, name: &str) -> Result<VmRecord, CoreError> {
        self.lookup_vm(name)
    }

    /// Get a VM by name with its state refreshed against the backend.
    ///
    /// Detects guest-initiated shutdowns. Prefer this for user-facing reads.
    pub async fn get_vm_refreshed(&self, name: &str) -> Result<VmRecord, CoreError> {
        let record = self.get_vm(name)?;
        let mut refreshed = self.refresh_vm_liveness(&record).await;
        self.discover_guest_ip(&mut refreshed).await;
        Ok(refreshed)
    }

    /// Fill guest_ip for a running EFI-boot VM that does not have one yet.
    ///
    /// Attempts vsock connect (1-second timeout) then a GuestInfo request
    /// (1-second timeout) - at most 2 seconds per call in the worst case.
    /// Persists on success. Never fails the read - any error or timeout is
    /// silently discarded (debug! at most).
    ///
    /// Boot mode "efi" is used exclusively by macOS/VZ cloud-image VMs, where
    /// the guest IP is DHCP-assigned and not known at creation time. On Linux,
    /// boot_mode is always "direct" or "uefi", so this function is a no-op.
    async fn discover_guest_ip(&self, vm: &mut VmRecord) {
        if vm.guest_ip.is_some() || vm.state != "running" || vm.boot_mode != "efi" {
            return;
        }

        let connect_result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            self.vmm
                .vsock_connect(vm.id, husker_agent_proto::AGENT_VSOCK_PORT),
        )
        .await;

        let stream = match connect_result {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                debug!(name = %vm.name, error = %e, "discover_guest_ip: vsock connect failed");
                return;
            }
            Err(_) => {
                debug!(name = %vm.name, "discover_guest_ip: vsock connect timed out");
                return;
            }
        };

        let mut conn = crate::agent_client::AgentConnection::new(stream);
        let info_result =
            tokio::time::timeout(std::time::Duration::from_secs(1), conn.guest_info()).await;

        let info = match info_result {
            Ok(Ok(i)) => i,
            Ok(Err(e)) => {
                debug!(name = %vm.name, error = %e, "discover_guest_ip: GuestInfo request failed");
                return;
            }
            Err(_) => {
                debug!(name = %vm.name, "discover_guest_ip: GuestInfo request timed out");
                return;
            }
        };

        let Some(ip) = info.ipv4.into_iter().next() else {
            debug!(name = %vm.name, "discover_guest_ip: agent returned no IPv4 addresses");
            return;
        };

        if let Err(e) = self.state.update_vm_guest_ip(vm.id, &ip) {
            warn!(name = %vm.name, error = %e, "discover_guest_ip: failed to persist guest IP");
        }
        vm.guest_ip = Some(ip);
    }

    /// Refresh a persisted VM record against the backend's live process view.
    ///
    /// The backend's `vm_info` performs the actual liveness check (`try_wait`,
    /// which also reaps a child that exited on its own, e.g. a guest-initiated
    /// `poweroff`/`reboot`). When the DB says running/paused but the process is
    /// gone - the backend reports Stopped/Failed, or no longer tracks the VM at
    /// all - the record is marked stopped in state and the updated record is
    /// returned. Errors persisting the state are logged, not fatal: the caller
    /// still sees the corrected in-memory record.
    ///
    /// Platform scope: Firecracker and QEMU backends detect process exit via
    /// `try_wait` on the child process. The Apple VZ backend queries the live
    /// `VZVirtualMachine.state()` on the VM's dispatch queue so guest-initiated
    /// shutdown (poweroff, kernel panic) is also detected on macOS.
    pub async fn refresh_vm_liveness(&self, vm: &VmRecord) -> VmRecord {
        if vm.state != "running" && vm.state != "paused" {
            return vm.clone();
        }
        let alive = match self.vmm.vm_info(vm.id).await {
            Ok(info) => matches!(info.state, VmState::Running | VmState::Paused),
            // Backend does not track this VM (e.g. process reaped or daemon
            // restarted): it is not running.
            Err(_) => false,
        };
        if alive {
            return vm.clone();
        }
        info!(name = %vm.name, "VM process is gone; marking stopped");
        if let Err(e) = self.state.update_vm_state(vm.id, "stopped") {
            warn!(name = %vm.name, error = %e, "failed to persist stopped state");
        }
        let mut updated = vm.clone();
        updated.state = "stopped".to_string();
        updated.pid = None;
        updated
    }

    /// Create a host group.
    pub fn create_host_group(
        &self,
        req: CreateHostGroupRequest,
    ) -> Result<HostGroupRecord, CoreError> {
        validate_resource_name("host group", &req.name)?;
        let record = HostGroupRecord {
            id: Uuid::new_v4(),
            name: req.name,
            description: req.description,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        self.state.insert_host_group(&record).map_err(|e| match e {
            husker_state::StateError::HostGroupAlreadyExists(name) => {
                CoreError::HostGroupAlreadyExists(name)
            }
            other => CoreError::State(other),
        })?;
        Ok(record)
    }

    /// List all host groups.
    pub fn list_host_groups(&self) -> Result<Vec<HostGroupRecord>, CoreError> {
        Ok(self.state.list_host_groups()?)
    }

    /// Get a host group by name.
    pub fn get_host_group(&self, name: &str) -> Result<HostGroupRecord, CoreError> {
        self.state
            .get_host_group_by_name(name)
            .map_err(|e| match e {
                husker_state::StateError::HostGroupNotFoundByName(_) => {
                    CoreError::HostGroupNotFound(name.into())
                }
                other => CoreError::State(other),
            })
    }

    /// Delete a host group by name.
    pub fn delete_host_group(&self, name: &str) -> Result<(), CoreError> {
        let record = self.get_host_group(name)?;
        self.state
            .delete_host_group(record.id)
            .map_err(|e| match e {
                husker_state::StateError::HostGroupNotFound(_) => {
                    CoreError::HostGroupNotFound(name.into())
                }
                other => CoreError::State(other),
            })
    }

    /// Create a service and reconcile it to its desired instance count.
    pub async fn create_service(
        self: &std::sync::Arc<Self>,
        req: CreateServiceRequest,
    ) -> Result<(ServiceRecord, ReconcileOutcome), CoreError>
    where
        B: 'static,
    {
        validate_resource_name("service", &req.name)?;
        let desired_instances = req.desired_instances.unwrap_or(1);
        validate_service_instance_names(&req.name, desired_instances)?;
        if let Some(ref volume) = req.volume
            && desired_instances > 1
        {
            return Err(CoreError::InvalidArgument(format!(
                "service '{}' requests {desired_instances} instances with volume '{volume}': \
                 volumes are exclusive-attach, so a volume-backed service is limited to 1 instance",
                req.name,
            )));
        }

        // cloud-image services are not yet supported on macOS; reject before
        // persisting the ServiceRecord so the error surfaces immediately.
        #[cfg(not(feature = "linux-net"))]
        if req.cloud_image.is_some() {
            return Err(CoreError::InvalidArgument(
                "cloud-image services are not yet supported on macOS".into(),
            ));
        }

        let (rootfs, kernel) = if req.cloud_image.is_some() {
            (
                req.rootfs_path.unwrap_or_default(),
                req.kernel_path.unwrap_or_default(),
            )
        } else {
            // Fall back to the daemon's configured defaults when the client omits
            // them, mirroring create_vm_record. The client omits unspecified paths
            // (so a remote client does not send its own local paths), so the daemon
            // must resolve them here too or service create would reject valid input.
            (
                req.rootfs_path
                    .or_else(|| self.default_rootfs.clone())
                    .ok_or_else(|| {
                        CoreError::InvalidArgument(
                            "service requires a rootfs (--image or --rootfs) or --cloud-image, \
                             and the daemon has no default rootfs"
                                .into(),
                        )
                    })?,
                req.kernel_path
                    .or_else(|| self.default_kernel.clone())
                    .ok_or_else(|| {
                        CoreError::InvalidArgument(
                            "service requires a kernel, and the daemon has no default kernel"
                                .into(),
                        )
                    })?,
            )
        };

        let host_group_id = match req.host_group.as_deref() {
            Some(group_name) => Some(
                self.state
                    .get_host_group_by_name(group_name)
                    .map_err(|e| match e {
                        husker_state::StateError::HostGroupNotFoundByName(_) => {
                            CoreError::HostGroupNotFound(group_name.into())
                        }
                        other => CoreError::State(other),
                    })?
                    .id,
            ),
            None => None,
        };

        // Validate the volume name now so a typo'd volume fails service creation
        // immediately rather than at instance spawn time.
        self.resolve_volume_attachment(&req.volume)?;

        let now = chrono::Utc::now();
        let record = ServiceRecord {
            id: Uuid::new_v4(),
            name: req.name,
            host_group_id,
            desired_instances,
            image: req.image,
            kernel_path: kernel.to_string_lossy().into_owned(),
            rootfs_path: rootfs.to_string_lossy().into_owned(),
            initrd_path: req.initrd_path.map(|p| p.to_string_lossy().into_owned()),
            vcpu_count: req.vcpu_count,
            mem_size_mib: req.mem_size_mib,
            userdata: req.userdata,
            userdata_env: if req.env.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&req.env).expect("env serializes to JSON"))
            },
            created_at: now,
            updated_at: now,
            cloud_image: req.cloud_image,
            disk_size: req.disk_size,
            balloon: req.balloon,
            volume: req.volume,
        };
        self.state.insert_service(&record).map_err(|e| match e {
            husker_state::StateError::ServiceAlreadyExists(name) => {
                CoreError::ServiceAlreadyExists(name)
            }
            other => CoreError::State(other),
        })?;

        let outcome = self.reconcile_service(&record).await;
        Ok((record, outcome))
    }

    /// List all services.
    pub fn list_services(&self) -> Result<Vec<ServiceRecord>, CoreError> {
        Ok(self.state.list_services()?)
    }

    /// Get a service by name.
    pub fn get_service(&self, name: &str) -> Result<ServiceRecord, CoreError> {
        self.state.get_service_by_name(name).map_err(|e| match e {
            husker_state::StateError::ServiceNotFoundByName(_) => {
                CoreError::ServiceNotFound(name.into())
            }
            other => CoreError::State(other),
        })
    }

    /// Scale a service to the desired instance count and reconcile.
    pub async fn scale_service(
        self: &std::sync::Arc<Self>,
        name: &str,
        desired_instances: u32,
    ) -> Result<(ServiceRecord, ReconcileOutcome), CoreError>
    where
        B: 'static,
    {
        let record = self.get_service(name)?;
        validate_service_instance_names(name, desired_instances)?;
        if let Some(ref volume) = record.volume
            && desired_instances > 1
        {
            return Err(CoreError::InvalidArgument(format!(
                "cannot scale service '{name}' to {desired_instances} instances with volume \
                 '{volume}': volumes are exclusive-attach, so a volume-backed service is \
                 limited to 1 instance",
            )));
        }
        self.state
            .update_service_desired_instances(record.id, desired_instances)
            .map_err(|e| match e {
                husker_state::StateError::ServiceNotFound(_) => {
                    CoreError::ServiceNotFound(name.into())
                }
                other => CoreError::State(other),
            })?;
        let record = self.get_service(name)?;
        let outcome = self.reconcile_service(&record).await;
        Ok((record, outcome))
    }

    /// Destroy all instances, then delete the service row.
    ///
    /// If any instance fails to destroy, the row is retained and the error returned.
    pub async fn delete_service(
        self: &std::sync::Arc<Self>,
        name: &str,
    ) -> Result<ReconcileOutcome, CoreError>
    where
        B: 'static,
    {
        let mut record = self.get_service(name)?;
        record.desired_instances = 0;
        let outcome = self.reconcile_service(&record).await;
        if !outcome.failed.is_empty() {
            let (inst, err) = &outcome.failed[0];
            return Err(CoreError::ServiceOperationFailed(format!(
                "cannot delete service '{name}': instance {inst} cleanup failed: {err}"
            )));
        }
        self.state.delete_service(record.id).map_err(|e| match e {
            husker_state::StateError::ServiceNotFound(_) => CoreError::ServiceNotFound(name.into()),
            other => CoreError::State(other),
        })?;
        Ok(outcome)
    }

    // ── Hot pools ─────────────────────────────────────────────────────

    /// Create a hot pool: boot a template VM from the base image, wait for its
    /// guest agent, suspend it to disk, and record the pool. `run`/`job --pool
    /// <name>` then fork this template into fresh, isolated VMs in sub-second.
    ///
    /// The template is a normal (suspended) VM named after the pool. Firecracker
    /// only (suspend needs full-state snapshot support). On any failure after the
    /// template is created it is destroyed, so the pool name is free again.
    pub async fn create_pool(&self, req: CreatePoolRequest) -> Result<PoolRecord, CoreError> {
        validate_resource_name("pool", &req.name)?;
        if self.state.get_pool_by_name(&req.name).is_ok() {
            return Err(CoreError::PoolAlreadyExists(req.name.clone()));
        }

        let template = self
            .create_vm(CreateVmRequest {
                name: req.name.clone(),
                kernel_path: req.kernel_path.clone(),
                rootfs_path: req.rootfs_path.clone(),
                vcpu_count: req.vcpu_count,
                mem_size_mib: req.mem_size_mib,
                initrd_path: req.initrd_path.clone(),
                userdata: None,
                env: Vec::new(),
                vmm: None,
                cloud_image: None,
                disk_size: None,
                ssh_authorized_keys: Vec::new(),
                balloon: false,
                volume: None,
                network: None,
                mounts: Vec::new(),
            })
            .await
            .map_err(|e| match e {
                CoreError::VmAlreadyExists(_) => CoreError::PoolAlreadyExists(req.name.clone()),
                other => other,
            })?;

        // Warm to agent-ready, then suspend = the pool template. Roll back the
        // half-built template on any failure so the pool name stays reusable.
        let warm_and_suspend = async {
            self.agent_connect_ready(&req.name, default_ready_timeout("direct"))
                .await?;
            self.suspend_vm(&req.name).await
        };
        if let Err(e) = warm_and_suspend.await {
            let _ = self.destroy_vm(&req.name).await;
            return Err(e);
        }

        let now = chrono::Utc::now();
        let record = PoolRecord {
            id: Uuid::new_v4(),
            name: req.name.clone(),
            template_vm_id: template.id,
            rootfs_path: template.rootfs_path.clone(),
            kernel_path: template.kernel_path.clone(),
            initrd_path: req
                .initrd_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            vcpu_count: req.vcpu_count,
            mem_size_mib: req.mem_size_mib,
            created_at: now,
            updated_at: now,
        };
        if let Err(e) = self.state.insert_pool(&record) {
            let _ = self.destroy_vm(&req.name).await;
            return Err(match e {
                husker_state::StateError::PoolAlreadyExists(_) => {
                    CoreError::PoolAlreadyExists(req.name.clone())
                }
                other => CoreError::State(other),
            });
        }
        info!(pool = %req.name, "hot pool created");
        Ok(record)
    }

    /// List all hot pools.
    pub fn list_pools(&self) -> Result<Vec<PoolRecord>, CoreError> {
        Ok(self.state.list_pools()?)
    }

    /// Get a hot pool by name.
    pub fn get_pool(&self, name: &str) -> Result<PoolRecord, CoreError> {
        self.state.get_pool_by_name(name).map_err(|e| match e {
            husker_state::StateError::PoolNotFoundByName(_) => CoreError::PoolNotFound(name.into()),
            other => CoreError::State(other),
        })
    }

    /// Check a fresh VM out of a pool: fork the suspended template into a new,
    /// isolated VM with its own identity (CoW rootfs, fresh IP/CID/MAC), in
    /// sub-second. The template stays suspended and reusable. Firecracker only.
    pub async fn checkout_pool(
        &self,
        pool_name: &str,
        vm_name: Option<&str>,
    ) -> Result<VmRecord, CoreError> {
        // Surface a clear pool-not-found before touching the template.
        self.get_pool(pool_name)?;
        // Default the member name to "<pool>-<short id>" when unspecified.
        let generated;
        let name = match vm_name {
            Some(n) => n,
            None => {
                let suffix = Uuid::new_v4().simple().to_string();
                generated = format!("{pool_name}-{}", &suffix[..8]);
                &generated
            }
        };
        // The template VM is named after the pool; fork it into a fresh VM.
        self.fork_vm(pool_name, name).await
    }

    /// Delete a hot pool: destroy its template VM, then remove the record.
    pub async fn delete_pool(&self, name: &str) -> Result<(), CoreError> {
        self.get_pool(name)?;
        match self.destroy_vm(name).await {
            Ok(()) => {}
            Err(CoreError::VmNotFound(_)) => {}
            Err(e) => return Err(e),
        }
        self.state.delete_pool_by_name(name).map_err(|e| match e {
            husker_state::StateError::PoolNotFoundByName(_) => CoreError::PoolNotFound(name.into()),
            other => CoreError::State(other),
        })?;
        info!(pool = %name, "hot pool deleted");
        Ok(())
    }

    /// Create a snapshot from a stopped VM.
    pub async fn create_snapshot(
        &self,
        req: CreateSnapshotRequest,
    ) -> Result<SnapshotRecord, CoreError> {
        validate_resource_name("snapshot", &req.name)?;
        let vm = self.lookup_vm(&req.vm)?;
        if vm.state != "stopped" {
            return Err(CoreError::InvalidState {
                name: vm.name,
                actual: vm.state,
                expected: "stopped".into(),
            });
        }

        let source_rootfs = self.storage.vm_dir(&req.vm).join("rootfs.ext4");
        let snapshots_dir = self.storage.images_dir().join("snapshots");
        tokio::fs::create_dir_all(&snapshots_dir)
            .await
            .map_err(husker_storage::StorageError::Io)?;

        let snapshot_path = snapshots_dir.join(format!("{}.ext4", req.name));
        self.storage_driver
            .clone_rootfs(&source_rootfs, &snapshot_path)
            .await?;

        let record = SnapshotRecord {
            id: Uuid::new_v4(),
            name: req.name.clone(),
            source_vm_name: req.vm,
            file_path: snapshot_path.to_string_lossy().into_owned(),
            created_at: chrono::Utc::now(),
        };

        if let Err(err) = self.state.insert_snapshot(&record).map_err(|e| match e {
            husker_state::StateError::SnapshotAlreadyExists(name) => {
                CoreError::SnapshotAlreadyExists(name)
            }
            other => CoreError::State(other),
        }) {
            let _ = tokio::fs::remove_file(&snapshot_path).await;
            return Err(err);
        }

        Ok(record)
    }

    /// List all snapshots.
    pub fn list_snapshots(&self) -> Result<Vec<SnapshotRecord>, CoreError> {
        Ok(self.state.list_snapshots()?)
    }

    /// Get a snapshot by name.
    pub fn get_snapshot(&self, name: &str) -> Result<SnapshotRecord, CoreError> {
        self.state.get_snapshot_by_name(name).map_err(|e| match e {
            husker_state::StateError::SnapshotNotFoundByName(_) => {
                CoreError::SnapshotNotFound(name.into())
            }
            other => CoreError::State(other),
        })
    }

    /// Delete a snapshot by name.
    pub async fn delete_snapshot(&self, name: &str) -> Result<(), CoreError> {
        let snapshot = self.get_snapshot(name)?;
        match tokio::fs::remove_file(&snapshot.file_path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(CoreError::Storage(husker_storage::StorageError::Io(e))),
        }

        self.state
            .delete_snapshot(snapshot.id)
            .map_err(|e| match e {
                husker_state::StateError::SnapshotNotFound(_) => {
                    CoreError::SnapshotNotFound(name.into())
                }
                other => CoreError::State(other),
            })
    }

    /// Restore a snapshot into a new VM.
    pub async fn restore_snapshot(
        &self,
        snapshot_name: &str,
        req: RestoreSnapshotRequest,
    ) -> Result<VmRecord, CoreError> {
        validate_resource_name("vm", &req.name)?;
        let snapshot = self.get_snapshot(snapshot_name)?;
        self.create_vm(CreateVmRequest {
            name: req.name,
            kernel_path: Some(req.kernel_path),
            rootfs_path: Some(PathBuf::from(snapshot.file_path)),
            vcpu_count: req.vcpu_count,
            mem_size_mib: req.mem_size_mib,
            initrd_path: req.initrd_path,
            userdata: req.userdata,
            env: req.env,
            vmm: None,
            cloud_image: None,
            disk_size: None,
            ssh_authorized_keys: Vec::new(),
            balloon: false,
            volume: None,
            network: None,
            mounts: Vec::new(),
        })
        .await
    }

    /// Import an image into the managed image catalog.
    pub async fn import_image(&self, req: ImportImageRequest) -> Result<ImageRecord, CoreError> {
        validate_resource_name("image", &req.name)?;
        validate_host_path("import source", &req.source_path)?;
        let kind = validate_image_kind(req.kind.as_deref())?;
        match self.state.get_image_by_name(&req.name) {
            Ok(_) => return Err(CoreError::ImageAlreadyExists(req.name)),
            Err(husker_state::StateError::ImageNotFoundByName(_)) => {}
            Err(other) => return Err(CoreError::State(other)),
        }

        if kind == "cloud-image" {
            husker_storage::validate_cloud_image(&req.source_path)?;
        } else {
            husker_storage::validate_rootfs(&req.source_path)?;
        }

        let catalog_dir = self.storage.images_dir().join("catalog");
        tokio::fs::create_dir_all(&catalog_dir)
            .await
            .map_err(husker_storage::StorageError::Io)?;

        let extension = req
            .source_path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("ext4");
        let image_path = catalog_dir.join(format!("{}.{}", req.name, extension));
        self.storage_driver
            .clone_rootfs(&req.source_path, &image_path)
            .await?;

        let metadata = tokio::fs::metadata(&image_path)
            .await
            .map_err(husker_storage::StorageError::Io)?;
        let format = if kind == "cloud-image" && req.format.is_none() {
            "qcow2".to_string()
        } else {
            req.format
                .unwrap_or_else(|| infer_image_format(&req.source_path))
        };
        let record = ImageRecord {
            id: Uuid::new_v4(),
            name: req.name.clone(),
            source_path: req.source_path.to_string_lossy().into_owned(),
            file_path: image_path.to_string_lossy().into_owned(),
            format,
            kind,
            boot_init: None,
            size_bytes: metadata.len(),
            created_at: chrono::Utc::now(),
        };

        if let Err(err) = self.state.insert_image(&record).map_err(|e| match e {
            husker_state::StateError::ImageAlreadyExists(name) => {
                CoreError::ImageAlreadyExists(name)
            }
            other => CoreError::State(other),
        }) {
            let _ = tokio::fs::remove_file(&image_path).await;
            return Err(err);
        }

        Ok(record)
    }

    /// Build a husker rootfs image from an OCI/Docker image and register it.
    ///
    /// Pulls the image, flattens its layers, injects the husker agent + guest
    /// runtime so the rootfs boots into the agent, builds an ext4 image, and
    /// registers it in the catalog as a `rootfs` image runnable with `husker run`.
    /// v1 targets busybox-init images (e.g. alpine); the host must have
    /// `mkfs.ext4` and the daemon must embed the guest agent.
    #[cfg(feature = "linux-net")]
    pub async fn import_oci_image(
        &self,
        name: &str,
        reference: &str,
    ) -> Result<ImageRecord, CoreError> {
        validate_resource_name("image", name)?;
        if self.embedded_agent.is_empty() {
            return Err(CoreError::InvalidArgument(
                "OCI import needs the embedded guest agent; build the daemon with \
                 `make build-agent` (or set HUSKER_EMBED_AGENT_BIN) first"
                    .into(),
            ));
        }
        match self.state.get_image_by_name(name) {
            Ok(_) => return Err(CoreError::ImageAlreadyExists(name.into())),
            Err(husker_state::StateError::ImageNotFoundByName(_)) => {}
            Err(other) => return Err(CoreError::State(other)),
        }

        let arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => {
                return Err(CoreError::InvalidArgument(format!(
                    "unsupported host architecture for OCI import: {other}"
                )));
            }
        };

        // Pull + flatten into a temp dir, then inject the guest runtime. The
        // image's runtime config (env/PATH/WorkingDir) is captured and written
        // into the rootfs so the agent applies it on exec.
        let work = tempfile::tempdir().map_err(|e| CoreError::Io(format!("oci work dir: {e}")))?;
        let rootfs_dir = work.path().join("rootfs");
        let image_config = husker_oci::pull_and_flatten(reference, arch, &rootfs_dir)
            .await
            .map_err(|e| CoreError::InvalidArgument(format!("pull {reference}: {e}")))?;
        let oci_runtime = husker_agent_proto::OciRuntimeConfig {
            env: image_config.env,
            working_dir: image_config.working_dir,
            entrypoint: image_config.entrypoint,
            cmd: image_config.cmd,
        };
        inject_guest_runtime(&rootfs_dir, self.embedded_agent, &oci_runtime)?;

        // Build the ext4 image sized to the tree plus generous overhead.
        let catalog_dir = self.storage.images_dir().join("catalog");
        tokio::fs::create_dir_all(&catalog_dir)
            .await
            .map_err(husker_storage::StorageError::Io)?;
        let image_path = catalog_dir.join(format!("{name}.ext4"));
        let tree_size = {
            let d = rootfs_dir.clone();
            tokio::task::spawn_blocking(move || husker_storage::dir_apparent_size(&d))
                .await
                .map_err(|e| CoreError::Io(format!("size join: {e}")))?
        };
        // Bound disk use: refuse images whose extracted tree is implausibly large
        // (a decompression-bomb guard on top of the compressed-download cap).
        const MAX_ROOTFS_BYTES: u64 = 8 * 1024 * 1024 * 1024;
        if tree_size > MAX_ROOTFS_BYTES {
            return Err(CoreError::InvalidArgument(format!(
                "imported rootfs is {tree_size} bytes, over the {MAX_ROOTFS_BYTES}-byte limit"
            )));
        }
        let size_bytes = (tree_size * 2).max(128 * 1024 * 1024) + 64 * 1024 * 1024;
        husker_storage::build_ext4_from_dir(&rootfs_dir, &image_path, size_bytes).await?;

        let metadata = tokio::fs::metadata(&image_path)
            .await
            .map_err(husker_storage::StorageError::Io)?;
        let record = ImageRecord {
            id: Uuid::new_v4(),
            name: name.into(),
            source_path: format!("oci://{reference}"),
            file_path: image_path.to_string_lossy().into_owned(),
            format: "ext4".into(),
            kind: "rootfs".into(),
            // Boot imported OCI images via the guest agent as PID 1 (the agent
            // supervisor does mounts/network/reaping), since they carry no
            // busybox init. The injected agent lives at this path.
            boot_init: Some("/usr/local/bin/husker-agent".to_string()),
            size_bytes: metadata.len(),
            created_at: chrono::Utc::now(),
        };
        if let Err(err) = self.state.insert_image(&record).map_err(|e| match e {
            husker_state::StateError::ImageAlreadyExists(n) => CoreError::ImageAlreadyExists(n),
            other => CoreError::State(other),
        }) {
            let _ = tokio::fs::remove_file(&image_path).await;
            return Err(err);
        }
        Ok(record)
    }

    /// OCI import is Linux-only (needs `mkfs.ext4`); the macOS build rejects it.
    #[cfg(not(feature = "linux-net"))]
    pub async fn import_oci_image(
        &self,
        _name: &str,
        _reference: &str,
    ) -> Result<ImageRecord, CoreError> {
        Err(CoreError::Vmm(husker_vmm::VmmError::Unsupported(
            "OCI image import is only supported on Linux".into(),
        )))
    }

    /// List all catalog images.
    pub fn list_images(&self) -> Result<Vec<ImageRecord>, CoreError> {
        Ok(self.state.list_images()?)
    }

    /// Get a catalog image by name.
    pub fn get_image(&self, name: &str) -> Result<ImageRecord, CoreError> {
        self.state.get_image_by_name(name).map_err(|e| match e {
            husker_state::StateError::ImageNotFoundByName(_) => {
                CoreError::ImageNotFound(name.into())
            }
            other => CoreError::State(other),
        })
    }

    /// Export a catalog image to a destination path.
    pub async fn export_image(
        &self,
        name: &str,
        req: ExportImageRequest,
    ) -> Result<ExportImageResult, CoreError> {
        validate_host_path("export destination", &req.destination_path)?;
        let image = self.get_image(name)?;
        self.storage_driver
            .clone_rootfs(Path::new(&image.file_path), &req.destination_path)
            .await?;
        let metadata = tokio::fs::metadata(&req.destination_path)
            .await
            .map_err(husker_storage::StorageError::Io)?;

        Ok(ExportImageResult {
            name: image.name,
            destination_path: req.destination_path,
            size_bytes: metadata.len(),
        })
    }

    /// Delete a catalog image by name.
    pub async fn delete_image(&self, name: &str) -> Result<(), CoreError> {
        let image = self.get_image(name)?;
        match tokio::fs::remove_file(&image.file_path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(CoreError::Storage(husker_storage::StorageError::Io(e))),
        }

        self.state.delete_image(image.id).map_err(|e| match e {
            husker_state::StateError::ImageNotFound(_) => CoreError::ImageNotFound(name.into()),
            other => CoreError::State(other),
        })
    }

    /// Create a new encrypted secret.
    pub fn create_secret(&self, req: CreateSecretRequest) -> Result<SecretMetadata, CoreError> {
        validate_resource_name("secret", &req.name)?;

        let key = load_or_create_secret_key(&self.storage.data_dir)?;
        let (ciphertext, nonce) = encrypt_secret(&key, req.value.as_bytes())?;
        let now = chrono::Utc::now();
        let record = SecretRecord {
            id: Uuid::new_v4(),
            name: req.name,
            ciphertext,
            nonce,
            created_at: now,
            updated_at: now,
        };

        self.state.insert_secret(&record).map_err(|e| match e {
            husker_state::StateError::SecretAlreadyExists(name) => {
                CoreError::SecretAlreadyExists(name)
            }
            other => CoreError::State(other),
        })?;

        Ok(secret_to_metadata(record))
    }

    /// List secret metadata (never includes plaintext values).
    pub fn list_secrets(&self) -> Result<Vec<SecretMetadata>, CoreError> {
        Ok(self
            .state
            .list_secrets()?
            .into_iter()
            .map(secret_to_metadata)
            .collect())
    }

    /// Get metadata for a secret by name.
    pub fn get_secret(&self, name: &str) -> Result<SecretMetadata, CoreError> {
        let record = self.state.get_secret_by_name(name).map_err(|e| match e {
            husker_state::StateError::SecretNotFoundByName(_) => {
                CoreError::SecretNotFound(name.into())
            }
            other => CoreError::State(other),
        })?;
        Ok(secret_to_metadata(record))
    }

    /// Reveal decrypted plaintext for a secret by name.
    pub fn reveal_secret(&self, name: &str) -> Result<RevealedSecret, CoreError> {
        let record = self.state.get_secret_by_name(name).map_err(|e| match e {
            husker_state::StateError::SecretNotFoundByName(_) => {
                CoreError::SecretNotFound(name.into())
            }
            other => CoreError::State(other),
        })?;
        let key = load_or_create_secret_key(&self.storage.data_dir)?;
        let plaintext = decrypt_secret(&key, &record.nonce, &record.ciphertext)?;
        let value = String::from_utf8(plaintext)
            .map_err(|e| CoreError::SecretCrypto(format!("secret is not valid UTF-8: {e}")))?;

        Ok(RevealedSecret {
            name: record.name,
            value,
            updated_at: record.updated_at,
        })
    }

    /// Rotate (replace) the value of an existing secret.
    pub fn rotate_secret(
        &self,
        name: &str,
        req: RotateSecretRequest,
    ) -> Result<SecretMetadata, CoreError> {
        let existing = self.state.get_secret_by_name(name).map_err(|e| match e {
            husker_state::StateError::SecretNotFoundByName(_) => {
                CoreError::SecretNotFound(name.into())
            }
            other => CoreError::State(other),
        })?;
        let key = load_or_create_secret_key(&self.storage.data_dir)?;
        let (ciphertext, nonce) = encrypt_secret(&key, req.value.as_bytes())?;
        self.state
            .update_secret_payload(existing.id, &ciphertext, &nonce)
            .map_err(|e| match e {
                husker_state::StateError::SecretNotFound(_) => {
                    CoreError::SecretNotFound(name.into())
                }
                other => CoreError::State(other),
            })?;
        self.get_secret(name)
    }

    /// Delete a secret by name.
    pub fn delete_secret(&self, name: &str) -> Result<(), CoreError> {
        let secret = self.state.get_secret_by_name(name).map_err(|e| match e {
            husker_state::StateError::SecretNotFoundByName(_) => {
                CoreError::SecretNotFound(name.into())
            }
            other => CoreError::State(other),
        })?;
        self.state.delete_secret(secret.id).map_err(|e| match e {
            husker_state::StateError::SecretNotFound(_) => CoreError::SecretNotFound(name.into()),
            other => CoreError::State(other),
        })
    }

    /// Path to a VM's serial console log file.
    pub fn serial_log_path(&self, name: &str) -> Result<PathBuf, CoreError> {
        let record = self.lookup_vm(name)?;
        Ok(self.runtime_dir.join(format!("{}.serial.log", record.id)))
    }

    /// Path to the captured userdata stdout/stderr log for a VM. Written by
    /// `run_userdata` so the output of the userdata script is inspectable via
    /// `husker logs <name> --userdata` instead of being discarded.
    pub fn userdata_log_path(&self, name: &str) -> Result<PathBuf, CoreError> {
        let record = self.lookup_vm(name)?;
        Ok(self.runtime_dir.join(format!("{}.userdata.log", record.id)))
    }

    /// Path to a VM's backend process ("boot") log: QEMU's own stdout/stderr or
    /// Firecracker's process log, distinct from the guest serial console.
    pub fn boot_log_path(&self, name: &str) -> Result<PathBuf, CoreError> {
        let record = self.lookup_vm(name)?;
        Ok(self.runtime_dir.join(format!("{}.boot.log", record.id)))
    }

    /// Stop all running and paused VMs during daemon shutdown.
    ///
    /// Returns the number of VMs that were drained. Errors on individual VMs
    /// are logged but do not abort the drain.
    pub async fn drain_vms(&self) -> usize {
        let vms = match self.list_vms() {
            Ok(vms) => vms,
            Err(e) => {
                warn!(error = %e, "failed to list VMs for drain");
                return 0;
            }
        };

        let mut count = 0;
        for vm in vms {
            if vm.state != "running" && vm.state != "paused" {
                continue;
            }
            info!(name = %vm.name, state = %vm.state, "draining VM");
            if let Err(e) = self.vmm.stop_vm(vm.id).await {
                warn!(name = %vm.name, error = %e, "failed to stop VM during drain");
            }
            if let Err(e) = self.state.update_vm_state(vm.id, "stopped") {
                warn!(name = %vm.name, error = %e, "failed to update state during drain");
            }
            count += 1;
        }
        count
    }

    /// Rotate serial log files that exceed the size threshold.
    ///
    /// Scans `runtime_dir` for `*.serial.log` files larger than 10 MiB,
    /// keeps the last 5 MiB using the copy-truncate pattern (safe for
    /// Firecracker/VZ which hold the fd open).
    ///
    /// Returns the number of files rotated.
    pub async fn rotate_serial_logs(&self) -> usize {
        let entries = match std::fs::read_dir(&self.runtime_dir) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "failed to read runtime dir for log rotation");
                return 0;
            }
        };

        let mut rotated = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.ends_with(".serial.log") {
                continue;
            }

            let metadata = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };

            if metadata.len() <= LOG_ROTATE_THRESHOLD {
                continue;
            }

            match rotate_log_file(&path, LOG_ROTATE_KEEP).await {
                Ok(()) => {
                    info!(path = %path.display(), "rotated serial log");
                    rotated += 1;
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "failed to rotate serial log");
                }
            }
        }
        rotated
    }

    /// Connect to the guest agent for a running VM.
    ///
    /// Delegates vsock connection to the VMM backend, which handles the
    /// platform-specific protocol (Firecracker UDS+CONNECT, Apple VZ socket).
    pub async fn agent_connect(
        &self,
        name: &str,
    ) -> Result<AgentConnection<B::VsockStream>, CoreError> {
        let record = self.lookup_vm(name)?;
        if record.state != "running" {
            return Err(CoreError::InvalidState {
                name: name.into(),
                actual: record.state,
                expected: "running".into(),
            });
        }
        debug!(%name, id = %record.id, "connecting to agent via vsock");
        let stream = self
            .vmm
            .vsock_connect(record.id, husker_agent_proto::AGENT_VSOCK_PORT)
            .await?;
        Ok(AgentConnection::new(stream))
    }

    /// Connect to the guest agent, retrying transient failures with backoff.
    ///
    /// Callers that reach the agent immediately after VM boot (e.g. `exec`)
    /// race the agent bind. Use this helper instead of [`Self::agent_connect`]
    /// when the caller can tolerate a bounded wait.
    ///
    /// The wait is bounded to approximately `timeout` (the last attempt is
    /// allowed to finish). Retries only VMM/Agent connection errors (vsock
    /// CONNECT rejected, agent not responding). State errors (VM destroyed or
    /// stopped) fail immediately.
    pub async fn agent_connect_ready(
        &self,
        name: &str,
        timeout: std::time::Duration,
    ) -> Result<AgentConnection<B::VsockStream>, CoreError> {
        let mut backoff = std::time::Duration::from_millis(200);
        let max_backoff = std::time::Duration::from_secs(2);
        // Shrink the deadline by one attempt window so a final attempt that
        // starts just under the deadline cannot push total wall-clock beyond
        // approximately `timeout`.
        let deadline =
            tokio::time::Instant::now() + timeout.saturating_sub(AGENT_PING_ATTEMPT_TIMEOUT);
        loop {
            // Each attempt (connect + ping) is bounded so a guest that accepts
            // the vsock but never replies cannot exceed the overall deadline.
            let attempt = tokio::time::timeout(AGENT_PING_ATTEMPT_TIMEOUT, async {
                let mut conn = self.agent_connect(name).await?;
                conn.ping().await?;
                Ok::<_, CoreError>(conn)
            })
            .await;
            match attempt {
                Ok(Ok(conn)) => return Ok(conn),
                // State errors (VM stopped/destroyed) fail fast.
                Ok(Err(e)) if !matches!(e, CoreError::Vmm(_) | CoreError::Agent(_)) => {
                    return Err(e);
                }
                // Connection/agent errors are transient.
                Ok(Err(e)) => debug!(%name, error = %e, "agent not ready, retrying"),
                // A timed-out attempt is transient.
                Err(_) => debug!(%name, "agent ping attempt timed out, retrying"),
            }
            if tokio::time::Instant::now() + backoff >= deadline {
                return Err(CoreError::Agent(
                    crate::agent_client::AgentError::NotReady {
                        timeout,
                        detail: self.boot_failure_detail(name),
                    },
                ));
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(max_backoff);
        }
    }

    /// Diagnostic suffix for a boot/agent-readiness failure: the tail of the
    /// guest serial console plus a pointer to the full log. Appended to
    /// readiness errors so a failed boot is diagnosable from the error alone,
    /// instead of leaving the user to discover `husker logs` on their own.
    /// Returns an empty string if the VM record is gone (nothing to point at).
    fn boot_failure_detail(&self, name: &str) -> String {
        let Ok(path) = self.serial_log_path(name) else {
            return String::new();
        };
        match tail_last_lines(&path, BOOT_FAILURE_SERIAL_TAIL_LINES) {
            Some(tail) => {
                let module_hint = kernel_module_mismatch_hint(&tail)
                    .map(|h| format!("\nhint: {h}"))
                    .unwrap_or_default();
                format!(
                    "\n--- guest serial console (last {BOOT_FAILURE_SERIAL_TAIL_LINES} lines) ---\n{tail}\n\
                     hint: run `husker logs --source serial {name}` for the full guest console{module_hint}",
                )
            }
            None => format!(
                "\nhint: the guest serial console has no output yet; \
                 run `husker logs --source serial {name}` to inspect it",
            ),
        }
    }

    /// Single-attempt readiness probe (for the `/ready` endpoint): connect and
    /// ping once with a short timeout. `Ok(true)` if the agent ponged, `Ok(false)`
    /// if not yet reachable (or timed out), and `Err` for state errors (VM
    /// stopped/destroyed) so callers can distinguish "not up yet" from "gone".
    pub async fn probe_ready(&self, name: &str) -> Result<bool, CoreError> {
        let attempt = tokio::time::timeout(AGENT_PING_ATTEMPT_TIMEOUT, async {
            let mut conn = self.agent_connect(name).await?;
            conn.ping().await?;
            Ok::<_, CoreError>(())
        })
        .await;
        match attempt {
            Ok(Ok(())) => Ok(true),
            Ok(Err(CoreError::Vmm(_) | CoreError::Agent(_))) => Ok(false),
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(false),
        }
    }

    /// Execute the userdata script inside a running VM.
    ///
    /// Retries agent connection with exponential backoff (bounded by the
    /// boot-mode-aware default readiness timeout), writes the script to
    /// `/tmp/husker-userdata.sh`, executes it via `sh`, and updates
    /// `userdata_status` to `completed` or `failed`.
    pub async fn run_userdata(&self, name: &str) -> Result<(), CoreError> {
        let record = self.lookup_vm(name)?;
        let script = match record.userdata {
            Some(ref s) => s.clone(),
            None => return Ok(()),
        };

        self.state.update_userdata_status(record.id, "running")?;

        let result: Result<(), CoreError> = async {
            let mut conn = self
                .agent_connect_ready(name, default_ready_timeout(&record.boot_mode))
                .await?;

            conn.write_file("/tmp/husker-userdata.sh", script.as_bytes(), Some(0o755))
                .await?;

            let env_pairs: Vec<(String, String)> = record
                .userdata_env
                .as_deref()
                .map(|s| serde_json::from_str(s).unwrap_or_default())
                .unwrap_or_default();
            let env_refs: Vec<(&str, &str)> = env_pairs
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();

            let exec_result = conn
                .exec("sh", &["/tmp/husker-userdata.sh"], None, &env_refs)
                .await?;

            // Persist the script's output so it is inspectable after the fact
            // via `husker logs <name> --userdata`, rather than being discarded.
            let log_path = self
                .runtime_dir
                .join(format!("{}.userdata.log", record.id));
            let mut log = exec_result.stdout.clone();
            if !exec_result.stderr.is_empty() {
                if !log.is_empty() && !log.ends_with('\n') {
                    log.push('\n');
                }
                log.push_str("[stderr]\n");
                log.push_str(&exec_result.stderr);
            }
            if let Err(e) = tokio::fs::write(&log_path, log).await {
                warn!(%name, path = %log_path.display(), error = %e, "failed to write userdata log");
            }

            if exec_result.exit_code == 0 {
                self.state.update_userdata_status(record.id, "completed")?;
            } else {
                warn!(
                    %name,
                    exit_code = exec_result.exit_code,
                    stderr = %exec_result.stderr,
                    "userdata script failed"
                );
                self.state.update_userdata_status(record.id, "failed")?;
            }
            Ok(())
        }
        .await;

        if let Err(ref e) = result {
            warn!(%name, error = %e, "userdata execution error");
            if let Err(status_err) = self.state.update_userdata_status(record.id, "failed") {
                warn!(%name, error = %status_err, "failed to update userdata status to failed");
            }
        }

        result
    }

    /// Spawn background userdata execution for a freshly created VM, if it has any.
    /// Fire-and-forget: returns immediately; `run_userdata` updates `userdata_status`.
    pub fn spawn_userdata(self: &Arc<Self>, record: &VmRecord)
    where
        B: 'static,
    {
        if record.userdata.is_none() {
            return;
        }
        let core = Arc::clone(self);
        let name = record.name.clone();
        tokio::spawn(async move {
            if let Err(e) = core.run_userdata(&name).await {
                warn!(%name, error = %e, "userdata execution failed");
            }
        });
    }

    /// Add a port forward from a host port to a guest port on a VM.
    #[cfg(feature = "linux-net")]
    pub async fn add_port_forward(
        &self,
        name: &str,
        host_port: u16,
        guest_port: u16,
        bind_addr: Option<std::net::IpAddr>,
    ) -> Result<husker_state::PortForwardRecord, CoreError> {
        let record = self.lookup_vm(name)?;

        // Bridged VMs are directly on the LAN; NAT port-forwarding does not apply to them.
        if record.network == "bridged" {
            return Err(CoreError::InvalidArgument(format!(
                "VM '{name}' uses bridged networking and is directly on the LAN; \
                 port forwards apply to NAT VMs only"
            )));
        }

        // The Linux nftables backend exposes forwards on all host interfaces; a
        // specific bind address is not supported here.
        if let Some(addr) = bind_addr
            && !addr.is_unspecified()
        {
            return Err(CoreError::InvalidArgument(format!(
                "--bind {addr} is not supported on the Linux nftables backend; \
                 forwards are reachable on all host interfaces"
            )));
        }

        let guest_ip: std::net::Ipv4Addr = record
            .guest_ip
            .as_deref()
            .ok_or_else(|| CoreError::VmNotFound(format!("{name}: no guest IP")))?
            .parse()
            .map_err(|_| CoreError::VmNotFound(format!("{name}: invalid guest IP")))?;
        let tap_name = record
            .tap_device
            .as_deref()
            .ok_or_else(|| CoreError::VmNotFound(format!("{name}: no TAP device")))?;

        // Idempotent behavior: if this exact forward already exists on this VM,
        // treat it as success.
        if let Ok(existing) = self.state.list_port_forwards_for_vm(record.id)
            && let Some(found) = existing
                .iter()
                .find(|pf| pf.host_port == host_port && pf.guest_port == guest_port)
        {
            info!(%name, host_port, guest_port, "port forward already present (no-op)");
            return Ok(found.clone());
        }

        husker_net::add_port_forward(host_port, guest_ip, guest_port, tap_name, &self.bridge_name)
            .await?;

        let pf_record = husker_state::PortForwardRecord {
            id: 0,
            vm_id: record.id,
            host_port,
            guest_port,
            protocol: "tcp".into(),
            bind_addr: None,
            created_at: chrono::Utc::now(),
        };
        if let Err(e) = self
            .state
            .insert_port_forward(&pf_record)
            .map_err(|e| match e {
                husker_state::StateError::PortAlreadyForwarded(port) => {
                    CoreError::PortForwardConflict(port)
                }
                other => CoreError::State(other),
            })
        {
            if let Err(rollback_err) =
                husker_net::remove_port_forward(host_port, tap_name, &self.bridge_name).await
            {
                warn!(
                    %name,
                    host_port,
                    tap = tap_name,
                    error = %rollback_err,
                    "failed to rollback nftables rule after state insert error"
                );
            }
            return Err(e);
        }

        info!(%name, host_port, guest_port, "port forward added");
        Ok(pf_record)
    }

    /// Remove a port forward.
    #[cfg(feature = "linux-net")]
    pub async fn remove_port_forward(&self, name: &str, host_port: u16) -> Result<(), CoreError> {
        let record = self.lookup_vm(name)?;
        let tap_name = record
            .tap_device
            .as_deref()
            .ok_or_else(|| CoreError::VmNotFound(format!("{name}: no TAP device")))?;

        husker_net::remove_port_forward(host_port, tap_name, &self.bridge_name).await?;
        self.state.delete_port_forward(host_port)?;

        info!(%name, host_port, "port forward removed");
        Ok(())
    }

    /// Add a port forward via the userspace proxy (macOS).
    ///
    /// Binds a host TCP listener and relays accepted connections to the guest.
    /// The forward is bound to the running VM instance; it is torn down on stop
    /// or destroy and does not survive a daemon restart.
    #[cfg(not(feature = "linux-net"))]
    pub async fn add_port_forward(
        &self,
        name: &str,
        host_port: u16,
        guest_port: u16,
        bind_addr: Option<std::net::IpAddr>,
    ) -> Result<husker_state::PortForwardRecord, CoreError> {
        let _guard = self.vm_name_lock(name).lock_owned().await;
        let record = self.lookup_vm(name)?;
        if record.state != "running" {
            return Err(CoreError::InvalidState {
                name: name.into(),
                actual: record.state,
                expected: "running".into(),
            });
        }
        let guest_ip: std::net::Ipv4Addr = record
            .guest_ip
            .as_deref()
            .ok_or_else(|| CoreError::InvalidState {
                name: name.into(),
                actual: "running without a discovered guest IP".into(),
                expected: "running with a guest IP".into(),
            })?
            .parse()
            .map_err(|_| CoreError::InvalidArgument(format!("{name}: invalid guest IP")))?;

        let bind = bind_addr.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let bind_str = bind.to_string();

        // Idempotent only when host port, guest port, AND bind address all match
        // an existing forward. A re-add with a different bind on the same host
        // port falls through and is rejected as a conflict by the bind below.
        if let Ok(existing) = self.state.list_port_forwards_for_vm(record.id)
            && let Some(found) = existing.iter().find(|pf| {
                pf.host_port == host_port
                    && pf.guest_port == guest_port
                    && pf.bind_addr.as_deref() == Some(bind_str.as_str())
            })
        {
            return Ok(found.clone());
        }

        let bound = self
            .port_proxy
            .add(record.id, bind, host_port, guest_ip, guest_port)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::AddrInUse => CoreError::PortForwardConflict(host_port),
                std::io::ErrorKind::PermissionDenied => CoreError::PortForwardDenied(host_port),
                _ => CoreError::Io(e.to_string()),
            })?;

        let pf_record = husker_state::PortForwardRecord {
            id: 0,
            vm_id: record.id,
            host_port: bound,
            guest_port,
            protocol: "tcp".into(),
            bind_addr: Some(bind_str),
            created_at: chrono::Utc::now(),
        };
        if let Err(e) = self
            .state
            .insert_port_forward(&pf_record)
            .map_err(|e| match e {
                husker_state::StateError::PortAlreadyForwarded(_) => {
                    CoreError::PortForwardConflict(bound)
                }
                other => CoreError::State(other),
            })
        {
            self.port_proxy.stop(record.id, bound);
            return Err(e);
        }
        info!(%name, host_port = bound, guest_port, "port forward added (userspace proxy)");
        Ok(pf_record)
    }

    /// Remove a port forward (macOS userspace proxy).
    #[cfg(not(feature = "linux-net"))]
    pub async fn remove_port_forward(&self, name: &str, host_port: u16) -> Result<(), CoreError> {
        let _guard = self.vm_name_lock(name).lock_owned().await;
        let record = self.lookup_vm(name)?;
        // Only remove a forward that belongs to this VM. `delete_port_forward`
        // keys on host_port globally, so an unscoped delete could drop another
        // VM's row and orphan its listener. No-op (idempotent) otherwise.
        let owned = self
            .state
            .list_port_forwards_for_vm(record.id)?
            .iter()
            .any(|pf| pf.host_port == host_port);
        if owned {
            self.port_proxy.stop(record.id, host_port);
            self.state.delete_port_forward(host_port)?;
            info!(%name, host_port, "port forward removed (userspace proxy)");
        }
        Ok(())
    }

    /// List port forwards for a VM.
    pub fn list_port_forwards(
        &self,
        name: &str,
    ) -> Result<Vec<husker_state::PortForwardRecord>, CoreError> {
        let record = self.lookup_vm(name)?;
        Ok(self.state.list_port_forwards_for_vm(record.id)?)
    }

    /// Rebuild nftables port-forward rules from persisted state on startup.
    ///
    /// This closes drift after daemon restarts because `init_nat` recreates the
    /// nftables table while port-forward records remain in SQLite.
    #[cfg(feature = "linux-net")]
    pub async fn reconcile_port_forwards_from_state(&self) -> usize {
        let vms = match self.state.list_vms() {
            Ok(vms) => vms,
            Err(e) => {
                warn!(error = %e, "failed to list VMs for port-forward reconciliation");
                return 0;
            }
        };

        let mut restored = 0usize;
        for vm in vms {
            let Some(guest_ip_str) = vm.guest_ip.as_deref() else {
                continue;
            };
            let Some(tap_name) = vm.tap_device.as_deref() else {
                continue;
            };
            let guest_ip: Ipv4Addr = match guest_ip_str.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    warn!(name = %vm.name, guest_ip = %guest_ip_str, "skipping invalid guest IP during reconciliation");
                    continue;
                }
            };

            let forwards = match self.state.list_port_forwards_for_vm(vm.id) {
                Ok(f) => f,
                Err(e) => {
                    warn!(name = %vm.name, error = %e, "failed to list port forwards during reconciliation");
                    continue;
                }
            };

            for pf in forwards {
                match husker_net::add_port_forward(
                    pf.host_port,
                    guest_ip,
                    pf.guest_port,
                    tap_name,
                    &self.bridge_name,
                )
                .await
                {
                    Ok(()) => {
                        restored += 1;
                    }
                    Err(e) => {
                        warn!(
                            name = %vm.name,
                            tap = tap_name,
                            host_port = pf.host_port,
                            guest_port = pf.guest_port,
                            error = %e,
                            "failed to restore port-forward rule"
                        );
                    }
                }
            }
        }
        restored
    }

    /// List VMs owned by a service (core wrapper over state).
    pub fn list_vms_for_service(&self, service_id: Uuid) -> Result<Vec<VmRecord>, CoreError> {
        Ok(self.state.list_vms_for_service(service_id)?)
    }

    /// Create the partial unique index for service ordinals (core wrapper over state).
    pub fn create_service_ordinal_index(&self) -> Result<(), CoreError> {
        Ok(self.state.create_service_ordinal_index()?)
    }

    /// Converge a service's running instances to `desired_instances`.
    /// Target: ordinals 0..desired-1 each backed by exactly one `running` VM.
    pub async fn reconcile_service(self: &Arc<Self>, svc: &ServiceRecord) -> ReconcileOutcome
    where
        B: 'static,
    {
        let _guard = self.reconcile_lock(svc.id).lock_owned().await;
        let mut outcome = ReconcileOutcome::default();

        if svc.rootfs_path.is_empty() && svc.cloud_image.is_none() {
            outcome
                .failed
                .push((svc.name.clone(), "service has no rootfs template".into()));
            return outcome;
        }

        let instances = match self.state.list_vms_for_service(svc.id) {
            Ok(v) => v,
            Err(e) => {
                outcome.failed.push((svc.name.clone(), e.to_string()));
                return outcome;
            }
        };

        // Dedupe: one survivor per ordinal (BTreeMap = deterministic ascending order),
        // destroy the rest + any NULL-ordinal orphans.
        let mut by_ordinal: std::collections::BTreeMap<u32, VmRecord> =
            std::collections::BTreeMap::new();
        for vm in instances {
            let vm = self.refresh_vm_liveness(&vm).await;
            let Some(ord) = vm.service_ordinal else {
                let _ = self.destroy_instance(&vm, &mut outcome).await; // orphan
                continue;
            };
            match by_ordinal.get(&ord) {
                None => {
                    by_ordinal.insert(ord, vm);
                }
                Some(existing) => {
                    if better_survivor(&vm, existing) {
                        let loser = by_ordinal.insert(ord, vm).expect("ordinal present");
                        let _ = self.destroy_instance(&loser, &mut outcome).await;
                    } else {
                        let _ = self.destroy_instance(&vm, &mut outcome).await;
                    }
                }
            }
        }

        // Ordinals 0..desired-1: ensure each is a single running instance.
        for ordinal in 0..svc.desired_instances {
            match by_ordinal.get(&ordinal) {
                Some(vm) if vm.state == "running" => {}
                Some(vm) => {
                    let vm = vm.clone();
                    if self.destroy_instance(&vm, &mut outcome).await {
                        self.create_instance(svc, ordinal, &mut outcome).await;
                    }
                }
                None => self.create_instance(svc, ordinal, &mut outcome).await,
            }
        }

        // Scale-down: destroy survivors with ordinal >= desired (ascending, deterministic).
        let excess: Vec<VmRecord> = by_ordinal
            .into_iter()
            .filter(|(ord, _)| *ord >= svc.desired_instances)
            .map(|(_, vm)| vm)
            .collect();
        for vm in excess {
            let _ = self.destroy_instance(&vm, &mut outcome).await;
        }

        outcome
    }

    async fn create_instance(
        self: &Arc<Self>,
        svc: &ServiceRecord,
        ordinal: u32,
        outcome: &mut ReconcileOutcome,
    ) where
        B: 'static,
    {
        let name = instance_name(&svc.name, ordinal);

        // Ownership preflight: never clobber a VM not owned by this service.
        if let Ok(existing) = self.state.get_vm_by_name(&name)
            && existing.service_id != Some(svc.id)
        {
            outcome
                .failed
                .push((name, "name owned by a non-service VM".into()));
            return;
        }

        let req = instance_request(svc, &name);
        match self
            .create_vm_record(
                req,
                Some(ServiceTag {
                    service_id: svc.id,
                    ordinal,
                }),
                false,
            )
            .await
        {
            Ok(record) => {
                self.spawn_userdata(&record);
                outcome.created.push(name);
            }
            Err(e) => outcome.failed.push((name, e.to_string())),
        }
    }

    async fn destroy_instance(&self, vm: &VmRecord, outcome: &mut ReconcileOutcome) -> bool {
        let _name_guard = self.vm_name_lock(&vm.name).lock_owned().await;
        match self.destroy_vm_inner(vm).await {
            Ok(()) => {
                outcome.destroyed.push(vm.name.clone());
                true
            }
            Err(e) => {
                outcome.failed.push((vm.name.clone(), e.to_string()));
                false
            }
        }
    }

    fn lookup_vm(&self, name: &str) -> Result<VmRecord, CoreError> {
        self.state.get_vm_by_name(name).map_err(|e| match e {
            husker_state::StateError::VmNotFoundByName(_) => CoreError::VmNotFound(name.into()),
            other => CoreError::State(other),
        })
    }

    /// Resize a running VM's memory balloon (amount = MiB reclaimed from the guest).
    ///
    /// Fails immediately when the VM was not created with `--balloon` (the
    /// device is absent in the guest) or when the VM is not currently running.
    pub async fn set_balloon(&self, name: &str, amount_mib: u32) -> Result<(), CoreError> {
        let record = self.lookup_vm(name)?;
        if !record.balloon {
            return Err(CoreError::InvalidArgument(format!(
                "VM '{name}' was created without --balloon"
            )));
        }
        if record.state != "running" {
            return Err(CoreError::InvalidState {
                name: name.into(),
                actual: record.state,
                expected: "running".into(),
            });
        }
        self.vmm
            .set_balloon(record.id, amount_mib)
            .await
            .map_err(CoreError::Vmm)
    }

    // ── Volume lifecycle ─────────────────────────────────────────────────────

    /// Resolve a volume name to its record and image path for attachment.
    ///
    /// Returns `(volume_name, image_path)` when a name is provided. Returns
    /// `None` when no volume is requested (name is None).
    fn resolve_volume_attachment(
        &self,
        name: &Option<String>,
    ) -> Result<Option<(String, PathBuf)>, CoreError> {
        let Some(vol_name) = name else {
            return Ok(None);
        };
        let record = self
            .state
            .get_volume_by_name(vol_name)
            .map_err(|e| match e {
                husker_state::StateError::VolumeNotFoundByName(_) => {
                    CoreError::InvalidArgument(format!("volume '{vol_name}' not found"))
                }
                other => CoreError::State(other),
            })?;
        husker_storage::validate_volume(std::path::Path::new(&record.file_path))
            .map_err(CoreError::Storage)?;
        Ok(Some((record.name, PathBuf::from(record.file_path))))
    }

    /// Create a named persistent volume.
    ///
    /// Validates the name, rejects duplicates, creates a sparse ext4 image
    /// under `{data_dir}/volumes/`, and inserts the catalog record. On insert
    /// failure the image file is removed (mirror of `import_image`'s
    /// compensation pattern).
    pub async fn create_volume(&self, req: CreateVolumeRequest) -> Result<VolumeRecord, CoreError> {
        validate_resource_name("volume", &req.name)?;
        match self.state.get_volume_by_name(&req.name) {
            Ok(_) => return Err(CoreError::VolumeAlreadyExists(req.name)),
            Err(husker_state::StateError::VolumeNotFoundByName(_)) => {}
            Err(other) => return Err(CoreError::State(other)),
        }

        let volumes_dir = self.storage.volumes_dir();
        let image_path = volumes_dir.join(format!("{}.img", req.name));

        husker_storage::create_volume_image(&image_path, req.size_bytes).await?;

        let record = VolumeRecord {
            id: uuid::Uuid::new_v4(),
            name: req.name.clone(),
            file_path: image_path.to_string_lossy().into_owned(),
            size_bytes: req.size_bytes,
            created_at: chrono::Utc::now(),
        };

        if let Err(err) = self.state.insert_volume(&record).map_err(|e| match e {
            husker_state::StateError::VolumeAlreadyExists(name) => {
                CoreError::VolumeAlreadyExists(name)
            }
            other => CoreError::State(other),
        }) {
            let _ = tokio::fs::remove_file(&image_path).await;
            return Err(err);
        }

        Ok(record)
    }

    /// List all catalog volumes.
    pub fn list_volumes(&self) -> Result<Vec<VolumeRecord>, CoreError> {
        Ok(self.state.list_volumes()?)
    }

    /// Get a catalog volume by name.
    pub fn get_volume(&self, name: &str) -> Result<VolumeRecord, CoreError> {
        self.state.get_volume_by_name(name).map_err(|e| match e {
            husker_state::StateError::VolumeNotFoundByName(_) => {
                CoreError::VolumeNotFound(name.into())
            }
            other => CoreError::State(other),
        })
    }

    /// Delete a catalog volume by name.
    ///
    /// Refuses deletion while any VM record holds the volume. After the record
    /// is deleted the image file is removed on a best-effort basis.
    pub async fn delete_volume(&self, name: &str) -> Result<(), CoreError> {
        let record = self.get_volume(name)?;

        if let Some(holder) = self.state.find_vm_by_volume(name)? {
            return Err(CoreError::VolumeAttached {
                volume: name.into(),
                vm: holder.name,
            });
        }

        self.state.delete_volume(record.id).map_err(|e| match e {
            husker_state::StateError::VolumeNotFound(_) => CoreError::VolumeNotFound(name.into()),
            other => CoreError::State(other),
        })?;

        // Best-effort: log but do not fail if the file is already gone.
        match tokio::fs::remove_file(&record.file_path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                warn!(
                    volume = %name,
                    path = %record.file_path,
                    error = %e,
                    "failed to remove volume image file during delete"
                );
            }
        }

        Ok(())
    }
}

/// Build the create request for one service instance.
///
/// Cloud-image services boot the image via UEFI; direct services use the
/// recorded rootfs and kernel. Both variants forward the service's balloon
/// and volume preferences so replacement instances keep the same device
/// configuration.
pub(crate) fn instance_request(svc: &ServiceRecord, name: &str) -> CreateVmRequest {
    let env: Vec<(String, String)> = svc
        .userdata_env
        .as_deref()
        .map(|s| serde_json::from_str(s).unwrap_or_default())
        .unwrap_or_default();
    if let Some(ref image) = svc.cloud_image {
        CreateVmRequest {
            name: name.to_string(),
            kernel_path: None,
            rootfs_path: None,
            cloud_image: Some(image.clone()),
            disk_size: svc.disk_size,
            vcpu_count: svc.vcpu_count,
            mem_size_mib: svc.mem_size_mib,
            initrd_path: None,
            userdata: svc.userdata.clone(),
            env,
            vmm: None,
            ssh_authorized_keys: Vec::new(),
            balloon: svc.balloon,
            volume: svc.volume.clone(),
            // Services always use NAT; bridged networking is not supported for services.
            network: None,
            mounts: Vec::new(),
        }
    } else {
        CreateVmRequest {
            name: name.to_string(),
            kernel_path: Some(svc.kernel_path.clone().into()),
            rootfs_path: Some(svc.rootfs_path.clone().into()),
            cloud_image: None,
            disk_size: None,
            vcpu_count: svc.vcpu_count,
            mem_size_mib: svc.mem_size_mib,
            initrd_path: svc.initrd_path.clone().map(Into::into),
            userdata: svc.userdata.clone(),
            env,
            vmm: None,
            ssh_authorized_keys: Vec::new(),
            balloon: svc.balloon,
            volume: svc.volume.clone(),
            // Services always use NAT; bridged networking is not supported for services.
            network: None,
            mounts: Vec::new(),
        }
    }
}

const SECRET_KEY_LEN: usize = 32;
const SECRET_NONCE_LEN: usize = 12;

fn secret_to_metadata(secret: SecretRecord) -> SecretMetadata {
    SecretMetadata {
        id: secret.id,
        name: secret.name,
        created_at: secret.created_at,
        updated_at: secret.updated_at,
    }
}

fn load_or_create_secret_key(data_dir: &Path) -> Result<[u8; SECRET_KEY_LEN], CoreError> {
    let key_path = data_dir.join("keys/secrets.key");
    match std::fs::read(&key_path) {
        Ok(bytes) => {
            if bytes.len() != SECRET_KEY_LEN {
                return Err(CoreError::InvalidArgument(format!(
                    "invalid secret key length in {}: expected {}, got {}",
                    key_path.display(),
                    SECRET_KEY_LEN,
                    bytes.len()
                )));
            }
            let mut key = [0u8; SECRET_KEY_LEN];
            key.copy_from_slice(&bytes);
            return Ok(key);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(CoreError::Storage(husker_storage::StorageError::Io(e))),
    }

    let parent = key_path
        .parent()
        .ok_or_else(|| CoreError::InvalidArgument("invalid secret key path".into()))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| CoreError::Storage(husker_storage::StorageError::Io(e)))?;

    let mut key = [0u8; SECRET_KEY_LEN];
    ring::rand::SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| CoreError::SecretCrypto("failed to generate secret key".into()))?;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(&key_path) {
        Ok(mut file) => {
            use std::io::Write;
            file.write_all(&key)
                .map_err(|e| CoreError::Storage(husker_storage::StorageError::Io(e)))?;
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let bytes = std::fs::read(&key_path).map_err(|read_err| {
                CoreError::Storage(husker_storage::StorageError::Io(read_err))
            })?;
            if bytes.len() != SECRET_KEY_LEN {
                return Err(CoreError::InvalidArgument(format!(
                    "invalid secret key length in {}: expected {}, got {}",
                    key_path.display(),
                    SECRET_KEY_LEN,
                    bytes.len()
                )));
            }
            let mut existing = [0u8; SECRET_KEY_LEN];
            existing.copy_from_slice(&bytes);
            Ok(existing)
        }
        Err(e) => Err(CoreError::Storage(husker_storage::StorageError::Io(e))),
    }
}

fn encrypt_secret(
    key_bytes: &[u8; SECRET_KEY_LEN],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CoreError> {
    let unbound = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key_bytes)
        .map_err(|_| CoreError::SecretCrypto("failed to initialize encryption key".into()))?;
    let key = ring::aead::LessSafeKey::new(unbound);

    let mut nonce_bytes = [0u8; SECRET_NONCE_LEN];
    ring::rand::SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| CoreError::SecretCrypto("failed to generate secret nonce".into()))?;

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(
        ring::aead::Nonce::assume_unique_for_key(nonce_bytes),
        ring::aead::Aad::empty(),
        &mut in_out,
    )
    .map_err(|_| CoreError::SecretCrypto("failed to encrypt secret".into()))?;
    Ok((in_out, nonce_bytes.to_vec()))
}

fn decrypt_secret(
    key_bytes: &[u8; SECRET_KEY_LEN],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    if nonce_bytes.len() != SECRET_NONCE_LEN {
        return Err(CoreError::SecretCrypto(format!(
            "invalid nonce length: expected {SECRET_NONCE_LEN}, got {}",
            nonce_bytes.len()
        )));
    }

    let unbound = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key_bytes)
        .map_err(|_| CoreError::SecretCrypto("failed to initialize decryption key".into()))?;
    let key = ring::aead::LessSafeKey::new(unbound);

    let mut nonce = [0u8; SECRET_NONCE_LEN];
    nonce.copy_from_slice(nonce_bytes);
    let mut in_out = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(
            ring::aead::Nonce::assume_unique_for_key(nonce),
            ring::aead::Aad::empty(),
            &mut in_out,
        )
        .map_err(|_| CoreError::SecretCrypto("failed to decrypt secret".into()))?;
    Ok(plaintext.to_vec())
}

fn infer_image_format(path: &Path) -> String {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .unwrap_or_else(|| "ext4".to_string())
}

/// Validate and normalize the network mode field.
///
/// Returns "nat" or "bridged". Unknown values are rejected with an
/// `InvalidArgument` error listing the accepted values.
pub fn validate_network_mode(n: Option<&str>) -> Result<&'static str, CoreError> {
    match n {
        None | Some("nat") => Ok("nat"),
        Some("bridged") => Ok("bridged"),
        Some(other) => Err(CoreError::InvalidArgument(format!(
            "unknown network mode '{other}' (accepted: nat, bridged)"
        ))),
    }
}

/// Validate and default an image-import kind ("rootfs" when unset).
fn validate_image_kind(kind: Option<&str>) -> Result<String, CoreError> {
    match kind {
        None | Some("rootfs") => Ok("rootfs".to_string()),
        Some("cloud-image") => Ok("cloud-image".to_string()),
        Some(other) => Err(CoreError::InvalidArgument(format!(
            "unknown image kind '{other}' (expected 'rootfs' or 'cloud-image')"
        ))),
    }
}

/// Serial log files exceeding this size are eligible for rotation.
const LOG_ROTATE_THRESHOLD: u64 = 10 * 1024 * 1024; // 10 MiB

/// How many bytes to keep when rotating a serial log.
const LOG_ROTATE_KEEP: u64 = 5 * 1024 * 1024; // 5 MiB

/// Truncate a log file, keeping only the last `keep_bytes`.
///
/// Uses the copy-truncate pattern: read tail, truncate, write back.
/// Small data-loss window between read and truncate is acceptable
/// for diagnostic serial console output.
async fn rotate_log_file(path: &std::path::Path, keep_bytes: u64) -> std::io::Result<()> {
    let file_len = tokio::fs::metadata(path).await?.len();
    if file_len <= keep_bytes {
        return Ok(());
    }

    // Read the tail and rewrite it with std::fs in a blocking task. `read_exact`
    // into a sized buffer reads exactly `keep_bytes`; tokio's async `File` can
    // short-read after a `seek` (its `read_to_end` then stops early and keeps
    // fewer bytes than requested), so the synchronous path is deterministic.
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut buf = vec![0u8; keep_bytes as usize];
        let mut src = std::fs::File::open(&path)?;
        src.seek(SeekFrom::Start(file_len - keep_bytes))?;
        src.read_exact(&mut buf)?;
        drop(src);
        let mut dst = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)?;
        dst.write_all(&buf)?;
        Ok(())
    })
    .await
    .map_err(std::io::Error::other)?
}

/// Prepare a cloud-image boot disk: validate the base image and OVMF firmware exist,
/// clone the base qcow2 into `dest_disk`, optionally grow it, and return the UEFI
/// BootMode carrying the firmware paths. This is pure file I/O (no networking), so the
/// full create path's TAP setup is not involved and it is unit-tested directly.
#[cfg(feature = "linux-net")]
async fn prepare_cloud_disk(
    storage_driver: &dyn husker_storage::StorageDriver,
    image: &Path,
    disk_size: Option<u64>,
    dest_disk: &Path,
    ovmf_code: &Path,
    ovmf_vars_template: &Path,
) -> Result<husker_vmm::BootMode, CoreError> {
    husker_storage::validate_cloud_image(image)?;
    if !ovmf_code.exists() || !ovmf_vars_template.exists() {
        return Err(CoreError::InvalidArgument(format!(
            "OVMF firmware missing (need {} and {}); install the host OVMF package",
            ovmf_code.display(),
            ovmf_vars_template.display()
        )));
    }
    storage_driver.clone_rootfs(image, dest_disk).await?;
    if let Some(size) = disk_size {
        husker_storage::resize_disk(dest_disk, size).await?;
    }
    Ok(husker_vmm::BootMode::Uefi {
        ovmf_code: ovmf_code.to_path_buf(),
        ovmf_vars_template: ovmf_vars_template.to_path_buf(),
    })
}

/// Convert a seed-build failure into a core error. Invalid SSH keys are the
/// caller's input, not an internal fault, so they surface as InvalidArgument
/// (HTTP 400) instead of an internal cloud-init error.
fn seed_error_to_core(e: husker_cloudinit::CloudInitError) -> CoreError {
    match e {
        e @ husker_cloudinit::CloudInitError::InvalidSshKey(_) => {
            CoreError::InvalidArgument(e.to_string())
        }
        other => CoreError::CloudInit(other),
    }
}

/// Mount a rootfs image via loop, write `/etc/resolv.conf`, and unmount.
#[cfg(feature = "linux-net")]
async fn inject_resolv_conf(rootfs: &std::path::Path, servers: &[String]) -> Result<(), CoreError> {
    use tokio::process::Command;

    let mount_dir =
        tempfile::tempdir().map_err(|e| CoreError::Storage(husker_storage::StorageError::Io(e)))?;

    let status = Command::new("mount")
        .args(["-o", "loop"])
        .arg(rootfs)
        .arg(mount_dir.path())
        .status()
        .await
        .map_err(|e| CoreError::Storage(husker_storage::StorageError::Io(e)))?;

    if !status.success() {
        return Err(CoreError::Storage(husker_storage::StorageError::Io(
            std::io::Error::other("mount failed"),
        )));
    }

    let resolv_path = mount_dir.path().join("etc/resolv.conf");

    // Remove symlink if present (e.g. systemd-resolved's stub-resolv.conf)
    // so we can write a static file that persists across boot.
    if resolv_path.is_symlink()
        && let Err(e) = tokio::fs::remove_file(&resolv_path).await
    {
        warn!(path = %resolv_path.display(), error = %e, "failed to remove resolv.conf symlink");
    }

    let contents: String = servers
        .iter()
        .map(|s| format!("nameserver {s}\n"))
        .collect();

    let write_result = tokio::fs::write(&resolv_path, contents.as_bytes()).await;

    // Mask systemd-resolved so it doesn't recreate the symlink on boot
    let resolved_link = mount_dir
        .path()
        .join("etc/systemd/system/systemd-resolved.service");
    if !resolved_link.exists()
        && let Err(e) = tokio::fs::symlink("/dev/null", &resolved_link).await
    {
        warn!(path = %resolved_link.display(), error = %e, "failed to mask systemd-resolved");
    }

    // Always unmount, even if write failed
    let umount_status = Command::new("umount").arg(mount_dir.path()).status().await;

    write_result.map_err(|e| CoreError::Storage(husker_storage::StorageError::Io(e)))?;

    match umount_status {
        Ok(s) if s.success() => Ok(()),
        Ok(_) => Err(CoreError::Storage(husker_storage::StorageError::Io(
            std::io::Error::other("umount failed"),
        ))),
        Err(e) => Err(CoreError::Storage(husker_storage::StorageError::Io(e))),
    }
}

/// If a serial-console tail shows a kernel/module ABI mismatch - stale baked
/// `.ko` files that disagree with the running kernel after a kernel refresh -
/// return a targeted remediation hint. This failure otherwise surfaces only as a
/// generic "agent not ready" timeout (the guest never brings up vsock), which is
/// opaque without reading the serial log.
pub fn kernel_module_mismatch_hint(tail: &str) -> Option<&'static str> {
    let mismatched = tail.contains("disagrees about version of symbol")
        || tail.contains("module_layout")
        || tail.contains("Invalid module format");
    mismatched.then_some(
        "the guest's baked kernel modules do not match the running kernel \
         (a kernel refresh likely invalidated them); rebuild the rootfs against \
         the current kernel",
    )
}

/// Return the last `max_lines` non-empty-trailing lines of a file, or `None`
/// when the file is missing or has no content. Used to attach the guest serial
/// console tail to boot-failure errors.
fn tail_last_lines(path: &std::path::Path, max_lines: usize) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let trimmed = content.trim_end();
    if trimmed.is_empty() {
        return None;
    }
    let lines: Vec<&str> = trimmed.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    Some(lines[start..].join("\n"))
}

/// Remove a file, treating a missing file as success. Cleanup paths use this so
/// a file that was never created (or already gone) does not produce a spurious
/// warning. Returns `Err` only for real failures (e.g. permission denied).
async fn remove_file_best_effort(path: &std::path::Path) -> std::io::Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Write `contents` to `path` atomically and durably: write to a sibling
/// `<path>.tmp`, fsync it, rename it over `path`, then fsync the parent
/// directory. A crash can leave the temp file (harmless) but never a
/// partially-written `path`. Used for the suspend manifest, whose truncation
/// would otherwise make a suspended VM unrecoverable.
async fn write_file_atomic(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut tmp_os = path.as_os_str().to_owned();
    tmp_os.push(".tmp");
    let tmp = PathBuf::from(tmp_os);
    {
        let mut f = tokio::fs::File::create(&tmp).await?;
        f.write_all(contents).await?;
        f.sync_all().await?;
    }
    tokio::fs::rename(&tmp, path).await?;
    // Best-effort directory fsync so the rename survives power loss.
    if let Some(parent) = path.parent()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_file_atomic_writes_content_and_removes_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        write_file_atomic(&path, b"hello").await.unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), b"hello");
        let mut tmp = path.clone().into_os_string();
        tmp.push(".tmp");
        assert!(
            !std::path::Path::new(&tmp).exists(),
            "atomic write must not leave its temp file behind"
        );
    }

    #[tokio::test]
    async fn write_file_atomic_overwrites_existing_completely() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.json");
        tokio::fs::write(&path, b"old-and-longer").await.unwrap();
        write_file_atomic(&path, b"new").await.unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), b"new");
    }

    /// Block until `/proc/<pid>/cmdline` is observable, so the test never reads a
    /// just-forked child before it has finished `exec`-ing the shell.
    #[cfg(target_os = "linux")]
    fn wait_until_cmdline_contains(pid: u32, needle: &str) {
        for _ in 0..200 {
            if std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
                .unwrap_or_default()
                .contains(needle)
            {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("process {pid} never showed a cmdline containing {needle:?}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reap_vmm_if_orphaned_kills_only_the_identified_process() {
        use std::process::{Command, Stdio};

        // A live process whose argv carries the VM id (as both backends do via
        // their per-VM socket/pidfile paths) is identified and killed. `read`
        // blocks on the piped stdin without forking, so the shell's own cmdline
        // carries the id (no child to orphan).
        let id = Uuid::new_v4();
        let mut victim = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("read _x # {id}"))
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn victim");
        wait_until_cmdline_contains(victim.id(), &id.to_string());
        assert!(
            reap_vmm_if_orphaned(id, victim.id()),
            "a live process whose cmdline names the VM id must be reaped"
        );
        let status = victim.wait().expect("wait victim");
        assert!(
            !status.success(),
            "the reaped process must have been killed by a signal"
        );

        // A live process whose argv does NOT carry the VM id (a recycled pid now
        // belonging to something unrelated) must be left untouched.
        let other_id = Uuid::new_v4();
        let mut bystander = Command::new("/bin/sh")
            .arg("-c")
            .arg("read _x")
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn bystander");
        wait_until_cmdline_contains(bystander.id(), "read");
        assert!(
            !reap_vmm_if_orphaned(other_id, bystander.id()),
            "a process whose cmdline does not name the VM id must not be touched"
        );
        assert!(
            bystander.try_wait().expect("try_wait bystander").is_none(),
            "the bystander must still be alive"
        );
        bystander.kill().ok();
        bystander.wait().ok();
    }

    #[cfg(feature = "linux-net")]
    #[test]
    fn apply_boot_init_appends_supervisor_tokens_when_set() {
        let base = "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw \
                    ip=172.20.0.2::172.20.0.1:255.255.255.252::eth0:off";
        let cmd = apply_boot_init(base, Some("/usr/local/bin/husker-agent"));
        assert!(cmd.contains("init=/usr/local/bin/husker-agent"));
        assert!(cmd.contains("husker.init=1"));
        // Unchanged when no boot_init is set.
        assert_eq!(apply_boot_init(base, None), base);
        // A user-supplied explicit init= wins (left untouched).
        let with_init = "console=ttyS0 init=/sbin/myinit";
        assert_eq!(
            apply_boot_init(with_init, Some("/usr/local/bin/husker-agent")),
            with_init
        );
    }

    #[test]
    fn oci_ref_to_catalog_name_sanitizes_deterministically() {
        assert_eq!(
            oci_ref_to_catalog_name("python:3.12-alpine"),
            "python-3.12-alpine"
        );
        assert_eq!(oci_ref_to_catalog_name("ghcr.io/o/r:v1"), "ghcr.io-o-r-v1");
        assert_eq!(oci_ref_to_catalog_name("alpine"), "alpine");
        // Deterministic (so repeat runs of the same ref reuse the cached import).
        assert_eq!(
            oci_ref_to_catalog_name("python:3.12-alpine"),
            oci_ref_to_catalog_name("python:3.12-alpine")
        );
    }

    #[test]
    fn looks_like_path_distinguishes_paths_from_refs() {
        assert!(looks_like_path("/var/lib/husker/x.ext4"));
        assert!(looks_like_path("./rel.ext4"));
        assert!(looks_like_path("../up.ext4"));
        // Image names and OCI refs are not path-shaped.
        assert!(!looks_like_path("myimg"));
        assert!(!looks_like_path("python:3.12-alpine"));
        assert!(!looks_like_path("ghcr.io/o/r:v1"));
    }

    #[cfg(feature = "linux-net")]
    #[test]
    fn resolve_vmm_kind_uses_daemon_default_when_unspecified() {
        use husker_vmm::VmmKind;
        // No explicit --vmm: a QEMU-default daemon must resolve to QEMU, so the
        // persisted record matches the backend the dispatcher actually runs.
        // (Previously this was hardcoded to Firecracker, mislabeling the VM.)
        assert_eq!(
            resolve_vmm_kind(None, false, VmmKind::Qemu).unwrap(),
            VmmKind::Qemu
        );
        assert_eq!(
            resolve_vmm_kind(None, false, VmmKind::Firecracker).unwrap(),
            VmmKind::Firecracker
        );
    }

    #[cfg(feature = "linux-net")]
    #[test]
    fn resolve_vmm_kind_explicit_request_overrides_default() {
        use husker_vmm::VmmKind;
        assert_eq!(
            resolve_vmm_kind(Some("firecracker"), false, VmmKind::Qemu).unwrap(),
            VmmKind::Firecracker
        );
        // An unparseable backend string is rejected, not silently defaulted.
        assert!(resolve_vmm_kind(Some("xen"), false, VmmKind::Qemu).is_err());
    }

    #[cfg(feature = "linux-net")]
    #[test]
    fn resolve_vmm_kind_cloud_is_always_qemu() {
        use husker_vmm::VmmKind;
        // Cloud-image boot is QEMU-only regardless of the daemon default.
        assert_eq!(
            resolve_vmm_kind(None, true, VmmKind::Firecracker).unwrap(),
            VmmKind::Qemu
        );
    }

    #[cfg(feature = "linux-net")]
    #[test]
    fn inject_guest_runtime_does_not_follow_symlinks() {
        // An untrusted image symlinks an injection-path parent to an outside dir;
        // injection must replace the symlink with a real dir and write inside the
        // rootfs, never through the symlink.
        let rootfs = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(rootfs.path().join("usr/local")).unwrap();
        std::os::unix::fs::symlink(outside.path(), rootfs.path().join("usr/local/bin")).unwrap();

        inject_guest_runtime(
            rootfs.path(),
            b"AGENT",
            &husker_agent_proto::OciRuntimeConfig::default(),
        )
        .unwrap();

        assert!(
            !outside.path().join("husker-agent").exists(),
            "must not write through the symlink to outside the rootfs"
        );
        assert!(
            std::fs::symlink_metadata(rootfs.path().join("usr/local/bin"))
                .unwrap()
                .file_type()
                .is_dir(),
            "the symlinked parent is replaced with a real directory"
        );
        assert_eq!(
            std::fs::read(rootfs.path().join("usr/local/bin/husker-agent")).unwrap(),
            b"AGENT"
        );
    }

    #[cfg(feature = "linux-net")]
    #[test]
    fn inject_guest_runtime_boots_via_agent_and_writes_oci_config() {
        // An image that ships its own /sbin/init (e.g. a symlink into the image)
        // must be overridden so the husker agent becomes PID 1, and the OCI
        // runtime config must be written for the agent to apply on exec.
        let rootfs = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(rootfs.path().join("sbin")).unwrap();
        // Pre-existing image init that must be replaced.
        std::os::unix::fs::symlink("/lib/systemd/systemd", rootfs.path().join("sbin/init"))
            .unwrap();

        let cfg = husker_agent_proto::OciRuntimeConfig {
            env: vec!["PATH=/usr/local/bin:/usr/bin".into()],
            working_dir: Some("/app".into()),
            entrypoint: vec![],
            cmd: vec![],
        };
        inject_guest_runtime(rootfs.path(), b"AGENT", &cfg).unwrap();

        // /sbin/init now points at the agent (boots via the supervisor).
        let init_target = std::fs::read_link(rootfs.path().join("sbin/init")).unwrap();
        assert_eq!(
            init_target,
            std::path::Path::new("/usr/local/bin/husker-agent")
        );

        // The OCI runtime config is written and round-trips.
        let written = std::fs::read(rootfs.path().join("etc/husker/oci-config.json")).unwrap();
        let parsed: husker_agent_proto::OciRuntimeConfig =
            serde_json::from_slice(&written).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[cfg(feature = "linux-net")]
    #[test]
    fn with_uefi_firmware_sets_both_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let code = tmp.path().join("OVMF_CODE_4M.fd");
        let vars = tmp.path().join("OVMF_VARS_4M.fd");
        let state = husker_state::StateStore::open_memory().unwrap();
        let storage = husker_storage::StorageConfig {
            data_dir: tmp.path().to_path_buf(),
        };
        let runtime_dir = tmp.path().join("run");
        let core = HuskerCore::new(
            husker_vmm::firecracker::FirecrackerBackend::new(
                std::path::Path::new("firecracker"),
                &runtime_dir,
            ),
            state,
            husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
            storage,
            "husker0".into(),
            vec![],
            runtime_dir,
        )
        .with_uefi_firmware(code.clone(), vars.clone());
        assert_eq!(core.ovmf_code_path, code);
        assert_eq!(core.ovmf_vars_template_path, vars);
    }

    #[cfg(feature = "linux-net")]
    #[tokio::test]
    async fn resolve_rootfs_arg_handles_paths_names_and_unknowns() {
        let tmp = tempfile::tempdir().unwrap();
        let state = husker_state::StateStore::open_memory().unwrap();
        let runtime_dir = tmp.path().join("run");
        let core = HuskerCore::new(
            husker_vmm::firecracker::FirecrackerBackend::new(
                std::path::Path::new("firecracker"),
                &runtime_dir,
            ),
            state,
            husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
            husker_storage::StorageConfig {
                data_dir: tmp.path().to_path_buf(),
            },
            "husker0".into(),
            vec![],
            runtime_dir,
        );

        // A catalog image name resolves to its file path.
        core.state
            .insert_image(&ImageRecord {
                id: Uuid::new_v4(),
                name: "myimg".into(),
                source_path: "oci://x".into(),
                file_path: "/var/lib/husker/images/catalog/myimg.ext4".into(),
                format: "ext4".into(),
                kind: "rootfs".into(),
                boot_init: Some("/usr/local/bin/husker-agent".into()),
                size_bytes: 1,
                created_at: chrono::Utc::now(),
            })
            .unwrap();
        assert_eq!(
            core.resolve_rootfs_arg(std::path::Path::new("myimg"))
                .await
                .unwrap(),
            std::path::PathBuf::from("/var/lib/husker/images/catalog/myimg.ext4")
        );

        // An existing file is used as-is.
        let real = tmp.path().join("real.ext4");
        std::fs::write(&real, b"x").unwrap();
        assert_eq!(core.resolve_rootfs_arg(&real).await.unwrap(), real);

        // A path-shaped argument that doesn't exist is passed through (the rootfs
        // validator reports it), not treated as an image reference.
        let ghost = std::path::Path::new("/no/such/file.ext4");
        assert_eq!(core.resolve_rootfs_arg(ghost).await.unwrap(), ghost);

        // A bare unknown name is a clear error.
        let err = core
            .resolve_rootfs_arg(std::path::Path::new("nope"))
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::InvalidArgument(_)), "got {err:?}");
    }

    #[cfg(feature = "linux-net")]
    #[tokio::test]
    async fn prepare_cloud_disk_returns_uefi_and_clones() {
        let tmp = tempfile::tempdir().unwrap();
        let image = tmp.path().join("base.qcow2");
        let code = tmp.path().join("CODE.fd");
        let vars = tmp.path().join("VARS.fd");
        // image must have valid qcow2 magic so validate_cloud_image passes.
        let mut qcow2_data = vec![0u8; 512];
        qcow2_data[..4].copy_from_slice(&[0x51, 0x46, 0x49, 0xfb]);
        std::fs::write(&image, &qcow2_data).unwrap();
        for p in [&code, &vars] {
            std::fs::write(p, b"x").unwrap();
        }
        let dest = tmp.path().join("vm/disk.qcow2");
        let driver = husker_storage::default_storage_driver();
        // disk_size = None so no qemu-img resize is needed (keeps the test hermetic).
        let boot = super::prepare_cloud_disk(driver.as_ref(), &image, None, &dest, &code, &vars)
            .await
            .unwrap();
        match boot {
            husker_vmm::BootMode::Uefi {
                ovmf_code,
                ovmf_vars_template,
            } => {
                assert_eq!(ovmf_code, code);
                assert_eq!(ovmf_vars_template, vars);
            }
            other => panic!("expected Uefi, got {other:?}"),
        }
        assert!(dest.exists(), "base image must be cloned to dest");
    }

    #[cfg(feature = "linux-net")]
    #[tokio::test]
    async fn prepare_cloud_disk_errors_on_missing_image() {
        let tmp = tempfile::tempdir().unwrap();
        let code = tmp.path().join("CODE.fd");
        let vars = tmp.path().join("VARS.fd");
        for p in [&code, &vars] {
            std::fs::write(p, b"x").unwrap();
        }
        let driver = husker_storage::default_storage_driver();
        let err = super::prepare_cloud_disk(
            driver.as_ref(),
            Path::new("/no/such/image.qcow2"),
            None,
            &tmp.path().join("d.qcow2"),
            &code,
            &vars,
        )
        .await
        .unwrap_err();
        // validate_cloud_image reports missing files as Storage(InvalidCloudImage).
        assert!(
            matches!(
                err,
                super::CoreError::Storage(husker_storage::StorageError::InvalidCloudImage(_))
            ),
            "got {err:?}"
        );
    }

    #[cfg(feature = "linux-net")]
    #[tokio::test]
    async fn prepare_cloud_disk_errors_on_missing_ovmf() {
        let tmp = tempfile::tempdir().unwrap();
        let image = tmp.path().join("base.qcow2");
        // image must have valid qcow2 magic so validate_cloud_image passes.
        let mut qcow2_data = vec![0u8; 512];
        qcow2_data[..4].copy_from_slice(&[0x51, 0x46, 0x49, 0xfb]);
        std::fs::write(&image, &qcow2_data).unwrap();
        let driver = husker_storage::default_storage_driver();
        let err = super::prepare_cloud_disk(
            driver.as_ref(),
            &image,
            None,
            &tmp.path().join("d.qcow2"),
            &tmp.path().join("missing-code.fd"),
            &tmp.path().join("missing-vars.fd"),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, super::CoreError::InvalidArgument(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn invalid_ssh_key_seed_error_is_invalid_argument() {
        let e = husker_cloudinit::CloudInitError::InvalidSshKey("bad".into());
        assert!(matches!(
            super::seed_error_to_core(e),
            super::CoreError::InvalidArgument(_)
        ));
        let other = husker_cloudinit::CloudInitError::EmptyAgent;
        assert!(matches!(
            super::seed_error_to_core(other),
            super::CoreError::CloudInit(_)
        ));
    }

    #[cfg(not(feature = "linux-net"))]
    #[test]
    fn with_embedded_agent_available_without_linux_net() {
        let tmp = tempfile::tempdir().unwrap();
        let state = husker_state::StateStore::open_memory().unwrap();
        let storage = husker_storage::StorageConfig {
            data_dir: tmp.path().to_path_buf(),
        };
        let runtime_dir = tmp.path().join("run");
        let core = HuskerCore::new(
            husker_vmm::apple_vz::AppleVzBackend::new(&runtime_dir),
            state,
            storage,
            runtime_dir,
        )
        .with_embedded_agent(b"fake-agent");
        assert_eq!(core.embedded_agent, b"fake-agent");
    }

    #[test]
    fn kernel_module_mismatch_hint_detects_abi_failures() {
        // The classic stale-baked-module signatures.
        assert!(
            kernel_module_mismatch_hint("vsock: disagrees about version of symbol module_layout")
                .is_some()
        );
        assert!(kernel_module_mismatch_hint("insmod: ERROR: Invalid module format").is_some());
        // A normal boot tail produces no module hint.
        assert!(
            kernel_module_mismatch_hint("husker-init: skipped virtio_blk (built-in)").is_none()
        );
    }

    #[test]
    fn tail_last_lines_returns_last_n_and_handles_missing_or_empty() {
        let dir = tempfile::tempdir().unwrap();

        // Missing file -> None (no spurious tail for a never-created log).
        assert!(tail_last_lines(&dir.path().join("missing.log"), 5).is_none());

        // Empty / whitespace-only file -> None.
        let empty = dir.path().join("empty.log");
        std::fs::write(&empty, "\n\n  \n").unwrap();
        assert!(tail_last_lines(&empty, 5).is_none());

        // More lines than requested -> only the last N, trailing blank trimmed.
        let many = dir.path().join("many.log");
        std::fs::write(&many, "a\nb\nc\nd\ne\n").unwrap();
        assert_eq!(tail_last_lines(&many, 2).unwrap(), "d\ne");

        // Fewer lines than requested -> all of them.
        assert_eq!(tail_last_lines(&many, 20).unwrap(), "a\nb\nc\nd\ne");
    }

    #[tokio::test]
    async fn remove_file_best_effort_ignores_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.serial.log");
        // A file that is already gone is not a cleanup failure.
        remove_file_best_effort(&missing)
            .await
            .expect("missing file should be treated as success");
    }

    #[tokio::test]
    async fn remove_file_best_effort_removes_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("present.serial.log");
        tokio::fs::write(&path, b"log").await.unwrap();
        assert!(path.exists());
        remove_file_best_effort(&path)
            .await
            .expect("removing an existing file should succeed");
        assert!(!path.exists(), "file should be gone after removal");
    }

    #[cfg(all(feature = "linux-net", unix))]
    use std::ffi::{OsStr, OsString};
    #[cfg(all(feature = "linux-net", unix))]
    use std::path::Path;
    #[cfg(all(feature = "linux-net", unix))]
    use std::sync::OnceLock;

    #[cfg(all(feature = "linux-net", unix))]
    const FAKE_MOUNT_SCRIPT: &str = r#"#!/bin/sh
set -eu
mount_dir="$4"
if [ "${HUSKER_FAKE_SKIP_ETC_DIR:-0}" = "1" ]; then
  exit "${HUSKER_FAKE_MOUNT_EXIT:-0}"
fi
mkdir -p "$mount_dir/etc/systemd/system"
mkdir -p "$mount_dir/run/systemd/resolve"
touch "$mount_dir/run/systemd/resolve/stub-resolv.conf"
ln -sf "$mount_dir/run/systemd/resolve/stub-resolv.conf" "$mount_dir/etc/resolv.conf"
exit "${HUSKER_FAKE_MOUNT_EXIT:-0}"
"#;

    #[cfg(all(feature = "linux-net", unix))]
    const FAKE_UMOUNT_SCRIPT: &str = r#"#!/bin/sh
set -eu
mount_dir="$1"
if [ -n "${HUSKER_FAKE_CAPTURE_FILE:-}" ] && [ -f "$mount_dir/etc/resolv.conf" ]; then
  cp "$mount_dir/etc/resolv.conf" "$HUSKER_FAKE_CAPTURE_FILE"
fi
if [ -n "${HUSKER_FAKE_MASK_CAPTURE_FILE:-}" ] && [ -L "$mount_dir/etc/systemd/system/systemd-resolved.service" ]; then
  readlink "$mount_dir/etc/systemd/system/systemd-resolved.service" > "$HUSKER_FAKE_MASK_CAPTURE_FILE"
fi
exit "${HUSKER_FAKE_UMOUNT_EXIT:-0}"
"#;

    #[cfg(all(feature = "linux-net", unix))]
    fn env_test_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    #[cfg(all(feature = "linux-net", unix))]
    fn write_executable_script(path: &Path, script: &str) {
        std::fs::write(path, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }

    #[cfg(all(feature = "linux-net", unix))]
    struct ScopedEnvVar {
        key: &'static str,
        previous: Option<OsString>,
    }

    #[cfg(all(feature = "linux-net", unix))]
    impl ScopedEnvVar {
        fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
            let previous = std::env::var_os(key);
            // SAFETY: tests serialize environment mutation using env_test_lock().
            unsafe { std::env::set_var(key, value.as_ref()) };
            Self { key, previous }
        }
    }

    #[cfg(all(feature = "linux-net", unix))]
    impl Drop for ScopedEnvVar {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => {
                    // SAFETY: tests serialize environment mutation using env_test_lock().
                    unsafe { std::env::set_var(self.key, value) };
                }
                None => {
                    // SAFETY: tests serialize environment mutation using env_test_lock().
                    unsafe { std::env::remove_var(self.key) };
                }
            }
        }
    }

    #[tokio::test]
    async fn rotate_log_file_truncates_oversized() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.serial.log");

        // Write a 12 MiB file with a recognizable pattern at the end
        let data: Vec<u8> = (0..12 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &data).unwrap();

        rotate_log_file(&path, LOG_ROTATE_KEEP).await.unwrap();

        let result = std::fs::read(&path).unwrap();
        assert!(
            result.len() as u64 == LOG_ROTATE_KEEP,
            "expected {} bytes, got {}",
            LOG_ROTATE_KEEP,
            result.len()
        );
        // The kept portion should match the tail of the original data
        let expected_tail = &data[data.len() - LOG_ROTATE_KEEP as usize..];
        assert_eq!(&result, expected_tail);
    }

    #[tokio::test]
    async fn rotate_log_file_skips_small_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("small.serial.log");

        let data = vec![0u8; 1024]; // 1 KiB
        std::fs::write(&path, &data).unwrap();

        rotate_log_file(&path, LOG_ROTATE_KEEP).await.unwrap();

        let result = std::fs::read(&path).unwrap();
        assert_eq!(result.len(), 1024, "small file should not be modified");
    }

    #[tokio::test]
    async fn rotate_log_file_nonexistent_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.serial.log");

        let result = rotate_log_file(&path, LOG_ROTATE_KEEP).await;
        assert!(result.is_err());
    }

    #[cfg(all(feature = "linux-net", unix))]
    #[tokio::test]
    async fn inject_resolv_conf_writes_nameservers_and_masks_resolved() {
        let _guard = env_test_lock().lock().await;

        let bin_dir = tempfile::tempdir().unwrap();
        write_executable_script(&bin_dir.path().join("mount"), FAKE_MOUNT_SCRIPT);
        write_executable_script(&bin_dir.path().join("umount"), FAKE_UMOUNT_SCRIPT);

        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = rootfs_dir.path().join("rootfs.img");
        std::fs::write(&rootfs, b"fake-rootfs").unwrap();

        let capture_dir = tempfile::tempdir().unwrap();
        let resolv_capture = capture_dir.path().join("resolv.conf.capture");
        let mask_capture = capture_dir.path().join("resolved-mask.capture");

        let mut path = OsString::from(bin_dir.path().as_os_str());
        path.push(":");
        path.push(std::env::var_os("PATH").unwrap_or_default());

        let _path_guard = ScopedEnvVar::set("PATH", &path);
        let _mount_exit = ScopedEnvVar::set("HUSKER_FAKE_MOUNT_EXIT", "0");
        let _umount_exit = ScopedEnvVar::set("HUSKER_FAKE_UMOUNT_EXIT", "0");
        let _capture_guard = ScopedEnvVar::set("HUSKER_FAKE_CAPTURE_FILE", &resolv_capture);
        let _mask_guard = ScopedEnvVar::set("HUSKER_FAKE_MASK_CAPTURE_FILE", &mask_capture);

        let servers = vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()];
        inject_resolv_conf(&rootfs, &servers).await.unwrap();

        let resolv_contents = std::fs::read_to_string(resolv_capture).unwrap();
        assert_eq!(resolv_contents, "nameserver 1.1.1.1\nnameserver 8.8.8.8\n");

        let mask_target = std::fs::read_to_string(mask_capture).unwrap();
        assert_eq!(mask_target.trim(), "/dev/null");
    }

    #[cfg(all(feature = "linux-net", unix))]
    #[tokio::test]
    async fn inject_resolv_conf_returns_error_when_mount_fails() {
        let _guard = env_test_lock().lock().await;

        let bin_dir = tempfile::tempdir().unwrap();
        write_executable_script(&bin_dir.path().join("mount"), FAKE_MOUNT_SCRIPT);
        write_executable_script(&bin_dir.path().join("umount"), FAKE_UMOUNT_SCRIPT);

        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = rootfs_dir.path().join("rootfs.img");
        std::fs::write(&rootfs, b"fake-rootfs").unwrap();

        let mut path = OsString::from(bin_dir.path().as_os_str());
        path.push(":");
        path.push(std::env::var_os("PATH").unwrap_or_default());

        let _path_guard = ScopedEnvVar::set("PATH", &path);
        let _mount_exit = ScopedEnvVar::set("HUSKER_FAKE_MOUNT_EXIT", "1");
        let _umount_exit = ScopedEnvVar::set("HUSKER_FAKE_UMOUNT_EXIT", "0");

        let servers = vec!["1.1.1.1".to_string()];
        let err = inject_resolv_conf(&rootfs, &servers).await.unwrap_err();

        match err {
            CoreError::Storage(husker_storage::StorageError::Io(ioe)) => {
                assert!(ioe.to_string().contains("mount failed"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[cfg(all(feature = "linux-net", unix))]
    #[tokio::test]
    async fn inject_resolv_conf_returns_error_when_umount_fails() {
        let _guard = env_test_lock().lock().await;

        let bin_dir = tempfile::tempdir().unwrap();
        write_executable_script(&bin_dir.path().join("mount"), FAKE_MOUNT_SCRIPT);
        write_executable_script(&bin_dir.path().join("umount"), FAKE_UMOUNT_SCRIPT);

        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = rootfs_dir.path().join("rootfs.img");
        std::fs::write(&rootfs, b"fake-rootfs").unwrap();

        let mut path = OsString::from(bin_dir.path().as_os_str());
        path.push(":");
        path.push(std::env::var_os("PATH").unwrap_or_default());

        let _path_guard = ScopedEnvVar::set("PATH", &path);
        let _mount_exit = ScopedEnvVar::set("HUSKER_FAKE_MOUNT_EXIT", "0");
        let _umount_exit = ScopedEnvVar::set("HUSKER_FAKE_UMOUNT_EXIT", "1");

        let servers = vec!["1.1.1.1".to_string()];
        let err = inject_resolv_conf(&rootfs, &servers).await.unwrap_err();

        match err {
            CoreError::Storage(husker_storage::StorageError::Io(ioe)) => {
                assert!(ioe.to_string().contains("umount failed"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[cfg(all(feature = "linux-net", unix))]
    #[tokio::test]
    async fn inject_resolv_conf_returns_error_when_resolv_write_fails() {
        let _guard = env_test_lock().lock().await;

        let bin_dir = tempfile::tempdir().unwrap();
        write_executable_script(&bin_dir.path().join("mount"), FAKE_MOUNT_SCRIPT);
        write_executable_script(&bin_dir.path().join("umount"), FAKE_UMOUNT_SCRIPT);

        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = rootfs_dir.path().join("rootfs.img");
        std::fs::write(&rootfs, b"fake-rootfs").unwrap();

        let mut path = OsString::from(bin_dir.path().as_os_str());
        path.push(":");
        path.push(std::env::var_os("PATH").unwrap_or_default());

        let _path_guard = ScopedEnvVar::set("PATH", &path);
        let _mount_exit = ScopedEnvVar::set("HUSKER_FAKE_MOUNT_EXIT", "0");
        let _umount_exit = ScopedEnvVar::set("HUSKER_FAKE_UMOUNT_EXIT", "0");
        let _skip_etc = ScopedEnvVar::set("HUSKER_FAKE_SKIP_ETC_DIR", "1");

        let servers = vec!["1.1.1.1".to_string()];
        let err = inject_resolv_conf(&rootfs, &servers).await.unwrap_err();

        match err {
            CoreError::Storage(husker_storage::StorageError::Io(ioe)) => {
                assert!(ioe.to_string().contains("No such file"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    fn make_vm_record(
        name: &str,
        state: &str,
        pid: Option<u32>,
        vmm: &str,
    ) -> husker_state::VmRecord {
        husker_state::VmRecord {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            state: state.into(),
            pid,
            vcpu_count: 1,
            mem_size_mib: 128,
            vsock_cid: 3,
            tap_device: None,
            host_ip: None,
            guest_ip: None,
            kernel_path: "/boot/vmlinux".into(),
            rootfs_path: "/images/rootfs.ext4".into(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            userdata: None,
            userdata_status: None,
            userdata_env: None,
            service_id: None,
            service_ordinal: None,
            vmm: vmm.into(),
            boot_mode: "direct".into(),
            balloon: false,
            volume: None,
            network: "nat".into(),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reap_does_not_kill_non_qemu_running_vm() {
        // A VM in `running` state whose pid points at our own process (non-qemu):
        // must NOT be killed, reaped count stays 0, and we stay alive.
        let state = husker_state::StateStore::open_memory().unwrap();
        let self_pid = std::process::id();
        let rec = make_vm_record("live-non-qemu", "running", Some(self_pid), "firecracker");
        state.insert_vm(&rec).unwrap();

        let reaped = crate::reap_orphaned_vmms(&state);

        assert_eq!(reaped, 0, "must not kill a non-qemu process");
        // We are still alive.
        assert_eq!(std::process::id(), self_pid);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reap_skips_stopped_vms_and_dead_pids() {
        let state = husker_state::StateStore::open_memory().unwrap();
        // A stopped VM - must be ignored regardless of pid.
        let stopped = make_vm_record("stopped-vm", "stopped", Some(std::process::id()), "qemu");
        state.insert_vm(&stopped).unwrap();
        // A running VM whose pid is almost certainly dead (above default pid_max).
        let dead_pid: u32 = 4_000_000;
        let dead = make_vm_record("orphan-dead-pid", "running", Some(dead_pid), "qemu");
        state.insert_vm(&dead).unwrap();
        // A running VM with no pid recorded.
        let no_pid = make_vm_record("orphan-no-pid", "running", None, "qemu");
        state.insert_vm(&no_pid).unwrap();

        let reaped = crate::reap_orphaned_vmms(&state);

        assert_eq!(
            reaped, 0,
            "stopped VMs and dead/absent pids must not be counted as reaped"
        );
        // We are still alive.
        assert!(std::process::id() > 0);
    }

    #[test]
    fn create_vm_request_defaults_cloud_fields_to_none() {
        let json = r#"{"name":"v"}"#;
        let req: super::CreateVmRequest = serde_json::from_str(json).unwrap();
        assert!(req.kernel_path.is_none());
        assert!(req.rootfs_path.is_none());
        assert!(req.cloud_image.is_none());
        assert!(req.disk_size.is_none());
        assert!(req.ssh_authorized_keys.is_empty());
        assert!(!req.balloon, "balloon must default to false");
    }

    #[test]
    fn create_service_request_new_fields_default() {
        let json = r#"{"name":"svc","kernel_path":"/k","rootfs_path":"/r"}"#;
        let req: super::CreateServiceRequest = serde_json::from_str(json).unwrap();
        assert!(req.cloud_image.is_none());
        assert!(req.disk_size.is_none());
        assert!(!req.balloon, "balloon must default to false");
    }

    #[test]
    fn instance_request_direct_sets_kernel_and_rootfs() {
        let now = chrono::Utc::now();
        let svc = husker_state::ServiceRecord {
            id: uuid::Uuid::new_v4(),
            name: "svc".into(),
            host_group_id: None,
            desired_instances: 1,
            image: None,
            kernel_path: "/boot/vmlinux".into(),
            rootfs_path: "/images/rootfs.ext4".into(),
            initrd_path: None,
            vcpu_count: Some(2),
            mem_size_mib: Some(256),
            userdata: Some("echo hi".into()),
            userdata_env: Some(r#"[["FOO","bar"]]"#.into()),
            created_at: now,
            updated_at: now,
            cloud_image: None,
            disk_size: None,
            balloon: false,
            volume: None,
        };
        let req = super::instance_request(&svc, "svc-0");
        assert_eq!(req.name, "svc-0");
        assert_eq!(
            req.kernel_path,
            Some(std::path::PathBuf::from("/boot/vmlinux"))
        );
        assert_eq!(
            req.rootfs_path,
            Some(std::path::PathBuf::from("/images/rootfs.ext4"))
        );
        assert!(req.cloud_image.is_none());
        assert!(req.disk_size.is_none());
        assert_eq!(req.vcpu_count, Some(2));
        assert_eq!(req.mem_size_mib, Some(256));
        assert_eq!(req.userdata.as_deref(), Some("echo hi"));
        assert_eq!(req.env, vec![("FOO".to_string(), "bar".to_string())]);
        assert!(!req.balloon);
    }

    #[test]
    fn instance_request_direct_balloon_propagates() {
        let now = chrono::Utc::now();
        let svc = husker_state::ServiceRecord {
            id: uuid::Uuid::new_v4(),
            name: "svc".into(),
            host_group_id: None,
            desired_instances: 1,
            image: None,
            kernel_path: "/boot/vmlinux".into(),
            rootfs_path: "/images/rootfs.ext4".into(),
            initrd_path: None,
            vcpu_count: Some(1),
            mem_size_mib: Some(128),
            userdata: None,
            userdata_env: None,
            created_at: now,
            updated_at: now,
            cloud_image: None,
            disk_size: None,
            balloon: true,
            volume: None,
        };
        let req = super::instance_request(&svc, "svc-0");
        assert!(
            req.balloon,
            "balloon should be forwarded from service record"
        );
    }

    #[test]
    fn instance_request_cloud_sets_image_fields() {
        let now = chrono::Utc::now();
        let svc = husker_state::ServiceRecord {
            id: uuid::Uuid::new_v4(),
            name: "cloudsvc".into(),
            host_group_id: None,
            desired_instances: 1,
            image: None,
            kernel_path: "".into(),
            rootfs_path: "".into(),
            initrd_path: None,
            vcpu_count: Some(2),
            mem_size_mib: Some(2048),
            userdata: None,
            userdata_env: None,
            created_at: now,
            updated_at: now,
            cloud_image: Some("ubuntu-2404".into()),
            disk_size: Some(10 * 1024 * 1024 * 1024),
            balloon: true,
            volume: None,
        };
        let req = super::instance_request(&svc, "cloudsvc-0");
        assert_eq!(req.name, "cloudsvc-0");
        assert!(
            req.kernel_path.is_none(),
            "cloud arm must not set kernel_path"
        );
        assert!(
            req.rootfs_path.is_none(),
            "cloud arm must not set rootfs_path"
        );
        assert_eq!(req.cloud_image.as_deref(), Some("ubuntu-2404"));
        assert_eq!(req.disk_size, Some(10 * 1024 * 1024 * 1024));
        assert_eq!(req.vcpu_count, Some(2));
        assert_eq!(req.mem_size_mib, Some(2048));
        assert!(req.balloon, "balloon forwarded from cloud service");
    }

    #[test]
    fn import_image_kind_validation() {
        assert_eq!(validate_image_kind(None).unwrap(), "rootfs");
        assert_eq!(
            validate_image_kind(Some("cloud-image")).unwrap(),
            "cloud-image"
        );
        assert_eq!(validate_image_kind(Some("rootfs")).unwrap(), "rootfs");
        assert!(validate_image_kind(Some("bogus")).is_err());
    }

    #[test]
    fn ready_timeout_is_boot_mode_aware() {
        assert_eq!(
            default_ready_timeout("direct"),
            std::time::Duration::from_secs(DEFAULT_READY_TIMEOUT_SECS)
        );
        assert_eq!(
            default_ready_timeout("uefi"),
            std::time::Duration::from_secs(UEFI_READY_TIMEOUT_SECS)
        );
        // "efi" (Apple VZ cloud-image path) runs full cloud-init and needs the
        // same extended timeout as "uefi".
        assert_eq!(
            default_ready_timeout("efi"),
            std::time::Duration::from_secs(UEFI_READY_TIMEOUT_SECS)
        );
        // Unknown values fall back to the conservative direct-kernel default.
        assert_eq!(
            default_ready_timeout("something-else"),
            std::time::Duration::from_secs(DEFAULT_READY_TIMEOUT_SECS)
        );
    }

    // ── Volume CRUD tests ────────────────────────────────────────────────────

    /// Insert a volume record directly via state (no mkfs needed) and verify
    /// that a duplicate name is rejected with `VolumeAlreadyExists`.
    #[test]
    fn create_volume_duplicate_name_rejected() {
        let state = husker_state::StateStore::open_memory().unwrap();
        let vol = husker_state::VolumeRecord {
            id: uuid::Uuid::new_v4(),
            name: "data".into(),
            file_path: "/volumes/data.img".into(),
            size_bytes: 1024 * 1024 * 1024,
            created_at: chrono::Utc::now(),
        };
        state.insert_volume(&vol).unwrap();

        // Inserting another volume with the same name must fail with VolumeAlreadyExists.
        let dup = husker_state::VolumeRecord {
            id: uuid::Uuid::new_v4(),
            name: "data".into(),
            file_path: "/volumes/data2.img".into(),
            size_bytes: 512 * 1024 * 1024,
            created_at: chrono::Utc::now(),
        };
        let err = state.insert_volume(&dup).unwrap_err();
        assert!(
            matches!(err, husker_state::StateError::VolumeAlreadyExists(_)),
            "expected VolumeAlreadyExists, got {err:?}"
        );
    }

    /// A volume that is not attached to any VM can be deleted by the core.
    /// A volume attached to a VM must be refused.
    #[test]
    fn delete_volume_refused_while_attached() {
        let state = husker_state::StateStore::open_memory().unwrap();

        // Insert a volume record.
        let vol = husker_state::VolumeRecord {
            id: uuid::Uuid::new_v4(),
            name: "mydata".into(),
            file_path: "/volumes/mydata.img".into(),
            size_bytes: 1024 * 1024 * 1024,
            created_at: chrono::Utc::now(),
        };
        state.insert_volume(&vol).unwrap();

        // Insert a VM record that references the volume.
        let vm = husker_state::VmRecord {
            id: uuid::Uuid::new_v4(),
            name: "vm-with-vol".into(),
            state: "running".into(),
            pid: None,
            vcpu_count: 1,
            mem_size_mib: 128,
            vsock_cid: 4,
            tap_device: None,
            host_ip: None,
            guest_ip: None,
            kernel_path: "/boot/vmlinux".into(),
            rootfs_path: "/images/rootfs.ext4".into(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            userdata: None,
            userdata_status: None,
            userdata_env: None,
            service_id: None,
            service_ordinal: None,
            vmm: "apple_vz".into(),
            boot_mode: "direct".into(),
            balloon: false,
            volume: Some("mydata".into()),
            network: "nat".into(),
        };
        state.insert_vm(&vm).unwrap();

        // find_vm_by_volume should find the holder.
        let holder = state.find_vm_by_volume("mydata").unwrap();
        assert!(holder.is_some(), "volume should be found as attached");
        assert_eq!(holder.unwrap().name, "vm-with-vol");
    }

    /// Volumes not referenced by any VM are detected as unattached.
    #[test]
    fn find_vm_by_volume_returns_none_when_unattached() {
        let state = husker_state::StateStore::open_memory().unwrap();

        let vol = husker_state::VolumeRecord {
            id: uuid::Uuid::new_v4(),
            name: "free-vol".into(),
            file_path: "/volumes/free.img".into(),
            size_bytes: 512 * 1024 * 1024,
            created_at: chrono::Utc::now(),
        };
        state.insert_volume(&vol).unwrap();

        let found = state.find_vm_by_volume("free-vol").unwrap();
        assert!(
            found.is_none(),
            "unattached volume must return None from find_vm_by_volume"
        );
    }

    /// `instance_request` threads the service's volume field into the VM request
    /// for both cloud and direct boot paths.
    #[test]
    fn instance_request_threads_volume_cloud() {
        let now = chrono::Utc::now();
        let svc = husker_state::ServiceRecord {
            id: uuid::Uuid::new_v4(),
            name: "svc".into(),
            host_group_id: None,
            desired_instances: 1,
            image: None,
            kernel_path: "".into(),
            rootfs_path: "".into(),
            initrd_path: None,
            vcpu_count: None,
            mem_size_mib: None,
            userdata: None,
            userdata_env: None,
            created_at: now,
            updated_at: now,
            cloud_image: Some("u24".into()),
            disk_size: None,
            balloon: false,
            volume: Some("data".into()),
        };
        let req = super::instance_request(&svc, "svc-0");
        assert_eq!(
            req.volume.as_deref(),
            Some("data"),
            "volume must be forwarded to cloud instance request"
        );
    }

    #[test]
    fn instance_request_threads_volume_direct() {
        let now = chrono::Utc::now();
        let svc = husker_state::ServiceRecord {
            id: uuid::Uuid::new_v4(),
            name: "svc".into(),
            host_group_id: None,
            desired_instances: 1,
            image: None,
            kernel_path: "/boot/vmlinux".into(),
            rootfs_path: "/images/rootfs.ext4".into(),
            initrd_path: None,
            vcpu_count: None,
            mem_size_mib: None,
            userdata: None,
            userdata_env: None,
            created_at: now,
            updated_at: now,
            cloud_image: None,
            disk_size: None,
            balloon: false,
            volume: Some("persist".into()),
        };
        let req = super::instance_request(&svc, "svc-0");
        assert_eq!(
            req.volume.as_deref(),
            Some("persist"),
            "volume must be forwarded to direct instance request"
        );
    }

    /// `CreateVmRequest` and `CreateServiceRequest` default `volume` to `None`
    /// when not present in JSON, preserving backward compatibility.
    #[test]
    fn create_vm_request_volume_defaults_to_none() {
        let req: super::CreateVmRequest = serde_json::from_str(r#"{"name":"v"}"#).unwrap();
        assert!(req.volume.is_none(), "volume must default to None");
    }

    #[test]
    fn create_service_request_volume_defaults_to_none() {
        let req: super::CreateServiceRequest =
            serde_json::from_str(r#"{"name":"svc","kernel_path":"/k","rootfs_path":"/r"}"#)
                .unwrap();
        assert!(req.volume.is_none(), "volume must default to None");
    }

    /// `create_volume` with mkfs.ext4 available: creates the sparse file and
    /// inserts the catalog record. Skips the mkfs assertion gracefully on macOS
    /// dev hosts where mkfs.ext4 is absent.
    #[tokio::test]
    async fn create_volume_full_path_when_mkfs_available() {
        // Check for mkfs.ext4; skip the destructive mkfs assertion on macOS.
        let has_mkfs = std::process::Command::new("which")
            .arg("mkfs.ext4")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        let tmp = tempfile::tempdir().unwrap();
        let state = husker_state::StateStore::open_memory().unwrap();
        let storage = husker_storage::StorageConfig {
            data_dir: tmp.path().to_path_buf(),
        };
        let runtime_dir = tmp.path().join("run");
        #[cfg(not(feature = "linux-net"))]
        let core = HuskerCore::new(
            husker_vmm::apple_vz::AppleVzBackend::new(&runtime_dir),
            state,
            storage,
            runtime_dir,
        );
        #[cfg(feature = "linux-net")]
        let core = HuskerCore::new(
            husker_vmm::firecracker::FirecrackerBackend::new(
                std::path::Path::new("firecracker"),
                &runtime_dir,
            ),
            state,
            husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
            storage,
            "husker0".into(),
            vec![],
            runtime_dir,
        );

        if !has_mkfs {
            eprintln!("create_volume test: mkfs.ext4 not found, skipping mkfs assertion");
            // Verify the name validation still works without mkfs.
            let bad = core
                .create_volume(CreateVolumeRequest {
                    name: "../escape".into(),
                    size_bytes: 1024,
                })
                .await;
            assert!(bad.is_err(), "path-traversal name must be rejected");
            return;
        }

        let req = CreateVolumeRequest {
            name: "testvol".into(),
            size_bytes: 64 * 1024 * 1024, // 64 MiB sparse
        };
        let rec = core.create_volume(req).await.unwrap();
        assert_eq!(rec.name, "testvol");
        assert_eq!(rec.size_bytes, 64 * 1024 * 1024);
        assert!(
            std::path::Path::new(&rec.file_path).exists(),
            "volume image must exist on disk"
        );

        // Duplicate must be rejected.
        let dup = core
            .create_volume(CreateVolumeRequest {
                name: "testvol".into(),
                size_bytes: 64 * 1024 * 1024,
            })
            .await;
        assert!(
            matches!(dup, Err(CoreError::VolumeAlreadyExists(_))),
            "duplicate volume must return VolumeAlreadyExists"
        );

        // get_volume round-trip.
        let fetched = core.get_volume("testvol").unwrap();
        assert_eq!(fetched.id, rec.id);

        // list_volumes includes the new volume.
        let list = core.list_volumes().unwrap();
        assert!(list.iter().any(|v| v.name == "testvol"));

        // delete_volume removes the record and the file.
        core.delete_volume("testvol").await.unwrap();
        assert!(
            !std::path::Path::new(&rec.file_path).exists(),
            "volume image must be removed after delete"
        );
        assert!(
            matches!(
                core.get_volume("testvol"),
                Err(CoreError::VolumeNotFound(_))
            ),
            "volume must not be found after delete"
        );
    }

    /// `create_service` with a non-existent volume name must fail before
    /// persisting any record, with an error message that contains the volume name.
    #[tokio::test]
    async fn create_service_unknown_volume_fails_eagerly() {
        let tmp = tempfile::tempdir().unwrap();
        let state = husker_state::StateStore::open_memory().unwrap();
        let storage = husker_storage::StorageConfig {
            data_dir: tmp.path().to_path_buf(),
        };
        let runtime_dir = tmp.path().join("run");
        #[cfg(not(feature = "linux-net"))]
        let core = std::sync::Arc::new(HuskerCore::new(
            husker_vmm::apple_vz::AppleVzBackend::new(&runtime_dir),
            state,
            storage,
            runtime_dir,
        ));
        #[cfg(feature = "linux-net")]
        let core = std::sync::Arc::new(HuskerCore::new(
            husker_vmm::firecracker::FirecrackerBackend::new(
                std::path::Path::new("firecracker"),
                &runtime_dir,
            ),
            state,
            husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
            storage,
            "husker0".into(),
            vec![],
            runtime_dir,
        ));

        let req = CreateServiceRequest {
            name: "svc-bad-vol".into(),
            host_group: None,
            desired_instances: Some(1),
            image: None,
            rootfs_path: Some("/tmp/rootfs.ext4".into()),
            kernel_path: Some("/tmp/vmlinux".into()),
            initrd_path: None,
            vcpu_count: None,
            mem_size_mib: None,
            userdata: None,
            env: vec![],
            cloud_image: None,
            disk_size: None,
            balloon: false,
            volume: Some("no-such-volume".into()),
        };

        let result = core.create_service(req).await;
        assert!(
            result.is_err(),
            "create_service with unknown volume must fail"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("no-such-volume"),
            "error message must contain the volume name, got: {msg}"
        );

        // No service record must have been inserted.
        let services = core.list_services().unwrap();
        assert!(
            services.is_empty(),
            "no service must be persisted when volume validation fails"
        );
    }

    #[tokio::test]
    async fn create_service_volume_with_multiple_instances_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let state = husker_state::StateStore::open_memory().unwrap();
        let storage = husker_storage::StorageConfig {
            data_dir: tmp.path().to_path_buf(),
        };
        let runtime_dir = tmp.path().join("run");
        #[cfg(not(feature = "linux-net"))]
        let core = std::sync::Arc::new(HuskerCore::new(
            husker_vmm::apple_vz::AppleVzBackend::new(&runtime_dir),
            state,
            storage,
            runtime_dir,
        ));
        #[cfg(feature = "linux-net")]
        let core = std::sync::Arc::new(HuskerCore::new(
            husker_vmm::firecracker::FirecrackerBackend::new(
                std::path::Path::new("firecracker"),
                &runtime_dir,
            ),
            state,
            husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
            storage,
            "husker0".into(),
            vec![],
            runtime_dir,
        ));

        let req = CreateServiceRequest {
            name: "svc-vol-multi".into(),
            host_group: None,
            desired_instances: Some(2),
            image: None,
            rootfs_path: Some("/tmp/rootfs.ext4".into()),
            kernel_path: Some("/tmp/vmlinux".into()),
            initrd_path: None,
            vcpu_count: None,
            mem_size_mib: None,
            userdata: None,
            env: vec![],
            cloud_image: None,
            disk_size: None,
            balloon: false,
            volume: Some("data".into()),
        };

        let err = core.create_service(req).await.unwrap_err();
        assert!(
            matches!(err, CoreError::InvalidArgument(_)),
            "volume + multiple instances must be InvalidArgument, got: {err:?}"
        );
        assert!(
            err.to_string().contains("exclusive"),
            "error must explain volumes are exclusive-attach, got: {err}"
        );
        let services = core.list_services().unwrap();
        assert!(
            services.is_empty(),
            "no service must be persisted when the volume/instances combination is invalid"
        );
    }

    #[tokio::test]
    async fn scale_service_with_volume_beyond_one_instance_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let state = husker_state::StateStore::open_memory().unwrap();
        std::fs::write(tmp.path().join("data.img"), b"").unwrap();
        state
            .insert_volume(&husker_state::VolumeRecord {
                id: Uuid::new_v4(),
                name: "data".into(),
                file_path: tmp.path().join("data.img").to_string_lossy().into_owned(),
                size_bytes: 1024 * 1024,
                created_at: chrono::Utc::now(),
            })
            .unwrap();
        let storage = husker_storage::StorageConfig {
            data_dir: tmp.path().to_path_buf(),
        };
        let runtime_dir = tmp.path().join("run");
        #[cfg(not(feature = "linux-net"))]
        let core = std::sync::Arc::new(HuskerCore::new(
            husker_vmm::apple_vz::AppleVzBackend::new(&runtime_dir),
            state,
            storage,
            runtime_dir,
        ));
        #[cfg(feature = "linux-net")]
        let core = std::sync::Arc::new(HuskerCore::new(
            husker_vmm::firecracker::FirecrackerBackend::new(
                std::path::Path::new("firecracker"),
                &runtime_dir,
            ),
            state,
            husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
            storage,
            "husker0".into(),
            vec![],
            runtime_dir,
        ));

        let req = CreateServiceRequest {
            name: "svc-vol-scale".into(),
            host_group: None,
            desired_instances: Some(1),
            image: None,
            rootfs_path: Some("/tmp/rootfs.ext4".into()),
            kernel_path: Some("/tmp/vmlinux".into()),
            initrd_path: None,
            vcpu_count: None,
            mem_size_mib: None,
            userdata: None,
            env: vec![],
            cloud_image: None,
            disk_size: None,
            balloon: false,
            volume: Some("data".into()),
        };
        // Instance spawn may fail (no real VMM in tests); only the record matters.
        let (record, _outcome) = core.create_service(req).await.unwrap();
        assert_eq!(record.desired_instances, 1);

        let err = core.scale_service("svc-vol-scale", 2).await.unwrap_err();
        assert!(
            matches!(err, CoreError::InvalidArgument(_)),
            "scaling a volume-backed service beyond 1 must be InvalidArgument, got: {err:?}"
        );
        let record = core.get_service("svc-vol-scale").unwrap();
        assert_eq!(
            record.desired_instances, 1,
            "desired_instances must be unchanged after a rejected scale"
        );
    }

    // ── Network mode validation ──────────────────────────────────────────────

    #[test]
    fn validate_network_mode_defaults_to_nat() {
        assert_eq!(validate_network_mode(None).unwrap(), "nat");
    }

    #[test]
    fn validate_network_mode_accepts_nat() {
        assert_eq!(validate_network_mode(Some("nat")).unwrap(), "nat");
    }

    #[test]
    fn validate_network_mode_accepts_bridged() {
        assert_eq!(validate_network_mode(Some("bridged")).unwrap(), "bridged");
    }

    #[test]
    fn validate_network_mode_rejects_unknown() {
        let err = validate_network_mode(Some("vxlan")).unwrap_err();
        assert!(
            matches!(err, CoreError::InvalidArgument(ref msg) if msg.contains("vxlan")),
            "expected InvalidArgument mentioning the unknown mode, got {err:?}"
        );
    }

    /// Bridged mode without `--cloud-image` must be rejected before any resource is allocated.
    /// Uses in-memory state so no TAP or IP allocation code is reached. The kernel and
    /// rootfs are real temp files because `create_vm` validates their existence before
    /// `try_create_vm` reaches the network-mode checks.
    #[cfg(feature = "linux-net")]
    #[tokio::test]
    async fn bridged_rejects_without_cloud_image() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel_file = tmp.path().join("vmlinux");
        let rootfs_file = tmp.path().join("rootfs.ext4");
        // Write a kernel stub with the ARM64 Image magic at offset 56 so that
        // validate_kernel_format (macOS-only) passes before the network check.
        let mut kernel_stub = vec![0u8; 64];
        kernel_stub[56..60].copy_from_slice(&[0x41, 0x52, 0x4d, 0x64]); // "ARMd" LE = 0x644d5241
        std::fs::write(&kernel_file, &kernel_stub).unwrap();
        std::fs::write(&rootfs_file, b"rootfs").unwrap();
        let state = husker_state::StateStore::open_memory().unwrap();
        let storage = husker_storage::StorageConfig {
            data_dir: tmp.path().to_path_buf(),
        };
        let runtime_dir = tmp.path().join("run");
        // Provide a lan_bridge so that precondition doesn't fire first.
        let core = HuskerCore::new(
            husker_vmm::firecracker::FirecrackerBackend::new(
                std::path::Path::new("firecracker"),
                &runtime_dir,
            ),
            state,
            husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
            storage,
            "husker0".into(),
            vec![],
            runtime_dir,
        )
        .with_lan_bridge(Some("br-lan".into()));

        let req = CreateVmRequest {
            name: "vm1".into(),
            kernel_path: Some(kernel_file),
            rootfs_path: Some(rootfs_file),
            cloud_image: None, // no cloud image - must be rejected
            network: Some("bridged".into()),
            vcpu_count: None,
            mem_size_mib: None,
            initrd_path: None,
            userdata: None,
            env: vec![],
            vmm: None,
            disk_size: None,
            ssh_authorized_keys: vec![],
            balloon: false,
            volume: None,
            mounts: vec![],
        };

        let err = core.create_vm(req).await.unwrap_err();
        assert!(
            matches!(err, CoreError::InvalidArgument(ref msg) if msg.contains("cloud-image")),
            "expected InvalidArgument mentioning cloud-image, got {err:?}"
        );
    }

    /// Bridged mode without `lan_bridge` configured must be rejected before any resource is allocated.
    #[cfg(feature = "linux-net")]
    #[tokio::test]
    async fn bridged_rejects_without_lan_bridge() {
        let tmp = tempfile::tempdir().unwrap();
        let state = husker_state::StateStore::open_memory().unwrap();
        let storage = husker_storage::StorageConfig {
            data_dir: tmp.path().to_path_buf(),
        };
        let runtime_dir = tmp.path().join("run");
        // No with_lan_bridge call -> lan_bridge stays None.
        let core = HuskerCore::new(
            husker_vmm::firecracker::FirecrackerBackend::new(
                std::path::Path::new("firecracker"),
                &runtime_dir,
            ),
            state,
            husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
            storage,
            "husker0".into(),
            vec![],
            runtime_dir,
        );

        let req = CreateVmRequest {
            name: "vm2".into(),
            kernel_path: None,
            rootfs_path: None,
            cloud_image: Some("/images/ubuntu.qcow2".into()),
            network: Some("bridged".into()),
            vcpu_count: None,
            mem_size_mib: None,
            initrd_path: None,
            userdata: None,
            env: vec![],
            vmm: None,
            disk_size: None,
            ssh_authorized_keys: vec![],
            balloon: false,
            volume: None,
            mounts: vec![],
        };

        let err = core.create_vm(req).await.unwrap_err();
        assert!(
            matches!(err, CoreError::InvalidArgument(ref msg) if msg.contains("lan_bridge")),
            "expected InvalidArgument mentioning lan_bridge, got {err:?}"
        );
    }

    /// Port-forward add on a bridged VM must be rejected with a clear message.
    #[cfg(feature = "linux-net")]
    #[tokio::test]
    async fn add_port_forward_rejects_bridged_vm() {
        let tmp = tempfile::tempdir().unwrap();
        let state = husker_state::StateStore::open_memory().unwrap();

        // Insert a bridged VM record directly (no need to actually create it).
        let vm = husker_state::VmRecord {
            id: uuid::Uuid::new_v4(),
            name: "bridged-vm".into(),
            state: "running".into(),
            pid: None,
            vcpu_count: 1,
            mem_size_mib: 512,
            vsock_cid: 10,
            tap_device: Some("husker10".into()),
            host_ip: None,
            guest_ip: None,
            kernel_path: String::new(),
            rootfs_path: "/images/ubuntu.qcow2".into(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            userdata: None,
            userdata_status: None,
            userdata_env: None,
            service_id: None,
            service_ordinal: None,
            vmm: "qemu".into(),
            boot_mode: "uefi".into(),
            balloon: false,
            volume: None,
            network: "bridged".into(),
        };
        state.insert_vm(&vm).unwrap();

        let storage = husker_storage::StorageConfig {
            data_dir: tmp.path().to_path_buf(),
        };
        let runtime_dir = tmp.path().join("run");
        let core = HuskerCore::new(
            husker_vmm::firecracker::FirecrackerBackend::new(
                std::path::Path::new("firecracker"),
                &runtime_dir,
            ),
            state,
            husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
            storage,
            "husker0".into(),
            vec![],
            runtime_dir,
        );

        let err = core
            .add_port_forward("bridged-vm", 8080, 80, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, CoreError::InvalidArgument(ref msg) if msg.contains("bridged")),
            "expected InvalidArgument mentioning bridged, got {err:?}"
        );
    }

    /// On non-linux-net builds, requesting bridged mode must fail with a
    /// Linux-only message. Uses cloud_image to bypass the host-kernel validation
    /// that runs before try_create_vm (cloud_image skips the kernel/rootfs checks).
    /// The bridged rejection fires in try_create_vm before the cloud_image check.
    #[cfg(not(feature = "linux-net"))]
    #[tokio::test]
    async fn bridged_rejected_on_non_linux_net() {
        let tmp = tempfile::tempdir().unwrap();
        let state = husker_state::StateStore::open_memory().unwrap();
        let storage = husker_storage::StorageConfig {
            data_dir: tmp.path().to_path_buf(),
        };
        let runtime_dir = tmp.path().join("run");
        let core = HuskerCore::new(
            husker_vmm::apple_vz::AppleVzBackend::new(&runtime_dir),
            state,
            storage,
            runtime_dir,
        );

        // cloud_image is set so the kernel/rootfs host-path check is skipped in
        // create_vm_record. The bridged rejection in try_create_vm fires first.
        let req = CreateVmRequest {
            name: "vm3".into(),
            kernel_path: None,
            rootfs_path: None,
            cloud_image: Some("/images/ubuntu.qcow2".into()),
            network: Some("bridged".into()),
            vcpu_count: None,
            mem_size_mib: None,
            initrd_path: None,
            userdata: None,
            env: vec![],
            vmm: None,
            disk_size: None,
            ssh_authorized_keys: vec![],
            balloon: false,
            volume: None,
            mounts: vec![],
        };

        let err = core.create_vm(req).await.unwrap_err();
        assert!(
            matches!(err, CoreError::InvalidArgument(ref msg) if msg.contains("Linux")),
            "expected InvalidArgument mentioning Linux, got {err:?}"
        );
    }

    // ── macOS cloud-image path tests ─────────────────────────────────────────

    /// Helper: write a file with valid qcow2 magic (4-byte header + padding).
    #[cfg(not(feature = "linux-net"))]
    fn write_qcow2_magic(dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("test.qcow2");
        let mut data = vec![0u8; 512];
        data[..4].copy_from_slice(&[0x51, 0x46, 0x49, 0xfb]);
        std::fs::write(&path, &data).unwrap();
        path
    }

    /// Helper: build a HuskerCore for the non-linux-net (Apple VZ) path.
    #[cfg(not(feature = "linux-net"))]
    fn make_vz_core(
        state: husker_state::StateStore,
        tmp: &std::path::Path,
    ) -> HuskerCore<husker_vmm::apple_vz::AppleVzBackend> {
        let storage = husker_storage::StorageConfig {
            data_dir: tmp.to_path_buf(),
        };
        let runtime_dir = tmp.join("run");
        HuskerCore::new(
            husker_vmm::apple_vz::AppleVzBackend::new(&runtime_dir),
            state,
            storage,
            runtime_dir,
        )
    }

    /// Helper: a running NAT VM record with a discovered guest IP, for the
    /// macOS userspace port-forward tests.
    #[cfg(not(feature = "linux-net"))]
    fn running_nat_vm(name: &str) -> husker_state::VmRecord {
        husker_state::VmRecord {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            state: "running".into(),
            pid: None,
            vcpu_count: 1,
            mem_size_mib: 128,
            vsock_cid: 3,
            tap_device: None,
            host_ip: None,
            guest_ip: Some("127.0.0.1".into()),
            kernel_path: String::new(),
            rootfs_path: "/images/ubuntu.qcow2".into(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            userdata: None,
            userdata_status: None,
            userdata_env: None,
            service_id: None,
            service_ordinal: None,
            vmm: "apple_vz".into(),
            boot_mode: "efi".into(),
            balloon: false,
            volume: None,
            network: "nat".into(),
        }
    }

    /// macOS: adding a forward to a non-running VM is a state conflict.
    #[cfg(not(feature = "linux-net"))]
    #[tokio::test]
    async fn add_port_forward_rejects_non_running_vm() {
        let tmp = tempfile::tempdir().unwrap();
        let state = husker_state::StateStore::open_memory().unwrap();
        let mut vm = running_nat_vm("pf-stopped");
        vm.state = "stopped".into();
        state.insert_vm(&vm).unwrap();
        let core = make_vz_core(state, tmp.path());
        let err = core
            .add_port_forward("pf-stopped", 18080, 80, None)
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::InvalidState { .. }));
    }

    /// macOS: a running VM without a discovered guest IP is a state conflict.
    #[cfg(not(feature = "linux-net"))]
    #[tokio::test]
    async fn add_port_forward_rejects_missing_guest_ip() {
        let tmp = tempfile::tempdir().unwrap();
        let state = husker_state::StateStore::open_memory().unwrap();
        let mut vm = running_nat_vm("pf-noip");
        vm.guest_ip = None;
        state.insert_vm(&vm).unwrap();
        let core = make_vz_core(state, tmp.path());
        let err = core
            .add_port_forward("pf-noip", 18081, 80, None)
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::InvalidState { .. }));
    }

    /// macOS: destroying a VM aborts its userspace proxy listeners and drops the
    /// forward rows. Proven by the bound host port becoming free again.
    #[cfg(not(feature = "linux-net"))]
    #[tokio::test]
    async fn destroy_vm_tears_down_port_forwards() {
        let tmp = tempfile::tempdir().unwrap();
        let state = husker_state::StateStore::open_memory().unwrap();
        state.insert_vm(&running_nat_vm("pf-td")).unwrap();
        let core = make_vz_core(state, tmp.path());
        // Reserve a concrete free port, then release it so the proxy can bind it.
        let host_port = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        // add only binds a host listener (no vmm call, no dial until a connection
        // arrives), so it succeeds without a live backend VM.
        core.add_port_forward("pf-td", host_port, 5, None)
            .await
            .unwrap();
        assert_eq!(core.list_port_forwards("pf-td").unwrap().len(), 1);
        // The proxy holds the port now: a re-bind must fail.
        assert!(std::net::TcpListener::bind(("127.0.0.1", host_port)).is_err());

        core.destroy_vm("pf-td").await.unwrap();

        // The listener abort is async; poll briefly until the port frees.
        let mut freed = false;
        for _ in 0..50 {
            if std::net::TcpListener::bind(("127.0.0.1", host_port)).is_ok() {
                freed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            freed,
            "host port should be free after destroy aborts the proxy listener"
        );
    }

    /// macOS: removing a forward via the wrong VM must not drop the owning VM's
    /// row or orphan its listener (`delete_port_forward` keys on host_port).
    #[cfg(not(feature = "linux-net"))]
    #[tokio::test]
    async fn remove_port_forward_scoped_to_owning_vm() {
        let tmp = tempfile::tempdir().unwrap();
        let state = husker_state::StateStore::open_memory().unwrap();
        let a = running_nat_vm("vm-a");
        let mut b = running_nat_vm("vm-b");
        b.vsock_cid = 4;
        state.insert_vm(&a).unwrap();
        state.insert_vm(&b).unwrap();
        let core = make_vz_core(state, tmp.path());
        let host_port = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        core.add_port_forward("vm-a", host_port, 80, None)
            .await
            .unwrap();
        // Wrong-VM remove must be a no-op for vm-a's forward.
        core.remove_port_forward("vm-b", host_port).await.unwrap();
        assert_eq!(
            core.list_port_forwards("vm-a").unwrap().len(),
            1,
            "vm-a forward must survive a wrong-VM remove"
        );
        assert!(
            std::net::TcpListener::bind(("127.0.0.1", host_port)).is_err(),
            "vm-a listener must still hold the port"
        );
        // Removing via the owning VM works.
        core.remove_port_forward("vm-a", host_port).await.unwrap();
        assert!(core.list_port_forwards("vm-a").unwrap().is_empty());
    }

    /// macOS: the same host port with a different bind address is a conflict
    /// (not silently idempotent); the same bind is idempotent.
    #[cfg(not(feature = "linux-net"))]
    #[tokio::test]
    async fn add_port_forward_same_port_different_bind_conflicts() {
        let tmp = tempfile::tempdir().unwrap();
        let state = husker_state::StateStore::open_memory().unwrap();
        state.insert_vm(&running_nat_vm("vm-c")).unwrap();
        let core = make_vz_core(state, tmp.path());
        let host_port = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let all: std::net::IpAddr = "0.0.0.0".parse().unwrap();
        core.add_port_forward("vm-c", host_port, 80, Some(loopback))
            .await
            .unwrap();
        // Different bind on the same host port -> conflict.
        let err = core
            .add_port_forward("vm-c", host_port, 80, Some(all))
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::PortForwardConflict(_)));
        // Same bind -> idempotent.
        let rec = core
            .add_port_forward("vm-c", host_port, 80, Some(loopback))
            .await
            .unwrap();
        assert_eq!(rec.host_port, host_port);
    }

    /// cloud-image + volume must be rejected before any disk I/O.
    #[cfg(not(feature = "linux-net"))]
    #[tokio::test]
    async fn cloud_image_with_volume_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let image_path = write_qcow2_magic(tmp.path());
        let state = husker_state::StateStore::open_memory().unwrap();
        let core = make_vz_core(state, tmp.path());

        let req = CreateVmRequest {
            name: "vm-vol".into(),
            kernel_path: None,
            rootfs_path: None,
            cloud_image: Some(image_path.to_string_lossy().into_owned()),
            volume: Some("data".into()),
            vcpu_count: None,
            mem_size_mib: None,
            initrd_path: None,
            userdata: None,
            env: vec![],
            vmm: None,
            disk_size: None,
            ssh_authorized_keys: vec![],
            balloon: false,
            network: None,
            mounts: vec![],
        };

        let err = core.create_vm(req).await.unwrap_err();
        assert!(
            matches!(err, CoreError::InvalidArgument(ref msg) if msg.contains("volume")),
            "expected InvalidArgument mentioning volume, got {err:?}"
        );
        assert!(
            core.list_vms().unwrap().is_empty(),
            "no VM should be persisted on rejection"
        );
    }

    /// cloud-image without the embedded agent must be rejected with a clear message.
    #[cfg(not(feature = "linux-net"))]
    #[tokio::test]
    async fn cloud_image_with_empty_agent_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let image_path = write_qcow2_magic(tmp.path());
        let state = husker_state::StateStore::open_memory().unwrap();
        // Core built WITHOUT with_embedded_agent -> embedded_agent is &[].
        let core = make_vz_core(state, tmp.path());

        let req = CreateVmRequest {
            name: "vm-noagent".into(),
            kernel_path: None,
            rootfs_path: None,
            cloud_image: Some(image_path.to_string_lossy().into_owned()),
            volume: None,
            vcpu_count: None,
            mem_size_mib: None,
            initrd_path: None,
            userdata: None,
            env: vec![],
            vmm: None,
            disk_size: None,
            ssh_authorized_keys: vec![],
            balloon: false,
            network: None,
            mounts: vec![],
        };

        let err = core.create_vm(req).await.unwrap_err();
        assert!(
            matches!(err, CoreError::InvalidArgument(ref msg) if msg.contains("embedded guest agent")),
            "expected InvalidArgument mentioning embedded guest agent, got {err:?}"
        );
        assert!(
            core.list_vms().unwrap().is_empty(),
            "no VM should be persisted on rejection"
        );
    }

    /// A file without qcow2 magic must be rejected as InvalidCloudImage.
    #[cfg(not(feature = "linux-net"))]
    #[tokio::test]
    async fn cloud_image_bad_magic_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let bad_path = tmp.path().join("bad.img");
        std::fs::write(&bad_path, b"not a qcow").unwrap();
        let state = husker_state::StateStore::open_memory().unwrap();
        let core = make_vz_core(state, tmp.path()).with_embedded_agent(b"fake-agent");

        let req = CreateVmRequest {
            name: "vm-badmagic".into(),
            kernel_path: None,
            rootfs_path: None,
            cloud_image: Some(bad_path.to_string_lossy().into_owned()),
            volume: None,
            vcpu_count: None,
            mem_size_mib: None,
            initrd_path: None,
            userdata: None,
            env: vec![],
            vmm: None,
            disk_size: None,
            ssh_authorized_keys: vec![],
            balloon: false,
            network: None,
            mounts: vec![],
        };

        let err = core.create_vm(req).await.unwrap_err();
        assert!(
            matches!(
                err,
                CoreError::Storage(husker_storage::StorageError::InvalidCloudImage(_))
            ),
            "expected Storage(InvalidCloudImage), got {err:?}"
        );
        assert!(
            core.list_vms().unwrap().is_empty(),
            "no VM should be persisted on rejection"
        );
    }

    /// A failed qemu-img convert must roll back the vm_dir so no partial disk
    /// is left on disk and no VM record is persisted.
    #[cfg(not(feature = "linux-net"))]
    #[tokio::test]
    async fn cloud_image_conversion_failure_rolls_back_vm_dir() {
        // qemu-img is required; skip cleanly if unavailable (dev hosts without it).
        fn qemu_img_available() -> bool {
            std::process::Command::new("qemu-img")
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
        if !qemu_img_available() {
            eprintln!(
                "skipping cloud_image_conversion_failure_rolls_back_vm_dir: qemu-img not installed"
            );
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        // Write a file with valid qcow2 magic but a truncated/garbage body so
        // validate_cloud_image passes but qemu-img convert fails.
        let bad_qcow2 = tmp.path().join("bad_body.qcow2");
        let mut data = vec![0xffu8; 64]; // garbage body
        data[..4].copy_from_slice(&[0x51, 0x46, 0x49, 0xfb]); // valid magic
        std::fs::write(&bad_qcow2, &data).unwrap();

        let state = husker_state::StateStore::open_memory().unwrap();
        let core = make_vz_core(state, tmp.path()).with_embedded_agent(b"fake-agent");

        let vm_name = "vm-rollback";
        let req = CreateVmRequest {
            name: vm_name.into(),
            kernel_path: None,
            rootfs_path: None,
            cloud_image: Some(bad_qcow2.to_string_lossy().into_owned()),
            volume: None,
            vcpu_count: None,
            mem_size_mib: None,
            initrd_path: None,
            userdata: None,
            env: vec![],
            vmm: None,
            disk_size: None,
            ssh_authorized_keys: vec![],
            balloon: false,
            network: None,
            mounts: vec![],
        };

        let err = core.create_vm(req).await;
        assert!(err.is_err(), "expected error from corrupt qcow2");

        // The vm_dir must not exist after rollback.
        let vm_dir = tmp.path().join("vms").join(vm_name);
        assert!(
            !vm_dir.exists(),
            "vm_dir should be removed by rollback, but it still exists at {}",
            vm_dir.display()
        );

        // No VM record should be persisted.
        assert!(
            core.list_vms().unwrap().is_empty(),
            "no VM should be persisted after a failed create"
        );
    }

    /// create_service with cloud_image on macOS must be rejected eagerly.
    #[cfg(not(feature = "linux-net"))]
    #[tokio::test]
    async fn service_with_cloud_image_rejected_on_macos() {
        let tmp = tempfile::tempdir().unwrap();
        let state = husker_state::StateStore::open_memory().unwrap();
        let core = std::sync::Arc::new(make_vz_core(state, tmp.path()));

        let req = CreateServiceRequest {
            name: "svc-cloud".into(),
            kernel_path: None,
            rootfs_path: None,
            image: None,
            cloud_image: Some("/images/ubuntu.qcow2".into()),
            disk_size: None,
            vcpu_count: None,
            mem_size_mib: None,
            initrd_path: None,
            userdata: None,
            env: vec![],
            desired_instances: None,
            balloon: false,
            volume: None,
            host_group: None,
        };

        let err = core.create_service(req).await.unwrap_err();
        assert!(
            matches!(err, CoreError::InvalidArgument(ref msg) if msg.contains("macOS")),
            "expected InvalidArgument mentioning macOS, got {err:?}"
        );
        assert!(
            core.list_services().unwrap().is_empty(),
            "no service should be persisted on rejection"
        );
    }

    // ── Default-image resolution (Part A, remote-client fix) ────────────────

    /// A create request with no kernel or rootfs but with daemon defaults set
    /// must pass validation (the daemon fills in its own paths).
    ///
    /// Note: driving create_vm_record to completion in the non-linux test harness
    /// requires a real VMM process, which is unavailable in unit tests. Instead we
    /// assert that the early validation error ("no kernel specified") is NOT
    /// returned when defaults are wired — the error boundary we can reliably exercise
    /// without a running VMM.
    #[cfg(not(feature = "linux-net"))]
    #[tokio::test]
    async fn default_images_fill_missing_kernel_and_rootfs() {
        let tmp = tempfile::tempdir().unwrap();
        let state = husker_state::StateStore::open_memory().unwrap();
        let runtime_dir = tmp.path().join("run");
        let storage = husker_storage::StorageConfig {
            data_dir: tmp.path().to_path_buf(),
        };

        // Create minimal real files so validate_kernel / validate_rootfs pass.
        // On macOS, validate_kernel checks the ARM64 Image magic at offset 56.
        let kernel_path = tmp.path().join("vmlinux");
        let mut kernel_stub = vec![0u8; 64];
        kernel_stub[56..60].copy_from_slice(&[0x41, 0x52, 0x4d, 0x64]); // ARM64 magic LE
        std::fs::write(&kernel_path, &kernel_stub).unwrap();

        let rootfs_path = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs_path, b"rootfs").unwrap();

        let core = HuskerCore::new(
            husker_vmm::apple_vz::AppleVzBackend::new(&runtime_dir),
            state,
            storage,
            runtime_dir,
        )
        .with_default_images(Some(kernel_path.clone()), Some(rootfs_path.clone()), None);

        // A request with no explicit kernel/rootfs should not return the
        // "no kernel specified" error; it should get past validation and
        // fail at a later stage (VMM not running), not at the path-check.
        let req = CreateVmRequest {
            name: "test-defaults".into(),
            kernel_path: None,
            rootfs_path: None,
            initrd_path: None,
            cloud_image: None,
            vcpu_count: None,
            mem_size_mib: None,
            userdata: None,
            env: vec![],
            vmm: None,
            disk_size: None,
            ssh_authorized_keys: vec![],
            balloon: false,
            volume: None,
            network: None,
            mounts: vec![],
        };

        let err = core.create_vm_record(req, None, true).await.unwrap_err();
        // Must NOT be "no kernel specified" - that would mean defaults weren't applied.
        let msg = err.to_string();
        assert!(
            !msg.contains("no kernel specified"),
            "daemon defaults should have filled the kernel; got: {msg}"
        );
        assert!(
            !msg.contains("no rootfs specified"),
            "daemon defaults should have filled the rootfs; got: {msg}"
        );
    }

    /// A create request with no kernel/rootfs and NO daemon defaults must return
    /// a clear InvalidArgument error — not a panic or a misleading message.
    #[cfg(not(feature = "linux-net"))]
    #[tokio::test]
    async fn missing_kernel_without_defaults_returns_invalid_argument() {
        let tmp = tempfile::tempdir().unwrap();
        let state = husker_state::StateStore::open_memory().unwrap();
        let core = make_vz_core(state, tmp.path());

        let req = CreateVmRequest {
            name: "test-no-defaults".into(),
            kernel_path: None,
            rootfs_path: None,
            initrd_path: None,
            cloud_image: None,
            vcpu_count: None,
            mem_size_mib: None,
            userdata: None,
            env: vec![],
            vmm: None,
            disk_size: None,
            ssh_authorized_keys: vec![],
            balloon: false,
            volume: None,
            network: None,
            mounts: vec![],
        };

        let err = core.create_vm_record(req, None, true).await.unwrap_err();
        assert!(
            matches!(err, CoreError::InvalidArgument(ref msg) if msg.contains("no kernel specified")),
            "expected InvalidArgument with 'no kernel specified', got: {err:?}"
        );
    }

    /// Regression: the client omits unspecified paths, so `create_service` must
    /// fall back to the daemon's default kernel/rootfs (like create_vm_record)
    /// instead of rejecting the request with "service requires a kernel/rootfs".
    #[cfg(not(feature = "linux-net"))]
    #[tokio::test]
    async fn create_service_uses_daemon_default_images() {
        let tmp = tempfile::tempdir().unwrap();
        let state = husker_state::StateStore::open_memory().unwrap();
        let runtime_dir = tmp.path().join("run");
        let storage = husker_storage::StorageConfig {
            data_dir: tmp.path().to_path_buf(),
        };

        let kernel_path = tmp.path().join("vmlinux");
        let mut kernel_stub = vec![0u8; 64];
        kernel_stub[56..60].copy_from_slice(&[0x41, 0x52, 0x4d, 0x64]); // ARM64 magic LE
        std::fs::write(&kernel_path, &kernel_stub).unwrap();
        let rootfs_path = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs_path, b"rootfs").unwrap();

        let core = HuskerCore::new(
            husker_vmm::apple_vz::AppleVzBackend::new(&runtime_dir),
            state,
            storage,
            runtime_dir,
        )
        .with_default_images(Some(kernel_path.clone()), Some(rootfs_path.clone()), None);

        let req = CreateServiceRequest {
            name: "svc-defaults".into(),
            host_group: None,
            desired_instances: Some(0),
            image: None,
            rootfs_path: None,
            kernel_path: None,
            initrd_path: None,
            vcpu_count: None,
            mem_size_mib: None,
            userdata: None,
            env: vec![],
            cloud_image: None,
            disk_size: None,
            balloon: false,
            volume: None,
        };

        // Must not be rejected for a missing kernel/rootfs - the daemon defaults
        // fill them. (It may still fail later in the test harness; we only assert
        // the path-requirement gate is not what rejected it.)
        if let Err(e) = std::sync::Arc::new(core).create_service(req).await {
            let msg = e.to_string();
            assert!(
                !msg.contains("service requires a"),
                "daemon defaults should have filled the service kernel/rootfs; got: {msg}"
            );
        }
    }

    #[test]
    fn parse_mount_spec_defaults_and_ro() {
        let s = parse_mount_spec("/srv/work", 0).unwrap();
        assert_eq!(
            (
                s.host.as_path(),
                s.guest.as_str(),
                s.read_only,
                s.tag.as_str()
            ),
            (std::path::Path::new("/srv/work"), "/mnt/work", false, "fs0")
        );
        let s = parse_mount_spec("/srv/work:/build:ro", 2).unwrap();
        assert_eq!(
            (
                s.host.as_path(),
                s.guest.as_str(),
                s.read_only,
                s.tag.as_str()
            ),
            (std::path::Path::new("/srv/work"), "/build", true, "fs2")
        );
    }

    #[test]
    fn parse_mount_spec_two_part_ro_shorthand() {
        // Two-part spec with second part exactly "ro" means host + read-only + default guest.
        let s = parse_mount_spec("/data:ro", 1).unwrap();
        assert_eq!(s.host.as_path(), std::path::Path::new("/data"));
        assert_eq!(s.guest, "/mnt/data");
        assert!(s.read_only);
        assert_eq!(s.tag, "fs1");
    }

    #[test]
    fn parse_mount_spec_two_part_custom_guest_rw() {
        let s = parse_mount_spec("/host/src:/workspace", 3).unwrap();
        assert_eq!(s.host.as_path(), std::path::Path::new("/host/src"));
        assert_eq!(s.guest, "/workspace");
        assert!(!s.read_only);
        assert_eq!(s.tag, "fs3");
    }

    #[test]
    fn parse_mount_spec_errors() {
        // Relative host path.
        assert!(parse_mount_spec("relative/path:/guest", 0).is_err());
        // Empty host path.
        assert!(parse_mount_spec(":/guest", 0).is_err());
        // Non-absolute guest path.
        assert!(parse_mount_spec("/host:relative/guest", 0).is_err());
        // Unknown trailing option.
        assert!(parse_mount_spec("/host:/guest:rw", 0).is_err());
        // Host path with ".." component.
        assert!(parse_mount_spec("/host/../etc:/guest", 0).is_err());
    }
}
