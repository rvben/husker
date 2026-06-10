//! Core orchestration layer for VM lifecycle, agent connectivity, and recovery logic.

pub mod agent_client;

#[cfg(feature = "linux-net")]
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use husker_vmm::VmmBackend;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use uuid::Uuid;

pub use husker_state::{
    HostGroupRecord, ImageRecord, SecretRecord, ServiceRecord, SnapshotRecord, VmRecord,
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
    #[error("snapshot not found: {0}")]
    SnapshotNotFound(String),
    #[error("snapshot already exists: {0}")]
    SnapshotAlreadyExists(String),
    #[error("image not found: {0}")]
    ImageNotFound(String),
    #[error("image already exists: {0}")]
    ImageAlreadyExists(String),
    #[error("secret not found: {0}")]
    SecretNotFound(String),
    #[error("secret already exists: {0}")]
    SecretAlreadyExists(String),
    #[error("secret crypto error: {0}")]
    SecretCrypto(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("service operation failed: {0}")]
    ServiceOperationFailed(String),
    #[error("VMM error: {0}")]
    Vmm(#[from] husker_vmm::VmmError),
    #[cfg(feature = "linux-net")]
    #[error("network error: {0}")]
    Network(#[from] husker_net::NetError),
    #[cfg(feature = "linux-net")]
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
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub kernel_path: PathBuf,
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub rootfs_path: PathBuf,
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

/// Kill VMM child processes orphaned by a previous daemon that exited without
/// cleanup (SIGKILL/OOM). At startup, any VM still marked `running`/`paused` in
/// the DB is an orphan (a clean shutdown drains + marks them stopped). For each,
/// SIGKILL its recorded pid only if it is still a live `qemu-system` process
/// (so a recycled PID is never touched). Must run BEFORE mark_stale_vms_stopped.
/// Returns the number reaped.
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
        // /proc/<pid>/cmdline confirms liveness + identity; only a live
        // qemu-system process is killed (never a recycled non-qemu PID).
        let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        if cmdline.contains("qemu-system")
            && unsafe { libc::kill(pid as i32, libc::SIGKILL) } == 0
        {
            reaped += 1;
            warn!(pid, vm = %vm.name, "reaped orphaned qemu process from a prior daemon");
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
    #[cfg(feature = "linux-net")]
    embedded_agent: &'static [u8],
    #[cfg(feature = "linux-net")]
    bridge_name: String,
    #[cfg(feature = "linux-net")]
    dns_servers: Vec<String>,
    runtime_dir: PathBuf,
    /// Per-VM-name locks guarding the create/destroy critical section.
    vm_name_locks: std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Per-service reconcile locks; serialize concurrent reconciles of the same service.
    reconcile_locks: std::sync::Mutex<std::collections::HashMap<Uuid, Arc<tokio::sync::Mutex<()>>>>,
}

/// Per-attempt timeout for agent connect+ping in readiness loops.
const AGENT_PING_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

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
            dns_servers,
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
            runtime_dir,
            vm_name_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
            reconcile_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Provide the embedded guest agent used to build cloud-init seeds. Empty (the
    /// default) disables cloud-image support with a clear error at create time.
    #[cfg(feature = "linux-net")]
    pub fn with_embedded_agent(mut self, agent: &'static [u8]) -> Self {
        self.embedded_agent = agent;
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

    /// Internal/advanced: prefer `create_vm`. Used by the reconciler to stamp service ownership.
    ///
    /// `tags` stamps service ownership atomically onto the new VM record.
    /// `replace_existing_stopped` controls whether an existing stopped/failed
    /// same-named VM is auto-replaced (public API: true; reconciler: false to
    /// avoid clobbering a foreign stopped VM).
    pub async fn create_vm_record(
        &self,
        req: CreateVmRequest,
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
            husker_storage::validate_kernel(&req.kernel_path)?;
            husker_storage::validate_rootfs(&req.rootfs_path)?;
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
        let guest_ip = self.ip_allocator.allocate()?;
        resources.guest_ip = Some(guest_ip);

        let cid = self.state.allocate_cid()?;
        resources.cid = Some(cid);

        let tap_name = format!("husker{cid}");
        let mac = husker_net::generate_mac(cid);
        let gateway = self.ip_allocator.gateway();
        let netmask = husker_net::prefix_len_to_netmask(self.ip_allocator.prefix_len());
        debug!(tap = %tap_name, %guest_ip, %gateway, cid, "resources allocated");

        husker_net::create_tap(&tap_name).await?;
        resources.tap_name = Some(tap_name.clone());

        husker_net::attach_to_bridge(&tap_name, &self.bridge_name).await?;

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

        // Choose the boot disk + mode. A cloud image boots via UEFI/OVMF from a cloned
        // qcow2; the default path boots a host kernel from a raw ext4 rootfs.
        let (disk_path, boot, is_cloud, seed_path) = if let Some(image) = req.cloud_image.as_ref() {
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
                image,
                req.disk_size,
                &disk,
                &self.ovmf_code_path,
                &self.ovmf_vars_template_path,
            )
            .await?;
            // Build the NoCloud seed: install + start the embedded agent and apply a
            // static network config (husker's allocated IP) so cloud-init does not
            // stall on DHCP before the agent comes up.
            let seed = husker_cloudinit::build_seed(&husker_cloudinit::SeedSpec {
                agent: self.embedded_agent,
                hostname: req.name.clone(),
                instance_id: req.name.clone(),
                ssh_authorized_keys: Vec::new(),
                network: husker_cloudinit::NetworkConfig {
                    ip: guest_ip,
                    prefix_len: self.ip_allocator.prefix_len(),
                    gateway,
                    dns: self.dns_servers.clone(),
                },
            })?;
            let seed_path = vm_dir.join("seed.img");
            tokio::fs::write(&seed_path, &seed)
                .await
                .map_err(|e| CoreError::Storage(husker_storage::StorageError::Io(e)))?;
            (disk, boot, true, Some(seed_path))
        } else {
            let vm_rootfs = vm_dir.join("rootfs.ext4");
            self.storage_driver
                .clone_rootfs(&req.rootfs_path, &vm_rootfs)
                .await?;
            (vm_rootfs, husker_vmm::BootMode::DirectKernel, false, None)
        };

        // resolv.conf injection loop-mounts the ext4 rootfs; skip it for qcow2 cloud
        // images, which are not ext4. Cloud images configure DNS via cloud-init at boot.
        if !is_cloud && !self.dns_servers.is_empty() {
            inject_resolv_conf(&disk_path, &self.dns_servers).await?;
        }

        let vmm_kind = if is_cloud {
            Some(husker_vmm::VmmKind::Qemu)
        } else {
            match req.vmm.as_deref() {
                Some(s) => Some(s.parse::<husker_vmm::VmmKind>().map_err(CoreError::Vmm)?),
                None => None,
            }
        };

        let vm_config = husker_vmm::VmConfig {
            name: req.name.clone(),
            vcpu_count: req.vcpu_count.unwrap_or(1),
            mem_size_mib: req.mem_size_mib.unwrap_or(128),
            kernel_path: req.kernel_path.clone(),
            rootfs_path: disk_path,
            kernel_args: if is_cloud {
                None
            } else {
                Some(format!(
                    "console=ttyS0 reboot=k panic=1 pci=off \
                     ip={guest_ip}::{gateway}:{netmask}::eth0:off"
                ))
            },
            initrd_path: req.initrd_path.clone(),
            vsock_cid: cid,
            tap_device: Some(tap_name.clone()),
            guest_mac: Some(mac),
            vmm: vmm_kind,
            boot,
            seed_path,
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
            tap_device: Some(tap_name),
            // host_ip stores the bridge gateway — the same for all VMs in the subnet.
            // Kept for CLI display and API responses (shows the default gateway).
            host_ip: Some(gateway.to_string()),
            guest_ip: Some(guest_ip.to_string()),
            kernel_path: req.kernel_path.to_string_lossy().into_owned(),
            rootfs_path: req.rootfs_path.to_string_lossy().into_owned(),
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
            vmm: vmm_kind.map(|k| k.to_string()).unwrap_or_else(|| "firecracker".to_string()),
            boot_mode: if is_cloud { "uefi".to_string() } else { "direct".to_string() },
        };

        self.state.insert_vm(&record).map_err(|e| match e {
            husker_state::StateError::VmAlreadyExists(name) => CoreError::VmAlreadyExists(name),
            other => CoreError::State(other),
        })?;

        Ok(record)
    }

    /// Inner create logic without host networking.
    ///
    /// Networking is handled by the VMM backend (e.g. VZ NAT).
    #[cfg(not(feature = "linux-net"))]
    async fn try_create_vm(
        &self,
        req: CreateVmRequest,
        tags: Option<ServiceTag>,
        resources: &mut AllocatedResources,
    ) -> Result<VmRecord, CoreError> {
        if req.cloud_image.is_some() {
            return Err(CoreError::InvalidArgument(
                "cloud-image boot is only supported on Linux with the QEMU backend".into(),
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
        let vm_rootfs = vm_dir.join("rootfs.ext4");
        self.storage_driver
            .clone_rootfs(&req.rootfs_path, &vm_rootfs)
            .await?;
        resources.vm_dir = Some(vm_dir);

        // Resolve initrd: use explicit path, or look for conventional location
        let initrd_path = req.initrd_path.clone().or_else(|| {
            let conventional = self.storage.data_dir.join("kernels/initramfs-virt.gz");
            conventional.exists().then_some(conventional)
        });

        let vm_config = husker_vmm::VmConfig {
            name: req.name.clone(),
            vcpu_count: req.vcpu_count.unwrap_or(1),
            mem_size_mib: req.mem_size_mib.unwrap_or(128),
            kernel_path: req.kernel_path.clone(),
            rootfs_path: vm_rootfs,
            kernel_args: Some("console=hvc0 root=/dev/vda rw init=/sbin/init".into()),
            initrd_path,
            vsock_cid: cid,
            tap_device: None,
            guest_mac: None,
            vmm: None,
            boot: husker_vmm::BootMode::DirectKernel,
            seed_path: None,
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
            kernel_path: req.kernel_path.to_string_lossy().into_owned(),
            rootfs_path: req.rootfs_path.to_string_lossy().into_owned(),
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
        let record = self.lookup_vm(name)?;
        match record.state.as_str() {
            "running" | "paused" => {}
            "stopped" => {
                debug!(%name, "VM already stopped; stop is a no-op");
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

    /// Resume a paused VM.
    ///
    /// Idempotent: resuming an already running VM is a no-op.
    pub async fn resume_vm(&self, name: &str) -> Result<(), CoreError> {
        info!(%name, "resuming VM");
        let record = self.lookup_vm(name)?;
        match record.state.as_str() {
            "paused" => {}
            "running" => {
                debug!(%name, "VM already running; resume is a no-op");
                return Ok(());
            }
            _ => {
                return Err(CoreError::InvalidState {
                    name: name.into(),
                    actual: record.state,
                    expected: "paused".into(),
                });
            }
        }
        self.vmm.resume_vm(record.id).await?;
        self.state.update_vm_state(record.id, "running")?;
        Ok(())
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

        self.state.delete_vm(record.id)?;
        info!(%name, "VM destroyed");
        Ok(())
    }

    /// List all VMs.
    pub fn list_vms(&self) -> Result<Vec<VmRecord>, CoreError> {
        Ok(self.state.list_vms()?)
    }

    /// Get info about a specific VM.
    pub fn get_vm(&self, name: &str) -> Result<VmRecord, CoreError> {
        self.lookup_vm(name)
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

        let rootfs = req.rootfs_path.ok_or_else(|| {
            CoreError::InvalidArgument("service requires a rootfs (--image or --rootfs)".into())
        })?;
        let kernel = req
            .kernel_path
            .ok_or_else(|| CoreError::InvalidArgument("service requires a kernel".into()))?;

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
            kernel_path: req.kernel_path,
            rootfs_path: PathBuf::from(snapshot.file_path),
            vcpu_count: req.vcpu_count,
            mem_size_mib: req.mem_size_mib,
            initrd_path: req.initrd_path,
            userdata: req.userdata,
            env: req.env,
            vmm: None,
            cloud_image: None,
            disk_size: None,
        })
        .await
    }

    /// Import a rootfs image into the managed image catalog.
    pub async fn import_image(&self, req: ImportImageRequest) -> Result<ImageRecord, CoreError> {
        validate_resource_name("image", &req.name)?;
        validate_host_path("import source", &req.source_path)?;
        match self.state.get_image_by_name(&req.name) {
            Ok(_) => return Err(CoreError::ImageAlreadyExists(req.name)),
            Err(husker_state::StateError::ImageNotFoundByName(_)) => {}
            Err(other) => return Err(CoreError::State(other)),
        }

        husker_storage::validate_rootfs(&req.source_path)?;

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
        let record = ImageRecord {
            id: Uuid::new_v4(),
            name: req.name.clone(),
            source_path: req.source_path.to_string_lossy().into_owned(),
            file_path: image_path.to_string_lossy().into_owned(),
            format: req
                .format
                .unwrap_or_else(|| infer_image_format(&req.source_path)),
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
                    crate::agent_client::AgentError::NotReady(timeout),
                ));
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(max_backoff);
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
    /// Retries agent connection with exponential backoff (up to 120s total),
    /// writes the script to `/tmp/husker-userdata.sh`, executes it via `sh`,
    /// and updates `userdata_status` to `completed` or `failed`.
    pub async fn run_userdata(&self, name: &str) -> Result<(), CoreError> {
        let record = self.lookup_vm(name)?;
        let script = match record.userdata {
            Some(ref s) => s.clone(),
            None => return Ok(()),
        };

        self.state.update_userdata_status(record.id, "running")?;

        let result: Result<(), CoreError> = async {
            let mut conn = self
                .agent_connect_ready(name, std::time::Duration::from_secs(120))
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
    ) -> Result<(), CoreError> {
        let record = self.lookup_vm(name)?;
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
            && existing
                .iter()
                .any(|pf| pf.host_port == host_port && pf.guest_port == guest_port)
        {
            info!(%name, host_port, guest_port, "port forward already present (no-op)");
            return Ok(());
        }

        husker_net::add_port_forward(host_port, guest_ip, guest_port, tap_name, &self.bridge_name).await?;

        let pf_record = husker_state::PortForwardRecord {
            id: 0,
            vm_id: record.id,
            host_port,
            guest_port,
            protocol: "tcp".into(),
            created_at: chrono::Utc::now(),
        };
        if let Err(e) = self
            .state
            .insert_port_forward(&pf_record)
            .map_err(|e| match e {
                husker_state::StateError::PortAlreadyForwarded(port) => {
                    CoreError::Network(husker_net::NetError::CommandFailed {
                        cmd: "port forward".into(),
                        message: format!("host port {port} is already forwarded"),
                    })
                }
                other => CoreError::State(other),
            })
        {
            if let Err(rollback_err) = husker_net::remove_port_forward(host_port, tap_name, &self.bridge_name).await {
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
        Ok(())
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

    /// List port forwards for a VM.
    #[cfg(feature = "linux-net")]
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
                match husker_net::add_port_forward(pf.host_port, guest_ip, pf.guest_port, tap_name, &self.bridge_name)
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

        if svc.rootfs_path.is_empty() {
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

        let env: Vec<(String, String)> = svc
            .userdata_env
            .as_deref()
            .map(|s| serde_json::from_str(s).unwrap_or_default())
            .unwrap_or_default();
        let req = CreateVmRequest {
            name: name.clone(),
            kernel_path: svc.kernel_path.clone().into(),
            rootfs_path: svc.rootfs_path.clone().into(),
            vcpu_count: svc.vcpu_count,
            mem_size_mib: svc.mem_size_mib,
            initrd_path: svc.initrd_path.clone().map(Into::into),
            userdata: svc.userdata.clone(),
            env,
            vmm: None,
            cloud_image: None,
            disk_size: None,
        };
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
    use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

    let file_len = tokio::fs::metadata(path).await?.len();
    if file_len <= keep_bytes {
        return Ok(());
    }

    let mut file = tokio::fs::File::open(path).await?;
    file.seek(std::io::SeekFrom::Start(file_len - keep_bytes))
        .await?;
    let mut buf = Vec::with_capacity(keep_bytes as usize);
    file.read_to_end(&mut buf).await?;
    drop(file);

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .await?;
    file.write_all(&buf).await?;
    Ok(())
}

/// Prepare a cloud-image boot disk: validate the base image and OVMF firmware exist,
/// clone the base qcow2 into `dest_disk`, optionally grow it, and return the UEFI
/// BootMode carrying the firmware paths. This is pure file I/O (no networking), so the
/// full create path's TAP setup is not involved and it is unit-tested directly.
#[cfg(feature = "linux-net")]
async fn prepare_cloud_disk(
    storage_driver: &dyn husker_storage::StorageDriver,
    image: &str,
    disk_size: Option<u64>,
    dest_disk: &Path,
    ovmf_code: &Path,
    ovmf_vars_template: &Path,
) -> Result<husker_vmm::BootMode, CoreError> {
    let image_path = PathBuf::from(image);
    if !image_path.exists() {
        return Err(CoreError::InvalidArgument(format!(
            "cloud image not found: {}",
            image_path.display()
        )));
    }
    if !ovmf_code.exists() || !ovmf_vars_template.exists() {
        return Err(CoreError::InvalidArgument(format!(
            "OVMF firmware missing (need {} and {}); install the host OVMF package",
            ovmf_code.display(),
            ovmf_vars_template.display()
        )));
    }
    storage_driver.clone_rootfs(&image_path, dest_disk).await?;
    if let Some(size) = disk_size {
        husker_storage::resize_disk(dest_disk, size).await?;
    }
    Ok(husker_vmm::BootMode::Uefi {
        ovmf_code: ovmf_code.to_path_buf(),
        ovmf_vars_template: ovmf_vars_template.to_path_buf(),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "linux-net")]
    #[tokio::test]
    async fn prepare_cloud_disk_returns_uefi_and_clones() {
        let tmp = tempfile::tempdir().unwrap();
        let image = tmp.path().join("base.qcow2");
        let code = tmp.path().join("CODE.fd");
        let vars = tmp.path().join("VARS.fd");
        for p in [&image, &code, &vars] {
            std::fs::write(p, b"x").unwrap();
        }
        let dest = tmp.path().join("vm/disk.qcow2");
        let driver = husker_storage::default_storage_driver();
        // disk_size = None so no qemu-img resize is needed (keeps the test hermetic).
        let boot = super::prepare_cloud_disk(
            driver.as_ref(),
            image.to_str().unwrap(),
            None,
            &dest,
            &code,
            &vars,
        )
        .await
        .unwrap();
        match boot {
            husker_vmm::BootMode::Uefi { ovmf_code, ovmf_vars_template } => {
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
            "/no/such/image.qcow2",
            None,
            &tmp.path().join("d.qcow2"),
            &code,
            &vars,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, super::CoreError::InvalidArgument(_)), "got {err:?}");
    }

    #[cfg(feature = "linux-net")]
    #[tokio::test]
    async fn prepare_cloud_disk_errors_on_missing_ovmf() {
        let tmp = tempfile::tempdir().unwrap();
        let image = tmp.path().join("base.qcow2");
        std::fs::write(&image, b"x").unwrap();
        let driver = husker_storage::default_storage_driver();
        let err = super::prepare_cloud_disk(
            driver.as_ref(),
            image.to_str().unwrap(),
            None,
            &tmp.path().join("d.qcow2"),
            &tmp.path().join("missing-code.fd"),
            &tmp.path().join("missing-vars.fd"),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, super::CoreError::InvalidArgument(_)), "got {err:?}");
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
    fn make_vm_record(name: &str, state: &str, pid: Option<u32>, vmm: &str) -> husker_state::VmRecord {
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

        assert_eq!(reaped, 0, "stopped VMs and dead/absent pids must not be counted as reaped");
        // We are still alive.
        assert!(std::process::id() > 0);
    }

    #[test]
    fn create_vm_request_defaults_cloud_fields_to_none() {
        let json = r#"{"name":"v","kernel_path":"/k","rootfs_path":"/r"}"#;
        let req: super::CreateVmRequest = serde_json::from_str(json).unwrap();
        assert!(req.cloud_image.is_none());
        assert!(req.disk_size.is_none());
    }
}
