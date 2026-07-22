//! Request/response DTOs for the husker HTTP API.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use husker_core::DaemonProfile;

// ── Response Types ────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct VmResponse {
    pub id: String,
    pub name: String,
    pub state: String,
    pub pid: Option<u32>,
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    pub vsock_cid: u32,
    pub host_ip: Option<String>,
    pub guest_ip: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userdata_status: Option<String>,
    pub vmm: String,
    pub boot_mode: String,
    /// Source rootfs (direct boot) or cloud image (UEFI boot) this VM was
    /// created from. Empty when unknown.
    pub rootfs_path: String,
    /// Kernel the VM boots (direct-kernel boot only; empty for UEFI boot).
    pub kernel_path: String,
    /// Name of the persistent volume attached to this VM, or None.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume: Option<String>,
    /// Network mode for this VM: "nat" (husker-managed NAT) or "bridged" (LAN bridge via DHCP).
    pub network: String,
    /// Idle window in seconds before this VM is suspended, if the idle policy is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_timeout_secs: Option<u64>,
    /// Seconds a suspended VM may sit idle before it is reaped. None/0 = never reap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspend_ttl_secs: Option<u64>,
    /// Whether the VM auto-resumes on activity/connect while suspended. Only present
    /// when the idle policy is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_resume: Option<bool>,
    /// Timestamp the VM was suspended at, if currently suspended.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspended_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct HostGroupResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServiceResponse {
    pub id: String,
    pub name: String,
    pub host_group_id: Option<String>,
    pub desired_instances: u32,
    pub current_instances: u32,
    pub image: Option<String>,
    pub rootfs_path: String,
    pub kernel_path: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_size: Option<u64>,
    pub balloon: bool,
    /// Name of the persistent volume attached to instances of this service, or None.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServiceInstance {
    pub name: String,
    pub ordinal: u32,
    pub state: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServiceDetailResponse {
    #[serde(flatten)]
    pub service: ServiceResponse,
    pub instances: Vec<ServiceInstance>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ReconcileFailure {
    pub instance: String,
    pub error: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ReconcileOutcomeResponse {
    pub created: Vec<String>,
    pub destroyed: Vec<String>,
    pub failed: Vec<ReconcileFailure>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServiceMutationResponse {
    pub service: ServiceResponse,
    pub outcome: ReconcileOutcomeResponse,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServiceDeleteResponse {
    pub name: String,
    pub outcome: ReconcileOutcomeResponse,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PoolResponse {
    pub id: String,
    pub name: String,
    pub template_vm_id: String,
    pub rootfs_path: String,
    pub kernel_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initrd_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcpu_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_size_mib: Option<u32>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CheckoutPoolRequest {
    /// Name for the checked-out VM. Generated from the pool name if omitted.
    #[serde(default)]
    pub vm_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PoolDeleteResponse {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SnapshotResponse {
    pub id: String,
    pub name: String,
    pub source_vm_name: String,
    pub file_path: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ImageResponse {
    pub id: String,
    pub name: String,
    pub source_path: String,
    pub file_path: String,
    pub format: String,
    /// Image kind: "rootfs" (direct-kernel boot) or "cloud-image" (UEFI/OVMF boot).
    pub kind: String,
    pub size_bytes: u64,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ExportImageResponse {
    pub name: String,
    pub destination_path: String,
    pub size_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct VolumeResponse {
    pub id: String,
    pub name: String,
    pub file_path: String,
    pub size_bytes: u64,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateVolumeApiRequest {
    pub name: String,
    pub size_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SecretResponse {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RevealedSecretResponse {
    pub name: String,
    pub value: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ScaleServiceRequest {
    pub desired_instances: u32,
}

/// Body for `PUT /v1/vms/{name}/balloon`.
///
/// `amount_mib` is the balloon target: memory reclaimed FROM the guest, not
/// the remaining guest size. Requires the VM to have been created with
/// `balloon: true`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct BalloonRequest {
    pub amount_mib: u32,
}

/// Body for `POST /v1/vms/{name}/fork`. `fork_name` is the new VM's name.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ForkRequest {
    pub fork_name: String,
}

/// Body for `POST /v1/images/import-oci`: pull an OCI image and register it.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ImportOciRequest {
    /// Catalog name for the resulting image.
    pub name: String,
    /// OCI/Docker reference, e.g. `alpine:3.20` or `ghcr.io/o/i:tag`.
    pub reference: String,
}

// ── Exec Types ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct ExecRequest {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub working_dir: Option<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Secrets to inject as environment variables, mapping an env-var name to the
    /// name of a stored secret. The daemon resolves each to its plaintext (it
    /// holds the key) and adds it to `env`, so the value never crosses the client,
    /// process table, or shell history. A secret overrides `env` on a key clash.
    #[serde(default)]
    pub secret_env: HashMap<String, String>,
    /// Seconds to wait for the guest agent to become reachable. Defaults to
    /// `DEFAULT_EXEC_CONNECT_TIMEOUT_SECS` (or the extended cloud-image timeout
    /// for EFI/UEFI VMs, which boot slower) and is clamped to a sane range.
    pub connect_timeout_secs: Option<u64>,
    /// Maximum seconds the command may run. Defaults to the daemon's
    /// `exec_timeout_secs` and is clamped to `exec_timeout_max_secs`.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ExecResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

// ── File Types ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct ReadFileRequest {
    pub path: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReadFileResponse {
    pub data: String,
    pub size: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct WriteFileRequest {
    pub path: String,
    /// Base64-encoded file data.
    pub data: String,
    pub mode: Option<u32>,
    /// Open the destination for append instead of truncating it. Used by a
    /// client sending a large file as a sequence of chunks: the first chunk
    /// omits this (or sets it false) to truncate, later chunks set it true
    /// to append. Defaults to false so a request built before this field
    /// existed still decodes and keeps today's truncate-and-write behavior.
    #[serde(default)]
    pub append: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WriteFileResponse {
    pub bytes_written: u64,
}

// ── Port Forward Types ────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddPortForwardRequest {
    pub host_port: u16,
    pub guest_port: u16,
    /// Host address to bind (macOS userspace proxy). Defaults to 127.0.0.1.
    #[serde(default)]
    pub bind_addr: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PortForwardResponse {
    pub host_port: u16,
    pub guest_port: u16,
    pub protocol: String,
    /// Effective host bind address. `None` on Linux (all interfaces).
    pub bind_addr: Option<String>,
    pub created_at: String,
}

// ── WebSocket Shell Types ─────────────────────────────────────────────

/// Messages sent by the client to the server over the shell WebSocket.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsShellInput {
    Start {
        command: Option<String>,
        #[serde(default = "default_cols")]
        cols: u16,
        #[serde(default = "default_rows")]
        rows: u16,
    },
    Data {
        data: String,
    },
    Resize {
        cols: u16,
        rows: u16,
    },
}

fn default_cols() -> u16 {
    80
}
fn default_rows() -> u16 {
    24
}

// ── Ready Types ──────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ReadyResponse {
    pub vm: String,
    pub ready: bool,
}

/// Guest network and protocol information, used by a client to preflight
/// whether the connected agent supports a feature (e.g. append-mode writes)
/// before relying on it.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct GuestInfoResponse {
    pub ipv4: Vec<String>,
    pub protocol_version: u32,
}

/// Named VM presets configured in the daemon and served to clients.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ProfilesResponse {
    pub profiles: HashMap<String, DaemonProfile>,
}

// ── Logs Types ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct LogsQuery {
    #[serde(default)]
    pub follow: bool,
    pub tail: Option<u64>,
    /// Serve the captured userdata script output instead of the serial console.
    #[serde(default)]
    pub userdata: bool,
    /// Log source: "serial" (default), "boot", or "userdata". Takes precedence
    /// over `userdata` when set.
    #[schema(example = "serial")]
    pub source: Option<String>,
}

/// Messages sent by the server to the client over the shell WebSocket.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsShellOutput {
    Started,
    Data { data: String },
    Exit { exit_code: i32 },
    Error { message: String },
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub vms: VmCounts,
    pub checks: HashMap<String, String>,
    pub uptime_seconds: u64,
    /// Capability-defining backend kind: `"firecracker"`, `"qemu"`, or
    /// `"apple_vz"`. Lets clients pre-flight backend-specific operations.
    pub backend: String,
    /// What this daemon's backend and build can actually do.
    pub capabilities: DaemonCapabilities,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VmCounts {
    pub total: u64,
    pub running: u64,
}

/// The set of optional operations a daemon supports, derived from its backend
/// kind and compile-time build features. Clients use this to fail fast with an
/// actionable message instead of attempting an operation the daemon can't run.
#[derive(Debug, Serialize, ToSchema)]
pub struct DaemonCapabilities {
    /// `husker fork` (fork a suspended VM). Firecracker only.
    pub fork: bool,
    /// `husker suspend` (full-state snapshot to disk). Firecracker only.
    pub snapshot: bool,
    /// `husker image import-oci` (import OCI/Docker images). Linux builds only.
    pub oci_import: bool,
    /// `husker port-forward`. nftables host->guest mapping on Linux; a userspace
    /// TCP proxy on macOS.
    pub port_forward: bool,
    /// `--net bridged` (attach VMs to the LAN bridge). linux-net builds only.
    pub bridged_net: bool,
}
