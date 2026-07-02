use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use husker::{
    default_data_dir, default_images_base_url, default_initrd_path, default_kernel_path,
    default_rootfs_path,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct Config {
    #[cfg(feature = "linux-net")]
    #[serde(default = "default_firecracker_bin")]
    pub(crate) firecracker_bin: PathBuf,
    #[cfg(feature = "linux-net")]
    #[serde(default)]
    pub(crate) vmm: VmmSelection,
    #[cfg(all(feature = "linux-net", target_os = "linux"))]
    #[serde(default = "default_qemu_bin")]
    pub(crate) qemu_bin: PathBuf,
    #[cfg(all(feature = "linux-net", target_os = "linux"))]
    #[serde(default = "default_ovmf_code")]
    pub(crate) ovmf_code: PathBuf,
    #[cfg(all(feature = "linux-net", target_os = "linux"))]
    #[serde(default = "default_ovmf_vars")]
    pub(crate) ovmf_vars: PathBuf,
    #[serde(default = "default_data_dir")]
    pub(crate) data_dir: PathBuf,
    /// Directory for the live state DB, runtime sockets, and the daemon lock.
    /// Unset means "same as data_dir" (current behavior). Set by `setup storage`
    /// when the data dir becomes a dedicated reflink-capable mount.
    #[serde(default)]
    pub(crate) state_dir: Option<PathBuf>,
    /// True when `data_dir` is a dedicated storage mount that must be present
    /// before the daemon starts. Set by `setup storage`.
    #[serde(default)]
    pub(crate) storage_volume: bool,
    #[serde(default = "husker::default_kernel_path")]
    pub(crate) default_kernel: PathBuf,
    #[serde(default = "husker::default_rootfs_path")]
    pub(crate) default_rootfs: PathBuf,
    #[serde(default = "husker::default_initrd_some")]
    pub(crate) default_initrd: Option<PathBuf>,
    /// Default disk size for cloud-image VMs when --disk-size is omitted
    /// (human units, e.g. "10G"). None leaves the image's own size.
    #[serde(default)]
    pub(crate) default_disk_size: Option<String>,
    /// Default memory (MiB) applied when neither the CLI flag nor a profile sets it.
    /// Falls back to the built-in 128 MiB when unset.
    #[serde(default)]
    pub(crate) default_memory: Option<u32>,
    /// Default vCPU count applied when neither the CLI flag nor a profile sets it.
    /// Falls back to the built-in 1 when unset.
    #[serde(default)]
    pub(crate) default_cpus: Option<u32>,
    #[serde(default = "husker::default_images_base_url")]
    pub(crate) images_base_url: String,
    #[serde(default)]
    pub(crate) api_token: Option<String>,
    /// Optional separate bind for a `GET /v1/metrics` endpoint, so Prometheus can
    /// scrape while the main API (listen) stays on localhost. Only metrics are
    /// served there. Env override: HUSKER_METRICS_LISTEN.
    #[serde(default)]
    pub(crate) metrics_listen: Option<SocketAddr>,
    /// Optional bearer token for the metrics listener (env: HUSKER_METRICS_TOKEN).
    /// When set, the metrics endpoint requires `Authorization: Bearer <token>` -
    /// defense in depth alongside a host firewall. Independent of `api_token`, so
    /// the main API can stay token-less on localhost. When unset the metrics
    /// endpoint is unauthenticated (the standard exporter pattern).
    #[serde(default)]
    pub(crate) metrics_token: Option<String>,
    /// Enable per-VM cgroup v2 resource limits (Linux only). Off by default.
    #[serde(default)]
    pub(crate) resource_limits: bool,
    /// Host-memory margin (MiB) over guest RAM for the VM's memory.max.
    #[serde(default = "default_memory_overhead_mib")]
    pub(crate) memory_overhead_mib: u32,
    /// Also cap host CPU per VM (cpu.max). Off by default.
    #[serde(default)]
    pub(crate) cpu_limit: bool,
    #[serde(default = "default_api_max_request_bytes")]
    pub(crate) api_max_request_bytes: usize,
    #[serde(default = "default_api_max_file_read_bytes")]
    pub(crate) api_max_file_read_bytes: usize,
    #[serde(default = "default_api_max_file_write_bytes")]
    pub(crate) api_max_file_write_bytes: usize,
    #[serde(default = "default_api_sensitive_rate_limit_per_minute")]
    pub(crate) api_sensitive_rate_limit_per_minute: u32,
    #[serde(default)]
    pub(crate) allowed_read_paths: Vec<String>,
    #[serde(default)]
    pub(crate) allowed_write_paths: Vec<String>,
    #[serde(default)]
    pub(crate) allowed_mount_host_paths: Vec<String>,
    #[serde(default = "default_exec_timeout_secs")]
    pub(crate) exec_timeout_secs: u64,
    #[serde(default = "default_exec_timeout_max_secs")]
    pub(crate) exec_timeout_max_secs: u64,
    #[serde(default)]
    pub(crate) exec_allowlist: Vec<String>,
    #[serde(default)]
    pub(crate) exec_denylist: Vec<String>,
    #[serde(default)]
    pub(crate) exec_env_allowlist: Vec<String>,
    #[serde(default = "default_service_reconcile_interval")]
    pub(crate) service_reconcile_interval_secs: u64,
    #[serde(default = "default_true")]
    pub(crate) service_reconcile_enabled: bool,
    #[cfg(feature = "linux-net")]
    #[serde(default = "default_host_interface")]
    pub(crate) host_interface: String,
    #[cfg(feature = "linux-net")]
    #[serde(default = "default_bridge_name")]
    pub(crate) bridge_name: String,
    #[cfg(feature = "linux-net")]
    #[serde(default = "default_bridge_subnet")]
    pub(crate) bridge_subnet: String,
    #[cfg(feature = "linux-net")]
    #[serde(default = "default_dns_servers")]
    pub(crate) dns_servers: Vec<String>,
    /// Starting CID for vsock and TAP-name allocation (`husker<cid>`). Two
    /// co-located daemons must use distinct non-overlapping bases so their CID
    /// and TAP-name spaces are disjoint. Default 3 (no separation; suitable
    /// for a single-daemon setup).
    #[cfg(feature = "linux-net")]
    #[serde(default = "default_cid_base")]
    pub(crate) cid_base: u32,
    /// Host bridge device to attach bridged-mode VMs to (Linux only).
    /// The bridge must be pre-created by the administrator; husker only
    /// enslaves the VM's TAP to it. Unset means bridged mode is unavailable.
    #[cfg(all(feature = "linux-net", target_os = "linux"))]
    #[serde(default)]
    pub(crate) lan_bridge: Option<String>,
    #[serde(default)]
    pub(crate) profiles: std::collections::HashMap<String, Profile>,
    /// Idle-suspend policy defaults for the idle-loop reconciler. Only VMs
    /// that opt in (via `--idle-timeout` or a profile) are affected.
    #[serde(default)]
    pub(crate) idle_policy: IdlePolicyToml,
}

/// Named VM preset, selectable with `--profile <name>` on run/job. Every key
/// is optional; explicit CLI flags always win over profile values.
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Profile {
    pub(crate) cloud_image: Option<PathBuf>,
    pub(crate) rootfs: Option<PathBuf>,
    pub(crate) kernel: Option<PathBuf>,
    pub(crate) initrd: Option<PathBuf>,
    pub(crate) cpus: Option<u32>,
    pub(crate) memory: Option<u32>,
    pub(crate) disk_size: Option<String>,
    #[serde(default)]
    pub(crate) ssh_keys: Vec<PathBuf>,
    pub(crate) vmm: Option<String>,
    #[serde(default)]
    pub(crate) env: Vec<String>,
    pub(crate) balloon: Option<bool>,
    pub(crate) idle_timeout_secs: Option<u64>,
    pub(crate) suspend_ttl_secs: Option<u64>,
    pub(crate) auto_resume: Option<bool>,
    pub(crate) volume: Option<String>,
    #[serde(default)]
    pub(crate) mounts: Vec<String>,
    pub(crate) network: Option<String>,
}

/// Serde mirror of `husker_core::IdlePolicyConfig` (which has no serde derive)
/// for `[idle_policy]` TOML parsing. Convert with `.into()` before handing to
/// core APIs.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct IdlePolicyToml {
    pub(crate) poll_interval_secs: u64,
    pub(crate) default_idle_timeout_secs: u64,
    pub(crate) default_suspend_ttl_secs: u64,
    pub(crate) default_auto_resume: bool,
}

impl Default for IdlePolicyToml {
    fn default() -> Self {
        let d = husker_core::IdlePolicyConfig::default();
        Self {
            poll_interval_secs: d.poll_interval_secs,
            default_idle_timeout_secs: d.default_idle_timeout_secs,
            default_suspend_ttl_secs: d.default_suspend_ttl_secs,
            default_auto_resume: d.default_auto_resume,
        }
    }
}

impl From<IdlePolicyToml> for husker_core::IdlePolicyConfig {
    fn from(t: IdlePolicyToml) -> Self {
        Self {
            poll_interval_secs: t.poll_interval_secs,
            default_idle_timeout_secs: t.default_idle_timeout_secs,
            default_suspend_ttl_secs: t.default_suspend_ttl_secs,
            default_auto_resume: t.default_auto_resume,
        }
    }
}

/// Whether the winning profile entry came from the local config or the daemon.
///
/// Used by `build_vm_request_body` to decide whether path fields (rootfs,
/// kernel, initrd) should be resolved against the client filesystem. Local
/// profiles are resolved; daemon profiles are sent as-is so bare catalog names
/// (e.g. "alpine-x86_64.ext4") reach the daemon unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProfileOrigin {
    Local,
    Daemon,
}

/// Merge daemon profiles (base) with local profiles (overlay). Local entries
/// win on name conflicts so per-user tweaks always override daemon defaults.
///
/// Returns the merged profile map alongside an origin map that records, for
/// each profile name, whether the winning entry is `Local` or `Daemon`. A
/// local profile that overrides a same-named daemon profile is `Local`-origin;
/// only profiles that came purely from the daemon are `Daemon`-origin.
pub(crate) fn merge_profiles(
    daemon: std::collections::HashMap<String, Profile>,
    local: &std::collections::HashMap<String, Profile>,
) -> (
    std::collections::HashMap<String, Profile>,
    std::collections::HashMap<String, ProfileOrigin>,
) {
    let mut merged = daemon;
    let mut origins: std::collections::HashMap<String, ProfileOrigin> = merged
        .keys()
        .map(|k| (k.clone(), ProfileOrigin::Daemon))
        .collect();
    for (name, profile) in local {
        merged.insert(name.clone(), profile.clone());
        origins.insert(name.clone(), ProfileOrigin::Local);
    }
    (merged, origins)
}

#[cfg(feature = "linux-net")]
fn default_firecracker_bin() -> PathBuf {
    PathBuf::from("firecracker")
}

#[cfg(feature = "linux-net")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum VmmSelection {
    #[default]
    Firecracker,
    #[cfg(target_os = "linux")]
    Qemu,
}

#[cfg(feature = "linux-net")]
impl VmmSelection {
    pub(crate) fn from_env_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "firecracker" | "fc" => Some(Self::Firecracker),
            #[cfg(target_os = "linux")]
            "qemu" | "kvm" => Some(Self::Qemu),
            _ => None,
        }
    }
}

#[cfg(all(feature = "linux-net", target_os = "linux"))]
fn default_qemu_bin() -> PathBuf {
    PathBuf::from("qemu-system-x86_64")
}

#[cfg(all(feature = "linux-net", target_os = "linux"))]
fn default_ovmf_code() -> PathBuf {
    PathBuf::from("/usr/share/OVMF/OVMF_CODE_4M.fd")
}

#[cfg(all(feature = "linux-net", target_os = "linux"))]
fn default_ovmf_vars() -> PathBuf {
    PathBuf::from("/usr/share/OVMF/OVMF_VARS_4M.fd")
}

fn default_api_max_request_bytes() -> usize {
    2 * 1024 * 1024
}

fn default_api_max_file_read_bytes() -> usize {
    1024 * 1024
}

fn default_api_max_file_write_bytes() -> usize {
    1024 * 1024
}

fn default_api_sensitive_rate_limit_per_minute() -> u32 {
    120
}

fn default_exec_timeout_secs() -> u64 {
    30
}

fn default_exec_timeout_max_secs() -> u64 {
    3600
}

fn default_service_reconcile_interval() -> u64 {
    15
}

fn default_true() -> bool {
    true
}

#[cfg(feature = "linux-net")]
fn default_host_interface() -> String {
    "eth0".into()
}

#[cfg(feature = "linux-net")]
fn default_bridge_name() -> String {
    "husker0".into()
}

#[cfg(feature = "linux-net")]
fn default_bridge_subnet() -> String {
    "172.20.0.0/24".into()
}

#[cfg(feature = "linux-net")]
fn default_dns_servers() -> Vec<String> {
    vec!["8.8.8.8".into(), "1.1.1.1".into()]
}

#[cfg(feature = "linux-net")]
fn default_cid_base() -> u32 {
    3
}

fn default_memory_overhead_mib() -> u32 {
    256
}

impl Default for Config {
    fn default() -> Self {
        Self {
            #[cfg(feature = "linux-net")]
            firecracker_bin: default_firecracker_bin(),
            #[cfg(feature = "linux-net")]
            vmm: VmmSelection::default(),
            #[cfg(all(feature = "linux-net", target_os = "linux"))]
            qemu_bin: default_qemu_bin(),
            #[cfg(all(feature = "linux-net", target_os = "linux"))]
            ovmf_code: default_ovmf_code(),
            #[cfg(all(feature = "linux-net", target_os = "linux"))]
            ovmf_vars: default_ovmf_vars(),
            data_dir: default_data_dir(),
            state_dir: None,
            storage_volume: false,
            default_kernel: default_kernel_path(),
            default_rootfs: default_rootfs_path(),
            default_initrd: Some(default_initrd_path()),
            default_disk_size: None,
            default_memory: None,
            default_cpus: None,
            images_base_url: default_images_base_url(),
            api_token: None,
            metrics_listen: None,
            metrics_token: None,
            resource_limits: false,
            memory_overhead_mib: default_memory_overhead_mib(),
            cpu_limit: false,
            api_max_request_bytes: default_api_max_request_bytes(),
            api_max_file_read_bytes: default_api_max_file_read_bytes(),
            api_max_file_write_bytes: default_api_max_file_write_bytes(),
            api_sensitive_rate_limit_per_minute: default_api_sensitive_rate_limit_per_minute(),
            allowed_read_paths: Vec::new(),
            allowed_write_paths: Vec::new(),
            allowed_mount_host_paths: Vec::new(),
            exec_timeout_secs: default_exec_timeout_secs(),
            exec_timeout_max_secs: default_exec_timeout_max_secs(),
            exec_allowlist: Vec::new(),
            exec_denylist: Vec::new(),
            exec_env_allowlist: Vec::new(),
            service_reconcile_interval_secs: default_service_reconcile_interval(),
            service_reconcile_enabled: default_true(),
            #[cfg(feature = "linux-net")]
            host_interface: default_host_interface(),
            #[cfg(feature = "linux-net")]
            bridge_name: default_bridge_name(),
            #[cfg(feature = "linux-net")]
            bridge_subnet: default_bridge_subnet(),
            #[cfg(feature = "linux-net")]
            dns_servers: default_dns_servers(),
            #[cfg(feature = "linux-net")]
            cid_base: default_cid_base(),
            #[cfg(all(feature = "linux-net", target_os = "linux"))]
            lan_bridge: None,
            profiles: Default::default(),
            idle_policy: IdlePolicyToml::default(),
        }
    }
}

impl Config {
    /// The effective state directory: explicit `state_dir`, else `data_dir`.
    pub(crate) fn effective_state_dir(&self) -> PathBuf {
        self.state_dir
            .clone()
            .unwrap_or_else(|| self.data_dir.clone())
    }
}

/// Resolve the config file path by checking (in order):
/// 1. Explicit path from --config flag
/// 2. `~/.config/husker/config.toml` (XDG user config)
/// 3. `/etc/husker/config.toml` (system config)
pub(crate) fn resolve_config_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_owned();
    }
    if let Some(home) = std::env::var_os("HOME") {
        let user_config = PathBuf::from(home).join(".config/husker/config.toml");
        if user_config.exists() {
            return user_config;
        }
    }
    PathBuf::from("/etc/husker/config.toml")
}

/// Apply environment variable overrides to the configuration.
///
/// Environment variables take precedence over file-based config.
pub(crate) fn apply_env_overrides(config: &mut Config) {
    if let Ok(val) = std::env::var("HUSKER_DATA_DIR") {
        let new_data_dir = PathBuf::from(val);
        // Cascade the override to kernel/rootfs/initrd paths when they were
        // left at their defaults. Explicit TOML values (which do not match
        // the default-based paths) are preserved.
        let old_default_kernel = husker::default_kernel_path_for(&config.data_dir);
        let old_default_rootfs = husker::default_rootfs_path_for(&config.data_dir);
        let old_default_initrd = husker::default_initrd_path_for(&config.data_dir);
        if config.default_kernel == old_default_kernel {
            config.default_kernel = husker::default_kernel_path_for(&new_data_dir);
        }
        if config.default_rootfs == old_default_rootfs {
            config.default_rootfs = husker::default_rootfs_path_for(&new_data_dir);
        }
        if config.default_initrd.as_ref() == Some(&old_default_initrd) {
            config.default_initrd = Some(husker::default_initrd_path_for(&new_data_dir));
        }
        config.data_dir = new_data_dir;
    }
    if let Ok(val) = std::env::var("HUSKER_STATE_DIR") {
        config.state_dir = Some(PathBuf::from(val));
    }
    if let Ok(val) = std::env::var("HUSKER_STORAGE_VOLUME") {
        config.storage_volume = matches!(val.as_str(), "1" | "true" | "yes" | "on");
    }
    if let Ok(val) = std::env::var("HUSKER_DEFAULT_KERNEL") {
        config.default_kernel = PathBuf::from(val);
    }
    if let Ok(val) = std::env::var("HUSKER_DEFAULT_ROOTFS") {
        config.default_rootfs = PathBuf::from(val);
    }
    if let Ok(val) = std::env::var("HUSKER_DEFAULT_INITRD") {
        config.default_initrd = Some(PathBuf::from(val));
    }
    if let Ok(val) = std::env::var("HUSKER_DEFAULT_DISK_SIZE") {
        config.default_disk_size = Some(val);
    }
    if let Ok(val) = std::env::var("HUSKER_DEFAULT_MEMORY")
        && let Ok(parsed) = val.parse::<u32>()
    {
        config.default_memory = Some(parsed);
    }
    if let Ok(val) = std::env::var("HUSKER_DEFAULT_CPUS")
        && let Ok(parsed) = val.parse::<u32>()
    {
        config.default_cpus = Some(parsed);
    }
    if let Ok(val) = std::env::var("HUSKER_IMAGES_BASE_URL") {
        config.images_base_url = val;
    }
    if let Ok(val) = std::env::var("HUSKER_API_TOKEN") {
        config.api_token = Some(val);
    }
    if let Ok(val) = std::env::var("HUSKER_METRICS_LISTEN")
        && let Ok(parsed) = val.parse::<SocketAddr>()
    {
        config.metrics_listen = Some(parsed);
    }
    if let Ok(val) = std::env::var("HUSKER_METRICS_TOKEN") {
        config.metrics_token = Some(val);
    }
    if let Ok(val) = std::env::var("HUSKER_RESOURCE_LIMITS") {
        config.resource_limits = matches!(val.as_str(), "1" | "true" | "yes");
    }
    if let Ok(val) = std::env::var("HUSKER_MEMORY_OVERHEAD_MIB")
        && let Ok(parsed) = val.parse::<u32>()
    {
        config.memory_overhead_mib = parsed;
    }
    if let Ok(val) = std::env::var("HUSKER_CPU_LIMIT") {
        config.cpu_limit = matches!(val.as_str(), "1" | "true" | "yes");
    }
    if let Ok(val) = std::env::var("HUSKER_API_MAX_REQUEST_BYTES")
        && let Ok(parsed) = val.parse::<usize>()
    {
        config.api_max_request_bytes = parsed;
    }
    if let Ok(val) = std::env::var("HUSKER_API_MAX_FILE_READ_BYTES")
        && let Ok(parsed) = val.parse::<usize>()
    {
        config.api_max_file_read_bytes = parsed;
    }
    if let Ok(val) = std::env::var("HUSKER_API_MAX_FILE_WRITE_BYTES")
        && let Ok(parsed) = val.parse::<usize>()
    {
        config.api_max_file_write_bytes = parsed;
    }
    if let Ok(val) = std::env::var("HUSKER_API_SENSITIVE_RATE_LIMIT_PER_MINUTE")
        && let Ok(parsed) = val.parse::<u32>()
    {
        config.api_sensitive_rate_limit_per_minute = parsed;
    }
    if let Ok(val) = std::env::var("HUSKER_ALLOWED_READ_PATHS") {
        config.allowed_read_paths = val
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Ok(val) = std::env::var("HUSKER_ALLOWED_WRITE_PATHS") {
        config.allowed_write_paths = val
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Ok(val) = std::env::var("HUSKER_ALLOWED_MOUNT_HOST_PATHS") {
        config.allowed_mount_host_paths = val
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Ok(val) = std::env::var("HUSKER_EXEC_TIMEOUT_SECS")
        && let Ok(parsed) = val.parse::<u64>()
    {
        config.exec_timeout_secs = parsed;
    }
    if let Ok(val) = std::env::var("HUSKER_EXEC_TIMEOUT_MAX_SECS")
        && let Ok(parsed) = val.parse::<u64>()
    {
        config.exec_timeout_max_secs = parsed;
    }
    if let Ok(val) = std::env::var("HUSKER_EXEC_ALLOWLIST") {
        config.exec_allowlist = val
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Ok(val) = std::env::var("HUSKER_EXEC_DENYLIST") {
        config.exec_denylist = val
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Ok(val) = std::env::var("HUSKER_EXEC_ENV_ALLOWLIST") {
        config.exec_env_allowlist = val
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Ok(val) = std::env::var("HUSKER_SERVICE_RECONCILE_INTERVAL")
        && let Ok(parsed) = val.parse::<u64>()
    {
        config.service_reconcile_interval_secs = parsed;
    }
    if let Ok(val) = std::env::var("HUSKER_SERVICE_RECONCILE_ENABLED") {
        config.service_reconcile_enabled = matches!(val.as_str(), "1" | "true" | "TRUE" | "yes");
    }
    if let Ok(val) = std::env::var("HUSKER_IDLE_POLL_INTERVAL_SECS")
        && let Ok(n) = val.parse::<u64>()
    {
        config.idle_policy.poll_interval_secs = n;
    }
    if let Ok(val) = std::env::var("HUSKER_IDLE_DEFAULT_TIMEOUT_SECS")
        && let Ok(n) = val.parse::<u64>()
    {
        config.idle_policy.default_idle_timeout_secs = n;
    }
    if let Ok(val) = std::env::var("HUSKER_IDLE_DEFAULT_SUSPEND_TTL_SECS")
        && let Ok(n) = val.parse::<u64>()
    {
        config.idle_policy.default_suspend_ttl_secs = n;
    }
    if let Ok(val) = std::env::var("HUSKER_IDLE_DEFAULT_AUTO_RESUME") {
        config.idle_policy.default_auto_resume =
            matches!(val.as_str(), "1" | "true" | "yes" | "on");
    }
    #[cfg(feature = "linux-net")]
    {
        if let Ok(val) = std::env::var("HUSKER_FIRECRACKER_BIN") {
            config.firecracker_bin = PathBuf::from(val);
        }
        #[cfg(target_os = "linux")]
        if let Ok(val) = std::env::var("HUSKER_QEMU_BIN") {
            config.qemu_bin = PathBuf::from(val);
        }
        #[cfg(target_os = "linux")]
        if let Ok(val) = std::env::var("HUSKER_OVMF_CODE") {
            config.ovmf_code = PathBuf::from(val);
        }
        #[cfg(target_os = "linux")]
        if let Ok(val) = std::env::var("HUSKER_OVMF_VARS") {
            config.ovmf_vars = PathBuf::from(val);
        }
        if let Ok(val) = std::env::var("HUSKER_VMM") {
            match VmmSelection::from_env_str(&val) {
                Some(sel) => config.vmm = sel,
                None => tracing::warn!(
                    value = %val,
                    "HUSKER_VMM: unrecognised or unsupported backend on this platform, ignoring (valid: firecracker, qemu)"
                ),
            }
        }
        if let Ok(val) = std::env::var("HUSKER_HOST_INTERFACE") {
            config.host_interface = val;
        }
        if let Ok(val) = std::env::var("HUSKER_BRIDGE_NAME") {
            config.bridge_name = val;
        }
        if let Ok(val) = std::env::var("HUSKER_BRIDGE_SUBNET") {
            config.bridge_subnet = val;
        }
        if let Ok(val) = std::env::var("HUSKER_DNS_SERVERS") {
            config.dns_servers = val.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(val) = std::env::var("HUSKER_CID_BASE")
            && let Ok(parsed) = val.parse::<u32>()
        {
            config.cid_base = parsed;
        }
        #[cfg(target_os = "linux")]
        if let Ok(val) = std::env::var("HUSKER_LAN_BRIDGE") {
            config.lan_bridge = if val.is_empty() { None } else { Some(val) };
        }
    }
}

pub(crate) fn load_config(explicit_path: Option<&Path>) -> Config {
    let path = resolve_config_path(explicit_path);
    let mut config = match std::fs::read_to_string(&path) {
        Ok(contents) => toml::from_str(&contents).unwrap_or_else(|e| {
            eprintln!("Warning: invalid config file: {e}");
            Config::default()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
        Err(e) => {
            eprintln!(
                "Warning: could not read config file {}: {e}",
                path.display()
            );
            Config::default()
        }
    };
    apply_env_overrides(&mut config);
    config
}

/// Strict config loader for the daemon: a present-but-unparseable (or otherwise
/// unreadable) config file is fatal rather than silently falling back to
/// `Config::default()`. Without this, a typo while editing the config would drop
/// `api_token` (and exec allow/deny lists, path allowlists, etc.) and bring the
/// daemon up on insecure defaults after a routine restart. A *missing* file still
/// falls back to defaults, preserving the documented zero-config path.
pub(crate) fn load_config_strict(explicit_path: Option<&Path>) -> Result<Config> {
    let path = resolve_config_path(explicit_path);
    let mut config = match std::fs::read_to_string(&path) {
        Ok(contents) => toml::from_str(&contents)
            .with_context(|| format!("invalid config file {}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // A missing file at an explicit --config path is a user error; a missing
            // file at a default discovery location is the zero-config path.
            if explicit_path.is_some() {
                anyhow::bail!("config file not found: {}", path.display());
            }
            Config::default()
        }
        Err(e) => {
            return Err(anyhow::Error::new(e))
                .with_context(|| format!("could not read config file {}", path.display()));
        }
    };
    apply_env_overrides(&mut config);
    Ok(config)
}
