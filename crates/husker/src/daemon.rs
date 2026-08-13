use std::net::SocketAddr;
use std::path::Path;
#[cfg(not(all(not(feature = "linux-net"), target_os = "macos")))]
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::config::Config;
#[cfg(all(feature = "linux-net", target_os = "linux"))]
use crate::config::VmmSelection;
use crate::vm_creation::profile_to_daemon;

pub(crate) fn validate_daemon_bind(
    listen: SocketAddr,
    allow_remote: bool,
    has_token: bool,
) -> Result<()> {
    if !listen.ip().is_loopback() && !allow_remote {
        anyhow::bail!(
            "refusing to bind daemon to non-loopback address {listen} without \
             --allow-remote"
        );
    }
    // A remotely reachable daemon must require authentication. Without this guard,
    // `husker daemon --listen 0.0.0.0:7777 --allow-remote` with no token would start
    // silently with every route (exec, shell, secret reveal, destroy) open to anyone
    // on the network.
    if !listen.ip().is_loopback() && !has_token {
        anyhow::bail!(
            "refusing to bind daemon to non-loopback address {listen} without an api_token: \
             a remotely reachable daemon must require authentication. Set `api_token` in the \
             config file, or the HUSKER_API_TOKEN env var, or pass --api-token."
        );
    }
    Ok(())
}

/// Restrict a daemon-owned directory to owner-only (0700). Best-effort: logs on
/// failure rather than aborting startup. The state and runtime dirs hold the
/// secrets key, the SQLite DB, and per-VM sockets, so they must not be left
/// group/world-readable by the process umask on a shared host.
#[cfg(unix)]
pub(crate) fn restrict_dir_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)) {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "could not restrict directory permissions to 0700"
        );
    }
}

#[cfg(not(unix))]
pub(crate) fn restrict_dir_permissions(_path: &Path) {}

/// Parse a CIDR string (e.g. "172.20.0.0/24") into base address and prefix length.
///
/// Validates that:
/// - The string contains a `/` separator
/// - The base address is a valid IPv4 address
/// - The prefix length is between 1 and 30 (inclusive)
/// - The base address is network-aligned (host bits are zero)
#[cfg(feature = "linux-net")]
pub(crate) fn parse_cidr(cidr: &str) -> Result<(std::net::Ipv4Addr, u8)> {
    let (base_str, prefix_str) = cidr.split_once('/').context("invalid CIDR: missing '/'")?;
    let base: std::net::Ipv4Addr = base_str.parse().context("invalid CIDR base address")?;
    let prefix_len: u8 = prefix_str.parse().context("invalid CIDR prefix length")?;
    anyhow::ensure!(
        (1..=30).contains(&prefix_len),
        "prefix length must be 1..=30 (got {prefix_len})"
    );

    // Verify the base address has no host bits set (is a proper network address).
    let base_u32 = u32::from(base);
    let host_mask = (1u32 << (32 - prefix_len)) - 1;
    anyhow::ensure!(
        base_u32 & host_mask == 0,
        "base address {base} is not network-aligned for /{prefix_len} \
         (did you mean {}/{}?)",
        std::net::Ipv4Addr::from(base_u32 & !host_mask),
        prefix_len,
    );

    Ok((base, prefix_len))
}

/// Ensure Firecracker is available. If the binary can't be found, auto-install
/// when `HUSKER_AUTO_INSTALL_FIRECRACKER=1` is set, prompt interactively on a
/// TTY, or bail with a hint otherwise.
#[cfg(all(target_os = "linux", feature = "linux-net"))]
pub(crate) async fn ensure_firecracker(config: &Config) -> anyhow::Result<PathBuf> {
    if let Some(p) = find_in_path(&config.firecracker_bin) {
        return Ok(p);
    }
    let data = &config.data_dir;
    let bin = data.join("bin/firecracker");
    if bin.exists() {
        return Ok(bin);
    }

    let env = std::env::var("HUSKER_AUTO_INSTALL_FIRECRACKER").ok();
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin())
        && std::io::IsTerminal::is_terminal(&std::io::stderr());
    let url = husker::firecracker::firecracker_download_url();

    let should_install = match decide_auto_install(env.as_deref(), is_tty) {
        AutoInstallDecision::Yes => true,
        AutoInstallDecision::No => false,
        AutoInstallDecision::Prompt => prompt_firecracker_install(&url)?,
    };

    if !should_install {
        anyhow::bail!(
            "firecracker not found on PATH. Install it, or re-run with HUSKER_AUTO_INSTALL_FIRECRACKER=1 to download {url}"
        );
    }
    let installed = husker::firecracker::install(data).await?;
    eprintln!("Installed firecracker to {}", installed.display());
    Ok(installed)
}

#[cfg(all(target_os = "linux", feature = "linux-net"))]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum AutoInstallDecision {
    Yes,
    No,
    Prompt,
}

#[cfg(all(target_os = "linux", feature = "linux-net"))]
pub(crate) fn decide_auto_install(env: Option<&str>, is_tty: bool) -> AutoInstallDecision {
    match env {
        Some("1") => AutoInstallDecision::Yes,
        _ if is_tty => AutoInstallDecision::Prompt,
        _ => AutoInstallDecision::No,
    }
}

#[cfg(all(target_os = "linux", feature = "linux-net"))]
pub(crate) fn prompt_firecracker_install(url: &str) -> anyhow::Result<bool> {
    use std::io::Write;
    eprintln!("firecracker not found on PATH.");
    eprintln!("husker can download a pinned release from:");
    eprintln!("  {url}");
    eprint!("Install it now? [Y/n] ");
    std::io::stderr().flush().ok();
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_lowercase();
    Ok(matches!(answer.as_str(), "" | "y" | "yes"))
}

#[cfg(all(test, target_os = "linux", feature = "linux-net"))]
mod auto_install_tests {
    use super::{AutoInstallDecision, decide_auto_install};

    #[test]
    fn env_one_always_installs() {
        assert_eq!(
            decide_auto_install(Some("1"), true),
            AutoInstallDecision::Yes
        );
        assert_eq!(
            decide_auto_install(Some("1"), false),
            AutoInstallDecision::Yes
        );
    }

    #[test]
    fn no_env_on_tty_prompts() {
        assert_eq!(decide_auto_install(None, true), AutoInstallDecision::Prompt);
        assert_eq!(
            decide_auto_install(Some(""), true),
            AutoInstallDecision::Prompt
        );
        assert_eq!(
            decide_auto_install(Some("0"), true),
            AutoInstallDecision::Prompt
        );
    }

    #[test]
    fn no_env_without_tty_bails() {
        assert_eq!(decide_auto_install(None, false), AutoInstallDecision::No);
        assert_eq!(
            decide_auto_install(Some(""), false),
            AutoInstallDecision::No
        );
        assert_eq!(
            decide_auto_install(Some("0"), false),
            AutoInstallDecision::No
        );
    }
}

/// Check if a binary name can be found in PATH.
#[cfg(feature = "linux-net")]
pub(crate) fn find_in_path(name: &Path) -> Option<PathBuf> {
    if name.is_absolute() {
        return name.is_file().then(|| name.to_path_buf());
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Acquire an exclusive, non-blocking advisory lock on the daemon lock file.
/// The returned `File` must be kept alive for the daemon's lifetime; the lock
/// releases when it is dropped or the process exits. An error means another
/// process already holds it (a daemon is running).
pub(crate) fn acquire_daemon_lock(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)?;
    // SAFETY: file owns a valid fd for the duration of this call.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(file)
}

/// Whether the daemon may proceed under the storage-volume policy. When the
/// data dir is a dedicated mount (`storage_volume`), the loopback must be
/// mounted, proven by the sentinel file existing under the data dir.
pub(crate) fn storage_mount_satisfied(storage_volume: bool, sentinel_exists: bool) -> bool {
    !storage_volume || sentinel_exists
}

/// Remove `vms_dir` subdirectories that have no backing VM record. These are
/// orphaned rootfs clones left by a failed create or an interrupted destroy.
/// Pure filesystem logic (unit-tested); suspend snapshots live under
/// `data_dir/suspend/`, not `vms_dir`, so they are never touched.
pub(crate) fn remove_orphan_clone_dirs(
    vms_dir: &Path,
    known_names: &std::collections::HashSet<&str>,
) -> usize {
    let Ok(entries) = std::fs::read_dir(vms_dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !known_names.contains(name) && std::fs::remove_dir_all(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Reconcile host resources against DB state on startup: reclaim the TAP devices
/// and API/vsock sockets of VMs that are no longer running, and remove orphaned
/// rootfs clone directories. Scoped to this daemon's own state and data dir, so a
/// co-located daemon's resources are never touched.
///
/// Runs after `mark_stale_vms_stopped`, so at this point nothing this daemon
/// manages is running. Suspended VMs are skipped: they intentionally preserve
/// their TAP, IP, and rootfs so `resume` can restore the same identity in place.
async fn reconcile_host_resources(
    state: &husker_state::StateStore,
    storage: &husker_storage::StorageConfig,
    runtime_dir: &Path,
) {
    let vms = match state.list_vms() {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "host reconcile: could not list VMs");
            return;
        }
    };
    let known_names: std::collections::HashSet<&str> =
        vms.iter().map(|v| v.name.as_str()).collect();

    #[cfg(feature = "linux-net")]
    let mut taps = 0usize;
    let mut socks = 0usize;
    for vm in &vms {
        // Suspended VMs keep their TAP/sockets/rootfs for resume; leave them.
        if vm.state == "suspended" {
            continue;
        }
        #[cfg(feature = "linux-net")]
        if let Some(tap) = vm.tap_device.as_deref()
            && husker_net::delete_tap(tap).await.is_ok()
        {
            taps += 1;
        }
        for ext in ["sock", "vsock"] {
            let p = runtime_dir.join(format!("{}.{ext}", vm.id));
            if p.exists() && std::fs::remove_file(&p).is_ok() {
                socks += 1;
            }
        }
    }

    let dirs = remove_orphan_clone_dirs(&storage.vms_dir(), &known_names);

    #[cfg(feature = "linux-net")]
    if taps + socks + dirs > 0 {
        tracing::info!(
            taps,
            socks,
            dirs,
            "reconciled leaked host resources from a prior run"
        );
    }
    #[cfg(not(feature = "linux-net"))]
    if socks + dirs > 0 {
        tracing::info!(
            socks,
            dirs,
            "reconciled leaked host resources from a prior run"
        );
    }
}

pub(crate) async fn start_daemon(config: Config, listen: SocketAddr) -> Result<()> {
    tracing::info!("starting husker daemon");

    // Resolve firecracker_bin to an absolute path before handing it to the
    // VMM backend. Auto-installed Firecracker lands at `{data_dir}/bin/firecracker`
    // which is not on PATH for most setups; look there when PATH lookup fails.
    #[cfg(all(target_os = "linux", feature = "linux-net"))]
    let config = {
        let mut config = config;
        if !config.firecracker_bin.is_absolute() && find_in_path(&config.firecracker_bin).is_none()
        {
            let candidate = config.data_dir.join("bin/firecracker");
            if candidate.is_file() {
                tracing::info!(path = %candidate.display(), "resolved firecracker_bin from data dir");
                config.firecracker_bin = candidate;
            }
        }
        config
    };

    let storage = husker_storage::StorageConfig {
        data_dir: config.data_dir.clone(),
        state_dir: config.effective_state_dir(),
    };

    // Mount guard: when data_dir is a dedicated storage mount, refuse to start
    // (and create nothing under it) until the loopback is actually mounted.
    if !storage_mount_satisfied(config.storage_volume, storage.sentinel_path().exists()) {
        anyhow::bail!(
            "storage_volume is enabled but the storage loopback is not mounted \
             (sentinel {} missing). Mount it before starting husker \
             (systemctl start the .mount unit, or mount -o loop the image).",
            storage.sentinel_path().display()
        );
    }

    // Daemon lock: refuse to start a second daemon against the same state dir.
    std::fs::create_dir_all(storage.state_dir.clone()).context("creating state directory")?;
    restrict_dir_permissions(&storage.state_dir);
    let _daemon_lock = acquire_daemon_lock(&storage.lock_path())
        .context("another husker daemon is already running (state dir is locked)")?;

    let runtime_dir = storage.runtime_dir();
    let db_path = storage.db_path();
    let api_policy = husker_api::ApiPolicy {
        max_request_bytes: config.api_max_request_bytes,
        max_file_read_bytes: config.api_max_file_read_bytes,
        max_file_write_bytes: config.api_max_file_write_bytes,
        sensitive_rate_limit_per_minute: config.api_sensitive_rate_limit_per_minute,
        allowed_read_paths: config.allowed_read_paths.clone(),
        allowed_write_paths: config.allowed_write_paths.clone(),
        allowed_mount_host_paths: config.allowed_mount_host_paths.clone(),
        exec_timeout_secs: config.exec_timeout_secs,
        exec_timeout_max_secs: config.exec_timeout_max_secs,
        exec_allowlist: config.exec_allowlist.clone(),
        exec_denylist: config.exec_denylist.clone(),
        exec_env_allowlist: config.exec_env_allowlist.clone(),
    };
    husker_api::set_policy(api_policy);
    husker_api::set_max_vms(config.max_vms);

    std::fs::create_dir_all(&runtime_dir).context("creating runtime directory")?;
    restrict_dir_permissions(&runtime_dir);
    std::fs::create_dir_all(storage.vms_dir()).context("creating vms directory")?;
    restrict_dir_permissions(&storage.vms_dir());

    let state = husker_state::StateStore::open(&db_path).context("opening state database")?;

    #[cfg(target_os = "linux")]
    {
        let reaped = husker_core::reap_orphaned_vmms(&state);
        if reaped > 0 {
            tracing::info!(reaped, "reaped orphaned VMM processes from a prior run");
        }
    }

    let stale_count = state
        .mark_stale_vms_stopped()
        .context("reconciling stale VM state")?;
    if stale_count > 0 {
        tracing::info!(stale_count, "marked stale VMs as stopped");
    }

    // Reclaim host resources (TAP devices, sockets, orphaned rootfs clones) that a
    // prior daemon incarnation may have leaked on an unclean exit. Runs after the
    // stale-state pass, so nothing this daemon manages is running.
    reconcile_host_resources(&state, &storage, &runtime_dir).await;

    // macOS userspace port-forward proxies do not survive a daemon restart, so
    // every persisted forward is stale. Clear them so `list` reflects reality.
    #[cfg(not(feature = "linux-net"))]
    if let Err(e) = state.clear_all_port_forwards() {
        tracing::warn!(error = %e, "failed to clear stale port forwards on startup");
    }

    #[cfg(feature = "linux-net")]
    state
        .ensure_cid_base(config.cid_base)
        .context("applying cid_base")?;

    #[cfg(feature = "linux-net")]
    {
        let (base, prefix_len) = parse_cidr(&config.bridge_subnet)?;
        let ip_allocator = husker_net::IpAllocator::new(base, prefix_len);

        // Fail before creating host-network resources. The old hard exit lived
        // after bridge/NAT setup and made cleanup impossible on cgroup failure.
        #[cfg(target_os = "linux")]
        let cgroup = Arc::new(
            husker_vmm::cgroup::CgroupSupervisor::init(husker_vmm::cgroup::CgroupConfig {
                enabled: config.resource_limits,
                memory_overhead_mib: config.memory_overhead_mib,
                cpu_limit: config.cpu_limit,
            })
            .context("initializing cgroup resource limits")?,
        );

        // The allocator is in-memory and starts empty on each restart. Rebuild
        // its state from persisted VMs so a new allocation cannot collide with an
        // IP still recorded for an existing VM, and so releasing such an IP on
        // destroy succeeds. IPs outside this subnet (e.g. bridged-mode VMs) are
        // rejected by reserve() and skipped.
        if let Ok(vms) = state.list_vms() {
            let mut reserved = 0usize;
            for vm in &vms {
                if let Some(ip) = vm
                    .guest_ip
                    .as_deref()
                    .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
                    && ip_allocator.reserve(ip).is_ok()
                {
                    reserved += 1;
                }
            }
            if reserved > 0 {
                tracing::info!(reserved, "seeded IP allocator from persisted VMs");
            }
        }

        // Clean up any stale bridge from a previous run
        let _ = husker_net::delete_bridge(&config.bridge_name).await;

        // With our own bridge removed, any host route still overlapping the
        // configured subnet is a foreign conflict: reject it now with guidance
        // rather than silently hijacking host traffic once NAT rules go in.
        husker_net::check_subnet_conflict(
            base,
            prefix_len,
            &config.bridge_subnet,
            &config.bridge_name,
        )
        .await
        .context("checking bridge subnet for conflicts")?;

        let bridge_name = config.bridge_name.clone();
        husker_net::create_bridge(&bridge_name, ip_allocator.gateway(), prefix_len)
            .await
            .context("creating bridge")?;

        // From this point on, every return path flows through host-network
        // teardown. This includes nftables initialization and runtime failures.
        let runtime_result: Result<()> = async {
            // Resolve the NAT uplink ("auto" follows the IPv4 default route) and
            // surface anything that would silently leave guests without WAN.
            let uplink = husker_net::resolve_host_interface(&config.host_interface);
            for warning in &uplink.warnings {
                tracing::warn!("{warning}");
            }
            tracing::info!(
                iface = %uplink.effective,
                source = ?uplink.source,
                "guest NAT uplink"
            );

            // Build the isolation policy from config. Resolvers that parse as IPv4
            // become DNS carve-outs so guests keep name resolution under the deny.
            let isolation = config.guest_isolation.then(|| {
                let resolvers = config
                    .dns_servers
                    .iter()
                    .filter_map(|s| s.parse::<std::net::Ipv4Addr>().ok())
                    .collect();
                husker_net::IsolationPolicy { resolvers }
            });
            if isolation.is_some() {
                tracing::info!("guest isolation enabled: NAT guests denied LAN + host access");
            }
            husker_net::init_nat(
                &config.bridge_name,
                &config.bridge_subnet,
                &uplink.effective,
                isolation.as_ref(),
            )
            .await
            .context("initializing nftables")?;

            let runtime_config = DaemonRuntimeConfig::from_config(
                &config,
                listen,
                DaemonRuntimeMode::LinuxNet {
                    reclaim_grace_secs: config.reclaim_grace_secs,
                },
            );

            #[cfg(target_os = "linux")]
            let core = {
                let firecracker = husker_vmm::firecracker::FirecrackerBackend::new(
                    &config.firecracker_bin,
                    &runtime_dir,
                    Arc::clone(&cgroup),
                );
                let qemu =
                    husker_vmm::qemu::QemuKvmBackend::new(&config.qemu_bin, &runtime_dir, cgroup);
                let default_kind = match config.vmm {
                    VmmSelection::Qemu => husker_vmm::VmmKind::Qemu,
                    VmmSelection::Firecracker => husker_vmm::VmmKind::Firecracker,
                };
                let vmm = husker_vmm::LinuxDispatchBackend::new(firecracker, qemu, default_kind);
                if husker::agent_embedded() {
                    tracing::info!("cloud-image support enabled (guest agent embedded)");
                } else {
                    tracing::info!(
                        "cloud-image support disabled (no embedded agent; run make build-agent)"
                    );
                }
                Arc::new(
                    husker_core::HuskerCore::new(
                        vmm,
                        state,
                        ip_allocator,
                        storage,
                        config.bridge_name.clone(),
                        config.dns_servers,
                        runtime_dir.clone(),
                    )
                    .with_embedded_agent(husker::EMBEDDED_AGENT)
                    .with_storage_volume(config.storage_volume)
                    .with_resource_limits(config.resource_limits)
                    .with_host_interface(uplink.effective.clone())
                    .with_uefi_firmware(config.ovmf_code.clone(), config.ovmf_vars.clone())
                    .with_lan_bridge(config.lan_bridge.clone())
                    .with_default_vmm_kind(default_kind)
                    .with_default_images(
                        Some(config.default_kernel.clone()),
                        Some(config.default_rootfs.clone()),
                        config.default_initrd.clone(),
                    )
                    .with_default_resources(config.default_memory, config.default_cpus)
                    .with_profiles(
                        config
                            .profiles
                            .iter()
                            .map(|(k, v)| (k.clone(), profile_to_daemon(v)))
                            .collect(),
                    )
                    .with_idle_policy(config.idle_policy.clone().into()),
                )
            };
            #[cfg(not(target_os = "linux"))]
            let core = {
                // linux-net without target_os=linux (not a real deployment target):
                // no QEMU/vsock available, so Firecracker only.
                let vmm = husker_vmm::firecracker::FirecrackerBackend::new(
                    &config.firecracker_bin,
                    &runtime_dir,
                    std::sync::Arc::new(husker_vmm::cgroup::CgroupSupervisor::disabled()),
                );
                Arc::new(
                    husker_core::HuskerCore::new(
                        vmm,
                        state,
                        ip_allocator,
                        storage,
                        config.bridge_name.clone(),
                        config.dns_servers,
                        runtime_dir.clone(),
                    )
                    .with_storage_volume(config.storage_volume)
                    .with_resource_limits(config.resource_limits)
                    .with_host_interface(uplink.effective.clone())
                    .with_default_images(
                        Some(config.default_kernel.clone()),
                        Some(config.default_rootfs.clone()),
                        config.default_initrd.clone(),
                    )
                    .with_default_resources(config.default_memory, config.default_cpus)
                    .with_profiles(
                        config
                            .profiles
                            .iter()
                            .map(|(k, v)| (k.clone(), profile_to_daemon(v)))
                            .collect(),
                    )
                    .with_idle_policy(config.idle_policy.clone().into()),
                )
            };
            run_daemon_runtime(core, runtime_config).await
        }
        .await;

        // Network cleanup after VM drain. If the process is killed
        // (SIGKILL, panic, OOM), the stale bridge cleanup at startup above
        // handles the next launch.
        finish_linux_network(
            runtime_result,
            async {
                husker_net::cleanup_nat(&bridge_name)
                    .await
                    .context("cleaning up daemon NAT rules")
            },
            async {
                husker_net::delete_bridge(&bridge_name)
                    .await
                    .context("deleting daemon bridge")
            },
        )
        .await
    }

    #[cfg(all(not(feature = "linux-net"), target_os = "macos"))]
    {
        let runtime_config =
            DaemonRuntimeConfig::from_config(&config, listen, DaemonRuntimeMode::Basic);
        let vmm = husker_vmm::apple_vz::AppleVzBackend::new(&runtime_dir);

        let core = Arc::new(
            husker_core::HuskerCore::new(vmm, state, storage, runtime_dir.clone())
                .with_embedded_agent(husker::EMBEDDED_AGENT)
                .with_storage_volume(config.storage_volume)
                .with_resource_limits(config.resource_limits)
                .with_default_images(
                    Some(config.default_kernel.clone()),
                    Some(config.default_rootfs.clone()),
                    config.default_initrd.clone(),
                )
                .with_default_resources(config.default_memory, config.default_cpus)
                .with_profiles(
                    config
                        .profiles
                        .iter()
                        .map(|(k, v)| (k.clone(), profile_to_daemon(v)))
                        .collect(),
                ),
        );

        run_daemon_runtime(core, runtime_config).await
    }

    #[cfg(all(not(feature = "linux-net"), not(target_os = "macos")))]
    {
        let runtime_config =
            DaemonRuntimeConfig::from_config(&config, listen, DaemonRuntimeMode::Basic);
        // No networking stack available (no `linux-net` feature, not macOS).
        // The API server can still run; VM operations will fail at create time
        // because no networking is configured. Primarily used by CI drills.
        let vmm = husker_vmm::firecracker::FirecrackerBackend::new(
            PathBuf::from("firecracker"),
            &runtime_dir,
            std::sync::Arc::new(husker_vmm::cgroup::CgroupSupervisor::disabled()),
        );

        let core = Arc::new(
            husker_core::HuskerCore::new(vmm, state, storage, runtime_dir.clone())
                .with_embedded_agent(husker::EMBEDDED_AGENT)
                .with_storage_volume(config.storage_volume)
                .with_resource_limits(config.resource_limits)
                .with_default_images(
                    Some(config.default_kernel.clone()),
                    Some(config.default_rootfs.clone()),
                    config.default_initrd.clone(),
                )
                .with_default_resources(config.default_memory, config.default_cpus)
                .with_profiles(
                    config
                        .profiles
                        .iter()
                        .map(|(k, v)| (k.clone(), profile_to_daemon(v)))
                        .collect(),
                ),
        );

        run_daemon_runtime(core, runtime_config).await
    }
}

/// Run an initial service reconcile for all services, then create the ordinal index.
/// Always run on daemon startup (independent of the periodic-loop setting).
async fn run_initial_service_reconcile<B: husker_vmm::VmmBackend + 'static>(
    core: &Arc<husker_core::HuskerCore<B>>,
) {
    // Recover any source rootfs left stranded by a fork that crashed mid-load,
    // BEFORE the suspend reconcile (which can leave VMs resumable): a later
    // resume must not open a stale symlink to a fork clone.
    let recovered_disks = core.recover_stranded_fork_rootfs();
    if recovered_disks > 0 {
        tracing::info!(
            recovered_disks,
            "recovered source rootfs disks stranded by interrupted forks"
        );
    }
    // Recover any VM interrupted mid-suspend on the previous run, so a VM whose
    // memory was freed before its state write is finished to "suspended"
    // (resumable) instead of being lost. Runs on every platform branch.
    match core.reconcile_suspended_vms().await {
        Ok(n) if n > 0 => tracing::info!(reconciled = n, "recovered interrupted suspends"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "failed to reconcile interrupted suspends"),
    }
    match core.list_services() {
        Ok(services) => {
            for svc in &services {
                let o = core.reconcile_service(svc).await;
                if !o.created.is_empty() || !o.destroyed.is_empty() || !o.failed.is_empty() {
                    tracing::info!(
                        service = %svc.name,
                        created = o.created.len(),
                        destroyed = o.destroyed.len(),
                        failed = o.failed.len(),
                        "startup service reconcile"
                    );
                }
            }
        }
        Err(e) => tracing::warn!(error = %e, "failed to list services for startup reconcile"),
    }
    if let Err(e) = core.create_service_ordinal_index() {
        tracing::warn!(error = %e, "failed to create service ordinal index");
    }
}

/// Configuration for the lifecycle that begins after a platform adapter has
/// assembled its `HuskerCore`.
#[derive(Debug)]
struct DaemonRuntimeConfig {
    listen: SocketAddr,
    api_token: Option<String>,
    metrics_listen: Option<SocketAddr>,
    metrics_token: Option<String>,
    service_reconcile_enabled: bool,
    service_reconcile_interval: u64,
    mode: DaemonRuntimeMode,
}

impl DaemonRuntimeConfig {
    fn from_config(config: &Config, listen: SocketAddr, mode: DaemonRuntimeMode) -> Self {
        Self {
            listen,
            api_token: config.api_token.clone(),
            metrics_listen: config.metrics_listen,
            metrics_token: config.metrics_token.clone(),
            service_reconcile_enabled: config.service_reconcile_enabled,
            service_reconcile_interval: config.service_reconcile_interval_secs,
            mode,
        }
    }
}

/// The only valid platform extensions to the shared daemon runtime. Keeping
/// this as a closed enum makes Linux-only recovery and workers explicit without
/// admitting impossible combinations of feature booleans.
#[derive(Debug)]
enum DaemonRuntimeMode {
    #[cfg_attr(feature = "linux-net", allow(dead_code))]
    Basic,
    #[cfg(feature = "linux-net")]
    LinuxNet { reclaim_grace_secs: u64 },
}

/// Own every task started by the daemon runtime. Mutating workers receive a
/// cooperative stop signal, so an in-flight reconciliation completes before VM
/// draining begins. Read-only endpoints may be aborted after those workers stop.
struct RuntimeWorkers {
    shutdown: tokio::sync::watch::Sender<bool>,
    cooperative: Vec<tokio::task::JoinHandle<()>>,
    abortable: Vec<tokio::task::JoinHandle<()>>,
}

impl RuntimeWorkers {
    const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

    fn new() -> Self {
        let (shutdown, _) = tokio::sync::watch::channel(false);
        Self {
            shutdown,
            cooperative: Vec::new(),
            abortable: Vec::new(),
        }
    }

    fn shutdown_signal(&self) -> tokio::sync::watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    fn supervise(&mut self, worker: Option<tokio::task::JoinHandle<()>>) {
        if let Some(worker) = worker {
            self.cooperative.push(worker);
        }
    }

    fn supervise_abortable(&mut self, worker: Option<tokio::task::JoinHandle<()>>) {
        if let Some(worker) = worker {
            self.abortable.push(worker);
        }
    }

    async fn stop_with_grace(&mut self, grace: std::time::Duration) {
        tracing::info!(
            cooperative = self.cooperative.len(),
            abortable = self.abortable.len(),
            "stopping daemon background workers"
        );
        self.shutdown.send_replace(true);
        let deadline = tokio::time::Instant::now() + grace;
        for mut worker in self.cooperative.drain(..) {
            match tokio::time::timeout_at(deadline, &mut worker).await {
                Ok(result) => report_worker_exit(result, "background worker"),
                Err(_) => {
                    tracing::warn!("background worker did not stop within grace period; aborting");
                    worker.abort();
                    report_worker_exit(worker.await, "background worker");
                }
            }
        }
        for worker in &self.abortable {
            worker.abort();
        }
        for worker in self.abortable.drain(..) {
            report_worker_exit(worker.await, "background endpoint");
        }
        tracing::info!("daemon background workers stopped");
    }
}

impl Drop for RuntimeWorkers {
    fn drop(&mut self) {
        // A panic or future early-return must never detach daemon-owned work.
        for worker in self.cooperative.iter().chain(&self.abortable) {
            worker.abort();
        }
    }
}

fn report_worker_exit(result: std::result::Result<(), tokio::task::JoinError>, kind: &str) {
    if let Err(error) = result
        && !error.is_cancelled()
    {
        tracing::error!(%error, "{kind} failed while stopping daemon runtime");
    }
}

async fn wait_for_runtime_shutdown(shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}

/// Complete the daemon lifecycle in a fixed order and preserve the original
/// server outcome: stop workers, drain VMs, then return the serving result.
async fn finish_daemon_runtime<S, D>(workers: RuntimeWorkers, serve: S, drain: D) -> Result<()>
where
    S: std::future::Future<Output = Result<()>>,
    D: std::future::Future<Output = ()>,
{
    finish_daemon_runtime_with_grace(workers, serve, drain, RuntimeWorkers::SHUTDOWN_GRACE).await
}

async fn finish_daemon_runtime_with_grace<S, D>(
    mut workers: RuntimeWorkers,
    serve: S,
    drain: D,
    worker_grace: std::time::Duration,
) -> Result<()>
where
    S: std::future::Future<Output = Result<()>>,
    D: std::future::Future<Output = ()>,
{
    let serve_result = serve.await;
    workers.stop_with_grace(worker_grace).await;
    drain.await;
    serve_result
}

/// Attempt both Linux host-network teardown steps and preserve the most useful
/// failure. A runtime failure is primary because it explains why serving ended;
/// otherwise the first cleanup failure becomes the returned error.
#[cfg(feature = "linux-net")]
async fn finish_linux_network<N, B>(
    runtime_result: Result<()>,
    cleanup_nat: N,
    delete_bridge: B,
) -> Result<()>
where
    N: std::future::Future<Output = Result<()>>,
    B: std::future::Future<Output = Result<()>>,
{
    let nat_result = cleanup_nat.await;
    let bridge_result = delete_bridge.await;

    match runtime_result {
        Err(runtime_error) => {
            if let Err(error) = nat_result {
                tracing::warn!(%error, "secondary NAT cleanup failure");
            }
            if let Err(error) = bridge_result {
                tracing::warn!(%error, "secondary bridge cleanup failure");
            }
            Err(runtime_error)
        }
        Ok(()) => match (nat_result, bridge_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(error), Err(secondary)) => {
                tracing::warn!(error = %secondary, "secondary bridge cleanup failure");
                Err(error)
            }
        },
    }
}

/// Run the shared post-core daemon lifecycle. Platform adapters retain backend
/// construction and host-network setup/teardown; this interface owns startup
/// reconciliation, workers, serving, cancellation, draining, and outcome order.
async fn run_daemon_runtime<B: husker_vmm::VmmBackend + 'static>(
    core: Arc<husker_core::HuskerCore<B>>,
    config: DaemonRuntimeConfig,
) -> Result<()> {
    #[cfg(feature = "linux-net")]
    let reclaim_network_on_shutdown = matches!(&config.mode, DaemonRuntimeMode::LinuxNet { .. });

    run_initial_service_reconcile(&core).await;

    match &config.mode {
        DaemonRuntimeMode::Basic => {}
        #[cfg(feature = "linux-net")]
        DaemonRuntimeMode::LinuxNet { .. } => {
            let reconcile = core.reconcile_port_forwards_from_state().await;
            if reconcile.restored > 0 {
                tracing::info!(
                    restored = reconcile.restored,
                    "restored persisted port-forward nftables rules"
                );
            }
            if reconcile.skipped_suspended > 0 {
                tracing::info!(
                    skipped = reconcile.skipped_suspended,
                    "skipped DNAT restore for suspended VMs; re-installing resume listeners instead"
                );
            }
            core.reinstall_resume_listeners().await;
        }
    }

    let mut workers = RuntimeWorkers::new();
    workers.supervise(spawn_service_reconcile_loop(
        Arc::clone(&core),
        config.service_reconcile_enabled,
        config.service_reconcile_interval,
        workers.shutdown_signal(),
    ));
    workers.supervise(Some(spawn_log_rotation(
        Arc::clone(&core),
        workers.shutdown_signal(),
    )));
    workers.supervise_abortable(spawn_metrics_endpoint(
        Arc::clone(&core),
        config.metrics_listen,
        config.metrics_token,
    ));

    #[cfg(feature = "linux-net")]
    if let DaemonRuntimeMode::LinuxNet { reclaim_grace_secs } = config.mode {
        workers.supervise(spawn_reclaim_loop(
            Arc::clone(&core),
            reclaim_grace_secs,
            workers.shutdown_signal(),
        ));
        workers.supervise(Some(spawn_idle_policy_loop(
            Arc::clone(&core),
            core.idle_policy().poll_interval_secs,
            workers.shutdown_signal(),
        )));
    }

    let serve = async {
        husker_api::serve_with_auth(Arc::clone(&core), config.listen, config.api_token)
            .await
            .context("serving daemon API")
    };
    let drain = async {
        core.quiesce_shutdown_ingress();
        drain_vms_on_shutdown(&core).await;
        #[cfg(feature = "linux-net")]
        if reclaim_network_on_shutdown {
            let reclaimed = core.reclaim_shutdown_vms().await;
            if reclaimed > 0 {
                tracing::info!(reclaimed, "released drained VM host resources");
            }
        }
    };
    finish_daemon_runtime(workers, serve, drain).await
}

/// Spawn the standalone metrics endpoint if configured. It is read-only and is
/// aborted after cooperative mutating workers have stopped. A bind failure is
/// logged, not fatal: the daemon must still serve its primary API.
fn spawn_metrics_endpoint<B: husker_vmm::VmmBackend + 'static>(
    core: Arc<husker_core::HuskerCore<B>>,
    metrics_listen: Option<SocketAddr>,
    metrics_token: Option<String>,
) -> Option<tokio::task::JoinHandle<()>> {
    metrics_listen.map(|addr| {
        tokio::spawn(async move {
            if let Err(error) = husker_api::serve_metrics(core, addr, metrics_token).await {
                tracing::error!(%addr, %error, "metrics endpoint failed to serve");
            }
        })
    })
}

/// Spawn the periodic self-healing reconcile loop (only when enabled).
/// Spawn the crashed-VM reclaim sweep: periodically release leaked host
/// resources (TAP/nftables/IP) from VMs abandoned past `grace_secs`, keeping the
/// stopped record. Disabled when `grace_secs == 0`. Linux only.
#[cfg(feature = "linux-net")]
fn spawn_reclaim_loop<B: husker_vmm::VmmBackend + 'static>(
    core: Arc<husker_core::HuskerCore<B>>,
    grace_secs: u64,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    if grace_secs == 0 {
        return None;
    }
    // Sweep at roughly half the grace period, bounded to [30s, 300s], so a leak
    // is reclaimed reasonably soon after the grace expires without busy-looping.
    let interval = std::time::Duration::from_secs((grace_secs / 2).clamp(30, 300));
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // consume the immediate first tick
        loop {
            tokio::select! {
                biased;
                () = wait_for_runtime_shutdown(&mut shutdown) => break,
                _ = ticker.tick() => {
                    let n = core.reclaim_abandoned_vms(grace_secs).await;
                    if n > 0 {
                        tracing::info!(
                            reclaimed = n,
                            "reclaim sweep released abandoned VM resources"
                        );
                    }
                }
            }
        }
    }))
}

fn spawn_service_reconcile_loop<B: husker_vmm::VmmBackend + 'static>(
    core: Arc<husker_core::HuskerCore<B>>,
    enabled: bool,
    interval_secs: u64,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !enabled {
        return None;
    }
    let interval = std::time::Duration::from_secs(interval_secs.max(1));
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // consume the immediate first tick
        loop {
            tokio::select! {
                biased;
                () = wait_for_runtime_shutdown(&mut shutdown) => break,
                _ = ticker.tick() => {
                    let services = match core.list_services() {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!(error = %e, "reconcile loop: list_services failed");
                            continue;
                        }
                    };
                    for svc in &services {
                        let o = core.reconcile_service(svc).await;
                        if !o.created.is_empty() || !o.destroyed.is_empty() || !o.failed.is_empty() {
                            tracing::info!(
                                service = %svc.name,
                                created = o.created.len(),
                                destroyed = o.destroyed.len(),
                                failed = o.failed.len(),
                                "reconcile loop"
                            );
                        }
                    }
                    // Attempt to create the unique ordinal index after reconciling all
                    // services. It is idempotent (CREATE UNIQUE INDEX IF NOT EXISTS) and
                    // only fails while a duplicate ordinal still exists. Each tick's
                    // reconcile removes duplicates, so a later tick will succeed.
                    if let Err(e) = core.create_service_ordinal_index() {
                        tracing::warn!(error = %e, "reconcile loop: failed to create ordinal index");
                    }
                }
            }
        }
    }))
}

/// Spawn the periodic idle-policy evaluation loop: one `idle_policy_tick` per
/// poll interval, suspending idle VMs and reaping expired suspends.
///
/// Only called from the `LinuxNet` daemon runtime: suspend/resume relies on the
/// nftables DNAT removal and userspace resume listeners that `linux-net`
/// provides, so the idle policy loop has no basic-runtime counterpart.
#[cfg(feature = "linux-net")]
fn spawn_idle_policy_loop<B: husker_vmm::VmmBackend + 'static>(
    core: Arc<husker_core::HuskerCore<B>>,
    poll_interval_secs: u64,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let interval = std::time::Duration::from_secs(poll_interval_secs.max(1));
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // consume the immediate first tick
        loop {
            tokio::select! {
                biased;
                () = wait_for_runtime_shutdown(&mut shutdown) => break,
                _ = ticker.tick() => core.idle_policy_tick().await,
            }
        }
    })
}

/// Spawn a background task that rotates oversized serial logs every hour.
fn spawn_log_rotation<B: husker_vmm::VmmBackend + 'static>(
    core: Arc<husker_core::HuskerCore<B>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        interval.tick().await; // first tick fires immediately, skip it
        loop {
            tokio::select! {
                biased;
                () = wait_for_runtime_shutdown(&mut shutdown) => break,
                _ = interval.tick() => {
                    let count = core.rotate_serial_logs().await;
                    if count > 0 {
                        tracing::info!(count, "rotated serial logs");
                    }
                }
            }
        }
    })
}

/// Drain all running/paused VMs with a 30-second timeout.
async fn drain_vms_on_shutdown<B: husker_vmm::VmmBackend>(core: &husker_core::HuskerCore<B>) {
    tracing::info!("shutting down, draining VMs");
    match tokio::time::timeout(std::time::Duration::from_secs(30), core.drain_vms()).await {
        Ok(count) => {
            if count > 0 {
                tracing::info!(count, "drained VMs on shutdown");
            }
        }
        Err(_) => {
            tracing::warn!("VM drain timed out after 30s");
        }
    }
}

#[cfg(test)]
mod runtime_tests {
    use super::*;

    type Events = Arc<std::sync::Mutex<Vec<&'static str>>>;

    fn record(events: &Events, event: &'static str) {
        events.lock().expect("events lock poisoned").push(event);
    }

    #[tokio::test]
    async fn runtime_stops_workers_before_drain() {
        let events = Events::default();
        let mut workers = RuntimeWorkers::new();
        let mut shutdown = workers.shutdown_signal();
        let worker_events = Arc::clone(&events);
        workers.supervise(Some(tokio::spawn(async move {
            wait_for_runtime_shutdown(&mut shutdown).await;
            record(&worker_events, "worker stopping");
            tokio::task::yield_now().await;
            record(&worker_events, "worker stopped");
        })));

        let serve_events = Arc::clone(&events);
        let serve = async move {
            record(&serve_events, "server stopped");
            Ok(())
        };
        let drain_events = Arc::clone(&events);
        let drain = async move { record(&drain_events, "VMs drained") };

        finish_daemon_runtime(workers, serve, drain).await.unwrap();
        assert_eq!(
            *events.lock().unwrap(),
            [
                "server stopped",
                "worker stopping",
                "worker stopped",
                "VMs drained"
            ]
        );
    }

    #[tokio::test]
    async fn runtime_drains_and_preserves_server_error() {
        let events = Events::default();
        let workers = RuntimeWorkers::new();
        let drain_events = Arc::clone(&events);

        let error = finish_daemon_runtime(
            workers,
            async { anyhow::bail!("primary server failure") },
            async move { record(&drain_events, "VMs drained") },
        )
        .await
        .unwrap_err();

        assert_eq!(error.to_string(), "primary server failure");
        assert_eq!(*events.lock().unwrap(), ["VMs drained"]);
    }

    struct RecordDrop {
        events: Events,
    }

    impl Drop for RecordDrop {
        fn drop(&mut self) {
            record(&self.events, "worker aborted");
        }
    }

    #[tokio::test]
    async fn stuck_worker_is_aborted_before_drain() {
        let events = Events::default();
        let mut workers = RuntimeWorkers::new();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let worker_events = Arc::clone(&events);
        workers.supervise(Some(tokio::spawn(async move {
            let _drop = RecordDrop {
                events: worker_events,
            };
            ready_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        })));
        ready_rx.await.unwrap();

        let drain_events = Arc::clone(&events);
        finish_daemon_runtime_with_grace(
            workers,
            async { Ok(()) },
            async move { record(&drain_events, "VMs drained") },
            std::time::Duration::from_millis(10),
        )
        .await
        .unwrap();

        assert_eq!(*events.lock().unwrap(), ["worker aborted", "VMs drained"]);
    }

    #[cfg(feature = "linux-net")]
    #[tokio::test]
    async fn linux_cleanup_attempts_both_steps_and_preserves_runtime_error() {
        let events = Events::default();
        let nat_events = Arc::clone(&events);
        let bridge_events = Arc::clone(&events);

        let error = finish_linux_network(
            Err(anyhow::anyhow!("runtime failed")),
            async move {
                record(&nat_events, "NAT cleaned");
                anyhow::bail!("NAT cleanup failed")
            },
            async move {
                record(&bridge_events, "bridge deleted");
                anyhow::bail!("bridge cleanup failed")
            },
        )
        .await
        .unwrap_err();

        assert_eq!(error.to_string(), "runtime failed");
        assert_eq!(*events.lock().unwrap(), ["NAT cleaned", "bridge deleted"]);
    }

    #[cfg(feature = "linux-net")]
    #[tokio::test]
    async fn linux_cleanup_error_is_returned_after_successful_runtime() {
        let error = finish_linux_network(
            Ok(()),
            async { anyhow::bail!("NAT cleanup failed") },
            async { Ok(()) },
        )
        .await
        .unwrap_err();

        assert_eq!(error.to_string(), "NAT cleanup failed");
    }
}
