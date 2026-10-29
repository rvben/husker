use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::guest_stop::{GUEST_SHUTDOWN_GRACE, GuestExit, wait_for_process_exit_or_kill};
use crate::{
    BackendKind, CreatedVm, RestoreTarget, SnapshotMeta, SnapshotPaths, VmConfig, VmInfo, VmState,
    VmmBackend, VmmError,
};

/// Tracks a running Firecracker VM instance.
struct FcInstance {
    info: VmInfo,
    socket_path: PathBuf,
    vsock_path: PathBuf,
    boot_log_path: PathBuf,
    serial_log_path: PathBuf,
    /// Finished once the process is confirmed exited, keeping its final output.
    serial_capture: Option<crate::serial_capture::SerialCapture>,
    process: tokio::process::Child,
    /// Whether the balloon device was installed at boot.
    balloon: bool,
    /// Per-VM cgroup resource limits (no-op when the supervisor is disabled).
    cgroup: crate::cgroup::VmCgroup,
    fork_source: Option<ForkSource>,
}

/// Source ownership follows the registered child, not its observation future.
struct ForkSource {
    _source_lock: Arc<tokio::sync::OwnedMutexGuard<()>>,
    alias: RootfsAlias,
}

/// Explicitly restored after load acknowledgment or confirmed child exit.
/// Drop deliberately leaves ambiguous disk ownership stranded for reconciliation.
struct RootfsAlias {
    source_rootfs: PathBuf,
    fork_rootfs: PathBuf,
    backup: PathBuf,
    original_identity: (u64, u64),
    stashed: bool,
    linked: bool,
}

/// Path of the backup that [`RootfsAlias`] stashes a source rootfs into while a
/// fork holds it aliased to the fork's clone during `/snapshot/load`.
fn fork_src_backup_path(source_rootfs: &Path) -> PathBuf {
    PathBuf::from(format!("{}.fork-src-bak", source_rootfs.display()))
}

impl RootfsAlias {
    fn prepare(source_rootfs: &Path, fork_rootfs: &Path) -> Result<Self, VmmError> {
        use std::os::unix::fs::MetadataExt;
        let source = std::fs::symlink_metadata(source_rootfs)?;
        let fork = std::fs::symlink_metadata(fork_rootfs)?;
        let backup = fork_src_backup_path(source_rootfs);
        if !source.is_file()
            || !fork.is_file()
            || source.nlink() != 1
            || fork.nlink() != 1
            || (source.dev(), source.ino()) == (fork.dev(), fork.ino())
        {
            return Err(VmmError::InvalidConfig(
                "fork disks must be distinct regular files with one link".into(),
            ));
        }
        match std::fs::symlink_metadata(&backup) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
            Ok(_) => {
                return Err(VmmError::ProcessError(
                    "fork source backup requires prior reconciliation".into(),
                ));
            }
        }
        Ok(Self {
            source_rootfs: source_rootfs.to_path_buf(),
            fork_rootfs: fork_rootfs.to_path_buf(),
            backup,
            original_identity: (source.dev(), source.ino()),
            stashed: false,
            linked: false,
        })
    }

    fn activate(&mut self) -> Result<(), VmmError> {
        use std::os::unix::fs::MetadataExt;
        let source = std::fs::symlink_metadata(&self.source_rootfs)?;
        if !source.is_file() || (source.dev(), source.ino()) != self.original_identity {
            return Err(VmmError::ProcessError(
                "fork source identity changed before alias".into(),
            ));
        }
        match std::fs::symlink_metadata(&self.backup) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
            Ok(_) => {
                return Err(VmmError::ProcessError(
                    "fork source backup unexpectedly occupied".into(),
                ));
            }
        }
        std::fs::rename(&self.source_rootfs, &self.backup)?;
        self.stashed = true;
        std::os::unix::fs::symlink(&self.fork_rootfs, &self.source_rootfs)?;
        self.linked = true;
        Ok(())
    }

    fn undo(&mut self) -> Result<(), VmmError> {
        use std::os::unix::fs::MetadataExt;
        if !self.stashed {
            return Ok(());
        }
        let backup = std::fs::symlink_metadata(&self.backup)?;
        if !backup.is_file() || (backup.dev(), backup.ino()) != self.original_identity {
            return Err(VmmError::ProcessError(
                "fork source backup identity changed".into(),
            ));
        }
        if self.linked {
            if std::fs::read_link(&self.source_rootfs)? != self.fork_rootfs {
                return Err(VmmError::ProcessError(
                    "fork source alias identity changed".into(),
                ));
            }
        } else {
            match std::fs::symlink_metadata(&self.source_rootfs) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e.into()),
                Ok(_) => {
                    return Err(VmmError::ProcessError(
                        "fork source path unexpectedly occupied".into(),
                    ));
                }
            }
        }
        // Atomically replace the owned symlink, preserving ownership on error.
        std::fs::rename(&self.backup, &self.source_rootfs)?;
        self.stashed = false;
        self.linked = false;
        Ok(())
    }
}

impl Drop for RootfsAlias {
    fn drop(&mut self) {
        if self.stashed {
            tracing::warn!(source = %self.source_rootfs.display(), "fork source alias remains unreconciled; no destruction proof on drop");
        }
    }
}

/// Firecracker VMM backend.
///
/// Communicates with each Firecracker process via its HTTP-over-Unix-socket API.
pub struct FirecrackerBackend {
    firecracker_bin: PathBuf,
    runtime_dir: PathBuf,
    creation_locks: crate::creation::CreationLocks,
    instances: Arc<Mutex<HashMap<Uuid, FcInstance>>>,
    /// Pre-allocation children survive cancelled observations until confirmed reap.
    version_probes: Mutex<HashMap<Uuid, tokio::process::Child>>,
    cgroup: std::sync::Arc<crate::cgroup::CgroupSupervisor>,
}

/// Minimum Firecracker version `husker fork` needs: `network_overrides` (1.12.0,
/// PR #4731) to rebind the host TAP, plus `vsock_override` (1.16.0, PR #5323) to
/// give each fork its own vsock socket so concurrent forks of one snapshot do
/// not collide on the host UDS. The later of the two requirements wins.
const FORK_MIN_FIRECRACKER: (u32, u32, u32) = (1, 16, 0);
const VERSION_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const VERSION_OUTPUT_LIMIT: usize = 4096;

/// Record that `instance`'s Firecracker process has exited: the VM is stopped,
/// has no pid, and its cgroup is released.
async fn settle_stopped(instance: &mut FcInstance) {
    instance.info.state = VmState::Stopped;
    instance.info.pid = None;
    instance.cgroup.remove().await;
    crate::serial_capture::finish_child_capture(&mut instance.serial_capture).await;
}

/// Wait for a guest-triggered Firecracker exit and force termination when the
/// guest does not shut down within the bound. A successful `stop_vm` must mean
/// the process no longer owns its TAP/rootfs/vsock resources; merely accepting
/// `SendCtrlAltDel` is not sufficient for callers that immediately clean them.
async fn wait_for_exit_or_kill(
    instances: &Mutex<HashMap<Uuid, FcInstance>>,
    id: Uuid,
    grace: std::time::Duration,
) -> Result<GuestExit, VmmError> {
    wait_for_process_exit_or_kill(instances, id, grace, "firecracker", |instance| {
        Some(&mut instance.process)
    })
    .await
}

/// Parse Firecracker's `--version` output into `(major, minor, patch)`. The
/// first line looks like `Firecracker v1.16.0`; the first whitespace token that
/// parses as `X.Y[.Z]` (optional leading `v`, trailing non-digits ignored) wins.
fn parse_firecracker_version(output: &str) -> Option<(u32, u32, u32)> {
    let line = output.lines().next()?;
    line.split_whitespace().find_map(|tok| {
        let t = tok.trim_start_matches('v');
        let mut it = t.split('.');
        let major = it.next()?.parse::<u32>().ok()?;
        let minor = it.next()?.parse::<u32>().ok()?;
        let patch = it
            .next()
            .map(|p| {
                p.chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse()
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        Some((major, minor, patch))
    })
}

impl FirecrackerBackend {
    pub fn new(
        firecracker_bin: impl Into<PathBuf>,
        runtime_dir: impl Into<PathBuf>,
        cgroup: std::sync::Arc<crate::cgroup::CgroupSupervisor>,
    ) -> Self {
        Self {
            firecracker_bin: firecracker_bin.into(),
            runtime_dir: runtime_dir.into(),
            instances: Arc::new(Mutex::new(HashMap::new())),
            version_probes: Mutex::new(HashMap::new()),
            creation_locks: crate::creation::CreationLocks::default(),
            cgroup,
        }
    }

    /// Fail with a clear message when the installed Firecracker is too old to
    /// fork (it would otherwise reject the `network_overrides` / `vsock_override`
    /// fields with an opaque 400). Run `firecracker --version` and compare.
    async fn assert_firecracker_supports_fork(&self, id: Uuid) -> Result<(), VmmError> {
        use tokio::io::AsyncReadExt;
        let mut probes = self.version_probes.lock().await;
        if probes.contains_key(&id) {
            return Err(VmmError::InvalidConfig(
                "version probe UUID is already allocated".into(),
            ));
        }
        let mut process = tokio::process::Command::new(&self.firecracker_bin)
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                VmmError::ProcessError(format!(
                    "run `{} --version`: {e}",
                    self.firecracker_bin.display()
                ))
            })?;
        let stdout = process.stdout.take().expect("piped version stdout");
        probes.insert(id, process);
        let process = probes.get_mut(&id).unwrap();
        let result = tokio::time::timeout(VERSION_PROBE_TIMEOUT, async {
            let mut output = Vec::new();
            stdout
                .take((VERSION_OUTPUT_LIMIT + 1) as u64)
                .read_to_end(&mut output)
                .await?;
            if output.len() > VERSION_OUTPUT_LIMIT {
                return Err(VmmError::ProcessError(
                    "Firecracker version output exceeds 4 KiB".into(),
                ));
            }
            let status = process.wait().await?;
            if !status.success() {
                return Err(VmmError::ProcessError(
                    "Firecracker version command failed".into(),
                ));
            }
            Ok(output)
        })
        .await
        .unwrap_or_else(|_| {
            Err(VmmError::ProcessError(
                "Firecracker version probe exceeded 3s".into(),
            ))
        });
        // Keep ownership on cancellation or failed termination; the UUID cleanup
        // path can retry. Only a confirmed exit releases this pre-allocation child.
        crate::termination::terminate_child(process, "Firecracker version probe").await?;
        let output = result?;
        let text = String::from_utf8_lossy(&output);
        let version = parse_firecracker_version(&text).ok_or_else(|| {
            VmmError::ProcessError(format!(
                "could not parse Firecracker version from: {}",
                text.trim()
            ))
        })?;
        if version < FORK_MIN_FIRECRACKER {
            let (mi, mj, mp) = FORK_MIN_FIRECRACKER;
            let (a, b, c) = version;
            return Err(VmmError::Unsupported(format!(
                "husker fork requires Firecracker >= {mi}.{mj}.{mp} (it rebinds the host TAP and \
                 the vsock socket on snapshot restore via `network_overrides` + `vsock_override`); \
                 found {a}.{b}.{c}. Upgrade firecracker."
            )));
        }
        probes.remove(&id);
        Ok(())
    }

    /// Send an HTTP request to the Firecracker API over its Unix socket.
    ///
    /// Returns the response body as bytes. On non-2xx status, reads the error
    /// body and includes it in the error message.
    async fn fc_request(
        socket_path: &Path,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<Bytes, VmmError> {
        let budget = if matches!(path, "/snapshot/create" | "/snapshot/load") {
            std::time::Duration::from_secs(120)
        } else {
            std::time::Duration::from_secs(10)
        };
        tokio::time::timeout(budget, Self::fc_exchange(socket_path, method, path, body))
            .await
            .map_err(|_| {
                VmmError::ApiError(format!(
                    "{method} {path} timed out after {}s",
                    budget.as_secs()
                ))
            })?
    }

    async fn fc_exchange(
        socket_path: &Path,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<Bytes, VmmError> {
        const MAX_RESPONSE_BYTES: usize = 64 * 1024;
        let body_bytes = match body {
            Some(v) => {
                serde_json::to_vec(v).map_err(|e| VmmError::ApiError(format!("serialize: {e}")))?
            }
            None => Vec::new(),
        };
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("Host", "localhost")
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))
            .map_err(|e| VmmError::ApiError(format!("build request: {e}")))?;
        let stream = tokio::net::UnixStream::connect(socket_path)
            .await
            .map_err(|e| VmmError::ApiError(format!("connect Firecracker API: {e}")))?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| VmmError::ApiError(format!("Firecracker HTTP handshake: {e}")))?;
        // The HTTP driver owns the socket. Always abort it on return, timeout or
        // caller cancellation instead of leaving a detached pooled connection.
        struct ConnectionTask(tokio::task::JoinHandle<()>);
        impl Drop for ConnectionTask {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let _connection = ConnectionTask(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| VmmError::ApiError(format!("{method} {path}: {e}")))?;
        let status = resp.status();
        let mut response = resp.into_body();
        let mut retained = Vec::new();
        while let Some(frame) = response.frame().await {
            let frame =
                frame.map_err(|e| VmmError::ApiError(format!("read response body: {e}")))?;
            if let Ok(data) = frame.into_data() {
                if data.len() > MAX_RESPONSE_BYTES - retained.len() {
                    return Err(VmmError::ApiError(format!(
                        "{method} {path} response exceeds 64 KiB"
                    )));
                }
                retained.extend_from_slice(&data);
            }
        }
        if !status.is_success() {
            let detail = String::from_utf8_lossy(&retained[..retained.len().min(4096)]);
            return Err(VmmError::ApiError(format!(
                "{method} {path} returned {status}: {detail}{}",
                if retained.len() > 4096 {
                    " [error body truncated]"
                } else {
                    ""
                }
            )));
        }
        Ok(Bytes::from(retained))
    }

    /// Convenience wrapper for PUT requests (most Firecracker config endpoints).
    async fn fc_put(
        socket_path: &Path,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<(), VmmError> {
        Self::fc_request(socket_path, "PUT", path, Some(body)).await?;
        Ok(())
    }

    /// Convenience wrapper for PATCH requests (runtime Firecracker updates).
    async fn fc_patch(
        socket_path: &Path,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<(), VmmError> {
        Self::fc_request(socket_path, "PATCH", path, Some(body)).await?;
        Ok(())
    }

    /// Read the running Firecracker's reported version via `GET /`.
    async fn fc_instance_version(socket_path: &Path) -> Result<String, VmmError> {
        let bytes = Self::fc_request(socket_path, "GET", "/", None).await?;
        let v: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| VmmError::ApiError(format!("parse instance info: {e}")))?;
        Ok(v.get("vmm_version")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string())
    }

    fn path_to_str<'a>(path: &'a Path, label: &str) -> Result<&'a str, VmmError> {
        path.to_str()
            .ok_or_else(|| VmmError::InvalidConfig(format!("{label} is not valid UTF-8")))
    }

    /// Default kernel command line used when the caller does not supply `kernel_args`.
    ///
    /// When booting without an initrd the kernel must mount the root filesystem
    /// itself, so `root=/dev/vda rw` is appended after `pci=off`. With an
    /// initrd present the initrd handles root mounting and the argument is omitted.
    ///
    /// husker-core always supplies `kernel_args` for direct-kernel boots, so this
    /// is a fallback for external callers; it carries
    /// [`crate::LEGACY_PROBE_SUPPRESSION`] so those callers get the same boot
    /// latency as the managed path.
    fn default_boot_args(has_initrd: bool) -> String {
        let base = "console=ttyS0 reboot=k panic=1 pci=off";
        let root = if has_initrd { "" } else { " root=/dev/vda rw" };
        format!(
            "{base} {probe}{root} ip=172.20.0.2::172.20.0.1:255.255.255.252::eth0:off",
            probe = crate::LEGACY_PROBE_SUPPRESSION,
        )
    }

    fn boot_source_payload(
        kernel_image_path: &str,
        boot_args: &str,
        initrd_path: Option<&str>,
    ) -> serde_json::Value {
        let mut payload = serde_json::json!({
            "kernel_image_path": kernel_image_path,
            "boot_args": boot_args,
        });
        if let Some(initrd_path) = initrd_path {
            payload["initrd_path"] = serde_json::json!(initrd_path);
        }
        payload
    }

    /// Spawn a Firecracker process, configure it, and start the VM.
    ///
    /// Separated from `create_vm` so the caller can clean up the serial log
    /// file on any failure (spawn, API config, or start).
    #[allow(clippy::too_many_arguments)]
    async fn spawn_and_configure(
        &self,
        id: Uuid,
        config: VmConfig,
        socket_path: &Path,
        boot_log_path: &Path,
        vsock_path: &Path,
        serial_log_path: &Path,
        serial: (std::process::Stdio, crate::serial_capture::SerialCapture),
        stderr_file: std::fs::File,
    ) -> Result<VmInfo, VmmError> {
        let (serial_output, serial_capture) = serial;
        // Create the per-VM cgroup before spawning so we can place the process
        // immediately after obtaining its pid, before InstanceStart.
        let vm_cgroup = self
            .cgroup
            .create_vm_cgroup(id, config.vcpu_count, config.mem_size_mib)
            .map_err(|e| VmmError::ProcessError(format!("create cgroup: {e}")))?;

        // Hold the registry across synchronous spawn and insertion: no await
        // may strand a live child before a retryable owner is published.
        let mut instances = self.instances.lock().await;
        // Spawn the Firecracker process
        let process = match tokio::process::Command::new(&self.firecracker_bin)
            .arg("--api-sock")
            .arg(socket_path)
            .arg("--log-path")
            .arg(boot_log_path)
            .arg("--level")
            .arg("Info")
            .stdout(serial_output)
            .stderr(stderr_file)
            .kill_on_drop(true)
            .spawn()
        {
            Ok(p) => p,
            Err(e) => {
                return Err(VmmError::ProcessError(format!("spawn firecracker: {e}")));
            }
        };

        let pid = process.id();
        instances.insert(
            id,
            FcInstance {
                info: VmInfo {
                    id,
                    name: config.name.clone(),
                    state: VmState::Creating,
                    pid,
                    vcpu_count: config.vcpu_count,
                    mem_size_mib: config.mem_size_mib,
                    vsock_cid: config.vsock_cid,
                },
                socket_path: socket_path.to_owned(),
                vsock_path: vsock_path.to_owned(),
                boot_log_path: boot_log_path.to_owned(),
                serial_log_path: serial_log_path.to_owned(),
                serial_capture: Some(serial_capture),
                process,
                fork_source: None,
                balloon: config.balloon,
                cgroup: vm_cgroup,
            },
        );
        if let Some(p) = pid
            && let Err(e) = instances.get(&id).unwrap().cgroup.place(p)
        {
            return Err(VmmError::ProcessError(format!("place vmm in cgroup: {e}")));
        }
        #[cfg(target_os = "linux")]
        let recovery = if config.factory_recovery
            && config.network_disabled
            && config.tap_device.is_none()
            && let Some(cgroup) = self.cgroup.recovery_path(id)
        {
            Some(crate::recovery::Receipt::capture(
                &instances.get(&id).unwrap().info,
                &cgroup,
            )?)
        } else {
            None
        };
        drop(instances);
        #[cfg(target_os = "linux")]
        if let Some(receipt) = recovery {
            // Persist before API configuration acquires guest devices. A crash
            // before this receipt remains pending; never infer proof from absence.
            let runtime = self.runtime_dir.clone();
            tokio::task::spawn_blocking(move || receipt.persist(&runtime))
                .await
                .map_err(|error| {
                    VmmError::ProcessError(format!("persist recovery receipt: {error}"))
                })??;
        }

        // Wait for the API socket to appear
        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        if !socket_path.exists() {
            return Err(VmmError::ProcessError(
                "Firecracker socket did not appear within 5s".into(),
            ));
        }

        // Configure the VM via the Firecracker API
        let kernel_args = config
            .kernel_args
            .clone()
            .unwrap_or_else(|| Self::default_boot_args(config.initrd_path.is_some()));

        let kernel_path_str = Self::path_to_str(&config.kernel_path, "kernel_path")?;
        let rootfs_path_str = Self::path_to_str(&config.rootfs_path, "rootfs_path")?;
        let vsock_path_str = Self::path_to_str(vsock_path, "vsock_path")?;
        let initrd_path_str = config
            .initrd_path
            .as_deref()
            .map(|path| Self::path_to_str(path, "initrd_path"))
            .transpose()?;

        // Boot source
        let boot_source = Self::boot_source_payload(kernel_path_str, &kernel_args, initrd_path_str);
        Self::fc_put(socket_path, "/boot-source", &boot_source).await?;

        // Root drive
        Self::fc_put(
            socket_path,
            "/drives/rootfs",
            &serde_json::json!({
                "drive_id": "rootfs",
                "path_on_host": rootfs_path_str,
                "is_root_device": true,
                "is_read_only": false,
            }),
        )
        .await?;

        // Volume drive (second virtio disk, /dev/vdb in the guest)
        if let Some(ref vol_path) = config.volume_path {
            let vol_path_str = Self::path_to_str(vol_path, "volume_path")?;
            Self::fc_put(
                socket_path,
                "/drives/volume",
                &serde_json::json!({
                    "drive_id": "volume",
                    "path_on_host": vol_path_str,
                    "is_root_device": false,
                    "is_read_only": false,
                }),
            )
            .await?;
        }

        // Machine config
        Self::fc_put(
            socket_path,
            "/machine-config",
            &serde_json::json!({
                "vcpu_count": config.vcpu_count,
                "mem_size_mib": config.mem_size_mib,
            }),
        )
        .await?;

        // Network interface (optional)
        if let Some(ref tap) = config.tap_device {
            let mac = config
                .guest_mac
                .clone()
                .unwrap_or_else(|| "AA:FC:00:00:00:01".into());
            Self::fc_put(
                socket_path,
                "/network-interfaces/eth0",
                &serde_json::json!({
                    "iface_id": "eth0",
                    "guest_mac": mac,
                    "host_dev_name": tap,
                }),
            )
            .await?;
        }

        // Vsock
        Self::fc_put(
            socket_path,
            "/vsock",
            &serde_json::json!({
                "guest_cid": config.vsock_cid,
                "uds_path": vsock_path_str,
            }),
        )
        .await?;

        // Balloon device (must be configured before InstanceStart)
        if config.balloon {
            Self::fc_put(
                socket_path,
                "/balloon",
                &serde_json::json!({
                    "amount_mib": 0,
                    "deflate_on_oom": true,
                    "stats_polling_interval_s": 0,
                }),
            )
            .await?;
        }

        // Start the VM
        Self::fc_put(
            socket_path,
            "/actions",
            &serde_json::json!({
                "action_type": "InstanceStart",
            }),
        )
        .await?;

        let info = VmInfo {
            id,
            name: config.name,
            state: VmState::Running,
            pid,
            vcpu_count: config.vcpu_count,
            mem_size_mib: config.mem_size_mib,
            vsock_cid: config.vsock_cid,
        };

        self.instances
            .lock()
            .await
            .get_mut(&id)
            .ok_or(VmmError::VmNotFound(id))?
            .info = info.clone();

        Ok(info)
    }
}

impl VmmBackend for FirecrackerBackend {
    type VsockStream = tokio::net::UnixStream;

    fn backend_kind(&self) -> &'static str {
        "firecracker"
    }

    async fn create_vm(
        &self,
        selection: crate::BackendSelection,
        config: VmConfig,
    ) -> Result<CreatedVm, VmmError> {
        selection.validate_for_backend(&config, BackendKind::Firecracker)?;
        if !config.host_shares.is_empty() {
            return Err(VmmError::Unsupported(
                "host bind-mounts (--mount) are not supported on Firecracker; use --vmm qemu"
                    .into(),
            ));
        }
        if !matches!(config.boot, crate::BootMode::DirectKernel) {
            return Err(VmmError::InvalidConfig(
                "Firecracker only supports BootMode::DirectKernel".into(),
            ));
        }
        // Check for duplicate names
        {
            let instances = self.instances.lock().await;
            if instances.values().any(|i| i.info.name == config.name) {
                return Err(VmmError::VmAlreadyExists(config.name));
            }
        }

        if config.factory_recovery
            && (!config.network_disabled
                || config.tap_device.is_some()
                || config
                    .name
                    .strip_prefix("job-")
                    .and_then(|job| Uuid::parse_str(job).ok())
                    .is_none())
        {
            return Err(VmmError::InvalidConfig(
                "factory recovery requires an offline job generation".into(),
            ));
        }
        let id = crate::creation_id(&config)?;
        let _creation = self.creation_locks.lock(id).await;
        if self.instances.lock().await.contains_key(&id)
            || self.version_probes.lock().await.contains_key(&id)
        {
            return Err(VmmError::InvalidConfig(
                "requested VM UUID is already allocated".into(),
            ));
        }
        let socket_path = self.runtime_dir.join(format!("{id}.sock"));
        let boot_log_path = self.runtime_dir.join(format!("{id}.boot.log"));
        let vsock_path = self.runtime_dir.join(format!("{id}.vsock"));
        let serial_log_path = self.runtime_dir.join(self.serial_log_file(id));

        tokio::fs::create_dir_all(&self.runtime_dir).await?;

        // Firecracker requires the log file to exist before startup
        tokio::fs::write(&boot_log_path, b"").await?;

        // Firecracker writes guest serial console (ttyS0) to stdout.
        // Capture it to a file so `husker logs` can read it.
        let serial = crate::serial_capture::SerialCapture::for_child(&serial_log_path)?;

        // FC process stderr goes to the FC log file (separate from guest serial).
        let stderr_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&boot_log_path)
            .map_err(|e| VmmError::ProcessError(format!("open FC log for stderr: {e}")))?;

        // Spawn, configure, and start. Once spawned, a failed or cancelled boot
        // retains its child, cgroup and runtime files until confirmed destroy.
        match self
            .spawn_and_configure(
                id,
                config,
                &socket_path,
                &boot_log_path,
                &vsock_path,
                &serial_log_path,
                serial,
                stderr_file,
            )
            .await
        {
            Ok(info) => Ok(CreatedVm::new(info, selection)),
            Err(e) => {
                // Capture diagnostics while retaining any spawned owner.
                let serial_tail = crate::tail_lines(&serial_log_path, 20);
                let boot_tail = crate::tail_lines(&boot_log_path, 20);
                let mut instances = self.instances.lock().await;
                if let Some(instance) = instances.get_mut(&id) {
                    instance.info.state = VmState::Failed;
                } else {
                    // No child was spawned; these files have no live owner.
                    let _ = std::fs::remove_file(crate::serial_log::compaction_staging_path(
                        &serial_log_path,
                    ));
                    let _ = std::fs::remove_file(&serial_log_path);
                    let _ = std::fs::remove_file(&boot_log_path);
                    let _ = std::fs::remove_file(&socket_path);
                    let _ = std::fs::remove_file(&vsock_path);
                }
                let mut msg = format!("{e}");
                crate::append_log_tails(&mut msg, serial_tail, boot_tail, "firecracker boot log");
                Err(VmmError::ProcessError(msg))
            }
        }
    }

    async fn stop_vm(&self, id: Uuid) -> Result<(), VmmError> {
        // Extract what we need, then drop the lock before making the API call.
        // A guest that has already ended itself (the agent rebooted it on the
        // host's request) has no API to call and nothing to wait for.
        let socket_path = {
            let mut instances = self.instances.lock().await;
            let instance = instances.get_mut(&id).ok_or(VmmError::VmNotFound(id))?;
            if matches!(instance.process.try_wait(), Ok(Some(_))) {
                settle_stopped(instance).await;
                return Ok(());
            }
            instance.socket_path.clone()
        };

        let graceful_request = Self::fc_put(
            &socket_path,
            "/actions",
            &serde_json::json!({ "action_type": "SendCtrlAltDel" }),
        )
        .await;

        // Do not return while Firecracker can still hold the TAP open: shutdown
        // cleanup runs immediately after this call.
        let grace = match graceful_request {
            Ok(()) => GUEST_SHUTDOWN_GRACE,
            Err(error) => {
                tracing::warn!(%id, %error, "guest shutdown request failed; force-stopping firecracker");
                std::time::Duration::ZERO
            }
        };
        match wait_for_exit_or_kill(&self.instances, id, grace).await? {
            GuestExit::Clean => {}
            GuestExit::Forced => {
                tracing::warn!(%id, "guest did not exit cleanly; force-killed firecracker");
            }
            GuestExit::Gone => return Ok(()),
        }

        let mut instances = self.instances.lock().await;
        if let Some(instance) = instances.get_mut(&id) {
            settle_stopped(instance).await;
        }
        Ok(())
    }

    async fn abort_create(&self, id: Uuid) -> Result<(), VmmError> {
        crate::abort_registered_create(self.destroy_vm(id).await)
    }

    #[cfg(target_os = "linux")]
    async fn recover_factory_allocation(
        &self,
        id: Uuid,
        name: &str,
        cid: u32,
    ) -> Result<(), VmmError> {
        let _creation = self.creation_locks.lock(id).await;
        if self.instances.lock().await.contains_key(&id)
            || self.version_probes.lock().await.contains_key(&id)
        {
            return Err(VmmError::InvalidConfig(
                "factory generation still has a backend owner".into(),
            ));
        }
        let cgroup = self.cgroup.recovery_path(id).ok_or_else(|| {
            VmmError::Unsupported("factory recovery requires cgroup supervision".into())
        })?;
        let receipt = crate::recovery::Receipt::load(&self.runtime_dir, id)?;
        receipt
            .confirm(id, name, cid, &self.runtime_dir, &cgroup)
            .await?;
        for suffix in ["sock", "vsock", "boot.log"] {
            crate::termination::remove_runtime_file(
                &self.runtime_dir.join(format!("{id}.{suffix}")),
            )
            .await?;
        }
        crate::serial_capture::remove_serial_log(&self.runtime_dir.join(self.serial_log_file(id)))
            .await?;
        // Retain the receipt until core durably journals destruction. Retries
        // after a journal failure can repeat the same exact-generation proof.
        Ok(())
    }

    async fn destroy_vm(&self, id: Uuid) -> Result<(), VmmError> {
        let _creation = self.creation_locks.lock(id).await;
        let probe_removed = {
            let mut probes = self.version_probes.lock().await;
            if let Some(probe) = probes.get_mut(&id) {
                crate::termination::terminate_child(probe, "Firecracker version probe").await?;
                probes.remove(&id);
                true
            } else {
                false
            }
        };
        let mut instances = self.instances.lock().await;
        if probe_removed && !instances.contains_key(&id) {
            return Ok(());
        }
        let instance = instances.get_mut(&id).ok_or(VmmError::VmNotFound(id))?;
        tracing::debug!(%id, "destroying firecracker VM");
        crate::termination::terminate_child(&mut instance.process, "firecracker").await?;
        crate::serial_capture::finish_child_capture(&mut instance.serial_capture).await;
        if let Some(source) = instance.fork_source.as_mut() {
            source.alias.undo()?;
        }
        instance.fork_source = None;
        for path in [
            &instance.socket_path,
            &instance.vsock_path,
            &instance.boot_log_path,
        ] {
            crate::termination::remove_runtime_file(path).await?;
        }
        crate::serial_capture::remove_serial_log(&instance.serial_log_path).await?;
        instance.cgroup.remove_confirmed().await.map_err(|error| {
            VmmError::ProcessError(format!("confirm VMM cgroup cleanup: {error}"))
        })?;
        instances.remove(&id);
        Ok(())
    }

    async fn vm_info(&self, id: Uuid) -> Result<VmInfo, VmmError> {
        let mut instances = self.instances.lock().await;
        let instance = instances.get_mut(&id).ok_or(VmmError::VmNotFound(id))?;

        // Check if the process is still alive
        if instance.info.state == VmState::Running || instance.info.state == VmState::Paused {
            match instance.process.try_wait() {
                Ok(Some(_)) => {
                    // Process exited: mark as stopped and reap the now-empty cgroup.
                    instance.info.state = VmState::Stopped;
                    instance.info.pid = None;
                    instance.cgroup.remove().await;
                }
                Ok(None) => {} // Still running
                Err(_) => {
                    // try_wait() failed: the process state is ambiguous (it may
                    // still be alive), so do NOT reap the cgroup here. remove()
                    // SIGKILLs any pids in the cgroup, which could kill a live
                    // VMM. destroy_vm and the startup orphan sweep reclaim it.
                    instance.info.state = VmState::Failed;
                    instance.info.pid = None;
                }
            }
        }

        Ok(instance.info.clone())
    }

    async fn pause_vm(&self, id: Uuid) -> Result<(), VmmError> {
        let socket_path = {
            let instances = self.instances.lock().await;
            let instance = instances.get(&id).ok_or(VmmError::VmNotFound(id))?;
            instance.socket_path.clone()
        };

        Self::fc_patch(
            &socket_path,
            "/vm",
            &serde_json::json!({ "state": "Paused" }),
        )
        .await?;

        let mut instances = self.instances.lock().await;
        if let Some(instance) = instances.get_mut(&id) {
            instance.info.state = VmState::Paused;
        }
        Ok(())
    }

    async fn resume_vm(&self, id: Uuid) -> Result<(), VmmError> {
        let socket_path = {
            let instances = self.instances.lock().await;
            let instance = instances.get(&id).ok_or(VmmError::VmNotFound(id))?;
            instance.socket_path.clone()
        };

        Self::fc_patch(
            &socket_path,
            "/vm",
            &serde_json::json!({ "state": "Resumed" }),
        )
        .await?;

        let mut instances = self.instances.lock().await;
        if let Some(instance) = instances.get_mut(&id) {
            instance.info.state = VmState::Running;
        }
        Ok(())
    }

    async fn snapshot_vm(&self, id: Uuid, dst: &SnapshotPaths) -> Result<SnapshotMeta, VmmError> {
        let socket_path = {
            let instances = self.instances.lock().await;
            let instance = instances.get(&id).ok_or(VmmError::VmNotFound(id))?;
            if instance.info.state != VmState::Paused {
                return Err(VmmError::InvalidConfig(
                    "snapshot_vm requires the VM to be paused first".into(),
                ));
            }
            instance.socket_path.clone()
        };

        tokio::fs::create_dir_all(&dst.dir).await?;
        let vmstate = Self::path_to_str(&dst.vmstate, "vmstate")?.to_string();
        let memory = Self::path_to_str(&dst.memory, "memory")?.to_string();

        Self::fc_put(
            &socket_path,
            "/snapshot/create",
            &serde_json::json!({
                "snapshot_type": "Full",
                "snapshot_path": vmstate,
                "mem_file_path": memory,
            }),
        )
        .await?;

        let vmm_version = Self::fc_instance_version(&socket_path)
            .await
            .unwrap_or_default();

        Ok(SnapshotMeta {
            backend: "firecracker".into(),
            vmm_version,
        })
    }

    async fn restore_vm(
        &self,
        src: &SnapshotPaths,
        target: RestoreTarget,
    ) -> Result<VmInfo, VmmError> {
        // Common identity plus per-target specifics. Each restore binds its OWN
        // vsock UDS path (`<runtime>/<id>.vsock`) and overrides the snapshot's
        // embedded path via `vsock_override` (below), so concurrent forks of one
        // snapshot never collide on the host socket. `Fork` additionally rebinds
        // the NIC to a fresh TAP and aliases the embedded source rootfs to the
        // fork's clone during load.
        let (id, name, vcpu_count, mem_size_mib, vsock_cid, fork) = match target {
            RestoreTarget::Resume {
                id,
                name,
                vcpu_count,
                mem_size_mib,
                vsock_cid,
            } => (id, name, vcpu_count, mem_size_mib, vsock_cid, None),
            RestoreTarget::Fork {
                id,
                name,
                vcpu_count,
                mem_size_mib,
                vsock_cid,
                tap_device,
                source_rootfs,
                fork_rootfs,
                source_lock,
            } => (
                id,
                name,
                vcpu_count,
                mem_size_mib,
                vsock_cid,
                Some((tap_device, source_rootfs, fork_rootfs, source_lock)),
            ),
        };
        let _creation = self.creation_locks.lock(id).await;
        if self.instances.lock().await.contains_key(&id)
            || self.version_probes.lock().await.contains_key(&id)
        {
            return Err(VmmError::InvalidConfig(
                "restore VM UUID is already allocated".into(),
            ));
        }
        let vsock_path = self.runtime_dir.join(format!("{id}.vsock"));

        // A fork rebinds the guest NIC to a fresh host TAP via the
        // `network_overrides` field on `/snapshot/load`, which Firecracker only
        // understands from 1.12.0 on. Check up front so an old binary fails with
        // a clear, actionable message instead of an opaque deserialization 400.
        if fork.is_some() {
            self.assert_firecracker_supports_fork(id).await?;
        }

        let fork_source = match &fork {
            Some((_, source, clone, lock)) => Some(ForkSource {
                _source_lock: lock.clone(),
                alias: RootfsAlias::prepare(source, clone)?,
            }),
            None => None,
        };

        // Convert the snapshot/memory/vsock paths to &str up front, before
        // creating any runtime files, so a (rare) non-UTF-8 path returns without
        // leaking the socket and log files created below.
        let snapshot = Self::path_to_str(&src.vmstate, "vmstate")?;
        let mem = Self::path_to_str(&src.memory, "memory")?;
        let vsock_path_str = Self::path_to_str(&vsock_path, "vsock_path")?;

        let socket_path = self.runtime_dir.join(format!("{id}.sock"));
        let boot_log_path = self.runtime_dir.join(format!("{id}.boot.log"));
        let serial_log_path = self.runtime_dir.join(self.serial_log_file(id));

        tokio::fs::create_dir_all(&self.runtime_dir).await?;
        // Clear any stale socket so Firecracker can bind a fresh one.
        let _ = tokio::fs::remove_file(&socket_path).await;
        tokio::fs::write(&boot_log_path, b"").await?;

        let (serial_output, serial_capture) =
            crate::serial_capture::SerialCapture::for_child(&serial_log_path)?;
        let stderr_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&boot_log_path)
            .map_err(|e| VmmError::ProcessError(format!("open FC log for stderr: {e}")))?;

        let vm_cgroup = self
            .cgroup
            .create_vm_cgroup(id, vcpu_count, mem_size_mib)
            .map_err(|e| VmmError::ProcessError(format!("create cgroup: {e}")))?;

        // Publish the child before any readiness or API await. Destruction
        // serializes with this restore and confirms exit before deleting files.
        let mut instances = self.instances.lock().await;
        let process = match tokio::process::Command::new(&self.firecracker_bin)
            .arg("--api-sock")
            .arg(&socket_path)
            .arg("--log-path")
            .arg(&boot_log_path)
            .arg("--level")
            .arg("Info")
            .stdout(serial_output)
            .stderr(stderr_file)
            .kill_on_drop(true)
            .spawn()
        {
            Ok(p) => p,
            Err(e) => {
                return Err(VmmError::ProcessError(format!("spawn firecracker: {e}")));
            }
        };
        let pid = process.id();
        instances.insert(
            id,
            FcInstance {
                info: VmInfo {
                    id,
                    name,
                    state: VmState::Creating,
                    pid,
                    vcpu_count,
                    mem_size_mib,
                    vsock_cid,
                },
                socket_path: socket_path.clone(),
                vsock_path: vsock_path.clone(),
                boot_log_path: boot_log_path.clone(),
                serial_log_path: serial_log_path.clone(),
                serial_capture: Some(serial_capture),
                process,
                fork_source,
                balloon: false,
                cgroup: vm_cgroup,
            },
        );
        if let Some(p) = pid
            && let Err(e) = instances.get(&id).unwrap().cgroup.place(p)
        {
            instances.get_mut(&id).unwrap().info.state = VmState::Failed;
            return Err(VmmError::ProcessError(format!("place vmm in cgroup: {e}")));
        }
        drop(instances);

        let result = async {
            for _ in 0..50 {
                if socket_path.exists() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            if !socket_path.exists() {
                return Err(VmmError::ProcessError(
                    "Firecracker socket did not appear within 5s".into(),
                ));
            }

            // `vsock_override` rebinds the vsock to this VM's own socket path: a resumed
            // VM rebinds its own, a fork gets a fresh one (so concurrent forks of one
            // snapshot do not collide). Resume keeps the snapshot's NIC; fork rebinds
            // the NIC to its own fresh TAP and aliases the embedded source rootfs to
            // the fork's clone for the duration of the load.
            let mut load_body = serde_json::json!({
                "snapshot_path": snapshot,
                "mem_file_path": mem,
                "resume_vm": true,
                "vsock_override": { "uds_path": vsock_path_str },
            });
            if let Some((tap, _, _, _)) = &fork {
                load_body["network_overrides"] = serde_json::json!([{
                    "iface_id": "eth0",
                    "host_dev_name": tap,
                }]);
                let mut instances = self.instances.lock().await;
                instances
                    .get_mut(&id)
                    .ok_or(VmmError::VmNotFound(id))?
                    .fork_source
                    .as_mut()
                    .expect("registered fork source")
                    .alias
                    .activate()?;
            }

            if let Err(e) = Self::fc_put(&socket_path, "/snapshot/load", &load_body).await {
                // Capture diagnostics while retaining process and file ownership.
                // Source alias and lock remain owned until confirmed destruction.
                let serial_tail = crate::tail_lines(&serial_log_path, 20);
                let boot_tail = crate::tail_lines(&boot_log_path, 20);
                let mut msg = format!("{e}");
                crate::append_log_tails(&mut msg, serial_tail, boot_tail, "firecracker boot log");
                return Err(VmmError::ProcessError(msg));
            }
            // Firecracker now holds the fork's rootfs fd open; undo the alias so the
            // source keeps its own disk for a later resume.
            let mut instances = self.instances.lock().await;
            let instance = instances.get_mut(&id).ok_or(VmmError::VmNotFound(id))?;
            if let Some(source) = instance.fork_source.as_mut() {
                source.alias.undo()?;
            }
            instance.fork_source = None;
            Ok(())
        }
        .await;
        let mut instances = self.instances.lock().await;
        let instance = instances.get_mut(&id).ok_or(VmmError::VmNotFound(id))?;
        instance.info.state = if result.is_ok() {
            VmState::Running
        } else {
            VmState::Failed
        };
        result?;
        Ok(instance.info.clone())
    }

    async fn vsock_connect(&self, id: Uuid, port: u32) -> Result<Self::VsockStream, VmmError> {
        let vsock_path = {
            let instances = self.instances.lock().await;
            let inst = instances.get(&id).ok_or(VmmError::VmNotFound(id))?;
            inst.vsock_path.clone()
        };

        crate::vsock::connect_firecracker_vsock(&vsock_path, port)
            .await
            .map_err(|e| VmmError::ProcessError(format!("{e}")))
    }

    async fn set_balloon(&self, id: Uuid, amount_mib: u32) -> Result<(), VmmError> {
        let (socket_path, balloon) = {
            let instances = self.instances.lock().await;
            let inst = instances.get(&id).ok_or(VmmError::VmNotFound(id))?;
            (inst.socket_path.clone(), inst.balloon)
        };
        if !balloon {
            return Err(VmmError::InvalidConfig(
                "VM was created without a balloon device; rebuild with VmConfig.balloon = true"
                    .into(),
            ));
        }
        Self::fc_patch(
            &socket_path,
            "/balloon",
            &serde_json::json!({ "amount_mib": amount_mib }),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stalled_api_headers_or_body_time_out_and_close_the_owned_connection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for mode in ["headers", "body", "cancel"] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("api.sock");
            let listener = tokio::net::UnixListener::bind(&path).unwrap();
            let request = tokio::spawn(async move {
                FirecrackerBackend::fc_request(&path, "GET", "/", None).await
            });
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut incoming = [0; 1024];
            assert!(peer.read(&mut incoming).await.unwrap() > 0);
            if mode == "body" {
                peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nx")
                    .await
                    .unwrap();
            }
            if mode == "cancel" {
                request.abort();
                assert!(request.await.unwrap_err().is_cancelled());
            } else {
                tokio::time::pause();
                tokio::time::advance(std::time::Duration::from_secs(10)).await;
                let error = request.await.unwrap().unwrap_err();
                assert!(error.to_string().contains("timed out after 10s"));
                // Kernel socket closure is asynchronous; use the real clock
                // instead of auto-advancing past its pending readiness event.
                tokio::time::resume();
            }
            assert_eq!(
                tokio::time::timeout(std::time::Duration::from_secs(1), peer.read(&mut incoming))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        }
    }

    #[tokio::test]
    async fn oversized_api_response_is_rejected_before_unbounded_collection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut incoming = [0; 1024];
            assert!(stream.read(&mut incoming).await.unwrap() > 0);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n\r\n")
                .await
                .unwrap();
            let _ = stream.write_all(&vec![b'x'; 65537]).await;
        });
        let error = FirecrackerBackend::fc_request(&path, "GET", "/", None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("response exceeds 64 KiB"));
        peer.await.unwrap();
    }

    fn noop_cgroup() -> crate::cgroup::VmCgroup {
        crate::cgroup::CgroupSupervisor::disabled()
            .create_vm_cgroup(uuid::Uuid::nil(), 1, 128)
            .unwrap()
    }

    fn test_backend(
        bin: impl Into<std::path::PathBuf>,
        dir: impl Into<std::path::PathBuf>,
    ) -> FirecrackerBackend {
        FirecrackerBackend::new(
            bin,
            dir,
            std::sync::Arc::new(crate::cgroup::CgroupSupervisor::disabled()),
        )
    }

    /// A daemon running one backend answers every selection with that backend
    /// and refuses a request for another one instead of substituting its own.
    #[test]
    fn a_single_backend_grants_only_a_request_for_itself() {
        use crate::{BackendKind, BackendRequirements, BootKind, VmmBackend, VmmKind};

        let dir = tempfile::tempdir().unwrap();
        let backend = test_backend(dir.path().join("firecracker"), dir.path());
        let requirements = |requested| BackendRequirements {
            requested,
            boot: BootKind::DirectKernel,
            has_host_shares: false,
        };

        let unrequested = backend.select_backend(requirements(None)).unwrap();
        assert_eq!(unrequested.backend(), BackendKind::Firecracker);
        let own = backend
            .select_backend(requirements(Some(VmmKind::Firecracker)))
            .unwrap();
        assert_eq!(own.backend(), BackendKind::Firecracker);
        assert_eq!(own.requirements().requested, Some(VmmKind::Firecracker));

        let error = backend
            .select_backend(requirements(Some(VmmKind::Qemu)))
            .unwrap_err();
        let VmmError::InvalidConfig(message) = error else {
            panic!("expected InvalidConfig, got {error:?}");
        };
        assert!(
            message.contains("\"qemu\"") && message.contains("firecracker only"),
            "message must name the request and the running backend: {message}"
        );
    }

    #[test]
    fn parse_firecracker_version_extracts_semver() {
        assert_eq!(
            parse_firecracker_version("Firecracker v1.16.0\nSupported ..."),
            Some((1, 16, 0))
        );
        // No leading 'v', extra patch text, and minimal "X.Y" all parse.
        assert_eq!(
            parse_firecracker_version("Firecracker 1.12.3"),
            Some((1, 12, 3))
        );
        assert_eq!(
            parse_firecracker_version("Firecracker v2.0.0-rc1"),
            Some((2, 0, 0))
        );
        assert_eq!(
            parse_firecracker_version("Firecracker v1.10"),
            Some((1, 10, 0))
        );
        // Junk lines yield nothing.
        assert_eq!(parse_firecracker_version("no version here"), None);
        assert_eq!(parse_firecracker_version(""), None);
    }

    #[cfg(unix)]
    fn version_fixture(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("version-fixture");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn version_probe_bounds_output_checks_exit_and_retains_failed_receipts() {
        for (body, expected) in [
            ("printf 'Firecracker v1.16.0\\n'", None),
            (
                "printf 'Firecracker v1.16.0\\n'; exit 1",
                Some("version command failed"),
            ),
            (
                "printf 'Firecracker v1.10.0\\n'",
                Some("requires Firecracker"),
            ),
            ("printf 'invalid\\n'", Some("could not parse")),
            (
                "i=0; while [ \"$i\" -lt 5000 ]; do printf x; i=$((i+1)); done",
                Some("output exceeds 4 KiB"),
            ),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let backend = test_backend(version_fixture(temp.path(), body), temp.path());
            let id = Uuid::new_v4();
            let result = backend.assert_firecracker_supports_fork(id).await;
            if let Some(expected) = expected {
                assert!(result.unwrap_err().to_string().contains(expected));
                let mut probes = backend.version_probes.lock().await;
                assert!(probes.get_mut(&id).unwrap().try_wait().unwrap().is_some());
                drop(probes);
                // Failed pre-allocation is still an owned UUID until cleanup.
                assert!(backend.assert_firecracker_supports_fork(id).await.is_err());
                backend.destroy_vm(id).await.unwrap();
            } else {
                result.unwrap();
            }
            assert!(backend.version_probes.lock().await.is_empty());
            assert!(backend.instances.lock().await.is_empty());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn version_probe_timeout_reaps_and_cancellation_retains_child_for_destroy() {
        let temp = tempfile::tempdir().unwrap();
        let backend = Arc::new(test_backend(
            version_fixture(temp.path(), "exec /bin/sleep 30"),
            temp.path(),
        ));
        let timed_out = Uuid::new_v4();
        let error = backend
            .assert_firecracker_supports_fork(timed_out)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeded 3s"));
        assert!(
            backend
                .version_probes
                .lock()
                .await
                .get_mut(&timed_out)
                .unwrap()
                .try_wait()
                .unwrap()
                .is_some()
        );
        backend.destroy_vm(timed_out).await.unwrap();

        // A sentinel emitted before exec proves the probe is running before abort.
        let sentinel = temp.path().join("started");
        version_fixture(
            temp.path(),
            &format!(
                "printf started > '{}'; exec /bin/sleep 30",
                sentinel.display()
            ),
        );
        let id = Uuid::new_v4();
        let cloned = backend.clone();
        let snapshot = SnapshotPaths::in_dir(temp.path().join("snapshot"));
        let source_rootfs = temp.path().join("source.ext4");
        let fork_rootfs = temp.path().join("fork.ext4");
        let task = tokio::spawn(async move {
            cloned
                .restore_vm(
                    &snapshot,
                    RestoreTarget::Fork {
                        id,
                        name: "probe-cancellation".into(),
                        vcpu_count: 1,
                        mem_size_mib: 128,
                        vsock_cid: 3,
                        tap_device: "unused".into(),
                        source_rootfs,
                        fork_rootfs,
                        source_lock: Arc::new(Arc::new(Mutex::new(())).lock_owned().await),
                    },
                )
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !sentinel.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(
            backend
                .version_probes
                .lock()
                .await
                .get_mut(&id)
                .unwrap()
                .try_wait()
                .unwrap()
                .is_none()
        );
        let duplicate = backend
            .restore_vm(
                &SnapshotPaths::in_dir(temp.path()),
                RestoreTarget::Resume {
                    id,
                    name: "duplicate".into(),
                    vcpu_count: 1,
                    mem_size_mib: 128,
                    vsock_cid: 3,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(duplicate, VmmError::InvalidConfig(_)));
        assert!(!temp.path().join(format!("{id}.serial.log")).exists());
        backend.destroy_vm(id).await.unwrap();
        assert!(backend.version_probes.lock().await.is_empty());
        assert!(backend.instances.lock().await.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fork_alias_and_source_lock_survive_ambiguous_load_until_confirmed_cleanup() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for outcome in ["cancel", "reject", "success"] {
            let temp = tempfile::tempdir().unwrap();
            let binary = version_fixture(
                temp.path(),
                "if [ \"$1\" = --version ]; then printf 'Firecracker v1.16.0\\n'; exit 0; fi; exec /bin/sleep 30",
            );
            let backend = Arc::new(test_backend(binary, temp.path()));
            let source = temp.path().join("source.ext4");
            let fork = temp.path().join("fork.ext4");
            std::fs::write(&source, b"original source").unwrap();
            std::fs::write(&fork, b"private fork").unwrap();
            let id = Uuid::new_v4();
            let source_lock = Arc::new(Mutex::new(()));
            let guard = Arc::new(source_lock.clone().lock_owned().await);
            let target = RestoreTarget::Fork {
                id,
                name: "alias-test".into(),
                vcpu_count: 1,
                mem_size_mib: 128,
                vsock_cid: 3,
                tap_device: "unused".into(),
                source_rootfs: source.clone(),
                fork_rootfs: fork.clone(),
                source_lock: guard,
            };
            let cloned = backend.clone();
            let snapshot = SnapshotPaths::in_dir(temp.path().join("snapshot"));
            let task = tokio::spawn(async move { cloned.restore_vm(&snapshot, target).await });
            let serial = temp.path().join(format!("{id}.serial.log"));
            // This is fixture readiness, not the behavior under test. Coverage
            // instrumentation and shared runners can delay process/fs setup;
            // avoid a busy poll and leave room for the 3s version probe.
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while !serial.exists() {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("restore did not reach serial setup within 10s");
            // Serial creation follows stale-socket removal, so this bind cannot
            // be erased by the restore's setup path.
            let listener =
                tokio::net::UnixListener::bind(temp.path().join(format!("{id}.sock"))).unwrap();
            let (mut peer, _) =
                tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept())
                    .await
                    .expect("restore did not connect to the fixture API within 10s")
                    .unwrap();
            let mut request = vec![0; 4096];
            let n = peer.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..n]).contains("/snapshot/load"));
            assert_eq!(std::fs::read_link(&source).unwrap(), fork);
            assert!(source_lock.try_lock().is_err());
            match outcome {
                "cancel" => {
                    task.abort();
                    assert!(task.await.unwrap_err().is_cancelled());
                }
                "reject" => {
                    peer.write_all(b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .unwrap();
                    assert!(task.await.unwrap().is_err());
                }
                "success" => {
                    peer.write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                        .await
                        .unwrap();
                    assert_eq!(task.await.unwrap().unwrap().state, VmState::Running);
                    assert_eq!(std::fs::read(&source).unwrap(), b"original source");
                    assert!(source_lock.try_lock().is_ok());
                }
                _ => unreachable!(),
            }
            if outcome != "success" {
                assert!(
                    backend
                        .instances
                        .lock()
                        .await
                        .get_mut(&id)
                        .unwrap()
                        .process
                        .try_wait()
                        .unwrap()
                        .is_none()
                );
                assert_eq!(std::fs::read_link(&source).unwrap(), fork);
                assert!(source_lock.try_lock().is_err());
                // Restoration cannot overwrite an obstructing replacement path.
                std::fs::remove_file(&source).unwrap();
                std::fs::create_dir(&source).unwrap();
                assert!(backend.destroy_vm(id).await.is_err());
                assert!(
                    backend
                        .instances
                        .lock()
                        .await
                        .get_mut(&id)
                        .unwrap()
                        .process
                        .try_wait()
                        .unwrap()
                        .is_some()
                );
                assert!(source.is_dir());
                assert!(source_lock.try_lock().is_err());
                assert_eq!(
                    std::fs::read(fork_src_backup_path(&source)).unwrap(),
                    b"original source"
                );
                std::fs::remove_dir(&source).unwrap();
                std::os::unix::fs::symlink(&fork, &source).unwrap();
            }
            backend.destroy_vm(id).await.unwrap();
            assert_eq!(std::fs::read(&source).unwrap(), b"original source");
            assert_eq!(std::fs::read(&fork).unwrap(), b"private fork");
            assert!(!fork_src_backup_path(&source).exists());
            assert!(source_lock.try_lock().is_ok());
            assert!(backend.instances.lock().await.is_empty());
        }
    }

    #[test]
    fn fork_min_version_ordering() {
        // Tuple ordering is the comparison the preflight uses.
        assert!(
            (1, 10, 1) < FORK_MIN_FIRECRACKER,
            "v1.10.1 is too old to fork"
        );
        assert!(
            (1, 11, 0) < FORK_MIN_FIRECRACKER,
            "v1.11.0 is too old to fork"
        );
        assert!(
            (1, 15, 0) < FORK_MIN_FIRECRACKER,
            "v1.15.0 lacks vsock_override"
        );
        assert!((1, 16, 0) >= FORK_MIN_FIRECRACKER, "v1.16.0 is the floor");
    }

    #[test]
    fn vm_state_display() {
        assert_eq!(VmState::Creating.to_string(), "creating");
        assert_eq!(VmState::Running.to_string(), "running");
        assert_eq!(VmState::Paused.to_string(), "paused");
        assert_eq!(VmState::Stopped.to_string(), "stopped");
        assert_eq!(VmState::Failed.to_string(), "failed");
    }

    #[test]
    fn vm_state_json_roundtrip() {
        for state in [
            VmState::Creating,
            VmState::Running,
            VmState::Paused,
            VmState::Stopped,
            VmState::Failed,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let parsed: VmState = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, state);
        }
    }

    #[test]
    fn vm_config_serialization() {
        let config = VmConfig {
            requested_id: None,
            name: "test".into(),
            vcpu_count: 2,
            mem_size_mib: 256,
            kernel_path: "/var/lib/husker/kernels/vmlinux".into(),
            rootfs_path: "/var/lib/husker/images/ubuntu.ext4".into(),
            kernel_args: None,
            initrd_path: None,
            vsock_cid: 3,
            tap_device: Some("husker3".into()),
            guest_mac: Some("AA:FC:00:00:00:03".into()),
            vmm: None,
            boot: crate::BootMode::DirectKernel,
            seed_path: None,
            balloon: false,
            volume_path: None,
            network_disabled: false,
            factory_recovery: false,
            host_shares: Vec::new(),
        };
        let json = serde_json::to_value(&config).unwrap();
        assert_eq!(json["name"], "test");
        assert_eq!(json["vcpu_count"], 2);
        assert_eq!(json["mem_size_mib"], 256);
        assert!(json["kernel_args"].is_null());
        assert_eq!(json["tap_device"], "husker3");
    }

    #[test]
    fn vm_info_serialization() {
        let id = Uuid::new_v4();
        let info = VmInfo {
            id,
            name: "myvm".into(),
            state: VmState::Running,
            pid: Some(1234),
            vcpu_count: 1,
            mem_size_mib: 128,
            vsock_cid: 5,
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["name"], "myvm");
        assert_eq!(json["state"], "running");
        assert_eq!(json["pid"], 1234);
        assert_eq!(json["vsock_cid"], 5);

        let parsed: VmInfo = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.id, id);
        assert_eq!(parsed.state, VmState::Running);
    }

    #[test]
    fn path_to_str_valid() {
        let path = Path::new("/tmp/test.sock");
        assert_eq!(
            FirecrackerBackend::path_to_str(path, "test").unwrap(),
            "/tmp/test.sock"
        );
    }

    #[test]
    fn boot_source_payload_omits_initrd_when_not_set() {
        let payload =
            FirecrackerBackend::boot_source_payload("/tmp/vmlinux", "console=ttyS0", None);
        assert_eq!(payload["kernel_image_path"], "/tmp/vmlinux");
        assert_eq!(payload["boot_args"], "console=ttyS0");
        assert!(
            payload.get("initrd_path").is_none(),
            "initrd_path should be omitted when not configured"
        );
    }

    #[test]
    fn boot_source_payload_includes_initrd_when_set() {
        let payload = FirecrackerBackend::boot_source_payload(
            "/tmp/vmlinux",
            "console=ttyS0",
            Some("/tmp/initrd.img"),
        );
        assert_eq!(payload["kernel_image_path"], "/tmp/vmlinux");
        assert_eq!(payload["boot_args"], "console=ttyS0");
        assert_eq!(payload["initrd_path"], "/tmp/initrd.img");
    }

    #[test]
    fn default_boot_args_add_root_when_no_initrd() {
        let args = FirecrackerBackend::default_boot_args(false);
        assert!(
            args.contains("root=/dev/vda rw"),
            "expected root=/dev/vda rw when no initrd: {args}"
        );
        assert!(
            args.contains("console=ttyS0"),
            "console arg missing: {args}"
        );
        assert!(args.contains("pci=off"), "pci=off missing: {args}");
    }

    #[test]
    fn default_boot_args_omit_root_when_initrd_set() {
        let args = FirecrackerBackend::default_boot_args(true);
        assert!(
            !args.contains("root=/dev/vda"),
            "root= must be absent when initrd is set: {args}"
        );
        assert!(
            args.contains("console=ttyS0"),
            "console arg missing: {args}"
        );
        assert!(args.contains("pci=off"), "pci=off missing: {args}");
    }

    /// Callers that supply no `kernel_args` must not silently get a slower boot
    /// than the husker-core managed path. See [`crate::LEGACY_PROBE_SUPPRESSION`].
    #[test]
    fn default_boot_args_suppress_legacy_hardware_probes() {
        for has_initrd in [true, false] {
            let args = FirecrackerBackend::default_boot_args(has_initrd);
            for token in crate::LEGACY_PROBE_SUPPRESSION.split_whitespace() {
                assert!(
                    args.split_whitespace().any(|t| t == token),
                    "missing {token} (has_initrd={has_initrd}): {args}"
                );
            }
        }
    }

    #[tokio::test]
    async fn duplicate_name_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let backend = test_backend("firecracker", dir.path());

        // Manually insert a fake instance
        let id = Uuid::new_v4();
        let instance = FcInstance {
            info: VmInfo {
                id,
                name: "existing".into(),
                state: VmState::Running,
                pid: Some(999),
                vcpu_count: 1,
                mem_size_mib: 128,
                vsock_cid: 3,
            },
            socket_path: dir.path().join("fake.sock"),
            vsock_path: dir.path().join("fake.vsock"),
            boot_log_path: dir.path().join("fake.boot.log"),
            serial_log_path: dir.path().join("fake.serial.log"),
            serial_capture: None,
            process: tokio::process::Command::new("true").spawn().unwrap(),
            fork_source: None,
            balloon: false,
            cgroup: noop_cgroup(),
        };
        backend.instances.lock().await.insert(id, instance);

        let config = VmConfig {
            requested_id: None,
            name: "existing".into(),
            vcpu_count: 1,
            mem_size_mib: 128,
            kernel_path: "/tmp/vmlinux".into(),
            rootfs_path: "/tmp/rootfs.ext4".into(),
            kernel_args: None,
            initrd_path: None,
            vsock_cid: 4,
            tap_device: None,
            guest_mac: None,
            vmm: None,
            boot: crate::BootMode::DirectKernel,
            seed_path: None,
            balloon: false,
            volume_path: None,
            network_disabled: false,
            factory_recovery: false,
            host_shares: Vec::new(),
        };

        let err = backend
            .create_vm(backend.select_backend_for_config(&config).unwrap(), config)
            .await
            .unwrap_err();
        assert!(
            matches!(err, VmmError::VmAlreadyExists(ref name) if name == "existing"),
            "expected VmAlreadyExists, got: {err}"
        );
    }

    #[tokio::test]
    async fn create_vm_cleans_up_runtime_files_on_spawn_failure() {
        let dir = tempfile::tempdir().unwrap();
        // Point at a binary that does not exist so spawn() fails immediately.
        let backend = test_backend(dir.path().join("does-not-exist-firecracker"), dir.path());

        let config = VmConfig {
            requested_id: None,
            name: "cleanup-on-fail".into(),
            vcpu_count: 1,
            mem_size_mib: 128,
            kernel_path: "/tmp/vmlinux".into(),
            rootfs_path: "/tmp/rootfs.ext4".into(),
            kernel_args: None,
            initrd_path: None,
            vsock_cid: 4,
            tap_device: None,
            guest_mac: None,
            vmm: None,
            boot: crate::BootMode::DirectKernel,
            seed_path: None,
            balloon: false,
            volume_path: None,
            network_disabled: false,
            factory_recovery: false,
            host_shares: Vec::new(),
        };

        let err = backend
            .create_vm(backend.select_backend_for_config(&config).unwrap(), config)
            .await
            .unwrap_err();
        assert!(
            matches!(err, VmmError::ProcessError(_)),
            "expected ProcessError, got: {err}"
        );

        // After a create failure the runtime dir must not leak the pre-created
        // log / serial-log files, nor any partial socket / vsock artifacts.
        let leaked: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            leaked.is_empty(),
            "runtime dir should be empty after failed create_vm, found: {leaked:?}"
        );
    }

    #[tokio::test]
    async fn vm_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let backend = test_backend("firecracker", dir.path());
        let id = Uuid::new_v4();

        assert!(matches!(
            backend.vm_info(id).await,
            Err(VmmError::VmNotFound(_))
        ));
        assert!(matches!(
            backend.stop_vm(id).await,
            Err(VmmError::VmNotFound(_))
        ));
        assert!(matches!(
            backend.destroy_vm(id).await,
            Err(VmmError::VmNotFound(_))
        ));
        assert!(matches!(
            backend.pause_vm(id).await,
            Err(VmmError::VmNotFound(_))
        ));
        assert!(matches!(
            backend.resume_vm(id).await,
            Err(VmmError::VmNotFound(_))
        ));
    }

    #[tokio::test]
    async fn destroy_cleans_up_files() {
        let dir = tempfile::tempdir().unwrap();
        let backend = test_backend("firecracker", dir.path());

        let id = Uuid::new_v4();
        let socket_path = dir.path().join("test.sock");
        let vsock_path = dir.path().join("test.vsock");
        let boot_log_path = dir.path().join("test.boot.log");
        let serial_log_path = dir.path().join("test.serial.log");
        // Left by a compaction a crash interrupted.
        let serial_staging = crate::serial_log::compaction_staging_path(&serial_log_path);

        // Create the files
        tokio::fs::write(&socket_path, b"").await.unwrap();
        tokio::fs::write(&vsock_path, b"").await.unwrap();
        tokio::fs::write(&boot_log_path, b"").await.unwrap();
        tokio::fs::write(&serial_log_path, b"").await.unwrap();
        tokio::fs::write(&serial_staging, b"").await.unwrap();

        let instance = FcInstance {
            info: VmInfo {
                id,
                name: "cleanup-test".into(),
                state: VmState::Running,
                pid: Some(999),
                vcpu_count: 1,
                mem_size_mib: 128,
                vsock_cid: 3,
            },
            socket_path: socket_path.clone(),
            vsock_path: vsock_path.clone(),
            boot_log_path: boot_log_path.clone(),
            serial_log_path: serial_log_path.clone(),
            serial_capture: None,
            process: tokio::process::Command::new("true").spawn().unwrap(),
            fork_source: None,
            balloon: false,
            cgroup: noop_cgroup(),
        };
        backend.instances.lock().await.insert(id, instance);

        tokio::fs::remove_file(&socket_path).await.unwrap();
        tokio::fs::create_dir(&socket_path).await.unwrap();
        assert!(backend.destroy_vm(id).await.is_err());
        {
            let mut instances = backend.instances.lock().await;
            let owned = instances
                .get_mut(&id)
                .expect("failed cleanup must retain instance");
            assert!(owned.process.try_wait().unwrap().is_some());
        }
        tokio::fs::remove_dir(&socket_path).await.unwrap();
        backend.destroy_vm(id).await.unwrap();
        assert!(!backend.instances.lock().await.contains_key(&id));

        assert!(!socket_path.exists());
        assert!(!vsock_path.exists());
        assert!(!boot_log_path.exists());
        assert!(!serial_log_path.exists());
        assert!(!serial_staging.exists());
    }

    #[tokio::test]
    async fn vm_info_detects_dead_process() {
        let dir = tempfile::tempdir().unwrap();
        let backend = test_backend("firecracker", dir.path());

        let id = Uuid::new_v4();
        // Spawn a process that exits immediately
        let process = tokio::process::Command::new("true").spawn().unwrap();

        let instance = FcInstance {
            info: VmInfo {
                id,
                name: "dead-test".into(),
                state: VmState::Running,
                pid: process.id(),
                vcpu_count: 1,
                mem_size_mib: 128,
                vsock_cid: 3,
            },
            socket_path: dir.path().join("test.sock"),
            vsock_path: dir.path().join("test.vsock"),
            boot_log_path: dir.path().join("test.boot.log"),
            serial_log_path: dir.path().join("test.serial.log"),
            serial_capture: None,
            process,
            fork_source: None,
            balloon: false,
            cgroup: noop_cgroup(),
        };
        backend.instances.lock().await.insert(id, instance);

        // Give the process time to exit
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let info = backend.vm_info(id).await.unwrap();
        assert_eq!(info.state, VmState::Stopped);
        assert!(info.pid.is_none());
    }

    /// A running instance wrapping `process`, registered in `backend`'s map.
    async fn register_running_process(
        backend: &FirecrackerBackend,
        dir: &Path,
        process: tokio::process::Child,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let instance = FcInstance {
            info: VmInfo {
                id,
                name: format!("stop-wait-{id}"),
                state: VmState::Running,
                pid: process.id(),
                vcpu_count: 1,
                mem_size_mib: 128,
                vsock_cid: 3,
            },
            socket_path: dir.join(format!("{id}.sock")),
            vsock_path: dir.join(format!("{id}.vsock")),
            boot_log_path: dir.join(format!("{id}.boot.log")),
            serial_log_path: dir.join(format!("{id}.serial.log")),
            serial_capture: None,
            process,
            fork_source: None,
            balloon: false,
            cgroup: noop_cgroup(),
        };
        backend.instances.lock().await.insert(id, instance);
        id
    }

    async fn process_has_exited(backend: &FirecrackerBackend, id: Uuid) -> bool {
        let mut instances = backend.instances.lock().await;
        instances
            .get_mut(&id)
            .expect("instance stays registered")
            .process
            .try_wait()
            .unwrap()
            .is_some()
    }

    /// A guest that already ended itself gets no shutdown request: the API
    /// socket sees no connection, and the stop settles the instance at once.
    #[tokio::test]
    async fn stop_of_an_exited_guest_sends_no_shutdown_request() {
        let dir = tempfile::tempdir().unwrap();
        let backend = test_backend("firecracker", dir.path());
        let mut process = tokio::process::Command::new("true").spawn().unwrap();
        process.wait().await.unwrap();
        let id = register_running_process(&backend, dir.path(), process).await;
        let api_socket =
            tokio::net::UnixListener::bind(dir.path().join(format!("{id}.sock"))).unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), backend.stop_vm(id))
            .await
            .expect("an exited guest needs no grace period")
            .unwrap();

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), api_socket.accept())
                .await
                .is_err(),
            "stop_vm connected to the API socket of an exited guest"
        );
        let info = backend.vm_info(id).await.unwrap();
        assert_eq!(info.state, VmState::Stopped);
        assert!(info.pid.is_none());
    }

    #[tokio::test]
    async fn stop_wait_contract_observes_a_clean_process_exit() {
        let dir = tempfile::tempdir().unwrap();
        let backend = test_backend("firecracker", dir.path());
        let process = tokio::process::Command::new("true").spawn().unwrap();
        let id = register_running_process(&backend, dir.path(), process).await;

        let exit = wait_for_exit_or_kill(&backend.instances, id, std::time::Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(exit, GuestExit::Clean);
        assert!(process_has_exited(&backend, id).await);
    }

    #[tokio::test]
    async fn stop_wait_contract_kills_a_process_after_the_grace_period() {
        let dir = tempfile::tempdir().unwrap();
        let backend = test_backend("firecracker", dir.path());
        let process = tokio::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let id = register_running_process(&backend, dir.path(), process).await;

        let exit =
            wait_for_exit_or_kill(&backend.instances, id, std::time::Duration::from_millis(10))
                .await
                .unwrap();

        assert_eq!(exit, GuestExit::Forced);
        assert!(process_has_exited(&backend, id).await);
    }

    #[tokio::test]
    async fn stop_wait_contract_reports_an_instance_removed_during_the_wait() {
        let dir = tempfile::tempdir().unwrap();
        let backend = test_backend("firecracker", dir.path());
        let process = tokio::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let id = register_running_process(&backend, dir.path(), process).await;

        let instances = Arc::clone(&backend.instances);
        let wait = tokio::spawn(async move {
            wait_for_exit_or_kill(&instances, id, std::time::Duration::from_secs(5)).await
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let mut removed = backend.instances.lock().await.remove(&id).unwrap();
        removed.process.kill().await.unwrap();

        let exit = tokio::time::timeout(std::time::Duration::from_secs(1), wait)
            .await
            .expect("the wait notices the removal within one poll")
            .unwrap()
            .unwrap();
        assert_eq!(exit, GuestExit::Gone);
    }

    /// The regression guard for the stop that stalled every other VM: the
    /// instance map must be free while a guest uses its shutdown grace.
    #[tokio::test]
    async fn stop_wait_releases_the_instance_map_during_the_grace_period() {
        let dir = tempfile::tempdir().unwrap();
        let backend = test_backend("firecracker", dir.path());
        let process = tokio::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let id = register_running_process(&backend, dir.path(), process).await;

        let grace = std::time::Duration::from_millis(800);
        let started = std::time::Instant::now();
        let instances = Arc::clone(&backend.instances);
        let wait = tokio::spawn(async move { wait_for_exit_or_kill(&instances, id, grace).await });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !wait.is_finished(),
            "the wait must still be inside the grace period when the map is probed"
        );
        let probe = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            backend.instances.lock(),
        )
        .await;
        assert!(
            probe.is_ok(),
            "another VM's operation could not take the instance map while a guest shuts down"
        );
        drop(probe);

        assert_eq!(wait.await.unwrap().unwrap(), GuestExit::Forced);
        assert!(
            started.elapsed() >= grace,
            "the kill must not precede the grace period"
        );
        assert!(process_has_exited(&backend, id).await);
    }

    /// `set_balloon` on an unknown id returns VmNotFound.
    #[tokio::test]
    async fn set_balloon_unknown_id_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let backend = test_backend("firecracker", dir.path());
        let id = Uuid::new_v4();
        assert!(matches!(
            backend.set_balloon(id, 64).await,
            Err(VmmError::VmNotFound(_))
        ));
    }

    /// `set_balloon` on an instance created without a balloon device returns a
    /// clear InvalidConfig error before touching the Firecracker API.
    #[tokio::test]
    async fn set_balloon_without_device_is_invalid_config() {
        let dir = tempfile::tempdir().unwrap();
        let backend = test_backend("firecracker", dir.path());
        let id = Uuid::new_v4();
        let instance = FcInstance {
            info: VmInfo {
                id,
                name: "no-balloon".into(),
                state: VmState::Running,
                pid: Some(999),
                vcpu_count: 1,
                mem_size_mib: 256,
                vsock_cid: 5,
            },
            socket_path: dir.path().join("nb.sock"),
            vsock_path: dir.path().join("nb.vsock"),
            boot_log_path: dir.path().join("nb.boot.log"),
            serial_log_path: dir.path().join("nb.serial.log"),
            serial_capture: None,
            process: tokio::process::Command::new("true").spawn().unwrap(),
            fork_source: None,
            balloon: false,
            cgroup: noop_cgroup(),
        };
        backend.instances.lock().await.insert(id, instance);

        let err = backend.set_balloon(id, 64).await.unwrap_err();
        assert!(
            matches!(err, VmmError::InvalidConfig(ref msg) if msg.contains("balloon")),
            "expected InvalidConfig mentioning balloon, got: {err}"
        );
    }

    #[test]
    fn backend_accepts_a_disabled_supervisor() {
        use std::sync::Arc;
        let _be = FirecrackerBackend::new(
            "firecracker",
            "/tmp",
            Arc::new(crate::cgroup::CgroupSupervisor::disabled()),
        );
    }

    #[tokio::test]
    async fn firecracker_rejects_host_shares() {
        let dir = tempfile::tempdir().unwrap();
        let backend = test_backend("firecracker", dir.path());

        let mut config = VmConfig {
            requested_id: None,
            name: "test-shares".into(),
            vcpu_count: 1,
            mem_size_mib: 128,
            kernel_path: "/tmp/vmlinux".into(),
            rootfs_path: "/tmp/rootfs.ext4".into(),
            kernel_args: None,
            initrd_path: None,
            vsock_cid: 4,
            tap_device: None,
            guest_mac: None,
            vmm: None,
            boot: crate::BootMode::DirectKernel,
            seed_path: None,
            balloon: false,
            volume_path: None,
            network_disabled: false,
            factory_recovery: false,
            host_shares: Vec::new(),
        };
        config.host_shares = vec![crate::HostShare {
            host: "/srv/work".into(),
            guest: "/work".into(),
            read_only: false,
            tag: "fs0".into(),
        }];

        let err = backend
            .create_vm(backend.select_backend_for_config(&config).unwrap(), config)
            .await
            .unwrap_err();
        assert!(
            matches!(err, VmmError::Unsupported(_)),
            "expected Unsupported, got {err:?}"
        );
    }
}
