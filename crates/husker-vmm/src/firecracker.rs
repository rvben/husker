use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{
    RestoreTarget, SnapshotMeta, SnapshotPaths, VmConfig, VmInfo, VmState, VmmBackend, VmmError,
};

/// Tracks a running Firecracker VM instance.
struct FcInstance {
    info: VmInfo,
    socket_path: PathBuf,
    vsock_path: PathBuf,
    boot_log_path: PathBuf,
    serial_log_path: PathBuf,
    process: tokio::process::Child,
    /// Whether the balloon device was installed at boot.
    balloon: bool,
}

/// RAII guard that temporarily makes a snapshot's embedded source rootfs path
/// resolve to a fork's reflink clone, so Firecracker opens the fork's writable
/// disk on `/snapshot/load`. The source's real rootfs is moved aside and the
/// embedded path symlinked to the clone; on drop (success or error) the real
/// rootfs is restored, leaving Firecracker holding the clone's fd.
///
/// Forks of one source must be serialized (the caller holds the source's lock):
/// two concurrent installs would both try to move the same source file aside.
struct RootfsAlias {
    source_rootfs: PathBuf,
    backup: PathBuf,
    active: bool,
}

/// Path of the backup that [`RootfsAlias`] stashes a source rootfs into while a
/// fork holds it aliased to the fork's clone during `/snapshot/load`.
fn fork_src_backup_path(source_rootfs: &Path) -> PathBuf {
    PathBuf::from(format!("{}.fork-src-bak", source_rootfs.display()))
}

/// Recover a source rootfs stranded by a fork that died after stashing the real
/// disk aside (`<source_rootfs>.fork-src-bak`) but before restoring it, which
/// leaves `source_rootfs` as a stale symlink to a fork clone. Drops the symlink
/// and renames the backup back over it. Returns whether a recovery happened;
/// a no-op (and `Ok(false)`) when no backup exists. Call at daemon startup for
/// every VM's rootfs, before any resume could open a stale-symlinked source.
pub fn recover_aliased_rootfs(source_rootfs: &Path) -> std::io::Result<bool> {
    let backup = fork_src_backup_path(source_rootfs);
    if !backup.exists() {
        return Ok(false);
    }
    let _ = std::fs::remove_file(source_rootfs);
    std::fs::rename(&backup, source_rootfs)?;
    Ok(true)
}

impl RootfsAlias {
    fn install(source_rootfs: &Path, fork_rootfs: &Path) -> Result<Self, VmmError> {
        // Crash recovery: a leftover backup means a previous fork died after the
        // rename but before the undo, leaving `source_rootfs` as a stale symlink to
        // a fork clone and the real rootfs in `backup`. Restore it before
        // re-aliasing, so the source disk is never lost or overwritten.
        recover_aliased_rootfs(source_rootfs).map_err(|e| {
            VmmError::ProcessError(format!("fork: recover stranded source rootfs: {e}"))
        })?;
        let backup = fork_src_backup_path(source_rootfs);
        std::fs::rename(source_rootfs, &backup)
            .map_err(|e| VmmError::ProcessError(format!("fork: stash source rootfs aside: {e}")))?;
        if let Err(e) = std::os::unix::fs::symlink(fork_rootfs, source_rootfs) {
            // Restore immediately so a failed alias never strands the source.
            let _ = std::fs::rename(&backup, source_rootfs);
            return Err(VmmError::ProcessError(format!(
                "fork: alias source rootfs to clone: {e}"
            )));
        }
        Ok(Self {
            source_rootfs: source_rootfs.to_path_buf(),
            backup,
            active: true,
        })
    }

    fn undo(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        // Remove the symlink at the embedded path, then move the real rootfs back.
        let _ = std::fs::remove_file(&self.source_rootfs);
        let _ = std::fs::rename(&self.backup, &self.source_rootfs);
    }
}

impl Drop for RootfsAlias {
    fn drop(&mut self) {
        self.undo();
    }
}

/// Firecracker VMM backend.
///
/// Communicates with each Firecracker process via its HTTP-over-Unix-socket API.
pub struct FirecrackerBackend {
    firecracker_bin: PathBuf,
    runtime_dir: PathBuf,
    instances: Arc<Mutex<HashMap<Uuid, FcInstance>>>,
}

/// Minimum Firecracker version `husker fork` needs: `network_overrides` (1.12.0,
/// PR #4731) to rebind the host TAP, plus `vsock_override` (1.16.0, PR #5323) to
/// give each fork its own vsock socket so concurrent forks of one snapshot do
/// not collide on the host UDS. The later of the two requirements wins.
const FORK_MIN_FIRECRACKER: (u32, u32, u32) = (1, 16, 0);

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
    pub fn new(firecracker_bin: impl Into<PathBuf>, runtime_dir: impl Into<PathBuf>) -> Self {
        Self {
            firecracker_bin: firecracker_bin.into(),
            runtime_dir: runtime_dir.into(),
            instances: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Fail with a clear message when the installed Firecracker is too old to
    /// fork (it would otherwise reject the `network_overrides` / `vsock_override`
    /// fields with an opaque 400). Run `firecracker --version` and compare.
    async fn assert_firecracker_supports_fork(&self) -> Result<(), VmmError> {
        let output = tokio::process::Command::new(&self.firecracker_bin)
            .arg("--version")
            .output()
            .await
            .map_err(|e| {
                VmmError::ProcessError(format!(
                    "run `{} --version`: {e}",
                    self.firecracker_bin.display()
                ))
            })?;
        let text = String::from_utf8_lossy(&output.stdout);
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
        let socket_path = socket_path.to_owned();
        let connector = tower::util::service_fn(move |_: hyper::Uri| {
            let path = socket_path.clone();
            Box::pin(async move {
                let stream = tokio::net::UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            })
        });

        let client = Client::builder(TokioExecutor::new()).build::<_, Full<Bytes>>(connector);

        let body_bytes = match body {
            Some(v) => {
                serde_json::to_vec(v).map_err(|e| VmmError::ApiError(format!("serialize: {e}")))?
            }
            None => Vec::new(),
        };

        let req = Request::builder()
            .method(method)
            .uri(format!("http://localhost{path}"))
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))
            .map_err(|e| VmmError::ApiError(format!("build request: {e}")))?;

        let resp = client
            .request(req)
            .await
            .map_err(|e| VmmError::ApiError(format!("{method} {path}: {e}")))?;

        let status = resp.status();
        let resp_body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| VmmError::ApiError(format!("read response body: {e}")))?
            .to_bytes();

        if !status.is_success() {
            let detail = String::from_utf8_lossy(&resp_body);
            return Err(VmmError::ApiError(format!(
                "{method} {path} returned {status}: {detail}"
            )));
        }

        Ok(resp_body)
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
    fn default_boot_args(has_initrd: bool) -> String {
        let base = "console=ttyS0 reboot=k panic=1 pci=off";
        let root = if has_initrd { "" } else { " root=/dev/vda rw" };
        format!("{base}{root} ip=172.20.0.2::172.20.0.1:255.255.255.252::eth0:off")
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
        serial_file: std::fs::File,
        stderr_file: std::fs::File,
    ) -> Result<VmInfo, VmmError> {
        // Spawn the Firecracker process
        let process = tokio::process::Command::new(&self.firecracker_bin)
            .arg("--api-sock")
            .arg(socket_path)
            .arg("--log-path")
            .arg(boot_log_path)
            .arg("--level")
            .arg("Info")
            .stdout(serial_file)
            .stderr(stderr_file)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| VmmError::ProcessError(format!("spawn firecracker: {e}")))?;

        let pid = process.id();

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

        let instance = FcInstance {
            info: info.clone(),
            socket_path: socket_path.to_owned(),
            vsock_path: vsock_path.to_owned(),
            boot_log_path: boot_log_path.to_owned(),
            serial_log_path: serial_log_path.to_owned(),
            process,
            balloon: config.balloon,
        };

        self.instances.lock().await.insert(id, instance);

        Ok(info)
    }
}

impl VmmBackend for FirecrackerBackend {
    type VsockStream = tokio::net::UnixStream;

    fn backend_kind(&self) -> &'static str {
        "firecracker"
    }

    async fn create_vm(&self, config: VmConfig) -> Result<VmInfo, VmmError> {
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

        let id = Uuid::new_v4();
        let socket_path = self.runtime_dir.join(format!("{id}.sock"));
        let boot_log_path = self.runtime_dir.join(format!("{id}.boot.log"));
        let vsock_path = self.runtime_dir.join(format!("{id}.vsock"));
        let serial_log_path = self.runtime_dir.join(format!("{id}.serial.log"));

        tokio::fs::create_dir_all(&self.runtime_dir).await?;

        // Firecracker requires the log file to exist before startup
        tokio::fs::write(&boot_log_path, b"").await?;

        // Firecracker writes guest serial console (ttyS0) to stdout.
        // Capture it to a file so `husker logs` can read it.
        let serial_file = std::fs::File::create(&serial_log_path)
            .map_err(|e| VmmError::ProcessError(format!("create serial log: {e}")))?;

        // FC process stderr goes to the FC log file (separate from guest serial).
        let stderr_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&boot_log_path)
            .map_err(|e| VmmError::ProcessError(format!("open FC log for stderr: {e}")))?;

        // Spawn, configure, and start — cleaning up the serial log on any failure.
        match self
            .spawn_and_configure(
                id,
                config,
                &socket_path,
                &boot_log_path,
                &vsock_path,
                &serial_log_path,
                serial_file,
                stderr_file,
            )
            .await
        {
            Ok(info) => Ok(info),
            Err(e) => {
                // Capture diagnostics before removing the artifacts.
                let serial_tail = crate::tail_lines(&serial_log_path, 20);
                let boot_tail = crate::tail_lines(&boot_log_path, 20);
                let _ = std::fs::remove_file(&serial_log_path);
                let _ = std::fs::remove_file(&boot_log_path);
                let _ = std::fs::remove_file(&socket_path);
                let _ = std::fs::remove_file(&vsock_path);
                let mut msg = format!("{e}");
                crate::append_log_tails(&mut msg, serial_tail, boot_tail, "firecracker boot log");
                Err(VmmError::ProcessError(msg))
            }
        }
    }

    async fn stop_vm(&self, id: Uuid) -> Result<(), VmmError> {
        // Extract what we need, then drop the lock before making the API call
        let socket_path = {
            let instances = self.instances.lock().await;
            let instance = instances.get(&id).ok_or(VmmError::VmNotFound(id))?;
            instance.socket_path.clone()
        };

        Self::fc_put(
            &socket_path,
            "/actions",
            &serde_json::json!({ "action_type": "SendCtrlAltDel" }),
        )
        .await?;

        // Re-acquire lock to update state
        let mut instances = self.instances.lock().await;
        if let Some(instance) = instances.get_mut(&id) {
            instance.info.state = VmState::Stopped;
        }
        Ok(())
    }

    async fn destroy_vm(&self, id: Uuid) -> Result<(), VmmError> {
        let mut instances = self.instances.lock().await;
        let mut instance = instances.remove(&id).ok_or(VmmError::VmNotFound(id))?;

        let _ = instance.process.kill().await;
        let _ = tokio::fs::remove_file(&instance.socket_path).await;
        let _ = tokio::fs::remove_file(&instance.vsock_path).await;
        let _ = tokio::fs::remove_file(&instance.boot_log_path).await;
        let _ = tokio::fs::remove_file(&instance.serial_log_path).await;

        Ok(())
    }

    async fn vm_info(&self, id: Uuid) -> Result<VmInfo, VmmError> {
        let mut instances = self.instances.lock().await;
        let instance = instances.get_mut(&id).ok_or(VmmError::VmNotFound(id))?;

        // Check if the process is still alive
        if instance.info.state == VmState::Running || instance.info.state == VmState::Paused {
            match instance.process.try_wait() {
                Ok(Some(_)) => {
                    // Process exited — mark as stopped
                    instance.info.state = VmState::Stopped;
                    instance.info.pid = None;
                }
                Ok(None) => {} // Still running
                Err(_) => {
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
            } => (
                id,
                name,
                vcpu_count,
                mem_size_mib,
                vsock_cid,
                Some((tap_device, source_rootfs, fork_rootfs)),
            ),
        };
        let vsock_path = self.runtime_dir.join(format!("{id}.vsock"));

        // A fork rebinds the guest NIC to a fresh host TAP via the
        // `network_overrides` field on `/snapshot/load`, which Firecracker only
        // understands from 1.12.0 on. Check up front so an old binary fails with
        // a clear, actionable message instead of an opaque deserialization 400.
        if fork.is_some() {
            self.assert_firecracker_supports_fork().await?;
        }

        // Convert the snapshot/memory/vsock paths to &str up front, before
        // creating any runtime files, so a (rare) non-UTF-8 path returns without
        // leaking the socket and log files created below.
        let snapshot = Self::path_to_str(&src.vmstate, "vmstate")?;
        let mem = Self::path_to_str(&src.memory, "memory")?;
        let vsock_path_str = Self::path_to_str(&vsock_path, "vsock_path")?;

        let socket_path = self.runtime_dir.join(format!("{id}.sock"));
        let boot_log_path = self.runtime_dir.join(format!("{id}.boot.log"));
        let serial_log_path = self.runtime_dir.join(format!("{id}.serial.log"));

        tokio::fs::create_dir_all(&self.runtime_dir).await?;
        // Clear any stale socket so Firecracker can bind a fresh one.
        let _ = tokio::fs::remove_file(&socket_path).await;
        tokio::fs::write(&boot_log_path, b"").await?;

        let serial_file = std::fs::File::create(&serial_log_path)
            .map_err(|e| VmmError::ProcessError(format!("create serial log: {e}")))?;
        let stderr_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&boot_log_path)
            .map_err(|e| VmmError::ProcessError(format!("open FC log for stderr: {e}")))?;

        let process = tokio::process::Command::new(&self.firecracker_bin)
            .arg("--api-sock")
            .arg(&socket_path)
            .arg("--log-path")
            .arg(&boot_log_path)
            .arg("--level")
            .arg("Info")
            .stdout(serial_file)
            .stderr(stderr_file)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| VmmError::ProcessError(format!("spawn firecracker: {e}")))?;
        let pid = process.id();

        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        if !socket_path.exists() {
            // The FC process dies via kill_on_drop; remove the runtime files it
            // left so a timed-out restore does not leak the socket and logs.
            let _ = tokio::fs::remove_file(&socket_path).await;
            let _ = tokio::fs::remove_file(&serial_log_path).await;
            let _ = tokio::fs::remove_file(&boot_log_path).await;
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
        let _alias = match &fork {
            Some((tap, source_rootfs, fork_rootfs)) => {
                load_body["network_overrides"] = serde_json::json!([{
                    "iface_id": "eth0",
                    "host_dev_name": tap,
                }]);
                match RootfsAlias::install(source_rootfs, fork_rootfs) {
                    Ok(alias) => Some(alias),
                    Err(e) => {
                        // The FC process was already spawned; clean up its runtime
                        // files (the process itself dies via kill_on_drop) so a
                        // failed alias does not leak the socket and logs.
                        let _ = tokio::fs::remove_file(&socket_path).await;
                        let _ = tokio::fs::remove_file(&serial_log_path).await;
                        let _ = tokio::fs::remove_file(&boot_log_path).await;
                        return Err(e);
                    }
                }
            }
            None => None,
        };

        if let Err(e) = Self::fc_put(&socket_path, "/snapshot/load", &load_body).await {
            // Capture diagnostics before removing the artifacts. The alias guard
            // drops here too, restoring the source's rootfs.
            let serial_tail = crate::tail_lines(&serial_log_path, 20);
            let boot_tail = crate::tail_lines(&boot_log_path, 20);
            let _ = tokio::fs::remove_file(&socket_path).await;
            let _ = tokio::fs::remove_file(&serial_log_path).await;
            let _ = tokio::fs::remove_file(&boot_log_path).await;
            let mut msg = format!("{e}");
            crate::append_log_tails(&mut msg, serial_tail, boot_tail, "firecracker boot log");
            return Err(VmmError::ProcessError(msg));
        }
        // Firecracker now holds the fork's rootfs fd open; undo the alias so the
        // source keeps its own disk for a later resume.
        drop(_alias);

        let info = VmInfo {
            id,
            name,
            state: VmState::Running,
            pid,
            vcpu_count,
            mem_size_mib,
            vsock_cid,
        };
        let instance = FcInstance {
            info: info.clone(),
            socket_path,
            vsock_path,
            boot_log_path,
            serial_log_path,
            process,
            // A restored VM is not tracked as balloon-enabled; the snapshot restores
            // whatever device set it had, and the balloon op is opt-in per VM.
            balloon: false,
        };
        self.instances.lock().await.insert(id, instance);
        Ok(info)
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

    #[test]
    fn recover_aliased_rootfs_restores_real_disk_over_stale_symlink() {
        // Simulate a fork that crashed mid-load: source is a stale symlink to a
        // fork clone, and the real rootfs sits in the `.fork-src-bak` backup.
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("rootfs.ext4");
        let clone = dir.path().join("fork-clone.ext4");
        let backup = fork_src_backup_path(&source);
        std::fs::write(&clone, b"fork-disk").unwrap();
        std::fs::write(&backup, b"real-source-disk").unwrap();
        std::os::unix::fs::symlink(&clone, &source).unwrap();

        let recovered = recover_aliased_rootfs(&source).unwrap();

        assert!(recovered, "a stranded backup must be reported as recovered");
        assert!(!backup.exists(), "backup must be consumed");
        assert!(
            !std::fs::symlink_metadata(&source)
                .unwrap()
                .file_type()
                .is_symlink(),
            "source must no longer be a symlink"
        );
        assert_eq!(
            std::fs::read(&source).unwrap(),
            b"real-source-disk",
            "source must hold the real disk again, not the fork clone"
        );
    }

    #[test]
    fn recover_aliased_rootfs_is_noop_without_backup() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("rootfs.ext4");
        std::fs::write(&source, b"intact").unwrap();
        let recovered = recover_aliased_rootfs(&source).unwrap();
        assert!(!recovered, "no backup means nothing to recover");
        assert_eq!(std::fs::read(&source).unwrap(), b"intact");
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

    #[tokio::test]
    async fn duplicate_name_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FirecrackerBackend::new("firecracker", dir.path());

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
            process: tokio::process::Command::new("true").spawn().unwrap(),
            balloon: false,
        };
        backend.instances.lock().await.insert(id, instance);

        let config = VmConfig {
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
            host_shares: Vec::new(),
        };

        let err = backend.create_vm(config).await.unwrap_err();
        assert!(
            matches!(err, VmmError::VmAlreadyExists(ref name) if name == "existing"),
            "expected VmAlreadyExists, got: {err}"
        );
    }

    #[tokio::test]
    async fn create_vm_cleans_up_runtime_files_on_spawn_failure() {
        let dir = tempfile::tempdir().unwrap();
        // Point at a binary that does not exist so spawn() fails immediately.
        let backend =
            FirecrackerBackend::new(dir.path().join("does-not-exist-firecracker"), dir.path());

        let config = VmConfig {
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
            host_shares: Vec::new(),
        };

        let err = backend.create_vm(config).await.unwrap_err();
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
        let backend = FirecrackerBackend::new("firecracker", dir.path());
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
        let backend = FirecrackerBackend::new("firecracker", dir.path());

        let id = Uuid::new_v4();
        let socket_path = dir.path().join("test.sock");
        let vsock_path = dir.path().join("test.vsock");
        let boot_log_path = dir.path().join("test.boot.log");
        let serial_log_path = dir.path().join("test.serial.log");

        // Create the files
        tokio::fs::write(&socket_path, b"").await.unwrap();
        tokio::fs::write(&vsock_path, b"").await.unwrap();
        tokio::fs::write(&boot_log_path, b"").await.unwrap();
        tokio::fs::write(&serial_log_path, b"").await.unwrap();

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
            process: tokio::process::Command::new("true").spawn().unwrap(),
            balloon: false,
        };
        backend.instances.lock().await.insert(id, instance);

        backend.destroy_vm(id).await.unwrap();

        assert!(!socket_path.exists());
        assert!(!vsock_path.exists());
        assert!(!boot_log_path.exists());
        assert!(!serial_log_path.exists());
    }

    #[tokio::test]
    async fn vm_info_detects_dead_process() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FirecrackerBackend::new("firecracker", dir.path());

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
            process,
            balloon: false,
        };
        backend.instances.lock().await.insert(id, instance);

        // Give the process time to exit
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let info = backend.vm_info(id).await.unwrap();
        assert_eq!(info.state, VmState::Stopped);
        assert!(info.pid.is_none());
    }

    /// `set_balloon` on an unknown id returns VmNotFound.
    #[tokio::test]
    async fn set_balloon_unknown_id_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FirecrackerBackend::new("firecracker", dir.path());
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
        let backend = FirecrackerBackend::new("firecracker", dir.path());
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
            process: tokio::process::Command::new("true").spawn().unwrap(),
            balloon: false,
        };
        backend.instances.lock().await.insert(id, instance);

        let err = backend.set_balloon(id, 64).await.unwrap_err();
        assert!(
            matches!(err, VmmError::InvalidConfig(ref msg) if msg.contains("balloon")),
            "expected InvalidConfig mentioning balloon, got: {err}"
        );
    }

    #[tokio::test]
    async fn firecracker_rejects_host_shares() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FirecrackerBackend::new("firecracker", dir.path());

        let mut config = VmConfig {
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
            host_shares: Vec::new(),
        };
        config.host_shares = vec![crate::HostShare {
            host: "/srv/work".into(),
            guest: "/work".into(),
            read_only: false,
            tag: "fs0".into(),
        }];

        let err = backend.create_vm(config).await.unwrap_err();
        assert!(
            matches!(err, VmmError::Unsupported(_)),
            "expected Unsupported, got {err:?}"
        );
    }
}
