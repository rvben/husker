//! QEMU/KVM backend logic (cross-platform parts).
//!
//! The lifecycle methods are public API; the VmmBackend impl (Linux-only) delegates to them.
//! The `VmmBackend` trait impl and vsock connect (Linux-only, needs vhost-vsock)
//! live in a separate, Linux-gated block. The struct, argument builder, and lifecycle
//! methods here are platform-independent and unit-tested.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::Mutex;
use uuid::Uuid;

#[cfg(target_os = "linux")]
use crate::{BackendKind, CreatedVm};
use crate::{VmConfig, VmInfo, VmState, VmmError};

/// A running QEMU VM tracked by the backend.
pub(crate) struct QemuInstance {
    pub(crate) info: VmInfo,
    pub(crate) qmp_path: PathBuf,
    pub(crate) pidfile_path: PathBuf,
    pub(crate) serial_log_path: PathBuf,
    pub(crate) boot_log_path: PathBuf,
    pub(crate) process: tokio::process::Child,
    /// Whether the balloon device was installed at boot.
    pub(crate) balloon: bool,
    /// One virtiofsd child per host share (parallel to `virtiofsd_socks`).
    /// `kill_on_drop(true)` ensures they are terminated when the instance is removed.
    pub(crate) virtiofsds: Vec<tokio::process::Child>,
    /// Unix socket paths created by each virtiofsd; removed on destroy.
    pub(crate) virtiofsd_socks: Vec<PathBuf>,
    /// Per-VM cgroup resource limits (no-op when the supervisor is disabled).
    pub(crate) cgroup: crate::cgroup::VmCgroup,
}

/// Locate the virtiofsd binary: try `virtiofsd` on PATH, then well-known fallbacks.
fn virtiofsd_bin() -> &'static str {
    const FALLBACKS: &[&str] = &["/usr/libexec/virtiofsd", "/usr/lib/qemu/virtiofsd"];
    for path in FALLBACKS {
        if std::path::Path::new(path).exists() {
            return path;
        }
    }
    "virtiofsd"
}

/// Poll for a Unix socket path to appear, mirroring the QMP socket-wait loop.
/// Bounded to 50 * 100ms = 5 seconds.
async fn wait_for_socket(path: &std::path::Path) -> Result<(), VmmError> {
    for _ in 0..50 {
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Err(VmmError::ProcessError(format!(
        "virtiofsd socket did not appear within 5s: {}",
        path.display()
    )))
}

/// QEMU/KVM VMM backend. One `qemu-system` child process per VM.
pub struct QemuKvmBackend {
    pub(crate) binary: PathBuf,
    pub(crate) runtime_dir: PathBuf,
    pub(crate) instances: Arc<Mutex<HashMap<Uuid, QemuInstance>>>,
    cgroup: std::sync::Arc<crate::cgroup::CgroupSupervisor>,
}

impl QemuKvmBackend {
    pub fn new(
        binary: impl Into<PathBuf>,
        runtime_dir: impl Into<PathBuf>,
        cgroup: std::sync::Arc<crate::cgroup::CgroupSupervisor>,
    ) -> Self {
        Self {
            binary: binary.into(),
            runtime_dir: runtime_dir.into(),
            instances: Arc::new(Mutex::new(HashMap::new())),
            cgroup,
        }
    }

    fn qmp_socket(&self, id: Uuid) -> PathBuf {
        self.runtime_dir.join(format!("{id}.qmp"))
    }
    fn pidfile(&self, id: Uuid) -> PathBuf {
        self.runtime_dir.join(format!("{id}.pid"))
    }
    fn serial_log(&self, id: Uuid) -> PathBuf {
        self.runtime_dir.join(format!("{id}.serial.log"))
    }
    fn boot_log(&self, id: Uuid) -> PathBuf {
        self.runtime_dir.join(format!("{id}.boot.log"))
    }
    fn virtiofs_sock(&self, id: Uuid, n: usize) -> PathBuf {
        self.runtime_dir.join(format!("{id}-fs{n}.sock"))
    }

    /// Per-VM writable OVMF variable store (a copy of the firmware VARS template).
    pub(crate) fn ovmf_vars_copy(&self, id: Uuid) -> PathBuf {
        self.runtime_dir.join(format!("{id}.OVMF_VARS.fd"))
    }

    /// Build the full `qemu-system-*` argument vector. Pure function of
    /// (id, config, runtime paths) so it is unit-testable without spawning QEMU.
    pub fn build_args(&self, id: Uuid, config: &VmConfig) -> Result<Vec<String>, VmmError> {
        #[cfg(target_arch = "aarch64")]
        let machine = "virt";
        #[cfg(not(target_arch = "aarch64"))]
        let machine = "q35";

        // When host shares are present, guest RAM must be a shareable memfd object
        // (required for virtiofs). q35 and virt both accept memory-backend= on the
        // -machine arg, so attach it there instead of using a separate -numa node.
        let machine_arg = if config.host_shares.is_empty() {
            machine.to_string()
        } else {
            format!("{machine},memory-backend=mem0")
        };

        let mut args: Vec<String> = vec![
            "-machine".into(),
            machine_arg,
            "-smp".into(),
            config.vcpu_count.to_string(),
            "-nographic".into(),
            "-nodefaults".into(),
            "-name".into(),
            config.name.clone(),
            "-qmp".into(),
            format!("unix:{},server,nowait", self.qmp_socket(id).display()),
            // Guest serial console (ttyS0) -> file, so `husker logs` can read it.
            "-serial".into(),
            format!("file:{}", self.serial_log(id).display()),
            "-pidfile".into(),
            self.pidfile(id).to_string_lossy().into_owned(),
            "-device".into(),
            "virtio-rng-pci".into(),
            "-cpu".into(),
            "host".into(),
            "-enable-kvm".into(),
            // Guest agent transport: host<->guest vsock. cid allocated by core.
            "-device".into(),
            format!("vhost-vsock-pci,guest-cid={}", config.vsock_cid),
        ];

        // Plain -m for VMs without host shares; shared memfd when shares are present.
        if config.host_shares.is_empty() {
            args.push("-m".into());
            args.push(config.mem_size_mib.to_string());
        } else {
            args.push("-object".into());
            args.push(format!(
                "memory-backend-memfd,id=mem0,size={}M,share=on",
                config.mem_size_mib
            ));
        }

        // Memory balloon device (machine-level, independent of boot mode).
        if config.balloon {
            args.push("-device".into());
            args.push("virtio-balloon-pci".into());
        }

        match &config.boot {
            crate::BootMode::DirectKernel => {
                // Root disk: husker clones a RAW ext4 rootfs (not qcow2). Guest sees /dev/vda.
                args.push("-drive".into());
                args.push(format!(
                    "file={},format=raw,if=virtio,cache=writeback",
                    config.rootfs_path.display()
                ));

                // Volume disk (persistent data, /dev/vdb). Placed immediately after
                // the root disk so the guest device order is stable: vda=rootfs, vdb=volume.
                if let Some(ref vol) = config.volume_path {
                    args.push("-drive".into());
                    args.push(format!(
                        "file={},format=raw,if=virtio,cache=writeback",
                        vol.display()
                    ));
                }

                #[cfg(target_arch = "aarch64")]
                let default_console = "console=ttyAMA0";
                #[cfg(not(target_arch = "aarch64"))]
                let default_console = "console=ttyS0";
                let base_args = config
                    .kernel_args
                    .clone()
                    .unwrap_or_else(|| default_console.to_string());
                // Strip Firecracker's microVM `pci=off`; QEMU q35 needs PCIe enumeration.
                let base_args = base_args
                    .split_whitespace()
                    .filter(|tok| *tok != "pci=off")
                    .collect::<Vec<_>>()
                    .join(" ");
                args.push("-kernel".into());
                args.push(config.kernel_path.display().to_string());
                if let Some(initrd) = &config.initrd_path {
                    args.push("-initrd".into());
                    args.push(initrd.display().to_string());
                }
                args.push("-append".into());
                args.push(format!("{base_args} root=/dev/vda rw"));
            }
            crate::BootMode::Uefi {
                ovmf_code,
                ovmf_vars_template: _,
            } => {
                // OVMF firmware: read-only CODE + a per-VM writable VARS copy (made in `create`).
                args.push("-drive".into());
                args.push(format!(
                    "if=pflash,format=raw,unit=0,readonly=on,file={}",
                    ovmf_code.display()
                ));
                args.push("-drive".into());
                args.push(format!(
                    "if=pflash,format=raw,unit=1,file={}",
                    self.ovmf_vars_copy(id).display()
                ));
                // Boot disk: the cloned + resized qcow2 cloud image. The image's own
                // bootloader runs under UEFI, so there is no -kernel/-initrd/-append.
                // Guest sees /dev/vda.
                args.push("-drive".into());
                args.push(format!(
                    "file={},format=qcow2,if=virtio,cache=writeback",
                    config.rootfs_path.display()
                ));
                // Volume disk (persistent data, /dev/vdb). Placed immediately after
                // the boot disk and before the seed so the guest device order is
                // stable: vda=boot-disk, vdb=volume, vdc=seed (NoCloud finds seed by
                // filesystem label so its position is free).
                if let Some(ref vol) = config.volume_path {
                    args.push("-drive".into());
                    args.push(format!(
                        "file={},format=raw,if=virtio,cache=writeback",
                        vol.display()
                    ));
                }
                if let Some(seed) = &config.seed_path {
                    args.push("-drive".into());
                    args.push(format!("file={},format=raw,if=virtio", seed.display()));
                }
            }
            crate::BootMode::Efi { .. } => {
                return Err(VmmError::InvalidConfig(
                    "BootMode::Efi is not supported by the QEMU backend; use BootMode::Uefi with OVMF paths".into(),
                ));
            }
        }

        // Networking: husker-core already created/attached `config.tap_device`.
        // script=no/downscript=no => QEMU must not manage the TAP lifecycle.
        if let Some(tap) = &config.tap_device {
            let mac = config
                .guest_mac
                .clone()
                .unwrap_or_else(|| "52:54:00:00:00:01".into());
            args.push("-netdev".into());
            args.push(format!("tap,id=net0,ifname={tap},script=no,downscript=no"));
            args.push("-device".into());
            args.push(format!("virtio-net-pci,netdev=net0,mac={mac}"));
        }

        // virtiofs: one chardev socket + vhost-user-fs-pci device per host share.
        // The matching virtiofsd processes are spawned in `create()` before QEMU.
        for (n, share) in config.host_shares.iter().enumerate() {
            let sock = self.virtiofs_sock(id, n);
            args.push("-chardev".into());
            args.push(format!("socket,id=fs{n},path={}", sock.display()));
            args.push("-device".into());
            args.push(format!("vhost-user-fs-pci,chardev=fs{n},tag={}", share.tag));
        }

        Ok(args)
    }

    /// Spawn a QEMU process and track it. (`VmmBackend::create_vm` delegates here.)
    pub async fn create(&self, config: VmConfig) -> Result<VmInfo, VmmError> {
        if matches!(config.boot, crate::BootMode::Efi { .. }) {
            return Err(VmmError::InvalidConfig(
                "BootMode::Efi is not supported by the QEMU backend; use BootMode::Uefi with OVMF paths".into(),
            ));
        }
        {
            let instances = self.instances.lock().await;
            if instances.values().any(|i| i.info.name == config.name) {
                return Err(VmmError::VmAlreadyExists(config.name));
            }
        }
        tokio::fs::create_dir_all(&self.runtime_dir).await?;

        let id = Uuid::new_v4();
        let args = self.build_args(id, &config)?;

        // UEFI VMs need their own writable OVMF variable store. Copy the firmware
        // template into the runtime dir; build_args points pflash unit=1 at it.
        if let crate::BootMode::Uefi {
            ovmf_vars_template, ..
        } = &config.boot
        {
            let vars_copy = self.ovmf_vars_copy(id);
            std::fs::copy(ovmf_vars_template, &vars_copy).map_err(|e| {
                VmmError::ProcessError(format!(
                    "copy OVMF VARS template {} -> {}: {e}",
                    ovmf_vars_template.display(),
                    vars_copy.display()
                ))
            })?;
        }

        // Detach QEMU's own stdio. `-nographic` otherwise binds the monitor/serial
        // to the inherited stdio, which hangs whatever launched the daemon (e.g. a
        // controlling terminal). stdin is null; QEMU's own stdout/stderr (startup
        // and device errors, distinct from the guest serial console which `-serial
        // file:` captures) go to a per-VM log for diagnostics.
        let boot_log_path = self.boot_log(id);

        // Remove the per-VM artifacts (OVMF copy, logs, sockets) if create() bails
        // before the instance is tracked, so a failed log open or spawn does not
        // leak files. Disarmed once the tracked QemuInstance owns them.
        struct PartialCreateGuard {
            paths: Vec<std::path::PathBuf>,
            armed: bool,
        }
        impl Drop for PartialCreateGuard {
            fn drop(&mut self) {
                if self.armed {
                    for p in &self.paths {
                        let _ = std::fs::remove_file(p);
                    }
                }
            }
        }
        let mut artifacts = PartialCreateGuard {
            paths: vec![
                self.qmp_socket(id),
                self.pidfile(id),
                self.serial_log(id),
                boot_log_path.clone(),
                self.ovmf_vars_copy(id),
            ],
            armed: true,
        };

        let log_out = std::fs::File::create(&boot_log_path)
            .map_err(|e| VmmError::ProcessError(format!("create qemu log: {e}")))?;
        let log_err = log_out
            .try_clone()
            .map_err(|e| VmmError::ProcessError(format!("clone qemu log handle: {e}")))?;

        // Spawn one virtiofsd per host share before QEMU so the vhost-user sockets
        // exist when QEMU enumerates its devices. kill_on_drop(true) ensures the
        // children are killed if create() returns an error (Vec drops with the scope).
        let mut virtiofsds: Vec<tokio::process::Child> = Vec::new();
        let mut virtiofsd_socks: Vec<PathBuf> = Vec::new();
        for (n, share) in config.host_shares.iter().enumerate() {
            let sock = self.virtiofs_sock(id, n);
            // Register the socket path in the cleanup guard before creating it, so
            // a failure partway through still removes the already-created sockets.
            artifacts.paths.push(sock.clone());
            let mut cmd = tokio::process::Command::new(virtiofsd_bin());
            cmd.arg(format!("--socket-path={}", sock.display()))
                .arg(format!("--shared-dir={}", share.host.display()))
                .arg("--sandbox=none")
                .kill_on_drop(true);
            if share.read_only {
                cmd.arg("--readonly");
            }
            let child = cmd
                .spawn()
                .map_err(|e| VmmError::ProcessError(format!("spawn virtiofsd: {e}")))?;
            wait_for_socket(&sock).await?;
            virtiofsd_socks.push(sock);
            virtiofsds.push(child);
        }

        // Create the per-VM cgroup before spawning so we can place the process
        // immediately after obtaining its pid.
        let vm_cgroup = self
            .cgroup
            .create_vm_cgroup(id, config.vcpu_count, config.mem_size_mib)
            .map_err(|e| VmmError::ProcessError(format!("create cgroup: {e}")))?;

        let process = tokio::process::Command::new(&self.binary)
            .args(&args)
            .stdin(std::process::Stdio::null())
            .stdout(log_out)
            .stderr(log_err)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| VmmError::ProcessError(format!("spawn qemu: {e}")))?;
        let pid = process.id();
        if let Some(pid) = pid {
            vm_cgroup
                .place(pid)
                .map_err(|e| VmmError::ProcessError(format!("place vmm in cgroup: {e}")))?;
        }

        let qmp_path = self.qmp_socket(id);
        let mut appeared = false;
        for _ in 0..50 {
            if qmp_path.exists() {
                appeared = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        if !appeared {
            // Capture diagnostics before cleanup: the guest serial log carries
            // kernel panics (e.g. an unbootable rootfs); the boot log carries
            // QEMU's own startup/device errors.
            let serial_tail = crate::tail_lines(&self.serial_log(id), 20);
            let boot_tail = crate::tail_lines(&boot_log_path, 20);
            // `process` drops here (kill_on_drop) -> QEMU killed; `artifacts` drops
            // on return and removes the per-VM files (after the tails are read).
            let mut msg = String::from("QMP socket did not appear within 5s");
            crate::append_log_tails(&mut msg, serial_tail, boot_tail, "qemu boot log");
            return Err(VmmError::ProcessError(msg));
        }

        let info = VmInfo {
            id,
            name: config.name,
            state: VmState::Running,
            pid,
            vcpu_count: config.vcpu_count,
            mem_size_mib: config.mem_size_mib,
            vsock_cid: config.vsock_cid,
        };
        self.instances.lock().await.insert(
            id,
            QemuInstance {
                info: info.clone(),
                qmp_path,
                pidfile_path: self.pidfile(id),
                serial_log_path: self.serial_log(id),
                boot_log_path,
                process,
                balloon: config.balloon,
                virtiofsds,
                virtiofsd_socks,
                cgroup: vm_cgroup,
            },
        );
        // The tracked instance now owns these files; do not delete them on drop.
        artifacts.armed = false;
        Ok(info)
    }

    /// Best-effort, asynchronous shutdown: sends an ACPI powerdown event and marks
    /// the VM `Stopped`, but the QEMU process may still be winding down. Callers
    /// must not assume the process has exited (mirrors the Firecracker backend).
    pub async fn stop(&self, id: Uuid) -> Result<(), VmmError> {
        let qmp_path = {
            let instances = self.instances.lock().await;
            instances
                .get(&id)
                .ok_or(VmmError::VmNotFound(id))?
                .qmp_path
                .clone()
        };
        if let Ok(mut qmp) = crate::qmp::QmpClient::connect(&qmp_path).await {
            let _ = qmp.system_powerdown().await;
        }
        let mut instances = self.instances.lock().await;
        if let Some(inst) = instances.get_mut(&id) {
            inst.info.state = VmState::Stopped;
        }
        Ok(())
    }

    pub async fn destroy(&self, id: Uuid) -> Result<(), VmmError> {
        let mut instances = self.instances.lock().await;
        let mut inst = instances.remove(&id).ok_or(VmmError::VmNotFound(id))?;
        tracing::debug!(%id, "destroying qemu VM");
        if let Err(e) = inst.process.kill().await {
            tracing::warn!(%id, error = %e, "failed to kill qemu process during destroy");
        }
        // Kill virtiofsd children explicitly; kill_on_drop provides a backstop when
        // inst drops at the end of this block, but an explicit kill lets us await
        // the signal delivery and keeps the shutdown deterministic.
        for vfd in &mut inst.virtiofsds {
            let _ = vfd.kill().await;
        }
        let ovmf_vars_copy = self.ovmf_vars_copy(id);
        for path in [
            inst.qmp_path.as_path(),
            inst.pidfile_path.as_path(),
            inst.serial_log_path.as_path(),
            inst.boot_log_path.as_path(),
            ovmf_vars_copy.as_path(),
        ] {
            if let Err(e) = tokio::fs::remove_file(path).await
                && e.kind() != std::io::ErrorKind::NotFound
            {
                tracing::warn!(%id, path = %path.display(), error = %e, "failed to remove qemu runtime file during destroy");
            }
        }
        for sock in &inst.virtiofsd_socks {
            if let Err(e) = tokio::fs::remove_file(sock).await
                && e.kind() != std::io::ErrorKind::NotFound
            {
                tracing::warn!(%id, path = %sock.display(), error = %e, "failed to remove qemu virtiofsd socket during destroy");
            }
        }
        inst.cgroup.remove();
        Ok(())
    }

    pub async fn info(&self, id: Uuid) -> Result<VmInfo, VmmError> {
        let mut instances = self.instances.lock().await;
        let inst = instances.get_mut(&id).ok_or(VmmError::VmNotFound(id))?;
        if inst.info.state == VmState::Running || inst.info.state == VmState::Paused {
            match inst.process.try_wait() {
                Ok(Some(_)) => {
                    // Process exited: mark as stopped and reap the now-empty cgroup.
                    inst.info.state = VmState::Stopped;
                    inst.info.pid = None;
                    inst.cgroup.remove();
                }
                Ok(None) => {}
                Err(_) => {
                    // try_wait() failed: the process state is ambiguous (it may
                    // still be alive), so do NOT reap the cgroup here. remove()
                    // SIGKILLs any pids in the cgroup, which could kill a live
                    // VMM. destroy_vm and the startup orphan sweep reclaim it.
                    inst.info.state = VmState::Failed;
                    inst.info.pid = None;
                }
            }
        }
        Ok(inst.info.clone())
    }

    pub async fn pause(&self, id: Uuid) -> Result<(), VmmError> {
        let qmp_path = {
            let instances = self.instances.lock().await;
            instances
                .get(&id)
                .ok_or(VmmError::VmNotFound(id))?
                .qmp_path
                .clone()
        };
        let mut qmp = crate::qmp::QmpClient::connect(&qmp_path).await?;
        qmp.pause().await?;
        let mut instances = self.instances.lock().await;
        if let Some(inst) = instances.get_mut(&id) {
            inst.info.state = VmState::Paused;
        }
        Ok(())
    }

    pub async fn resume(&self, id: Uuid) -> Result<(), VmmError> {
        let qmp_path = {
            let instances = self.instances.lock().await;
            instances
                .get(&id)
                .ok_or(VmmError::VmNotFound(id))?
                .qmp_path
                .clone()
        };
        let mut qmp = crate::qmp::QmpClient::connect(&qmp_path).await?;
        qmp.resume().await?;
        let mut instances = self.instances.lock().await;
        if let Some(inst) = instances.get_mut(&id) {
            inst.info.state = VmState::Running;
        }
        Ok(())
    }

    /// Convert husker's `amount_mib` (MiB reclaimed FROM the guest) to the QMP
    /// `balloon` value (target guest physical memory in bytes).
    ///
    /// QMP `balloon` takes the desired GUEST size; husker's interface uses the
    /// amount to reclaim. The conversion is: guest_target = mem_size - amount.
    /// Returns `InvalidConfig` when `amount_mib >= mem_size_mib` because the
    /// resulting guest size would be zero or negative.
    pub(crate) fn balloon_qmp_bytes(mem_size_mib: u32, amount_mib: u32) -> Result<u64, VmmError> {
        if amount_mib >= mem_size_mib {
            return Err(VmmError::InvalidConfig(format!(
                "balloon amount {amount_mib} MiB must be less than VM memory {mem_size_mib} MiB"
            )));
        }
        Ok(u64::from(mem_size_mib - amount_mib) * 1024 * 1024)
    }

    pub async fn set_balloon_impl(&self, id: Uuid, amount_mib: u32) -> Result<(), VmmError> {
        let (qmp_path, balloon, mem_size_mib) = {
            let instances = self.instances.lock().await;
            let inst = instances.get(&id).ok_or(VmmError::VmNotFound(id))?;
            (inst.qmp_path.clone(), inst.balloon, inst.info.mem_size_mib)
        };
        if !balloon {
            return Err(VmmError::InvalidConfig(
                "VM was created without a balloon device; rebuild with VmConfig.balloon = true"
                    .into(),
            ));
        }
        let value = Self::balloon_qmp_bytes(mem_size_mib, amount_mib)?;
        let mut qmp = crate::qmp::QmpClient::connect(&qmp_path).await?;
        qmp.execute("balloon", Some(serde_json::json!({ "value": value })))
            .await?;
        Ok(())
    }
}

/// `VmmBackend` impl is Linux-only: it needs `tokio-vsock` (host AF_VSOCK) to
/// reach the guest agent, and QEMU's `vhost-vsock-pci` device requires
/// `/dev/vhost-vsock`. The lifecycle methods delegate to the cross-platform
/// inherent methods above.
#[cfg(target_os = "linux")]
impl crate::VmmBackend for QemuKvmBackend {
    type VsockStream = tokio_vsock::VsockStream;

    fn backend_kind(&self) -> &'static str {
        "qemu"
    }

    async fn create_vm(&self, config: VmConfig) -> Result<CreatedVm, VmmError> {
        if !std::path::Path::new("/dev/kvm").exists() {
            return Err(VmmError::InvalidConfig(
                "/dev/kvm missing (KVM not available on this host)".into(),
            ));
        }
        if !std::path::Path::new("/dev/vhost-vsock").exists() {
            return Err(VmmError::InvalidConfig(
                "/dev/vhost-vsock missing (load the vhost_vsock kernel module)".into(),
            ));
        }
        self.create(config)
            .await
            .map(|info| CreatedVm::new(info, BackendKind::Qemu))
    }

    async fn stop_vm(&self, id: Uuid) -> Result<(), VmmError> {
        self.stop(id).await
    }

    async fn destroy_vm(&self, id: Uuid) -> Result<(), VmmError> {
        self.destroy(id).await
    }

    async fn vm_info(&self, id: Uuid) -> Result<VmInfo, VmmError> {
        self.info(id).await
    }

    async fn pause_vm(&self, id: Uuid) -> Result<(), VmmError> {
        self.pause(id).await
    }

    async fn resume_vm(&self, id: Uuid) -> Result<(), VmmError> {
        self.resume(id).await
    }

    // snapshot_vm / restore_vm use the VmmBackend trait's default `Unsupported`
    // bodies; the QEMU backend has no snapshot support.

    async fn vsock_connect(&self, id: Uuid, port: u32) -> Result<Self::VsockStream, VmmError> {
        let cid = {
            let instances = self.instances.lock().await;
            instances
                .get(&id)
                .ok_or(VmmError::VmNotFound(id))?
                .info
                .vsock_cid
        };
        tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(cid, port))
            .await
            .map_err(|e| {
                VmmError::ProcessError(format!("vsock connect cid={cid} port={port}: {e}"))
            })
    }

    async fn set_balloon(&self, id: Uuid, amount_mib: u32) -> Result<(), VmmError> {
        self.set_balloon_impl(id, amount_mib).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noop_cgroup() -> crate::cgroup::VmCgroup {
        crate::cgroup::CgroupSupervisor::disabled()
            .create_vm_cgroup(uuid::Uuid::nil(), 1, 128)
            .unwrap()
    }

    fn test_backend(
        bin: impl Into<std::path::PathBuf>,
        dir: impl Into<std::path::PathBuf>,
    ) -> QemuKvmBackend {
        QemuKvmBackend::new(
            bin,
            dir,
            std::sync::Arc::new(crate::cgroup::CgroupSupervisor::disabled()),
        )
    }

    fn sample_config() -> VmConfig {
        VmConfig {
            name: "qvm".into(),
            vcpu_count: 2,
            mem_size_mib: 1024,
            kernel_path: "/var/lib/husker/kernels/vmlinux".into(),
            rootfs_path: "/var/lib/husker/vms/qvm/rootfs.ext4".into(),
            kernel_args: Some(
                "console=ttyS0 ip=192.0.2.2::192.0.2.1:255.255.255.252::eth0:off".into(),
            ),
            initrd_path: None,
            vsock_cid: 7,
            tap_device: Some("husker7".into()),
            guest_mac: Some("52:54:00:00:00:07".into()),
            vmm: None,
            boot: crate::BootMode::DirectKernel,
            seed_path: None,
            balloon: false,
            volume_path: None,
            host_shares: Vec::new(),
        }
    }

    #[test]
    fn build_args_has_core_flags() {
        let be = test_backend("qemu-system-x86_64", "/tmp");
        let args = be.build_args(Uuid::nil(), &sample_config()).unwrap();
        for flag in [
            "-machine",
            "-nographic",
            "-nodefaults",
            "-enable-kvm",
            "-kernel",
            "-append",
        ] {
            assert!(args.iter().any(|a| a == flag), "missing {flag} in {args:?}");
        }
        let m = args.iter().position(|a| a == "-m").unwrap();
        assert_eq!(args[m + 1], "1024");
        let smp = args.iter().position(|a| a == "-smp").unwrap();
        assert_eq!(args[smp + 1], "2");
    }

    #[test]
    fn build_args_wires_vsock_cid() {
        let be = test_backend("qemu-system-x86_64", "/tmp");
        let args = be.build_args(Uuid::nil(), &sample_config()).unwrap();
        assert!(
            args.iter().any(|a| a == "vhost-vsock-pci,guest-cid=7"),
            "vsock device missing or wrong cid: {args:?}"
        );
    }

    #[test]
    fn build_args_attaches_raw_rootfs_and_root_device() {
        let be = test_backend("qemu-system-x86_64", "/tmp");
        let args = be.build_args(Uuid::nil(), &sample_config()).unwrap();
        assert!(
            args.iter()
                .any(|a| a.contains("format=raw") && a.contains("if=virtio")),
            "rootfs not attached raw/virtio: {args:?}"
        );
        let append = args
            .iter()
            .find(|a| a.contains("root=/dev/vda"))
            .expect("append root= missing");
        assert!(
            append.contains("console=ttyS0"),
            "append dropped kernel_args: {append}"
        );
    }

    #[test]
    fn build_args_includes_tap_when_present() {
        let be = test_backend("qemu-system-x86_64", "/tmp");
        let args = be.build_args(Uuid::nil(), &sample_config()).unwrap();
        assert!(
            args.iter().any(|a| a.contains("ifname=husker7")),
            "tap netdev missing: {args:?}"
        );
        assert!(
            args.iter().any(|a| a.contains("mac=52:54:00:00:00:07")),
            "mac missing: {args:?}"
        );
    }

    #[tokio::test]
    async fn duplicate_name_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let be = test_backend("qemu-system-x86_64", dir.path());
        let id = Uuid::new_v4();
        be.instances.lock().await.insert(
            id,
            QemuInstance {
                info: VmInfo {
                    id,
                    name: "dup".into(),
                    state: VmState::Running,
                    pid: Some(1),
                    vcpu_count: 1,
                    mem_size_mib: 128,
                    vsock_cid: 3,
                },
                qmp_path: dir.path().join("x.qmp"),
                pidfile_path: dir.path().join("x.pid"),
                serial_log_path: dir.path().join("x.serial.log"),
                boot_log_path: dir.path().join("x.boot.log"),
                process: tokio::process::Command::new("true").spawn().unwrap(),
                balloon: false,
                virtiofsds: vec![],
                virtiofsd_socks: vec![],
                cgroup: noop_cgroup(),
            },
        );
        let mut cfg = sample_config();
        cfg.name = "dup".into();
        let err = be.create(cfg).await.unwrap_err();
        assert!(matches!(err, VmmError::VmAlreadyExists(ref n) if n == "dup"));
    }

    #[tokio::test]
    async fn destroy_removes_runtime_files() {
        let dir = tempfile::tempdir().unwrap();
        let be = test_backend("qemu-system-x86_64", dir.path());
        let id = Uuid::new_v4();
        let qmp = dir.path().join("a.qmp");
        let pid = dir.path().join("a.pid");
        let serial = dir.path().join("a.serial.log");
        for p in [&qmp, &pid, &serial] {
            tokio::fs::write(p, b"").await.unwrap();
        }
        be.instances.lock().await.insert(
            id,
            QemuInstance {
                info: VmInfo {
                    id,
                    name: "x".into(),
                    state: VmState::Running,
                    pid: Some(1),
                    vcpu_count: 1,
                    mem_size_mib: 128,
                    vsock_cid: 3,
                },
                qmp_path: qmp.clone(),
                pidfile_path: pid.clone(),
                serial_log_path: serial.clone(),
                boot_log_path: dir.path().join("a.boot.log"),
                process: tokio::process::Command::new("true").spawn().unwrap(),
                balloon: false,
                virtiofsds: vec![],
                virtiofsd_socks: vec![],
                cgroup: noop_cgroup(),
            },
        );
        be.destroy(id).await.unwrap();
        assert!(!qmp.exists() && !pid.exists() && !serial.exists());
    }

    #[tokio::test]
    async fn info_detects_dead_process() {
        let dir = tempfile::tempdir().unwrap();
        let be = test_backend("qemu-system-x86_64", dir.path());
        let id = Uuid::new_v4();
        let process = tokio::process::Command::new("true").spawn().unwrap();
        be.instances.lock().await.insert(
            id,
            QemuInstance {
                info: VmInfo {
                    id,
                    name: "d".into(),
                    state: VmState::Running,
                    pid: process.id(),
                    vcpu_count: 1,
                    mem_size_mib: 128,
                    vsock_cid: 3,
                },
                qmp_path: dir.path().join("d.qmp"),
                pidfile_path: dir.path().join("d.pid"),
                serial_log_path: dir.path().join("d.serial.log"),
                boot_log_path: dir.path().join("d.boot.log"),
                process,
                balloon: false,
                virtiofsds: vec![],
                virtiofsd_socks: vec![],
                cgroup: noop_cgroup(),
            },
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let info = be.info(id).await.unwrap();
        assert_eq!(info.state, VmState::Stopped);
        assert!(info.pid.is_none());
    }

    #[tokio::test]
    async fn not_found_errors() {
        let dir = tempfile::tempdir().unwrap();
        let be = test_backend("qemu-system-x86_64", dir.path());
        let id = Uuid::new_v4();
        assert!(matches!(be.info(id).await, Err(VmmError::VmNotFound(_))));
        assert!(matches!(be.destroy(id).await, Err(VmmError::VmNotFound(_))));
        assert!(matches!(be.stop(id).await, Err(VmmError::VmNotFound(_))));
        assert!(matches!(be.pause(id).await, Err(VmmError::VmNotFound(_))));
        assert!(matches!(be.resume(id).await, Err(VmmError::VmNotFound(_))));
    }

    #[test]
    fn build_args_strips_pci_off_for_qemu() {
        let be = test_backend("qemu-system-x86_64", "/tmp");
        let mut cfg = sample_config();
        cfg.kernel_args = Some("console=ttyS0 reboot=k panic=1 pci=off ip=192.0.2.2::192.0.2.1:255.255.255.252::eth0:off".into());
        let args = be.build_args(Uuid::nil(), &cfg).unwrap();
        let append = args
            .iter()
            .find(|a| a.contains("root=/dev/vda"))
            .expect("append present");
        assert!(
            !append.contains("pci=off"),
            "pci=off must be stripped for QEMU: {append}"
        );
        assert!(
            append.contains("console=ttyS0"),
            "other args preserved: {append}"
        );
        assert!(append.contains("panic=1"), "other args preserved: {append}");
    }

    fn uefi_config() -> VmConfig {
        let mut cfg = sample_config();
        cfg.rootfs_path = "/var/lib/husker/vms/qvm/disk.qcow2".into();
        cfg.boot = crate::BootMode::Uefi {
            ovmf_code: "/usr/share/OVMF/OVMF_CODE_4M.fd".into(),
            ovmf_vars_template: "/usr/share/OVMF/OVMF_VARS_4M.fd".into(),
        };
        cfg
    }

    #[test]
    fn build_args_uefi_uses_pflash_and_qcow2_no_kernel() {
        let be = test_backend("qemu-system-x86_64", "/run/husker");
        let id = Uuid::nil();
        let args = be.build_args(id, &uefi_config()).unwrap();

        for flag in ["-kernel", "-initrd", "-append"] {
            assert!(
                !args.iter().any(|a| a == flag),
                "UEFI must not emit {flag}: {args:?}"
            );
        }
        assert!(
            args.iter().any(|a| a.contains("if=pflash")
                && a.contains("unit=0")
                && a.contains("readonly=on")
                && a.contains("OVMF_CODE_4M.fd")),
            "missing read-only CODE pflash: {args:?}"
        );
        let vars_copy = be.ovmf_vars_copy(id);
        assert!(
            args.iter().any(|a| a.contains("if=pflash")
                && a.contains("unit=1")
                && a.contains(&vars_copy.display().to_string())),
            "missing per-VM VARS pflash: {args:?}"
        );
        assert!(
            args.iter().any(|a| a.contains("disk.qcow2")
                && a.contains("format=qcow2")
                && a.contains("if=virtio")),
            "missing qcow2 virtio disk: {args:?}"
        );
        assert!(
            args.iter().any(|a| a == "vhost-vsock-pci,guest-cid=7"),
            "vsock missing: {args:?}"
        );
    }

    #[test]
    fn build_args_direct_kernel_still_has_kernel_and_raw_rootfs() {
        let be = test_backend("qemu-system-x86_64", "/tmp");
        let args = be.build_args(Uuid::nil(), &sample_config()).unwrap();
        assert!(
            args.iter().any(|a| a == "-kernel"),
            "direct boot must keep -kernel"
        );
        assert!(
            args.iter()
                .any(|a| a.contains("format=raw") && a.contains("if=virtio"))
        );
        assert!(
            !args.iter().any(|a| a.contains("if=pflash")),
            "direct boot must not emit pflash"
        );
    }

    #[test]
    fn build_args_uefi_attaches_seed_when_present() {
        let be = test_backend("qemu-system-x86_64", "/run/husker");
        let mut cfg = uefi_config();
        cfg.seed_path = Some("/var/lib/husker/vms/qvm/seed.img".into());
        let args = be.build_args(Uuid::nil(), &cfg).unwrap();
        assert!(
            args.iter().any(|a| a.contains("seed.img")
                && a.contains("format=raw")
                && a.contains("if=virtio")),
            "seed disk not attached: {args:?}"
        );
    }

    #[test]
    fn build_args_uefi_omits_seed_when_absent() {
        let be = test_backend("qemu-system-x86_64", "/run/husker");
        let args = be.build_args(Uuid::nil(), &uefi_config()).unwrap(); // seed_path None
        assert!(
            !args.iter().any(|a| a.contains("seed.img")),
            "unexpected seed: {args:?}"
        );
    }

    #[tokio::test]
    async fn destroy_removes_ovmf_vars_copy() {
        let dir = tempfile::tempdir().unwrap();
        let be = test_backend("qemu-system-x86_64", dir.path());
        let id = Uuid::new_v4();
        // Simulate a booted UEFI VM: a VARS copy exists in the runtime dir.
        let vars = be.ovmf_vars_copy(id);
        tokio::fs::write(&vars, b"VARS").await.unwrap();
        be.instances.lock().await.insert(
            id,
            QemuInstance {
                info: VmInfo {
                    id,
                    name: "u".into(),
                    state: VmState::Running,
                    pid: Some(1),
                    vcpu_count: 1,
                    mem_size_mib: 128,
                    vsock_cid: 3,
                },
                qmp_path: dir.path().join("u.qmp"),
                pidfile_path: dir.path().join("u.pid"),
                serial_log_path: dir.path().join("u.serial.log"),
                boot_log_path: dir.path().join("u.boot.log"),
                process: tokio::process::Command::new("true").spawn().unwrap(),
                balloon: false,
                virtiofsds: vec![],
                virtiofsd_socks: vec![],
                cgroup: noop_cgroup(),
            },
        );
        be.destroy(id).await.unwrap();
        assert!(
            !vars.exists(),
            "destroy must remove the per-VM OVMF VARS copy"
        );
    }

    // ── balloon_qmp_bytes math ────────────────────────────────────────────

    #[test]
    fn balloon_qmp_bytes_normal_case() {
        // 64 MiB reclaimed from a 512 MiB VM -> guest target = 448 MiB in bytes.
        let bytes = QemuKvmBackend::balloon_qmp_bytes(512, 64).unwrap();
        assert_eq!(bytes, 448 * 1024 * 1024);
    }

    #[test]
    fn balloon_qmp_bytes_zero_reclaim_returns_full_memory() {
        // Reclaiming 0 MiB leaves all memory to the guest.
        let bytes = QemuKvmBackend::balloon_qmp_bytes(256, 0).unwrap();
        assert_eq!(bytes, 256 * 1024 * 1024);
    }

    #[test]
    fn balloon_qmp_bytes_equal_to_mem_is_rejected() {
        // amount == mem_size is invalid (would leave guest with 0 bytes).
        let err = QemuKvmBackend::balloon_qmp_bytes(512, 512).unwrap_err();
        assert!(
            matches!(err, VmmError::InvalidConfig(ref msg) if msg.contains("512")),
            "expected InvalidConfig with size info, got: {err}"
        );
    }

    #[test]
    fn balloon_qmp_bytes_exceeding_mem_is_rejected() {
        let err = QemuKvmBackend::balloon_qmp_bytes(512, 600).unwrap_err();
        assert!(
            matches!(err, VmmError::InvalidConfig(_)),
            "expected InvalidConfig, got: {err}"
        );
    }

    // ── build_args balloon flag ───────────────────────────────────────────

    #[test]
    fn build_args_includes_balloon_device_when_enabled() {
        let be = test_backend("qemu-system-x86_64", "/tmp");
        let mut cfg = sample_config();
        cfg.balloon = true;
        let args = be.build_args(Uuid::nil(), &cfg).unwrap();
        assert!(
            args.iter().any(|a| a == "virtio-balloon-pci"),
            "balloon device missing: {args:?}"
        );
    }

    #[test]
    fn build_args_omits_balloon_device_by_default() {
        let be = test_backend("qemu-system-x86_64", "/tmp");
        let args = be.build_args(Uuid::nil(), &sample_config()).unwrap();
        assert!(
            !args.iter().any(|a| a == "virtio-balloon-pci"),
            "balloon device present when not requested: {args:?}"
        );
    }

    #[test]
    fn build_args_uefi_includes_balloon_device_when_enabled() {
        let be = test_backend("qemu-system-x86_64", "/run/husker");
        let mut cfg = uefi_config();
        cfg.balloon = true;
        let args = be.build_args(Uuid::nil(), &cfg).unwrap();
        assert!(
            args.iter().any(|a| a == "virtio-balloon-pci"),
            "balloon device missing in UEFI boot: {args:?}"
        );
    }

    // ── set_balloon_impl early error ──────────────────────────────────────

    #[tokio::test]
    async fn set_balloon_without_device_is_invalid_config() {
        let dir = tempfile::tempdir().unwrap();
        let be = test_backend("qemu-system-x86_64", dir.path());
        let id = Uuid::new_v4();
        be.instances.lock().await.insert(
            id,
            QemuInstance {
                info: VmInfo {
                    id,
                    name: "nb".into(),
                    state: VmState::Running,
                    pid: Some(1),
                    vcpu_count: 1,
                    mem_size_mib: 512,
                    vsock_cid: 3,
                },
                qmp_path: dir.path().join("nb.qmp"),
                pidfile_path: dir.path().join("nb.pid"),
                serial_log_path: dir.path().join("nb.serial.log"),
                boot_log_path: dir.path().join("nb.boot.log"),
                process: tokio::process::Command::new("true").spawn().unwrap(),
                balloon: false,
                virtiofsds: vec![],
                virtiofsd_socks: vec![],
                cgroup: noop_cgroup(),
            },
        );
        let err = be.set_balloon_impl(id, 64).await.unwrap_err();
        assert!(
            matches!(err, VmmError::InvalidConfig(ref msg) if msg.contains("balloon")),
            "expected InvalidConfig mentioning balloon, got: {err}"
        );
    }

    // ── volume drive ordering ─────────────────────────────────────────────

    /// In UEFI/cloud-image mode with a volume and a seed: the boot-disk -drive
    /// must come first, then the volume -drive, then the seed -drive.
    /// This pins the guest device assignment: vda=boot-disk, vdb=volume,
    /// vdc=seed (NoCloud reads the seed by filesystem label so position is free).
    #[test]
    fn build_args_uefi_volume_ordering_disk_then_volume_then_seed() {
        let be = test_backend("qemu-system-x86_64", "/run/husker");
        let mut cfg = uefi_config();
        cfg.volume_path = Some("/var/lib/husker/volumes/data.img".into());
        cfg.seed_path = Some("/var/lib/husker/vms/qvm/seed.img".into());
        let args = be.build_args(Uuid::nil(), &cfg).unwrap();

        // Collect the values that follow each `-drive` flag.
        let drives: Vec<&str> = args
            .windows(2)
            .filter_map(|w| (w[0] == "-drive").then_some(w[1].as_str()))
            .collect();

        // Skip pflash entries (firmware drives); only virtio/virtio drives count.
        let virtio: Vec<&str> = drives
            .iter()
            .copied()
            .filter(|d| d.contains("if=virtio"))
            .collect();

        assert!(
            virtio.len() >= 3,
            "expected at least 3 virtio drives (disk, volume, seed), got: {virtio:?}"
        );
        let disk_idx = virtio
            .iter()
            .position(|d| d.contains("disk.qcow2"))
            .expect("boot disk drive missing");
        let volume_idx = virtio
            .iter()
            .position(|d| d.contains("data.img"))
            .expect("volume drive missing");
        let seed_idx = virtio
            .iter()
            .position(|d| d.contains("seed.img"))
            .expect("seed drive missing");
        assert!(
            disk_idx < volume_idx,
            "boot disk must precede volume: disk={disk_idx} volume={volume_idx} in {virtio:?}"
        );
        assert!(
            volume_idx < seed_idx,
            "volume must precede seed: volume={volume_idx} seed={seed_idx} in {virtio:?}"
        );
    }

    /// In direct-kernel mode with a volume: the rootfs -drive must come before
    /// the volume -drive so the guest sees vda=rootfs, vdb=volume.
    #[test]
    fn build_args_direct_volume_ordering_rootfs_then_volume() {
        let be = test_backend("qemu-system-x86_64", "/tmp");
        let mut cfg = sample_config();
        cfg.volume_path = Some("/var/lib/husker/volumes/data.img".into());
        let args = be.build_args(Uuid::nil(), &cfg).unwrap();

        let drives: Vec<&str> = args
            .windows(2)
            .filter_map(|w| (w[0] == "-drive").then_some(w[1].as_str()))
            .collect();
        let virtio: Vec<&str> = drives
            .iter()
            .copied()
            .filter(|d| d.contains("if=virtio"))
            .collect();

        assert!(
            virtio.len() >= 2,
            "expected at least 2 virtio drives (rootfs, volume), got: {virtio:?}"
        );
        let rootfs_idx = virtio
            .iter()
            .position(|d| d.contains("rootfs.ext4"))
            .expect("rootfs drive missing");
        let volume_idx = virtio
            .iter()
            .position(|d| d.contains("data.img"))
            .expect("volume drive missing");
        assert!(
            rootfs_idx < volume_idx,
            "rootfs must precede volume: rootfs={rootfs_idx} volume={volume_idx} in {virtio:?}"
        );
    }

    /// When no volume is set, the volume -drive is absent in both boot modes.
    #[test]
    fn build_args_no_volume_drive_when_absent() {
        let be = test_backend("qemu-system-x86_64", "/run/husker");
        // Direct-kernel, no volume
        let args_direct = be.build_args(Uuid::nil(), &sample_config()).unwrap();
        assert!(
            !args_direct.iter().any(|a| a.contains("data.img")),
            "unexpected volume drive in direct-kernel args: {args_direct:?}"
        );
        // UEFI, no volume
        let args_uefi = be.build_args(Uuid::nil(), &uefi_config()).unwrap();
        assert!(
            !args_uefi.iter().any(|a| a.contains("data.img")),
            "unexpected volume drive in uefi args: {args_uefi:?}"
        );
    }

    #[test]
    fn build_args_efi_returns_invalid_config_error() {
        let be = test_backend("qemu-system-x86_64", "/tmp");
        let mut cfg = sample_config();
        cfg.boot = crate::BootMode::Efi {
            variable_store: "/tmp/nvram.bin".into(),
        };
        let err = be.build_args(Uuid::nil(), &cfg).unwrap_err();
        assert!(
            matches!(err, VmmError::InvalidConfig(ref msg) if msg.contains("Efi") && msg.contains("QEMU")),
            "expected InvalidConfig mentioning Efi and QEMU, got: {err}"
        );
    }

    // ── shared memory backend (virtiofs prerequisite) ─────────────────────

    #[test]
    fn qemu_uses_shared_memory_backend_when_shares_present() {
        let be = test_backend("qemu-system-x86_64", "/tmp");
        let mut cfg = sample_config();
        cfg.mem_size_mib = 2048;
        cfg.host_shares = vec![crate::HostShare {
            host: "/srv/work".into(),
            guest: "/work".into(),
            read_only: false,
            tag: "fs0".into(),
        }];
        let args = be.build_args(Uuid::nil(), &cfg).unwrap();
        let joined = args.join(" ");
        assert!(
            joined.contains("memory-backend-memfd,id=mem0,size=2048M,share=on"),
            "{joined}"
        );
        assert!(
            !args.iter().any(|a| a == "-m"),
            "plain -m must be absent with shares: {joined}"
        );
        assert!(
            joined.contains("q35,memory-backend=mem0")
                || joined.contains("virt,memory-backend=mem0"),
            "machine must have memory-backend attached: {joined}"
        );
    }

    #[test]
    fn qemu_uses_plain_memory_without_shares() {
        let be = test_backend("qemu-system-x86_64", "/tmp");
        let mut cfg = sample_config();
        cfg.mem_size_mib = 512;
        let args = be.build_args(Uuid::nil(), &cfg).unwrap();
        let i = args.iter().position(|a| a == "-m").expect("-m present");
        assert_eq!(args[i + 1], "512");
        assert!(!args.join(" ").contains("memory-backend-memfd"));
    }

    // ── virtiofs device args ──────────────────────────────────────────────

    #[test]
    fn qemu_emits_vhost_user_fs_device_per_share() {
        let be = test_backend("qemu-system-x86_64", "/tmp");
        let mut cfg = sample_config();
        cfg.host_shares = vec![
            crate::HostShare {
                host: "/srv/a".into(),
                guest: "/a".into(),
                read_only: false,
                tag: "fs0".into(),
            },
            crate::HostShare {
                host: "/srv/b".into(),
                guest: "/b".into(),
                read_only: true,
                tag: "fs1".into(),
            },
        ];
        let args = be.build_args(Uuid::nil(), &cfg).unwrap();
        let j = args.join(" ");
        assert!(
            j.contains("vhost-user-fs-pci,chardev=fs0,tag=fs0"),
            "missing fs0 device: {j}"
        );
        assert!(
            j.contains("vhost-user-fs-pci,chardev=fs1,tag=fs1"),
            "missing fs1 device: {j}"
        );
        assert!(j.contains("socket,id=fs0"), "missing fs0 chardev: {j}");
        assert!(j.contains("socket,id=fs1"), "missing fs1 chardev: {j}");
        // No shares -> no vhost-user-fs args (regression guard).
        let args_no_shares = be.build_args(Uuid::nil(), &sample_config()).unwrap();
        assert!(
            !args_no_shares.iter().any(|a| a.contains("vhost-user-fs")),
            "vhost-user-fs must be absent without shares: {args_no_shares:?}"
        );
    }
}
