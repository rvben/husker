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

use crate::{VmConfig, VmInfo, VmState, VmmError};

/// A running QEMU VM tracked by the backend.
pub(crate) struct QemuInstance {
    pub(crate) info: VmInfo,
    pub(crate) qmp_path: PathBuf,
    pub(crate) pidfile_path: PathBuf,
    pub(crate) serial_log_path: PathBuf,
    pub(crate) boot_log_path: PathBuf,
    pub(crate) process: tokio::process::Child,
}

/// QEMU/KVM VMM backend. One `qemu-system` child process per VM.
pub struct QemuKvmBackend {
    pub(crate) binary: PathBuf,
    pub(crate) runtime_dir: PathBuf,
    pub(crate) instances: Arc<Mutex<HashMap<Uuid, QemuInstance>>>,
}

impl QemuKvmBackend {
    pub fn new(binary: impl Into<PathBuf>, runtime_dir: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            runtime_dir: runtime_dir.into(),
            instances: Arc::new(Mutex::new(HashMap::new())),
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

    /// Build the full `qemu-system-*` argument vector. Pure function of
    /// (id, config, runtime paths) so it is unit-testable without spawning QEMU.
    pub fn build_args(&self, id: Uuid, config: &VmConfig) -> Vec<String> {
        #[cfg(target_arch = "aarch64")]
        let machine = "virt";
        #[cfg(not(target_arch = "aarch64"))]
        let machine = "q35";

        let mut args: Vec<String> = vec![
            "-machine".into(),
            machine.into(),
            "-m".into(),
            config.mem_size_mib.to_string(),
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
            // Root disk: husker clones a RAW ext4 rootfs (not qcow2).
            "-drive".into(),
            format!(
                "file={},format=raw,if=virtio,cache=writeback",
                config.rootfs_path.display()
            ),
        ];

        // Direct kernel boot. husker's kernel_args carry console + static ip=;
        // QEMU additionally needs the root device for the virtio disk.
        #[cfg(target_arch = "aarch64")]
        let default_console = "console=ttyAMA0";
        #[cfg(not(target_arch = "aarch64"))]
        let default_console = "console=ttyS0";
        let base_args = config
            .kernel_args
            .clone()
            .unwrap_or_else(|| default_console.to_string());
        // QEMU q35 carries every virtio device (vsock/net/rng) on the PCIe bus.
        // husker-core adds `pci=off` for Firecracker's PCI-less microVM machine;
        // leaving it in would stop the QEMU guest from enumerating those devices
        // (no network, no vsock, no agent). Strip it for QEMU.
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

        args
    }

    /// Spawn a QEMU process and track it. (`VmmBackend::create_vm` delegates here.)
    pub async fn create(&self, config: VmConfig) -> Result<VmInfo, VmmError> {
        {
            let instances = self.instances.lock().await;
            if instances.values().any(|i| i.info.name == config.name) {
                return Err(VmmError::VmAlreadyExists(config.name));
            }
        }
        tokio::fs::create_dir_all(&self.runtime_dir).await?;

        let id = Uuid::new_v4();
        let args = self.build_args(id, &config);

        // Detach QEMU's own stdio. `-nographic` otherwise binds the monitor/serial
        // to the inherited stdio, which hangs whatever launched the daemon (e.g. a
        // controlling terminal). stdin is null; QEMU's own stdout/stderr (startup
        // and device errors, distinct from the guest serial console which `-serial
        // file:` captures) go to a per-VM log for diagnostics.
        let boot_log_path = self.boot_log(id);
        let log_out = std::fs::File::create(&boot_log_path)
            .map_err(|e| VmmError::ProcessError(format!("create qemu log: {e}")))?;
        let log_err = log_out
            .try_clone()
            .map_err(|e| VmmError::ProcessError(format!("clone qemu log handle: {e}")))?;

        let process = tokio::process::Command::new(&self.binary)
            .args(&args)
            .stdin(std::process::Stdio::null())
            .stdout(log_out)
            .stderr(log_err)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| VmmError::ProcessError(format!("spawn qemu: {e}")))?;
        let pid = process.id();

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
            // `process` drops here (kill_on_drop) -> QEMU killed.
            let _ = std::fs::remove_file(self.qmp_socket(id));
            let _ = std::fs::remove_file(self.pidfile(id));
            let _ = std::fs::remove_file(self.serial_log(id));
            let _ = std::fs::remove_file(&boot_log_path);
            let mut msg = String::from("QMP socket did not appear within 5s");
            if let Some(s) = serial_tail {
                msg.push_str(&format!("\n--- guest serial (tail) ---\n{s}"));
            }
            if let Some(b) = boot_tail {
                msg.push_str(&format!("\n--- qemu boot log (tail) ---\n{b}"));
            }
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
            },
        );
        Ok(info)
    }

    /// Best-effort, asynchronous shutdown: sends an ACPI powerdown event and marks
    /// the VM `Stopped`, but the QEMU process may still be winding down. Callers
    /// must not assume the process has exited (mirrors the Firecracker backend).
    pub async fn stop(&self, id: Uuid) -> Result<(), VmmError> {
        let qmp_path = {
            let instances = self.instances.lock().await;
            instances.get(&id).ok_or(VmmError::VmNotFound(id))?.qmp_path.clone()
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
        let _ = inst.process.kill().await;
        let _ = tokio::fs::remove_file(&inst.qmp_path).await;
        let _ = tokio::fs::remove_file(&inst.pidfile_path).await;
        let _ = tokio::fs::remove_file(&inst.serial_log_path).await;
        let _ = tokio::fs::remove_file(&inst.boot_log_path).await;
        Ok(())
    }

    pub async fn info(&self, id: Uuid) -> Result<VmInfo, VmmError> {
        let mut instances = self.instances.lock().await;
        let inst = instances.get_mut(&id).ok_or(VmmError::VmNotFound(id))?;
        if inst.info.state == VmState::Running || inst.info.state == VmState::Paused {
            match inst.process.try_wait() {
                Ok(Some(_)) => {
                    inst.info.state = VmState::Stopped;
                    inst.info.pid = None;
                }
                Ok(None) => {}
                Err(_) => {
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
            instances.get(&id).ok_or(VmmError::VmNotFound(id))?.qmp_path.clone()
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
            instances.get(&id).ok_or(VmmError::VmNotFound(id))?.qmp_path.clone()
        };
        let mut qmp = crate::qmp::QmpClient::connect(&qmp_path).await?;
        qmp.resume().await?;
        let mut instances = self.instances.lock().await;
        if let Some(inst) = instances.get_mut(&id) {
            inst.info.state = VmState::Running;
        }
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

    async fn create_vm(&self, config: VmConfig) -> Result<VmInfo, VmmError> {
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
        self.create(config).await
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

    async fn vsock_connect(&self, id: Uuid, port: u32) -> Result<Self::VsockStream, VmmError> {
        let cid = {
            let instances = self.instances.lock().await;
            instances.get(&id).ok_or(VmmError::VmNotFound(id))?.info.vsock_cid
        };
        tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(cid, port))
            .await
            .map_err(|e| {
                VmmError::ProcessError(format!("vsock connect cid={cid} port={port}: {e}"))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        }
    }

    #[test]
    fn build_args_has_core_flags() {
        let be = QemuKvmBackend::new("qemu-system-x86_64", "/tmp");
        let args = be.build_args(Uuid::nil(), &sample_config());
        for flag in ["-machine", "-nographic", "-nodefaults", "-enable-kvm", "-kernel", "-append"] {
            assert!(args.iter().any(|a| a == flag), "missing {flag} in {args:?}");
        }
        let m = args.iter().position(|a| a == "-m").unwrap();
        assert_eq!(args[m + 1], "1024");
        let smp = args.iter().position(|a| a == "-smp").unwrap();
        assert_eq!(args[smp + 1], "2");
    }

    #[test]
    fn build_args_wires_vsock_cid() {
        let be = QemuKvmBackend::new("qemu-system-x86_64", "/tmp");
        let args = be.build_args(Uuid::nil(), &sample_config());
        assert!(
            args.iter().any(|a| a == "vhost-vsock-pci,guest-cid=7"),
            "vsock device missing or wrong cid: {args:?}"
        );
    }

    #[test]
    fn build_args_attaches_raw_rootfs_and_root_device() {
        let be = QemuKvmBackend::new("qemu-system-x86_64", "/tmp");
        let args = be.build_args(Uuid::nil(), &sample_config());
        assert!(
            args.iter().any(|a| a.contains("format=raw") && a.contains("if=virtio")),
            "rootfs not attached raw/virtio: {args:?}"
        );
        let append = args.iter().find(|a| a.contains("root=/dev/vda")).expect("append root= missing");
        assert!(append.contains("console=ttyS0"), "append dropped kernel_args: {append}");
    }

    #[test]
    fn build_args_includes_tap_when_present() {
        let be = QemuKvmBackend::new("qemu-system-x86_64", "/tmp");
        let args = be.build_args(Uuid::nil(), &sample_config());
        assert!(args.iter().any(|a| a.contains("ifname=husker7")), "tap netdev missing: {args:?}");
        assert!(args.iter().any(|a| a.contains("mac=52:54:00:00:00:07")), "mac missing: {args:?}");
    }

    #[tokio::test]
    async fn duplicate_name_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let be = QemuKvmBackend::new("qemu-system-x86_64", dir.path());
        let id = Uuid::new_v4();
        be.instances.lock().await.insert(id, QemuInstance {
            info: VmInfo { id, name: "dup".into(), state: VmState::Running, pid: Some(1),
                           vcpu_count: 1, mem_size_mib: 128, vsock_cid: 3 },
            qmp_path: dir.path().join("x.qmp"),
            pidfile_path: dir.path().join("x.pid"),
            serial_log_path: dir.path().join("x.serial.log"),
            boot_log_path: dir.path().join("x.boot.log"),
            process: tokio::process::Command::new("true").spawn().unwrap(),
        });
        let mut cfg = sample_config();
        cfg.name = "dup".into();
        let err = be.create(cfg).await.unwrap_err();
        assert!(matches!(err, VmmError::VmAlreadyExists(ref n) if n == "dup"));
    }

    #[tokio::test]
    async fn destroy_removes_runtime_files() {
        let dir = tempfile::tempdir().unwrap();
        let be = QemuKvmBackend::new("qemu-system-x86_64", dir.path());
        let id = Uuid::new_v4();
        let qmp = dir.path().join("a.qmp");
        let pid = dir.path().join("a.pid");
        let serial = dir.path().join("a.serial.log");
        for p in [&qmp, &pid, &serial] {
            tokio::fs::write(p, b"").await.unwrap();
        }
        be.instances.lock().await.insert(id, QemuInstance {
            info: VmInfo { id, name: "x".into(), state: VmState::Running, pid: Some(1),
                           vcpu_count: 1, mem_size_mib: 128, vsock_cid: 3 },
            qmp_path: qmp.clone(), pidfile_path: pid.clone(), serial_log_path: serial.clone(),
            boot_log_path: dir.path().join("a.boot.log"),
            process: tokio::process::Command::new("true").spawn().unwrap(),
        });
        be.destroy(id).await.unwrap();
        assert!(!qmp.exists() && !pid.exists() && !serial.exists());
    }

    #[tokio::test]
    async fn info_detects_dead_process() {
        let dir = tempfile::tempdir().unwrap();
        let be = QemuKvmBackend::new("qemu-system-x86_64", dir.path());
        let id = Uuid::new_v4();
        let process = tokio::process::Command::new("true").spawn().unwrap();
        be.instances.lock().await.insert(id, QemuInstance {
            info: VmInfo { id, name: "d".into(), state: VmState::Running, pid: process.id(),
                           vcpu_count: 1, mem_size_mib: 128, vsock_cid: 3 },
            qmp_path: dir.path().join("d.qmp"),
            pidfile_path: dir.path().join("d.pid"),
            serial_log_path: dir.path().join("d.serial.log"),
            boot_log_path: dir.path().join("d.boot.log"),
            process,
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let info = be.info(id).await.unwrap();
        assert_eq!(info.state, VmState::Stopped);
        assert!(info.pid.is_none());
    }

    #[tokio::test]
    async fn not_found_errors() {
        let dir = tempfile::tempdir().unwrap();
        let be = QemuKvmBackend::new("qemu-system-x86_64", dir.path());
        let id = Uuid::new_v4();
        assert!(matches!(be.info(id).await, Err(VmmError::VmNotFound(_))));
        assert!(matches!(be.destroy(id).await, Err(VmmError::VmNotFound(_))));
        assert!(matches!(be.stop(id).await, Err(VmmError::VmNotFound(_))));
        assert!(matches!(be.pause(id).await, Err(VmmError::VmNotFound(_))));
        assert!(matches!(be.resume(id).await, Err(VmmError::VmNotFound(_))));
    }

    #[test]
    fn build_args_strips_pci_off_for_qemu() {
        let be = QemuKvmBackend::new("qemu-system-x86_64", "/tmp");
        let mut cfg = sample_config();
        cfg.kernel_args = Some("console=ttyS0 reboot=k panic=1 pci=off ip=192.0.2.2::192.0.2.1:255.255.255.252::eth0:off".into());
        let args = be.build_args(Uuid::nil(), &cfg);
        let append = args.iter().find(|a| a.contains("root=/dev/vda")).expect("append present");
        assert!(!append.contains("pci=off"), "pci=off must be stripped for QEMU: {append}");
        assert!(append.contains("console=ttyS0"), "other args preserved: {append}");
        assert!(append.contains("panic=1"), "other args preserved: {append}");
    }
}
