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

use crate::{VmConfig, VmInfo, VmState, VmmBackend, VmmError};

/// Tracks a running Firecracker VM instance.
struct FcInstance {
    info: VmInfo,
    socket_path: PathBuf,
    vsock_path: PathBuf,
    boot_log_path: PathBuf,
    serial_log_path: PathBuf,
    process: tokio::process::Child,
}

/// Firecracker VMM backend.
///
/// Communicates with each Firecracker process via its HTTP-over-Unix-socket API.
pub struct FirecrackerBackend {
    firecracker_bin: PathBuf,
    runtime_dir: PathBuf,
    instances: Arc<Mutex<HashMap<Uuid, FcInstance>>>,
}

impl FirecrackerBackend {
    pub fn new(firecracker_bin: impl Into<PathBuf>, runtime_dir: impl Into<PathBuf>) -> Self {
        Self {
            firecracker_bin: firecracker_bin.into(),
            runtime_dir: runtime_dir.into(),
            instances: Arc::new(Mutex::new(HashMap::new())),
        }
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

    fn path_to_str<'a>(path: &'a Path, label: &str) -> Result<&'a str, VmmError> {
        path.to_str()
            .ok_or_else(|| VmmError::InvalidConfig(format!("{label} is not valid UTF-8")))
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
        let kernel_args = config.kernel_args.clone().unwrap_or_else(|| {
            "console=ttyS0 reboot=k panic=1 pci=off \
             ip=172.20.0.2::172.20.0.1:255.255.255.252::eth0:off"
                .to_string()
        });

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
        };

        self.instances.lock().await.insert(id, instance);

        Ok(info)
    }
}

impl VmmBackend for FirecrackerBackend {
    type VsockStream = tokio::net::UnixStream;

    async fn create_vm(&self, config: VmConfig) -> Result<VmInfo, VmmError> {
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
                crate::append_log_tails(
                    &mut msg,
                    serial_tail,
                    boot_tail,
                    "firecracker boot log",
                );
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

        Self::fc_put(
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

        Self::fc_put(
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
        };
        backend.instances.lock().await.insert(id, instance);

        // Give the process time to exit
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let info = backend.vm_info(id).await.unwrap();
        assert_eq!(info.state, VmState::Stopped);
        assert!(info.pid.is_none());
    }
}
