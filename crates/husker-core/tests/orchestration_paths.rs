use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use chrono::Utc;
use husker_core::{
    CoreError, CreateHostGroupRequest, CreateSecretRequest, CreateServiceRequest,
    CreateSnapshotRequest, CreateVmRequest, ExportImageRequest, HuskerCore, ImportImageRequest,
    RestoreSnapshotRequest, RotateSecretRequest,
};
#[cfg(feature = "linux-net")]
use husker_state::PortForwardRecord;
use husker_state::{StateStore, VmRecord};
use husker_storage::StorageConfig;
use husker_vmm::{
    RestoreTarget, SnapshotMeta, SnapshotPaths, VmConfig, VmInfo, VmState, VmmBackend, VmmError,
};
use tokio::sync::{Mutex, Notify};
use uuid::Uuid;

/// Serializes the `run_userdata` tests, which drive the real guest agent on the
/// host and so share the host path `/tmp/husker-userdata.sh`. This in-process
/// mutex only covers `cargo test` (tests as threads in one process). Under
/// nextest each test runs in its own process, so the `husker-userdata-serial`
/// test-group in `.config/nextest.toml` provides the cross-process serialization.
fn userdata_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

struct MockInner {
    vms: Mutex<HashMap<Uuid, VmInfo>>,
    stop_failures: Mutex<HashSet<Uuid>>,
    stop_calls: Mutex<Vec<Uuid>>,
    #[cfg(not(feature = "linux-net"))]
    destroy_gate: Mutex<Option<Arc<DestroyGate>>>,
    pause_gate: Mutex<Option<Arc<PauseGate>>>,
    agent_socket: Mutex<Option<PathBuf>>,
    // Only needed by the kernel_args_composition tests (not(linux-net) builds).
    #[cfg(not(feature = "linux-net"))]
    last_config: Mutex<Option<VmConfig>>,
}

#[cfg(not(feature = "linux-net"))]
#[derive(Default)]
struct DestroyGate {
    entered: Notify,
    release: Notify,
}

#[derive(Default)]
struct PauseGate {
    entered: Notify,
    release: Notify,
}

#[derive(Clone)]
struct MockVmm {
    inner: Arc<MockInner>,
}

impl MockVmm {
    fn new() -> Self {
        Self {
            inner: Arc::new(MockInner {
                vms: Mutex::new(HashMap::new()),
                stop_failures: Mutex::new(HashSet::new()),
                stop_calls: Mutex::new(Vec::new()),
                #[cfg(not(feature = "linux-net"))]
                destroy_gate: Mutex::new(None),
                pause_gate: Mutex::new(None),
                agent_socket: Mutex::new(None),
                #[cfg(not(feature = "linux-net"))]
                last_config: Mutex::new(None),
            }),
        }
    }

    async fn set_agent_socket(&self, socket_path: Option<PathBuf>) {
        *self.inner.agent_socket.lock().await = socket_path;
    }

    async fn upsert_vm(&self, info: VmInfo) {
        self.inner.vms.lock().await.insert(info.id, info);
    }

    async fn mark_stop_failure(&self, id: Uuid) {
        self.inner.stop_failures.lock().await.insert(id);
    }

    async fn stop_call_count(&self) -> usize {
        self.inner.stop_calls.lock().await.len()
    }

    #[cfg(not(feature = "linux-net"))]
    async fn block_next_destroy(&self) -> Arc<DestroyGate> {
        let gate = Arc::new(DestroyGate::default());
        *self.inner.destroy_gate.lock().await = Some(Arc::clone(&gate));
        gate
    }

    async fn block_next_pause(&self) -> Arc<PauseGate> {
        let gate = Arc::new(PauseGate::default());
        *self.inner.pause_gate.lock().await = Some(Arc::clone(&gate));
        gate
    }

    #[cfg(not(feature = "linux-net"))]
    async fn last_config(&self) -> Option<VmConfig> {
        self.inner.last_config.lock().await.clone()
    }
}

impl VmmBackend for MockVmm {
    type VsockStream = tokio::net::UnixStream;

    async fn create_vm(&self, config: VmConfig) -> Result<VmInfo, VmmError> {
        let id = Uuid::new_v4();
        let info = VmInfo {
            id,
            name: config.name.clone(),
            state: VmState::Running,
            pid: Some(9999),
            vcpu_count: config.vcpu_count,
            mem_size_mib: config.mem_size_mib,
            vsock_cid: config.vsock_cid,
        };
        #[cfg(not(feature = "linux-net"))]
        {
            *self.inner.last_config.lock().await = Some(config);
        }
        // linux-net builds capture nothing; consume config to avoid an unused-variable warning.
        #[cfg(feature = "linux-net")]
        let _ = config;
        self.upsert_vm(info.clone()).await;
        Ok(info)
    }

    async fn stop_vm(&self, id: Uuid) -> Result<(), VmmError> {
        self.inner.stop_calls.lock().await.push(id);
        if self.inner.stop_failures.lock().await.contains(&id) {
            return Err(VmmError::ProcessError("injected stop failure".into()));
        }
        let mut vms = self.inner.vms.lock().await;
        match vms.get_mut(&id) {
            Some(vm) => {
                vm.state = VmState::Stopped;
                Ok(())
            }
            None => Err(VmmError::VmNotFound(id)),
        }
    }

    async fn destroy_vm(&self, id: Uuid) -> Result<(), VmmError> {
        #[cfg(not(feature = "linux-net"))]
        if let Some(gate) = self.inner.destroy_gate.lock().await.take() {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        self.inner.vms.lock().await.remove(&id);
        Ok(())
    }

    async fn vm_info(&self, id: Uuid) -> Result<VmInfo, VmmError> {
        self.inner
            .vms
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or(VmmError::VmNotFound(id))
    }

    async fn pause_vm(&self, id: Uuid) -> Result<(), VmmError> {
        if let Some(gate) = self.inner.pause_gate.lock().await.take() {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        let mut vms = self.inner.vms.lock().await;
        match vms.get_mut(&id) {
            Some(vm) => {
                vm.state = VmState::Paused;
                Ok(())
            }
            None => Err(VmmError::VmNotFound(id)),
        }
    }

    async fn resume_vm(&self, id: Uuid) -> Result<(), VmmError> {
        let mut vms = self.inner.vms.lock().await;
        match vms.get_mut(&id) {
            Some(vm) => {
                vm.state = VmState::Running;
                Ok(())
            }
            None => Err(VmmError::VmNotFound(id)),
        }
    }

    async fn snapshot_vm(&self, _id: Uuid, _dst: &SnapshotPaths) -> Result<SnapshotMeta, VmmError> {
        Err(VmmError::Unsupported("mock".into()))
    }

    async fn restore_vm(
        &self,
        _src: &SnapshotPaths,
        _target: RestoreTarget,
    ) -> Result<VmInfo, VmmError> {
        Err(VmmError::Unsupported("mock".into()))
    }

    async fn vsock_connect(&self, id: Uuid, _port: u32) -> Result<Self::VsockStream, VmmError> {
        if !self.inner.vms.lock().await.contains_key(&id) {
            return Err(VmmError::VmNotFound(id));
        }

        let socket_path = self
            .inner
            .agent_socket
            .lock()
            .await
            .clone()
            .ok_or_else(|| VmmError::ProcessError("agent socket not configured".into()))?;

        tokio::net::UnixStream::connect(&socket_path)
            .await
            .map_err(VmmError::Io)
    }

    async fn set_balloon(&self, _id: Uuid, _amount_mib: u32) -> Result<(), VmmError> {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn vm_record(
    id: Uuid,
    name: &str,
    state: &str,
    userdata: Option<String>,
    userdata_status: Option<String>,
    userdata_env: Option<String>,
    guest_ip: Option<String>,
    tap_device: Option<String>,
) -> VmRecord {
    let now = Utc::now();
    VmRecord {
        id,
        name: name.to_string(),
        state: state.to_string(),
        pid: Some(9999),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 7,
        tap_device,
        host_ip: Some("172.20.0.1".into()),
        guest_ip,
        kernel_path: "/tmp/vmlinux".into(),
        rootfs_path: "/tmp/rootfs.ext4".into(),
        created_at: now,
        updated_at: now,
        userdata,
        userdata_status,
        userdata_env,
        service_id: None,
        service_ordinal: None,
        vmm: "firecracker".into(),
        boot_mode: "direct".into(),
        balloon: false,
        volume: None,
        network: "nat".into(),
        last_activity_at: now,
        suspended_at: None,
        idle_timeout_secs: None,
        suspend_ttl_secs: None,
        auto_resume: true,
        forked_from: None,
    }
}

fn build_core(
    mock: MockVmm,
    state: StateStore,
    data_dir: &Path,
    runtime_dir: &Path,
) -> Arc<HuskerCore<MockVmm>> {
    let storage = StorageConfig {
        data_dir: data_dir.to_path_buf(),
        state_dir: data_dir.to_path_buf(),
    };

    #[cfg(feature = "linux-net")]
    {
        Arc::new(HuskerCore::new(
            mock,
            state,
            husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
            storage,
            "husker0".into(),
            vec!["8.8.8.8".into()],
            runtime_dir.to_path_buf(),
        ))
    }

    #[cfg(not(feature = "linux-net"))]
    {
        Arc::new(HuskerCore::new(
            mock,
            state,
            storage,
            runtime_dir.to_path_buf(),
        ))
    }
}

async fn spawn_agent() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = husker_agent::handle_connection(stream).await;
            });
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    (dir, path)
}

#[tokio::test]
async fn drain_vms_stops_running_and_paused() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = StateStore::open_memory().unwrap();
    let mock = MockVmm::new();

    let running_id = Uuid::new_v4();
    let paused_id = Uuid::new_v4();
    let stopped_id = Uuid::new_v4();
    state
        .insert_vm(&vm_record(
            running_id,
            "running-vm",
            "running",
            None,
            None,
            None,
            None,
            None,
        ))
        .unwrap();
    state
        .insert_vm(&vm_record(
            paused_id,
            "paused-vm",
            "paused",
            None,
            None,
            None,
            None,
            None,
        ))
        .unwrap();
    state
        .insert_vm(&vm_record(
            stopped_id,
            "stopped-vm",
            "stopped",
            None,
            None,
            None,
            None,
            None,
        ))
        .unwrap();

    mock.upsert_vm(VmInfo {
        id: running_id,
        name: "running-vm".into(),
        state: VmState::Running,
        pid: Some(1),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 7,
    })
    .await;
    mock.upsert_vm(VmInfo {
        id: paused_id,
        name: "paused-vm".into(),
        state: VmState::Paused,
        pid: Some(2),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 8,
    })
    .await;
    mock.upsert_vm(VmInfo {
        id: stopped_id,
        name: "stopped-vm".into(),
        state: VmState::Stopped,
        pid: Some(3),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 9,
    })
    .await;

    let core = build_core(mock.clone(), state, &data_dir, &runtime_dir);
    let drained = core.drain_vms().await;
    assert_eq!(drained, 2);
    assert_eq!(mock.stop_call_count().await, 2);
    let running = core.get_vm("running-vm").unwrap();
    assert_eq!(running.state, "stopped");
    assert_eq!(running.pid, None);
    let paused = core.get_vm("paused-vm").unwrap();
    assert_eq!(paused.state, "stopped");
    assert_eq!(paused.pid, None);
    assert_eq!(core.get_vm("stopped-vm").unwrap().state, "stopped");
}

#[tokio::test]
async fn drain_vms_continues_when_stop_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = StateStore::open_memory().unwrap();
    let mock = MockVmm::new();
    let vm_id = Uuid::new_v4();
    state
        .insert_vm(&vm_record(
            vm_id, "vm-fail", "running", None, None, None, None, None,
        ))
        .unwrap();

    mock.upsert_vm(VmInfo {
        id: vm_id,
        name: "vm-fail".into(),
        state: VmState::Running,
        pid: Some(4),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 10,
    })
    .await;
    mock.mark_stop_failure(vm_id).await;

    let core = build_core(mock.clone(), state, &data_dir, &runtime_dir);
    let drained = core.drain_vms().await;
    assert_eq!(drained, 1);
    assert_eq!(mock.stop_call_count().await, 1);
    assert_eq!(core.get_vm("vm-fail").unwrap().state, "stopped");
}

#[tokio::test]
async fn drain_vms_returns_zero_when_no_vm_needs_drain() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = StateStore::open_memory().unwrap();
    state
        .insert_vm(&vm_record(
            Uuid::new_v4(),
            "already-stopped",
            "stopped",
            None,
            None,
            None,
            None,
            None,
        ))
        .unwrap();

    let core = build_core(MockVmm::new(), state, &data_dir, &runtime_dir);
    assert_eq!(core.drain_vms().await, 0);
}

#[tokio::test]
async fn serial_log_path_uses_vm_id_filename() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = StateStore::open_memory().unwrap();
    let vm_id = Uuid::new_v4();
    state
        .insert_vm(&vm_record(
            vm_id, "vm-logs", "running", None, None, None, None, None,
        ))
        .unwrap();

    let core = build_core(MockVmm::new(), state, &data_dir, &runtime_dir);
    let path = core.serial_log_path("vm-logs").unwrap();
    assert_eq!(path, runtime_dir.join(format!("{vm_id}.serial.log")));
}

#[tokio::test]
async fn serial_log_path_missing_vm_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let core = build_core(
        MockVmm::new(),
        StateStore::open_memory().unwrap(),
        &data_dir,
        &runtime_dir,
    );
    let err = core.serial_log_path("no-such-vm").unwrap_err().to_string();
    assert!(
        err.contains("VM not found"),
        "unexpected missing-vm error: {err}"
    );
}

#[tokio::test]
async fn list_vms_returns_inserted_records() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = StateStore::open_memory().unwrap();
    state
        .insert_vm(&vm_record(
            Uuid::new_v4(),
            "vm-a",
            "running",
            None,
            None,
            None,
            None,
            None,
        ))
        .unwrap();
    state
        .insert_vm(&vm_record(
            Uuid::new_v4(),
            "vm-b",
            "stopped",
            None,
            None,
            None,
            None,
            None,
        ))
        .unwrap();

    let core = build_core(MockVmm::new(), state, &data_dir, &runtime_dir);
    let names: std::collections::HashSet<String> = core
        .list_vms()
        .unwrap()
        .into_iter()
        .map(|vm| vm.name)
        .collect();
    assert_eq!(names.len(), 2);
    assert!(names.contains("vm-a"));
    assert!(names.contains("vm-b"));
}

#[tokio::test]
async fn refreshed_vm_retires_the_identity_of_a_missing_vmm() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = StateStore::open_memory().unwrap();
    state
        .insert_vm(&vm_record(
            Uuid::new_v4(),
            "exited-vm",
            "running",
            None,
            None,
            None,
            None,
            None,
        ))
        .unwrap();
    // Deliberately leave the VMM backend empty: this is the observable state
    // after a guest-initiated shutdown that the daemon did not witness.
    let core = build_core(MockVmm::new(), state, &data_dir, &runtime_dir);

    let refreshed = core.get_vm_refreshed("exited-vm").await.unwrap();
    assert_eq!(refreshed.state, "stopped");
    assert_eq!(refreshed.pid, None);

    let persisted = core.get_vm("exited-vm").unwrap();
    assert_eq!(persisted.state, "stopped");
    assert_eq!(persisted.pid, None);
}

#[tokio::test]
async fn create_vm_rejects_duplicate_running_name_before_validation() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = StateStore::open_memory().unwrap();
    state
        .insert_vm(&vm_record(
            Uuid::new_v4(),
            "dup-vm",
            "running",
            None,
            None,
            None,
            None,
            None,
        ))
        .unwrap();

    let core = build_core(MockVmm::new(), state, &data_dir, &runtime_dir);
    let err = core
        .create_vm(CreateVmRequest {
            name: "dup-vm".into(),
            kernel_path: Some(PathBuf::from("/path/that/does/not/matter")),
            rootfs_path: Some(PathBuf::from("/path/that/also/does/not/matter")),
            vcpu_count: Some(1),
            mem_size_mib: Some(128),
            initrd_path: None,
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
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::VmAlreadyExists(ref name) if name == "dup-vm"));
}

#[tokio::test]
async fn create_vm_missing_kernel_returns_storage_error() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let core = build_core(
        MockVmm::new(),
        StateStore::open_memory().unwrap(),
        &data_dir,
        &runtime_dir,
    );
    let err = core
        .create_vm(CreateVmRequest {
            name: "vm-missing-kernel".into(),
            kernel_path: Some(tmp.path().join("missing-kernel")),
            rootfs_path: Some(tmp.path().join("missing-rootfs")),
            vcpu_count: Some(1),
            mem_size_mib: Some(128),
            initrd_path: None,
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
            ..Default::default()
        })
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("kernel not found"),
        "unexpected create_vm error: {err}"
    );
}

#[tokio::test]
async fn create_vm_replaces_stopped_vm_before_validation() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = StateStore::open_memory().unwrap();
    let mock = MockVmm::new();
    let vm_id = Uuid::new_v4();
    state
        .insert_vm(&vm_record(
            vm_id,
            "replace-vm",
            "stopped",
            None,
            None,
            None,
            None,
            None,
        ))
        .unwrap();
    mock.upsert_vm(VmInfo {
        id: vm_id,
        name: "replace-vm".into(),
        state: VmState::Stopped,
        pid: Some(9),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 15,
    })
    .await;

    let core = build_core(mock, state, &data_dir, &runtime_dir);
    let err = core
        .create_vm(CreateVmRequest {
            name: "replace-vm".into(),
            kernel_path: Some(tmp.path().join("missing-kernel-after-replace")),
            rootfs_path: Some(tmp.path().join("missing-rootfs-after-replace")),
            vcpu_count: Some(1),
            mem_size_mib: Some(128),
            initrd_path: None,
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
            ..Default::default()
        })
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("kernel not found"),
        "unexpected create_vm error after replace: {err}"
    );
    assert!(matches!(
        core.get_vm("replace-vm"),
        Err(CoreError::VmNotFound(_))
    ));
}

#[tokio::test]
async fn rotate_serial_logs_rotates_only_large_serial_files() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let large_log = runtime_dir.join("large.serial.log");
    let small_log = runtime_dir.join("small.serial.log");
    let other = runtime_dir.join("notes.txt");

    std::fs::write(&large_log, vec![b'a'; 11 * 1024 * 1024]).unwrap();
    std::fs::write(&small_log, vec![b'b'; 1024]).unwrap();
    std::fs::write(&other, b"hello").unwrap();

    let core = build_core(
        MockVmm::new(),
        StateStore::open_memory().unwrap(),
        &data_dir,
        &runtime_dir,
    );
    let rotated = core.rotate_serial_logs().await;

    assert_eq!(rotated, 1);
    assert_eq!(std::fs::read(&small_log).unwrap().len(), 1024);
    assert_eq!(std::fs::read(&other).unwrap(), b"hello");
    let rotated_size = std::fs::metadata(&large_log).unwrap().len();
    assert!(
        (4 * 1024 * 1024..11 * 1024 * 1024).contains(&rotated_size),
        "unexpected rotated size: {rotated_size}"
    );
}

#[tokio::test]
async fn rotate_serial_logs_missing_runtime_dir_returns_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("missing-run-dir");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let core = build_core(
        MockVmm::new(),
        StateStore::open_memory().unwrap(),
        &data_dir,
        &runtime_dir,
    );
    assert_eq!(core.rotate_serial_logs().await, 0);
}

#[tokio::test]
async fn run_userdata_marks_completed_on_success() {
    let _serial = userdata_test_lock().lock().await;
    let (_dir, socket_path) = spawn_agent().await;

    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = StateStore::open_memory().unwrap();
    let mock = MockVmm::new();
    mock.set_agent_socket(Some(socket_path)).await;

    let vm_id = Uuid::new_v4();
    state
        .insert_vm(&vm_record(
            vm_id,
            "vm-userdata-ok",
            "running",
            Some("exit 0".into()),
            Some("pending".into()),
            Some(serde_json::to_string(&vec![("GREETING", "hello")]).unwrap()),
            None,
            None,
        ))
        .unwrap();
    mock.upsert_vm(VmInfo {
        id: vm_id,
        name: "vm-userdata-ok".into(),
        state: VmState::Running,
        pid: Some(5),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 11,
    })
    .await;

    let core = build_core(mock, state, &data_dir, &runtime_dir);
    core.run_userdata("vm-userdata-ok").await.unwrap();
    let vm = core.get_vm("vm-userdata-ok").unwrap();
    assert_eq!(vm.userdata_status.as_deref(), Some("completed"));
}

#[tokio::test]
async fn run_userdata_captures_output_to_log() {
    let _serial = userdata_test_lock().lock().await;
    let (_dir, socket_path) = spawn_agent().await;

    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = StateStore::open_memory().unwrap();
    let mock = MockVmm::new();
    mock.set_agent_socket(Some(socket_path)).await;

    let vm_id = Uuid::new_v4();
    state
        .insert_vm(&vm_record(
            vm_id,
            "vm-userdata-log",
            "running",
            Some("echo husker-marker-9f3 >&2; echo on-stdout".into()),
            Some("pending".into()),
            None,
            None,
            None,
        ))
        .unwrap();
    mock.upsert_vm(VmInfo {
        id: vm_id,
        name: "vm-userdata-log".into(),
        state: VmState::Running,
        pid: Some(5),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 11,
    })
    .await;

    let core = build_core(mock, state, &data_dir, &runtime_dir);
    core.run_userdata("vm-userdata-log").await.unwrap();

    // The script's stdout and stderr are captured to the userdata log so they
    // can be inspected via `husker logs <name> --userdata`.
    let log_path = core.userdata_log_path("vm-userdata-log").unwrap();
    let captured = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        captured.contains("on-stdout"),
        "stdout captured: {captured}"
    );
    assert!(
        captured.contains("husker-marker-9f3"),
        "stderr captured: {captured}"
    );
    assert!(
        captured.contains("[stderr]"),
        "stderr section labeled: {captured}"
    );
}

#[tokio::test]
async fn run_userdata_marks_failed_on_nonzero_exit() {
    let _serial = userdata_test_lock().lock().await;
    let (_dir, socket_path) = spawn_agent().await;

    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = StateStore::open_memory().unwrap();
    let mock = MockVmm::new();
    mock.set_agent_socket(Some(socket_path)).await;

    let vm_id = Uuid::new_v4();
    state
        .insert_vm(&vm_record(
            vm_id,
            "vm-userdata-fail",
            "running",
            Some("exit 37".into()),
            Some("pending".into()),
            None,
            None,
            None,
        ))
        .unwrap();
    mock.upsert_vm(VmInfo {
        id: vm_id,
        name: "vm-userdata-fail".into(),
        state: VmState::Running,
        pid: Some(6),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 12,
    })
    .await;

    let core = build_core(mock, state, &data_dir, &runtime_dir);
    core.run_userdata("vm-userdata-fail").await.unwrap();
    let vm = core.get_vm("vm-userdata-fail").unwrap();
    assert_eq!(vm.userdata_status.as_deref(), Some("failed"));
}

#[tokio::test]
async fn run_userdata_without_script_is_noop() {
    let _serial = userdata_test_lock().lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = StateStore::open_memory().unwrap();
    let mock = MockVmm::new();
    let vm_id = Uuid::new_v4();

    state
        .insert_vm(&vm_record(
            vm_id,
            "vm-no-userdata",
            "running",
            None,
            None,
            None,
            None,
            None,
        ))
        .unwrap();
    mock.upsert_vm(VmInfo {
        id: vm_id,
        name: "vm-no-userdata".into(),
        state: VmState::Running,
        pid: Some(7),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 13,
    })
    .await;

    let core = build_core(mock, state, &data_dir, &runtime_dir);
    core.run_userdata("vm-no-userdata").await.unwrap();
    let vm = core.get_vm("vm-no-userdata").unwrap();
    assert!(vm.userdata_status.is_none());
}

#[tokio::test]
async fn run_userdata_on_non_running_vm_marks_failed_and_returns_error() {
    let _serial = userdata_test_lock().lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = StateStore::open_memory().unwrap();
    let mock = MockVmm::new();
    let vm_id = Uuid::new_v4();

    state
        .insert_vm(&vm_record(
            vm_id,
            "vm-paused-userdata",
            "paused",
            Some("exit 0".into()),
            Some("pending".into()),
            None,
            None,
            None,
        ))
        .unwrap();
    mock.upsert_vm(VmInfo {
        id: vm_id,
        name: "vm-paused-userdata".into(),
        state: VmState::Paused,
        pid: Some(8),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 14,
    })
    .await;

    let core = build_core(mock, state, &data_dir, &runtime_dir);
    let err = core
        .run_userdata("vm-paused-userdata")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("expected running"),
        "unexpected run_userdata error: {err}"
    );
    let vm = core.get_vm("vm-paused-userdata").unwrap();
    assert_eq!(vm.userdata_status.as_deref(), Some("failed"));
}

#[tokio::test]
async fn agent_connect_missing_vm_returns_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let core = build_core(
        MockVmm::new(),
        StateStore::open_memory().unwrap(),
        &data_dir,
        &runtime_dir,
    );
    match core.agent_connect("no-such-vm").await {
        Ok(_) => panic!("expected missing VM error"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("VM not found"),
                "unexpected agent_connect error: {msg}"
            );
        }
    }
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn add_port_forward_rejects_missing_guest_ip() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = StateStore::open_memory().unwrap();
    state
        .insert_vm(&vm_record(
            Uuid::new_v4(),
            "vm-no-guest-ip",
            "running",
            None,
            None,
            None,
            None,
            Some("husker7".into()),
        ))
        .unwrap();

    let core = build_core(MockVmm::new(), state, &data_dir, &runtime_dir);
    let err = core
        .add_port_forward("vm-no-guest-ip", 18080, 80, None)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("no guest IP"), "unexpected error: {err}");
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn add_port_forward_rejects_invalid_guest_ip() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = StateStore::open_memory().unwrap();
    state
        .insert_vm(&vm_record(
            Uuid::new_v4(),
            "vm-invalid-guest-ip",
            "running",
            None,
            None,
            None,
            Some("not-an-ip".into()),
            Some("husker8".into()),
        ))
        .unwrap();

    let core = build_core(MockVmm::new(), state, &data_dir, &runtime_dir);
    let err = core
        .add_port_forward("vm-invalid-guest-ip", 18081, 81, None)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("invalid guest IP"), "unexpected error: {err}");
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn add_port_forward_rejects_missing_tap_device() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = StateStore::open_memory().unwrap();
    state
        .insert_vm(&vm_record(
            Uuid::new_v4(),
            "vm-no-tap",
            "running",
            None,
            None,
            None,
            Some("172.20.0.2".into()),
            None,
        ))
        .unwrap();

    let core = build_core(MockVmm::new(), state, &data_dir, &runtime_dir);
    let err = core
        .add_port_forward("vm-no-tap", 18082, 82, None)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("no TAP device"), "unexpected error: {err}");
}

/// Port forwarding applies for a QEMU-backed VM exactly as for Firecracker:
/// `add_port_forward` keys on the TAP/guest IP and never branches on VMM kind.
///
/// Gated like the other net e2e tests: runs and no-ops by default, and does real
/// nft work only under `HUSKER_RUN_NET_E2E=1` with root on Linux. Uses a
/// test-only bridge/subnet, so it is safe to run on a host already running a
/// husker daemon (it never touches the daemon's `husker0` bridge or table).
#[cfg(feature = "linux-net")]
#[tokio::test]
async fn port_forward_applies_for_qemu_backed_vm() {
    if std::env::var("HUSKER_RUN_NET_E2E").is_err() {
        return;
    }
    const BRIDGE: &str = "hpfq0";
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    // Detect the default-route interface for the masquerade rule.
    let host_iface = std::process::Command::new("sh")
        .args(["-c", "ip route show default | awk '{print $5; exit}'"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "eth0".into());

    husker_net::create_bridge(BRIDGE, std::net::Ipv4Addr::new(192, 0, 2, 1), 24)
        .await
        .unwrap();
    husker_net::init_nat(BRIDGE, "192.0.2.0/24", &host_iface, None)
        .await
        .ok();

    let state = StateStore::open_memory().unwrap();
    let mut vm = vm_record(
        Uuid::new_v4(),
        "qemu-pf",
        "running",
        None,
        None,
        None,
        Some("192.0.2.2".into()),
        Some("hpfq-tap0".into()),
    );
    vm.vmm = "qemu".into();
    state.insert_vm(&vm).unwrap();

    // Core wired to the test bridge (build_core hardcodes husker0).
    let core = Arc::new(HuskerCore::new(
        MockVmm::new(),
        state,
        husker_net::IpAllocator::new(std::net::Ipv4Addr::new(192, 0, 2, 0), 24),
        StorageConfig {
            data_dir: data_dir.clone(),
            state_dir: data_dir.clone(),
        },
        BRIDGE.to_string(),
        vec!["8.8.8.8".into()],
        runtime_dir.clone(),
    ));

    core.add_port_forward("qemu-pf", 18090, 80, None)
        .await
        .unwrap();
    let forwards = core.list_port_forwards("qemu-pf").unwrap();
    assert_eq!(forwards.len(), 1);
    assert_eq!(forwards[0].host_port, 18090);

    let table = husker_net::nft_table_for_bridge(BRIDGE);
    let rules = tokio::process::Command::new("nft")
        .args(["list", "table", "ip", &table])
        .output()
        .await
        .unwrap();
    let rules = String::from_utf8_lossy(&rules.stdout);
    assert!(
        rules.contains("18090") && rules.contains("192.0.2.2"),
        "nft DNAT rule should target the qemu-backed VM's guest:\n{rules}"
    );

    core.remove_port_forward("qemu-pf", 18090).await.unwrap();
    let after = tokio::process::Command::new("nft")
        .args(["list", "table", "ip", &table])
        .output()
        .await
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&after.stdout).contains("18090"),
        "nft DNAT rule should be gone after removal"
    );

    husker_net::delete_bridge(BRIDGE).await.ok();
    let _ = tokio::process::Command::new("nft")
        .args(["delete", "table", "ip", &table])
        .output()
        .await;
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn remove_port_forward_rejects_missing_tap_device() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = StateStore::open_memory().unwrap();
    state
        .insert_vm(&vm_record(
            Uuid::new_v4(),
            "vm-no-tap-rm",
            "running",
            None,
            None,
            None,
            Some("172.20.0.3".into()),
            None,
        ))
        .unwrap();

    let core = build_core(MockVmm::new(), state, &data_dir, &runtime_dir);
    let err = core
        .remove_port_forward("vm-no-tap-rm", 18090)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("no TAP device"), "unexpected error: {err}");
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn reconcile_port_forwards_skips_invalid_guest_ip() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = StateStore::open_memory().unwrap();
    let vm_id = Uuid::new_v4();
    state
        .insert_vm(&vm_record(
            vm_id,
            "vm-bad-ip",
            "running",
            None,
            None,
            None,
            Some("nope".into()),
            Some("husker9".into()),
        ))
        .unwrap();
    state
        .insert_port_forward(&PortForwardRecord {
            id: 0,
            vm_id,
            host_port: 19000,
            guest_port: 9000,
            protocol: "tcp".into(),
            bind_addr: None,
            created_at: Utc::now(),
        })
        .unwrap();

    let core = build_core(MockVmm::new(), state, &data_dir, &runtime_dir);
    assert_eq!(core.reconcile_port_forwards_from_state().await.restored, 0);
}

#[tokio::test]
async fn create_snapshot_requires_stopped_vm() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(data_dir.join("vms/running-vm")).unwrap();
    std::fs::write(data_dir.join("vms/running-vm/rootfs.ext4"), b"rootfs").unwrap();

    let state = StateStore::open_memory().unwrap();
    let mock = MockVmm::new();
    state
        .insert_vm(&vm_record(
            Uuid::new_v4(),
            "running-vm",
            "running",
            None,
            None,
            None,
            None,
            None,
        ))
        .unwrap();
    let core = build_core(mock, state, &data_dir, &runtime_dir);

    let err = core
        .create_snapshot(CreateSnapshotRequest {
            name: "snap-1".into(),
            vm: "running-vm".into(),
        })
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::InvalidState { .. }));
}

#[tokio::test]
async fn snapshot_roundtrip_create_list_get_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(data_dir.join("vms/stopped-vm")).unwrap();
    std::fs::write(
        data_dir.join("vms/stopped-vm/rootfs.ext4"),
        b"snapshot-data",
    )
    .unwrap();

    let state = StateStore::open_memory().unwrap();
    let mock = MockVmm::new();
    state
        .insert_vm(&vm_record(
            Uuid::new_v4(),
            "stopped-vm",
            "stopped",
            None,
            None,
            None,
            None,
            None,
        ))
        .unwrap();
    let core = build_core(mock, state, &data_dir, &runtime_dir);

    let snapshot = core
        .create_snapshot(CreateSnapshotRequest {
            name: "snap-1".into(),
            vm: "stopped-vm".into(),
        })
        .await
        .unwrap();
    assert_eq!(snapshot.name, "snap-1");
    assert_eq!(snapshot.source_vm_name, "stopped-vm");

    let snapshot_path = data_dir.join("images/snapshots/snap-1.ext4");
    assert!(snapshot_path.exists());
    assert_eq!(std::fs::read(&snapshot_path).unwrap(), b"snapshot-data");

    let listed = core.list_snapshots().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "snap-1");

    let fetched = core.get_snapshot("snap-1").unwrap();
    assert_eq!(fetched.id, snapshot.id);

    core.delete_snapshot("snap-1").await.unwrap();
    assert!(!snapshot_path.exists());
    assert!(core.list_snapshots().unwrap().is_empty());
}

#[tokio::test]
async fn restore_snapshot_missing_snapshot_returns_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let core = build_core(
        MockVmm::new(),
        StateStore::open_memory().unwrap(),
        &data_dir,
        &runtime_dir,
    );

    let err = core
        .restore_snapshot(
            "missing",
            RestoreSnapshotRequest {
                name: "restored-vm".into(),
                kernel_path: data_dir.join("kernels/vmlinux"),
                vcpu_count: Some(1),
                mem_size_mib: Some(128),
                initrd_path: None,
                userdata: None,
                env: Vec::new(),
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::SnapshotNotFound(_)));
}

#[tokio::test]
async fn image_roundtrip_import_list_get_export_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let source_image = tmp.path().join("source.ext4");
    std::fs::write(&source_image, b"image-rootfs-data").unwrap();

    let core = build_core(
        MockVmm::new(),
        StateStore::open_memory().unwrap(),
        &data_dir,
        &runtime_dir,
    );

    let imported = core
        .import_image(ImportImageRequest {
            name: "ubuntu-base".into(),
            source_path: source_image.clone(),
            format: None,
            kind: None,
        })
        .await
        .unwrap();
    assert_eq!(imported.name, "ubuntu-base");
    assert_eq!(imported.format, "ext4");

    let catalog_path = data_dir.join("images/catalog/ubuntu-base.ext4");
    assert!(catalog_path.exists());
    assert_eq!(std::fs::read(&catalog_path).unwrap(), b"image-rootfs-data");

    let listed = core.list_images().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "ubuntu-base");

    let fetched = core.get_image("ubuntu-base").unwrap();
    assert_eq!(fetched.id, imported.id);

    let export_path = tmp.path().join("exports/ubuntu-base-copy.ext4");
    let exported = core
        .export_image(
            "ubuntu-base",
            ExportImageRequest {
                destination_path: export_path.clone(),
            },
        )
        .await
        .unwrap();
    assert_eq!(exported.name, "ubuntu-base");
    assert_eq!(std::fs::read(&export_path).unwrap(), b"image-rootfs-data");

    core.delete_image("ubuntu-base").await.unwrap();
    assert!(!catalog_path.exists());
    assert!(core.list_images().unwrap().is_empty());
}

#[tokio::test]
async fn export_missing_image_returns_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let core = build_core(
        MockVmm::new(),
        StateStore::open_memory().unwrap(),
        &data_dir,
        &runtime_dir,
    );

    let err = core
        .export_image(
            "missing",
            ExportImageRequest {
                destination_path: tmp.path().join("out.ext4"),
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::ImageNotFound(_)));
}

#[tokio::test]
async fn secret_roundtrip_create_reveal_rotate_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let core = build_core(
        MockVmm::new(),
        StateStore::open_memory().unwrap(),
        &data_dir,
        &runtime_dir,
    );

    let created = core
        .create_secret(CreateSecretRequest {
            name: "db-password".into(),
            value: "hunter2".into(),
        })
        .unwrap();
    assert_eq!(created.name, "db-password");
    assert!(data_dir.join("keys/secrets.key").exists());

    let listed = core.list_secrets().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "db-password");

    let metadata = core.get_secret("db-password").unwrap();
    assert_eq!(metadata.id, created.id);

    let revealed = core.reveal_secret("db-password").unwrap();
    assert_eq!(revealed.value, "hunter2");

    core.rotate_secret(
        "db-password",
        RotateSecretRequest {
            value: "new-password".into(),
        },
    )
    .unwrap();
    let revealed = core.reveal_secret("db-password").unwrap();
    assert_eq!(revealed.value, "new-password");

    core.delete_secret("db-password").unwrap();
    assert!(core.list_secrets().unwrap().is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn secret_key_file_is_mode_0o600_on_creation() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let core = make_core(&tmp);
    core.create_secret(CreateSecretRequest {
        name: "db-password".into(),
        value: "x".into(),
    })
    .unwrap();

    let key_path = tmp.path().join("data/keys/secrets.key");
    let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "secret key must be 0o600, got {mode:o}");
}

// --- Encryption at rest -------------------------------------------------------
//
// These drive the production create_secret/reveal_secret path and then reopen
// the on-disk state DB to inspect (and, for the integrity cases, corrupt) the
// raw persisted record, proving the stored value is AES-256-GCM ciphertext with
// a fresh nonce per encryption and that decryption fails closed under tampering
// or a key change.

/// Naive subsequence search: proves a plaintext does not appear verbatim inside
/// a persisted ciphertext blob.
fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn secret_is_persisted_as_ciphertext_not_plaintext() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();
    let db_path = data_dir.join("state.db");

    let core = build_core(
        MockVmm::new(),
        StateStore::open(&db_path).unwrap(),
        &data_dir,
        &runtime_dir,
    );

    let plaintext = "correct horse battery staple";
    core.create_secret(CreateSecretRequest {
        name: "api-key".into(),
        value: plaintext.into(),
    })
    .unwrap();

    // Reopen the same on-disk DB to inspect the raw stored record.
    let raw = StateStore::open(&db_path).unwrap();
    let record = raw.get_secret_by_name("api-key").unwrap();

    assert!(
        !bytes_contain(&record.ciphertext, plaintext.as_bytes()),
        "persisted ciphertext must not contain the plaintext"
    );
    // AES-256-GCM appends a 16-byte auth tag; the nonce is 96-bit.
    assert_eq!(record.ciphertext.len(), plaintext.len() + 16);
    assert_eq!(record.nonce.len(), 12);

    // The production reveal path still recovers the original plaintext.
    assert_eq!(core.reveal_secret("api-key").unwrap().value, plaintext);
}

#[tokio::test]
async fn secrets_with_identical_values_use_distinct_nonces() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();
    let db_path = data_dir.join("state.db");

    let core = build_core(
        MockVmm::new(),
        StateStore::open(&db_path).unwrap(),
        &data_dir,
        &runtime_dir,
    );

    for name in ["first", "second"] {
        core.create_secret(CreateSecretRequest {
            name: name.into(),
            value: "same-value".into(),
        })
        .unwrap();
    }

    let raw = StateStore::open(&db_path).unwrap();
    let a = raw.get_secret_by_name("first").unwrap();
    let b = raw.get_secret_by_name("second").unwrap();
    assert_ne!(a.nonce, b.nonce, "each encryption must use a fresh nonce");
    assert_ne!(
        a.ciphertext, b.ciphertext,
        "identical plaintext must not produce identical ciphertext"
    );
}

#[tokio::test]
async fn reveal_rejects_tampered_ciphertext() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();
    let db_path = data_dir.join("state.db");

    let core = build_core(
        MockVmm::new(),
        StateStore::open(&db_path).unwrap(),
        &data_dir,
        &runtime_dir,
    );
    core.create_secret(CreateSecretRequest {
        name: "token".into(),
        value: "s3cr3t".into(),
    })
    .unwrap();

    // Flip one bit of the persisted ciphertext, leaving the nonce intact.
    let raw = StateStore::open(&db_path).unwrap();
    let record = raw.get_secret_by_name("token").unwrap();
    let mut tampered = record.ciphertext.clone();
    tampered[0] ^= 0x01;
    raw.update_secret_payload(record.id, &tampered, &record.nonce)
        .unwrap();

    let err = core.reveal_secret("token").unwrap_err();
    assert!(
        matches!(err, CoreError::SecretCrypto(_)),
        "tampered ciphertext must fail GCM authentication, got {err:?}"
    );
}

#[tokio::test]
async fn reveal_fails_after_key_replaced_on_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let core = build_core(
        MockVmm::new(),
        StateStore::open_memory().unwrap(),
        &data_dir,
        &runtime_dir,
    );
    core.create_secret(CreateSecretRequest {
        name: "token".into(),
        value: "s3cr3t".into(),
    })
    .unwrap();

    // Replace the on-disk key with a different 32-byte key.
    let key_path = data_dir.join("keys/secrets.key");
    std::fs::write(&key_path, [0u8; 32]).unwrap();

    let err = core.reveal_secret("token").unwrap_err();
    assert!(
        matches!(err, CoreError::SecretCrypto(_)),
        "reveal under a replaced key must fail closed, got {err:?}"
    );
}

#[tokio::test]
async fn reveal_missing_secret_returns_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let core = build_core(
        MockVmm::new(),
        StateStore::open_memory().unwrap(),
        &data_dir,
        &runtime_dir,
    );

    let err = core.reveal_secret("missing").unwrap_err();
    assert!(matches!(err, CoreError::SecretNotFound(_)));
}

// --- Resource name validation -------------------------------------------------
//
// Names supplied by API callers feed directly into host filesystem paths
// (vm_dir, snapshots_dir, image catalog). Without validation a name such as
// "../../etc/passwd" lets a caller escape data_dir on create or delete. These
// tests assert that core rejects unsafe names with InvalidArgument before any
// filesystem operation is attempted.

const PATH_TRAVERSAL_NAMES: &[&str] = &[
    "../escape",
    "..",
    ".",
    ".hidden",
    "foo/bar",
    "foo\\bar",
    "with\0null",
    "name with spaces",
    "",
    "tab\there",
];

fn make_core(tmp: &tempfile::TempDir) -> Arc<HuskerCore<MockVmm>> {
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();
    build_core(
        MockVmm::new(),
        StateStore::open_memory().unwrap(),
        &data_dir,
        &runtime_dir,
    )
}

#[tokio::test]
async fn create_vm_rejects_unsafe_names() {
    let tmp = tempfile::tempdir().unwrap();
    let core = make_core(&tmp);
    for name in PATH_TRAVERSAL_NAMES {
        let err = core
            .create_vm(CreateVmRequest {
                name: (*name).into(),
                kernel_path: Some(PathBuf::from("/missing-kernel")),
                rootfs_path: Some(PathBuf::from("/missing-rootfs")),
                vcpu_count: Some(1),
                mem_size_mib: Some(128),
                initrd_path: None,
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
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, CoreError::InvalidArgument(_)),
            "create_vm should reject {name:?} with InvalidArgument, got {err:?}"
        );
    }
}

#[tokio::test]
async fn create_snapshot_rejects_unsafe_names() {
    let tmp = tempfile::tempdir().unwrap();
    let core = make_core(&tmp);
    for name in PATH_TRAVERSAL_NAMES {
        let err = core
            .create_snapshot(CreateSnapshotRequest {
                name: (*name).into(),
                vm: "any-vm".into(),
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, CoreError::InvalidArgument(_)),
            "create_snapshot should reject {name:?}, got {err:?}"
        );
    }
}

#[tokio::test]
async fn import_image_rejects_unsafe_names() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("src.ext4");
    std::fs::write(&source, b"data").unwrap();
    let core = make_core(&tmp);
    for name in PATH_TRAVERSAL_NAMES {
        let err = core
            .import_image(ImportImageRequest {
                name: (*name).into(),
                source_path: source.clone(),
                format: None,
                kind: None,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, CoreError::InvalidArgument(_)),
            "import_image should reject {name:?}, got {err:?}"
        );
    }
}

#[tokio::test]
async fn create_secret_rejects_unsafe_names() {
    let tmp = tempfile::tempdir().unwrap();
    let core = make_core(&tmp);
    for name in PATH_TRAVERSAL_NAMES {
        let err = core
            .create_secret(CreateSecretRequest {
                name: (*name).into(),
                value: "v".into(),
            })
            .unwrap_err();
        assert!(
            matches!(err, CoreError::InvalidArgument(_)),
            "create_secret should reject {name:?}, got {err:?}"
        );
    }
}

#[tokio::test]
async fn create_host_group_rejects_unsafe_names() {
    let tmp = tempfile::tempdir().unwrap();
    let core = make_core(&tmp);
    for name in PATH_TRAVERSAL_NAMES {
        let err = core
            .create_host_group(CreateHostGroupRequest {
                name: (*name).into(),
                description: None,
            })
            .unwrap_err();
        assert!(
            matches!(err, CoreError::InvalidArgument(_)),
            "create_host_group should reject {name:?}, got {err:?}"
        );
    }
}

#[tokio::test]
async fn create_service_rejects_unsafe_names() {
    let tmp = tempfile::tempdir().unwrap();
    let core = make_core(&tmp);
    for name in PATH_TRAVERSAL_NAMES {
        let err = core
            .create_service(CreateServiceRequest {
                name: (*name).into(),
                host_group: None,
                desired_instances: Some(1),
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
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, CoreError::InvalidArgument(_)),
            "create_service should reject {name:?}, got {err:?}"
        );
    }
}

#[tokio::test]
async fn fork_vm_rejects_unsafe_fork_names() {
    // fork builds `data_dir/vms/<fork_name>` and recursively deletes/recreates it.
    // An absolute or `..`-laden fork name must be rejected before any filesystem
    // operation, exactly like every other resource-creation path.
    let tmp = tempfile::tempdir().unwrap();
    let core = make_core(&tmp);
    for name in PATH_TRAVERSAL_NAMES {
        let err = core.fork_vm("any-source", name).await.unwrap_err();
        assert!(
            matches!(err, CoreError::InvalidArgument(_)),
            "fork_vm should reject fork name {name:?} with InvalidArgument, got {err:?}"
        );
    }
    // An absolute path is the most dangerous case (PathBuf::join replaces the whole
    // path), so assert it explicitly too.
    let err = core
        .fork_vm("any-source", "/tmp/husker-escape")
        .await
        .unwrap_err();
    assert!(
        matches!(err, CoreError::InvalidArgument(_)),
        "fork_vm should reject an absolute fork name, got {err:?}"
    );
}

#[tokio::test]
async fn restore_snapshot_rejects_unsafe_target_names() {
    let tmp = tempfile::tempdir().unwrap();
    let core = make_core(&tmp);
    let err = core
        .restore_snapshot(
            "any-snapshot",
            RestoreSnapshotRequest {
                name: "../escape".into(),
                kernel_path: PathBuf::from("/missing"),
                vcpu_count: Some(1),
                mem_size_mib: Some(128),
                initrd_path: None,
                userdata: None,
                env: Vec::new(),
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, CoreError::InvalidArgument(_)),
        "restore_snapshot should reject unsafe target name, got {err:?}"
    );
}

#[tokio::test]
async fn import_image_rejects_relative_source_path() {
    let tmp = tempfile::tempdir().unwrap();
    let core = make_core(&tmp);
    let err = core
        .import_image(ImportImageRequest {
            name: "ubuntu".into(),
            source_path: PathBuf::from("relative/rootfs.ext4"),
            format: None,
            kind: None,
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, CoreError::InvalidArgument(_)),
        "relative source path must be rejected, got {err:?}"
    );
}

#[tokio::test]
async fn import_image_rejects_source_with_parent_traversal() {
    let tmp = tempfile::tempdir().unwrap();
    let core = make_core(&tmp);
    let err = core
        .import_image(ImportImageRequest {
            name: "ubuntu".into(),
            source_path: PathBuf::from("/var/lib/husker/../../etc/shadow"),
            format: None,
            kind: None,
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, CoreError::InvalidArgument(_)),
        "source path with '..' must be rejected, got {err:?}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn import_image_rejects_symlink_source() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real.ext4");
    std::fs::write(&real, b"rootfs-bytes").unwrap();
    let link = tmp.path().join("link.ext4");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let core = make_core(&tmp);
    let err = core
        .import_image(ImportImageRequest {
            name: "ubuntu".into(),
            source_path: link,
            format: None,
            kind: None,
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, CoreError::InvalidArgument(_)),
        "symlink source must be rejected, got {err:?}"
    );
}

#[tokio::test]
async fn export_image_rejects_relative_destination_path() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("src.ext4");
    std::fs::write(&source, b"data").unwrap();
    let core = make_core(&tmp);
    core.import_image(ImportImageRequest {
        name: "base".into(),
        source_path: source,
        format: None,
        kind: None,
    })
    .await
    .unwrap();

    let err = core
        .export_image(
            "base",
            ExportImageRequest {
                destination_path: PathBuf::from("relative/out.ext4"),
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, CoreError::InvalidArgument(_)),
        "relative destination path must be rejected, got {err:?}"
    );
}

#[tokio::test]
async fn export_image_rejects_destination_with_parent_traversal() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("src.ext4");
    std::fs::write(&source, b"data").unwrap();
    let core = make_core(&tmp);
    core.import_image(ImportImageRequest {
        name: "base".into(),
        source_path: source,
        format: None,
        kind: None,
    })
    .await
    .unwrap();

    let err = core
        .export_image(
            "base",
            ExportImageRequest {
                destination_path: PathBuf::from("/var/lib/husker/../../etc/shadow"),
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, CoreError::InvalidArgument(_)),
        "destination with '..' must be rejected, got {err:?}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn export_image_rejects_symlink_destination() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("src.ext4");
    std::fs::write(&source, b"data").unwrap();
    let core = make_core(&tmp);
    core.import_image(ImportImageRequest {
        name: "base".into(),
        source_path: source,
        format: None,
        kind: None,
    })
    .await
    .unwrap();

    let real = tmp.path().join("target.ext4");
    std::fs::write(&real, b"original").unwrap();
    let link = tmp.path().join("link.ext4");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let err = core
        .export_image(
            "base",
            ExportImageRequest {
                destination_path: link,
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, CoreError::InvalidArgument(_)),
        "symlink destination must be rejected, got {err:?}"
    );
    assert_eq!(
        std::fs::read(&real).unwrap(),
        b"original",
        "symlink target must not be overwritten"
    );
}

#[tokio::test]
async fn create_vm_accepts_safe_names() {
    let tmp = tempfile::tempdir().unwrap();
    let core = make_core(&tmp);
    // Safe names should not be rejected on validation; they will fail later on
    // missing kernel/rootfs but with a different error than InvalidArgument.
    for name in &["my-vm", "vm_01", "v.1.2", "abc", "a", &"a".repeat(64)] {
        let err = core
            .create_vm(CreateVmRequest {
                name: (*name).into(),
                kernel_path: Some(PathBuf::from("/missing-kernel")),
                rootfs_path: Some(PathBuf::from("/missing-rootfs")),
                vcpu_count: Some(1),
                mem_size_mib: Some(128),
                initrd_path: None,
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
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert!(
            !matches!(err, CoreError::InvalidArgument(_)),
            "safe name {name:?} should not be rejected as InvalidArgument; got {err:?}"
        );
    }
}

// Cloud-image boot is Linux-only. On the not-linux-net path (macOS / Apple VZ),
// the request must be rejected before any networking or storage is touched.
#[cfg(not(feature = "linux-net"))]
#[tokio::test]
async fn cloud_image_rejected_on_non_qemu_platform() {
    let tmp = tempfile::tempdir().unwrap();
    let core = make_core(&tmp);
    let err = core
        .create_vm(CreateVmRequest {
            name: "cloudvm".into(),
            kernel_path: None,
            rootfs_path: None,
            vcpu_count: Some(1),
            mem_size_mib: Some(128),
            initrd_path: None,
            userdata: None,
            env: Vec::new(),
            vmm: None,
            cloud_image: Some("/some/image.qcow2".into()),
            disk_size: None,
            ssh_authorized_keys: Vec::new(),
            balloon: false,
            volume: None,
            network: None,
            mounts: Vec::new(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::InvalidArgument(_)), "got {err:?}");
}

// The concurrent-create test drives the full create path to completion (VMM
// create + state insert). The linux-net path requires real TAP device operations
// that cannot run in a unit test environment, so this test is restricted to the
// macOS/no-linux-net build where the VMM backend mock covers the full path.
#[cfg(not(feature = "linux-net"))]
#[tokio::test]
async fn concurrent_create_same_name_one_winner() {
    let tmp = tempfile::tempdir().unwrap();
    let core = make_core(&tmp);

    // Fixtures valid on both Linux and macOS (ARM64 Image magic at offset 56).
    let kernel = tmp.path().join("vmlinux");
    let mut kbytes = vec![0u8; 64];
    kbytes[56..60].copy_from_slice(&0x644d_5241u32.to_le_bytes());
    std::fs::write(&kernel, &kbytes).unwrap();
    let rootfs = tmp.path().join("rootfs.ext4");
    std::fs::write(&rootfs, b"rootfs").unwrap();

    let mk = |c: Arc<HuskerCore<MockVmm>>| {
        let kernel = kernel.clone();
        let rootfs = rootfs.clone();
        tokio::spawn(async move {
            c.create_vm(CreateVmRequest {
                name: "racer".into(),
                kernel_path: Some(kernel),
                rootfs_path: Some(rootfs),
                vcpu_count: Some(1),
                mem_size_mib: Some(128),
                initrd_path: None,
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
                ..Default::default()
            })
            .await
        })
    };
    let (a, b) = tokio::join!(mk(Arc::clone(&core)), mk(Arc::clone(&core)));
    let results = [a.unwrap(), b.unwrap()];
    let oks = results.iter().filter(|r| r.is_ok()).count();
    let already = results
        .iter()
        .filter(|r| matches!(r, Err(CoreError::VmAlreadyExists(_))))
        .count();
    assert_eq!(oks, 1, "exactly one create should win");
    assert_eq!(
        already, 1,
        "the loser must get VmAlreadyExists, not a partial/corrupt failure"
    );
    // Exactly one VM persisted.
    assert_eq!(core.list_vms().unwrap().len(), 1);
}

#[cfg(not(feature = "linux-net"))]
#[tokio::test(flavor = "current_thread")]
async fn destroy_waiting_behind_replacement_preserves_new_generation() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let kernel = tmp.path().join("vmlinux");
    let mut kbytes = vec![0u8; 64];
    kbytes[56..60].copy_from_slice(&0x644d_5241u32.to_le_bytes());
    std::fs::write(&kernel, &kbytes).unwrap();
    let rootfs = tmp.path().join("rootfs.ext4");
    std::fs::write(&rootfs, b"replacement rootfs").unwrap();

    let state = StateStore::open_memory().unwrap();
    let old_id = Uuid::new_v4();
    state
        .insert_vm(&vm_record(
            old_id,
            "generation-race",
            "stopped",
            None,
            None,
            None,
            None,
            None,
        ))
        .unwrap();

    let mock = MockVmm::new();
    mock.upsert_vm(VmInfo {
        id: old_id,
        name: "generation-race".into(),
        state: VmState::Stopped,
        pid: Some(9),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 7,
    })
    .await;
    let gate = mock.block_next_destroy().await;
    let core = build_core(mock, state, &data_dir, &runtime_dir);

    let replacing_core = Arc::clone(&core);
    let replacement = tokio::spawn(async move {
        replacing_core
            .create_vm(CreateVmRequest {
                name: "generation-race".into(),
                kernel_path: Some(kernel),
                rootfs_path: Some(rootfs),
                vcpu_count: Some(1),
                mem_size_mib: Some(128),
                ..Default::default()
            })
            .await
    });

    gate.entered.notified().await;

    let destroying_core = Arc::clone(&core);
    let stale_destroy =
        tokio::spawn(async move { destroying_core.destroy_vm("generation-race").await });
    // The current-thread runtime polls the destroy through its synchronous
    // lookup and up to the held per-name lock, deterministically capturing the
    // old generation before replacement is allowed to continue.
    tokio::task::yield_now().await;

    gate.release.notify_one();
    let replacement = replacement.await.unwrap().unwrap();
    stale_destroy.await.unwrap().unwrap();

    let current = core.get_vm("generation-race").unwrap();
    assert_eq!(current.id, replacement.id);
    assert_ne!(current.id, old_id);

    // Prove the stale destroy did not merely leave the row while deleting the
    // replacement's name-derived disk directory: the replacement can still be
    // stopped and snapshotted through the public lifecycle interface.
    core.stop_vm("generation-race").await.unwrap();
    let snapshot = core
        .create_snapshot(CreateSnapshotRequest {
            name: "generation-race-snapshot".into(),
            vm: "generation-race".into(),
        })
        .await
        .unwrap();
    assert_eq!(snapshot.source_vm_name, "generation-race");
}

#[tokio::test(flavor = "current_thread")]
async fn pause_and_destroy_serialize_one_vm_generation() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = StateStore::open_memory().unwrap();
    let vm_id = Uuid::new_v4();
    state
        .insert_vm(&vm_record(
            vm_id,
            "pause-destroy-race",
            "running",
            None,
            None,
            None,
            None,
            None,
        ))
        .unwrap();

    let mock = MockVmm::new();
    mock.upsert_vm(VmInfo {
        id: vm_id,
        name: "pause-destroy-race".into(),
        state: VmState::Running,
        pid: Some(99),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 7,
    })
    .await;
    let gate = mock.block_next_pause().await;
    let core = build_core(mock, state, &data_dir, &runtime_dir);

    let pausing_core = Arc::clone(&core);
    let pause = tokio::spawn(async move { pausing_core.pause_vm("pause-destroy-race").await });
    gate.entered.notified().await;

    let destroying_core = Arc::clone(&core);
    let destroy =
        tokio::spawn(async move { destroying_core.destroy_vm("pause-destroy-race").await });
    tokio::task::yield_now().await;

    gate.release.notify_one();
    pause.await.unwrap().unwrap();
    destroy.await.unwrap().unwrap();
    assert!(matches!(
        core.get_vm("pause-destroy-race"),
        Err(CoreError::VmNotFound(_))
    ));
}

#[tokio::test]
async fn run_userdata_spawn_userdata_drives_to_completed() {
    let _serial = userdata_test_lock().lock().await;
    let (_dir, socket_path) = spawn_agent().await;

    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let state = StateStore::open_memory().unwrap();
    let mock = MockVmm::new();
    mock.set_agent_socket(Some(socket_path)).await;

    let vm_id = Uuid::new_v4();
    let record = vm_record(
        vm_id,
        "vm-spawn-userdata",
        "running",
        Some("exit 0".into()),
        Some("pending".into()),
        None,
        None,
        None,
    );
    state.insert_vm(&record).unwrap();
    mock.upsert_vm(VmInfo {
        id: vm_id,
        name: "vm-spawn-userdata".into(),
        state: VmState::Running,
        pid: Some(5),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 11,
    })
    .await;

    let core = build_core(mock, state, &data_dir, &runtime_dir);
    core.spawn_userdata(&record);

    let mut status = None;
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        status = core.get_vm(&record.name).unwrap().userdata_status;
        if status.as_deref() == Some("completed") {
            break;
        }
    }
    assert_eq!(
        status.as_deref(),
        Some("completed"),
        "spawn_userdata should drive userdata_status to completed"
    );
}

// These tests verify boot-arg composition for the macOS/VZ direct-kernel path.
// On the linux-net path the composition is gated behind a TAP device creation
// that cannot run in a unit-test environment; CI covers it via the e2e suite.
//
// VZ note: Apple Virtualization.framework always passes kernel_args to the
// kernel and the initrd (when present) provides modules only, not root
// mounting. Therefore root=/dev/vda rw is always present in VZ kernel_args,
// regardless of whether an initrd is used.
#[cfg(not(feature = "linux-net"))]
mod kernel_args_composition {
    use super::*;

    fn kernel_stub_bytes() -> Vec<u8> {
        // ARM64 Image magic at offset 56 so validate_kernel_format passes.
        let mut b = vec![0u8; 64];
        b[56..60].copy_from_slice(&0x644d_5241u32.to_le_bytes());
        b
    }

    fn make_capturing_core(tmp: &tempfile::TempDir) -> (Arc<HuskerCore<MockVmm>>, MockVmm) {
        let runtime_dir = tmp.path().join("run");
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&runtime_dir).unwrap();
        std::fs::create_dir_all(&data_dir).unwrap();
        let mock = MockVmm::new();
        let core = Arc::new(HuskerCore::new(
            mock.clone(),
            StateStore::open_memory().unwrap(),
            StorageConfig {
                data_dir: data_dir.to_path_buf(),
                state_dir: data_dir.to_path_buf(),
            },
            runtime_dir,
        ));
        (core, mock)
    }

    #[tokio::test]
    async fn direct_kernel_without_initrd_has_root_arg() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = tmp.path().join("vmlinux");
        std::fs::write(&kernel, kernel_stub_bytes()).unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();

        let (core, mock) = make_capturing_core(&tmp);
        core.create_vm(CreateVmRequest {
            name: "no-initrd".into(),
            kernel_path: Some(kernel),
            rootfs_path: Some(rootfs),
            vcpu_count: Some(1),
            mem_size_mib: Some(128),
            initrd_path: None,
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
            ..Default::default()
        })
        .await
        .expect("create_vm should succeed");

        let cfg = mock.last_config().await.expect("VmConfig was captured");
        let args = cfg
            .kernel_args
            .as_deref()
            .expect("kernel_args must be Some for direct-kernel boot");
        assert!(
            args.contains("root=/dev/vda rw"),
            "kernel_args must contain root=/dev/vda rw when no initrd: {args}"
        );
        assert!(
            args.contains("console=hvc0"),
            "kernel_args must contain console=hvc0 for VZ: {args}"
        );
    }

    // The VZ (not-linux-net) path hardcodes root=/dev/vda rw unconditionally in
    // kernel_args; the initrd-conditional logic lives in the linux-net branch and
    // is covered by CI's Linux suite. This test documents the VZ invariant.
    #[tokio::test]
    async fn vz_direct_kernel_always_has_root_arg() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = tmp.path().join("vmlinux");
        std::fs::write(&kernel, kernel_stub_bytes()).unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        let initrd = tmp.path().join("initramfs.gz");
        std::fs::write(&initrd, b"initrd").unwrap();

        let (core, mock) = make_capturing_core(&tmp);
        core.create_vm(CreateVmRequest {
            name: "with-initrd".into(),
            kernel_path: Some(kernel),
            rootfs_path: Some(rootfs),
            vcpu_count: Some(1),
            mem_size_mib: Some(128),
            initrd_path: Some(initrd),
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
            ..Default::default()
        })
        .await
        .expect("create_vm should succeed");

        let cfg = mock.last_config().await.expect("VmConfig was captured");
        let args = cfg
            .kernel_args
            .as_deref()
            .expect("kernel_args must be Some for direct-kernel boot");
        assert!(
            args.contains("root=/dev/vda rw"),
            "VZ kernel_args must retain root=/dev/vda rw even with initrd: {args}"
        );
        assert!(
            cfg.initrd_path.is_some(),
            "initrd_path must be propagated to VmConfig"
        );
    }

    /// Regression: the non-linux-net direct-kernel branch previously hardcoded
    /// `req.vcpu_count.unwrap_or(1)` / `req.mem_size_mib.unwrap_or(128)` instead
    /// of consulting the daemon's configured defaults. A request that omits both
    /// fields must use the daemon defaults, not the built-in 1/128 fallback.
    #[tokio::test]
    async fn direct_kernel_applies_daemon_default_resources_when_request_omits_them() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = tmp.path().join("vmlinux");
        std::fs::write(&kernel, kernel_stub_bytes()).unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();

        let runtime_dir = tmp.path().join("run");
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&runtime_dir).unwrap();
        std::fs::create_dir_all(&data_dir).unwrap();
        let mock = MockVmm::new();
        let core = Arc::new(
            HuskerCore::new(
                mock.clone(),
                StateStore::open_memory().unwrap(),
                StorageConfig {
                    data_dir: data_dir.to_path_buf(),
                    state_dir: data_dir.to_path_buf(),
                },
                runtime_dir,
            )
            .with_default_resources(Some(512), Some(4)),
        );

        core.create_vm(CreateVmRequest {
            name: "defaults-test".into(),
            kernel_path: Some(kernel),
            rootfs_path: Some(rootfs),
            vcpu_count: None,
            mem_size_mib: None,
            initrd_path: None,
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
            ..Default::default()
        })
        .await
        .expect("create_vm should succeed with daemon defaults");

        let cfg = mock.last_config().await.expect("VmConfig was captured");
        assert_eq!(
            cfg.vcpu_count, 4,
            "daemon default_cpus=4 must be used when vcpu_count is omitted"
        );
        assert_eq!(
            cfg.mem_size_mib, 512,
            "daemon default_memory=512 must be used when mem_size_mib is omitted"
        );
    }
}
