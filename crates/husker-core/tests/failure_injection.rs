//! Failure-injection tests for core lifecycle operations.
//!
//! These tests verify state-store behavior when the VMM backend fails:
//! VM state must not be mutated to the target state unless the backend
//! operation succeeds.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use husker_core::{CoreError, HuskerCore};
use husker_vmm::{
    BackendKind, CreatedVm, RestoreTarget, SnapshotMeta, SnapshotPaths, VmConfig, VmInfo, VmState,
    VmmBackend, VmmError,
};
use tokio::sync::Mutex;
use uuid::Uuid;

#[cfg(feature = "linux-net")]
#[derive(Default)]
struct TestHostNetwork {
    taps: Mutex<HashSet<String>>,
    forwards: Mutex<HashSet<(u16, String)>>,
    fail_next_create_tap: std::sync::atomic::AtomicBool,
    fail_next_attach: std::sync::atomic::AtomicBool,
    fail_next_delete_tap: std::sync::atomic::AtomicBool,
    fail_next_forward: std::sync::atomic::AtomicBool,
    fail_next_remove_forward: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "linux-net")]
impl TestHostNetwork {
    fn fail_next_create_tap(&self) {
        self.fail_next_create_tap
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn fail_next_attach(&self) {
        self.fail_next_attach
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn fail_next_delete_tap(&self) {
        self.fail_next_delete_tap
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    async fn has_tap(&self, name: &str) -> bool {
        self.taps.lock().await.contains(name)
    }

    fn fail_next_forward(&self) {
        self.fail_next_forward
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn fail_next_remove_forward(&self) {
        self.fail_next_remove_forward
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(feature = "linux-net")]
impl husker_net::HostNetwork for TestHostNetwork {
    fn create_tap<'a>(&'a self, name: &'a str) -> husker_net::NetworkFuture<'a, ()> {
        Box::pin(async move {
            self.taps.lock().await.insert(name.to_string());
            if self
                .fail_next_create_tap
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(husker_net::NetError::CommandFailed {
                    cmd: "ip link set up".into(),
                    message: "injected failure after TAP creation".into(),
                });
            }
            Ok(())
        })
    }

    fn delete_tap<'a>(&'a self, name: &'a str) -> husker_net::NetworkFuture<'a, ()> {
        Box::pin(async move {
            if self
                .fail_next_delete_tap
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(husker_net::NetError::CommandFailed {
                    cmd: "ip link delete".into(),
                    message: "injected TAP cleanup failure".into(),
                });
            }
            self.taps.lock().await.remove(name);
            Ok(())
        })
    }

    fn attach_to_bridge<'a>(
        &'a self,
        _tap_name: &'a str,
        _bridge_name: &'a str,
    ) -> husker_net::NetworkFuture<'a, ()> {
        Box::pin(async move {
            if self
                .fail_next_attach
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(husker_net::NetError::CommandFailed {
                    cmd: "ip link set master".into(),
                    message: "injected attach failure".into(),
                });
            }
            Ok(())
        })
    }

    fn add_port_forward<'a>(
        &'a self,
        host_port: u16,
        _guest_ip: std::net::Ipv4Addr,
        _guest_port: u16,
        tap_name: &'a str,
        _bridge_name: &'a str,
    ) -> husker_net::NetworkFuture<'a, ()> {
        Box::pin(async move {
            if self
                .fail_next_forward
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(husker_net::NetError::CommandFailed {
                    cmd: "nft add rule".into(),
                    message: "injected nft failure".into(),
                });
            }
            self.forwards
                .lock()
                .await
                .insert((host_port, tap_name.to_string()));
            Ok(())
        })
    }

    fn remove_port_forward<'a>(
        &'a self,
        host_port: u16,
        tap_name: &'a str,
        _bridge_name: &'a str,
    ) -> husker_net::NetworkFuture<'a, ()> {
        Box::pin(async move {
            if self
                .fail_next_remove_forward
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(husker_net::NetError::CommandFailed {
                    cmd: "nft delete rule".into(),
                    message: "injected nft cleanup failure".into(),
                });
            }
            self.forwards
                .lock()
                .await
                .remove(&(host_port, tap_name.to_string()));
            Ok(())
        })
    }

    fn remove_all_port_forwards<'a>(
        &'a self,
        tap_name: &'a str,
        _bridge_name: &'a str,
    ) -> husker_net::NetworkFuture<'a, ()> {
        Box::pin(async move {
            if self
                .fail_next_remove_forward
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(husker_net::NetError::CommandFailed {
                    cmd: "nft delete rule".into(),
                    message: "injected nft cleanup failure".into(),
                });
            }
            self.forwards
                .lock()
                .await
                .retain(|(_, tap)| tap != tap_name);
            Ok(())
        })
    }

    fn read_all_port_forward_counters<'a>(
        &'a self,
        _bridge_name: &'a str,
    ) -> husker_net::NetworkFuture<'a, HashMap<String, (u64, u64)>> {
        Box::pin(async { Ok(HashMap::new()) })
    }
}

#[cfg(feature = "linux-net")]
#[derive(Default)]
struct PreparingStorage {
    clone_calls: std::sync::atomic::AtomicUsize,
    prepare_calls: std::sync::atomic::AtomicUsize,
}

#[cfg(feature = "linux-net")]
impl husker_storage::StorageDriver for PreparingStorage {
    fn name(&self) -> &'static str {
        "preparing-test"
    }

    fn clone_rootfs<'a>(
        &'a self,
        _source: &'a std::path::Path,
        _destination: &'a std::path::Path,
    ) -> husker_storage::StorageFuture<'a, Result<(), husker_storage::StorageError>> {
        self.clone_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async {
            Err(husker_storage::StorageError::CommandFailed(
                "shallow clone path must not be used by VM creation".into(),
            ))
        })
    }

    fn prepare_root_disk<'a>(
        &'a self,
        request: husker_storage::RootDiskRequest<'a>,
    ) -> husker_storage::StorageFuture<
        'a,
        Result<Option<husker_storage::AgentRefresh>, husker_storage::StorageError>,
    > {
        self.prepare_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move {
            if let Some(parent) = request.destination.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::write(request.destination, b"prepared-disk").await?;
            Ok(None)
        })
    }
}

#[cfg(feature = "linux-net")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct OciMaterializationCall {
    reference: String,
    destination: PathBuf,
    guest_agent: Vec<u8>,
}

#[cfg(feature = "linux-net")]
#[derive(Default)]
struct RecordingOciMaterializer {
    calls: Mutex<Vec<OciMaterializationCall>>,
}

#[cfg(feature = "linux-net")]
impl husker_core::OciImageMaterializer for RecordingOciMaterializer {
    fn materialize<'a>(
        &'a self,
        request: husker_core::OciMaterializationRequest<'a>,
    ) -> husker_core::OciMaterializationFuture<'a> {
        Box::pin(async move {
            self.calls.lock().await.push(OciMaterializationCall {
                reference: request.reference.to_string(),
                destination: request.destination.to_path_buf(),
                guest_agent: request.guest_agent.to_vec(),
            });
            if let Some(parent) = request.destination.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(|error| {
                    husker_core::OciMaterializationError::Runtime(error.to_string())
                })?;
            }
            tokio::fs::write(request.destination, b"materialized OCI image")
                .await
                .map_err(|error| {
                    husker_core::OciMaterializationError::Runtime(error.to_string())
                })?;
            Ok(husker_core::MaterializedOciImage { size_bytes: 4096 })
        })
    }
}

#[cfg(feature = "linux-net")]
struct CatalogRacingOciMaterializer {
    state: husker_state::StateStore,
}

#[cfg(feature = "linux-net")]
impl husker_core::OciImageMaterializer for CatalogRacingOciMaterializer {
    fn materialize<'a>(
        &'a self,
        request: husker_core::OciMaterializationRequest<'a>,
    ) -> husker_core::OciMaterializationFuture<'a> {
        Box::pin(async move {
            if let Some(parent) = request.destination.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(|error| {
                    husker_core::OciMaterializationError::Runtime(error.to_string())
                })?;
            }
            tokio::fs::write(request.destination, b"completed artifact")
                .await
                .map_err(|error| {
                    husker_core::OciMaterializationError::Runtime(error.to_string())
                })?;
            let name = request
                .destination
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap()
                .to_string();
            self.state
                .insert_image(&husker_state::ImageRecord {
                    id: Uuid::new_v4(),
                    name,
                    source_path: "winner".into(),
                    file_path: "winner.ext4".into(),
                    format: "ext4".into(),
                    kind: "rootfs".into(),
                    boot_init: Some("/winner".into()),
                    size_bytes: 1,
                    created_at: chrono::Utc::now(),
                })
                .map_err(|error| {
                    husker_core::OciMaterializationError::Runtime(error.to_string())
                })?;
            Ok(husker_core::MaterializedOciImage { size_bytes: 4096 })
        })
    }
}

struct FailingVmm {
    vms: Mutex<HashMap<Uuid, VmInfo>>,
    fail_ops: HashSet<&'static str>,
}

impl FailingVmm {
    fn new(fail_ops: &[&'static str]) -> Self {
        Self {
            vms: Mutex::new(HashMap::new()),
            fail_ops: fail_ops.iter().copied().collect(),
        }
    }

    fn should_fail(&self, op: &'static str) -> bool {
        self.fail_ops.contains(op)
    }
}

impl VmmBackend for FailingVmm {
    type VsockStream = tokio::net::UnixStream;

    fn backend_kind(&self) -> &'static str {
        if cfg!(feature = "linux-net") {
            "firecracker"
        } else {
            "apple_vz"
        }
    }

    async fn create_vm(&self, config: VmConfig) -> Result<CreatedVm, VmmError> {
        if self.should_fail("create") {
            return Err(VmmError::ApiError("injected create failure".into()));
        }
        let id = Uuid::new_v4();
        let info = VmInfo {
            id,
            name: config.name,
            state: VmState::Running,
            pid: Some(9999),
            vcpu_count: config.vcpu_count,
            mem_size_mib: config.mem_size_mib,
            vsock_cid: config.vsock_cid,
        };
        self.vms.lock().await.insert(id, info.clone());
        let backend = if cfg!(feature = "linux-net") {
            BackendKind::Firecracker
        } else {
            BackendKind::AppleVz
        };
        Ok(CreatedVm::new(info, backend))
    }

    async fn stop_vm(&self, id: Uuid) -> Result<(), VmmError> {
        if self.should_fail("stop") {
            return Err(VmmError::ApiError("injected stop failure".into()));
        }
        let mut vms = self.vms.lock().await;
        let Some(vm) = vms.get_mut(&id) else {
            return Err(VmmError::VmNotFound(id));
        };
        vm.state = VmState::Stopped;
        Ok(())
    }

    async fn destroy_vm(&self, id: Uuid) -> Result<(), VmmError> {
        if self.should_fail("destroy") {
            return Err(VmmError::ApiError("injected destroy failure".into()));
        }
        self.vms.lock().await.remove(&id);
        Ok(())
    }

    async fn vm_info(&self, id: Uuid) -> Result<VmInfo, VmmError> {
        self.vms
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or(VmmError::VmNotFound(id))
    }

    async fn pause_vm(&self, id: Uuid) -> Result<(), VmmError> {
        if self.should_fail("pause") {
            return Err(VmmError::ApiError("injected pause failure".into()));
        }
        let mut vms = self.vms.lock().await;
        let Some(vm) = vms.get_mut(&id) else {
            return Err(VmmError::VmNotFound(id));
        };
        vm.state = VmState::Paused;
        Ok(())
    }

    async fn resume_vm(&self, id: Uuid) -> Result<(), VmmError> {
        if self.should_fail("resume") {
            return Err(VmmError::ApiError("injected resume failure".into()));
        }
        let mut vms = self.vms.lock().await;
        let Some(vm) = vms.get_mut(&id) else {
            return Err(VmmError::VmNotFound(id));
        };
        vm.state = VmState::Running;
        Ok(())
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
        Err(VmmError::VmNotFound(id))
    }

    async fn set_balloon(&self, _id: Uuid, _amount_mib: u32) -> Result<(), VmmError> {
        Ok(())
    }
}

fn core_with_vm(name: &str, state: &str, fail_ops: &[&'static str]) -> Arc<HuskerCore<FailingVmm>> {
    let vmm = FailingVmm::new(fail_ops);
    let state_store = husker_state::StateStore::open_memory().unwrap();
    let storage = husker_storage::StorageConfig {
        data_dir: PathBuf::from("/tmp/husker-failure-test"),
        state_dir: PathBuf::from("/tmp/husker-failure-test"),
    };

    let id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let record = husker_state::VmRecord {
        id,
        name: name.into(),
        state: state.parse().expect("test fixture uses a known VM state"),
        pid: Some(9999),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 3,
        tap_device: None,
        host_ip: None,
        guest_ip: None,
        kernel_path: "/boot/vmlinux".into(),
        rootfs_path: "/images/rootfs.ext4".into(),
        created_at: now,
        updated_at: now,
        userdata: None,
        userdata_status: None,
        userdata_env: None,
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
    };
    state_store.insert_vm(&record).unwrap();

    let vm_info = VmInfo {
        id,
        name: name.into(),
        state: match state {
            "running" => VmState::Running,
            "paused" => VmState::Paused,
            "stopped" => VmState::Stopped,
            _ => VmState::Failed,
        },
        pid: Some(9999),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 3,
    };
    vmm.vms.try_lock().unwrap().insert(id, vm_info);

    #[cfg(feature = "linux-net")]
    {
        Arc::new(HuskerCore::new(
            vmm,
            state_store,
            husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
            storage,
            "husker0".into(),
            vec!["8.8.8.8".into(), "1.1.1.1".into()],
            PathBuf::from("/tmp/husker-failure-test/run"),
        ))
    }
    #[cfg(not(feature = "linux-net"))]
    {
        Arc::new(HuskerCore::new(
            vmm,
            state_store,
            storage,
            PathBuf::from("/tmp/husker-failure-test/run"),
        ))
    }
}

/// A fresh core with no pre-inserted VM, whose data dir is a real temp path so
/// the create path can clone a rootfs before the (failing) vmm step.
///
#[cfg(not(feature = "linux-net"))]
fn fresh_core(
    data_dir: &std::path::Path,
    fail_ops: &[&'static str],
) -> Arc<HuskerCore<FailingVmm>> {
    let vmm = FailingVmm::new(fail_ops);
    let state_store = husker_state::StateStore::open_memory().unwrap();
    let storage = husker_storage::StorageConfig {
        data_dir: data_dir.to_path_buf(),
        state_dir: data_dir.to_path_buf(),
    };
    let runtime_dir = data_dir.join("run");
    Arc::new(HuskerCore::new(vmm, state_store, storage, runtime_dir))
}

#[cfg(feature = "linux-net")]
fn fresh_linux_core(
    data_dir: &std::path::Path,
    network: Arc<TestHostNetwork>,
) -> Arc<HuskerCore<FailingVmm>> {
    fresh_linux_core_with_state(
        data_dir,
        husker_state::StateStore::open_memory().unwrap(),
        network,
    )
}

#[cfg(feature = "linux-net")]
fn fresh_linux_core_with_state(
    data_dir: &std::path::Path,
    state: husker_state::StateStore,
    network: Arc<TestHostNetwork>,
) -> Arc<HuskerCore<FailingVmm>> {
    let storage = husker_storage::StorageConfig {
        data_dir: data_dir.to_path_buf(),
        state_dir: data_dir.to_path_buf(),
    };
    Arc::new(
        HuskerCore::new(
            FailingVmm::new(&[]),
            state,
            husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
            storage,
            "husker0".into(),
            vec![],
            data_dir.join("run"),
        )
        .with_host_network(network),
    )
}

#[cfg(feature = "linux-net")]
fn linux_boot_fixture(data_dir: &std::path::Path) -> (PathBuf, PathBuf) {
    let rootfs = data_dir.join("rootfs.ext4");
    let mut rootfs_bytes = vec![0u8; 1024 * 1024];
    rootfs_bytes[1080] = 0x53;
    rootfs_bytes[1081] = 0xef;
    std::fs::write(&rootfs, rootfs_bytes).unwrap();

    let kernel = data_dir.join("vmlinux");
    let mut kernel_bytes = vec![0u8; 128];
    kernel_bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    kernel_bytes[56..60].copy_from_slice(&0x644d_5241u32.to_le_bytes());
    std::fs::write(&kernel, kernel_bytes).unwrap();
    (kernel, rootfs)
}

#[cfg(feature = "linux-net")]
fn linux_create_request(
    name: &str,
    kernel: &std::path::Path,
    rootfs: &std::path::Path,
) -> husker_core::CreateVmRequest {
    husker_core::CreateVmRequest {
        name: name.into(),
        kernel_path: Some(kernel.to_path_buf()),
        rootfs_path: Some(rootfs.to_path_buf()),
        vcpu_count: Some(1),
        mem_size_mib: Some(128),
        ..Default::default()
    }
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn create_uses_complete_disk_preparation_boundary() {
    use std::sync::atomic::Ordering;

    let tmp = tempfile::tempdir().unwrap();
    let (kernel, rootfs) = linux_boot_fixture(tmp.path());
    let network = Arc::new(TestHostNetwork::default());
    let storage = Arc::new(PreparingStorage::default());
    let core = Arc::new(
        HuskerCore::new(
            FailingVmm::new(&[]),
            husker_state::StateStore::open_memory().unwrap(),
            husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
            husker_storage::StorageConfig {
                data_dir: tmp.path().to_path_buf(),
                state_dir: tmp.path().to_path_buf(),
            },
            "husker0".into(),
            vec![],
            tmp.path().join("run"),
        )
        .with_host_network(network)
        .with_storage_driver(storage.clone()),
    );

    core.create_vm(linux_create_request("prepared", &kernel, &rootfs))
        .await
        .unwrap();

    assert_eq!(storage.prepare_calls.load(Ordering::SeqCst), 1);
    assert_eq!(storage.clone_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        std::fs::read(tmp.path().join("vms/prepared/rootfs.ext4")).unwrap(),
        b"prepared-disk"
    );
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn oci_import_persists_only_the_materializer_result() {
    let tmp = tempfile::tempdir().unwrap();
    let materializer = Arc::new(RecordingOciMaterializer::default());
    let core = HuskerCore::new(
        FailingVmm::new(&[]),
        husker_state::StateStore::open_memory().unwrap(),
        husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
        husker_storage::StorageConfig {
            data_dir: tmp.path().to_path_buf(),
            state_dir: tmp.path().to_path_buf(),
        },
        "husker0".into(),
        vec![],
        tmp.path().join("run"),
    )
    .with_embedded_agent(b"embedded-agent")
    .with_oci_materializer(materializer.clone());

    let image = core
        .import_oci_image("web", "oci://registry.example/acme/web:v1")
        .await
        .unwrap();

    assert_eq!(image.source_path, "oci://registry.example/acme/web:v1");
    assert_eq!(image.size_bytes, 4096);
    assert_eq!(
        image.boot_init.as_deref(),
        Some("/usr/local/bin/husker-agent")
    );
    let persisted = core.get_image("web").unwrap();
    assert_eq!(persisted.id, image.id);
    assert_eq!(persisted.file_path, image.file_path);
    assert_eq!(persisted.size_bytes, image.size_bytes);
    let calls = materializer.calls.lock().await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].reference, "registry.example/acme/web:v1");
    assert_eq!(calls[0].guest_agent, b"embedded-agent");
    assert_eq!(calls[0].destination, PathBuf::from(&image.file_path));
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn oci_catalog_race_removes_the_losing_artifact() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("state.db");
    let core_state = husker_state::StateStore::open(&db_path).unwrap();
    let racing_state = husker_state::StateStore::open(&db_path).unwrap();
    let core = HuskerCore::new(
        FailingVmm::new(&[]),
        core_state,
        husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
        husker_storage::StorageConfig {
            data_dir: tmp.path().to_path_buf(),
            state_dir: tmp.path().to_path_buf(),
        },
        "husker0".into(),
        vec![],
        tmp.path().join("run"),
    )
    .with_embedded_agent(b"embedded-agent")
    .with_oci_materializer(Arc::new(CatalogRacingOciMaterializer {
        state: racing_state,
    }));
    let artifact = tmp.path().join("images/catalog/race.ext4");

    let error = core
        .import_oci_image("race", "example/race:latest")
        .await
        .unwrap_err();

    assert!(matches!(error, CoreError::ImageAlreadyExists(name) if name == "race"));
    assert!(
        !artifact.exists(),
        "the catalog loser must remove the artifact it materialized"
    );
    let winner = core.get_image("race").unwrap();
    assert_eq!(winner.source_path, "winner");
    assert_eq!(winner.file_path, "winner.ext4");
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn attach_failure_rolls_back_tap_and_ip() {
    let tmp = tempfile::tempdir().unwrap();
    let (kernel, rootfs) = linux_boot_fixture(tmp.path());

    let network = Arc::new(TestHostNetwork::default());
    network.fail_next_attach();
    let core = fresh_linux_core(tmp.path(), Arc::clone(&network));
    let request = |name: &str| linux_create_request(name, &kernel, &rootfs);

    let error = core.create_vm(request("attach-fails")).await.unwrap_err();
    assert!(matches!(error, CoreError::Network(_)), "got {error:?}");
    assert!(!network.has_tap("husker3").await);
    assert!(core.list_vms().unwrap().is_empty());

    let created = core.create_vm(request("after-rollback")).await.unwrap();
    assert_eq!(created.guest_ip.as_deref(), Some("172.20.0.2"));
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn partial_tap_creation_is_owned_and_rolled_back() {
    let tmp = tempfile::tempdir().unwrap();
    let (kernel, rootfs) = linux_boot_fixture(tmp.path());
    let network = Arc::new(TestHostNetwork::default());
    network.fail_next_create_tap();
    let core = fresh_linux_core(tmp.path(), Arc::clone(&network));

    let error = core
        .create_vm(linux_create_request("partial-tap", &kernel, &rootfs))
        .await
        .unwrap_err();
    assert!(matches!(error, CoreError::Network(_)), "got {error:?}");
    assert!(!network.has_tap("husker3").await);

    let created = core
        .create_vm(linux_create_request("after-partial", &kernel, &rootfs))
        .await
        .unwrap();
    assert_eq!(created.vsock_cid, 3);
    assert_eq!(created.guest_ip.as_deref(), Some("172.20.0.2"));
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn restart_recovers_host_resources_that_rollback_could_not_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let (kernel, rootfs) = linux_boot_fixture(tmp.path());
    let state_path = tmp.path().join("state.db");
    let network = Arc::new(TestHostNetwork::default());
    network.fail_next_attach();
    network.fail_next_delete_tap();

    let core = fresh_linux_core_with_state(
        tmp.path(),
        husker_state::StateStore::open(&state_path).unwrap(),
        Arc::clone(&network),
    );
    let error = core
        .create_vm(linux_create_request("interrupted", &kernel, &rootfs))
        .await
        .unwrap_err();
    assert!(matches!(error, CoreError::Network(_)), "got {error:?}");
    assert!(network.has_tap("husker3").await);
    drop(core);

    let restarted = fresh_linux_core_with_state(
        tmp.path(),
        husker_state::StateStore::open(&state_path).unwrap(),
        Arc::clone(&network),
    );
    assert_eq!(restarted.recover_host_resource_leases().await.unwrap(), 1);
    assert!(!network.has_tap("husker3").await);

    let created = restarted
        .create_vm(linux_create_request("after-recovery", &kernel, &rootfs))
        .await
        .unwrap();
    assert_eq!(created.vsock_cid, 3);
    assert_eq!(created.guest_ip.as_deref(), Some("172.20.0.2"));
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn recovery_attempts_all_cleanup_and_retains_the_lease_on_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let (kernel, rootfs) = linux_boot_fixture(tmp.path());
    let state_path = tmp.path().join("state.db");
    let network = Arc::new(TestHostNetwork::default());
    network.fail_next_attach();
    network.fail_next_delete_tap();

    let core = fresh_linux_core_with_state(
        tmp.path(),
        husker_state::StateStore::open(&state_path).unwrap(),
        Arc::clone(&network),
    );
    core.create_vm(linux_create_request("retry-recovery", &kernel, &rootfs))
        .await
        .unwrap_err();
    assert!(network.has_tap("husker3").await);
    drop(core);

    let restarted = fresh_linux_core_with_state(
        tmp.path(),
        husker_state::StateStore::open(&state_path).unwrap(),
        Arc::clone(&network),
    );
    network.fail_next_remove_forward();
    let error = restarted.recover_host_resource_leases().await.unwrap_err();
    assert!(matches!(error, CoreError::Network(_)), "got {error:?}");
    assert!(
        !network.has_tap("husker3").await,
        "TAP cleanup must still run after nftables cleanup fails"
    );

    assert_eq!(restarted.recover_host_resource_leases().await.unwrap(), 1);
    let created = restarted
        .create_vm(linux_create_request("after-retry", &kernel, &rootfs))
        .await
        .unwrap();
    assert_eq!(created.vsock_cid, 3);
    assert_eq!(created.guest_ip.as_deref(), Some("172.20.0.2"));
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn incomplete_rollback_does_not_reuse_live_host_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let (kernel, rootfs) = linux_boot_fixture(tmp.path());
    let network = Arc::new(TestHostNetwork::default());
    network.fail_next_attach();
    network.fail_next_delete_tap();
    let core = fresh_linux_core(tmp.path(), Arc::clone(&network));

    core.create_vm(linux_create_request("leaked", &kernel, &rootfs))
        .await
        .unwrap_err();
    let created = core
        .create_vm(linux_create_request("while-leased", &kernel, &rootfs))
        .await
        .unwrap();

    assert_eq!(created.vsock_cid, 4);
    assert_eq!(created.guest_ip.as_deref(), Some("172.20.0.3"));
    assert!(network.has_tap("husker3").await);
    assert!(network.has_tap("husker4").await);
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn nft_failure_does_not_persist_a_port_forward() {
    let tmp = tempfile::tempdir().unwrap();
    let (kernel, rootfs) = linux_boot_fixture(tmp.path());

    let network = Arc::new(TestHostNetwork::default());
    let core = fresh_linux_core(tmp.path(), Arc::clone(&network));
    core.create_vm(linux_create_request("forward-owner", &kernel, &rootfs))
        .await
        .unwrap();

    network.fail_next_forward();
    let error = core
        .add_port_forward("forward-owner", 18080, 80, None)
        .await
        .unwrap_err();
    assert!(matches!(error, CoreError::Network(_)), "got {error:?}");
    assert!(core.list_port_forwards("forward-owner").unwrap().is_empty());
    assert!(network.forwards.lock().await.is_empty());
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn nft_cleanup_failure_retains_the_port_forward_record() {
    let tmp = tempfile::tempdir().unwrap();
    let (kernel, rootfs) = linux_boot_fixture(tmp.path());
    let network = Arc::new(TestHostNetwork::default());
    let core = fresh_linux_core(tmp.path(), Arc::clone(&network));
    core.create_vm(linux_create_request("forward-owner", &kernel, &rootfs))
        .await
        .unwrap();
    core.add_port_forward("forward-owner", 18080, 80, None)
        .await
        .unwrap();

    network.fail_next_remove_forward();
    let error = core
        .remove_port_forward("forward-owner", 18080)
        .await
        .unwrap_err();

    assert!(matches!(error, CoreError::Network(_)), "got {error:?}");
    assert_eq!(core.list_port_forwards("forward-owner").unwrap().len(), 1);
    assert_eq!(network.forwards.lock().await.len(), 1);
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn destroy_cleanup_failure_retains_resource_ownership_for_retry() {
    let tmp = tempfile::tempdir().unwrap();
    let (kernel, rootfs) = linux_boot_fixture(tmp.path());
    let network = Arc::new(TestHostNetwork::default());
    let core = fresh_linux_core(tmp.path(), Arc::clone(&network));
    let created = core
        .create_vm(linux_create_request("cleanup-retry", &kernel, &rootfs))
        .await
        .unwrap();

    network.fail_next_delete_tap();
    let error = core.destroy_vm("cleanup-retry").await.unwrap_err();
    assert!(matches!(error, CoreError::Network(_)), "got {error:?}");
    let retained = core.get_vm("cleanup-retry").unwrap();
    assert_eq!(retained.state, "stopped");
    assert_eq!(retained.vsock_cid, created.vsock_cid);
    assert_eq!(retained.tap_device, created.tap_device);
    assert_eq!(retained.guest_ip, created.guest_ip);

    core.destroy_vm("cleanup-retry").await.unwrap();
    assert!(matches!(
        core.get_vm("cleanup-retry"),
        Err(CoreError::VmNotFound(_))
    ));
    let replacement = core
        .create_vm(linux_create_request("after-destroy", &kernel, &rootfs))
        .await
        .unwrap();
    assert_eq!(replacement.vsock_cid, created.vsock_cid);
    assert_eq!(replacement.guest_ip, created.guest_ip);
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn reclaim_cleanup_failure_keeps_the_vm_resource_fields_for_retry() {
    let tmp = tempfile::tempdir().unwrap();
    let (kernel, rootfs) = linux_boot_fixture(tmp.path());
    let network = Arc::new(TestHostNetwork::default());
    let core = fresh_linux_core(tmp.path(), Arc::clone(&network));
    let created = core
        .create_vm(linux_create_request("reclaim-retry", &kernel, &rootfs))
        .await
        .unwrap();
    core.stop_vm("reclaim-retry").await.unwrap();

    network.fail_next_delete_tap();
    assert_eq!(core.reclaim_abandoned_vms(0).await, 0);
    let retained = core.get_vm("reclaim-retry").unwrap();
    assert_eq!(retained.tap_device, created.tap_device);
    assert_eq!(retained.guest_ip, created.guest_ip);

    assert_eq!(core.reclaim_abandoned_vms(0).await, 1);
    let reclaimed = core.get_vm("reclaim-retry").unwrap();
    assert_eq!(reclaimed.tap_device, None);
    assert_eq!(reclaimed.guest_ip, None);
}

#[cfg(not(feature = "linux-net"))]
#[tokio::test]
async fn create_failure_rolls_back_and_leaves_no_vm_record() {
    // FailingVmm fails create AFTER the core has allocated resources (CID, vm_dir,
    // vm_id). The AllocatedResources rollback must unwind them so no partial VM
    // record is left behind.
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path().join("rootfs.ext4");
    // A 1 MiB file with the ext4 superblock magic (0xEF53 at byte offset 1080)
    // so rootfs validation passes and create reaches the (failing) vmm step.
    let mut rbytes = vec![0u8; 1024 * 1024];
    rbytes[1080] = 0x53;
    rbytes[1081] = 0xef;
    std::fs::write(&rootfs, &rbytes).unwrap();
    // A kernel large enough with the ARM64 Image magic at offset 56 (VZ) / an ELF
    // header (Linux) so kernel validation passes on either backend.
    let kernel = tmp.path().join("vmlinux");
    let mut kbytes = vec![0u8; 128];
    kbytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']); // ELF magic (Linux)
    kbytes[56..60].copy_from_slice(&0x644d_5241u32.to_le_bytes()); // ARM64 Image magic (VZ)
    std::fs::write(&kernel, &kbytes).unwrap();

    let core = fresh_core(tmp.path(), &["create"]);
    let err = core
        .create_vm(husker_core::CreateVmRequest {
            name: "doomed".into(),
            kernel_path: Some(kernel),
            rootfs_path: Some(rootfs),
            vcpu_count: Some(1),
            mem_size_mib: Some(128),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, CoreError::Vmm(VmmError::ApiError(_))),
        "expected the injected vmm create failure, got {err:?}"
    );
    assert!(
        core.list_vms().unwrap().is_empty(),
        "a failed create must roll back its VM record, not leak it"
    );
    assert!(
        core.get_vm("doomed").is_err(),
        "the rolled-back VM must not be looked up"
    );
}

#[tokio::test]
async fn stop_failure_keeps_vm_running_in_state_store() {
    let core = core_with_vm("vm-stop-fail", "running", &["stop"]);
    let err = core.stop_vm("vm-stop-fail").await.unwrap_err();
    assert!(matches!(err, CoreError::Vmm(VmmError::ApiError(_))));
    assert_eq!(core.get_vm("vm-stop-fail").unwrap().state, "running");
}

#[tokio::test]
async fn pause_failure_keeps_vm_running_in_state_store() {
    let core = core_with_vm("vm-pause-fail", "running", &["pause"]);
    let err = core.pause_vm("vm-pause-fail").await.unwrap_err();
    assert!(matches!(err, CoreError::Vmm(VmmError::ApiError(_))));
    assert_eq!(core.get_vm("vm-pause-fail").unwrap().state, "running");
}

#[tokio::test]
async fn resume_failure_keeps_vm_paused_in_state_store() {
    let core = core_with_vm("vm-resume-fail", "paused", &["resume"]);
    let err = core.resume_vm("vm-resume-fail").await.unwrap_err();
    assert!(matches!(err, CoreError::Vmm(VmmError::ApiError(_))));
    assert_eq!(core.get_vm("vm-resume-fail").unwrap().state, "paused");
}

#[tokio::test]
async fn destroy_failure_keeps_vm_record_present() {
    let core = core_with_vm("vm-destroy-fail", "running", &["destroy"]);
    let err = core.destroy_vm("vm-destroy-fail").await.unwrap_err();
    assert!(matches!(err, CoreError::Vmm(VmmError::ApiError(_))));
    assert_eq!(core.get_vm("vm-destroy-fail").unwrap().state, "running");
}
