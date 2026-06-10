#![cfg(not(feature = "linux-net"))]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use husker_core::{CoreError, CreateServiceRequest, CreateVmRequest, HuskerCore, ServiceTag};
use husker_state::{ServiceRecord, StateStore};
use husker_storage::StorageConfig;
use husker_vmm::{VmConfig, VmInfo, VmState, VmmBackend, VmmError};
use tokio::sync::Mutex;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// MockVmm - copied from orchestration_paths.rs
// ---------------------------------------------------------------------------

struct MockInner {
    vms: Mutex<HashMap<Uuid, VmInfo>>,
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
            }),
        }
    }
}

impl VmmBackend for MockVmm {
    type VsockStream = tokio::net::UnixStream;

    async fn create_vm(&self, config: VmConfig) -> Result<VmInfo, VmmError> {
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
        self.inner.vms.lock().await.insert(id, info.clone());
        Ok(info)
    }

    async fn stop_vm(&self, id: Uuid) -> Result<(), VmmError> {
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

    async fn vsock_connect(&self, _id: Uuid, _port: u32) -> Result<Self::VsockStream, VmmError> {
        Err(VmmError::ProcessError("not configured".into()))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_core(
    mock: MockVmm,
    state: StateStore,
    data_dir: &Path,
    runtime_dir: &Path,
) -> Arc<HuskerCore<MockVmm>> {
    let storage = StorageConfig {
        data_dir: data_dir.to_path_buf(),
    };
    Arc::new(HuskerCore::new(
        mock,
        state,
        storage,
        runtime_dir.to_path_buf(),
    ))
}

// Kernel fixture valid on macOS too (ARM64 Image magic 0x644d5241 at offset 56).
fn write_fixtures(dir: &Path) -> (PathBuf, PathBuf) {
    let kernel = dir.join("vmlinux");
    let mut kbytes = vec![0u8; 64];
    kbytes[56..60].copy_from_slice(&0x644d_5241u32.to_le_bytes());
    std::fs::write(&kernel, &kbytes).unwrap();
    let rootfs = dir.join("rootfs.ext4");
    std::fs::write(&rootfs, b"rootfs").unwrap();
    (kernel, rootfs)
}

fn make_service_record(
    id: Uuid,
    name: &str,
    desired: u32,
    kernel: &Path,
    rootfs: &Path,
) -> ServiceRecord {
    let now = chrono::Utc::now();
    ServiceRecord {
        id,
        name: name.into(),
        host_group_id: None,
        desired_instances: desired,
        image: None,
        kernel_path: kernel.to_string_lossy().into_owned(),
        rootfs_path: rootfs.to_string_lossy().into_owned(),
        initrd_path: None,
        vcpu_count: Some(1),
        mem_size_mib: Some(128),
        userdata: None,
        userdata_env: None,
        created_at: now,
        updated_at: now,
    }
}

fn make_core_with_fixtures(
    tmp: &tempfile::TempDir,
) -> (Arc<HuskerCore<MockVmm>>, PathBuf, PathBuf) {
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();
    let (kernel, rootfs) = write_fixtures(tmp.path());
    let core = build_core(
        MockVmm::new(),
        StateStore::open_memory().unwrap(),
        &data_dir,
        &runtime_dir,
    );
    (core, kernel, rootfs)
}

fn sorted_names(names: &[String]) -> Vec<String> {
    let mut v = names.to_vec();
    v.sort();
    v
}

fn req_with_desired(
    desired: u32,
    kernel: &std::path::Path,
    rootfs: &std::path::Path,
) -> CreateServiceRequest {
    CreateServiceRequest {
        name: "web".into(),
        host_group: None,
        desired_instances: Some(desired),
        image: None,
        rootfs_path: Some(rootfs.to_path_buf()),
        kernel_path: Some(kernel.to_path_buf()),
        initrd_path: None,
        vcpu_count: Some(1),
        mem_size_mib: Some(128),
        userdata: None,
        env: vec![],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// 1. Scale up from zero: svc desired=3, empty -> reconcile -> 3 instances all running.
#[tokio::test]
async fn reconcile_scales_up_from_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let (core, kernel, rootfs) = make_core_with_fixtures(&tmp);
    let id = Uuid::new_v4();
    let svc = make_service_record(id, "web", 3, &kernel, &rootfs);

    let outcome = core.reconcile_service(&svc).await;

    assert!(outcome.failed.is_empty(), "failed: {:?}", outcome.failed);
    assert!(outcome.destroyed.is_empty());
    let mut created = outcome.created.clone();
    created.sort();
    assert_eq!(created, vec!["web-0", "web-1", "web-2"]);

    for name in &["web-0", "web-1", "web-2"] {
        let vm = core.get_vm(name).unwrap();
        assert_eq!(vm.state, "running", "{name} should be running");
        assert_eq!(vm.service_id, Some(id));
    }
    let owned = core.list_vms_for_service(id).unwrap();
    assert_eq!(owned.len(), 3);
}

// 2. Idempotent no-op: after scaling to 3, reconcile again -> empty outcome.
#[tokio::test]
async fn reconcile_idempotent_noop() {
    let tmp = tempfile::tempdir().unwrap();
    let (core, kernel, rootfs) = make_core_with_fixtures(&tmp);
    let id = Uuid::new_v4();
    let svc = make_service_record(id, "web", 3, &kernel, &rootfs);

    core.reconcile_service(&svc).await;

    let outcome = core.reconcile_service(&svc).await;
    assert!(outcome.created.is_empty(), "created: {:?}", outcome.created);
    assert!(outcome.destroyed.is_empty());
    assert!(outcome.failed.is_empty());
}

// 3. Self-heal: stop web-1 -> reconcile -> web-1 replaced, ends running, new id.
#[tokio::test]
async fn reconcile_self_heals_stopped() {
    let tmp = tempfile::tempdir().unwrap();
    let (core, kernel, rootfs) = make_core_with_fixtures(&tmp);
    let id = Uuid::new_v4();
    let svc = make_service_record(id, "web", 2, &kernel, &rootfs);

    core.reconcile_service(&svc).await;

    let old_id = core.get_vm("web-1").unwrap().id;
    core.stop_vm("web-1").await.unwrap();
    assert_eq!(core.get_vm("web-1").unwrap().state, "stopped");

    let outcome = core.reconcile_service(&svc).await;

    assert!(outcome.failed.is_empty(), "failed: {:?}", outcome.failed);
    assert!(
        outcome.destroyed.contains(&"web-1".to_string()),
        "expected web-1 in destroyed: {:?}",
        outcome.destroyed
    );
    assert!(
        outcome.created.contains(&"web-1".to_string()),
        "expected web-1 in created: {:?}",
        outcome.created
    );

    let new_vm = core.get_vm("web-1").unwrap();
    assert_eq!(new_vm.state, "running");
    assert_ne!(new_vm.id, old_id, "replaced VM should have a new id");
    // web-0 untouched
    assert_eq!(core.get_vm("web-0").unwrap().state, "running");
}

// 4. Scale down: svc desired=3 -> reconcile; then desired=1 -> reconcile -> only web-0 remains.
#[tokio::test]
async fn reconcile_scales_down_destroys_highest() {
    let tmp = tempfile::tempdir().unwrap();
    let (core, kernel, rootfs) = make_core_with_fixtures(&tmp);
    let id = Uuid::new_v4();
    let svc3 = make_service_record(id, "web", 3, &kernel, &rootfs);
    core.reconcile_service(&svc3).await;

    let svc1 = make_service_record(id, "web", 1, &kernel, &rootfs);
    let outcome = core.reconcile_service(&svc1).await;

    assert!(outcome.failed.is_empty(), "failed: {:?}", outcome.failed);
    let mut destroyed = outcome.destroyed.clone();
    destroyed.sort();
    assert_eq!(destroyed, vec!["web-1", "web-2"]);

    assert_eq!(core.get_vm("web-0").unwrap().state, "running");
    assert!(matches!(
        core.get_vm("web-1"),
        Err(CoreError::VmNotFound(_))
    ));
    assert!(matches!(
        core.get_vm("web-2"),
        Err(CoreError::VmNotFound(_))
    ));
    let owned = core.list_vms_for_service(id).unwrap();
    assert_eq!(owned.len(), 1);
}

// 5. Foreign running collision: standalone "web-1" -> reconcile -> web-1 in failed; web-0/web-2 created.
#[tokio::test]
async fn reconcile_foreign_running_collision() {
    let tmp = tempfile::tempdir().unwrap();
    let (core, kernel, rootfs) = make_core_with_fixtures(&tmp);

    // Create a foreign running VM named "web-1"
    core.create_vm(CreateVmRequest {
        name: "web-1".into(),
        kernel_path: Some(kernel.clone()),
        rootfs_path: Some(rootfs.clone()),
        vcpu_count: Some(1),
        mem_size_mib: Some(128),
        initrd_path: None,
        userdata: None,
        env: vec![],
        vmm: None,
        cloud_image: None,
        disk_size: None,
        ssh_authorized_keys: Vec::new(),
    })
    .await
    .unwrap();
    let foreign_id = core.get_vm("web-1").unwrap().id;
    assert_eq!(core.get_vm("web-1").unwrap().service_id, None);

    let id = Uuid::new_v4();
    let svc = make_service_record(id, "web", 3, &kernel, &rootfs);
    let outcome = core.reconcile_service(&svc).await;

    // web-1 should be in failed
    let failed_names: Vec<&str> = outcome.failed.iter().map(|(n, _)| n.as_str()).collect();
    assert!(
        failed_names.contains(&"web-1"),
        "expected web-1 in failed: {:?}",
        outcome.failed
    );

    // web-0 and web-2 should be created
    let created = sorted_names(&outcome.created);
    assert_eq!(created, vec!["web-0", "web-2"]);

    // Foreign web-1 is untouched
    let foreign = core.get_vm("web-1").unwrap();
    assert_eq!(foreign.id, foreign_id);
    assert_eq!(foreign.service_id, None);
    assert_eq!(foreign.state, "running");
}

// 6. Foreign stopped collision: standalone stopped "web-1" -> reconcile -> foreign NOT destroyed.
#[tokio::test]
async fn reconcile_foreign_stopped_collision() {
    let tmp = tempfile::tempdir().unwrap();
    let (core, kernel, rootfs) = make_core_with_fixtures(&tmp);

    // Create and stop a foreign VM named "web-1"
    core.create_vm(CreateVmRequest {
        name: "web-1".into(),
        kernel_path: Some(kernel.clone()),
        rootfs_path: Some(rootfs.clone()),
        vcpu_count: Some(1),
        mem_size_mib: Some(128),
        initrd_path: None,
        userdata: None,
        env: vec![],
        vmm: None,
        cloud_image: None,
        disk_size: None,
        ssh_authorized_keys: Vec::new(),
    })
    .await
    .unwrap();
    core.stop_vm("web-1").await.unwrap();
    let foreign_id = core.get_vm("web-1").unwrap().id;

    let id = Uuid::new_v4();
    let svc = make_service_record(id, "web", 3, &kernel, &rootfs);
    let outcome = core.reconcile_service(&svc).await;

    // web-1 should be in failed (not destroyed or created)
    let failed_names: Vec<&str> = outcome.failed.iter().map(|(n, _)| n.as_str()).collect();
    assert!(
        failed_names.contains(&"web-1"),
        "expected web-1 in failed: {:?}",
        outcome.failed
    );

    // Foreign web-1 still exists with same id and service_id == None
    let foreign = core.get_vm("web-1").unwrap();
    assert_eq!(
        foreign.id, foreign_id,
        "foreign VM should not have been replaced"
    );
    assert_eq!(
        foreign.service_id, None,
        "foreign VM service_id should still be None"
    );

    // web-0 and web-2 should be created
    let created = sorted_names(&outcome.created);
    assert_eq!(created, vec!["web-0", "web-2"]);
}

// 7. Dedupe: two VMs with same (service_id, ordinal) -> reconciler keeps best, destroys other.
#[tokio::test]
async fn reconcile_dedupes_duplicate_ordinal() {
    let tmp = tempfile::tempdir().unwrap();
    let (core, kernel, rootfs) = make_core_with_fixtures(&tmp);

    let id = Uuid::new_v4();
    let svc = make_service_record(id, "web", 1, &kernel, &rootfs);

    // Create "web-0" tagged as ordinal 0
    let rec0 = core
        .create_vm_record(
            CreateVmRequest {
                name: "web-0".into(),
                kernel_path: Some(kernel.clone()),
                rootfs_path: Some(rootfs.clone()),
                vcpu_count: Some(1),
                mem_size_mib: Some(128),
                initrd_path: None,
                userdata: None,
                env: vec![],
                vmm: None,
                cloud_image: None,
                disk_size: None,
                ssh_authorized_keys: Vec::new(),
            },
            Some(ServiceTag {
                service_id: id,
                ordinal: 0,
            }),
            false,
        )
        .await
        .unwrap();

    // Create "dup-0" also tagged as ordinal 0 (bypasses unique index - index not yet created)
    let _rec_dup = core
        .create_vm_record(
            CreateVmRequest {
                name: "dup-0".into(),
                kernel_path: Some(kernel.clone()),
                rootfs_path: Some(rootfs.clone()),
                vcpu_count: Some(1),
                mem_size_mib: Some(128),
                initrd_path: None,
                userdata: None,
                env: vec![],
                vmm: None,
                cloud_image: None,
                disk_size: None,
                ssh_authorized_keys: Vec::new(),
            },
            Some(ServiceTag {
                service_id: id,
                ordinal: 0,
            }),
            false,
        )
        .await
        .unwrap();

    let pre_count = core.list_vms_for_service(id).unwrap().len();
    assert_eq!(pre_count, 2, "should have 2 VMs before reconcile");

    let outcome = core.reconcile_service(&svc).await;

    assert!(outcome.failed.is_empty(), "failed: {:?}", outcome.failed);
    // One should be destroyed (the duplicate)
    assert!(
        !outcome.destroyed.is_empty(),
        "expected a destroyed instance: {:?}",
        outcome.destroyed
    );

    let post = core.list_vms_for_service(id).unwrap();
    assert_eq!(post.len(), 1, "should have exactly 1 VM after dedup");
    assert_eq!(post[0].state, "running");

    // The survivor (web-0) is running - verify rec0 survived (it was created first/running)
    // Both were running so tie-break by created_at then id. Doesn't matter which survives as
    // long as exactly one remains.
    let _ = rec0; // suppress unused warning
}

// 8. Replace paused: svc desired=1; reconcile; pause web-0; reconcile -> web-0 running.
#[tokio::test]
async fn reconcile_replaces_paused() {
    let tmp = tempfile::tempdir().unwrap();
    let (core, kernel, rootfs) = make_core_with_fixtures(&tmp);
    let id = Uuid::new_v4();
    let svc = make_service_record(id, "web", 1, &kernel, &rootfs);

    core.reconcile_service(&svc).await;
    assert_eq!(core.get_vm("web-0").unwrap().state, "running");

    core.pause_vm("web-0").await.unwrap();
    assert_eq!(core.get_vm("web-0").unwrap().state, "paused");

    let outcome = core.reconcile_service(&svc).await;

    assert!(outcome.failed.is_empty(), "failed: {:?}", outcome.failed);
    assert!(outcome.destroyed.contains(&"web-0".to_string()));
    assert!(outcome.created.contains(&"web-0".to_string()));

    let vm = core.get_vm("web-0").unwrap();
    assert_eq!(vm.state, "running", "web-0 should be running after replace");
}

// Additional: empty rootfs path returns failed outcome without panicking.
#[tokio::test]
async fn reconcile_empty_rootfs_returns_failed() {
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

    let now = chrono::Utc::now();
    let svc = ServiceRecord {
        id: Uuid::new_v4(),
        name: "empty-svc".into(),
        host_group_id: None,
        desired_instances: 1,
        image: None,
        kernel_path: "/some/kernel".into(),
        rootfs_path: "".into(), // empty!
        initrd_path: None,
        vcpu_count: Some(1),
        mem_size_mib: Some(128),
        userdata: None,
        userdata_env: None,
        created_at: now,
        updated_at: now,
    };

    let outcome = core.reconcile_service(&svc).await;
    assert!(
        !outcome.failed.is_empty(),
        "should have a failure for empty rootfs"
    );
    assert!(outcome.created.is_empty());
    assert!(outcome.destroyed.is_empty());
}

// 10. delete_service destroys all instances then removes the service row.
#[tokio::test]
async fn delete_service_destroys_all_instances() {
    let tmp = tempfile::tempdir().unwrap();
    let (core, kernel, rootfs) = make_core_with_fixtures(&tmp);

    let (svc, _) = core
        .create_service(req_with_desired(3, &kernel, &rootfs))
        .await
        .unwrap();

    let outcome = core.delete_service("web").await.unwrap();
    assert_eq!(
        outcome.destroyed.len(),
        3,
        "expected 3 destroyed, got {:?}",
        outcome.destroyed
    );
    assert!(
        outcome.failed.is_empty(),
        "unexpected failures: {:?}",
        outcome.failed
    );
    assert!(
        matches!(core.get_service("web"), Err(CoreError::ServiceNotFound(_))),
        "service row should be gone after delete"
    );
    let remaining = core
        .list_vms()
        .unwrap()
        .into_iter()
        .filter(|v| v.service_id == Some(svc.id))
        .collect::<Vec<_>>();
    assert!(
        remaining.is_empty(),
        "no VMs should remain for the deleted service, got {:?}",
        remaining
    );
}

// 11. scale to zero keeps the service definition but destroys all instances;
//     scale back to 1 re-creates exactly one instance.
#[tokio::test]
async fn scale_to_zero_then_back() {
    let tmp = tempfile::tempdir().unwrap();
    let (core, kernel, rootfs) = make_core_with_fixtures(&tmp);

    let (_svc, _) = core
        .create_service(req_with_desired(2, &kernel, &rootfs))
        .await
        .unwrap();

    let (svc0, _) = core.scale_service("web", 0).await.unwrap();
    assert_eq!(svc0.desired_instances, 0);
    assert!(
        core.list_vms_for_service(svc0.id).unwrap().is_empty(),
        "all instances should be destroyed at desired=0"
    );
    assert!(
        core.get_service("web").is_ok(),
        "service definition must be retained at desired=0"
    );

    let (_svc1, _) = core.scale_service("web", 1).await.unwrap();
    let instances = core.list_vms_for_service(svc0.id).unwrap();
    assert_eq!(
        instances.len(),
        1,
        "expected 1 instance after scale back to 1, got {:?}",
        instances.iter().map(|v| &v.name).collect::<Vec<_>>()
    );
    assert_eq!(instances[0].state, "running");
}

// 13. daemon-restart: all instances stopped -> reconcile recreates workload at same ordinals.
#[tokio::test]
async fn restart_recreates_all_instances_at_same_ordinals() {
    let tmp = tempfile::tempdir().unwrap();
    let (core, kernel, rootfs) = make_core_with_fixtures(&tmp);

    let (svc, _) = core
        .create_service(req_with_desired(2, &kernel, &rootfs))
        .await
        .unwrap();

    let old_ids: std::collections::HashMap<u32, uuid::Uuid> = core
        .list_vms_for_service(svc.id)
        .unwrap()
        .into_iter()
        .map(|v| (v.service_ordinal.unwrap(), v.id))
        .collect();
    assert_eq!(old_ids.len(), 2);

    // Simulate a daemon restart: mark_stale_vms_stopped marks every running instance stopped.
    core.stop_vm("web-0").await.unwrap();
    core.stop_vm("web-1").await.unwrap();

    // First reconcile after the restart (the daemon does this on startup).
    let outcome = core.reconcile_service(&svc).await;

    let after: Vec<_> = core.list_vms_for_service(svc.id).unwrap();
    assert_eq!(after.len(), 2, "workload restored to 2 instances");
    let mut ords: Vec<u32> = after.iter().filter_map(|v| v.service_ordinal).collect();
    ords.sort();
    assert_eq!(ords, vec![0, 1], "same ordinals 0 and 1");
    assert!(
        after.iter().all(|v| v.state == "running"),
        "all instances running again: {:?}",
        after
            .iter()
            .map(|v| (&v.name, &v.state))
            .collect::<Vec<_>>()
    );
    // Each instance is a fresh VM (new id) since the stale one was destroyed and recreated.
    for v in &after {
        let ord = v.service_ordinal.unwrap();
        assert_ne!(v.id, old_ids[&ord], "ordinal {ord} got a fresh instance");
    }
    assert_eq!(outcome.created.len(), 2);
    assert_eq!(outcome.destroyed.len(), 2);
}

// ---------------------------------------------------------------------------
// Helpers for liveness tests
// ---------------------------------------------------------------------------

/// Creates a service with `desired_instances = 1`, reconciles once so the
/// instance is running, then returns a handle to the core, the mock backend
/// (for direct manipulation), the service record, and the temp directory
/// (caller binds it as `_tmp` to keep it alive for the test's duration).
async fn service_with_one_running_instance() -> (
    Arc<HuskerCore<MockVmm>>,
    MockVmm,
    ServiceRecord,
    tempfile::TempDir,
) {
    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();
    let (kernel, rootfs) = write_fixtures(tmp.path());

    let mock = MockVmm::new();
    let state = StateStore::open_memory().unwrap();
    let storage = StorageConfig {
        data_dir: data_dir.to_path_buf(),
    };
    let core = Arc::new(HuskerCore::new(
        mock.clone(),
        state,
        storage,
        runtime_dir.to_path_buf(),
    ));

    let (svc, _) = core
        .create_service(req_with_desired(1, &kernel, &rootfs))
        .await
        .unwrap();

    // Ensure the instance is running before returning.
    assert_eq!(core.get_vm("web-0").unwrap().state, "running");

    (core, mock, svc, tmp)
}

// 14. Guest-initiated shutdown: backend reports Stopped; reconcile replaces the instance.
#[tokio::test]
async fn guest_initiated_shutdown_is_replaced_on_reconcile() {
    let (core, mock, svc, _tmp) = service_with_one_running_instance().await;

    // Simulate the guest shutting itself down: the process exited, so the
    // backend's vm_info now reports Stopped (this is what try_wait detects
    // for a real child). The DB still says running.
    {
        let mut vms = mock.inner.vms.lock().await;
        let info = vms.values_mut().next().expect("one instance");
        info.state = VmState::Stopped;
        info.pid = None;
    }

    let outcome = core.reconcile_service(&svc).await;
    assert_eq!(
        outcome.destroyed.len(),
        1,
        "dead instance must be destroyed"
    );
    assert_eq!(outcome.created.len(), 1, "and replaced");
    let vms = core.list_vms().unwrap();
    assert_eq!(vms.len(), 1);
    assert_eq!(vms[0].state, "running");
}

// 15. Backend no longer tracks the VM at all (process long gone); reconcile replaces the instance.
#[tokio::test]
async fn backend_unknown_instance_is_replaced_on_reconcile() {
    let (core, mock, svc, _tmp) = service_with_one_running_instance().await;

    // Simulate a VM the backend no longer tracks at all (process long gone).
    mock.inner.vms.lock().await.clear();

    let outcome = core.reconcile_service(&svc).await;
    assert_eq!(outcome.destroyed.len(), 1);
    assert_eq!(outcome.created.len(), 1);
    let vms = core.list_vms().unwrap();
    assert_eq!(vms.len(), 1);
    assert_eq!(vms[0].state, "running");
}

// 12. concurrent reconcile passes on the same service do not double-create instances.
#[tokio::test]
async fn concurrent_reconcile_same_service_no_double_create() {
    let tmp = tempfile::tempdir().unwrap();
    let (core, kernel, rootfs) = make_core_with_fixtures(&tmp);

    let (svc, _) = core
        .create_service(req_with_desired(3, &kernel, &rootfs))
        .await
        .unwrap();

    // Fire two concurrent reconcile passes after the initial create already
    // produced 3 instances. Each pass should be a no-op under the lock.
    let a = {
        let c = std::sync::Arc::clone(&core);
        let s = svc.clone();
        tokio::spawn(async move { c.reconcile_service(&s).await })
    };
    let b = {
        let c = std::sync::Arc::clone(&core);
        let s = svc.clone();
        tokio::spawn(async move { c.reconcile_service(&s).await })
    };
    let _ = tokio::join!(a, b);

    let count = core.list_vms_for_service(svc.id).unwrap().len();
    assert_eq!(
        count, 3,
        "exactly 3 instances should exist after concurrent reconciles"
    );
}
