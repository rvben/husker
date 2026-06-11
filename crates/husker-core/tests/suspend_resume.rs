//! Suspend/resume round-trip tests for HuskerCore.
//!
//! Uses a RecordingVmm that tracks which VMM calls were made and writes
//! real snapshot artifacts to a tempdir, so the full suspend->resume code
//! path executes without a real Firecracker process.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use husker_core::HuskerCore;
use husker_vmm::{
    RestoreTarget, SnapshotMeta, SnapshotPaths, VmConfig, VmInfo, VmState, VmmBackend, VmmError,
};
use uuid::Uuid;

#[derive(Default)]
struct Calls {
    snapshot: Vec<Uuid>,
    restore: Vec<Uuid>,
    destroyed: Vec<Uuid>,
}

struct RecordingVmm {
    vms: Mutex<HashMap<Uuid, VmInfo>>,
    calls: Mutex<Calls>,
}

impl RecordingVmm {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            vms: Mutex::new(HashMap::new()),
            calls: Mutex::new(Calls::default()),
        })
    }
}

/// Newtype so we can implement `VmmBackend` for a shared `Arc<RecordingVmm>`
/// without violating the orphan rule (Arc is foreign, VmmBackend is foreign).
struct SharedRecordingVmm(Arc<RecordingVmm>);

impl VmmBackend for SharedRecordingVmm {
    type VsockStream = tokio::net::UnixStream;

    async fn create_vm(&self, _config: VmConfig) -> Result<VmInfo, VmmError> {
        Err(VmmError::Unsupported("not used".into()))
    }

    async fn stop_vm(&self, _id: Uuid) -> Result<(), VmmError> {
        Ok(())
    }

    async fn destroy_vm(&self, id: Uuid) -> Result<(), VmmError> {
        self.0.calls.lock().unwrap().destroyed.push(id);
        self.0.vms.lock().unwrap().remove(&id);
        Ok(())
    }

    async fn vm_info(&self, id: Uuid) -> Result<VmInfo, VmmError> {
        self.0
            .vms
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or(VmmError::VmNotFound(id))
    }

    async fn pause_vm(&self, id: Uuid) -> Result<(), VmmError> {
        if let Some(i) = self.0.vms.lock().unwrap().get_mut(&id) {
            i.state = VmState::Paused;
        }
        Ok(())
    }

    async fn resume_vm(&self, id: Uuid) -> Result<(), VmmError> {
        if let Some(i) = self.0.vms.lock().unwrap().get_mut(&id) {
            i.state = VmState::Running;
        }
        Ok(())
    }

    async fn snapshot_vm(&self, id: Uuid, dst: &SnapshotPaths) -> Result<SnapshotMeta, VmmError> {
        std::fs::create_dir_all(&dst.dir).unwrap();
        std::fs::write(&dst.memory, b"mem").unwrap();
        std::fs::write(&dst.vmstate, b"state").unwrap();
        self.0.calls.lock().unwrap().snapshot.push(id);
        Ok(SnapshotMeta {
            backend: "firecracker".into(),
            vmm_version: "test".into(),
        })
    }

    async fn restore_vm(
        &self,
        src: &SnapshotPaths,
        target: RestoreTarget,
    ) -> Result<VmInfo, VmmError> {
        assert!(
            src.memory.exists(),
            "restore must see the captured memory file"
        );
        let RestoreTarget::Resume {
            id,
            name,
            vcpu_count,
            mem_size_mib,
            vsock_cid,
        } = target;
        let info = VmInfo {
            id,
            name,
            state: VmState::Running,
            pid: Some(1234),
            vcpu_count,
            mem_size_mib,
            vsock_cid,
        };
        self.0.vms.lock().unwrap().insert(id, info.clone());
        self.0.calls.lock().unwrap().restore.push(id);
        Ok(info)
    }

    async fn vsock_connect(&self, id: Uuid, _port: u32) -> Result<Self::VsockStream, VmmError> {
        Err(VmmError::VmNotFound(id))
    }

    async fn set_balloon(&self, _id: Uuid, _amount_mib: u32) -> Result<(), VmmError> {
        Ok(())
    }
}

/// Build a core backed by RecordingVmm with a pre-populated running VM record.
///
/// Mirrors the body of `mock_core_with_vm` from `tests/state_transitions.rs`,
/// replacing MockVmm with SharedRecordingVmm (a newtype over Arc<RecordingVmm>)
/// and using a real tempdir for data_dir so suspend-slot writes succeed.
fn core_with_running_vm(
    name: &str,
) -> (
    Arc<HuskerCore<SharedRecordingVmm>>,
    Arc<RecordingVmm>,
    Uuid,
    tempfile::TempDir,
) {
    let tmp = tempfile::tempdir().unwrap();
    let inner = RecordingVmm::new();
    let vmm = SharedRecordingVmm(Arc::clone(&inner));
    let state_store = husker_state::StateStore::open_memory().unwrap();
    let storage = husker_storage::StorageConfig {
        data_dir: tmp.path().to_path_buf(),
    };

    let now = chrono::Utc::now();
    let id = Uuid::new_v4();
    let record = husker_state::VmRecord {
        id,
        name: name.into(),
        state: "running".into(),
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
    };
    state_store.insert_vm(&record).unwrap();

    // Also insert the VM into the recording VMM so it can find it by ID.
    let vm_info = VmInfo {
        id,
        name: name.into(),
        state: VmState::Running,
        pid: Some(9999),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 3,
    };
    inner.vms.lock().unwrap().insert(id, vm_info);

    #[cfg(feature = "linux-net")]
    let core = Arc::new(HuskerCore::new(
        vmm,
        state_store,
        husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
        storage,
        "husker0".into(),
        vec!["8.8.8.8".into(), "1.1.1.1".into()],
        tmp.path().join("run"),
    ));
    #[cfg(not(feature = "linux-net"))]
    let core = Arc::new(HuskerCore::new(
        vmm,
        state_store,
        storage,
        tmp.path().join("run"),
    ));

    (core, inner, id, tmp)
}

#[tokio::test]
async fn suspend_then_resume_round_trips() {
    let (core, vmm, id, tmp) = core_with_running_vm("vm1");

    core.suspend_vm("vm1").await.unwrap();

    let rec = core
        .list_vms()
        .unwrap()
        .into_iter()
        .find(|v| v.id == id)
        .unwrap();
    assert_eq!(rec.state, "suspended");

    // Suspend slot must exist after suspend.
    let slot = tmp.path().join("suspend").join(id.to_string());
    assert!(slot.exists(), "suspend slot should exist after suspend");

    // VMM recorded one snapshot and one destroy (to terminate the process).
    {
        let calls = vmm.calls.lock().unwrap();
        assert_eq!(calls.snapshot.len(), 1, "snapshot should be called once");
        assert!(
            calls.destroyed.contains(&id),
            "destroy should be called during suspend"
        );
    }

    core.resume_vm("vm1").await.unwrap();

    let rec = core
        .list_vms()
        .unwrap()
        .into_iter()
        .find(|v| v.id == id)
        .unwrap();
    assert_eq!(rec.state, "running");

    // Slot must be cleaned up after resume.
    assert!(
        !slot.exists(),
        "suspend slot should be removed after resume"
    );

    // VMM recorded one restore.
    let calls = vmm.calls.lock().unwrap();
    assert_eq!(
        calls.restore.len(),
        1,
        "restore should be called once during resume"
    );
}

#[tokio::test]
async fn stop_on_suspended_discards_slot() {
    let (core, vmm, id, tmp) = core_with_running_vm("vm2");

    core.suspend_vm("vm2").await.unwrap();
    core.stop_vm("vm2").await.unwrap();

    let rec = core
        .list_vms()
        .unwrap()
        .into_iter()
        .find(|v| v.id == id)
        .unwrap();
    assert_eq!(rec.state, "stopped");

    // Slot must be cleaned up after stop.
    let slot = tmp.path().join("suspend").join(id.to_string());
    assert!(!slot.exists(), "suspend slot should be removed after stop");

    // Snapshot was called once (during suspend); restore was never called.
    let calls = vmm.calls.lock().unwrap();
    assert_eq!(calls.snapshot.len(), 1, "snapshot should be called once");
    assert_eq!(
        calls.restore.len(),
        0,
        "restore should not be called on stop"
    );
}

#[tokio::test]
async fn destroy_on_suspended_cleans_up() {
    let (core, _vmm, id, tmp) = core_with_running_vm("vm3");
    core.suspend_vm("vm3").await.unwrap();
    let slot = tmp.path().join("suspend").join(id.to_string());
    assert!(slot.exists(), "slot should exist after suspend");
    core.destroy_vm("vm3").await.unwrap();
    assert!(
        core.list_vms().unwrap().iter().all(|v| v.id != id),
        "VM should be gone after destroy"
    );
    assert!(!slot.exists(), "slot should be removed by destroy");
}
