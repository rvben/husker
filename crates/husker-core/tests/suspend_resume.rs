//! Suspend/resume round-trip tests for HuskerCore.
//!
//! Uses a RecordingVmm that tracks which VMM calls were made and writes
//! real snapshot artifacts to a tempdir, so the full suspend->resume code
//! path executes without a real Firecracker process.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use husker_core::{
    BackendKind, CoreError, CreatePoolRequest, HuskerCore, NetworkMode, VmLifecycleState,
};
use husker_vmm::{
    CreatedVm, RestoreTarget, SnapshotMeta, SnapshotPaths, VmConfig, VmInfo, VmState, VmmBackend,
    VmmError,
};
use uuid::Uuid;

#[derive(Default)]
struct Calls {
    paused: Vec<Uuid>,
    snapshot: Vec<Uuid>,
    restore: Vec<Uuid>,
    destroyed: Vec<Uuid>,
}

struct RecordingVmm {
    vms: Mutex<HashMap<Uuid, VmInfo>>,
    calls: Mutex<Calls>,
    snapshot_gate: Mutex<Option<Arc<SnapshotGate>>>,
    /// When set, `snapshot_vm` returns an error, to exercise capture-failure
    /// rollback in suspend.
    fail_snapshot: std::sync::atomic::AtomicBool,
}

#[derive(Default)]
struct SnapshotGate {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl RecordingVmm {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            vms: Mutex::new(HashMap::new()),
            calls: Mutex::new(Calls::default()),
            snapshot_gate: Mutex::new(None),
            fail_snapshot: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn block_next_snapshot(&self) -> Arc<SnapshotGate> {
        let gate = Arc::new(SnapshotGate::default());
        *self.snapshot_gate.lock().unwrap() = Some(Arc::clone(&gate));
        gate
    }
}

/// Newtype so we can implement `VmmBackend` for a shared `Arc<RecordingVmm>`
/// without violating the orphan rule (Arc is foreign, VmmBackend is foreign).
struct SharedRecordingVmm(Arc<RecordingVmm>);

impl VmmBackend for SharedRecordingVmm {
    type VsockStream = tokio::net::UnixStream;

    async fn create_vm(
        &self,
        _selection: husker_vmm::BackendSelection,
        _config: VmConfig,
    ) -> Result<CreatedVm, VmmError> {
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
        self.0.calls.lock().unwrap().paused.push(id);
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
        self.0.calls.lock().unwrap().snapshot.push(id);
        let gate = { self.0.snapshot_gate.lock().unwrap().take() };
        if let Some(gate) = gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        if self
            .0
            .fail_snapshot
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(VmmError::ProcessError("injected snapshot failure".into()));
        }
        std::fs::create_dir_all(&dst.dir).unwrap();
        std::fs::write(&dst.memory, b"mem").unwrap();
        std::fs::write(&dst.vmstate, b"state").unwrap();
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
        let (RestoreTarget::Resume {
            id,
            name,
            vcpu_count,
            mem_size_mib,
            vsock_cid,
        }
        | RestoreTarget::Fork {
            id,
            name,
            vcpu_count,
            mem_size_mib,
            vsock_cid,
            ..
        }) = target;
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
    core_with_running_vm_backend(name, "firecracker")
}

/// Like `core_with_running_vm` but lets the test pick the persisted backend kind
/// (`"firecracker"`, `"qemu"`, `"apple_vz"`), which drives capability gating.
fn core_with_running_vm_backend(
    name: &str,
    vmm_kind: &str,
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
        state_dir: tmp.path().to_path_buf(),
    };

    let now = chrono::Utc::now();
    let id = Uuid::new_v4();
    let record = husker_state::VmRecord {
        id,
        name: name.into(),
        state: VmLifecycleState::Running,
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
        vmm: vmm_kind.parse().expect("test backend kind must be valid"),
        boot_mode: husker_core::BootKind::DirectKernel,
        balloon: false,
        volume: None,
        network: NetworkMode::Nat,
        last_activity_at: now,
        suspended_at: None,
        idle_timeout_secs: None,
        suspend_ttl_secs: None,
        auto_resume: true,
        forked_from: None,
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

/// Build a core plus a handle to its state store and a VM in an arbitrary
/// persisted `state`, so reconciliation/recovery paths can be set up directly.
fn core_store_with_vm(
    name: &str,
    state: &str,
) -> (Arc<HuskerCore<SharedRecordingVmm>>, Uuid, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let inner = RecordingVmm::new();
    let vmm = SharedRecordingVmm(Arc::clone(&inner));
    let state_store = husker_state::StateStore::open_memory().unwrap();
    let storage = husker_storage::StorageConfig {
        data_dir: tmp.path().to_path_buf(),
        state_dir: tmp.path().to_path_buf(),
    };
    let now = chrono::Utc::now();
    let id = Uuid::new_v4();
    let record = husker_state::VmRecord {
        id,
        name: name.into(),
        state: state.parse().expect("test fixture uses a known VM state"),
        pid: Some(4242),
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
        vmm: BackendKind::Firecracker,
        boot_mode: husker_core::BootKind::DirectKernel,
        balloon: false,
        volume: None,
        network: NetworkMode::Nat,
        last_activity_at: now,
        suspended_at: None,
        idle_timeout_secs: None,
        suspend_ttl_secs: None,
        auto_resume: true,
        forked_from: None,
    };
    state_store.insert_vm(&record).unwrap();

    #[cfg(feature = "linux-net")]
    let core = Arc::new(HuskerCore::new(
        vmm,
        state_store,
        husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
        storage,
        "husker0".into(),
        vec!["8.8.8.8".into()],
        tmp.path().join("run"),
    ));
    #[cfg(not(feature = "linux-net"))]
    let core = Arc::new(HuskerCore::new(
        vmm,
        state_store,
        storage,
        tmp.path().join("run"),
    ));
    (core, id, tmp)
}

/// Read a VM's persisted state via the core's plain (non-refreshed) listing.
fn vm_state(core: &HuskerCore<SharedRecordingVmm>, id: Uuid) -> String {
    core.list_vms()
        .unwrap()
        .into_iter()
        .find(|v| v.id == id)
        .map(|v| v.state.to_string())
        .unwrap_or_else(|| "<missing>".into())
}

/// Write a valid suspend slot (manifest + vmstate + memory) for `id`.
fn write_valid_suspend_slot(data_dir: &std::path::Path, id: Uuid) {
    let slot = data_dir.join("suspend").join(id.to_string());
    std::fs::create_dir_all(&slot).unwrap();
    std::fs::write(slot.join("memory"), b"mem").unwrap();
    std::fs::write(slot.join("vmstate"), b"state").unwrap();
    std::fs::write(
        slot.join("manifest.json"),
        serde_json::to_vec(&serde_json::json!({
            "kind": "full",
            "backend": "firecracker",
            "vmm_version": "test",
            "vcpu_count": 1,
            "mem_size_mib": 128,
            "vsock_cid": 3,
            "rootfs_path": "/images/rootfs.ext4",
        }))
        .unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn reconcile_completes_interrupted_suspend() {
    // A daemon crash after the memory is freed but before the state write leaves
    // the VM in "suspending" with a valid slot. Reconciliation must finish the
    // transition to "suspended" so the VM stays resumable (not unrecoverable).
    let (core, id, tmp) = core_store_with_vm("vmint", "suspending");
    write_valid_suspend_slot(tmp.path(), id);

    let n = core.reconcile_suspended_vms().await.unwrap();
    assert_eq!(n, 1, "one interrupted suspend should be reconciled");

    assert_eq!(
        vm_state(&core, id),
        "suspended",
        "a 'suspending' VM with a valid slot must become 'suspended'"
    );
    let recovered = core.get_vm("vmint").unwrap();
    assert_eq!(
        recovered.pid, None,
        "completed suspend recovery must retire the interrupted VMM identity"
    );
}

#[tokio::test]
async fn reconcile_drops_suspending_without_slot() {
    // "suspending" with no valid slot means the snapshot never completed; the
    // memory state is unrecoverable, so the VM must fall back to "stopped"
    // (consistent, re-runnable) rather than be stuck in "suspending" forever.
    let (core, id, _tmp) = core_store_with_vm("vmnoslot", "suspending");

    let n = core.reconcile_suspended_vms().await.unwrap();
    assert_eq!(n, 1, "the orphaned suspending VM should be reconciled");

    assert_eq!(
        vm_state(&core, id),
        "stopped",
        "a 'suspending' VM without a valid slot must fall back to 'stopped'"
    );
    let recovered = core.get_vm("vmnoslot").unwrap();
    assert_eq!(
        recovered.pid, None,
        "failed suspend recovery must retire the interrupted VMM identity"
    );
}

#[tokio::test]
async fn recover_stranded_fork_rootfs_restores_source_disk() {
    // A fork that crashed mid-load leaves the source VM's rootfs as a stale
    // symlink to the fork clone, with the real disk in `.fork-src-bak`. Startup
    // recovery must restore the real disk at the exact path fork uses, so a
    // later resume does not load the wrong disk.
    let (core, id, tmp) = core_store_with_vm("vmsrc", "suspended");
    let vm_dir = tmp.path().join("vms").join("vmsrc");
    std::fs::create_dir_all(&vm_dir).unwrap();
    let rootfs = vm_dir.join("rootfs.ext4");
    let clone = tmp.path().join("clone.ext4");
    let backup = vm_dir.join("rootfs.ext4.fork-src-bak");
    std::fs::write(&clone, b"fork-disk").unwrap();
    std::fs::write(&backup, b"real-source-disk").unwrap();
    std::os::unix::fs::symlink(&clone, &rootfs).unwrap();
    let _ = id;

    let n = core.recover_stranded_fork_rootfs();
    assert_eq!(n, 1, "one stranded source rootfs should be recovered");
    assert!(!backup.exists(), "backup must be consumed");
    assert_eq!(
        std::fs::read(&rootfs).unwrap(),
        b"real-source-disk",
        "source rootfs must hold the real disk, not the fork clone"
    );
}

#[tokio::test]
async fn suspend_capture_failure_restores_original_state() {
    // If capture fails after the VM is moved to the transient "suspending" state,
    // suspend must roll the state back (and resume the VMM) so the VM is left
    // exactly as it was - never stranded in "suspending" with no slot.
    let (core, vmm, id, tmp) = core_with_running_vm("vmfail");
    vmm.fail_snapshot
        .store(true, std::sync::atomic::Ordering::SeqCst);

    let err = core.suspend_vm("vmfail").await.unwrap_err();
    assert!(
        err.to_string().contains("injected"),
        "expected the injected snapshot failure, got: {err}"
    );

    assert_eq!(
        vm_state(&core, id),
        "running",
        "a failed suspend must restore the original 'running' state, not leave 'suspending'"
    );
    let slot = tmp.path().join("suspend").join(id.to_string());
    assert!(
        !slot.exists(),
        "a failed suspend must not leave a slot behind"
    );
    assert!(
        vmm.calls.lock().unwrap().paused.contains(&id),
        "the VM was paused during the attempt"
    );
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

#[tokio::test(flavor = "current_thread")]
async fn stop_waiting_behind_suspend_retires_the_suspended_generation() {
    let (core, vmm, id, tmp) = core_with_running_vm("stop-suspend-race");
    let gate = vmm.block_next_snapshot();

    let suspending_core = Arc::clone(&core);
    let suspend =
        tokio::spawn(async move { suspending_core.suspend_vm("stop-suspend-race").await });
    gate.entered.notified().await;

    let stopping_core = Arc::clone(&core);
    let stop = tokio::spawn(async move { stopping_core.stop_vm("stop-suspend-race").await });
    tokio::task::yield_now().await;

    gate.release.notify_one();
    suspend.await.unwrap().unwrap();
    stop.await.unwrap().unwrap();

    let stopped = core.get_vm("stop-suspend-race").unwrap();
    assert_eq!(stopped.id, id);
    assert_eq!(stopped.state, "stopped");
    assert_eq!(stopped.pid, None);
    assert_eq!(stopped.suspended_at, None);
    assert!(
        !tmp.path().join("suspend").join(id.to_string()).exists(),
        "the later stop must discard the completed suspend slot"
    );
}

#[tokio::test]
async fn suspend_on_unsupported_backend_fails_fast() {
    // QEMU has no full-state snapshot, so suspend must be rejected *before* the
    // VM is paused or any snapshot is attempted - not discovered mid-flight after
    // a pause that then has to be rolled back.
    let (core, vmm, id, _tmp) = core_with_running_vm_backend("vmq", "qemu");

    let err = core.suspend_vm("vmq").await.unwrap_err();
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("suspend") && (msg.contains("not support") || msg.contains("unsupported")),
        "expected a clear suspend-unsupported message, got: {err}"
    );

    {
        let calls = vmm.calls.lock().unwrap();
        assert!(
            calls.paused.is_empty(),
            "VM must not be paused on a fail-fast suspend rejection"
        );
        assert!(
            calls.snapshot.is_empty(),
            "snapshot must not be attempted on an unsupported backend"
        );
    }

    // The VM is untouched and still running.
    let rec = core
        .list_vms()
        .unwrap()
        .into_iter()
        .find(|v| v.id == id)
        .unwrap();
    assert_eq!(
        rec.state, "running",
        "VM must remain running after a rejected suspend"
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

// ── Hot pools ──────────────────────────────────────────────────────────────
// The warm + fork happy path of create_pool/checkout_pool needs a live agent and
// a real create_vm, which the RecordingVmm stubs out (that path is covered by the
// real-Firecracker pool e2e gate). These cover the orchestration the mock CAN
// reach: CRUD, error mapping, and the delete teardown.

/// Build a core with a hot pool already recorded: a suspended template VM named
/// after the pool plus the pool row pointing at it.
fn core_with_pool(
    pool_name: &str,
) -> (
    Arc<HuskerCore<SharedRecordingVmm>>,
    Arc<RecordingVmm>,
    tempfile::TempDir,
) {
    core_with_named_pool_template(pool_name, pool_name)
}

fn core_with_named_pool_template(
    pool_name: &str,
    template_name: &str,
) -> (
    Arc<HuskerCore<SharedRecordingVmm>>,
    Arc<RecordingVmm>,
    tempfile::TempDir,
) {
    let tmp = tempfile::tempdir().unwrap();
    let inner = RecordingVmm::new();
    let vmm = SharedRecordingVmm(Arc::clone(&inner));
    let state_store = husker_state::StateStore::open_memory().unwrap();
    let storage = husker_storage::StorageConfig {
        data_dir: tmp.path().to_path_buf(),
        state_dir: tmp.path().to_path_buf(),
    };
    let now = chrono::Utc::now();
    let template_id = Uuid::new_v4();
    let template = husker_state::VmRecord {
        id: template_id,
        name: template_name.into(),
        state: VmLifecycleState::Suspended,
        pid: None,
        vcpu_count: 1,
        mem_size_mib: 512,
        vsock_cid: 3,
        tap_device: None,
        host_ip: None,
        guest_ip: None,
        kernel_path: "/boot/vmlinux".into(),
        rootfs_path: "/images/base.ext4".into(),
        created_at: now,
        updated_at: now,
        userdata: None,
        userdata_status: None,
        userdata_env: None,
        service_id: None,
        service_ordinal: None,
        vmm: BackendKind::Firecracker,
        boot_mode: husker_core::BootKind::DirectKernel,
        balloon: false,
        volume: None,
        network: NetworkMode::Nat,
        last_activity_at: now,
        suspended_at: None,
        idle_timeout_secs: None,
        suspend_ttl_secs: None,
        auto_resume: true,
        forked_from: None,
    };
    state_store.insert_vm(&template).unwrap();
    state_store
        .insert_pool(&husker_state::PoolRecord {
            id: Uuid::new_v4(),
            name: pool_name.into(),
            template_vm_id: template_id,
            rootfs_path: "/images/base.ext4".into(),
            kernel_path: "/boot/vmlinux".into(),
            initrd_path: None,
            vcpu_count: Some(1),
            mem_size_mib: Some(512),
            created_at: now,
            updated_at: now,
        })
        .unwrap();
    inner.vms.lock().unwrap().insert(
        template_id,
        VmInfo {
            id: template_id,
            name: template_name.into(),
            state: VmState::Running,
            pid: Some(1),
            vcpu_count: 1,
            mem_size_mib: 512,
            vsock_cid: 3,
        },
    );

    #[cfg(feature = "linux-net")]
    let core = Arc::new(HuskerCore::new(
        vmm,
        state_store,
        husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
        storage,
        "husker0".into(),
        vec!["8.8.8.8".into()],
        tmp.path().join("run"),
    ));
    #[cfg(not(feature = "linux-net"))]
    let core = Arc::new(HuskerCore::new(
        vmm,
        state_store,
        storage,
        tmp.path().join("run"),
    ));
    (core, inner, tmp)
}

fn create_pool_req(name: &str) -> CreatePoolRequest {
    CreatePoolRequest {
        name: name.into(),
        rootfs_path: Some("/images/base.ext4".into()),
        kernel_path: None,
        initrd_path: None,
        vcpu_count: None,
        mem_size_mib: None,
    }
}

#[tokio::test]
async fn pool_get_and_list() {
    let (core, _vmm, _tmp) = core_with_pool("web");
    let got = core.get_pool("web").unwrap();
    assert_eq!(got.name, "web");
    assert_eq!(got.rootfs_path, "/images/base.ext4");
    assert_eq!(core.list_pools().unwrap().len(), 1);
    assert!(matches!(core.get_pool("nope"), Err(CoreError::PoolNotFound(n)) if n == "nope"));
}

#[tokio::test]
async fn create_pool_rejects_duplicate_name() {
    let (core, _vmm, _tmp) = core_with_pool("web");
    // The duplicate guard fires before the VMM is touched, so this is reachable
    // even though create_vm is stubbed.
    let err = core.create_pool(create_pool_req("web")).await.unwrap_err();
    assert!(matches!(err, CoreError::PoolAlreadyExists(n) if n == "web"));
}

#[tokio::test]
async fn delete_pool_destroys_template_and_removes_record() {
    let (core, vmm, _tmp) = core_with_pool("web");
    core.delete_pool("web").await.unwrap();
    assert!(matches!(
        core.get_pool("web"),
        Err(CoreError::PoolNotFound(_))
    ));
    assert!(core.list_pools().unwrap().is_empty());
    assert_eq!(
        vmm.calls.lock().unwrap().destroyed.len(),
        1,
        "the template VM must be destroyed when the pool is deleted"
    );
}

#[tokio::test]
async fn direct_destroy_cannot_orphan_a_pool_template() {
    let (core, vmm, _tmp) = core_with_pool("web");

    let error = core.destroy_vm("web").await.unwrap_err();

    assert!(
        matches!(error, CoreError::PoolTemplateOwned { ref vm, ref pool }
            if vm == "web" && pool == "web"),
        "got {error:?}"
    );
    assert_eq!(core.get_pool("web").unwrap().name, "web");
    assert_eq!(core.get_vm("web").unwrap().state, "suspended");
    assert!(vmm.calls.lock().unwrap().destroyed.is_empty());
}

#[tokio::test]
async fn direct_stop_and_resume_cannot_mutate_a_pool_template() {
    let (core, vmm, _tmp) = core_with_pool("web");

    let stop_error = core.stop_vm("web").await.unwrap_err();
    assert!(matches!(stop_error, CoreError::PoolTemplateOwned { .. }));
    let resume_error = core.resume_vm("web").await.unwrap_err();
    assert!(matches!(resume_error, CoreError::PoolTemplateOwned { .. }));

    assert_eq!(core.get_vm("web").unwrap().state, "suspended");
    let calls = vmm.calls.lock().unwrap();
    assert!(calls.destroyed.is_empty());
    assert!(calls.restore.is_empty());
}

#[tokio::test]
async fn delete_pool_targets_its_stored_template_identity() {
    let (core, vmm, _tmp) = core_with_named_pool_template("web", "template-generation-7");

    core.delete_pool("web").await.unwrap();

    assert!(matches!(
        core.get_pool("web"),
        Err(CoreError::PoolNotFound(_))
    ));
    assert!(matches!(
        core.get_vm("template-generation-7"),
        Err(CoreError::VmNotFound(_))
    ));
    assert_eq!(vmm.calls.lock().unwrap().destroyed.len(), 1);
}

#[tokio::test]
async fn delete_pool_unknown_is_not_found() {
    let (core, _vmm, _tmp) = core_with_pool("web");
    assert!(matches!(
        core.delete_pool("nope").await,
        Err(CoreError::PoolNotFound(n)) if n == "nope"
    ));
}
