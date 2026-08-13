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
        state: state.into(),
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
/// macOS/VZ only: the Linux (`linux-net`) create path performs real `ip tuntap`
/// TAP creation before reaching the mockable vmm step, which needs root, mutates
/// host network state, and collides with a live daemon - not unit-testable. The
/// Linux create-rollback belongs in a gated e2e or behind a mockable net layer.
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
