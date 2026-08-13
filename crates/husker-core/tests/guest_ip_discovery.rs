//! Tests for lazy guest-IP discovery on EFI-boot (macOS cloud) VMs.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use husker_core::HuskerCore;
use husker_state::{StateStore, VmRecord};
use husker_storage::StorageConfig;
use husker_vmm::{
    BackendKind, CreatedVm, RestoreTarget, SnapshotMeta, SnapshotPaths, VmConfig, VmInfo, VmState,
    VmmBackend, VmmError,
};
use tokio::sync::Mutex;
use uuid::Uuid;

/// A mock VMM that makes vsock connections unreachable for all VMs.
struct UnreachableVsockVmm {
    vms: Mutex<HashMap<Uuid, VmInfo>>,
}

impl UnreachableVsockVmm {
    fn new() -> Self {
        Self {
            vms: Mutex::new(HashMap::new()),
        }
    }

    async fn upsert_vm(&self, info: VmInfo) {
        self.vms.lock().await.insert(info.id, info);
    }
}

impl VmmBackend for UnreachableVsockVmm {
    type VsockStream = tokio::net::UnixStream;

    async fn create_vm(&self, config: VmConfig) -> Result<CreatedVm, VmmError> {
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
        self.upsert_vm(info.clone()).await;
        let backend = if cfg!(feature = "linux-net") {
            BackendKind::Firecracker
        } else {
            BackendKind::AppleVz
        };
        Ok(CreatedVm::new(info, backend))
    }

    async fn stop_vm(&self, id: Uuid) -> Result<(), VmmError> {
        let mut vms = self.vms.lock().await;
        match vms.get_mut(&id) {
            Some(vm) => {
                vm.state = VmState::Stopped;
                Ok(())
            }
            None => Err(VmmError::VmNotFound(id)),
        }
    }

    async fn destroy_vm(&self, id: Uuid) -> Result<(), VmmError> {
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
        Err(VmmError::VmNotFound(id))
    }

    async fn resume_vm(&self, id: Uuid) -> Result<(), VmmError> {
        Err(VmmError::VmNotFound(id))
    }

    /// Always fails — proves discover_guest_ip does not call vsock_connect for
    /// non-qualifying VMs (direct boot, stopped, or already has an IP).
    async fn vsock_connect(&self, id: Uuid, _port: u32) -> Result<Self::VsockStream, VmmError> {
        Err(VmmError::ProcessError(format!(
            "unreachable vsock for {id}"
        )))
    }

    async fn set_balloon(&self, _id: Uuid, _amount_mib: u32) -> Result<(), VmmError> {
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
}

fn make_vm_record(
    id: Uuid,
    name: &str,
    state: &str,
    boot_mode: &str,
    guest_ip: Option<String>,
) -> VmRecord {
    let now = Utc::now();
    VmRecord {
        id,
        name: name.into(),
        state: state.parse().expect("test fixture uses a known VM state"),
        pid: if state == "running" { Some(9999) } else { None },
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 3,
        tap_device: None,
        host_ip: None,
        guest_ip,
        kernel_path: "/boot/vmlinux".into(),
        rootfs_path: "/images/rootfs.ext4".into(),
        created_at: now,
        updated_at: now,
        userdata: None,
        userdata_status: None,
        userdata_env: None,
        service_id: None,
        service_ordinal: None,
        vmm: "apple_vz".into(),
        boot_mode: boot_mode.into(),
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
    mock: UnreachableVsockVmm,
    state: StateStore,
) -> Arc<HuskerCore<UnreachableVsockVmm>> {
    let storage = StorageConfig {
        data_dir: PathBuf::from("/tmp/husker-discovery-test"),
        state_dir: PathBuf::from("/tmp/husker-discovery-test"),
    };
    let runtime_dir = PathBuf::from("/tmp/husker-discovery-test/run");

    #[cfg(feature = "linux-net")]
    {
        Arc::new(HuskerCore::new(
            mock,
            state,
            husker_net::IpAllocator::new(std::net::Ipv4Addr::new(192, 0, 2, 0), 24),
            storage,
            "husker0".into(),
            vec!["192.0.2.1".into()],
            runtime_dir,
        ))
    }
    #[cfg(not(feature = "linux-net"))]
    {
        Arc::new(HuskerCore::new(mock, state, storage, runtime_dir))
    }
}

/// For "direct" boot mode, even when running and no IP, discover_guest_ip must
/// be a no-op and must return quickly (no agent connection attempted).
#[tokio::test]
async fn discover_skips_non_efi_boot_mode() {
    let state = StateStore::open_memory().unwrap();
    let vmm = UnreachableVsockVmm::new();

    let id = Uuid::new_v4();
    let record = make_vm_record(id, "direct-vm", "running", "direct", None);
    state.insert_vm(&record).unwrap();
    vmm.upsert_vm(VmInfo {
        id,
        name: "direct-vm".into(),
        state: VmState::Running,
        pid: Some(9999),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 3,
    })
    .await;

    let core = build_core(vmm, state);

    // Must return well under 250 ms - a wrongly-attempted agent call would eat
    // up to the 1-second timeout.
    let start = std::time::Instant::now();
    let fetched = core.get_vm_refreshed("direct-vm").await.unwrap();
    assert!(
        start.elapsed() < std::time::Duration::from_millis(250),
        "non-efi VM caused unexpected delay: {:?}",
        start.elapsed()
    );
    assert!(
        fetched.guest_ip.is_none(),
        "guest_ip should stay None for direct-boot VMs"
    );
}

/// For a stopped EFI VM, discover_guest_ip must be a no-op.
#[tokio::test]
async fn discover_skips_stopped_efi_vm() {
    let state = StateStore::open_memory().unwrap();
    let vmm = UnreachableVsockVmm::new();

    let id = Uuid::new_v4();
    let record = make_vm_record(id, "stopped-efi", "stopped", "efi", None);
    state.insert_vm(&record).unwrap();
    // No entry in VMM — it's stopped, so vm_info would return VmNotFound.

    let core = build_core(vmm, state);

    let start = std::time::Instant::now();
    let fetched = core.get_vm_refreshed("stopped-efi").await.unwrap();
    assert!(
        start.elapsed() < std::time::Duration::from_millis(250),
        "stopped VM caused unexpected delay"
    );
    assert!(fetched.guest_ip.is_none());
}

/// If the EFI VM already has an IP, discover_guest_ip must leave it untouched.
#[tokio::test]
async fn discover_skips_vm_with_existing_ip() {
    let state = StateStore::open_memory().unwrap();
    let vmm = UnreachableVsockVmm::new();

    let id = Uuid::new_v4();
    let record = make_vm_record(id, "has-ip", "running", "efi", Some("192.0.2.5".into()));
    state.insert_vm(&record).unwrap();
    vmm.upsert_vm(VmInfo {
        id,
        name: "has-ip".into(),
        state: VmState::Running,
        pid: Some(9999),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 3,
    })
    .await;

    let core = build_core(vmm, state);

    let start = std::time::Instant::now();
    let fetched = core.get_vm_refreshed("has-ip").await.unwrap();
    assert!(
        start.elapsed() < std::time::Duration::from_millis(250),
        "VM-with-IP caused unexpected delay"
    );
    assert_eq!(fetched.guest_ip.as_deref(), Some("192.0.2.5"));
}

/// Running EFI VM with no IP and unreachable agent: must return within ~2.5 s
/// (two sequential 1-second timeouts - vsock connect + GuestInfo request - plus
/// margin) and leave guest_ip as None.
#[tokio::test]
async fn discover_times_out_cleanly_for_unreachable_agent() {
    let state = StateStore::open_memory().unwrap();
    let vmm = UnreachableVsockVmm::new();

    let id = Uuid::new_v4();
    let record = make_vm_record(id, "efi-no-agent", "running", "efi", None);
    state.insert_vm(&record).unwrap();
    vmm.upsert_vm(VmInfo {
        id,
        name: "efi-no-agent".into(),
        state: VmState::Running,
        pid: Some(9999),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 3,
    })
    .await;

    let core = build_core(vmm, state);

    let start = std::time::Instant::now();
    let fetched = core.get_vm_refreshed("efi-no-agent").await.unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_millis(2500),
        "discover_guest_ip took too long: {elapsed:?}"
    );
    assert!(
        fetched.guest_ip.is_none(),
        "unreachable agent should leave guest_ip None"
    );
}
