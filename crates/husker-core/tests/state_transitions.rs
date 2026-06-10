//! State machine transition tests for VM lifecycle operations.
//!
//! Uses a mock VMM backend that always succeeds, allowing us to test
//! the core layer's state validation logic in isolation.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use husker_core::{CoreError, HuskerCore};
use husker_vmm::{VmConfig, VmInfo, VmState, VmmBackend, VmmError};
use tokio::sync::Mutex;
use uuid::Uuid;

/// A mock VMM backend that tracks VMs in memory.
///
/// All operations succeed unconditionally (no real VM processes).
/// This lets us test state machine logic in the core layer.
struct MockVmm {
    vms: Mutex<HashMap<Uuid, VmInfo>>,
}

impl MockVmm {
    fn new() -> Self {
        Self {
            vms: Mutex::new(HashMap::new()),
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
        self.vms.lock().await.insert(id, info.clone());
        Ok(info)
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
        let mut vms = self.vms.lock().await;
        match vms.get_mut(&id) {
            Some(vm) => {
                vm.state = VmState::Paused;
                Ok(())
            }
            None => Err(VmmError::VmNotFound(id)),
        }
    }

    async fn resume_vm(&self, id: Uuid) -> Result<(), VmmError> {
        let mut vms = self.vms.lock().await;
        match vms.get_mut(&id) {
            Some(vm) => {
                vm.state = VmState::Running;
                Ok(())
            }
            None => Err(VmmError::VmNotFound(id)),
        }
    }

    async fn vsock_connect(&self, id: Uuid, _port: u32) -> Result<Self::VsockStream, VmmError> {
        // Not needed for state transition tests.
        Err(VmmError::VmNotFound(id))
    }

    async fn set_balloon(&self, _id: Uuid, _amount_mib: u32) -> Result<(), VmmError> {
        Ok(())
    }
}

/// Build a core backed by the mock VMM with a pre-populated VM record.
fn mock_core_with_vm(name: &str, state: &str) -> (Arc<HuskerCore<MockVmm>>, Uuid) {
    let vmm = MockVmm::new();
    let state_store = husker_state::StateStore::open_memory().unwrap();
    let storage = husker_storage::StorageConfig {
        data_dir: PathBuf::from("/tmp/husker-mock-test"),
    };

    let now = chrono::Utc::now();
    let id = Uuid::new_v4();
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
    };
    state_store.insert_vm(&record).unwrap();

    // Also insert the VM into the mock VMM so it can find it by ID.
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
    let core = Arc::new(HuskerCore::new(
        vmm,
        state_store,
        husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
        storage,
        "husker0".into(),
        vec!["8.8.8.8".into(), "1.1.1.1".into()],
        PathBuf::from("/tmp/husker-mock-test/run"),
    ));
    #[cfg(not(feature = "linux-net"))]
    let core = Arc::new(HuskerCore::new(
        vmm,
        state_store,
        storage,
        PathBuf::from("/tmp/husker-mock-test/run"),
    ));
    (core, id)
}

// ── Valid Transitions ────────────────────────────────────────────────

#[tokio::test]
async fn pause_running_vm() {
    let (core, _) = mock_core_with_vm("test-vm", "running");
    core.pause_vm("test-vm").await.unwrap();

    let record = core.get_vm("test-vm").unwrap();
    assert_eq!(record.state, "paused");
}

#[tokio::test]
async fn resume_paused_vm() {
    let (core, _) = mock_core_with_vm("test-vm", "paused");
    core.resume_vm("test-vm").await.unwrap();

    let record = core.get_vm("test-vm").unwrap();
    assert_eq!(record.state, "running");
}

#[tokio::test]
async fn stop_running_vm() {
    let (core, _) = mock_core_with_vm("test-vm", "running");
    core.stop_vm("test-vm").await.unwrap();

    let record = core.get_vm("test-vm").unwrap();
    assert_eq!(record.state, "stopped");
}

#[tokio::test]
async fn stop_paused_vm() {
    let (core, _) = mock_core_with_vm("test-vm", "paused");
    core.stop_vm("test-vm").await.unwrap();

    let record = core.get_vm("test-vm").unwrap();
    assert_eq!(record.state, "stopped");
}

#[tokio::test]
async fn destroy_running_vm() {
    let (core, _) = mock_core_with_vm("test-vm", "running");
    core.destroy_vm("test-vm").await.unwrap();

    let err = core.get_vm("test-vm").unwrap_err();
    assert!(matches!(err, CoreError::VmNotFound(_)));
}

#[tokio::test]
async fn destroy_stopped_vm() {
    let (core, _) = mock_core_with_vm("test-vm", "stopped");
    core.destroy_vm("test-vm").await.unwrap();

    let err = core.get_vm("test-vm").unwrap_err();
    assert!(matches!(err, CoreError::VmNotFound(_)));
}

#[tokio::test]
async fn destroy_paused_vm() {
    let (core, _) = mock_core_with_vm("test-vm", "paused");
    core.destroy_vm("test-vm").await.unwrap();

    let err = core.get_vm("test-vm").unwrap_err();
    assert!(matches!(err, CoreError::VmNotFound(_)));
}

#[tokio::test]
async fn destroy_failed_vm() {
    let (core, _) = mock_core_with_vm("test-vm", "failed");
    core.destroy_vm("test-vm").await.unwrap();

    let err = core.get_vm("test-vm").unwrap_err();
    assert!(matches!(err, CoreError::VmNotFound(_)));
}

// ── Invalid Transitions ──────────────────────────────────────────────

#[tokio::test]
async fn pause_stopped_vm_fails() {
    let (core, _) = mock_core_with_vm("test-vm", "stopped");
    let err = core.pause_vm("test-vm").await.unwrap_err();

    match err {
        CoreError::InvalidState {
            actual, expected, ..
        } => {
            assert_eq!(actual, "stopped");
            assert_eq!(expected, "running");
        }
        other => panic!("expected InvalidState, got: {other}"),
    }
}

#[tokio::test]
async fn pause_paused_vm_is_noop() {
    let (core, _) = mock_core_with_vm("test-vm", "paused");
    core.pause_vm("test-vm").await.unwrap();
    assert_eq!(core.get_vm("test-vm").unwrap().state, "paused");
}

#[tokio::test]
async fn resume_running_vm_is_noop() {
    let (core, _) = mock_core_with_vm("test-vm", "running");
    core.resume_vm("test-vm").await.unwrap();
    assert_eq!(core.get_vm("test-vm").unwrap().state, "running");
}

#[tokio::test]
async fn resume_stopped_vm_fails() {
    let (core, _) = mock_core_with_vm("test-vm", "stopped");
    let err = core.resume_vm("test-vm").await.unwrap_err();

    match err {
        CoreError::InvalidState {
            actual, expected, ..
        } => {
            assert_eq!(actual, "stopped");
            assert_eq!(expected, "paused");
        }
        other => panic!("expected InvalidState, got: {other}"),
    }
}

#[tokio::test]
async fn stop_stopped_vm_is_noop() {
    let (core, _) = mock_core_with_vm("test-vm", "stopped");
    core.stop_vm("test-vm").await.unwrap();
    assert_eq!(core.get_vm("test-vm").unwrap().state, "stopped");
}

// ── Nonexistent VM ───────────────────────────────────────────────────

#[tokio::test]
async fn pause_nonexistent_vm_fails() {
    let (core, _) = mock_core_with_vm("test-vm", "running");
    let err = core.pause_vm("no-such-vm").await.unwrap_err();
    assert!(matches!(err, CoreError::VmNotFound(_)));
}

#[tokio::test]
async fn resume_nonexistent_vm_fails() {
    let (core, _) = mock_core_with_vm("test-vm", "running");
    let err = core.resume_vm("no-such-vm").await.unwrap_err();
    assert!(matches!(err, CoreError::VmNotFound(_)));
}

// ── Full Lifecycle ───────────────────────────────────────────────────

#[tokio::test]
async fn full_lifecycle_run_pause_resume_stop_destroy() {
    let (core, _) = mock_core_with_vm("test-vm", "running");

    // running → paused
    core.pause_vm("test-vm").await.unwrap();
    assert_eq!(core.get_vm("test-vm").unwrap().state, "paused");

    // paused → running
    core.resume_vm("test-vm").await.unwrap();
    assert_eq!(core.get_vm("test-vm").unwrap().state, "running");

    // running → paused → stopped (via stop)
    core.pause_vm("test-vm").await.unwrap();
    core.stop_vm("test-vm").await.unwrap();
    assert_eq!(core.get_vm("test-vm").unwrap().state, "stopped");

    // stopped → destroyed
    core.destroy_vm("test-vm").await.unwrap();
    assert!(core.get_vm("test-vm").is_err());
}

#[tokio::test]
async fn multiple_pause_resume_cycles() {
    let (core, _) = mock_core_with_vm("test-vm", "running");

    for _ in 0..5 {
        core.pause_vm("test-vm").await.unwrap();
        assert_eq!(core.get_vm("test-vm").unwrap().state, "paused");

        core.resume_vm("test-vm").await.unwrap();
        assert_eq!(core.get_vm("test-vm").unwrap().state, "running");
    }
}

#[tokio::test]
async fn lifecycle_property_randomized_transitions() {
    let (core, _) = mock_core_with_vm("prop-vm", "running");
    let mut expected = "running".to_string();
    let mut seed: u64 = 0xC0FFEE;

    for _ in 0..200 {
        // Tiny deterministic PRNG to generate a stable random-looking sequence.
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let op = (seed % 3) as u8;

        match op {
            0 => {
                let result = core.pause_vm("prop-vm").await;
                match expected.as_str() {
                    "running" => {
                        result.unwrap();
                        expected = "paused".into();
                    }
                    "paused" => {
                        // idempotent no-op
                        result.unwrap();
                    }
                    "stopped" => {
                        assert!(matches!(result, Err(CoreError::InvalidState { .. })));
                    }
                    other => panic!("unexpected expected state: {other}"),
                }
            }
            1 => {
                let result = core.resume_vm("prop-vm").await;
                match expected.as_str() {
                    "paused" => {
                        result.unwrap();
                        expected = "running".into();
                    }
                    "running" => {
                        // idempotent no-op
                        result.unwrap();
                    }
                    "stopped" => {
                        assert!(matches!(result, Err(CoreError::InvalidState { .. })));
                    }
                    other => panic!("unexpected expected state: {other}"),
                }
            }
            _ => {
                let result = core.stop_vm("prop-vm").await;
                match expected.as_str() {
                    "running" | "paused" => {
                        result.unwrap();
                        expected = "stopped".into();
                    }
                    "stopped" => {
                        // idempotent no-op
                        result.unwrap();
                    }
                    other => panic!("unexpected expected state: {other}"),
                }
            }
        }

        let actual = core.get_vm("prop-vm").unwrap().state;
        assert_eq!(actual, expected);
    }
}

// ── Network Configuration ─────────────────────────────────────────────
//
// Verify that the IP allocator, netmask conversion, and gateway computation
// produce values consistent with the bridge networking model.

#[cfg(feature = "linux-net")]
#[test]
fn allocator_produces_correct_kernel_args_components() {
    use std::net::Ipv4Addr;

    let alloc = husker_net::IpAllocator::new(Ipv4Addr::new(172, 20, 0, 0), 24);
    let gateway = alloc.gateway();
    let netmask = husker_net::prefix_len_to_netmask(alloc.prefix_len());

    assert_eq!(gateway, Ipv4Addr::new(172, 20, 0, 1));
    assert_eq!(netmask, Ipv4Addr::new(255, 255, 255, 0));

    // Allocate two guests and verify they get sequential IPs in the subnet
    let guest1 = alloc.allocate().unwrap();
    let guest2 = alloc.allocate().unwrap();
    assert_eq!(guest1, Ipv4Addr::new(172, 20, 0, 2));
    assert_eq!(guest2, Ipv4Addr::new(172, 20, 0, 3));

    // Verify the kernel args format matches what try_create_vm constructs
    let args = format!(
        "console=ttyS0 reboot=k panic=1 pci=off ip={guest1}::{gateway}:{netmask}::eth0:off"
    );
    assert!(args.contains("ip=172.20.0.2::172.20.0.1:255.255.255.0::eth0:off"));

    // After releasing guest1, the next allocation reuses it
    alloc.release(guest1).unwrap();
    let reused = alloc.allocate().unwrap();
    assert_eq!(reused, guest1);
}

#[cfg(feature = "linux-net")]
#[test]
fn allocator_with_slash_16_subnet() {
    use std::net::Ipv4Addr;

    let alloc = husker_net::IpAllocator::new(Ipv4Addr::new(10, 0, 0, 0), 16);
    let gateway = alloc.gateway();
    let netmask = husker_net::prefix_len_to_netmask(alloc.prefix_len());

    assert_eq!(gateway, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(netmask, Ipv4Addr::new(255, 255, 0, 0));
    assert_eq!(alloc.prefix_len(), 16);

    let guest = alloc.allocate().unwrap();
    assert_eq!(guest, Ipv4Addr::new(10, 0, 0, 2));
}

// ── Agent Connect State Validation ───────────────────────────────────
//
// agent_connect (used by exec, shell, file operations) requires "running"
// state. Verify it rejects paused, stopped, and failed VMs.

#[tokio::test]
async fn agent_connect_rejects_paused_vm() {
    let (core, _) = mock_core_with_vm("test-vm", "paused");
    let result = core.agent_connect("test-vm").await;
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("agent_connect should reject non-running VM"),
    };

    match err {
        CoreError::InvalidState {
            actual, expected, ..
        } => {
            assert_eq!(actual, "paused");
            assert_eq!(expected, "running");
        }
        other => panic!("expected InvalidState, got: {other}"),
    }
}

#[tokio::test]
async fn agent_connect_rejects_stopped_vm() {
    let (core, _) = mock_core_with_vm("test-vm", "stopped");
    let result = core.agent_connect("test-vm").await;
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("agent_connect should reject non-running VM"),
    };

    match err {
        CoreError::InvalidState {
            actual, expected, ..
        } => {
            assert_eq!(actual, "stopped");
            assert_eq!(expected, "running");
        }
        other => panic!("expected InvalidState, got: {other}"),
    }
}

#[tokio::test]
async fn agent_connect_rejects_failed_vm() {
    let (core, _) = mock_core_with_vm("test-vm", "failed");
    let result = core.agent_connect("test-vm").await;
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("agent_connect should reject non-running VM"),
    };

    match err {
        CoreError::InvalidState {
            actual, expected, ..
        } => {
            assert_eq!(actual, "failed");
            assert_eq!(expected, "running");
        }
        other => panic!("expected InvalidState, got: {other}"),
    }
}
