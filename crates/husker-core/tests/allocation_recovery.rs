//! Recovery uses owned mock handles and private databases; no hypervisor runs.
use chrono::{Duration, Utc};
use husker_core::{CoreError, HuskerCore};
use husker_state::{
    HostResourceLease, StateStore,
    jobs::{CollectionState, JobState},
};
use husker_vmm::{BackendSelection, CreatedVm, VmConfig, VmInfo, VmState, VmmBackend, VmmError};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Default)]
struct Backend {
    owned: Arc<Mutex<HashMap<Uuid, VmInfo>>>,
    destroys: Arc<AtomicUsize>,
}
impl VmmBackend for Backend {
    type VsockStream = tokio::io::DuplexStream;
    fn backend_kind(&self) -> &'static str {
        "firecracker"
    }
    async fn create_vm(&self, _: BackendSelection, _: VmConfig) -> Result<CreatedVm, VmmError> {
        unreachable!()
    }
    async fn stop_vm(&self, _: Uuid) -> Result<(), VmmError> {
        unreachable!()
    }
    async fn pause_vm(&self, _: Uuid) -> Result<(), VmmError> {
        unreachable!()
    }
    async fn resume_vm(&self, _: Uuid) -> Result<(), VmmError> {
        unreachable!()
    }
    async fn vsock_connect(&self, _: Uuid, _: u32) -> Result<Self::VsockStream, VmmError> {
        unreachable!()
    }
    async fn set_balloon(&self, _: Uuid, _: u32) -> Result<(), VmmError> {
        unreachable!()
    }
    async fn destroy_vm(&self, id: Uuid) -> Result<(), VmmError> {
        self.destroys.fetch_add(1, Ordering::SeqCst);
        self.owned
            .lock()
            .await
            .remove(&id)
            .map(|_| ())
            .ok_or(VmmError::VmNotFound(id))
    }
    async fn vm_info(&self, id: Uuid) -> Result<VmInfo, VmmError> {
        self.owned
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or(VmmError::VmNotFound(id))
    }
}
fn core(root: &Path, store: StateStore, backend: Backend) -> HuskerCore<Backend> {
    let storage = husker_storage::StorageConfig {
        data_dir: root.into(),
        state_dir: root.into(),
    };
    #[cfg(feature = "linux-net")]
    {
        HuskerCore::new(
            backend,
            store,
            husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
            storage,
            "unused".into(),
            vec![],
            root.join("run"),
        )
    }
    #[cfg(not(feature = "linux-net"))]
    {
        HuskerCore::new(backend, store, storage, root.join("run"))
    }
}
fn lease(store: &StateStore, root: &Path, name: &str, id: Uuid) -> HostResourceLease {
    let lease = store.begin_host_resource_lease_for_vm(name, id).unwrap();
    store
        .enter_host_resource_lease_backend(lease.id, id)
        .unwrap();
    let dir = root.join("vms").join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("rootfs.ext4"), b"owned disk").unwrap();
    store.get_host_resource_lease(lease.id).unwrap()
}
async fn own(backend: &Backend, lease: &HostResourceLease) {
    let id = lease.vm_id.unwrap();
    backend.owned.lock().await.insert(
        id,
        VmInfo {
            id,
            name: lease.vm_name.clone(),
            state: VmState::Failed,
            pid: None,
            vcpu_count: 1,
            mem_size_mib: 128,
            vsock_cid: lease.vsock_cid,
        },
    );
}

#[tokio::test]
async fn entered_allocation_retries_the_owner_and_releases_only_after_confirmed_termination() {
    let temp = tempfile::tempdir().unwrap();
    let store = StateStore::open_memory().unwrap();
    let lease = lease(&store, temp.path(), "retry", Uuid::new_v4());
    let backend = Backend::default();
    own(&backend, &lease).await;
    let core = core(temp.path(), store, backend.clone());
    assert_eq!(
        core.recover_host_resource_leases().await.unwrap().recovered,
        1
    );
    assert_eq!(backend.destroys.load(Ordering::SeqCst), 1);
    assert!(!temp.path().join("vms/retry").exists());
    assert_eq!(
        core.recover_host_resource_leases().await.unwrap().recovered,
        0
    );
}

#[tokio::test]
async fn backend_absence_and_foreign_identity_preserve_disk_and_lease() {
    for foreign in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let store = StateStore::open_memory().unwrap();
        let lease = lease(&store, temp.path(), "uncertain", Uuid::new_v4());
        let backend = Backend::default();
        if foreign {
            own(&backend, &lease).await;
            backend
                .owned
                .lock()
                .await
                .get_mut(&lease.vm_id.unwrap())
                .unwrap()
                .vsock_cid += 1;
        }
        let core = core(temp.path(), store, backend.clone());
        for _ in 0..2 {
            assert_eq!(core.recover_host_resource_leases().await.unwrap().failed, 1);
        }
        assert_eq!(
            std::fs::read(temp.path().join("vms/uncertain/rootfs.ext4")).unwrap(),
            b"owned disk"
        );
        if foreign {
            assert_eq!(backend.destroys.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn confirmed_termination_survives_a_receipt_write_failure_without_destroying_twice() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.db");
    let store = StateStore::open(&path).unwrap();
    let lease = lease(&store, temp.path(), "receipt-retry", Uuid::new_v4());
    let backend = Backend::default();
    own(&backend, &lease).await;
    let core = core(temp.path(), store, backend.clone());
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER fail_receipt BEFORE UPDATE OF vm_destroyed ON host_resource_leases BEGIN SELECT RAISE(ABORT,'injected receipt failure'); END;").unwrap();
    assert!(core.recover_host_resource_leases().await.is_err());
    assert!(temp.path().join("vms/receipt-retry/rootfs.ext4").exists());
    assert_eq!(backend.destroys.load(Ordering::SeqCst), 1);
    conn.execute_batch("DROP TRIGGER fail_receipt;").unwrap();
    assert_eq!(
        core.recover_host_resource_leases().await.unwrap().recovered,
        1
    );
    assert_eq!(backend.destroys.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn terminal_factory_lease_recovers_with_the_exact_backend_generation() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.db");
    let store = StateStore::open(&path).unwrap();
    let deadline = Utc::now() + Duration::minutes(10);
    let job = store
        .accept_job(
            "failed-launch",
            "{}",
            deadline,
            deadline + Duration::hours(1),
        )
        .unwrap()
        .0;
    let id = Uuid::new_v4();
    let name = format!("job-{}", job.id);
    store.bind_job_vm(job.id, id, &name).unwrap();
    store
        .finish_job(
            job.id,
            JobState::InfrastructureFailed,
            CollectionState::Failed,
            "{}",
        )
        .unwrap();
    let lease = lease(&store, temp.path(), &name, id);
    let backend = Backend::default();
    own(&backend, &lease).await;
    let core = core(temp.path(), store, backend.clone());
    assert_eq!(
        core.recover_host_resource_leases().await.unwrap().recovered,
        1
    );
    let inspected = StateStore::open(&path).unwrap();
    assert!(inspected.get_job(job.id).unwrap().vm_destroyed);
    assert!(inspected.get_job(job.id).unwrap().cleanup_pending);
    assert_eq!(backend.destroys.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_factory_ownership_mismatch_preserves_its_lease_without_failing_startup() {
    let temp = tempfile::tempdir().unwrap();
    let store = StateStore::open_memory().unwrap();
    let deadline = Utc::now() + Duration::minutes(10);
    let job = store
        .accept_job("mismatch", "{}", deadline, deadline + Duration::hours(1))
        .unwrap()
        .0;
    let id = Uuid::new_v4();
    let name = format!("job-{}", job.id);
    store.bind_job_vm(job.id, id, &name).unwrap();
    store
        .finish_job(
            job.id,
            JobState::InfrastructureFailed,
            CollectionState::Failed,
            "{}",
        )
        .unwrap();
    let factory = lease(&store, temp.path(), &name, id);
    let unrelated = lease(&store, temp.path(), "unrelated", Uuid::new_v4());
    let backend = Backend::default();
    own(&backend, &factory).await;
    own(&backend, &unrelated).await;
    backend.owned.lock().await.get_mut(&id).unwrap().vsock_cid += 1;
    let core = core(temp.path(), store, backend.clone());
    assert_eq!(
        core.recover_host_resource_leases().await.unwrap(),
        husker_core::HostResourceRecovery {
            recovered: 1,
            failed: 1
        }
    );
    assert_eq!(backend.destroys.load(Ordering::SeqCst), 1);
    assert!(backend.owned.lock().await.contains_key(&id));
    assert_eq!(
        std::fs::read(temp.path().join("vms").join(&name).join("rootfs.ext4")).unwrap(),
        b"owned disk"
    );
    assert!(!temp.path().join("vms/unrelated").exists());
}

#[tokio::test]
async fn persisted_reboot_proof_recovers_legacy_null_ids_but_foreign_evidence_does_not() {
    for foreign in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.db");
        let store = StateStore::open(&path).unwrap();
        let lease = store.begin_host_resource_lease("legacy").unwrap();
        let dir = temp.path().join("vms/legacy");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("rootfs.ext4"), b"legacy disk").unwrap();
        let conn = rusqlite::Connection::open(&path).unwrap();
        // Model a previously persisted positive reboot receipt without relying
        // on this test machine exposing a particular OS identity provider.
        conn.execute(
            "DELETE FROM creation_lease_boot_epochs WHERE lease_id=?1",
            [lease.id.to_string()],
        )
        .unwrap();
        conn.execute(
            "UPDATE host_resource_leases SET backend_entered=1 WHERE id=?1",
            [lease.id.to_string()],
        )
        .unwrap();
        conn.execute("INSERT INTO creation_lease_boot_epochs(lease_id,host_id,boot_id,confirmed) VALUES (?1,?2,?3,?4)",
            rusqlite::params![lease.id.to_string(),Uuid::new_v4().to_string(),Uuid::new_v4().to_string(),!foreign]).unwrap();
        let backend = Backend::default();
        let core = core(temp.path(), store, backend.clone());
        let summary = core.recover_host_resource_leases().await.unwrap();
        assert_eq!(summary.recovered, usize::from(!foreign));
        assert_eq!(dir.exists(), foreign);
        assert_eq!(backend.destroys.load(Ordering::SeqCst), 0);
        let inspected = StateStore::open(&path).unwrap();
        assert_eq!(
            inspected.list_host_resource_leases().unwrap().len(),
            usize::from(foreign)
        );
        if !foreign {
            assert_eq!(inspected.allocate_cid().unwrap(), lease.vsock_cid);
        }
    }
}

#[tokio::test]
async fn factory_recovery_persists_job_proof_before_retiring_a_destroyed_lease() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.db");
    let store = StateStore::open(&path).unwrap();
    let deadline = Utc::now() + Duration::minutes(10);
    let job = store
        .accept_job(
            "retry-job-receipt",
            "{}",
            deadline,
            deadline + Duration::hours(1),
        )
        .unwrap()
        .0;
    let id = Uuid::new_v4();
    let name = format!("job-{}", job.id);
    store.bind_job_vm(job.id, id, &name).unwrap();
    store
        .finish_job(
            job.id,
            JobState::InfrastructureFailed,
            CollectionState::Failed,
            "{}",
        )
        .unwrap();
    let lease = lease(&store, temp.path(), &name, id);
    let backend = Backend::default();
    own(&backend, &lease).await;
    let core = core(temp.path(), store, backend.clone());
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER fail_job_receipt BEFORE UPDATE OF vm_destroyed ON execution_jobs BEGIN SELECT RAISE(ABORT,'injected job receipt failure'); END;").unwrap();
    assert!(core.recover_host_resource_leases().await.is_err());
    let inspected = StateStore::open(&path).unwrap();
    assert!(
        inspected
            .get_host_resource_lease(lease.id)
            .unwrap()
            .vm_destroyed
    );
    assert!(!inspected.get_job(job.id).unwrap().vm_destroyed);
    assert!(temp.path().join("vms").join(&name).exists());
    // The lease now carries its destruction receipt, so the next pass only
    // copies it to the job. A failing journal write must still stop startup.
    assert!(matches!(
        core.recover_host_resource_leases().await,
        Err(CoreError::State(_))
    ));
    assert!(!inspected.get_job(job.id).unwrap().vm_destroyed);
    assert_eq!(inspected.list_host_resource_leases().unwrap().len(), 1);
    conn.execute_batch("DROP TRIGGER fail_job_receipt;")
        .unwrap();
    assert_eq!(
        core.recover_host_resource_leases().await.unwrap().recovered,
        1
    );
    assert!(inspected.get_job(job.id).unwrap().vm_destroyed);
    assert!(inspected.list_host_resource_leases().unwrap().is_empty());
    assert_eq!(backend.destroys.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_durable_job_receipt_can_finish_a_matching_entered_lease_without_backend_guessing() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.db");
    let store = StateStore::open(&path).unwrap();
    let deadline = Utc::now() + Duration::minutes(10);
    let job = store
        .accept_job("job-proof", "{}", deadline, deadline + Duration::hours(1))
        .unwrap()
        .0;
    let id = Uuid::new_v4();
    let name = format!("job-{}", job.id);
    store.bind_job_vm(job.id, id, &name).unwrap();
    store
        .finish_job(
            job.id,
            JobState::InfrastructureFailed,
            CollectionState::Failed,
            "{}",
        )
        .unwrap();
    lease(&store, temp.path(), &name, id);
    // Model a positive destruction receipt persisted by another teardown path.
    store.record_job_vm_destruction(id).unwrap();
    let backend = Backend::default();
    let core = core(temp.path(), store, backend.clone());
    assert_eq!(
        core.recover_host_resource_leases().await.unwrap().recovered,
        1
    );
    assert_eq!(backend.destroys.load(Ordering::SeqCst), 0);
}
