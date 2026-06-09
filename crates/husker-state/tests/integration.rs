use chrono::Utc;
use husker_state::{PortForwardRecord, StateStore, VmRecord};
use tempfile::tempdir;
use uuid::Uuid;

fn make_record(name: &str) -> VmRecord {
    VmRecord {
        id: Uuid::new_v4(),
        name: name.into(),
        state: "running".into(),
        pid: Some(1234),
        vcpu_count: 2,
        mem_size_mib: 256,
        vsock_cid: 3,
        tap_device: Some("tap0".into()),
        host_ip: Some("172.20.0.1".into()),
        guest_ip: Some("172.20.0.2".into()),
        kernel_path: "/boot/vmlinux".into(),
        rootfs_path: "/images/rootfs.ext4".into(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        userdata: None,
        userdata_status: None,
        userdata_env: None,
        service_id: None,
        service_ordinal: None,
        vmm: "firecracker".into(),
        boot_mode: "direct".into(),
    }
}

#[test]
fn full_roundtrip_with_cid() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let id;
    let cid;
    {
        let store = StateStore::open(&db_path).unwrap();
        cid = store.allocate_cid().unwrap();
        let mut rec = make_record("roundtrip-vm");
        rec.vsock_cid = cid;
        id = rec.id;
        store.insert_vm(&rec).unwrap();

        // Allocate another CID to advance the counter
        let _ = store.allocate_cid().unwrap();
    }
    // Store dropped, file closed

    // Reopen and verify data persists
    let store = StateStore::open(&db_path).unwrap();
    let fetched = store.get_vm(id).unwrap();
    assert_eq!(fetched.name, "roundtrip-vm");
    assert_eq!(fetched.vsock_cid, cid);

    // CID counter should continue from where it left off
    let next_cid = store.allocate_cid().unwrap();
    assert!(
        next_cid > cid,
        "CID counter should have advanced: got {next_cid}, expected > {cid}"
    );
}

#[test]
fn migration_idempotency() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("migrate.db");

    let id;
    {
        let store = StateStore::open(&db_path).unwrap();
        let rec = make_record("migrate-vm");
        id = rec.id;
        store.insert_vm(&rec).unwrap();
    }

    // Open again — migrations run again, data should survive
    let store = StateStore::open(&db_path).unwrap();
    let fetched = store.get_vm(id).unwrap();
    assert_eq!(fetched.name, "migrate-vm");
}

#[test]
fn two_stores_same_file_wal_mode() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("shared.db");

    let store1 = StateStore::open(&db_path).unwrap();
    let rec = make_record("shared-vm");
    let id = rec.id;
    store1.insert_vm(&rec).unwrap();

    // Second handle to same file can read what first wrote
    let store2 = StateStore::open(&db_path).unwrap();
    let fetched = store2.get_vm(id).unwrap();
    assert_eq!(fetched.name, "shared-vm");
}

#[test]
fn wal_mode_creates_wal_file() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("wal-test.db");

    let store = StateStore::open(&db_path).unwrap();
    let rec = make_record("wal-vm");
    store.insert_vm(&rec).unwrap();

    // WAL mode should create a -wal file after writes
    let wal_path = dir.path().join("wal-test.db-wal");
    assert!(
        wal_path.exists(),
        "WAL file should exist at {}",
        wal_path.display()
    );
}

#[test]
fn large_dataset() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("large.db");

    let store = StateStore::open(&db_path).unwrap();

    for i in 0..1000 {
        let rec = make_record(&format!("vm-{i:04}"));
        store.insert_vm(&rec).unwrap();
    }

    let vms = store.list_vms().unwrap();
    assert_eq!(vms.len(), 1000);
}

#[test]
fn port_forward_persistence() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("pf.db");

    let vm_id;
    {
        let store = StateStore::open(&db_path).unwrap();
        let rec = make_record("pf-persist-vm");
        vm_id = rec.id;
        store.insert_vm(&rec).unwrap();

        store
            .insert_port_forward(&PortForwardRecord {
                id: 0,
                vm_id,
                host_port: 8080,
                guest_port: 80,
                protocol: "tcp".into(),
                created_at: Utc::now(),
            })
            .unwrap();
    }

    // Reopen and verify port forward persists
    let store = StateStore::open(&db_path).unwrap();
    let forwards = store.list_port_forwards_for_vm(vm_id).unwrap();
    assert_eq!(forwards.len(), 1);
    assert_eq!(forwards[0].host_port, 8080);
    assert_eq!(forwards[0].guest_port, 80);
}
