//! Journal fault/replay contracts, using real on-disk SQLite databases.
use chrono::{Duration, Utc};
use husker_state::StateStore;
use husker_state::jobs::*;
use uuid::Uuid;

fn submit(store: &StateStore, key: &str) -> JobRecord {
    let now = Utc::now();
    store
        .accept_job(
            key,
            r#"{"source":"sha256:source","acceptance":"sha256:acceptance","argv":["true"]}"#,
            now + Duration::hours(1),
            now + Duration::days(1),
        )
        .unwrap()
        .0
}
fn running(store: &StateStore, key: &str) -> JobRecord {
    let job = submit(store, key);
    store
        .bind_job_vm(job.id, Uuid::new_v4(), &format!("disposable-{}", job.id))
        .unwrap();
    store.mark_job_running(job.id).unwrap();
    store.get_job(job.id).unwrap()
}
fn event(sequence: u64, data: &[u8]) -> JobEvent {
    JobEvent {
        sequence,
        stream: "stdout".into(),
        data: data.to_vec(),
    }
}

fn budget_spec() -> &'static str {
    r#"{"resources":{"vcpu_count":2,"mem_size_mib":512,"disk_size_bytes":1073741824}}"#
}
fn budget() -> FactoryResourceBudget {
    FactoryResourceBudget {
        max_jobs: 4,
        max_vcpus: 8,
        max_memory_mib: 4096,
        memory_overhead_mib: 128,
        max_root_disk_bytes: 4 * 1024 * 1024 * 1024,
        max_boot_storage_bytes: 16 * 1024 * 1024 * 1024,
        min_free_storage_bytes: 16 * 1024 * 1024,
    }
}
fn budget_submit(
    store: &StateStore,
    key: &str,
    budget: &FactoryResourceBudget,
) -> Result<(JobRecord, bool), JournalError> {
    store.accept_job_with_budget(
        key,
        budget_spec(),
        Utc::now() + Duration::hours(1),
        Utc::now() + Duration::days(1),
        budget,
        || {
            Ok(FactoryAvailableStorage {
                shared_filesystem: false,
                boot_bytes: u64::MAX,
                journal_bytes: u64::MAX,
            })
        },
    )
}

#[test]
fn each_resource_budget_rejects_before_acceptance_and_replay_remains_available() {
    for (dimension, expected) in [
        ("jobs", "factory job budget"),
        ("cpus", "factory vCPU budget"),
        ("memory", "factory memory budget"),
        ("disk", "factory root disk budget"),
        ("boot", "factory boot storage budget"),
    ] {
        let store = StateStore::open_memory().unwrap();
        let mut budget = budget();
        match dimension {
            "jobs" => budget.max_jobs = 1,
            "cpus" => budget.max_vcpus = 2,
            "memory" => budget.max_memory_mib = 640,
            "disk" => budget.max_root_disk_bytes = 1024 * 1024 * 1024,
            "boot" => budget.max_boot_storage_bytes = 3 * 1024 * 1024 * 1024,
            _ => unreachable!(),
        }
        let first = budget_submit(&store, "first", &budget).unwrap().0;
        assert!(matches!(
            budget_submit(&store, "second", &budget),
            Err(JournalError::Capacity(reason)) if reason == expected
        ));
        assert_eq!(store.recoverable_jobs().unwrap().len(), 1);
        // A lower operator budget cannot erase a committed receipt.
        budget.max_memory_mib = 256;
        let (replayed, fresh) = store
            .accept_job_with_budget(
                "first",
                &first.specification,
                chrono::DateTime::from_timestamp(first.deadline, 0).unwrap(),
                chrono::DateTime::from_timestamp(first.retention_until, 0).unwrap(),
                &budget,
                || panic!("replay must not observe storage"),
            )
            .unwrap();
        assert!(!fresh);
        assert_eq!(replayed.id, first.id);
    }
}

#[test]
fn resource_charges_survive_restart_and_termination_until_cleanup_is_confirmed() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("budget.sqlite");
    let store = StateStore::open(&path).unwrap();
    let mut budget = budget();
    budget.max_vcpus = 2;
    let first = budget_submit(&store, "first", &budget).unwrap().0;
    let vm = Uuid::new_v4();
    store
        .bind_job_vm(first.id, vm, "pending-budget-vm")
        .unwrap();
    store
        .finish_job(first.id, JobState::Unknown, CollectionState::Failed, "{}")
        .unwrap();
    store.record_job_vm_destruction(vm).unwrap();
    drop(store);
    let store = StateStore::open(&path).unwrap();
    assert!(matches!(
        budget_submit(&store, "second", &budget),
        Err(JournalError::Capacity("factory vCPU budget"))
    ));
    store.confirm_job_cleanup(first.id, vm).unwrap();
    assert!(budget_submit(&store, "second", &budget).unwrap().1);
}

#[test]
fn boot_storage_reservation_counts_two_disks_and_stays_owned_until_full_cleanup() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("boot-budget.sqlite");
    let store = StateStore::open(&path).unwrap();
    let mut budget = budget();
    // Exactly one 1-GiB job, including absent-initrd conservative headroom.
    budget.max_boot_storage_bytes = 2 * 1024 * 1024 * 1024
        + husker_types::factory_limits::KERNEL_BYTES
        + husker_types::factory_limits::INITRD_BYTES
        + husker_types::factory_limits::SERIAL_BYTES;
    let first = budget_submit(&store, "boot-first", &budget).unwrap().0;
    let vm = Uuid::new_v4();
    store.bind_job_vm(first.id, vm, "boot-budget-vm").unwrap();
    store
        .finish_job(first.id, JobState::Unknown, CollectionState::Failed, "{}")
        .unwrap();
    store.record_job_vm_destruction(vm).unwrap();
    drop(store);
    let store = StateStore::open(&path).unwrap();
    assert!(matches!(
        budget_submit(&store, "boot-second", &budget),
        Err(JournalError::Capacity("factory boot storage budget"))
    ));
    // Storage ownership cannot be replaced by a termination receipt alone.
    store.confirm_job_cleanup(first.id, vm).unwrap();
    assert!(budget_submit(&store, "boot-second", &budget).unwrap().1);
}

#[test]
fn doubled_disk_reservation_overflow_and_missing_configuration_fail_closed() {
    let store = StateStore::open_memory().unwrap();
    let now = Utc::now();
    store.accept_job("legacy-huge-disk", r#"{"resources":{"vcpu_count":1,"mem_size_mib":512,"disk_size_bytes":18446744073709551615}}"#,
        now + Duration::hours(1), now + Duration::days(1)).unwrap();
    let mut budget = budget();
    budget.max_root_disk_bytes = u64::MAX;
    budget.max_boot_storage_bytes = u64::MAX;
    assert!(matches!(
        budget_submit(&store, "new", &budget),
        Err(JournalError::Capacity("factory boot storage budget"))
    ));
    budget.max_boot_storage_bytes = 0;
    assert!(budget.validate().is_err());
    let mut config = serde_json::to_value(budget).unwrap();
    config
        .as_object_mut()
        .unwrap()
        .remove("max_boot_storage_bytes");
    assert!(serde_json::from_value::<FactoryResourceBudget>(config).is_err());
}

#[test]
fn concurrent_connections_cannot_overbook_resource_budget() {
    for storage in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("concurrent-budget.sqlite");
        StateStore::open(&path).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = (0..2)
            .map(|i| {
                let store = StateStore::open(&path).unwrap();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut budget = budget();
                    if storage {
                        budget.max_boot_storage_bytes = 3 * 1024 * 1024 * 1024;
                    } else {
                        budget.max_vcpus = 2;
                    }
                    barrier.wait();
                    budget_submit(&store, &format!("racer-{i}"), &budget)
                })
            })
            .collect();
        let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(JournalError::Capacity(reason)) if *reason == if storage { "factory boot storage budget" } else { "factory vCPU budget" }))
            .count(),
        1
    );
        assert_eq!(
            StateStore::open(&path)
                .unwrap()
                .recoverable_jobs()
                .unwrap()
                .len(),
            1
        );
    }
}

#[test]
fn unreadable_legacy_resources_and_arithmetic_overflow_fail_closed() {
    for specification in [
        "{}",
        r#"{"resources":{"vcpu_count":18446744073709551615,"mem_size_mib":512,"disk_size_bytes":1073741824}}"#,
    ] {
        let store = StateStore::open_memory().unwrap();
        let now = Utc::now();
        store
            .accept_job(
                "legacy",
                specification,
                now + Duration::hours(1),
                now + Duration::days(1),
            )
            .unwrap();
        let mut budget = budget();
        budget.max_vcpus = u64::MAX;
        assert!(matches!(
            budget_submit(&store, "new", &budget),
            Err(JournalError::Capacity(_))
        ));
        assert_eq!(store.recoverable_jobs().unwrap().len(), 1);
    }
}

#[test]
fn exact_unentered_lease_abort_is_durable_and_fences_late_backend_entry() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("prebackend.sqlite");
    let store = StateStore::open(&path).unwrap();
    let job = submit(&store, "prebackend");
    let name = store.claim_job_vm(job.id).unwrap().vm_name.unwrap();
    let vm_id = Uuid::new_v4();
    store.bind_job_vm(job.id, vm_id, &name).unwrap();
    let lease = store
        .begin_host_resource_lease_for_vm(&name, vm_id)
        .unwrap();
    assert_eq!(lease.vm_id, Some(vm_id));
    assert!(!lease.backend_entered);
    store
        .record_job_leased_prebackend_abort(job.id, vm_id, lease.id)
        .unwrap();
    drop(store);
    let store = StateStore::open(&path).unwrap();
    let job = store.get_job(job.id).unwrap();
    let lease = store.get_host_resource_lease(lease.id).unwrap();
    assert!(job.vm_allocation_aborted && lease.allocation_aborted);
    assert!(!job.vm_destroyed && !lease.backend_entered && job.cleanup_pending);
    assert!(
        store
            .enter_host_resource_lease_backend(lease.id, vm_id)
            .is_err()
    );
    assert!(
        store
            .enter_host_resource_lease_backend(lease.id, Uuid::new_v4())
            .is_err()
    );
    assert!(store.mark_job_running(job.id).is_err());
    store
        .record_job_leased_prebackend_abort(job.id, vm_id, lease.id)
        .unwrap();
    assert_ne!(store.allocate_cid().unwrap(), lease.vsock_cid);
}

#[test]
fn prebackend_abort_refuses_entered_or_foreign_generation_leases() {
    for scenario in ["entered", "foreign-id", "foreign-name", "unbound"] {
        let store = StateStore::open_memory().unwrap();
        let job = submit(&store, scenario);
        let name = store.claim_job_vm(job.id).unwrap().vm_name.unwrap();
        let vm_id = Uuid::new_v4();
        store.bind_job_vm(job.id, vm_id, &name).unwrap();
        let lease = match scenario {
            "foreign-id" => store
                .begin_host_resource_lease_for_vm(&name, Uuid::new_v4())
                .unwrap(),
            "foreign-name" => store
                .begin_host_resource_lease_for_vm("foreign-owner", vm_id)
                .unwrap(),
            "unbound" => store.begin_host_resource_lease(&name).unwrap(),
            _ => store
                .begin_host_resource_lease_for_vm(&name, vm_id)
                .unwrap(),
        };
        if scenario == "entered" {
            store
                .enter_host_resource_lease_backend(lease.id, vm_id)
                .unwrap();
        }
        assert!(
            store
                .record_job_leased_prebackend_abort(job.id, vm_id, lease.id)
                .is_err()
        );
        assert!(!store.get_job(job.id).unwrap().vm_allocation_aborted);
        assert!(
            !store
                .get_host_resource_lease(lease.id)
                .unwrap()
                .allocation_aborted
        );
    }
}

#[test]
fn prebackend_abort_rolls_back_lease_fence_when_job_receipt_cannot_commit() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("abort-failure.sqlite");
    let store = StateStore::open(&path).unwrap();
    let job = submit(&store, "abort-failure");
    let name = store.claim_job_vm(job.id).unwrap().vm_name.unwrap();
    let vm_id = Uuid::new_v4();
    store.bind_job_vm(job.id, vm_id, &name).unwrap();
    let lease = store
        .begin_host_resource_lease_for_vm(&name, vm_id)
        .unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER injected_abort_failure BEFORE UPDATE OF vm_allocation_aborted ON execution_jobs BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END;").unwrap();
    assert!(
        store
            .record_job_leased_prebackend_abort(job.id, vm_id, lease.id)
            .is_err()
    );
    assert!(!store.get_job(job.id).unwrap().vm_allocation_aborted);
    assert!(
        !store
            .get_host_resource_lease(lease.id)
            .unwrap()
            .allocation_aborted
    );
    assert_ne!(store.allocate_cid().unwrap(), lease.vsock_cid);
    conn.execute_batch("DROP TRIGGER injected_abort_failure;")
        .unwrap();
    store
        .record_job_leased_prebackend_abort(job.id, vm_id, lease.id)
        .unwrap();
}

#[test]
fn lost_acceptance_response_restart_replays_identity_and_changed_inputs_conflict() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.sqlite");
    let now = Utc::now();
    let deadline = now + Duration::hours(1);
    let retention = now + Duration::days(1);
    let spec = r#"{"image":"sha256:one","source":"sha256:two","acceptance":"sha256:three","commands":[["true"]]}"#;
    let id;
    let session;
    {
        let store = StateStore::open(&path).unwrap();
        // Simulate crash before acceptance: a new database has no pending work.
        assert!(store.recoverable_jobs().unwrap().is_empty());
        let (job, new) = store.accept_job("key", spec, deadline, retention).unwrap();
        assert!(new);
        id = job.id;
        session = job.session_id;
        // Drop without sending a command or returning a receipt.
    }
    let store = StateStore::open(&path).unwrap();
    let (replay, new) = store.accept_job("key", spec, deadline, retention).unwrap();
    assert!(!new);
    assert_eq!(replay.id, id);
    assert_eq!(replay.session_id, session);
    assert_eq!(replay.state, JobState::Accepted);
    assert!(matches!(
        store.accept_job("key", "{}", deadline, retention),
        Err(JournalError::Conflict(_))
    ));
    assert!(matches!(
        store.accept_job("key", spec, deadline + Duration::seconds(1), retention),
        Err(JournalError::Conflict(_))
    ));
    // An identical retry still resolves after the deadline; it cannot reset TTL.
    assert_eq!(store.recoverable_jobs().unwrap().len(), 1);
}

#[test]
fn concurrent_connections_accept_exactly_one_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.sqlite");
    let first = StateStore::open(&path).unwrap();
    let second = StateStore::open(&path).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let now = Utc::now();
    let handles: Vec<_> = [first, second]
        .into_iter()
        .map(|store| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .accept_job(
                        "same",
                        "{}",
                        now + Duration::hours(1),
                        now + Duration::days(1),
                    )
                    .unwrap()
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results[0].0.id, results[1].0.id);
    assert_eq!(results.iter().filter(|r| r.1).count(), 1);
}

#[test]
fn binding_and_cleanup_fence_vm_generations_and_keep_evidence_after_vm_deletion() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.sqlite");
    let store = StateStore::open(&path).unwrap();
    let job = running(&store, "vm-bound");
    let generation = job.vm_id.unwrap();
    assert!(matches!(
        store.bind_job_vm(job.id, Uuid::new_v4(), &format!("disposable-{}", job.id)),
        Err(JournalError::Conflict(_))
    ));
    assert_eq!(
        store
            .bind_job_vm(job.id, generation, job.vm_name.as_deref().unwrap())
            .unwrap()
            .vm_id,
        Some(generation)
    );
    store
        .append_job_events(job.id, &[event(1, b"diagnostic\0\xff")], false)
        .unwrap();
    store
        .finish_job(
            job.id,
            JobState::CommandFailed,
            CollectionState::Complete,
            r#"{"exit_code":1}"#,
        )
        .unwrap();
    assert!(store.confirm_job_cleanup(job.id, Uuid::new_v4()).is_err());
    assert!(store.delete_job_evidence(job.id).is_err());
    // Use a VM row whose UUID is the job's recorded generation, then delete it.
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute("INSERT INTO vms(id,name,state,vcpu_count,mem_size_mib,vsock_cid,kernel_path,rootfs_path,created_at,updated_at) VALUES (?1,'disposable','stopped',1,128,3,'kernel','disk',?2,?2)", rusqlite::params![generation.to_string(), Utc::now().to_rfc3339()]).unwrap();
    store.delete_vm(generation).unwrap();
    drop(store);
    let store = StateStore::open(&path).unwrap();
    let page = store.job_events(job.id, 0).unwrap();
    assert_eq!(page.events[0].data, b"diagnostic\0\xff");
    assert_eq!(page.job.manifest.as_deref(), Some(r#"{"exit_code":1}"#));
    assert!(page.job.cleanup_pending);
    assert_eq!(store.recoverable_jobs().unwrap().len(), 1);
    assert!(store.confirm_job_cleanup(job.id, generation).is_err());
    store.record_job_vm_destruction(generation).unwrap();
    store.confirm_job_cleanup(job.id, generation).unwrap();
    assert!(store.recoverable_jobs().unwrap().is_empty());
    store.delete_job_evidence(job.id).unwrap();
    assert!(matches!(
        store.get_job(job.id),
        Err(JournalError::NotFound(_))
    ));
    assert!(matches!(
        store.accept_job(
            "vm-bound",
            &job.specification,
            chrono::DateTime::from_timestamp(job.deadline, 0).unwrap(),
            chrono::DateTime::from_timestamp(job.retention_until, 0).unwrap()
        ),
        Err(JournalError::Conflict(_))
    ));
}

#[test]
fn append_replay_is_atomic_binary_safe_and_cursor_reconnect_is_bounded() {
    let store = StateStore::open_memory().unwrap();
    let job = running(&store, "events");
    let first: Vec<_> = (1..=128).map(|seq| event(seq, &[0, 255])).collect();
    store.append_job_events(job.id, &first, false).unwrap();
    store.append_job_events(job.id, &first, false).unwrap();
    store
        .append_job_events(job.id, &[event(129, b"end")], false)
        .unwrap();
    let page = store.job_events(job.id, 0).unwrap();
    assert_eq!(page.events.len(), 128);
    assert_eq!(page.next_cursor, 128);
    assert!(page.has_more);
    let next = store.job_events(job.id, page.next_cursor).unwrap();
    assert_eq!(next.events[0].data, b"end");
    assert_eq!(next.next_cursor, 129);
    assert!(!next.has_more);
    assert!(store.job_events(job.id, 129).unwrap().events.is_empty());
    // The first new event must roll back when the second event has a gap.
    assert!(
        store
            .append_job_events(
                job.id,
                &[event(130, b"not-committed"), event(132, b"gap")],
                false
            )
            .is_err()
    );
    assert_eq!(store.get_job(job.id).unwrap().capture_cursor, 129);
    assert!(
        store
            .append_job_events(job.id, &[event(1, b"changed")], false)
            .is_err()
    );
    assert_eq!(
        store.job_events(job.id, 0).unwrap().events[0].data,
        [0, 255]
    );
    assert!(store.job_events(job.id, u64::MAX).is_err());
}

#[test]
fn bounded_logs_publish_truncation_and_reject_forged_discarded_replay() {
    let store = StateStore::open_memory().unwrap();
    let job = running(&store, "large-log");
    let chunk = vec![42; MAX_EVENT_BYTES];
    for page in 0..5 {
        let events: Vec<_> = (1..=128)
            .map(|seq| event(page * 128 + seq, &chunk))
            .collect();
        store.append_job_events(job.id, &events, false).unwrap();
    }
    let info = store.get_job(job.id).unwrap();
    assert_eq!(info.retained_bytes, MAX_OUTPUT_BYTES);
    assert!(info.output_truncated);
    assert_eq!(info.capture_cursor, 640);
    let last = store.job_events(job.id, 512).unwrap();
    assert!(last.events.is_empty());
    assert_eq!(last.next_cursor, 640);
    assert!(
        store
            .append_job_events(job.id, &[event(640, b"altered")], false)
            .is_err()
    );
    assert!(
        store
            .finish_job(job.id, JobState::Completed, CollectionState::Complete, "{}")
            .is_err()
    );
    store
        .finish_job(
            job.id,
            JobState::Completed,
            CollectionState::Truncated,
            "{}",
        )
        .unwrap();
    assert!(
        store
            .append_job_events(job.id, &[event(641, b"late")], false)
            .is_err()
    );
}

#[test]
fn terminal_winner_and_collection_failure_remain_distinct_and_immutable() {
    let store = StateStore::open_memory().unwrap();
    let job = running(&store, "terminal");
    store
        .finish_job(
            job.id,
            JobState::TimedOut,
            CollectionState::Failed,
            r#"{"reason":"collection failed"}"#,
        )
        .unwrap();
    store
        .finish_job(
            job.id,
            JobState::TimedOut,
            CollectionState::Failed,
            r#"{"reason":"collection failed"}"#,
        )
        .unwrap();
    assert!(
        store
            .finish_job(job.id, JobState::Completed, CollectionState::Complete, "{}")
            .is_err()
    );
    assert!(
        store
            .finish_job(job.id, JobState::Cancelled, CollectionState::Failed, "{}")
            .is_err()
    );
    let info = store.get_job(job.id).unwrap();
    assert_eq!(info.state, JobState::TimedOut);
    assert_eq!(info.collection, CollectionState::Failed);
    let accepted = submit(&store, "not-executed");
    assert!(store.mark_job_running(accepted.id).is_err());
    assert!(
        store
            .finish_job(
                accepted.id,
                JobState::Completed,
                CollectionState::Complete,
                "{}"
            )
            .is_err()
    );
    store
        .finish_job(
            accepted.id,
            JobState::Unknown,
            CollectionState::Failed,
            "{}",
        )
        .unwrap();
}

#[test]
fn cleanup_pending_reserves_admission_across_terminal_outcomes_and_restart() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("admission.sqlite");
    let store = StateStore::open(&path).unwrap();
    let jobs: Vec<_> = (0..MAX_ACTIVE_JOBS)
        .map(|i| running(&store, &format!("reserved-{i}")))
        .collect();
    // Mix active execution with sealed but unresolved allocation ownership.
    for job in jobs.iter().take(MAX_ACTIVE_JOBS / 2) {
        store
            .finish_job(job.id, JobState::Unknown, CollectionState::Failed, "{}")
            .unwrap();
    }
    drop(store);
    let store = StateStore::open(&path).unwrap();
    let reject_new = || {
        assert!(matches!(
            store.accept_job(
                "next-reservation",
                "{}",
                Utc::now() + Duration::hours(1),
                Utc::now() + Duration::days(1)
            ),
            Err(JournalError::Capacity("active jobs"))
        ));
    };
    reject_new();
    let old = &jobs[0];
    // Idempotent reconciliation is available even while capacity is exhausted.
    assert!(
        !store
            .accept_job(
                "reserved-0",
                &old.specification,
                chrono::DateTime::from_timestamp(old.deadline, 0).unwrap(),
                chrono::DateTime::from_timestamp(old.retention_until, 0).unwrap()
            )
            .unwrap()
            .1
    );
    let generation = old.vm_id.unwrap();
    assert!(store.confirm_job_cleanup(old.id, generation).is_err());
    store.record_job_vm_destruction(generation).unwrap();
    // VMM termination alone leaves storage/resource cleanup outstanding.
    reject_new();
    store.confirm_job_cleanup(old.id, generation).unwrap();
    let next = submit(&store, "next-reservation");
    assert_eq!(next.state, JobState::Accepted);
    assert!(matches!(
        store.accept_job(
            "one-too-many",
            "{}",
            Utc::now() + Duration::hours(1),
            Utc::now() + Duration::days(1)
        ),
        Err(JournalError::Capacity("active jobs"))
    ));
}

#[test]
fn admission_and_retention_are_bounded_and_deletion_never_allows_key_reexecution() {
    let store = StateStore::open_memory().unwrap();
    let jobs: Vec<_> = (0..MAX_ACTIVE_JOBS)
        .map(|i| submit(&store, &format!("job-{i}")))
        .collect();
    assert!(matches!(
        store.accept_job(
            "over-active",
            "{}",
            Utc::now() + Duration::hours(1),
            Utc::now() + Duration::days(1)
        ),
        Err(JournalError::Capacity(_))
    ));
    // Replay works at capacity, and a new key gets an explicit capacity error.
    let job = &jobs[0];
    assert!(
        !store
            .accept_job(
                "job-0",
                &job.specification,
                chrono::DateTime::from_timestamp(job.deadline, 0).unwrap(),
                chrono::DateTime::from_timestamp(job.retention_until, 0).unwrap()
            )
            .unwrap()
            .1
    );
    for job in jobs {
        store
            .finish_job(job.id, JobState::Interrupted, CollectionState::Failed, "{}")
            .unwrap();
    }
    for i in MAX_ACTIVE_JOBS..MAX_RETAINED_JOBS {
        let job = submit(&store, &format!("job-{i}"));
        store
            .finish_job(
                job.id,
                JobState::InfrastructureFailed,
                CollectionState::Failed,
                "{}",
            )
            .unwrap();
    }
    assert!(matches!(
        store.accept_job(
            "over-retained",
            "{}",
            Utc::now() + Duration::hours(1),
            Utc::now() + Duration::days(1)
        ),
        Err(JournalError::Capacity(_))
    ));
    assert_eq!(
        store
            .expire_job_evidence(Utc::now() + Duration::days(2))
            .unwrap(),
        MAX_RETAINED_JOBS
    );
    let job = submit(&store, "after-retention");
    assert_eq!(job.state, JobState::Accepted);
    assert!(matches!(
        store.accept_job(
            "job-0",
            "{}",
            Utc::now() + Duration::hours(1),
            Utc::now() + Duration::days(1)
        ),
        Err(JournalError::Conflict(_))
    ));
}

#[test]
fn invalid_or_oversized_evidence_and_expired_initial_acceptance_are_rejected() {
    let store = StateStore::open_memory().unwrap();
    let now = Utc::now();
    for spec in [
        "[]".to_owned(),
        "not-json".to_owned(),
        format!("{{\"x\":\"{}\"}}", "x".repeat(MAX_SPEC_BYTES)),
    ] {
        assert!(
            store
                .accept_job(
                    "invalid",
                    &spec,
                    now + Duration::hours(1),
                    now + Duration::days(1)
                )
                .is_err()
        );
    }
    assert!(
        store
            .accept_job(
                "expired",
                "{}",
                now - Duration::seconds(1),
                now + Duration::days(1)
            )
            .is_err()
    );
    assert!(
        store
            .accept_job(
                "retention",
                "{}",
                now + Duration::hours(1),
                now + Duration::days(31)
            )
            .is_err()
    );
    let job = running(&store, "limits");
    for invalid in [
        JobEvent {
            sequence: 1,
            stream: "other".into(),
            data: vec![],
        },
        event(0, b"zero"),
        event(1, &vec![0; MAX_EVENT_BYTES + 1]),
        event(MAX_EVENTS + 1, b"over"),
    ] {
        assert!(store.append_job_events(job.id, &[invalid], false).is_err());
    }
    assert!(
        store
            .finish_job(
                job.id,
                JobState::Completed,
                CollectionState::Complete,
                &format!("{{\"x\":\"{}\"}}", "x".repeat(MAX_MANIFEST_BYTES))
            )
            .is_err()
    );
}

#[test]
fn receipt_capacity_stays_bounded_after_repeated_evidence_deletion() {
    let store = StateStore::open_memory().unwrap();
    for i in 0..MAX_SUBMISSION_RECEIPTS {
        let job = submit(&store, &format!("receipt-{i}"));
        store
            .finish_job(job.id, JobState::Interrupted, CollectionState::Failed, "{}")
            .unwrap();
        store.delete_job_evidence(job.id).unwrap();
    }
    assert!(matches!(
        store.accept_job(
            "overflow",
            "{}",
            Utc::now() + Duration::hours(1),
            Utc::now() + Duration::days(1)
        ),
        Err(JournalError::Capacity("submission receipts"))
    ));
    assert!(matches!(
        store.accept_job(
            "receipt-0",
            "{}",
            Utc::now() + Duration::hours(1),
            Utc::now() + Duration::days(1)
        ),
        Err(JournalError::Conflict(_))
    ));
}

#[test]
fn cleanup_ownership_survives_retention_expiry_and_two_jobs_cannot_share_one_vm() {
    let store = StateStore::open_memory().unwrap();
    let first = running(&store, "first");
    let second = submit(&store, "second");
    assert!(matches!(
        store.bind_job_vm(second.id, first.vm_id.unwrap(), "disposable"),
        Err(JournalError::Conflict(_))
    ));
    assert!(store.delete_job_evidence(second.id).is_err());
    store
        .finish_job(
            first.id,
            JobState::Interrupted,
            CollectionState::Failed,
            "{}",
        )
        .unwrap();
    assert_eq!(
        store
            .expire_job_evidence(Utc::now() + Duration::days(2))
            .unwrap(),
        0
    );
    assert!(store.get_job(first.id).unwrap().cleanup_pending);
    store
        .record_job_vm_destruction(first.vm_id.unwrap())
        .unwrap();
    store
        .confirm_job_cleanup(first.id, first.vm_id.unwrap())
        .unwrap();
    assert_eq!(
        store
            .expire_job_evidence(Utc::now() + Duration::days(2))
            .unwrap(),
        1
    );
}

fn remove_creation_lease_schema_20(conn: &rusqlite::Connection) {
    conn.execute_batch(
        "DROP TRIGGER creation_lease_release_requires_proof;
        DROP TRIGGER creation_lease_cannot_reenter_after_reboot;
        DROP TABLE creation_lease_boot_epochs;
        DROP TRIGGER creation_lease_planned_identity_is_immutable;
        ALTER TABLE host_resource_leases DROP COLUMN allocation_aborted;
        DROP TRIGGER creation_lease_identity_is_immutable;
        ALTER TABLE host_resource_leases DROP COLUMN vm_destroyed;
        ALTER TABLE host_resource_leases DROP COLUMN backend_entered;
        ALTER TABLE host_resource_leases DROP COLUMN vm_id;",
    )
    .unwrap();
}

#[test]
fn migration_16_upgrades_existing_database_and_identity_cannot_be_rewritten() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.sqlite");
    StateStore::open(&path).unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    remove_creation_lease_schema_20(&conn);
    conn.execute_batch(
        "DROP TABLE execution_job_artifacts; DROP TABLE execution_job_events; DROP TABLE execution_jobs; PRAGMA user_version=15;",
    )
    .unwrap();
    let vm_id = Uuid::new_v4();
    conn.execute("INSERT INTO vms(id,name,state,vcpu_count,mem_size_mib,vsock_cid,kernel_path,rootfs_path,created_at,updated_at) VALUES (?1,'migration-survivor','stopped',1,128,3,'kernel','disk',?2,?2)", rusqlite::params![vm_id.to_string(), Utc::now().to_rfc3339()]).unwrap();
    let store = StateStore::open(&path).unwrap();
    assert_eq!(store.get_vm(vm_id).unwrap().name, "migration-survivor");
    let job = running(&store, "immutable");
    for query in [
        "UPDATE execution_jobs SET spec_digest='changed' WHERE id=?1",
        "UPDATE execution_jobs SET deadline=deadline+1 WHERE id=?1",
        "UPDATE execution_jobs SET specification='{}' WHERE id=?1",
        "UPDATE execution_jobs SET vm_id=NULL WHERE id=?1",
    ] {
        assert!(conn.execute(query, [job.id.to_string()]).is_err());
    }
    // Every pooled file connection is initialized with FULL synchronous mode.
    // The public tests exercise real close/reopen persistence; the initialization
    // setting is checked inside the state library tests for each pooled connection.
    assert_eq!(
        conn.query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))
            .unwrap(),
        23
    );
}

fn artifact_digest(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(data)))
}

#[test]
fn binary_artifacts_survive_terminal_vm_deletion_and_reopen_until_explicit_evidence_deletion() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.sqlite");
    let store = StateStore::open(&path).unwrap();
    let job = running(&store, "artifact-reopen");
    let data = [0, 255, 128, 42];
    let digest = artifact_digest(&data);
    let record = store
        .retain_job_artifact(job.id, 0, "results/raw", &digest, &data)
        .unwrap();
    assert_eq!(record.size_bytes, data.len());
    assert_eq!(
        store
            .retain_job_artifact(job.id, 0, "results/raw", &digest, &data)
            .unwrap(),
        record
    );
    assert!(
        store
            .retain_job_artifact(job.id, 0, "results/changed", &digest, &data)
            .is_err()
    );
    assert!(
        store
            .retain_job_artifact(job.id, 1, "results/raw", &digest, &data)
            .is_err()
    );
    assert!(
        store
            .retain_job_artifact(job.id, 1, "results/bad", &digest, b"changed")
            .is_err()
    );
    store
        .finish_job(job.id, JobState::Completed, CollectionState::Complete, "{}")
        .unwrap();
    assert!(
        store
            .retain_job_artifact(job.id, 1, "late", &digest, &data)
            .is_err()
    );
    let generation = job.vm_id.unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute("INSERT INTO vms(id,name,state,vcpu_count,mem_size_mib,vsock_cid,kernel_path,rootfs_path,created_at,updated_at) VALUES (?1,'disposable','stopped',1,128,3,'kernel','disk',?2,?2)", rusqlite::params![generation.to_string(), Utc::now().to_rfc3339()]).unwrap();
    store.delete_vm(generation).unwrap();
    store.record_job_vm_destruction(job.vm_id.unwrap()).unwrap();
    store
        .confirm_job_cleanup(job.id, job.vm_id.unwrap())
        .unwrap();
    drop(store);
    let store = StateStore::open(&path).unwrap();
    assert_eq!(store.job_artifacts(job.id).unwrap(), vec![record]);
    assert_eq!(store.job_artifact(job.id, 0).unwrap(), data);
    assert_eq!(
        store
            .retain_job_artifact(job.id, 0, "results/raw", &digest, &data)
            .unwrap()
            .digest,
        digest
    );
    store.delete_job_evidence(job.id).unwrap();
    assert!(store.job_artifact(job.id, 0).is_err());
}

#[test]
fn artifact_limits_apply_across_multiple_files_and_replay_at_capacity() {
    let store = StateStore::open_memory().unwrap();
    let job = running(&store, "artifact-capacity");
    let data = vec![42; MAX_ARTIFACT_BYTES];
    let digest = artifact_digest(&data);
    for index in 0..4 {
        store
            .retain_job_artifact(job.id, index, &format!("results/{index}"), &digest, &data)
            .unwrap();
    }
    store
        .retain_job_artifact(job.id, 0, "results/0", &digest, &data)
        .unwrap();
    assert!(matches!(
        store.retain_job_artifact(job.id, 4, "overflow", &artifact_digest(b"x"), b"x"),
        Err(JournalError::Capacity(_))
    ));
    for path in ["../escape", "/absolute", "a//b", "a\\b"] {
        assert!(
            store
                .retain_job_artifact(job.id, 5, path, &artifact_digest(b"x"), b"x")
                .is_err()
        );
    }
    assert!(
        store
            .retain_job_artifact(job.id, 16, "index", &artifact_digest(b"x"), b"x")
            .is_err()
    );
    let too_big = vec![0; MAX_ARTIFACT_BYTES + 1];
    assert!(
        store
            .retain_job_artifact(job.id, 5, "large", &artifact_digest(&too_big), &too_big)
            .is_err()
    );
    assert_eq!(store.job_artifacts(job.id).unwrap().len(), 4);
}

#[test]
fn staged_guest_manifest_is_durable_and_immutable_before_export_failure() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.sqlite");
    let store = StateStore::open(&path).unwrap();
    let job = running(&store, "staged");
    store
        .stage_job_manifest(job.id, r#"{"guest":"receipt"}"#)
        .unwrap();
    store
        .stage_job_manifest(job.id, r#"{"guest":"receipt"}"#)
        .unwrap();
    assert!(
        store
            .stage_job_manifest(job.id, r#"{"guest":"changed"}"#)
            .is_err()
    );
    drop(store);
    let store = StateStore::open(&path).unwrap();
    assert_eq!(
        store.get_job(job.id).unwrap().manifest.as_deref(),
        Some(r#"{"guest":"receipt"}"#)
    );
    store.finish_job(job.id, JobState::InfrastructureFailed, CollectionState::Failed,
        r#"{"guest_result":{"guest":"receipt"},"collection_error":"synthetic transfer failure"}"#).unwrap();
    assert!(store.stage_job_manifest(job.id, "{}").is_err());
}

#[test]
fn creation_reservation_survives_restart_and_late_generation_binding_keeps_terminal_state() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.sqlite");
    let store = StateStore::open(&path).unwrap();
    let job = submit(&store, "creation-crash");
    let reserved = store.reserve_job_vm(job.id).unwrap();
    let name = reserved.vm_name.unwrap();
    assert_eq!(name, format!("job-{}", job.id));
    assert_eq!(reserved.state, JobState::Preparing);
    assert!(reserved.cleanup_pending);
    assert!(reserved.vm_id.is_none());
    assert!(store.mark_job_running(job.id).is_err());
    assert!(
        store
            .confirm_unallocated_job_cleanup(job.id, &name)
            .is_err()
    );
    drop(store);
    let store = StateStore::open(&path).unwrap();
    assert_eq!(
        store.recoverable_jobs().unwrap()[0].vm_name.as_deref(),
        Some(name.as_str())
    );
    let replay = store.reserve_job_vm(job.id).unwrap();
    assert_eq!(replay.vm_name.as_deref(), Some(name.as_str()));
    assert!(
        store
            .bind_job_vm(job.id, Uuid::new_v4(), "different")
            .is_err()
    );
    let other = submit(&store, "other-owner");
    assert!(store.bind_job_vm(other.id, Uuid::new_v4(), &name).is_err());
    store
        .finish_job(job.id, JobState::Interrupted, CollectionState::Failed, "{}")
        .unwrap();
    assert!(store.delete_job_evidence(job.id).is_err());
    // Creation completion racing cancellation/recovery must attach the UUID for
    // cleanup, without reviving execution or overwriting the terminal receipt.
    let generation = Uuid::new_v4();
    let late = store.bind_job_vm(job.id, generation, &name).unwrap();
    assert_eq!(late.state, JobState::Interrupted);
    assert_eq!(late.vm_id, Some(generation));
    assert!(store.mark_job_running(job.id).is_err());
    assert!(
        store
            .confirm_unallocated_job_cleanup(job.id, &name)
            .is_err()
    );
    assert!(store.confirm_job_cleanup(job.id, generation).is_err());
    store.record_job_vm_destruction(generation).unwrap();
    store.confirm_job_cleanup(job.id, generation).unwrap();
    store.delete_job_evidence(job.id).unwrap();
}

#[test]
fn unallocated_cleanup_requires_terminal_matching_reservation_and_prevents_late_binding() {
    let store = StateStore::open_memory().unwrap();
    let job = submit(&store, "failed-allocation");
    let reserved = store.reserve_job_vm(job.id).unwrap();
    let name = reserved.vm_name.unwrap();
    store
        .finish_job(
            job.id,
            JobState::InfrastructureFailed,
            CollectionState::Failed,
            "{}",
        )
        .unwrap();
    assert!(
        store
            .confirm_unallocated_job_cleanup(job.id, "different")
            .is_err()
    );
    assert!(store.get_job(job.id).unwrap().cleanup_pending);
    store
        .confirm_unallocated_job_cleanup(job.id, &name)
        .unwrap();
    assert!(store.bind_job_vm(job.id, Uuid::new_v4(), &name).is_err());
    assert!(store.recoverable_jobs().unwrap().is_empty());
    store.delete_job_evidence(job.id).unwrap();
}

#[test]
fn allocation_claim_has_one_winner_and_replay_is_read_only() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.sqlite");
    let store = StateStore::open(&path).unwrap();
    let job = submit(&store, "claim-once");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers = (0..2)
        .map(|_| {
            let store = StateStore::open(&path).unwrap();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.claim_job_vm(job.id).is_ok()
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        workers
            .into_iter()
            .filter_map(|worker| worker.join().unwrap().then_some(()))
            .count(),
        1
    );
    assert_eq!(
        store.reserve_job_vm(job.id).unwrap().state,
        JobState::Preparing
    );
    assert!(store.claim_job_vm(job.id).is_err());
}

#[test]
fn destruction_receipt_survives_reopen_cannot_be_reversed_and_blocks_execution() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.sqlite");
    let store = StateStore::open(&path).unwrap();
    let job = running(&store, "destroyed-receipt");
    let vm_id = job.vm_id.unwrap();
    assert!(!store.job_for_vm(vm_id).unwrap().unwrap().vm_destroyed);
    store.record_job_vm_destruction(vm_id).unwrap();
    assert!(store.mark_job_running(job.id).is_err());
    assert!(store.confirm_job_cleanup(job.id, vm_id).is_err());
    drop(store);
    let store = StateStore::open(&path).unwrap();
    assert!(store.job_for_vm(vm_id).unwrap().unwrap().vm_destroyed);
    let conn = rusqlite::Connection::open(&path).unwrap();
    assert!(
        conn.execute(
            "UPDATE execution_jobs SET vm_destroyed=0 WHERE id=?1",
            [job.id.to_string()]
        )
        .is_err()
    );
    store
        .finish_job(job.id, JobState::Interrupted, CollectionState::Failed, "{}")
        .unwrap();
    store.confirm_job_cleanup(job.id, vm_id).unwrap();
    assert!(!store.get_job(job.id).unwrap().cleanup_pending);
}

#[test]
fn preallocation_abort_is_durable_generation_fenced_and_never_a_destruction_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.sqlite");
    let store = StateStore::open(&path).unwrap();
    let job = submit(&store, "preallocation-abort");
    let generation = Uuid::new_v4();
    let name = format!("job-{}", job.id);
    store.claim_job_vm(job.id).unwrap();
    store.bind_job_vm(job.id, generation, &name).unwrap();
    assert!(
        store
            .record_job_vm_allocation_abort(job.id, Uuid::new_v4())
            .is_err()
    );
    store
        .record_job_vm_allocation_abort(job.id, generation)
        .unwrap();
    store
        .record_job_vm_allocation_abort(job.id, generation)
        .unwrap();
    assert!(store.mark_job_running(job.id).is_err());
    assert!(store.bind_job_vm(job.id, generation, &name).is_err());
    assert!(store.confirm_job_cleanup(job.id, generation).is_err());
    assert!(store.record_job_vm_destruction(generation).is_err());
    drop(store);
    let store = StateStore::open(&path).unwrap();
    let aborted = store.get_job(job.id).unwrap();
    assert!(aborted.vm_allocation_aborted);
    assert!(!aborted.vm_destroyed);
    assert!(aborted.cleanup_pending);
    let conn = rusqlite::Connection::open(&path).unwrap();
    assert!(
        conn.execute(
            "UPDATE execution_jobs SET vm_allocation_aborted=0 WHERE id=?1",
            [job.id.to_string()]
        )
        .is_err()
    );
    store
        .finish_job(job.id, JobState::Interrupted, CollectionState::Failed, "{}")
        .unwrap();
    assert!(store.confirm_job_cleanup(job.id, Uuid::new_v4()).is_err());
    store.confirm_job_cleanup(job.id, generation).unwrap();
    let cleaned = store.get_job(job.id).unwrap();
    assert!(!cleaned.cleanup_pending);
    assert!(cleaned.vm_allocation_aborted);
    assert!(!cleaned.vm_destroyed);
    let active = running(&store, "already-started");
    assert!(
        store
            .record_job_vm_allocation_abort(active.id, active.vm_id.unwrap())
            .is_err()
    );
    store.delete_job_evidence(job.id).unwrap();
}

#[test]
fn migration_20_keeps_existing_uncertain_allocations_unconfirmed() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.sqlite");
    let store = StateStore::open(&path).unwrap();
    let job = running(&store, "legacy-uncertain-allocation");
    store
        .finish_job(job.id, JobState::Unknown, CollectionState::Failed, "{}")
        .unwrap();
    drop(store);
    let conn = rusqlite::Connection::open(&path).unwrap();
    remove_creation_lease_schema_20(&conn);
    conn.execute_batch("DROP TRIGGER execution_job_allocation_abort_is_monotonic; ALTER TABLE execution_jobs DROP COLUMN vm_allocation_aborted; PRAGMA user_version=19;").unwrap();
    drop(conn);
    let store = StateStore::open(&path).unwrap();
    let migrated = store.get_job(job.id).unwrap();
    assert!(migrated.cleanup_pending);
    assert!(!migrated.vm_destroyed);
    assert!(!migrated.vm_allocation_aborted);
    assert!(
        store
            .confirm_job_cleanup(job.id, job.vm_id.unwrap())
            .is_err()
    );
}

#[test]
fn filesystem_pressure_is_atomic_and_replay_never_observes_storage() {
    let store = StateStore::open_memory().unwrap();
    let budget = budget();
    let accept = |key: &str, storage| {
        store.accept_job_with_budget(
            key,
            budget_spec(),
            Utc::now() + Duration::hours(1),
            Utc::now() + Duration::days(1),
            &budget,
            || Ok(storage),
        )
    };
    let boot = 2 * 1024 * 1024 * 1024
        + husker_types::factory_limits::KERNEL_BYTES
        + husker_types::factory_limits::INITRD_BYTES
        + husker_types::factory_limits::SERIAL_BYTES;
    let floor = budget.min_free_storage_bytes;
    for (storage, reason) in [
        (
            FactoryAvailableStorage {
                shared_filesystem: false,
                boot_bytes: boot + floor - 1,
                journal_bytes: u64::MAX,
            },
            "factory boot filesystem pressure",
        ),
        (
            FactoryAvailableStorage {
                shared_filesystem: false,
                boot_bytes: u64::MAX,
                journal_bytes: floor + 64 * 1024 * 1024 - 1,
            },
            "factory journal filesystem pressure",
        ),
        (
            FactoryAvailableStorage {
                shared_filesystem: true,
                boot_bytes: boot + floor,
                journal_bytes: boot + floor,
            },
            "factory boot filesystem pressure",
        ),
    ] {
        assert!(
            matches!(accept("pressure", storage), Err(JournalError::Capacity(r)) if r == reason)
        );
        assert!(store.recoverable_jobs().unwrap().is_empty());
    }
    assert!(
        store
            .accept_job_with_budget(
                "observation-error",
                budget_spec(),
                Utc::now() + Duration::hours(1),
                Utc::now() + Duration::days(1),
                &budget,
                || Err(JournalError::Capacity("observation failed"))
            )
            .is_err()
    );
    assert!(store.recoverable_jobs().unwrap().is_empty());
    let first = accept(
        "accepted",
        FactoryAvailableStorage {
            shared_filesystem: true,
            boot_bytes: boot + floor + 64 * 1024 * 1024,
            journal_bytes: boot + floor + 64 * 1024 * 1024,
        },
    )
    .unwrap()
    .0;
    store
        .finish_job(
            first.id,
            JobState::Interrupted,
            CollectionState::Failed,
            "{}",
        )
        .unwrap();
    // No VM was allocated, but its retained journal still needs headroom.
    assert!(matches!(
        accept(
            "next",
            FactoryAvailableStorage {
                shared_filesystem: false,
                boot_bytes: u64::MAX,
                journal_bytes: floor + 64 * 1024 * 1024
            }
        ),
        Err(JournalError::Capacity(
            "factory journal filesystem pressure"
        ))
    ));
    assert!(
        !store
            .accept_job_with_budget(
                "accepted",
                &first.specification,
                chrono::DateTime::from_timestamp(first.deadline, 0).unwrap(),
                chrono::DateTime::from_timestamp(first.retention_until, 0).unwrap(),
                &budget,
                || panic!("replay must not observe storage")
            )
            .unwrap()
            .1
    );
}

#[test]
fn concurrent_free_space_claims_cannot_overbook() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("free-space.sqlite");
    StateStore::open(&path).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|i| {
            let store = StateStore::open(&path).unwrap();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let budget = budget();
                barrier.wait();
                store.accept_job_with_budget(
                    &format!("space-{i}"),
                    budget_spec(),
                    Utc::now() + Duration::hours(1),
                    Utc::now() + Duration::days(1),
                    &budget,
                    || {
                        Ok(FactoryAvailableStorage {
                            shared_filesystem: false,
                            boot_bytes: 3 * 1024 * 1024 * 1024,
                            journal_bytes: u64::MAX,
                        })
                    },
                )
            })
        })
        .collect();
    let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(
                r,
                Err(JournalError::Capacity("factory boot filesystem pressure"))
            ))
            .count(),
        1
    );
}

#[test]
fn free_storage_floor_is_required_positive_and_checked_for_overflow() {
    let mut limits = budget();
    let mut config = serde_json::to_value(limits).unwrap();
    config
        .as_object_mut()
        .unwrap()
        .remove("min_free_storage_bytes");
    assert!(serde_json::from_value::<FactoryResourceBudget>(config).is_err());
    limits.min_free_storage_bytes = 0;
    assert!(limits.validate().is_err());
    limits.min_free_storage_bytes = u64::MAX;
    let store = StateStore::open_memory().unwrap();
    assert!(matches!(
        budget_submit(&store, "overflow", &limits),
        Err(JournalError::Capacity("factory storage headroom overflow"))
    ));
    assert!(store.recoverable_jobs().unwrap().is_empty());
}

#[test]
fn host_failure_preserves_receipt_committed_after_a_stale_host_observation() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.sqlite");
    let store = StateStore::open(&path).unwrap();
    let other = StateStore::open(&path).unwrap();
    let job = running(&store, "stale-observation");
    store
        .append_job_events(job.id, &[event(1, b"durable prefix")], false)
        .unwrap();
    let observed = store.get_job(job.id).unwrap();
    assert!(observed.manifest.is_none());
    let envelope = r#"{"host_error":"observation failed","collection":"failed"}"#;
    other
        .stage_job_manifest(
            job.id,
            r#"{"commands":[{"exit_code":0}],"identity":"latest guest"}"#,
        )
        .unwrap();
    let sealed = store
        .finish_job_failure(job.id, JobState::Unknown, envelope)
        .unwrap();
    assert_eq!(sealed.state, JobState::Unknown);
    assert_eq!(sealed.collection, CollectionState::Failed);
    assert!(sealed.cleanup_pending && !sealed.vm_destroyed);
    let manifest: serde_json::Value =
        serde_json::from_str(sealed.manifest.as_deref().unwrap()).unwrap();
    assert_eq!(manifest["guest_result"]["identity"], "latest guest");
    assert_eq!(manifest["guest_result"]["commands"][0]["exit_code"], 0);
    assert_eq!(
        store.job_events(job.id, 0).unwrap().events[0].data,
        b"durable prefix"
    );
    assert!(
        store
            .finish_job_failure(job.id, JobState::Cancelled, envelope)
            .is_err()
    );
    assert!(store.stage_job_manifest(job.id, "{}").is_err());
    drop(store);
    let reopened = StateStore::open(&path).unwrap();
    assert_eq!(reopened.get_job(job.id).unwrap().manifest, sealed.manifest);
    assert_eq!(reopened.get_job(job.id).unwrap().state, sealed.state);
}

#[test]
fn concurrent_staging_and_failure_decisions_never_lose_a_committed_guest_receipt() {
    use std::sync::{Arc, Barrier};
    for attempt in 0..8 {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.sqlite");
        let store = StateStore::open(&path).unwrap();
        let job = running(&store, &format!("race-{attempt}"));
        let stager = StateStore::open(&path).unwrap();
        let cancel = StateStore::open(&path).unwrap();
        let timeout = StateStore::open(&path).unwrap();
        let barrier = Arc::new(Barrier::new(4));
        let stage_start = Arc::clone(&barrier);
        let stage = std::thread::spawn(move || {
            stage_start.wait();
            stager.stage_job_manifest(job.id, r#"{"receipt":"racing guest"}"#)
        });
        let cancel_start = Arc::clone(&barrier);
        let cancelled = std::thread::spawn(move || {
            cancel_start.wait();
            cancel.finish_job_failure(job.id, JobState::Cancelled, r#"{"host_error":"cancel"}"#)
        });
        let timeout_start = Arc::clone(&barrier);
        let timed_out = std::thread::spawn(move || {
            timeout_start.wait();
            timeout.finish_job_failure(job.id, JobState::TimedOut, r#"{"host_error":"deadline"}"#)
        });
        barrier.wait();
        let stage = stage.join().unwrap();
        let cancel = cancelled.join().unwrap();
        let timeout = timed_out.join().unwrap();
        let loser = match (cancel, timeout) {
            (Ok(_), Err(error)) | (Err(error), Ok(_)) => error,
            other => panic!("expected exactly one terminal winner: {other:?}"),
        };
        assert!(matches!(loser, JournalError::Conflict(_)));
        let sealed = store.get_job(job.id).unwrap();
        let manifest: serde_json::Value =
            serde_json::from_str(sealed.manifest.as_deref().unwrap()).unwrap();
        assert_eq!(
            manifest["host_error"],
            if sealed.state == JobState::Cancelled {
                "cancel"
            } else {
                "deadline"
            }
        );
        assert_eq!(sealed.collection, CollectionState::Failed);
        match stage {
            Ok(()) => assert_eq!(manifest["guest_result"]["receipt"], "racing guest"),
            Err(error) => {
                assert!(matches!(error, JournalError::Conflict(_)));
                assert!(manifest.get("guest_result").is_none());
            }
        }
    }
}

#[test]
fn failed_failure_publication_rolls_back_and_retry_bounds_the_latest_guest_receipt() {
    use sha2::{Digest, Sha256};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.sqlite");
    let store = StateStore::open(&path).unwrap();
    let job = running(&store, "bounded-failure");
    let staged = serde_json::json!({"payload": "x".repeat(65500)}).to_string();
    store.stage_job_manifest(job.id, &staged).unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("CREATE TRIGGER fail_terminal BEFORE UPDATE OF state ON execution_jobs BEGIN SELECT RAISE(ABORT, 'injected terminal failure'); END;").unwrap();
    let envelope = serde_json::json!({"host_error": "fault".repeat(128)}).to_string();
    assert!(
        store
            .finish_job_failure(job.id, JobState::Unknown, &envelope)
            .is_err()
    );
    let pending = store.get_job(job.id).unwrap();
    assert_eq!(pending.state, JobState::Running);
    assert_eq!(pending.collection, CollectionState::Pending);
    assert_eq!(pending.manifest.as_deref(), Some(staged.as_str()));
    connection
        .execute_batch("DROP TRIGGER fail_terminal;")
        .unwrap();
    let sealed = store
        .finish_job_failure(job.id, JobState::Unknown, &envelope)
        .unwrap();
    let encoded = sealed.manifest.as_deref().unwrap();
    assert!(encoded.len() <= MAX_MANIFEST_BYTES);
    let manifest: serde_json::Value = serde_json::from_str(encoded).unwrap();
    assert!(manifest.get("guest_result").is_none());
    assert_eq!(manifest["guest_result_body_truncated"], true);
    assert_eq!(
        manifest["guest_result_sha256"],
        format!("sha256:{}", hex::encode(Sha256::digest(staged.as_bytes())))
    );
    assert_eq!(sealed.collection, CollectionState::Failed);
    assert!(
        store
            .finish_job_failure(job.id, JobState::Unknown, &envelope)
            .is_err()
    );
    assert_eq!(store.get_job(job.id).unwrap().manifest, sealed.manifest);
}

#[test]
fn failure_envelopes_cannot_forge_guest_receipts_or_command_completion() {
    let store = StateStore::open_memory().unwrap();
    let job = running(&store, "envelope-validation");
    store
        .stage_job_manifest(job.id, r#"{"receipt":"original"}"#)
        .unwrap();
    for state in [
        JobState::Completed,
        JobState::CommandFailed,
        JobState::Running,
    ] {
        assert!(store.finish_job_failure(job.id, state, "{}").is_err());
    }
    for envelope in [
        r#"{"guest_result":{}}"#,
        r#"{"guest_result_sha256":"forged"}"#,
        r#"{"guest_result_body_truncated":false}"#,
        "[]",
        "invalid",
    ] {
        assert!(
            store
                .finish_job_failure(job.id, JobState::Unknown, envelope)
                .is_err()
        );
    }
    // A valid but near-limit host envelope cannot discard the receipt simply
    // because even its hash envelope would exceed the total bound.
    let too_large = serde_json::json!({"host_error": "x".repeat(65510)}).to_string();
    assert!(
        store
            .finish_job_failure(job.id, JobState::Unknown, &too_large)
            .is_err()
    );
    assert_eq!(store.get_job(job.id).unwrap().state, JobState::Running);
    assert_eq!(
        store.get_job(job.id).unwrap().manifest.as_deref(),
        Some(r#"{"receipt":"original"}"#)
    );
}
