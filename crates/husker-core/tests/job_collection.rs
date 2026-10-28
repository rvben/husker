//! Collect over real framed agent messages into real SQLite; no VMM/runtime
//! claim is made by this synthetic guest transport.
use chrono::{TimeZone, Utc};
use husker_agent_proto::job_spec::JobSpec;
use husker_agent_proto::*;
use husker_core::agent_client::AgentConnection;
use husker_core::job_collection::collect_finished_job;
use husker_state::{StateStore, jobs::*};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn fixture(store: &StateStore) -> (JobRecord, JobSpec, Vec<u8>) {
    let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&data)));
    let deadline = Utc.timestamp_opt(Utc::now().timestamp() + 60, 0).unwrap();
    let spec: JobSpec = serde_json::from_value(json!({
        "version": 1, "image": {"catalog_id": Uuid::new_v4(), "rootfs_digest": format!("sha256:{}", "a".repeat(64)), "kernel_digest": format!("sha256:{}", "b".repeat(64)), "initrd_digest": null},
        "source": {"digest": digest, "size_bytes": 1024}, "acceptance": {"digest": digest, "size_bytes": 1024},
        "commands": [{"argv": ["true"], "timeout_secs": 30}], "working_directory": "/workspace",
        "writable_directories": ["results"], "environment": {}, "uid": 1000, "gid": 1000,
        "resources": {"vcpu_count": 1, "mem_size_mib": 512, "disk_size_bytes": 2 * 1024_u64.pow(3), "pids_limit": 128},
        "network": {"mode": "none"}, "deadline": deadline,
        "artifacts": [{"path": "results/output", "max_bytes": 100000}],
        "correlation": {"job": "synthetic", "stage": "candidate", "round": 0}
    })).unwrap();
    let job = store
        .accept_job(
            "submission",
            &spec.canonical_json().unwrap(),
            deadline,
            deadline + chrono::Duration::days(1),
        )
        .unwrap()
        .0;
    store
        .bind_job_vm(job.id, Uuid::new_v4(), "disposable")
        .unwrap();
    store.mark_job_running(job.id).unwrap();
    (store.get_job(job.id).unwrap(), spec, data)
}

fn guest(
    job: &JobRecord,
    spec: &JobSpec,
    artifact: Vec<u8>,
    mode: &'static str,
) -> (
    AgentConnection<tokio::io::DuplexStream>,
    tokio::task::JoinHandle<()>,
) {
    let job = job.clone();
    let manifest = json!({
        "version": 1, "job_id": job.id, "execution_specification_digest": spec.digest().unwrap(),
        "image": spec.image, "source": spec.source, "acceptance": spec.acceptance,
        "commands": [{"command_index": 0, "exit_code": 0, "outcome": "completed", "duration_ms": 1, "output": "ok", "output_truncated": false, "logs_truncated": false, "termination_confirmed": true}],
        "artifacts": [{"path": "results/output", "stored_name": "0.bin", "digest": format!("sha256:{}",hex::encode(Sha256::digest(&artifact))), "size_bytes": artifact.len(), "error": null}],
        "source_changed": mode == "source_changed", "source_verification_error": null,
        "collection_status": "complete", "outcome": "completed"
    }).to_string().into_bytes();
    let (client, mut server) = tokio::io::duplex(256 * 1024);
    let task = tokio::spawn(async move {
        while let Some(request) = read_message::<AgentRequest, _>(&mut server).await.unwrap() {
            let info = SessionInfo {
                id: job.session_id.to_string(),
                command: "/usr/local/bin/husker-job-runner".into(),
                state: SessionState::Completed,
                created_at: 1,
                finished_at: Some(2),
                exit_code: Some(if mode == "runner_failed" { 127 } else { 0 }),
                output_truncated: mode == "truncated",
            };
            let response = match request {
                AgentRequest::GuestInfo => AgentResponse::GuestInfo(GuestInfoResponse {
                    ipv4: vec![],
                    protocol_version: PROTOCOL_VERSION,
                }),
                AgentRequest::SessionGet { .. } => AgentResponse::Session(info),
                AgentRequest::SessionEvents { after, .. } => {
                    let events: Vec<_> = [
                        SessionEvent {
                            sequence: 1,
                            stream: "stdout".into(),
                            data: base64_encode(b"hello"),
                        },
                        SessionEvent {
                            sequence: 2,
                            stream: "stderr".into(),
                            data: base64_encode(&[0, 255]),
                        },
                    ]
                    .into_iter()
                    .filter(|e| e.sequence > after)
                    .collect();
                    AgentResponse::SessionEvents(SessionEventsResponse {
                        session: info,
                        next_cursor: events.last().map_or(after, |e| e.sequence),
                        events,
                        has_more: false,
                    })
                }
                AgentRequest::ReadFile(request) => {
                    let is_artifact = request.path.ends_with("0.bin");
                    if is_artifact && mode == "missing" {
                        AgentResponse::Error(ErrorResponse {
                            code: None,
                            message: "synthetic missing artifact".into(),
                        })
                    } else {
                        let mut bytes = if is_artifact {
                            artifact.clone()
                        } else {
                            manifest.clone()
                        };
                        if is_artifact && mode == "bad_digest" {
                            bytes[0] ^= 1;
                        }
                        let offset = request.offset as usize;
                        let end = bytes.len().min(offset + request.len.unwrap() as usize);
                        AgentResponse::ReadFile(ReadFileResponse {
                            data: base64_encode(&bytes[offset..end]),
                            size: (end - offset) as u64,
                            total_size: Some(bytes.len() as u64),
                            modified_nanos: Some(
                                if mode == "changed_transfer" && is_artifact && offset > 0 {
                                    2
                                } else {
                                    1
                                },
                            ),
                        })
                    }
                }
                other => panic!("unexpected request {other:?}"),
            };
            write_message(&mut server, &response).await.unwrap();
        }
    });
    (AgentConnection::new(client), task)
}

#[tokio::test]
async fn collects_cursor_reconnect_binary_artifacts_and_manifest_before_vm_row_deletion() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.sqlite");
    let store = StateStore::open(&path).unwrap();
    let (job, spec, data) = fixture(&store);
    store
        .append_job_events(
            job.id,
            &[JobEvent {
                sequence: 1,
                stream: "stdout".into(),
                data: b"hello".to_vec(),
            }],
            false,
        )
        .unwrap();
    let (mut connection, task) = guest(&job, &spec, data.clone(), "good");
    let result = collect_finished_job(&store, job.id, &mut connection)
        .await
        .unwrap();
    assert_eq!(result.state, JobState::Completed);
    assert_eq!(result.collection, CollectionState::Complete);
    assert!(result.cleanup_pending);
    drop(connection);
    task.await.unwrap();
    let generation = job.vm_id.unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute("INSERT INTO vms(id,name,state,vcpu_count,mem_size_mib,vsock_cid,kernel_path,rootfs_path,created_at,updated_at) VALUES (?1,'disposable','stopped',1,128,3,'kernel','disk',?2,?2)", rusqlite::params![generation.to_string(), Utc::now().to_rfc3339()]).unwrap();
    store.delete_vm(generation).unwrap();
    drop(store);
    let store = StateStore::open(&path).unwrap();
    assert_eq!(store.job_artifact(job.id, 0).unwrap(), data);
    let page = store.job_events(job.id, 1).unwrap();
    assert_eq!(page.next_cursor, 2);
    assert_eq!(page.events[0].data, [0, 255]);
    assert_eq!(page.job.state, JobState::Completed);
    assert!(page.job.manifest.is_some());
}

#[tokio::test]
async fn missing_corrupt_changed_exports_and_source_mutation_remain_nonpassing() {
    for mode in [
        "missing",
        "bad_digest",
        "changed_transfer",
        "source_changed",
    ] {
        let store = StateStore::open_memory().unwrap();
        let (job, spec, data) = fixture(&store);
        let (mut connection, task) = guest(&job, &spec, data, mode);
        assert!(
            collect_finished_job(&store, job.id, &mut connection)
                .await
                .is_err(),
            "{mode}"
        );
        let result = store.get_job(job.id).unwrap();
        assert_eq!(result.state, JobState::InfrastructureFailed, "{mode}");
        assert_eq!(result.collection, CollectionState::Failed);
        assert!(result.cleanup_pending);
        let failure: serde_json::Value =
            serde_json::from_str(result.manifest.as_deref().unwrap()).unwrap();
        assert!(failure["collection_error"].is_string());
        if mode != "source_changed" {
            assert_eq!(failure["guest_result"]["commands"][0]["exit_code"], 0);
        }
        assert!(store.job_artifacts(job.id).unwrap().is_empty());
        assert_eq!(store.job_events(job.id, 0).unwrap().events.len(), 2);
        drop(connection);
        task.await.unwrap();
    }
}

#[tokio::test]
async fn guest_log_truncation_is_preserved_when_artifacts_are_complete() {
    let store = StateStore::open_memory().unwrap();
    let (job, spec, data) = fixture(&store);
    let (mut connection, task) = guest(&job, &spec, data, "truncated");
    let result = collect_finished_job(&store, job.id, &mut connection)
        .await
        .unwrap();
    assert_eq!(result.collection, CollectionState::Truncated);
    assert!(result.output_truncated);
    drop(connection);
    task.await.unwrap();
}

fn live_output_guest(
    job: &JobRecord,
    sequence: u64,
    terminal: bool,
    malformed: bool,
) -> (
    AgentConnection<tokio::io::DuplexStream>,
    tokio::task::JoinHandle<()>,
) {
    let job = job.clone();
    let (client, mut peer) = tokio::io::duplex(1024);
    let task = tokio::spawn(async move {
        while let Some(request) = read_message::<AgentRequest, _>(&mut peer).await.unwrap() {
            let mut info = SessionInfo {
                id: job.session_id.to_string(),
                command: "/usr/local/bin/husker-job-runner".into(),
                state: SessionState::Running,
                created_at: 1,
                finished_at: None,
                exit_code: None,
                output_truncated: false,
            };
            let response = match request {
                AgentRequest::GuestInfo => AgentResponse::GuestInfo(GuestInfoResponse {
                    ipv4: vec![],
                    protocol_version: PROTOCOL_VERSION,
                }),
                AgentRequest::SessionGet { id } => {
                    assert_eq!(id, info.id);
                    AgentResponse::Session(info)
                }
                AgentRequest::SessionEvents { id, after, .. } => {
                    assert_eq!(id, info.id);
                    assert_eq!(after, sequence - 1);
                    if terminal {
                        info.state = SessionState::Completed;
                        info.finished_at = Some(2);
                        info.exit_code = Some(0);
                    }
                    AgentResponse::SessionEvents(SessionEventsResponse {
                        session: info,
                        events: vec![SessionEvent {
                            sequence,
                            stream: "stdout".into(),
                            data: base64_encode(&[sequence as u8, 0, 255]),
                        }],
                        next_cursor: if malformed { sequence + 1 } else { sequence },
                        has_more: false,
                    })
                }
                other => {
                    panic!("live capture must not submit execution or read result files: {other:?}")
                }
            };
            write_message(&mut peer, &response).await.unwrap();
        }
    });
    (AgentConnection::new(client), task)
}

#[tokio::test]
async fn live_output_is_durable_before_terminal_result_and_reconnect_resumes_cursor() {
    use husker_core::job_collection::capture_job_output;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.sqlite");
    let store = StateStore::open(&path).unwrap();
    let (job, _, _) = fixture(&store);
    let (mut connection, task) = live_output_guest(&job, 1, false, false);
    let observed = capture_job_output(&store, job.id, &mut connection)
        .await
        .unwrap();
    assert_eq!(observed.state, SessionState::Running);
    assert_eq!(store.get_job(job.id).unwrap().capture_cursor, 1);
    assert_eq!(
        store.get_job(job.id).unwrap().collection,
        CollectionState::Pending
    );
    drop(connection);
    task.await.unwrap();
    drop(store);
    let store = StateStore::open(&path).unwrap();
    assert_eq!(
        store.job_events(job.id, 0).unwrap().events[0].data,
        [1, 0, 255]
    );
    // A malformed next page cannot erase earlier host evidence or advance its
    // durable cursor. The next connection retries from that committed cursor.
    let (mut connection, task) = live_output_guest(&job, 2, false, true);
    assert!(
        capture_job_output(&store, job.id, &mut connection)
            .await
            .is_err()
    );
    assert_eq!(store.get_job(job.id).unwrap().capture_cursor, 1);
    assert_eq!(
        store.get_job(job.id).unwrap().collection,
        CollectionState::Pending
    );
    drop(connection);
    task.await.unwrap();
    let (mut connection, task) = live_output_guest(&job, 2, true, false);
    let observed = capture_job_output(&store, job.id, &mut connection)
        .await
        .unwrap();
    assert_eq!(observed.state, SessionState::Completed);
    assert_eq!(store.get_job(job.id).unwrap().capture_cursor, 2);
    let events = store.job_events(job.id, 0).unwrap().events;
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].data, [2, 0, 255]);
    // A successful helper receipt alone is still not a passing factory job.
    assert_eq!(store.get_job(job.id).unwrap().state, JobState::Running);
    assert_eq!(
        store.get_job(job.id).unwrap().collection,
        CollectionState::Pending
    );
    drop(connection);
    task.await.unwrap();
}

#[tokio::test]
async fn failed_helper_still_exports_logs_before_explicit_infrastructure_failure() {
    let store = StateStore::open_memory().unwrap();
    let (job, spec, data) = fixture(&store);
    let (mut connection, task) = guest(&job, &spec, data, "runner_failed");
    assert!(
        collect_finished_job(&store, job.id, &mut connection)
            .await
            .is_err()
    );
    let failed = store.get_job(job.id).unwrap();
    assert_eq!(failed.state, JobState::InfrastructureFailed);
    assert_eq!(failed.collection, CollectionState::Failed);
    assert!(failed.cleanup_pending);
    assert_eq!(failed.capture_cursor, 2);
    let logs = store.job_events(job.id, 0).unwrap();
    assert_eq!(logs.events[0].data, b"hello");
    assert_eq!(logs.events[1].data, [0, 255]);
    assert!(
        failed
            .manifest
            .unwrap()
            .contains("no confirmed successful terminal receipt")
    );
    drop(connection);
    task.await.unwrap();
}
