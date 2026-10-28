//! Framed synthetic guest + actual SQLite, not a live VM proof.
use chrono::{TimeZone, Utc};
use husker_agent_proto::frozen_bundle::{BundleFile, FrozenBundle};
use husker_agent_proto::job_spec::JobSpec;
use husker_agent_proto::*;
use husker_core::agent_client::AgentConnection;
use husker_core::job_launch::stage_and_launch_job;
use husker_state::{StateStore, jobs::*};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

fn fixture(store: &StateStore) -> (JobRecord, FrozenBundle, FrozenBundle) {
    fixture_with_lifetime(store, 60)
}
fn fixture_with_lifetime(
    store: &StateStore,
    seconds: i64,
) -> (JobRecord, FrozenBundle, FrozenBundle) {
    let source = FrozenBundle::from_files(BTreeMap::from([(
        "src/code".into(),
        BundleFile {
            data: vec![42; 150000],
            executable: false,
        },
    )]))
    .unwrap();
    let acceptance = FrozenBundle::from_files(BTreeMap::from([(
        "test.py".into(),
        BundleFile {
            data: b"assert True".to_vec(),
            executable: false,
        },
    )]))
    .unwrap();
    let deadline = Utc
        .timestamp_opt(Utc::now().timestamp() + seconds, 0)
        .unwrap();
    let digest = format!("sha256:{}", "a".repeat(64));
    let spec: JobSpec = serde_json::from_value(json!({
        "version":1,"image":{"catalog_id":Uuid::new_v4(),"rootfs_digest":digest,"kernel_digest":digest,"initrd_digest":null},
        "source":{"digest":source.digest(),"size_bytes":source.bytes().len()},
        "acceptance":{"digest":acceptance.digest(),"size_bytes":acceptance.bytes().len()},
        "commands":[{"argv":["true"],"timeout_secs":20}],"working_directory":"/workspace",
        "writable_directories":["target"],"environment":{},"uid":1000,"gid":1000,
        "resources":{"vcpu_count":1,"mem_size_mib":512,"disk_size_bytes":2147483648_u64,"pids_limit":32},
        "network":{"mode":"none"},"deadline":deadline,"artifacts":[],
        "correlation":{"job":"fixture","stage":"baseline","round":1}
    })).unwrap();
    let (job, _) = store
        .accept_job(
            "launch",
            &spec.canonical_json().unwrap(),
            deadline,
            deadline + chrono::Duration::hours(1),
        )
        .unwrap();
    store
        .bind_job_vm(job.id, Uuid::new_v4(), "disposable")
        .unwrap();
    (store.get_job(job.id).unwrap(), source, acceptance)
}

type UploadedFiles = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

fn guest(
    job: &JobRecord,
    lose_start_ack: bool,
    fail_upload: bool,
    reconnect: bool,
) -> (
    AgentConnection<tokio::io::DuplexStream>,
    tokio::task::JoinHandle<()>,
    UploadedFiles,
) {
    let job = job.clone();
    let files = Arc::new(Mutex::new(BTreeMap::<String, Vec<u8>>::new()));
    let recorded = files.clone();
    let (client, mut peer) = tokio::io::duplex(1024);
    let task = tokio::spawn(async move {
        let mut starts = 0;
        while let Some(request) = read_message::<AgentRequest, _>(&mut peer).await.unwrap() {
            let info = SessionInfo {
                id: job.session_id.to_string(),
                command: "/usr/local/bin/husker-job-runner".into(),
                state: SessionState::Running,
                created_at: job.created_at as u64,
                finished_at: None,
                exit_code: None,
                output_truncated: false,
            };
            let response = match request {
                AgentRequest::GuestInfo => AgentResponse::GuestInfo(GuestInfoResponse {
                    ipv4: vec![],
                    protocol_version: PROTOCOL_VERSION,
                }),
                AgentRequest::Exec(exec) => {
                    assert!(!reconnect);
                    assert_eq!(exec.command, "/usr/local/bin/husker-job-runner");
                    assert_eq!(
                        exec.args,
                        ["--prepare", &job.id.to_string(), &job.specification_digest]
                    );
                    assert!(exec.env.is_empty());
                    AgentResponse::Exec(ExecResponse {
                        exit_code: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                }
                AgentRequest::WriteFile(write) => {
                    assert!(!reconnect);
                    let bytes = base64_decode(&write.data).unwrap();
                    assert!(bytes.len() <= 65536);
                    assert_eq!(write.mode, Some(0o600));
                    if fail_upload {
                        AgentResponse::WriteFile(WriteFileResponse { bytes_written: 0 })
                    } else {
                        let mut files = recorded.lock().unwrap();
                        let data = files.entry(write.path).or_default();
                        if !write.append {
                            data.clear();
                        }
                        data.extend(&bytes);
                        AgentResponse::WriteFile(WriteFileResponse {
                            bytes_written: bytes.len() as u64,
                        })
                    }
                }
                AgentRequest::SessionStartReplay(start) => {
                    assert!(!reconnect);
                    starts += 1;
                    assert_eq!(starts, 1);
                    assert_eq!(start.id, job.session_id.to_string());
                    assert_eq!(
                        start.exec.args,
                        [job.id.to_string(), job.specification_digest.clone()]
                    );
                    assert_eq!(
                        start.exec.timeout_secs,
                        Some((job.deadline - job.created_at) as u64)
                    );
                    assert_eq!(recorded.lock().unwrap().len(), 3);
                    if lose_start_ack {
                        return;
                    }
                    AgentResponse::Session(info)
                }
                AgentRequest::SessionGet { id } => {
                    assert!(reconnect);
                    assert_eq!(id, job.session_id.to_string());
                    AgentResponse::Session(info)
                }
                other => panic!("unexpected launch request: {other:?}"),
            };
            write_message(&mut peer, &response).await.unwrap();
        }
    });
    (AgentConnection::new(client), task, files)
}

#[tokio::test]
async fn uploads_bounded_exact_inputs_before_one_stable_session_submission() {
    let store = StateStore::open_memory().unwrap();
    let (job, source, acceptance) = fixture(&store);
    let (mut connection, task, files) = guest(&job, false, false, false);
    let info = stage_and_launch_job(&store, job.id, &mut connection, &source, &acceptance)
        .await
        .unwrap();
    assert_eq!(info.id, job.session_id.to_string());
    assert_eq!(store.get_job(job.id).unwrap().state, JobState::Running);
    assert_eq!(
        files.lock().unwrap()["/run/husker-job/source.tar"],
        source.bytes()
    );
    assert_eq!(
        files.lock().unwrap()["/run/husker-job/acceptance.tar"],
        acceptance.bytes()
    );
    assert_eq!(
        files.lock().unwrap()["/run/husker-job/spec.json"],
        job.specification.as_bytes()
    );
    drop(connection);
    task.await.unwrap();
}

#[tokio::test]
async fn lost_start_response_survives_reopen_and_reconnect_only_observes() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state.sqlite");
    let store = StateStore::open(&path).unwrap();
    let (job, source, acceptance) = fixture(&store);
    let (mut connection, task, _) = guest(&job, true, false, false);
    assert!(
        stage_and_launch_job(&store, job.id, &mut connection, &source, &acceptance)
            .await
            .is_err()
    );
    task.await.unwrap();
    drop(store);
    let store = StateStore::open(&path).unwrap();
    let current = store.get_job(job.id).unwrap();
    assert_eq!(current.state, JobState::Running);
    assert_eq!(current.collection, CollectionState::Pending);
    let (mut connection, task, files) = guest(&current, false, false, true);
    stage_and_launch_job(&store, job.id, &mut connection, &source, &acceptance)
        .await
        .unwrap();
    assert!(files.lock().unwrap().is_empty());
    drop(connection);
    task.await.unwrap();
}

#[tokio::test]
async fn incomplete_upload_is_terminal_infrastructure_failure_and_never_starts_checks() {
    let store = StateStore::open_memory().unwrap();
    let (job, source, acceptance) = fixture(&store);
    let (mut connection, task, _) = guest(&job, false, true, false);
    assert!(
        stage_and_launch_job(&store, job.id, &mut connection, &source, &acceptance)
            .await
            .is_err()
    );
    let failed = store.get_job(job.id).unwrap();
    assert_eq!(failed.state, JobState::InfrastructureFailed);
    assert_eq!(failed.collection, CollectionState::Failed);
    assert!(failed.cleanup_pending);
    assert!(failed.manifest.unwrap().contains("incomplete input chunk"));
    drop(connection);
    task.await.unwrap();
}

#[tokio::test]
async fn absent_session_on_reconnect_stays_unknown_without_fresh_submission() {
    let store = StateStore::open_memory().unwrap();
    let (job, source, acceptance) = fixture(&store);
    store.mark_job_running(job.id).unwrap();
    let (client, mut peer) = tokio::io::duplex(1024);
    let expected = job.session_id.to_string();
    let task = tokio::spawn(async move {
        assert!(matches!(
            read_message::<AgentRequest, _>(&mut peer)
                .await
                .unwrap()
                .unwrap(),
            AgentRequest::GuestInfo
        ));
        write_message(
            &mut peer,
            &AgentResponse::GuestInfo(GuestInfoResponse {
                ipv4: vec![],
                protocol_version: PROTOCOL_VERSION,
            }),
        )
        .await
        .unwrap();

        assert!(
            matches!(read_message::<AgentRequest,_>(&mut peer).await.unwrap().unwrap(),
            AgentRequest::SessionGet {id} if id==expected)
        );
        write_message(
            &mut peer,
            &AgentResponse::Error(ErrorResponse {
                code: None,
                message: "session not found".into(),
            }),
        )
        .await
        .unwrap();
        assert!(
            read_message::<AgentRequest, _>(&mut peer)
                .await
                .unwrap()
                .is_none()
        );
    });
    let mut connection = AgentConnection::new(client);
    assert!(
        stage_and_launch_job(&store, job.id, &mut connection, &source, &acceptance)
            .await
            .is_err()
    );
    let pending = store.get_job(job.id).unwrap();
    assert_eq!(pending.state, JobState::Running);
    assert_eq!(pending.collection, CollectionState::Pending);
    assert!(pending.cleanup_pending);
    drop(connection);
    task.await.unwrap();
}

#[tokio::test]
async fn stalled_staging_obeys_absolute_deadline_and_never_submits_session() {
    let store = StateStore::open_memory().unwrap();
    let (job, source, acceptance) = fixture_with_lifetime(&store, 2);
    let (client, mut peer) = tokio::io::duplex(1024);
    let task = tokio::spawn(async move {
        assert!(matches!(
            read_message::<AgentRequest, _>(&mut peer)
                .await
                .unwrap()
                .unwrap(),
            AgentRequest::GuestInfo
        ));
        write_message(
            &mut peer,
            &AgentResponse::GuestInfo(GuestInfoResponse {
                ipv4: vec![],
                protocol_version: PROTOCOL_VERSION,
            }),
        )
        .await
        .unwrap();
        assert!(matches!(
            read_message::<AgentRequest, _>(&mut peer)
                .await
                .unwrap()
                .unwrap(),
            AgentRequest::Exec(_)
        ));
        write_message(
            &mut peer,
            &AgentResponse::Exec(ExecResponse {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }),
        )
        .await
        .unwrap();
        assert!(matches!(
            read_message::<AgentRequest, _>(&mut peer)
                .await
                .unwrap()
                .unwrap(),
            AgentRequest::WriteFile(_)
        ));
        // Withhold the write response; the host deadline must cover transfer,
        // including a peer that sends no further bytes at all.
        assert!(
            read_message::<AgentRequest, _>(&mut peer)
                .await
                .unwrap()
                .is_none()
        );
    });
    let mut connection = AgentConnection::new(client);
    assert!(
        stage_and_launch_job(&store, job.id, &mut connection, &source, &acceptance)
            .await
            .is_err()
    );
    let finished = Utc::now();
    assert!(
        finished.timestamp_millis() < job.deadline * 1000 + 200,
        "deadline acquired extra whole-second grace"
    );
    let failed = store.get_job(job.id).unwrap();
    assert_eq!(failed.state, JobState::TimedOut);
    assert_eq!(failed.collection, CollectionState::Failed);
    assert!(failed.cleanup_pending);
    drop(connection);
    task.await.unwrap();
}
