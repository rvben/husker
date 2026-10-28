//! Host journal HTTP contract; no VMM or untrusted guest is activated.
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use husker_agent_proto::{
    base64_encode,
    frozen_bundle::{BundleFile, FrozenBundle},
    job_spec::{JobSpec, JobSubmission},
};
use husker_api::{ApiPolicy, BearerToken, router_with_auth};
use husker_core::HuskerCore;
use husker_state::{
    StateStore,
    jobs::{CollectionState, JobEvent, JobState},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};
use tower::ServiceExt;
use uuid::Uuid;

// Use the minimum valid disk reservation: this HTTP contract does not need a larger disk.
fn spec(bundle: &FrozenBundle) -> JobSpec {
    serde_json::from_value(json!({
        "version":1,"image":{"catalog_id":Uuid::new_v4(),"rootfs_digest":format!("sha256:{}", "a".repeat(64)),"kernel_digest":format!("sha256:{}", "b".repeat(64)),"initrd_digest":null},
        "source":{"digest":bundle.digest(),"size_bytes":bundle.bytes().len()},
        "acceptance":{"digest":bundle.digest(),"size_bytes":bundle.bytes().len()},
        "commands":[{"argv":["true"],"timeout_secs":20}],"working_directory":"/workspace",
        "writable_directories":[],"environment":{},"uid":1000,"gid":1000,
        "resources":{"vcpu_count":1,"mem_size_mib":512,"disk_size_bytes":1073741824_u64,"pids_limit":32},
        "network":{"mode":"none"},"deadline":chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp()+60,0),"artifacts":[],
        "correlation":{"job":"http-fixture","stage":"baseline","round":1}
    })).unwrap()
}
async fn request(
    app: &axum::Router,
    method: &str,
    path: &str,
    body: Value,
    auth: bool,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("Content-Type", "application/json");
    if auth {
        request = request.header("Authorization", "Bearer synthetic-token");
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
#[tokio::test]
async fn retained_evidence_auth_replay_cancel_and_deletion_contract() {
    let temp = tempfile::tempdir().unwrap();
    let store = StateStore::open(&temp.path().join("state.db")).unwrap();
    let bundle = FrozenBundle::from_files(BTreeMap::from([(
        "input".into(),
        BundleFile {
            data: b"frozen".to_vec(),
            executable: false,
        },
    )]))
    .unwrap();
    let spec = spec(&bundle);
    let submission = JobSubmission {
        idempotency_key: "retained".into(),
        execution_specification_digest: spec.digest().unwrap(),
        specification: spec.clone(),
    };
    let (job, _) = store
        .accept_job(
            &submission.idempotency_key,
            &spec.canonical_json().unwrap(),
            spec.deadline,
            spec.deadline + chrono::Duration::hours(1),
        )
        .unwrap();
    let vm = Uuid::new_v4();
    store
        .bind_job_vm(job.id, vm, &format!("job-{}", job.id))
        .unwrap();
    store.mark_job_running(job.id).unwrap();
    store
        .append_job_events(
            job.id,
            &[JobEvent {
                sequence: 1,
                stream: "stdout".into(),
                data: vec![0, 255, 10],
            }],
            false,
        )
        .unwrap();
    let bytes = b"declared evidence\0";
    let digest = format!(
        "sha256:{}",
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    store
        .retain_job_artifact(job.id, 0, "result.txt", &digest, bytes)
        .unwrap();
    store
        .finish_job(
            job.id,
            JobState::Completed,
            CollectionState::Complete,
            "{\"fixture\":true}",
        )
        .unwrap();
    store.record_job_vm_destruction(vm).unwrap();
    store.confirm_job_cleanup(job.id, vm).unwrap();
    let (active, _) = store
        .accept_job(
            "active",
            &spec.canonical_json().unwrap(),
            spec.deadline,
            spec.deadline + chrono::Duration::hours(1),
        )
        .unwrap();
    store
        .bind_job_vm(active.id, Uuid::new_v4(), &format!("job-{}", active.id))
        .unwrap();
    let storage = husker_storage::StorageConfig {
        data_dir: temp.path().into(),
        state_dir: temp.path().into(),
    };
    let vmm = husker_vmm::firecracker::FirecrackerBackend::new(
        std::path::Path::new("/nonexistent"),
        temp.path(),
        Arc::new(husker_vmm::cgroup::CgroupSupervisor::disabled()),
    );
    #[cfg(feature = "linux-net")]
    let core = HuskerCore::new(
        vmm,
        store,
        husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
        storage,
        "unused".into(),
        vec![],
        temp.path().join("run"),
    );
    #[cfg(not(feature = "linux-net"))]
    let core = HuskerCore::new(vmm, store, storage, temp.path().join("run"));
    let core = Arc::new(core.with_factory_resource_budget(Some(
        husker_state::jobs::FactoryResourceBudget {
            max_jobs: 4,
            max_vcpus: 4,
            max_memory_mib: 4096,
            memory_overhead_mib: 128,
            max_root_disk_bytes: 8 * 1024 * 1024 * 1024,
            max_boot_storage_bytes: 20 * 1024 * 1024 * 1024,
            min_free_storage_bytes: 16 * 1024 * 1024,
        },
    )));
    let app = router_with_auth(
        Arc::clone(&core),
        ApiPolicy::default(),
        Some(BearerToken::new("synthetic-token").unwrap()),
    );
    let path = format!("/v1/jobs/{}", job.id);
    for token in [None, Some(String::new()), Some("   ".into())] {
        let unprotected = router_with_auth(
            Arc::clone(&core),
            ApiPolicy::default(),
            token.and_then(|token| BearerToken::new(token).ok()),
        );
        for (method, endpoint) in [
            ("POST", "/v1/jobs".to_owned()),
            ("GET", "/v1/job-submissions".to_owned()),
            ("GET", path.clone()),
            ("GET", format!("{path}/events")),
            ("GET", format!("{path}/artifacts")),
            ("GET", format!("{path}/artifacts/0")),
            ("POST", format!("{path}/cancel")),
            ("DELETE", path.clone()),
        ] {
            let (status, _) = request(&unprotected, method, &endpoint, Value::Null, false).await;
            assert!(matches!(
                status,
                StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED
            ));
        }
    }

    let payload = json!({"submission":submission,"source_bundle":base64_encode(bundle.bytes()),"acceptance_bundle":base64_encode(bundle.bytes()),"retention_until":spec.deadline+chrono::Duration::hours(1)});
    for endpoint in [
        path.clone(),
        format!("{path}/events"),
        format!("{path}/artifacts"),
        format!("{path}/artifacts/0"),
    ] {
        assert_eq!(
            request(&app, "GET", &endpoint, Value::Null, false).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        request(&app, "POST", "/v1/jobs", payload.clone(), true)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let lookup = format!(
        "/v1/job-submissions?idempotency_key=retained&execution_specification_digest={}",
        submission.execution_specification_digest
    );
    assert_eq!(
        request(&app, "GET", &lookup, Value::Null, false).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, found) = request(&app, "GET", &lookup, Value::Null, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(found["job"]["id"], job.id.to_string());
    let missing = lookup.replace("key=retained", "key=not-accepted");
    assert_eq!(
        request(&app, "GET", &missing, Value::Null, true).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(&app, "GET", &missing, Value::Null, true).await.0,
        StatusCode::NOT_FOUND
    );
    let changed_lookup = format!(
        "/v1/job-submissions?idempotency_key=retained&execution_specification_digest=sha256:{}",
        "f".repeat(64)
    );
    assert_eq!(
        request(&app, "GET", &changed_lookup, Value::Null, true)
            .await
            .0,
        StatusCode::CONFLICT
    );
    let (status, inspected) = request(&app, "GET", &path, Value::Null, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspected["job"]["state"], "completed");
    assert_eq!(inspected["job"]["cleanup_pending"], false);
    assert_eq!(inspected["references"]["job"], path);
    assert!(!inspected.to_string().contains("synthetic-token"));
    let (_, events) = request(&app, "GET", &format!("{path}/events"), Value::Null, true).await;
    assert_eq!(events["events"][0]["data"], base64_encode(&[0, 255, 10]));
    assert_eq!(events["next_cursor"], 1);
    let (_, events) = request(
        &app,
        "GET",
        &format!("{path}/events?after=1"),
        Value::Null,
        true,
    )
    .await;
    assert_eq!(events["events"], json!([]));
    let (_, artifact) = request(
        &app,
        "GET",
        &format!("{path}/artifacts/0"),
        Value::Null,
        true,
    )
    .await;
    assert_eq!(artifact["data"], base64_encode(bytes));
    assert_eq!(artifact["descriptor"]["digest"], digest);
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("{path}/artifacts/1"),
            Value::Null,
            true
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("{path}/events?after=4097"),
            Value::Null,
            true
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let policy = ApiPolicy {
        factory_jobs_enabled: true,
        exec_allowlist: vec!["true".into()],
        ..ApiPolicy::default()
    };
    let unprotected = router_with_auth(Arc::clone(&core), policy.clone(), None);
    let app = router_with_auth(
        Arc::clone(&core),
        policy,
        Some(BearerToken::new("synthetic-token").unwrap()),
    );
    let (status, denied) = request(&unprotected, "POST", "/v1/jobs", payload.clone(), true).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(denied["kind"], "factory_auth_required");
    let (status, replay) = request(&app, "POST", "/v1/jobs", payload.clone(), true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["job"]["id"], job.id.to_string());
    let mut over_budget = payload.clone();
    over_budget["submission"]["idempotency_key"] = json!("over-budget");
    over_budget["submission"]["specification"]["resources"]["vcpu_count"] = json!(5);
    let over_spec: JobSpec =
        serde_json::from_value(over_budget["submission"]["specification"].clone()).unwrap();
    over_budget["submission"]["execution_specification_digest"] =
        json!(over_spec.digest().unwrap());
    let (status, denied) = request(&app, "POST", "/v1/jobs", over_budget, true).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(denied["kind"], "job_capacity_exhausted");
    assert_eq!(
        request(
            &app,
            "GET",
            &lookup.replace("key=retained", "key=over-budget"),
            Value::Null,
            true
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    // Lose a fresh receipt. Its missing catalog entry fails on the owned worker;
    // identical replay observes that same identity and never retries execution.
    let mut fresh_payload = payload.clone();
    fresh_payload["submission"]["idempotency_key"] = json!("lost-receipt");
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/jobs")
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer synthetic-token")
                .body(Body::from(fresh_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let receipt = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "{}",
        String::from_utf8_lossy(&receipt)
    );
    let lost_lookup = lookup.replace("key=retained", "key=lost-receipt");
    let (status, lost_identity) = request(&app, "GET", &lost_lookup, Value::Null, true).await;
    assert_eq!(status, StatusCode::OK);
    let (status, fresh_replay) =
        request(&app, "POST", "/v1/jobs", fresh_payload.clone(), true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fresh_replay["replayed"], true);
    assert_eq!(fresh_replay["job"]["id"], lost_identity["job"]["id"]);
    let fresh_id = fresh_replay["job"]["id"].as_str().unwrap();
    let fresh_path = format!("/v1/jobs/{fresh_id}");
    let failure = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let (_, state) = request(&app, "GET", &fresh_path, Value::Null, true).await;
            if state["job"]["state"] == "infrastructure_failed" {
                break state;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(failure["job"]["collection"], "failed");
    assert_eq!(failure["job"]["vm_id"], Value::Null);
    let (_, repeated) = request(&app, "POST", "/v1/jobs", fresh_payload, true).await;
    assert_eq!(repeated["job"]["id"], fresh_id);
    assert_eq!(repeated["job"]["state"], "infrastructure_failed");
    let mut oversized = payload.clone();
    oversized["source_bundle"] = json!("a".repeat(2 * 1024 * 1024));
    assert_eq!(
        request(&app, "POST", "/v1/jobs", oversized, true).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let mut changed = payload.clone();
    let mut changed_spec = spec.clone();
    changed_spec.correlation.round = 2;
    changed["submission"]["specification"] = serde_json::to_value(&changed_spec).unwrap();
    changed["submission"]["execution_specification_digest"] = json!(changed_spec.digest().unwrap());
    assert_eq!(
        request(&app, "POST", "/v1/jobs", changed, true).await.0,
        StatusCode::CONFLICT
    );
    let mut corrupt = payload.clone();
    corrupt["source_bundle"] = json!("aW52YWxpZA==");
    assert_eq!(
        request(&app, "POST", "/v1/jobs", corrupt, true).await.0,
        StatusCode::BAD_REQUEST
    );
    let mut denied = payload.clone();
    denied["submission"]["specification"]["environment"] = json!({"HOME":"/workspace"});
    let denied_spec: JobSpec =
        serde_json::from_value(denied["submission"]["specification"].clone()).unwrap();
    denied["submission"]["execution_specification_digest"] = json!(denied_spec.digest().unwrap());
    assert_eq!(
        request(&app, "POST", "/v1/jobs", denied, true).await.0,
        StatusCode::FORBIDDEN
    );
    let active_path = format!("/v1/jobs/{}", active.id);
    assert_eq!(
        request(&app, "DELETE", &active_path, Value::Null, true)
            .await
            .0,
        StatusCode::CONFLICT
    );
    let (status, cancelled) = request(
        &app,
        "POST",
        &format!("{active_path}/cancel"),
        Value::Null,
        true,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(cancelled["job"]["state"], "cancelled");
    assert_eq!(cancelled["job"]["collection"], "failed");
    assert_eq!(cancelled["job"]["cleanup_pending"], true);
    assert_eq!(
        request(&app, "DELETE", &active_path, Value::Null, true)
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(&app, "POST", &format!("{path}/cancel"), Value::Null, true)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        request(&app, "DELETE", &path, Value::Null, true).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        request(&app, "GET", &path, Value::Null, true).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(&app, "GET", &lookup, Value::Null, true).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(&app, "POST", "/v1/jobs", payload, true).await.0,
        StatusCode::CONFLICT
    );
    // Reserve the shutdown-only job when its contract is exercised.
    let waiting = StateStore::open(&temp.path().join("state.db"))
        .unwrap()
        .accept_job(
            "shutdown-unstarted",
            &spec.canonical_json().unwrap(),
            spec.deadline,
            spec.deadline + chrono::Duration::hours(1),
        )
        .unwrap()
        .0;
    let shutdown = core
        .shutdown_factory_jobs(std::time::Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(shutdown.workers_joined, 1);
    assert_eq!(shutdown.workers_pending, 0);
    let (_, interrupted) = request(
        &app,
        "GET",
        &format!("/v1/jobs/{}", waiting.id),
        Value::Null,
        true,
    )
    .await;
    assert_eq!(interrupted["job"]["state"], "interrupted");
    assert_eq!(interrupted["job"]["collection"], "failed");
    assert_eq!(interrupted["job"]["vm_id"], Value::Null);
    assert_eq!(shutdown.cleanup_pending, 1); // Previously cancelled owner is still unconfirmed.
    let mut fresh = json!({"submission":submission,"source_bundle":base64_encode(bundle.bytes()),
        "acceptance_bundle":base64_encode(bundle.bytes()),"retention_until":spec.deadline+chrono::Duration::hours(1)});
    fresh["submission"]["idempotency_key"] = json!("after-shutdown");
    assert_eq!(
        request(&app, "POST", "/v1/jobs", fresh, true).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        request(&app, "GET", &active_path, Value::Null, true)
            .await
            .0,
        StatusCode::OK
    );
}
