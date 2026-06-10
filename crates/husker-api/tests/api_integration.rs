//! API integration tests that exercise the full router with a real HuskerCore
//! backed by in-memory state.
//!
//! These tests go beyond the unit tests in `src/lib.rs` by:
//! - Sharing state across multiple requests to the same router
//! - Testing request/response content types and JSON structure
//! - Verifying error response bodies in detail
//! - Testing concurrent request handling
//! - Exercising the full middleware stack (tracing)

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use husker_api::{VmResponse, router};
use husker_core::HuskerCore;

fn make_core(
    state: husker_state::StateStore,
    storage: husker_storage::StorageConfig,
    runtime_dir: PathBuf,
) -> Arc<HuskerCore<husker_vmm::firecracker::FirecrackerBackend>> {
    let vmm = husker_vmm::firecracker::FirecrackerBackend::new(
        std::path::Path::new("/nonexistent"),
        std::path::Path::new("/tmp"),
    );

    #[cfg(feature = "linux-net")]
    {
        let ip_allocator = husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24);
        Arc::new(HuskerCore::new(
            vmm,
            state,
            ip_allocator,
            storage,
            "husker0".into(),
            vec!["8.8.8.8".into(), "1.1.1.1".into()],
            runtime_dir,
        ))
    }

    #[cfg(not(feature = "linux-net"))]
    {
        Arc::new(HuskerCore::new(vmm, state, storage, runtime_dir))
    }
}

fn test_core() -> Arc<HuskerCore<husker_vmm::firecracker::FirecrackerBackend>> {
    let state = husker_state::StateStore::open_memory().unwrap();
    let storage = husker_storage::StorageConfig {
        data_dir: PathBuf::from("/tmp/husker-test"),
    };
    make_core(state, storage, PathBuf::from("/tmp/husker-test/run"))
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn response_text(response: axum::response::Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// ── Health Endpoint ──────────────────────────────────────────────────

#[tokio::test]
async fn health_returns_json_with_version_and_vm_counts() {
    let app = router(test_core());
    let response = app
        .oneshot(Request::get("/v1/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    assert_eq!(json["status"], "ok");
    let version = json["version"]
        .as_str()
        .expect("version should be a string");
    assert!(!version.is_empty(), "version should not be empty");
    assert_eq!(json["vms"]["total"], 0);
    assert_eq!(json["vms"]["running"], 0);
}

#[tokio::test]
async fn health_counts_vms_correctly() {
    let state = husker_state::StateStore::open_memory().unwrap();
    let now = chrono::Utc::now();

    // Insert 3 VMs: 2 running, 1 stopped
    for (i, vm_state) in ["running", "running", "stopped"].iter().enumerate() {
        let record = husker_state::VmRecord {
            id: uuid::Uuid::new_v4(),
            name: format!("health-vm-{i}"),
            state: (*vm_state).into(),
            pid: Some(1000 + i as u32),
            vcpu_count: 1,
            mem_size_mib: 128,
            vsock_cid: 3 + i as u32,
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
        state.insert_vm(&record).unwrap();
    }

    let storage = husker_storage::StorageConfig {
        data_dir: PathBuf::from("/tmp/husker-test"),
    };
    let core = make_core(state, storage, PathBuf::from("/tmp/husker-test/run"));

    let app = router(core);
    let response = app
        .oneshot(Request::get("/v1/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    assert_eq!(json["status"], "ok");
    assert_eq!(json["vms"]["total"], 3);
    assert_eq!(json["vms"]["running"], 2);
}

#[tokio::test]
async fn health_includes_subsystem_checks_and_uptime() {
    let app = router(test_core());
    let response = app
        .oneshot(Request::get("/v1/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    assert_eq!(json["checks"]["state_db"], "ok");
    assert!(json["checks"]["vmm_backend"].is_string());
    assert!(json["checks"]["network_backend"].is_string());
    assert!(json["uptime_seconds"].is_u64());
}

#[tokio::test]
async fn metrics_endpoint_returns_prometheus_text() {
    let app = router(test_core());

    // Drive at least one request before scraping metrics.
    let _ = app
        .clone()
        .oneshot(Request::get("/v1/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let response = app
        .oneshot(Request::get("/v1/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("husker_api_requests_total"));
    assert!(body.contains("husker_vms_total"));
    assert!(body.contains("husker_api_uptime_seconds"));
}

// ── List Endpoint ────────────────────────────────────────────────────

#[tokio::test]
async fn list_vms_returns_empty_array() {
    let app = router(test_core());
    let response = app
        .oneshot(Request::get("/v1/vms").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    let arr = json.as_array().expect("response should be a JSON array");
    assert!(arr.is_empty());
}

// ── Host Groups / Services ───────────────────────────────────────────

#[tokio::test]
async fn host_group_and_service_endpoints_roundtrip() {
    let app = router(test_core());

    let group_body = serde_json::json!({
        "name": "default",
        "description": "default hosts",
    });
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/host-groups")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&group_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let group = response_json(response).await;
    assert_eq!(group["name"], "default");

    let response = app
        .clone()
        .oneshot(Request::get("/v1/host-groups").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let groups = response_json(response).await;
    assert_eq!(groups.as_array().unwrap().len(), 1);

    let service_body = serde_json::json!({
        "name": "api",
        "host_group": "default",
        "desired_instances": 0,
        "image": "ghcr.io/example/api:latest",
        "rootfs_path": "/tmp/r",
        "kernel_path": "/tmp/k"
    });
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/services")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&service_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let service = response_json(response).await;
    assert_eq!(service["service"]["name"], "api");
    assert_eq!(service["service"]["desired_instances"], 0);
    assert!(service["service"]["host_group_id"].is_string());
    assert_eq!(service["service"]["current_instances"], 0);
    assert_eq!(service["outcome"]["created"], serde_json::json!([]));
}

#[tokio::test]
async fn scale_service_endpoint_updates_desired_instances() {
    let app = router(test_core());

    let create = serde_json::json!({
        "name": "api",
        "desired_instances": 0,
        "rootfs_path": "/tmp/r",
        "kernel_path": "/tmp/k"
    });
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/services")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&create).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let scale = serde_json::json!({ "desired_instances": 3 });
    let response = app
        .oneshot(
            Request::post("/v1/services/api/scale")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&scale).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let service = response_json(response).await;
    assert_eq!(service["service"]["name"], "api");
    assert_eq!(service["service"]["desired_instances"], 3);
    assert_eq!(service["service"]["current_instances"], 0);
    assert_eq!(service["outcome"]["created"], serde_json::json!([]));
}

#[tokio::test]
async fn snapshot_endpoints_roundtrip() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    let runtime_dir = temp.path().join("run");
    std::fs::create_dir_all(data_dir.join("vms/snap-vm")).unwrap();
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::write(data_dir.join("vms/snap-vm/rootfs.ext4"), b"snapshot-source").unwrap();

    let state = husker_state::StateStore::open_memory().unwrap();
    let now = chrono::Utc::now();
    state
        .insert_vm(&husker_state::VmRecord {
            id: uuid::Uuid::new_v4(),
            name: "snap-vm".into(),
            state: "stopped".into(),
            pid: Some(1234),
            vcpu_count: 1,
            mem_size_mib: 128,
            vsock_cid: 7,
            tap_device: None,
            host_ip: None,
            guest_ip: None,
            kernel_path: "/tmp/vmlinux".into(),
            rootfs_path: "/tmp/rootfs.ext4".into(),
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
        })
        .unwrap();

    let core = make_core(
        state,
        husker_storage::StorageConfig {
            data_dir: data_dir.clone(),
        },
        runtime_dir,
    );
    let app = router(core);

    let create = serde_json::json!({ "name": "snap-1", "vm": "snap-vm" });
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/snapshots")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&create).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let snapshot = response_json(response).await;
    assert_eq!(snapshot["name"], "snap-1");
    assert_eq!(snapshot["source_vm_name"], "snap-vm");

    let response = app
        .clone()
        .oneshot(Request::get("/v1/snapshots").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshots = response_json(response).await;
    assert_eq!(snapshots.as_array().unwrap().len(), 1);

    let response = app
        .clone()
        .oneshot(
            Request::get("/v1/snapshots/snap-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(
            Request::delete("/v1/snapshots/snap-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn image_endpoints_roundtrip() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    let runtime_dir = temp.path().join("run");
    let source_image = temp.path().join("source.ext4");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::write(&source_image, b"image-source-data").unwrap();

    let core = make_core(
        husker_state::StateStore::open_memory().unwrap(),
        husker_storage::StorageConfig {
            data_dir: data_dir.clone(),
        },
        runtime_dir,
    );
    let app = router(core);

    let create = serde_json::json!({
        "name": "ubuntu-base",
        "source_path": source_image,
    });
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/images")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&create).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let image = response_json(response).await;
    assert_eq!(image["name"], "ubuntu-base");
    assert_eq!(image["format"], "ext4");

    let response = app
        .clone()
        .oneshot(Request::get("/v1/images").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let images = response_json(response).await;
    assert_eq!(images.as_array().unwrap().len(), 1);

    let response = app
        .clone()
        .oneshot(
            Request::get("/v1/images/ubuntu-base")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let export_path = temp.path().join("exports/ubuntu-base-copy.ext4");
    let export = serde_json::json!({
        "destination_path": export_path,
    });
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/images/ubuntu-base/export")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&export).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let exported = response_json(response).await;
    assert_eq!(exported["name"], "ubuntu-base");
    assert_eq!(
        std::fs::read(temp.path().join("exports/ubuntu-base-copy.ext4")).unwrap(),
        b"image-source-data"
    );

    let response = app
        .oneshot(
            Request::delete("/v1/images/ubuntu-base")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn secret_endpoints_roundtrip() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    let runtime_dir = temp.path().join("run");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&runtime_dir).unwrap();

    let core = make_core(
        husker_state::StateStore::open_memory().unwrap(),
        husker_storage::StorageConfig {
            data_dir: data_dir.clone(),
        },
        runtime_dir,
    );
    let app = router(core);

    let create = serde_json::json!({
        "name": "db-password",
        "value": "hunter2",
    });
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/secrets")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&create).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let secret = response_json(response).await;
    assert_eq!(secret["name"], "db-password");

    let response = app
        .clone()
        .oneshot(Request::get("/v1/secrets").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let secrets = response_json(response).await;
    assert_eq!(secrets.as_array().unwrap().len(), 1);

    let response = app
        .clone()
        .oneshot(
            Request::get("/v1/secrets/db-password/reveal")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let revealed = response_json(response).await;
    assert_eq!(revealed["value"], "hunter2");

    let rotate = serde_json::json!({ "value": "new-secret" });
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/secrets/db-password/rotate")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&rotate).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(
            Request::get("/v1/secrets/db-password/reveal")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let revealed = response_json(response).await;
    assert_eq!(revealed["value"], "new-secret");

    let response = app
        .oneshot(
            Request::delete("/v1/secrets/db-password")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn restore_missing_snapshot_returns_404() {
    let app = router(test_core());
    let body = serde_json::json!({
        "name": "restored-vm",
        "kernel_path": "/tmp/vmlinux",
        "vcpu_count": 1,
        "mem_size_mib": 128
    });
    let response = app
        .oneshot(
            Request::post("/v1/snapshots/missing/restore")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let json = response_json(response).await;
    assert_eq!(json["code"], "snapshot_not_found");
}

#[tokio::test]
async fn create_service_with_missing_host_group_returns_404() {
    let app = router(test_core());
    let body = serde_json::json!({
        "name": "api",
        "host_group": "missing-group",
        "rootfs_path": "/tmp/r",
        "kernel_path": "/tmp/k"
    });
    let response = app
        .oneshot(
            Request::post("/v1/services")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let json = response_json(response).await;
    assert_eq!(json["code"], "host_group_not_found");
}

#[tokio::test]
async fn create_service_with_zero_instances_succeeds() {
    // Scale-to-zero is allowed; desired_instances=0 creates a service with no instances.
    let app = router(test_core());
    let body = serde_json::json!({
        "name": "api",
        "desired_instances": 0,
        "rootfs_path": "/tmp/r",
        "kernel_path": "/tmp/k"
    });
    let response = app
        .oneshot(
            Request::post("/v1/services")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let json = response_json(response).await;
    assert_eq!(json["service"]["desired_instances"], 0);
    assert_eq!(json["service"]["current_instances"], 0);
    assert_eq!(json["outcome"]["created"], serde_json::json!([]));
}

// ── GET VM Not Found ─────────────────────────────────────────────────

#[tokio::test]
async fn get_nonexistent_vm_returns_404_with_error_body() {
    let app = router(test_core());
    let response = app
        .oneshot(
            Request::get("/v1/vms/no-such-vm")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let json = response_json(response).await;
    let error = json["error"].as_str().expect("should have error field");
    assert!(
        error.contains("not found"),
        "error should mention 'not found', got: {error}"
    );
    assert_eq!(json["code"], "vm_not_found");
    assert_eq!(json["message"], error);
}

// ── POST /vms with Missing Content-Type ──────────────────────────────

#[tokio::test]
async fn create_vm_without_content_type_returns_unsupported_media_type() {
    let app = router(test_core());
    let body = serde_json::json!({
        "name": "test-vm",
        "kernel_path": "/nonexistent/vmlinux",
        "rootfs_path": "/nonexistent/rootfs.ext4"
    });
    let response = app
        .oneshot(
            Request::post("/v1/vms")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // axum returns 415 when Content-Type header is missing for Json extractor
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// ── POST /vms with Invalid JSON ──────────────────────────────────────

#[tokio::test]
async fn create_vm_with_invalid_json_returns_400() {
    let app = router(test_core());
    let response = app
        .oneshot(
            Request::post("/v1/vms")
                .header("content-type", "application/json")
                .body(Body::from("not valid json"))
                .unwrap(),
        )
        .await
        .unwrap();

    // axum returns 400 for syntactically invalid JSON
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ── POST /vms with Missing Required Fields ───────────────────────────

#[tokio::test]
async fn create_vm_missing_name_returns_422() {
    let app = router(test_core());
    let body = serde_json::json!({
        "kernel_path": "/tmp/vmlinux",
        "rootfs_path": "/tmp/rootfs.ext4"
    });
    let response = app
        .oneshot(
            Request::post("/v1/vms")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// ── POST /vms with Bad Kernel Path ───────────────────────────────────

#[tokio::test]
async fn create_vm_bad_kernel_returns_500_with_error() {
    let app = router(test_core());
    let body = serde_json::json!({
        "name": "test-vm",
        "kernel_path": "/nonexistent/vmlinux",
        "rootfs_path": "/nonexistent/rootfs.ext4"
    });
    let response = app
        .oneshot(
            Request::post("/v1/vms")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let json = response_json(response).await;
    let error = json["error"].as_str().expect("should have error field");
    assert!(
        error.contains("kernel"),
        "error should mention kernel, got: {error}"
    );
}

// ── Stop/Destroy/Exec on Nonexistent VM ──────────────────────────────

#[tokio::test]
async fn stop_nonexistent_vm_returns_404() {
    let app = router(test_core());
    let response = app
        .oneshot(
            Request::post("/v1/vms/ghost/stop")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let json = response_json(response).await;
    assert!(json["error"].as_str().unwrap().contains("not found"));
}

#[tokio::test]
async fn destroy_nonexistent_vm_returns_404() {
    let app = router(test_core());
    let response = app
        .oneshot(
            Request::delete("/v1/vms/ghost")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn exec_on_nonexistent_vm_returns_404() {
    let app = router(test_core());
    let body = serde_json::json!({
        "command": "ls",
        "args": ["-la"]
    });
    let response = app
        .oneshot(
            Request::post("/v1/vms/ghost/exec")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn exec_running_vm_with_unavailable_agent_returns_503() {
    let state = husker_state::StateStore::open_memory().unwrap();
    let now = chrono::Utc::now();
    let vm_name = "agent-unavailable";
    let record = husker_state::VmRecord {
        id: uuid::Uuid::new_v4(),
        name: vm_name.into(),
        state: "running".into(),
        pid: Some(1234),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 42,
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
    state.insert_vm(&record).unwrap();

    let storage = husker_storage::StorageConfig {
        data_dir: PathBuf::from("/tmp/husker-test"),
    };
    let core = make_core(state, storage, PathBuf::from("/tmp/husker-test/run"));
    let app = router(core);

    let body = serde_json::json!({
        "command": "echo",
        "args": ["hello"]
    });
    let response = app
        .oneshot(
            Request::post(format!("/v1/vms/{vm_name}/exec"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let json = response_json(response).await;
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|msg| msg.contains("agent not ready")),
        "expected agent-not-ready error message, got: {json}"
    );
}

// ── File Read/Write on Nonexistent VM ────────────────────────────────

#[tokio::test]
async fn read_file_nonexistent_vm_returns_404() {
    let app = router(test_core());
    let body = serde_json::json!({ "path": "/etc/hostname" });
    let response = app
        .oneshot(
            Request::post("/v1/vms/ghost/files/read")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn write_file_nonexistent_vm_returns_404() {
    let app = router(test_core());
    let body = serde_json::json!({
        "path": "/tmp/test.txt",
        "data": "aGVsbG8=",
    });
    let response = app
        .oneshot(
            Request::post("/v1/vms/ghost/files/write")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ── Write File with Invalid Base64 ───────────────────────────────────

#[tokio::test]
async fn write_file_invalid_base64_returns_400() {
    // The base64 decode happens before the VM lookup in the handler
    let app = router(test_core());
    let body = serde_json::json!({
        "path": "/tmp/test.txt",
        "data": "!!!invalid-base64!!!",
    });
    let response = app
        .oneshot(
            Request::post("/v1/vms/ghost/files/write")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = response_json(response).await;
    assert!(json["error"].as_str().unwrap().contains("base64"));
}

// ── Unknown Routes ───────────────────────────────────────────────────

#[tokio::test]
async fn unknown_route_returns_404() {
    let app = router(test_core());
    let response = app
        .oneshot(Request::get("/v1/nonexistent").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn wrong_method_returns_405() {
    let app = router(test_core());
    // PUT is not registered on /v1/vms
    let response = app
        .oneshot(Request::put("/v1/vms").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

// ── VmResponse Deserialization ───────────────────────────────────────

#[tokio::test]
async fn vm_response_json_structure() {
    // Insert a VM record directly into state and verify the GET response
    // matches the expected VmResponse structure
    let state = husker_state::StateStore::open_memory().unwrap();
    let now = chrono::Utc::now();
    let record = husker_state::VmRecord {
        id: uuid::Uuid::new_v4(),
        name: "shape-test".into(),
        state: "running".into(),
        pid: Some(999),
        vcpu_count: 2,
        mem_size_mib: 256,
        vsock_cid: 5,
        tap_device: Some("husker5".into()),
        host_ip: Some("172.20.0.1".into()),
        guest_ip: Some("172.20.0.2".into()),
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
    state.insert_vm(&record).unwrap();

    // Build a core with this pre-populated state
    let storage = husker_storage::StorageConfig {
        data_dir: PathBuf::from("/tmp/husker-test"),
    };
    let populated_core = make_core(state, storage, PathBuf::from("/tmp/husker-test/run"));

    let app = router(populated_core.clone());
    let response = app
        .oneshot(
            Request::get("/v1/vms/shape-test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;

    // Verify all expected fields are present and correctly typed.
    // The record was inserted as "running" with no backend process behind it,
    // so the liveness-refreshed read correctly reports it stopped (pid cleared).
    assert_eq!(json["name"].as_str().unwrap(), "shape-test");
    assert_eq!(json["state"].as_str().unwrap(), "stopped");
    assert!(json["pid"].is_null());
    assert_eq!(json["vcpu_count"].as_u64().unwrap(), 2);
    assert_eq!(json["mem_size_mib"].as_u64().unwrap(), 256);
    assert_eq!(json["vsock_cid"].as_u64().unwrap(), 5);
    assert_eq!(json["host_ip"].as_str().unwrap(), "172.20.0.1");
    assert_eq!(json["guest_ip"].as_str().unwrap(), "172.20.0.2");
    assert!(json["id"].as_str().is_some());
    assert!(json["created_at"].as_str().is_some());
    assert!(json["updated_at"].as_str().is_some());

    // Verify the id matches what we inserted
    assert_eq!(json["id"].as_str().unwrap(), record.id.to_string());

    // boot_mode is surfaced in the response
    assert_eq!(json["boot_mode"].as_str().unwrap(), "direct");

    // Verify JSON can be deserialized to VmResponse
    let vm: VmResponse = serde_json::from_value(json).unwrap();
    assert_eq!(vm.name, "shape-test");
    assert_eq!(vm.vcpu_count, 2);
    assert_eq!(vm.boot_mode, "direct");
}

// ── List with Pre-populated State ────────────────────────────────────

#[tokio::test]
async fn list_vms_returns_all_records() {
    let state = husker_state::StateStore::open_memory().unwrap();
    let now = chrono::Utc::now();

    for i in 0..3 {
        let record = husker_state::VmRecord {
            id: uuid::Uuid::new_v4(),
            name: format!("vm-{i}"),
            state: "running".into(),
            pid: Some(1000 + i),
            vcpu_count: 1,
            mem_size_mib: 128,
            vsock_cid: 3 + i,
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
        state.insert_vm(&record).unwrap();
    }

    let storage = husker_storage::StorageConfig {
        data_dir: PathBuf::from("/tmp/husker-test"),
    };
    let core = make_core(state, storage, PathBuf::from("/tmp/husker-test/run"));

    let app = router(core);
    let response = app
        .oneshot(Request::get("/v1/vms").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 3);

    // Verify they are ordered and have names
    let names: Vec<&str> = arr.iter().map(|v| v["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"vm-0"));
    assert!(names.contains(&"vm-1"));
    assert!(names.contains(&"vm-2"));
}

// ── Exec with Missing Required Fields ────────────────────────────────

#[tokio::test]
async fn exec_without_command_field_returns_422() {
    let app = router(test_core());
    let body = serde_json::json!({
        "args": ["hello"]
    });
    let response = app
        .oneshot(
            Request::post("/v1/vms/some-vm/exec")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Missing required field "command" should return 422 (JSON parse error)
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// ── Exec with Empty Body ─────────────────────────────────────────────

#[tokio::test]
async fn exec_with_empty_body_returns_400() {
    let app = router(test_core());
    let response = app
        .oneshot(
            Request::post("/v1/vms/some-vm/exec")
                .header("content-type", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // axum returns 400 for empty body (syntactically invalid JSON)
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ── Read File with Missing Path Field ────────────────────────────────

#[tokio::test]
async fn read_file_missing_path_returns_422() {
    let app = router(test_core());
    let body = serde_json::json!({});
    let response = app
        .oneshot(
            Request::post("/v1/vms/some-vm/files/read")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// ── Write File with Missing Fields ───────────────────────────────────

#[tokio::test]
async fn write_file_missing_data_returns_422() {
    let app = router(test_core());
    let body = serde_json::json!({
        "path": "/tmp/test.txt"
    });
    let response = app
        .oneshot(
            Request::post("/v1/vms/some-vm/files/write")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// ── Port Forward Endpoints ───────────────────────────────────────────
//
// Port forward routes are only registered with the linux-net feature.

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn add_port_forward_nonexistent_vm_returns_404() {
    let app = router(test_core());
    let body = serde_json::json!({
        "host_port": 8080,
        "guest_port": 80,
    });
    let response = app
        .oneshot(
            Request::post("/v1/vms/ghost/ports")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let json = response_json(response).await;
    assert!(json["error"].as_str().unwrap().contains("not found"));
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn list_port_forwards_nonexistent_vm_returns_404() {
    let app = router(test_core());
    let response = app
        .oneshot(
            Request::get("/v1/vms/ghost/ports")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let json = response_json(response).await;
    assert!(json["error"].as_str().unwrap().contains("not found"));
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn remove_port_forward_nonexistent_vm_returns_404() {
    let app = router(test_core());
    let response = app
        .oneshot(
            Request::delete("/v1/vms/ghost/ports/8080")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let json = response_json(response).await;
    assert!(json["error"].as_str().unwrap().contains("not found"));
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn add_port_forward_missing_fields_returns_422() {
    let app = router(test_core());
    let body = serde_json::json!({
        "host_port": 8080,
    });
    let response = app
        .oneshot(
            Request::post("/v1/vms/some-vm/ports")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn add_port_forward_invalid_json_returns_400() {
    let app = router(test_core());
    let response = app
        .oneshot(
            Request::post("/v1/vms/some-vm/ports")
                .header("content-type", "application/json")
                .body(Body::from("not json"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[cfg(feature = "linux-net")]
#[tokio::test]
async fn list_port_forwards_empty_for_existing_vm() {
    let state = husker_state::StateStore::open_memory().unwrap();
    let now = chrono::Utc::now();
    let record = husker_state::VmRecord {
        id: uuid::Uuid::new_v4(),
        name: "pf-test".into(),
        state: "running".into(),
        pid: Some(1000),
        vcpu_count: 1,
        mem_size_mib: 128,
        vsock_cid: 3,
        tap_device: Some("husker0".into()),
        host_ip: Some("172.20.0.1".into()),
        guest_ip: Some("172.20.0.2".into()),
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
    state.insert_vm(&record).unwrap();

    let storage = husker_storage::StorageConfig {
        data_dir: PathBuf::from("/tmp/husker-test"),
    };
    let core = make_core(state, storage, PathBuf::from("/tmp/husker-test/run"));

    let app = router(core);
    let response = app
        .oneshot(
            Request::get("/v1/vms/pf-test/ports")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    let arr = json.as_array().expect("response should be a JSON array");
    assert!(arr.is_empty());
}

// ── VmResponse Null Fields ───────────────────────────────────────────

#[tokio::test]
async fn vm_response_with_null_optional_fields() {
    let state = husker_state::StateStore::open_memory().unwrap();
    let now = chrono::Utc::now();
    let record = husker_state::VmRecord {
        id: uuid::Uuid::new_v4(),
        name: "null-fields".into(),
        state: "creating".into(),
        pid: None,
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
    state.insert_vm(&record).unwrap();

    let storage = husker_storage::StorageConfig {
        data_dir: PathBuf::from("/tmp/husker-test"),
    };
    let core = make_core(state, storage, PathBuf::from("/tmp/husker-test/run"));

    let app = router(core);
    let response = app
        .oneshot(
            Request::get("/v1/vms/null-fields")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;

    // Optional fields should be null
    assert!(json["pid"].is_null());
    assert!(json["host_ip"].is_null());
    assert!(json["guest_ip"].is_null());
}

// ── Logs Endpoint ───────────────────────────────────────────────────

#[tokio::test]
async fn logs_nonexistent_vm_returns_404() {
    let app = router(test_core());
    let response = app
        .oneshot(
            Request::get("/v1/vms/ghost/logs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn logs_returns_serial_output() {
    let runtime_dir = tempfile::tempdir().unwrap();
    let state = husker_state::StateStore::open_memory().unwrap();
    let now = chrono::Utc::now();
    let vm_id = uuid::Uuid::new_v4();
    let record = husker_state::VmRecord {
        id: vm_id,
        name: "log-test".into(),
        state: "running".into(),
        pid: Some(1000),
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
    state.insert_vm(&record).unwrap();

    // Pre-create serial log file with known content
    let serial_log = runtime_dir.path().join(format!("{vm_id}.serial.log"));
    std::fs::write(&serial_log, "Linux version 6.1.102\nBoot complete\n").unwrap();

    let storage = husker_storage::StorageConfig {
        data_dir: PathBuf::from("/tmp/husker-test"),
    };
    let core = make_core(state, storage, runtime_dir.path().to_path_buf());

    let app = router(core);
    let response = app
        .oneshot(
            Request::get("/v1/vms/log-test/logs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("Linux version 6.1.102"));
    assert!(body.contains("Boot complete"));
}

#[tokio::test]
async fn logs_tail_returns_last_n_lines() {
    let runtime_dir = tempfile::tempdir().unwrap();
    let state = husker_state::StateStore::open_memory().unwrap();
    let now = chrono::Utc::now();
    let vm_id = uuid::Uuid::new_v4();
    let record = husker_state::VmRecord {
        id: vm_id,
        name: "tail-test".into(),
        state: "running".into(),
        pid: Some(1000),
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
    state.insert_vm(&record).unwrap();

    let serial_log = runtime_dir.path().join(format!("{vm_id}.serial.log"));
    std::fs::write(&serial_log, "line1\nline2\nline3\nline4\nline5\n").unwrap();

    let storage = husker_storage::StorageConfig {
        data_dir: PathBuf::from("/tmp/husker-test"),
    };
    let core = make_core(state, storage, runtime_dir.path().to_path_buf());

    let app = router(core);
    let response = app
        .oneshot(
            Request::get("/v1/vms/tail-test/logs?tail=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(!body.contains("line3"));
    assert!(body.contains("line4"));
    assert!(body.contains("line5"));
}

#[tokio::test]
async fn logs_no_serial_file_returns_404() {
    let runtime_dir = tempfile::tempdir().unwrap();
    let state = husker_state::StateStore::open_memory().unwrap();
    let now = chrono::Utc::now();
    let vm_id = uuid::Uuid::new_v4();
    let record = husker_state::VmRecord {
        id: vm_id,
        name: "no-log-test".into(),
        state: "running".into(),
        pid: Some(1000),
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
    state.insert_vm(&record).unwrap();

    // Do NOT create the serial log file
    let storage = husker_storage::StorageConfig {
        data_dir: PathBuf::from("/tmp/husker-test"),
    };
    let core = make_core(state, storage, runtime_dir.path().to_path_buf());

    let app = router(core);
    let response = app
        .oneshot(
            Request::get("/v1/vms/no-log-test/logs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let json = response_json(response).await;
    assert!(json["error"].as_str().unwrap().contains("no serial log"));
}

/// Helper: create a core with a pre-populated VM and optional serial log content.
fn logs_test_core(
    vm_name: &str,
    serial_content: Option<&str>,
) -> (
    Arc<HuskerCore<husker_vmm::firecracker::FirecrackerBackend>>,
    tempfile::TempDir,
) {
    let runtime_dir = tempfile::tempdir().unwrap();
    let state = husker_state::StateStore::open_memory().unwrap();
    let now = chrono::Utc::now();
    let vm_id = uuid::Uuid::new_v4();
    let record = husker_state::VmRecord {
        id: vm_id,
        name: vm_name.into(),
        state: "running".into(),
        pid: Some(1000),
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
    state.insert_vm(&record).unwrap();

    if let Some(content) = serial_content {
        let serial_log = runtime_dir.path().join(format!("{vm_id}.serial.log"));
        std::fs::write(&serial_log, content).unwrap();
    }

    let storage = husker_storage::StorageConfig {
        data_dir: PathBuf::from("/tmp/husker-test"),
    };
    let core = make_core(state, storage, runtime_dir.path().to_path_buf());
    (core, runtime_dir)
}

#[tokio::test]
async fn logs_empty_serial_file_returns_empty_body() {
    let (core, _dir) = logs_test_core("empty-log", Some(""));
    let app = router(core);
    let response = app
        .oneshot(
            Request::get("/v1/vms/empty-log/logs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert_eq!(body, "");
}

#[tokio::test]
async fn logs_tail_zero_returns_empty() {
    let (core, _dir) = logs_test_core("tail-zero", Some("line1\nline2\nline3\n"));
    let app = router(core);
    let response = app
        .oneshot(
            Request::get("/v1/vms/tail-zero/logs?tail=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert_eq!(body, "");
}

#[tokio::test]
async fn logs_tail_exceeding_line_count_returns_all() {
    let content = "alpha\nbeta\n";
    let (core, _dir) = logs_test_core("tail-big", Some(content));
    let app = router(core);
    let response = app
        .oneshot(
            Request::get("/v1/vms/tail-big/logs?tail=999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert_eq!(body, content);
}

#[tokio::test]
async fn logs_tail_on_empty_file_returns_empty() {
    let (core, _dir) = logs_test_core("tail-empty", Some(""));
    let app = router(core);
    let response = app
        .oneshot(
            Request::get("/v1/vms/tail-empty/logs?tail=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert_eq!(body, "");
}

#[tokio::test]
async fn logs_preserves_blank_lines() {
    let content = "boot start\n\n\nkernel loaded\n\nready\n";
    let (core, _dir) = logs_test_core("blank-lines", Some(content));
    let app = router(core);
    let response = app
        .oneshot(
            Request::get("/v1/vms/blank-lines/logs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert_eq!(body, content);
}

#[tokio::test]
async fn logs_content_type_is_text_plain() {
    let (core, _dir) = logs_test_core("ct-test", Some("hello\n"));
    let app = router(core);
    let response = app
        .oneshot(
            Request::get("/v1/vms/ct-test/logs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let ct = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("text/plain"), "expected text/plain, got: {ct}");
}

#[tokio::test]
async fn logs_with_binary_like_content_returns_ok() {
    // Serial output can contain ANSI escape codes, partial UTF-8, etc.
    // The file is read as UTF-8 string, so non-UTF-8 would fail.
    // Test that ANSI-heavy output works fine.
    let content =
        "[\x1b[32m  OK  \x1b[0m] Started systemd\n[\x1b[32m  OK  \x1b[0m] Reached target\n";
    let (core, _dir) = logs_test_core("ansi-test", Some(content));
    let app = router(core);
    let response = app
        .oneshot(
            Request::get("/v1/vms/ansi-test/logs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("Started systemd"));
    assert!(body.contains("Reached target"));
}

#[tokio::test]
async fn logs_no_trailing_newline_preserved() {
    let content = "line1\nline2\nno-newline-at-end";
    let (core, _dir) = logs_test_core("no-nl", Some(content));
    let app = router(core);
    let response = app
        .oneshot(
            Request::get("/v1/vms/no-nl/logs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert_eq!(body, content);
}

#[tokio::test]
async fn logs_tail_with_no_trailing_newline() {
    let content = "a\nb\nc";
    let (core, _dir) = logs_test_core("tail-no-nl", Some(content));
    let app = router(core);
    let response = app
        .oneshot(
            Request::get("/v1/vms/tail-no-nl/logs?tail=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert_eq!(body, "b\nc");
}

#[tokio::test]
async fn logs_tail_one_from_multiline() {
    let content = "first\nsecond\nthird\n";
    let (core, _dir) = logs_test_core("tail-one", Some(content));
    let app = router(core);
    let response = app
        .oneshot(
            Request::get("/v1/vms/tail-one/logs?tail=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert_eq!(body, "third\n");
}

#[tokio::test]
async fn logs_large_file_is_truncated() {
    let runtime_dir = tempfile::tempdir().unwrap();
    let state = husker_state::StateStore::open_memory().unwrap();
    let now = chrono::Utc::now();
    let vm_id = uuid::Uuid::new_v4();
    let record = husker_state::VmRecord {
        id: vm_id,
        name: "big-log".into(),
        state: "running".into(),
        pid: Some(1000),
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
    state.insert_vm(&record).unwrap();

    // Create a serial log larger than 1 MiB
    let serial_log = runtime_dir.path().join(format!("{vm_id}.serial.log"));
    let line = "kernel: [    0.000000] Booting Linux on physical CPU\n";
    let repeat_count = (1024 * 1024 * 2) / line.len() + 1; // ~2 MiB
    let large_content: String = line.repeat(repeat_count);
    std::fs::write(&serial_log, &large_content).unwrap();

    let storage = husker_storage::StorageConfig {
        data_dir: PathBuf::from("/tmp/husker-test"),
    };
    let core = make_core(state, storage, runtime_dir.path().to_path_buf());

    let app = router(core);
    let response = app
        .oneshot(
            Request::get("/v1/vms/big-log/logs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(
        body.starts_with("[... truncated, showing last 1 MiB ...]"),
        "should have truncation notice"
    );
    // Body should be roughly 1 MiB + notice, not the full 2 MiB
    assert!(
        body.len() < 1024 * 1024 + 1024 * 100,
        "body should be ~1 MiB, got {} bytes",
        body.len()
    );
}
