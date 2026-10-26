//! API latency baseline and regression gate.
//!
//! The gate runs against the production store shape: a file-backed SQLite
//! state opened through `StateStore::open` (WAL journal, pooled connections)
//! and seeded with a fleet of stopped VMs, so every measured request pays the
//! real query plans, row decoding and response serialization instead of
//! touching an empty in-memory table. It measures the hot read paths (health,
//! the full fleet listing, one paginated page) and the cheapest durable write
//! path (secret creation: one encrypted row, no VMM involvement) and enforces
//! conservative p95/p99 ceilings that catch order-of-magnitude regressions
//! without flaking under hosted-runner variance.
//!
//! Regressions that do not show up as request latency are guarded by their
//! mechanism tests instead of this gate: lock hold times in the stop path by
//! `stop_wait_releases_the_instance_map_during_the_grace_period`, shutdown
//! drain concurrency by `drain_vms_stops_live_vms_concurrently`, and the
//! store's durability settings by
//! `file_store_connections_use_wal_with_normal_synchronous`.

use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use chrono::Utc;
use tempfile::TempDir;
use tower::ServiceExt;
use uuid::Uuid;

use husker_api::router;
use husker_core::HuskerCore;
use husker_state::{BackendKind, BootKind, NetworkMode, StateStore, VmLifecycleState, VmRecord};

/// Fleet size the store is seeded with. Large enough that a listing pays for
/// row decoding and serialization, small enough to seed in well under a
/// second.
const FLEET_SIZE: u32 = 300;
/// Samples per measured request kind.
const SAMPLES: usize = 250;
const PAGE_LIMIT: usize = 25;
const PAGE_OFFSET: usize = 150;

/// A stopped VM record. Stopped rows are listed without a backend liveness
/// probe, so the listing cost is the store and serialization path alone,
/// which is what this gate bounds.
fn stopped_vm(ordinal: u32) -> VmRecord {
    let now = Utc::now();
    VmRecord {
        id: Uuid::new_v4(),
        name: format!("perf-vm-{ordinal:04}"),
        state: VmLifecycleState::Stopped,
        pid: None,
        vcpu_count: 2,
        mem_size_mib: 512,
        vsock_cid: 3 + ordinal,
        tap_device: None,
        host_ip: None,
        guest_ip: None,
        kernel_path: "/var/lib/husker/kernels/vmlinux".into(),
        rootfs_path: format!("/var/lib/husker/vms/perf-vm-{ordinal:04}/rootfs.ext4"),
        created_at: now,
        updated_at: now,
        userdata: None,
        userdata_status: None,
        userdata_env: None,
        service_id: None,
        service_ordinal: None,
        vmm: BackendKind::Firecracker,
        boot_mode: BootKind::DirectKernel,
        balloon: false,
        volume: None,
        network: NetworkMode::Nat,
        last_activity_at: now,
        suspended_at: None,
        idle_timeout_secs: None,
        suspend_ttl_secs: None,
        auto_resume: true,
        forked_from: None,
        egress_policy: None,
    }
}

/// A core over a file-backed store seeded with `FLEET_SIZE` stopped VMs. The
/// returned directory owns the store file and the secret key; it must outlive
/// the core.
fn seeded_core(dir: &TempDir) -> Arc<HuskerCore<husker_vmm::firecracker::FirecrackerBackend>> {
    let state = StateStore::open(&dir.path().join("husker.db")).unwrap();
    for ordinal in 0..FLEET_SIZE {
        state.insert_vm(&stopped_vm(ordinal)).unwrap();
    }
    let storage = husker_storage::StorageConfig {
        data_dir: dir.path().to_path_buf(),
        state_dir: dir.path().to_path_buf(),
    };
    let vmm = husker_vmm::firecracker::FirecrackerBackend::new(
        std::path::Path::new("/nonexistent"),
        dir.path(),
        Arc::new(husker_vmm::cgroup::CgroupSupervisor::disabled()),
    );
    let runtime_dir = dir.path().join("run");

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

fn percentile(mut values: Vec<u128>, p: f64) -> u128 {
    values.sort_unstable();
    let len = values.len();
    let idx = ((len.saturating_sub(1)) as f64 * p).round() as usize;
    values[idx]
}

/// Sends `request` through the router and returns the response plus the
/// elapsed wall time in microseconds, after asserting the expected status.
async fn timed(
    app: &axum::Router,
    request: Request<Body>,
    expected: StatusCode,
) -> (axum::response::Response, u128) {
    let started = Instant::now();
    let response = app.clone().oneshot(request).await.unwrap();
    let elapsed = started.elapsed().as_micros();
    assert_eq!(response.status(), expected, "{}", response.status());
    (response, elapsed)
}

fn assert_ceilings(name: &str, samples: Vec<u128>, p95_max: u128, p99_max: u128) {
    let p95 = percentile(samples.clone(), 0.95);
    let p99 = percentile(samples, 0.99);
    println!("perf baseline (microseconds): {name} p95={p95} p99={p99}");
    assert!(p95 <= p95_max, "{name} p95 too high: {p95}us > {p95_max}us");
    assert!(p99 <= p99_max, "{name} p99 too high: {p99}us > {p99_max}us");
}

#[tokio::test]
async fn request_latency_baseline_on_a_seeded_file_store() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(seeded_core(&dir));

    // The gate only means something against the seeded fleet, so prove the
    // listing sees it before timing anything.
    let (full, _) = timed(
        &app,
        Request::get("/v1/vms").body(Body::empty()).unwrap(),
        StatusCode::OK,
    )
    .await;
    let total = full
        .headers()
        .get("x-total-count")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u32>().ok());
    assert_eq!(
        total,
        Some(FLEET_SIZE),
        "listing must report the seeded fleet"
    );

    let page_uri = format!("/v1/vms?limit={PAGE_LIMIT}&offset={PAGE_OFFSET}");
    let (page, _) = timed(
        &app,
        Request::get(&page_uri).body(Body::empty()).unwrap(),
        StatusCode::OK,
    )
    .await;
    let page_body = axum::body::to_bytes(page.into_body(), usize::MAX)
        .await
        .unwrap();
    let page_rows: Vec<serde_json::Value> = serde_json::from_slice(&page_body).unwrap();
    assert_eq!(
        page_rows.len(),
        PAGE_LIMIT,
        "page must hold a full limit of rows"
    );

    let mut health = Vec::with_capacity(SAMPLES);
    let mut list_all = Vec::with_capacity(SAMPLES);
    let mut list_page = Vec::with_capacity(SAMPLES);
    let mut create_secret = Vec::with_capacity(SAMPLES);

    for sample in 0..SAMPLES {
        health.push(
            timed(
                &app,
                Request::get("/v1/health").body(Body::empty()).unwrap(),
                StatusCode::OK,
            )
            .await
            .1,
        );
        list_all.push(
            timed(
                &app,
                Request::get("/v1/vms").body(Body::empty()).unwrap(),
                StatusCode::OK,
            )
            .await
            .1,
        );
        list_page.push(
            timed(
                &app,
                Request::get(&page_uri).body(Body::empty()).unwrap(),
                StatusCode::OK,
            )
            .await
            .1,
        );
        let body = serde_json::json!({
            "name": format!("perf-secret-{sample:04}"),
            "value": "0123456789abcdef0123456789abcdef",
        });
        create_secret.push(
            timed(
                &app,
                Request::post("/v1/secrets")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
                StatusCode::CREATED,
            )
            .await
            .1,
        );
    }

    // Conservative CI ceilings (microseconds). Tight enough to catch
    // pathological regressions while remaining stable across hosted runners.
    const READ_P95_MAX_US: u128 = 75_000;
    const READ_P99_MAX_US: u128 = 125_000;
    const WRITE_P95_MAX_US: u128 = 50_000;
    const WRITE_P99_MAX_US: u128 = 100_000;

    assert_ceilings("health", health, READ_P95_MAX_US, READ_P99_MAX_US);
    assert_ceilings("list all", list_all, READ_P95_MAX_US, READ_P99_MAX_US);
    assert_ceilings("list page", list_page, READ_P95_MAX_US, READ_P99_MAX_US);
    assert_ceilings(
        "create secret",
        create_secret,
        WRITE_P95_MAX_US,
        WRITE_P99_MAX_US,
    );
}
