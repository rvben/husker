//! Lightweight API latency baseline and regression gate.
//!
//! This is intentionally small and deterministic enough for CI. It exercises
//! hot read paths and enforces conservative p95/p99 ceilings to catch major
//! regressions without flaking under normal runner variance.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

use husker_api::router;
use husker_core::HuskerCore;

fn test_core() -> Arc<HuskerCore<husker_vmm::firecracker::FirecrackerBackend>> {
    let state = husker_state::StateStore::open_memory().unwrap();
    let storage = husker_storage::StorageConfig {
        data_dir: PathBuf::from("/tmp/husker-perf-test"),
        state_dir: PathBuf::from("/tmp/husker-perf-test"),
    };
    let vmm = husker_vmm::firecracker::FirecrackerBackend::new(
        std::path::Path::new("/nonexistent"),
        std::path::Path::new("/tmp"),
        std::sync::Arc::new(husker_vmm::cgroup::CgroupSupervisor::disabled()),
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
            PathBuf::from("/tmp/husker-perf-test/run"),
        ))
    }
    #[cfg(not(feature = "linux-net"))]
    {
        Arc::new(HuskerCore::new(
            vmm,
            state,
            storage,
            PathBuf::from("/tmp/husker-perf-test/run"),
        ))
    }
}

fn percentile(mut values: Vec<u128>, p: f64) -> u128 {
    values.sort_unstable();
    let len = values.len();
    let idx = ((len.saturating_sub(1)) as f64 * p).round() as usize;
    values[idx]
}

#[tokio::test]
async fn health_and_list_latency_baseline() {
    let app = router(test_core());
    let mut health = Vec::with_capacity(250);
    let mut list = Vec::with_capacity(250);

    for _ in 0..250 {
        let t0 = Instant::now();
        let resp = app
            .clone()
            .oneshot(Request::get("/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        health.push(t0.elapsed().as_micros());

        let t1 = Instant::now();
        let resp = app
            .clone()
            .oneshot(Request::get("/v1/vms").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        list.push(t1.elapsed().as_micros());
    }

    let health_p95 = percentile(health.clone(), 0.95);
    let health_p99 = percentile(health.clone(), 0.99);
    let list_p95 = percentile(list.clone(), 0.95);
    let list_p99 = percentile(list.clone(), 0.99);

    println!(
        "perf baseline (microseconds): health p95={health_p95} p99={health_p99}, \
         list p95={list_p95} p99={list_p99}"
    );

    // Conservative CI ceilings (microseconds). Tight enough to catch
    // pathological regressions while remaining stable across hosted runners.
    const HEALTH_P95_MAX_US: u128 = 75_000;
    const HEALTH_P99_MAX_US: u128 = 125_000;
    const LIST_P95_MAX_US: u128 = 75_000;
    const LIST_P99_MAX_US: u128 = 125_000;

    assert!(
        health_p95 <= HEALTH_P95_MAX_US,
        "health p95 too high: {health_p95}us > {HEALTH_P95_MAX_US}us"
    );
    assert!(
        health_p99 <= HEALTH_P99_MAX_US,
        "health p99 too high: {health_p99}us > {HEALTH_P99_MAX_US}us"
    );
    assert!(
        list_p95 <= LIST_P95_MAX_US,
        "list p95 too high: {list_p95}us > {LIST_P95_MAX_US}us"
    );
    assert!(
        list_p99 <= LIST_P99_MAX_US,
        "list p99 too high: {list_p99}us > {LIST_P99_MAX_US}us"
    );
}
