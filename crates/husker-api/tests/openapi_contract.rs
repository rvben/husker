//! OpenAPI contract tests.
//!
//! These tests validate that our generated OpenAPI document stays stable
//! for clients: required paths remain present and canonical error schema
//! fields are not accidentally removed.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use husker_api::router;
use husker_core::HuskerCore;

fn test_core() -> Arc<HuskerCore<husker_vmm::firecracker::FirecrackerBackend>> {
    let state = husker_state::StateStore::open_memory().unwrap();
    let storage = husker_storage::StorageConfig {
        data_dir: PathBuf::from("/tmp/husker-openapi-test"),
        state_dir: PathBuf::from("/tmp/husker-openapi-test"),
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
            PathBuf::from("/tmp/husker-openapi-test/run"),
        ))
    }

    #[cfg(not(feature = "linux-net"))]
    {
        Arc::new(HuskerCore::new(
            vmm,
            state,
            storage,
            PathBuf::from("/tmp/husker-openapi-test/run"),
        ))
    }
}

async fn fetch_openapi() -> serde_json::Value {
    let app = router(test_core());
    let response = app
        .oneshot(
            Request::get("/api-docs/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn openapi_contains_critical_paths() {
    let doc = fetch_openapi().await;
    let paths = doc["paths"].as_object().expect("paths must be an object");

    for required in [
        "/v1/health",
        "/v1/metrics",
        "/v1/host-groups",
        "/v1/host-groups/{name}",
        "/v1/services",
        "/v1/services/{name}",
        "/v1/services/{name}/scale",
        "/v1/pools",
        "/v1/pools/{name}",
        "/v1/pools/{name}/checkout",
        "/v1/images",
        "/v1/images/{name}",
        "/v1/images/{name}/export",
        "/v1/volumes",
        "/v1/volumes/{name}",
        "/v1/secrets",
        "/v1/secrets/{name}",
        "/v1/secrets/{name}/reveal",
        "/v1/secrets/{name}/rotate",
        "/v1/snapshots",
        "/v1/snapshots/{name}",
        "/v1/snapshots/{name}/restore",
        "/v1/vms",
        "/v1/vms/{name}",
        "/v1/vms/{name}/balloon",
        "/v1/vms/{name}/exec",
        "/v1/vms/{name}/files/read",
        "/v1/vms/{name}/files/write",
        "/v1/vms/{name}/logs",
        "/v1/vms/{name}/ready",
        "/v1/vms/{name}/shell",
        "/v1/diagnostics",
    ] {
        assert!(
            paths.contains_key(required),
            "missing OpenAPI path: {required}"
        );
    }

    // Port-forward routes are cross-platform (nftables on Linux, a userspace
    // proxy on macOS), so they must always be in the contract.
    for required in ["/v1/vms/{name}/ports", "/v1/vms/{name}/ports/{host_port}"] {
        assert!(
            paths.contains_key(required),
            "missing OpenAPI path: {required}"
        );
    }
}

#[tokio::test]
async fn openapi_error_response_schema_is_stable() {
    let doc = fetch_openapi().await;
    let schemas = doc["components"]["schemas"]
        .as_object()
        .expect("components.schemas must be an object");
    let err = schemas
        .get("ErrorResponse")
        .expect("ErrorResponse schema must exist");

    let properties = err["properties"]
        .as_object()
        .expect("ErrorResponse.properties must be an object");
    for key in ["code", "message", "hint", "details", "error"] {
        assert!(
            properties.contains_key(key),
            "ErrorResponse missing property: {key}"
        );
    }
}

#[tokio::test]
async fn openapi_ports_tag_is_cross_platform() {
    let doc = fetch_openapi().await;
    let tags = doc["tags"].as_array().expect("tags should be an array");
    let ports_tag = tags
        .iter()
        .find(|tag| tag["name"] == "ports")
        .expect("ports tag must exist");
    let description = ports_tag["description"].as_str().unwrap_or("");
    assert_eq!(
        description, "Port forwarding",
        "ports tag should no longer carry a Linux-only caveat"
    );
}
