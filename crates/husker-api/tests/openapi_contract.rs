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
        "/v1/vms/{name}/exec/stream",
        "/v1/vms/{name}/sessions",
        "/v1/vms/{name}/sessions/{id}",
        "/v1/vms/{name}/sessions/{id}/events",
        "/v1/vms/{name}/sessions/{id}/cancel",
        "/v1/vms/{name}/tunnel/{port}",
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
async fn openapi_lists_every_logs_query_parameter() {
    let doc = fetch_openapi().await;
    let parameters = doc["paths"]["/v1/vms/{name}/logs"]["get"]["parameters"]
        .as_array()
        .expect("logs GET must declare parameters");
    let mut listed: Vec<(&str, &str, bool)> = parameters
        .iter()
        .map(|parameter| {
            (
                parameter["name"].as_str().unwrap(),
                parameter["in"].as_str().unwrap(),
                parameter["required"].as_bool().unwrap_or(false),
            )
        })
        .collect();
    listed.sort_unstable();
    assert_eq!(
        listed,
        vec![
            ("follow", "query", false),
            ("name", "path", true),
            ("source", "query", false),
            ("tail", "query", false),
            ("userdata", "query", false),
        ]
    );
}

/// The exec, session and preview routes answer policy refusals, timeouts and
/// refusals from the guest agent with their own statuses; a consumer
/// branching on them must find each one in the contract, not just the
/// success case.
#[tokio::test]
async fn openapi_documents_every_exec_and_session_error_status() {
    let doc = fetch_openapi().await;
    let expectations: [(&str, &str, &[&str]); 8] = [
        (
            "/v1/vms/{name}/exec",
            "post",
            &["200", "403", "404", "408", "409", "503"],
        ),
        (
            "/v1/vms/{name}/sessions",
            "post",
            &["201", "403", "404", "409", "429", "501", "502", "503"],
        ),
        (
            "/v1/vms/{name}/sessions",
            "get",
            &["200", "404", "409", "501", "502", "503"],
        ),
        (
            "/v1/vms/{name}/sessions/{id}",
            "get",
            &["200", "400", "404", "501", "502", "503"],
        ),
        (
            "/v1/vms/{name}/sessions/{id}",
            "delete",
            &["204", "400", "404", "409", "501", "502", "503"],
        ),
        (
            "/v1/vms/{name}/sessions/{id}/events",
            "get",
            &["200", "400", "404", "501", "502", "503"],
        ),
        (
            "/v1/vms/{name}/sessions/{id}/cancel",
            "post",
            &["200", "400", "404", "501", "502", "503"],
        ),
        (
            "/v1/vms/{name}/tunnel/{port}",
            "get",
            &["101", "400", "404", "429", "501", "502", "503"],
        ),
    ];
    for (path, method, statuses) in expectations {
        let responses = doc["paths"][path][method]["responses"]
            .as_object()
            .unwrap_or_else(|| panic!("{method} {path} must declare responses"));
        let mut listed: Vec<&str> = responses.keys().map(String::as_str).collect();
        listed.sort_unstable();
        assert_eq!(listed, statuses, "{method} {path}");
        for status in statuses
            .iter()
            .filter(|status| status.starts_with(['4', '5']))
        {
            assert!(
                refers_to(&responses[*status], "ErrorResponse"),
                "{method} {path} {status} must carry the error envelope"
            );
        }
    }
    // The timeout of a session or preview request is the general agent
    // deadline, not a gateway timeout of its own.
    for (path, method) in [
        ("/v1/vms/{name}/sessions", "post"),
        ("/v1/vms/{name}/tunnel/{port}", "get"),
    ] {
        assert!(
            doc["paths"][path][method]["responses"]["504"].is_null(),
            "{method} {path} must not document a 504"
        );
    }
}

/// Whether a property schema refers to the named component, directly or
/// through the wrapper utoipa emits for an optional field.
fn refers_to(property: &serde_json::Value, component: &str) -> bool {
    serde_json::to_string(property)
        .unwrap()
        .contains(&format!("\"#/components/schemas/{component}\""))
}

#[tokio::test]
async fn openapi_types_the_vocabulary_enums() {
    let doc = fetch_openapi().await;
    let schemas = &doc["components"]["schemas"];

    for (component, values) in [
        ("BootKind", vec!["direct", "uefi", "efi", "macos"]),
        (
            "UserdataStatus",
            vec!["pending", "running", "completed", "failed", "interrupted"],
        ),
        ("ImageKind", vec!["rootfs", "cloud-image"]),
    ] {
        assert_eq!(
            schemas[component]["enum"],
            serde_json::json!(values),
            "{component} must enumerate its wire values"
        );
    }

    let vm = &schemas["VmResponse"]["properties"];
    assert!(
        refers_to(&vm["boot_mode"], "BootKind"),
        "{}",
        vm["boot_mode"]
    );
    assert!(
        refers_to(&vm["userdata_status"], "UserdataStatus"),
        "{}",
        vm["userdata_status"]
    );
    let image = &schemas["ImageResponse"]["properties"];
    assert!(refers_to(&image["kind"], "ImageKind"), "{}", image["kind"]);
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
    for key in ["kind", "message", "hint", "details", "error"] {
        assert!(
            properties.contains_key(key),
            "ErrorResponse missing property: {key}"
        );
    }
}

/// Every request that talks to the guest agent takes the same optional wait
/// for the agent to come up, so a client that learned `connect_timeout_secs`
/// on `exec` can apply it to a file transfer or a shell.
#[tokio::test]
async fn openapi_offers_the_agent_connect_timeout_on_every_agent_request() {
    let doc = fetch_openapi().await;
    let schemas = doc["components"]["schemas"]
        .as_object()
        .expect("components.schemas must be an object");
    for name in ["ExecRequest", "ReadFileRequest", "WriteFileRequest"] {
        let properties = schemas[name]["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{name}.properties must be an object"));
        assert!(
            properties.contains_key("connect_timeout_secs"),
            "{name} lacks connect_timeout_secs"
        );
    }
    let start = schemas["WsShellInput"]["oneOf"]
        .as_array()
        .expect("WsShellInput must be a tagged union")
        .iter()
        .find(|variant| variant["properties"]["type"]["enum"] == serde_json::json!(["start"]))
        .expect("WsShellInput must have a start variant");
    assert!(
        start["properties"].get("connect_timeout_secs").is_some(),
        "the shell start message lacks connect_timeout_secs: {start}"
    );
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

#[tokio::test]
async fn openapi_documents_ephemeral_vm_creation_contract() {
    let doc = fetch_openapi().await;
    let request_schema =
        &doc["paths"]["/v1/vms"]["post"]["requestBody"]["content"]["application/json"]["schema"];
    assert_eq!(
        request_schema["$ref"],
        "#/components/schemas/CreateVmApiRequest"
    );

    let schema = &doc["components"]["schemas"]["CreateVmApiRequest"];
    let encoded = serde_json::to_string(schema).unwrap();
    assert!(
        encoded.contains("expires_after_secs"),
        "ephemeral lifetime is missing from CreateVmApiRequest: {schema}"
    );
    assert!(
        encoded.contains("owner"),
        "expiration owner is missing from CreateVmApiRequest: {schema}"
    );
    let vm_schema = &doc["components"]["schemas"]["CreateVmRequest"];
    assert!(
        vm_schema["properties"].get("egress").is_some(),
        "per-VM egress policy is missing from CreateVmRequest: {vm_schema}"
    );
    assert!(
        doc["components"]["schemas"]
            .get("EgressRuleRequest")
            .is_some(),
        "egress rule schema is missing"
    );
}
