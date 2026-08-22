//! HTTP API surface for husker, including OpenAPI docs, auth, policy, and shell/log endpoints.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use utoipa::OpenApi;
use utoipa::ToSchema;

use husker_core::{
    CheckResult, CheckStatus, CreateHostGroupRequest, CreatePoolRequest, CreateSecretRequest,
    CreateServiceRequest, CreateSnapshotRequest, CreateVmRequest, DaemonProfile, DiagnosticsReport,
    EgressRuleRequest, ExportImageRequest, HuskerCore, ImportImageRequest, RestoreSnapshotRequest,
    RotateSecretRequest,
};

type AppState<B> = Arc<HuskerCore<B>>;

mod dto;
mod errors;
mod handlers;
mod router;

pub use dto::*;
pub use errors::ErrorResponse;
pub use router::{metrics_router, router, router_with_auth, serve, serve_metrics, serve_with_auth};

use handlers::*;

#[cfg(test)]
use axum::http::Method;
#[cfg(test)]
use axum::http::StatusCode;
#[cfg(test)]
use errors::{map_agent_connect_error, map_error};
#[cfg(test)]
use husker_core::{
    BackendKind, BootKind, CoreError, NetworkMode, VmExpirationRecord, VmLifecycleState, VmRecord,
};
#[cfg(test)]
use router::{is_protected_route, is_rate_limited_route};
#[cfg(test)]
use std::sync::atomic::Ordering;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiPolicy {
    pub max_request_bytes: usize,
    pub max_file_read_bytes: usize,
    pub max_file_write_bytes: usize,
    pub sensitive_rate_limit_per_minute: u32,
    pub allowed_read_paths: Vec<String>,
    pub allowed_write_paths: Vec<String>,
    pub exec_timeout_secs: u64,
    /// Upper bound for per-request exec timeouts (`ExecRequest.timeout_secs`).
    pub exec_timeout_max_secs: u64,
    pub exec_allowlist: Vec<String>,
    pub exec_denylist: Vec<String>,
    pub exec_env_allowlist: Vec<String>,
    /// Host paths allowed as virtiofs mount sources. Empty means deny all mounts.
    #[serde(default)]
    pub allowed_mount_host_paths: Vec<String>,
}

impl Default for ApiPolicy {
    fn default() -> Self {
        Self {
            max_request_bytes: 2 * 1024 * 1024,
            max_file_read_bytes: 1024 * 1024,
            max_file_write_bytes: 1024 * 1024,
            sensitive_rate_limit_per_minute: 120,
            allowed_read_paths: Vec::new(),
            allowed_write_paths: Vec::new(),
            exec_timeout_secs: 30,
            exec_timeout_max_secs: 3600,
            exec_allowlist: Vec::new(),
            exec_denylist: Vec::new(),
            exec_env_allowlist: Vec::new(),
            allowed_mount_host_paths: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ApiMetrics {
    start: Instant,
    pub(crate) requests_total: AtomicU64,
    pub(crate) errors_total: AtomicU64,
    pub(crate) rate_limited_total: AtomicU64,
    pub(crate) exec_total: AtomicU64,
    pub(crate) file_reads_total: AtomicU64,
    pub(crate) file_writes_total: AtomicU64,
    pub(crate) shell_sessions_total: AtomicU64,
}

impl ApiMetrics {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            requests_total: AtomicU64::new(0),
            errors_total: AtomicU64::new(0),
            rate_limited_total: AtomicU64::new(0),
            exec_total: AtomicU64::new(0),
            file_reads_total: AtomicU64::new(0),
            file_writes_total: AtomicU64::new(0),
            shell_sessions_total: AtomicU64::new(0),
        }
    }
}

/// Width of the sliding window every sensitive-endpoint limit is counted over.
pub(crate) const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// The outcome of one rate-limit check.
///
/// A rejection carries the wait because only the limiter knows it: the window
/// frees capacity as its oldest event ages out, and a client left to guess
/// either stalls far longer than needed or retries in a tight loop.
#[derive(Debug)]
pub(crate) enum RateLimitDecision {
    Allowed,
    Limited { retry_after: Duration },
}

#[derive(Debug, Default)]
pub(crate) struct SlidingWindowRateLimiter {
    events: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl SlidingWindowRateLimiter {
    #[cfg(test)]
    fn clear(&self) {
        self.events
            .lock()
            .expect("rate limiter lock poisoned")
            .clear();
    }

    /// Record one request against `key`, or reject it and say when the window
    /// next has room. A rejected request is deliberately not recorded, so
    /// retrying while limited cannot push that moment further away.
    pub(crate) fn check(&self, key: &str, limit_per_minute: u32) -> RateLimitDecision {
        if limit_per_minute == 0 {
            return RateLimitDecision::Allowed;
        }
        let mut events = self.events.lock().expect("rate limiter lock poisoned");
        let now = Instant::now();
        let window_start = now - RATE_LIMIT_WINDOW;
        let queue = events.entry(key.to_string()).or_default();
        while queue.front().is_some_and(|t| *t < window_start) {
            queue.pop_front();
        }
        if queue.len() >= limit_per_minute as usize {
            // The request that frees a slot is the oldest one still in the
            // window; capacity returns one window after it was recorded.
            let retry_after = queue
                .front()
                .map(|oldest| (*oldest + RATE_LIMIT_WINDOW).saturating_duration_since(now))
                .unwrap_or(RATE_LIMIT_WINDOW);
            return RateLimitDecision::Limited { retry_after };
        }
        queue.push_back(now);
        RateLimitDecision::Allowed
    }
}

static API_POLICY: OnceLock<RwLock<ApiPolicy>> = OnceLock::new();
static API_METRICS: OnceLock<ApiMetrics> = OnceLock::new();
static RATE_LIMITER: OnceLock<SlidingWindowRateLimiter> = OnceLock::new();
pub(crate) static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);
/// Max VMs the daemon will admit before rejecting `create` (0 = unlimited).
/// Set from config at startup; bounds host resource use by a single client.
static MAX_VMS: AtomicU64 = AtomicU64::new(0);

/// Set the max-VMs admission limit (`None` = unlimited).
pub fn set_max_vms(max: Option<usize>) {
    MAX_VMS.store(
        max.unwrap_or(0) as u64,
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// The configured max-VMs admission limit, or `None` if unlimited.
pub(crate) fn max_vms() -> Option<usize> {
    match MAX_VMS.load(std::sync::atomic::Ordering::Relaxed) {
        0 => None,
        n => Some(n as usize),
    }
}

// ── OpenAPI ───────────────────────────────────────────────────────────

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Husker API",
        description = "REST API for managing Firecracker microVMs",
        version = "0.1.0",
        license(name = "MIT")
    ),
    paths(
        health,
        list_profiles,
        list_host_groups,
        create_host_group,
        get_host_group,
        delete_host_group,
        list_services,
        create_service,
        get_service,
        delete_service,
        scale_service,
        list_pools,
        create_pool,
        get_pool,
        delete_pool,
        checkout_pool,
        list_images,
        import_image,
        import_oci_image,
        get_image,
        delete_image,
        export_image,
        list_volumes,
        create_volume,
        get_volume,
        delete_volume,
        list_secrets,
        create_secret,
        get_secret,
        reveal_secret,
        rotate_secret,
        delete_secret,
        list_snapshots,
        create_snapshot,
        get_snapshot,
        delete_snapshot,
        restore_snapshot,
        list_vms,
        create_vm,
        get_vm,
        stop_vm,
        pause_vm,
        resume_vm,
        suspend_vm,
        fork_vm,
        destroy_vm,
        set_balloon,
        exec_vm,
        exec_ws,
        read_file_handler,
        write_file_handler,
        shell_ws,
        get_logs,
        get_ready,
        get_guest_info,
        metrics_handler,
        diagnostics,
    ),
    components(schemas(
        VmResponse,
        ForkRequest,
        HostGroupResponse,
        ServiceResponse,
        ServiceInstance,
        ServiceDetailResponse,
        ServiceMutationResponse,
        ServiceDeleteResponse,
        PoolResponse,
        CreatePoolRequest,
        CheckoutPoolRequest,
        PoolDeleteResponse,
        ReconcileOutcomeResponse,
        ReconcileFailure,
        SnapshotResponse,
        ImageResponse,
        ExportImageResponse,
        VolumeResponse,
        CreateVolumeApiRequest,
        SecretResponse,
        RevealedSecretResponse,
        ErrorResponse,
        ExecRequest,
        ExecResponse,
        ReadFileRequest,
        ReadFileResponse,
        WriteFileRequest,
        WriteFileResponse,
        HealthResponse,
        VmCounts,
        ReadyResponse,
        GuestInfoResponse,
        ProfilesResponse,
        DaemonProfile,
        LogsQuery,
        WsShellInput,
        WsShellOutput,
        WsExecInput,
        WsExecOutput,
        CreateHostGroupRequest,
        CreateServiceRequest,
        CreateSnapshotRequest,
        RestoreSnapshotRequest,
        ImportImageRequest,
        ImportOciRequest,
        ExportImageRequest,
        CreateSecretRequest,
        RotateSecretRequest,
        ScaleServiceRequest,
        BalloonRequest,
        CreateVmApiRequest,
        CreateVmRequest,
        EgressRuleRequest,
        DiagnosticsReport,
        CheckResult,
        CheckStatus,
    )),
    tags(
        (name = "vms", description = "VM lifecycle management"),
        (name = "host_groups", description = "Host group management"),
        (name = "services", description = "Service model resources"),
        (name = "pools", description = "Hot pool resources"),
        (name = "images", description = "Image catalog resources"),
        (name = "volumes", description = "Persistent volume resources"),
        (name = "secrets", description = "Encrypted secret resources"),
        (name = "snapshots", description = "Snapshot lifecycle resources"),
        (name = "exec", description = "Command execution in VMs"),
        (name = "files", description = "File transfer to/from VMs"),
        (name = "shell", description = "Interactive shell sessions"),
        (name = "logs", description = "Serial console output"),
        (name = "ports", description = "Port forwarding"),
        (name = "health", description = "Service health"),
        (name = "profiles", description = "Named VM presets")
    )
)]
pub(crate) struct ApiDoc;

#[derive(OpenApi)]
#[openapi(
    paths(
        add_port_forward_handler,
        list_port_forwards_handler,
        remove_port_forward_handler,
    ),
    components(schemas(AddPortForwardRequest, PortForwardResponse,))
)]
pub(crate) struct PortForwardApiDoc;

fn policy_lock() -> &'static RwLock<ApiPolicy> {
    API_POLICY.get_or_init(|| RwLock::new(ApiPolicy::default()))
}

pub(crate) fn metrics() -> &'static ApiMetrics {
    API_METRICS.get_or_init(ApiMetrics::new)
}

pub(crate) fn rate_limiter() -> &'static SlidingWindowRateLimiter {
    RATE_LIMITER.get_or_init(SlidingWindowRateLimiter::default)
}

pub(crate) fn current_policy() -> ApiPolicy {
    policy_lock()
        .read()
        .expect("api policy lock poisoned")
        .clone()
}

pub fn set_policy(policy: ApiPolicy) {
    *policy_lock().write().expect("api policy lock poisoned") = policy;
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::sync::OnceLock;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn make_core(
        state: husker_state::StateStore,
        storage: husker_storage::StorageConfig,
        runtime_dir: PathBuf,
    ) -> Arc<HuskerCore<husker_vmm::firecracker::FirecrackerBackend>> {
        let vmm = husker_vmm::firecracker::FirecrackerBackend::new(
            std::path::Path::new("/nonexistent"),
            std::path::Path::new("/tmp"),
            std::sync::Arc::new(husker_vmm::cgroup::CgroupSupervisor::disabled()),
        );

        #[cfg(feature = "linux-net")]
        {
            let ip_allocator =
                husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24);
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
            state_dir: PathBuf::from("/tmp/husker-test"),
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

    fn seeded_core_for_metrics() -> Arc<HuskerCore<husker_vmm::firecracker::FirecrackerBackend>> {
        let state = husker_state::StateStore::open_memory().unwrap();
        let now = chrono::Utc::now();

        // Insert a service named "svc" with desired_instances = 2.
        let svc_id = uuid::Uuid::new_v4();
        state
            .insert_service(&husker_state::ServiceRecord {
                id: svc_id,
                name: "svc".into(),
                host_group_id: None,
                desired_instances: 2,
                image: None,
                kernel_path: String::new(),
                rootfs_path: String::new(),
                initrd_path: None,
                vcpu_count: None,
                mem_size_mib: None,
                userdata: None,
                userdata_env: None,
                created_at: now,
                updated_at: now,
                cloud_image: None,
                disk_size: None,
                balloon: false,
                volume: None,
            })
            .unwrap();

        // 1 running VM owned by "svc".
        state
            .insert_vm(&husker_state::VmRecord {
                id: uuid::Uuid::new_v4(),
                name: "vm-running".into(),
                state: VmLifecycleState::Running,
                pid: Some(1),
                vcpu_count: 1,
                mem_size_mib: 128,
                vsock_cid: 100,
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
                service_id: Some(svc_id),
                service_ordinal: Some(0),
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
            })
            .unwrap();

        // 1 stopped VM not owned by any service.
        state
            .insert_vm(&husker_state::VmRecord {
                id: uuid::Uuid::new_v4(),
                name: "vm-stopped".into(),
                state: VmLifecycleState::Stopped,
                pid: None,
                vcpu_count: 1,
                mem_size_mib: 128,
                vsock_cid: 101,
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
            })
            .unwrap();

        make_core(
            state,
            husker_storage::StorageConfig {
                data_dir: std::path::PathBuf::from("/tmp/husker-test"),
                state_dir: std::path::PathBuf::from("/tmp/husker-test"),
            },
            std::path::PathBuf::from("/tmp/husker-test/run"),
        )
    }

    fn policy_test_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    #[tokio::test]
    async fn health_check() {
        let app = router(test_core());
        let response = app
            .oneshot(Request::get("/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["status"], "ok");
        assert!(json["version"].as_str().is_some());
        assert_eq!(json["vms"]["total"], 0);
        assert_eq!(json["vms"]["running"], 0);
    }

    #[tokio::test]
    async fn health_advertises_backend_and_capabilities() {
        // test_core() runs on a real FirecrackerBackend.
        let app = router(test_core());
        let response = app
            .oneshot(Request::get("/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["backend"], "firecracker", "daemon names its backend");
        let caps = &json["capabilities"];
        assert_eq!(caps["fork"], true, "firecracker advertises fork");
        assert_eq!(caps["snapshot"], true, "firecracker advertises snapshot");
        // Platform/feature-gated capabilities reflect the build configuration.
        assert_eq!(caps["port_forward"], serde_json::json!(true));
        assert_eq!(caps["bridged_net"], cfg!(feature = "linux-net"));
        assert_eq!(caps["oci_import"], cfg!(target_os = "linux"));
    }

    #[tokio::test]
    async fn diagnostics_endpoint_returns_checks() {
        let app = router(test_core());
        let response = app
            .oneshot(Request::get("/v1/diagnostics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let report: husker_core::DiagnosticsReport = serde_json::from_slice(&bytes).unwrap();
        assert!(report.checks.iter().any(|c| c.name == "data-dir reflink"));
    }

    #[tokio::test]
    async fn list_vms_empty() {
        let app = router(test_core());
        let response = app
            .oneshot(Request::get("/v1/vms").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let json = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json, serde_json::json!([]));
    }

    #[tokio::test]
    async fn host_group_and_service_crud_basic() {
        let app = router(test_core());

        let create_group = serde_json::json!({
            "name": "default",
            "description": "default hosts"
        });
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/host-groups")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&create_group).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let group = response_json(response).await;
        assert_eq!(group["name"], "default");

        let create_service = serde_json::json!({
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
                    .body(Body::from(serde_json::to_string(&create_service).unwrap()))
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

        let response = app
            .clone()
            .oneshot(
                Request::get("/v1/services/api")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let get_json = response_json(response).await;
        assert_eq!(get_json["name"], "api");
        assert_eq!(get_json["desired_instances"], 0);
        assert_eq!(get_json["instances"], serde_json::json!([]));

        let response = app
            .clone()
            .oneshot(
                Request::delete("/v1/services/api")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let delete_json = response_json(response).await;
        assert_eq!(delete_json["name"], "api");
        assert_eq!(delete_json["outcome"]["created"], serde_json::json!([]));
        assert_eq!(delete_json["outcome"]["destroyed"], serde_json::json!([]));

        let response = app
            .clone()
            .oneshot(
                Request::delete("/v1/host-groups/default")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn create_service_unknown_host_group_returns_404() {
        let app = router(test_core());
        let body = serde_json::json!({
            "name": "api",
            "host_group": "missing",
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
        assert_eq!(json["kind"], "host_group_not_found");
    }

    #[tokio::test]
    async fn create_service_zero_instances_succeeds() {
        // Scale-to-zero is now allowed; desired_instances=0 creates a service with no instances.
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

    #[tokio::test]
    async fn scale_service_updates_desired_instances() {
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

        let scale = serde_json::json!({ "desired_instances": 4 });
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
        let json = response_json(response).await;
        assert_eq!(json["service"]["name"], "api");
        assert_eq!(json["service"]["desired_instances"], 4);
        assert_eq!(json["service"]["current_instances"], 0);
        assert_eq!(json["outcome"]["created"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn scale_service_to_zero_succeeds() {
        // Scale-to-zero is now allowed; desired_instances=0 stops all instances but keeps the service.
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

        let scale = serde_json::json!({ "desired_instances": 0 });
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
        let json = response_json(response).await;
        assert_eq!(json["service"]["desired_instances"], 0);
        assert_eq!(json["service"]["current_instances"], 0);
        assert_eq!(json["outcome"]["created"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn snapshot_crud_basic() {
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
                state: VmLifecycleState::Stopped,
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
            })
            .unwrap();

        let core = make_core(
            state,
            husker_storage::StorageConfig {
                data_dir: data_dir.clone(),
                state_dir: data_dir.clone(),
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
        let json = response_json(response).await;
        assert_eq!(json["name"], "snap-1");
        assert_eq!(json["source_vm_name"], "snap-vm");

        let response = app
            .clone()
            .oneshot(Request::get("/v1/snapshots").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let listed = response_json(response).await;
        assert_eq!(listed.as_array().unwrap().len(), 1);

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
    async fn image_crud_and_export_basic() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let runtime_dir = temp.path().join("run");
        let source_path = temp.path().join("source.ext4");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::create_dir_all(&runtime_dir).unwrap();
        std::fs::write(&source_path, b"image-bytes").unwrap();

        let core = make_core(
            husker_state::StateStore::open_memory().unwrap(),
            husker_storage::StorageConfig {
                data_dir: data_dir.clone(),
                state_dir: data_dir.clone(),
            },
            runtime_dir,
        );
        let app = router(core);

        let import = serde_json::json!({
            "name": "ubuntu-base",
            "source_path": source_path,
        });
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/images")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&import).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let imported = response_json(response).await;
        assert_eq!(imported["name"], "ubuntu-base");
        assert_eq!(imported["format"], "ext4");

        let response = app
            .clone()
            .oneshot(Request::get("/v1/images").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let listed = response_json(response).await;
        assert_eq!(listed.as_array().unwrap().len(), 1);

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

        let export_path = temp.path().join("exports/base-copy.ext4");
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
        assert_eq!(std::fs::read(export_path).unwrap(), b"image-bytes");

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
    async fn secret_crud_and_reveal_basic() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let runtime_dir = temp.path().join("run");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::create_dir_all(&runtime_dir).unwrap();

        let core = make_core(
            husker_state::StateStore::open_memory().unwrap(),
            husker_storage::StorageConfig {
                data_dir: data_dir.clone(),
                state_dir: data_dir.clone(),
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
        let created = response_json(response).await;
        assert_eq!(created["name"], "db-password");

        let response = app
            .clone()
            .oneshot(Request::get("/v1/secrets").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let listed = response_json(response).await;
        assert_eq!(listed.as_array().unwrap().len(), 1);

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

        let rotate = serde_json::json!({ "value": "new-value" });
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
        assert_eq!(revealed["value"], "new-value");

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
        assert_eq!(json["kind"], "snapshot_not_found");
    }

    #[tokio::test]
    async fn get_vm_not_found() {
        let app = router(test_core());
        let response = app
            .oneshot(
                Request::get("/v1/vms/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let json = response_json(response).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(json["error"].as_str().unwrap().contains("not found"));
    }

    #[tokio::test]
    async fn create_vm_bad_kernel() {
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
        let status = response.status();
        let json = response_json(response).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(json["error"].as_str().unwrap().contains("kernel"));
    }

    #[tokio::test]
    async fn ephemeral_vm_creation_validates_expiration_before_allocating_resources() {
        for body in [
            serde_json::json!({
                "name": "owner-without-expiration",
                "owner": "werkt/run-1"
            }),
            serde_json::json!({
                "name": "zero-expiration",
                "expires_after_secs": 0
            }),
        ] {
            let response = router(test_core())
                .oneshot(
                    Request::post("/v1/vms")
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let json = response_json(response).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "response: {json}");
            assert_eq!(json["kind"], "invalid_argument");
        }
    }

    #[tokio::test]
    async fn create_rejected_when_max_vms_reached() {
        // One VM already exists and the limit is 1, so a create is rejected with
        // 429 at admission - before it reaches kernel validation (which would 500).
        let state = husker_state::StateStore::open_memory().unwrap();
        let now = chrono::Utc::now();
        state
            .insert_vm(&husker_state::VmRecord {
                id: uuid::Uuid::new_v4(),
                name: "existing".into(),
                state: VmLifecycleState::Running,
                pid: Some(1),
                vcpu_count: 1,
                mem_size_mib: 128,
                vsock_cid: 100,
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
            })
            .unwrap();
        let storage = husker_storage::StorageConfig {
            data_dir: PathBuf::from("/tmp/husker-maxvms-test"),
            state_dir: PathBuf::from("/tmp/husker-maxvms-test"),
        };
        let core = make_core(state, storage, PathBuf::from("/tmp/husker-maxvms-test/run"));

        set_max_vms(Some(1));
        let app = router(core);
        let body = serde_json::json!({
            "name": "over-limit",
            "kernel_path": "/nonexistent/vmlinux",
            "rootfs_path": "/nonexistent/rootfs.ext4",
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
        // Reset the global before asserting so a failure never leaks the limit to
        // other tests sharing the process under `cargo test`.
        set_max_vms(None);
        let status = response.status();
        let json = response_json(response).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(json["error"].as_str().unwrap().contains("VM limit reached"));
    }

    #[tokio::test]
    async fn stop_vm_not_found() {
        let app = router(test_core());
        let response = app
            .oneshot(
                Request::post("/v1/vms/nonexistent/stop")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn pause_vm_not_found() {
        let app = router(test_core());
        let response = app
            .oneshot(
                Request::post("/v1/vms/nonexistent/pause")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn suspend_vm_not_found() {
        let app = router(test_core());
        let response = app
            .oneshot(
                Request::post("/v1/vms/ghost/suspend")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn logs_missing_use_kind_specific_error_codes() {
        // The VM exists but has no log files, so each request reaches the
        // log-not-found path. The structured `code` is part of the API contract:
        // the serial path must keep `serial_log_not_found`, and the userdata path
        // gets its own distinct code rather than reusing the serial one.
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let runtime_dir = temp.path().join("run");
        std::fs::create_dir_all(&runtime_dir).unwrap();

        let state = husker_state::StateStore::open_memory().unwrap();
        let now = chrono::Utc::now();
        state
            .insert_vm(&husker_state::VmRecord {
                id: uuid::Uuid::new_v4(),
                name: "logvm".into(),
                state: VmLifecycleState::Running,
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
            })
            .unwrap();

        let core = make_core(
            state,
            husker_storage::StorageConfig {
                data_dir: data_dir.clone(),
                state_dir: data_dir,
            },
            runtime_dir,
        );
        let app = router(core);

        let serial = app
            .clone()
            .oneshot(
                Request::get("/v1/vms/logvm/logs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(serial.status(), StatusCode::NOT_FOUND);
        assert_eq!(response_json(serial).await["kind"], "serial_log_not_found");

        let userdata = app
            .clone()
            .oneshot(
                Request::get("/v1/vms/logvm/logs?userdata=true")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(userdata.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response_json(userdata).await["kind"],
            "userdata_log_not_found"
        );

        // source=boot yields boot_log_not_found when the file is absent.
        let boot = app
            .clone()
            .oneshot(
                Request::get("/v1/vms/logvm/logs?source=boot")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(boot.status(), StatusCode::NOT_FOUND);
        assert_eq!(response_json(boot).await["kind"], "boot_log_not_found");

        // source=serial via explicit param works like default.
        let serial2 = app
            .clone()
            .oneshot(
                Request::get("/v1/vms/logvm/logs?source=serial")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(serial2.status(), StatusCode::NOT_FOUND);
        assert_eq!(response_json(serial2).await["kind"], "serial_log_not_found");

        // Unknown source yields 400 invalid_log_source.
        let bad = app
            .oneshot(
                Request::get("/v1/vms/logvm/logs?source=garbage")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_json(bad).await["kind"], "invalid_log_source");
    }

    #[tokio::test]
    async fn resume_vm_not_found() {
        let app = router(test_core());
        let response = app
            .oneshot(
                Request::post("/v1/vms/nonexistent/resume")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ── balloon handler tests ─────────────────────────────────────────

    #[tokio::test]
    async fn balloon_on_vm_without_balloon_flag_returns_400() {
        // Insert a VM with balloon=false (the default); the endpoint must
        // return 400 before ever calling the VMM backend.
        let state = husker_state::StateStore::open_memory().unwrap();
        let now = chrono::Utc::now();
        state
            .insert_vm(&husker_state::VmRecord {
                id: uuid::Uuid::new_v4(),
                name: "no-balloon-vm".into(),
                state: VmLifecycleState::Running,
                pid: Some(42),
                vcpu_count: 1,
                mem_size_mib: 256,
                vsock_cid: 10,
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
            })
            .unwrap();
        let core = make_core(
            state,
            husker_storage::StorageConfig {
                data_dir: std::path::PathBuf::from("/tmp/husker-test"),
                state_dir: std::path::PathBuf::from("/tmp/husker-test"),
            },
            std::path::PathBuf::from("/tmp/husker-test/run"),
        );
        let app = router(core);
        let body = serde_json::json!({ "amount_mib": 64 });
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/vms/no-balloon-vm/balloon")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["kind"], "invalid_argument");
        assert!(
            json["message"].as_str().unwrap_or("").contains("--balloon"),
            "error message should mention --balloon"
        );
    }

    #[tokio::test]
    async fn balloon_on_missing_vm_returns_404() {
        let app = router(test_core());
        let body = serde_json::json!({ "amount_mib": 64 });
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/vms/nonexistent/balloon")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn destroy_vm_not_found() {
        let app = router(test_core());
        let response = app
            .oneshot(
                Request::delete("/v1/vms/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn exec_vm_not_found() {
        let app = router(test_core());
        let body = serde_json::json!({
            "command": "echo",
            "args": ["hello"]
        });
        let response = app
            .oneshot(
                Request::post("/v1/vms/nonexistent/exec")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn exec_vm_missing_secret_returns_404_before_vm_lookup() {
        // A --secret reference to a non-existent secret is rejected with a
        // secret-specific 404, and the resolution happens before the VM lookup
        // (so even a missing VM surfaces the secret error first).
        let app = router(test_core());
        let body = serde_json::json!({
            "command": "echo",
            "args": ["hi"],
            "secret_env": { "TOKEN": "does-not-exist" }
        });
        let response = app
            .oneshot(
                Request::post("/v1/vms/nonexistent/exec")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains("secret"),
            "expected a secret-not-found error, got: {text}"
        );
    }

    #[tokio::test]
    async fn read_file_policy_denied_returns_403() {
        let _guard = policy_test_lock().lock().await;
        set_policy(ApiPolicy {
            allowed_read_paths: vec!["/safe".into()],
            ..ApiPolicy::default()
        });

        let app = router(test_core());
        let body = serde_json::json!({ "path": "/etc/passwd" });
        let response = app
            .oneshot(
                Request::post("/v1/vms/any/files/read")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let json = response_json(response).await;
        assert_eq!(json["kind"], "policy_read_path_denied");

        set_policy(ApiPolicy::default());
    }

    #[tokio::test]
    async fn write_file_policy_denied_returns_403() {
        let _guard = policy_test_lock().lock().await;
        set_policy(ApiPolicy {
            allowed_write_paths: vec!["/safe".into()],
            ..ApiPolicy::default()
        });

        let app = router(test_core());
        let body = serde_json::json!({
            "path": "/etc/passwd",
            "data": husker_agent_proto::base64_encode(b"x"),
            "mode": null
        });
        let response = app
            .oneshot(
                Request::post("/v1/vms/any/files/write")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let json = response_json(response).await;
        assert_eq!(json["kind"], "policy_write_path_denied");

        set_policy(ApiPolicy::default());
    }

    #[tokio::test]
    async fn write_file_too_large_returns_413() {
        let _guard = policy_test_lock().lock().await;
        set_policy(ApiPolicy {
            max_file_write_bytes: 1,
            ..ApiPolicy::default()
        });

        let app = router(test_core());
        let body = serde_json::json!({
            "path": "/tmp/output.bin",
            "data": husker_agent_proto::base64_encode(b"xy"),
            "mode": null
        });
        let response = app
            .oneshot(
                Request::post("/v1/vms/any/files/write")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let json = response_json(response).await;
        assert_eq!(json["kind"], "write_file_too_large");

        set_policy(ApiPolicy::default());
    }

    /// A minimal `VmRecord`: `running`, `firecracker`, no idle policy set by
    /// default, no service/fork/volume attachments.
    fn sample_vm_record(name: &str) -> VmRecord {
        let now = chrono::Utc::now();
        VmRecord {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            state: VmLifecycleState::Running,
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

    #[test]
    fn vm_response_includes_policy_fields() {
        let mut r = sample_vm_record("r");
        r.idle_timeout_secs = Some(120);
        r.auto_resume = false;
        let expiration = VmExpirationRecord {
            vm_id: r.id,
            owner: Some("werkt/run-123".into()),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        };
        let resp = record_to_response(r, Some(expiration.clone()));
        assert_eq!(resp.vmm, "firecracker");
        assert_eq!(resp.idle_timeout_secs, Some(120));
        assert_eq!(resp.suspend_ttl_secs, None);
        assert_eq!(resp.auto_resume, Some(false));
        assert_eq!(resp.expires_at, Some(expiration.expires_at.to_rfc3339()));
        assert_eq!(resp.owner.as_deref(), Some("werkt/run-123"));

        // A VM that never opted into the idle policy must not surface
        // `auto_resume` at all, keeping the no-policy payload tidy.
        let no_policy = sample_vm_record("no-policy");
        let resp = record_to_response(no_policy, None);
        assert_eq!(resp.idle_timeout_secs, None);
        assert_eq!(resp.auto_resume, None);
        assert_eq!(resp.expires_at, None);
        assert_eq!(resp.owner, None);
    }

    #[test]
    fn create_vm_api_request_preserves_flat_shape_and_expiration_fields() {
        let request: CreateVmApiRequest = serde_json::from_value(serde_json::json!({
            "name": "werkt-run-123",
            "rootfs_path": "python:3.12-alpine",
            "network": "none",
            "expires_after_secs": 420,
            "owner": "werkt/run-123"
        }))
        .unwrap();

        assert_eq!(request.vm.name, "werkt-run-123");
        assert_eq!(
            request.vm.rootfs_path.as_deref(),
            Some(std::path::Path::new("python:3.12-alpine"))
        );
        assert_eq!(request.vm.network.as_deref(), Some("none"));
        assert_eq!(request.expires_after_secs, Some(420));
        assert_eq!(request.owner.as_deref(), Some("werkt/run-123"));

        let encoded = serde_json::to_value(request).unwrap();
        assert_eq!(encoded["name"], "werkt-run-123");
        assert_eq!(encoded["expires_after_secs"], 420);
        assert!(encoded.get("vm").is_none(), "request must remain flat");
    }

    #[test]
    fn protected_route_detection_is_correct() {
        // Deny-by-default: only an explicit allowlist is reachable without a token.
        // Health (orchestrator liveness) and the static API docs are public.
        assert!(!is_protected_route("/v1/health"));
        assert!(!is_protected_route("/docs"));
        assert!(!is_protected_route("/docs/index.html"));
        assert!(!is_protected_route("/api-docs/openapi.json"));

        // Reads expose guest_ip / pid / rootfs_path and other topology, so on a
        // token-protected daemon they require the token too (this is the SEC-3 fix:
        // previously these GETs were public).
        assert!(is_protected_route("/v1/vms"));
        assert!(is_protected_route("/v1/vms/example"));
        assert!(is_protected_route("/v1/services"));
        assert!(is_protected_route("/v1/host-groups"));
        assert!(is_protected_route("/v1/images"));
        assert!(is_protected_route("/v1/snapshots"));
        assert!(is_protected_route("/v1/volumes"));
        assert!(is_protected_route("/v1/pools"));
        // Previously outside the checklist entirely (SEC-11): now protected.
        assert!(is_protected_route("/v1/profiles"));
        assert!(is_protected_route("/v1/diagnostics"));

        // Secrets, metrics, and every mutation stay protected.
        assert!(is_protected_route("/v1/secrets"));
        assert!(is_protected_route("/v1/secrets/db-password"));
        assert!(is_protected_route("/v1/metrics"));
        assert!(is_protected_route("/v1/services"));
        assert!(is_protected_route("/v1/images/base"));
        assert!(is_protected_route("/v1/snapshots/snap-1"));
        assert!(is_protected_route("/v1/vms/example/stop"));
        assert!(is_protected_route("/v1/vms/example"));
        assert!(is_protected_route("/v1/vms/example/shell"));
        assert!(is_protected_route("/v1/vms/example/exec/stream"));
        assert!(is_protected_route("/v1/vms/example/logs"));
        assert!(is_protected_route("/v1/vms/example/ready"));
        assert!(is_protected_route("/v1/volumes/data"));
        assert!(is_protected_route("/v1/pools/web/checkout"));
    }

    #[tokio::test]
    async fn auth_enabled_allows_public_health_without_token() {
        let app = router_with_auth(test_core(), Some("secret".into()));
        let response = app
            .oneshot(Request::get("/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_enabled_rejects_read_without_token() {
        // SEC-3 regression: list/detail reads leak guest_ip/pid/rootfs_path, so on a
        // token-protected daemon they must require the token (previously public).
        let app = router_with_auth(test_core(), Some("secret".into()));
        for path in ["/v1/vms", "/v1/pools", "/v1/diagnostics", "/v1/profiles"] {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "GET {path} must require a token when one is configured"
            );
        }
        // With the token, the same read succeeds.
        let response = app
            .oneshot(
                Request::get("/v1/vms")
                    .header(axum::http::header::AUTHORIZATION, "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_enabled_rejects_mutating_endpoint_without_token() {
        let app = router_with_auth(test_core(), Some("secret".into()));
        let response = app
            .oneshot(
                Request::post("/v1/vms/nonexistent/stop")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = response_json(response).await;
        assert!(
            json["error"]
                .as_str()
                .is_some_and(|msg| msg.contains("missing or invalid bearer token"))
        );
    }

    #[tokio::test]
    async fn auth_enabled_accepts_valid_token_for_mutating_endpoint() {
        let app = router_with_auth(test_core(), Some("secret".into()));
        let response = app
            .oneshot(
                Request::post("/v1/vms/nonexistent/stop")
                    .header(axum::http::header::AUTHORIZATION, "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Request passed auth middleware and reached VM lookup.
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn auth_enabled_requires_token_for_shell_endpoint() {
        let app = router_with_auth(test_core(), Some("secret".into()));
        let response = app
            .oneshot(
                Request::get("/v1/vms/nonexistent/shell")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_enabled_rejects_logs_without_token() {
        let app = router_with_auth(test_core(), Some("secret".into()));
        let response = app
            .oneshot(
                Request::get("/v1/vms/any/logs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_enabled_rejects_metrics_without_token() {
        let app = router_with_auth(test_core(), Some("secret".into()));
        let response = app
            .oneshot(Request::get("/v1/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_enabled_rejects_service_mutation_without_token() {
        let app = router_with_auth(test_core(), Some("secret".into()));
        let body = serde_json::json!({ "name": "default" });
        let response = app
            .oneshot(
                Request::post("/v1/host-groups")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_enabled_rejects_snapshot_mutation_without_token() {
        let app = router_with_auth(test_core(), Some("secret".into()));
        let body = serde_json::json!({ "name": "snap-1", "vm": "vm-a" });
        let response = app
            .oneshot(
                Request::post("/v1/snapshots")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_enabled_rejects_image_mutation_without_token() {
        let app = router_with_auth(test_core(), Some("secret".into()));
        let body = serde_json::json!({
            "name": "ubuntu-base",
            "source_path": "/tmp/source.ext4"
        });
        let response = app
            .oneshot(
                Request::post("/v1/images")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_enabled_rejects_volume_delete_without_token() {
        let app = router_with_auth(test_core(), Some("secret".into()));
        let response = app
            .oneshot(
                Request::delete("/v1/volumes/data")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_enabled_rejects_volume_create_without_token() {
        let app = router_with_auth(test_core(), Some("secret".into()));
        let body = serde_json::json!({ "name": "data", "size_mib": 1024 });
        let response = app
            .oneshot(
                Request::post("/v1/volumes")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_enabled_rejects_secret_read_without_token() {
        let app = router_with_auth(test_core(), Some("secret".into()));
        let response = app
            .oneshot(Request::get("/v1/secrets").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn normalize_guest_path_rejects_parent_traversal() {
        assert_eq!(normalize_guest_path("relative/path"), None);
        assert_eq!(normalize_guest_path("/var/log/../tmp"), None);
        assert_eq!(
            normalize_guest_path("/var//log/./kernel"),
            Some("/var/log/kernel".into())
        );
    }

    #[test]
    fn allowlist_path_enforcement() {
        let allow = vec!["/tmp".to_string(), "/var/log".to_string()];
        assert!(is_allowed_guest_path("/tmp/test.txt", &allow));
        assert!(is_allowed_guest_path("/var/log/kern.log", &allow));
        assert!(!is_allowed_guest_path("/etc/passwd", &allow));

        let no_allowlist: Vec<String> = Vec::new();
        assert!(is_allowed_guest_path("/etc/passwd", &no_allowlist));
        assert!(!is_allowed_guest_path("etc/passwd", &no_allowlist));
    }

    #[test]
    fn exec_connect_timeout_defaults_and_clamps() {
        assert_eq!(
            resolve_exec_connect_timeout(None, BootKind::DirectKernel),
            Duration::from_secs(DEFAULT_EXEC_CONNECT_TIMEOUT_SECS)
        );
        assert_eq!(
            resolve_exec_connect_timeout(None, BootKind::Uefi),
            Duration::from_secs(husker_core::UEFI_READY_TIMEOUT_SECS)
        );
        // EFI (macOS/VZ cloud-image) needs the same extended timeout as UEFI.
        assert_eq!(
            resolve_exec_connect_timeout(None, BootKind::Efi),
            Duration::from_secs(husker_core::UEFI_READY_TIMEOUT_SECS)
        );
        assert_eq!(
            resolve_exec_connect_timeout(Some(5), BootKind::DirectKernel),
            Duration::from_secs(5)
        );
        // An explicit timeout wins regardless of boot mode.
        assert_eq!(
            resolve_exec_connect_timeout(Some(5), BootKind::Uefi),
            Duration::from_secs(5)
        );
        assert_eq!(
            resolve_exec_connect_timeout(Some(5), BootKind::Efi),
            Duration::from_secs(5)
        );
        assert_eq!(
            resolve_exec_connect_timeout(Some(0), BootKind::DirectKernel),
            Duration::from_secs(1)
        );
        assert_eq!(
            resolve_exec_connect_timeout(Some(u64::MAX), BootKind::DirectKernel),
            Duration::from_secs(MAX_EXEC_CONNECT_TIMEOUT_SECS)
        );
    }

    #[test]
    fn exec_run_timeout_defaults_and_clamps() {
        let policy = ApiPolicy {
            exec_timeout_secs: 30,
            exec_timeout_max_secs: 3600,
            ..ApiPolicy::default()
        };
        assert_eq!(
            resolve_exec_run_timeout(None, &policy),
            Duration::from_secs(30)
        );
        assert_eq!(
            resolve_exec_run_timeout(Some(600), &policy),
            Duration::from_secs(600)
        );
        assert_eq!(
            resolve_exec_run_timeout(Some(0), &policy),
            Duration::from_secs(1)
        );
        assert_eq!(
            resolve_exec_run_timeout(Some(u64::MAX), &policy),
            Duration::from_secs(3600)
        );
        // A zero daemon default still yields the 1s floor when the request
        // does not specify a timeout (pre-existing behavior).
        let zero_default = ApiPolicy {
            exec_timeout_secs: 0,
            exec_timeout_max_secs: 3600,
            ..ApiPolicy::default()
        };
        assert_eq!(
            resolve_exec_run_timeout(None, &zero_default),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn exec_policy_allow_deny_and_env() {
        let mut policy = ApiPolicy {
            exec_allowlist: vec!["echo".into(), "ls".into()],
            exec_denylist: vec!["rm".into()],
            exec_env_allowlist: vec!["PATH".into(), "HOME".into()],
            ..ApiPolicy::default()
        };
        assert!(exec_command_allowed("echo", &policy));
        assert!(!exec_command_allowed("rm", &policy));
        assert!(!exec_command_allowed("cat", &policy));

        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/usr/bin".to_string());
        assert!(exec_env_allowed(&env, &policy));
        env.insert("LD_PRELOAD".to_string(), "x".to_string());
        assert!(!exec_env_allowed(&env, &policy));

        policy.exec_allowlist.clear();
        assert!(exec_command_allowed("cat", &policy));
        policy.exec_env_allowlist.clear();
        assert!(exec_env_allowed(&env, &policy));
    }

    #[test]
    fn rate_limited_route_classification() {
        assert_eq!(
            is_rate_limited_route(&Method::POST, "/v1/vms/test/exec"),
            Some("exec")
        );
        assert_eq!(
            is_rate_limited_route(&Method::GET, "/v1/vms/test/exec/stream"),
            Some("exec")
        );
        assert_eq!(
            is_rate_limited_route(&Method::POST, "/v1/vms/test/files/read"),
            Some("file_read")
        );
        assert_eq!(
            is_rate_limited_route(&Method::POST, "/v1/vms/test/files/write"),
            Some("file_write")
        );
        assert_eq!(
            is_rate_limited_route(&Method::GET, "/v1/vms/test/shell"),
            Some("shell")
        );
        assert_eq!(is_rate_limited_route(&Method::GET, "/v1/vms"), None);
        assert_eq!(is_rate_limited_route(&Method::POST, "/v1/vms"), None);
    }

    #[tokio::test]
    async fn rate_limit_middleware_ignores_x_forwarded_for() {
        let _guard = policy_test_lock().lock().await;
        rate_limiter().clear();
        set_policy(ApiPolicy {
            sensitive_rate_limit_per_minute: 2,
            ..ApiPolicy::default()
        });

        let body = serde_json::json!({ "path": "/safe/ok" });
        let mk = || router(test_core());

        for xff in ["1.1.1.1", "2.2.2.2"] {
            let response = mk()
                .oneshot(
                    Request::post("/v1/vms/any/files/read")
                        .header("content-type", "application/json")
                        .header("x-forwarded-for", xff)
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "request under limit must not be rate-limited (xff={xff})"
            );
        }

        let response = mk()
            .oneshot(
                Request::post("/v1/vms/any/files/read")
                    .header("content-type", "application/json")
                    .header("x-forwarded-for", "3.3.3.3")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "spoofed x-forwarded-for must not evade the rate limiter"
        );

        rate_limiter().clear();
        set_policy(ApiPolicy::default());
    }

    /// A rate-limited client that is told nothing can only guess when to come
    /// back, and a guess is either a stall or a spin. The daemon knows, so it
    /// says so in the header the standard reserves for it.
    #[tokio::test]
    async fn rate_limited_response_says_when_to_retry() {
        let _guard = policy_test_lock().lock().await;
        rate_limiter().clear();
        set_policy(ApiPolicy {
            sensitive_rate_limit_per_minute: 1,
            ..ApiPolicy::default()
        });

        let body = serde_json::json!({ "path": "/safe/ok" });
        let request = || {
            Request::post("/v1/vms/any/files/read")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap()
        };
        let accepted = router(test_core()).oneshot(request()).await.unwrap();
        assert_ne!(accepted.status(), StatusCode::TOO_MANY_REQUESTS);

        let limited = router(test_core()).oneshot(request()).await.unwrap();

        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after = limited
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .expect("a rate-limited response carries Retry-After")
            .to_str()
            .expect("Retry-After is ASCII")
            .parse::<u64>()
            .expect("Retry-After is whole seconds");
        // The one accepted request was made moments ago and is the only thing
        // holding the slot, so it leaves the window in very nearly its full
        // width. Both bounds matter: a constant zero and a constant window
        // width are each wrong, and each would satisfy only one of them.
        assert!(
            (56..=60).contains(&retry_after),
            "the header must carry the real deadline, not a placeholder: {retry_after}"
        );

        rate_limiter().clear();
        set_policy(ApiPolicy::default());
    }

    #[test]
    fn rate_limiter_blocks_when_limit_reached() {
        let limiter = SlidingWindowRateLimiter::default();
        assert!(matches!(limiter.check("k", 2), RateLimitDecision::Allowed));
        assert!(matches!(limiter.check("k", 2), RateLimitDecision::Allowed));
        assert!(matches!(
            limiter.check("k", 2),
            RateLimitDecision::Limited { .. }
        ));
    }

    #[test]
    fn rate_limiter_zero_limit_allows_requests() {
        let limiter = SlidingWindowRateLimiter::default();
        assert!(matches!(limiter.check("k", 0), RateLimitDecision::Allowed));
        assert!(matches!(limiter.check("k", 0), RateLimitDecision::Allowed));
    }

    /// A sliding window frees capacity as its oldest event ages out, and the
    /// limiter is the only party that knows when that is. Reporting it turns a
    /// rejection into backpressure a client can act on.
    #[test]
    fn rate_limiter_reports_when_capacity_frees() {
        let limiter = SlidingWindowRateLimiter::default();
        assert!(matches!(limiter.check("k", 2), RateLimitDecision::Allowed));
        assert!(matches!(limiter.check("k", 2), RateLimitDecision::Allowed));

        let RateLimitDecision::Limited { retry_after } = limiter.check("k", 2) else {
            panic!("a third request against a limit of two must be limited");
        };

        // The two accepted events were recorded moments ago, so the oldest of
        // them leaves the window in just under its full width.
        assert!(
            retry_after <= Duration::from_secs(60),
            "never longer than the window: {retry_after:?}"
        );
        assert!(
            retry_after > Duration::from_secs(55),
            "the window has barely advanced yet: {retry_after:?}"
        );
    }

    /// A rejected request is not recorded, so retrying while limited must not
    /// push the moment capacity frees any further away.
    #[test]
    fn rate_limiter_retry_does_not_extend_the_window() {
        let limiter = SlidingWindowRateLimiter::default();
        assert!(matches!(limiter.check("k", 1), RateLimitDecision::Allowed));

        let RateLimitDecision::Limited { retry_after: first } = limiter.check("k", 1) else {
            panic!("second request against a limit of one must be limited");
        };
        let RateLimitDecision::Limited {
            retry_after: second,
        } = limiter.check("k", 1)
        else {
            panic!("a retry while still limited must stay limited");
        };

        assert!(
            second <= first,
            "the wait must shrink as the window advances, not grow: {first:?} then {second:?}"
        );
    }

    // ── tail_lines unit tests ─────────────────────────────────────────

    #[test]
    fn tail_lines_returns_last_n() {
        let content = "a\nb\nc\nd\ne\n";
        assert_eq!(tail_lines(content, 2), "d\ne\n");
        assert_eq!(tail_lines(content, 3), "c\nd\ne\n");
    }

    #[test]
    fn tail_lines_n_exceeds_line_count_returns_all() {
        let content = "a\nb\nc\n";
        assert_eq!(tail_lines(content, 100), "a\nb\nc\n");
    }

    #[test]
    fn tail_lines_zero_returns_empty() {
        let content = "a\nb\nc\n";
        assert_eq!(tail_lines(content, 0), "");
    }

    #[test]
    fn tail_lines_empty_input() {
        assert_eq!(tail_lines("", 5), "");
    }

    #[test]
    fn tail_lines_no_trailing_newline() {
        let content = "a\nb\nc";
        assert_eq!(tail_lines(content, 2), "b\nc");
    }

    #[test]
    fn tail_lines_single_line_with_newline() {
        assert_eq!(tail_lines("hello\n", 1), "hello\n");
        assert_eq!(tail_lines("hello\n", 5), "hello\n");
    }

    #[test]
    fn tail_lines_single_line_without_newline() {
        assert_eq!(tail_lines("hello", 1), "hello");
    }

    #[test]
    fn tail_lines_blank_lines_preserved() {
        let content = "a\n\nb\n\nc\n";
        // lines() yields: ["a", "", "b", "", "c"] — 5 lines
        assert_eq!(tail_lines(content, 3), "b\n\nc\n");
    }

    /// A volume held by a VM nobody is using blocks every later job, and the
    /// only way out is to destroy that VM. Naming it is not enough when the
    /// reader has to guess the command.
    #[test]
    fn a_held_volume_says_how_to_release_it() {
        let (status, body) = map_error(CoreError::VolumeAttached {
            volume: "build-cache".into(),
            vm: "job-dd1980c6".into(),
        });

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body.kind, "volume_attached");
        let hint = body.hint.as_deref().expect("a held volume carries a hint");
        assert!(
            hint.contains("husker destroy job-dd1980c6"),
            "the hint names the VM that must go: {hint}"
        );
    }

    #[test]
    fn error_mapping_variants() {
        use husker_core::AgentError;
        use std::time::Duration;

        let (status, _) = map_error(CoreError::VmNotFound("test".into()));
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = map_error(CoreError::VmAlreadyExists("test".into()));
        assert_eq!(status, StatusCode::CONFLICT);

        let (status, _) = map_error(CoreError::HostGroupNotFound("test".into()));
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = map_error(CoreError::ServiceNotFound("test".into()));
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = map_error(CoreError::ImageNotFound("test".into()));
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = map_error(CoreError::SecretNotFound("test".into()));
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = map_error(CoreError::HostGroupAlreadyExists("test".into()));
        assert_eq!(status, StatusCode::CONFLICT);

        let (status, _) = map_error(CoreError::ServiceAlreadyExists("test".into()));
        assert_eq!(status, StatusCode::CONFLICT);

        let (status, body) = map_error(CoreError::PoolTemplateOwned {
            vm: "template".into(),
            pool: "web".into(),
        });
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body.kind, "pool_template_owned");

        let (status, body) = map_error(CoreError::PoolTemplateUnavailable {
            pool: "web".into(),
            template: uuid::Uuid::nil(),
        });
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body.kind, "pool_template_unavailable");

        let (status, _) = map_error(CoreError::ImageAlreadyExists("test".into()));
        assert_eq!(status, StatusCode::CONFLICT);

        let (status, _) = map_error(CoreError::SecretAlreadyExists("test".into()));
        assert_eq!(status, StatusCode::CONFLICT);

        let (status, _) = map_error(CoreError::InvalidArgument("bad value".into()));
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _) = map_error(CoreError::Agent(AgentError::NotReady {
            timeout: Duration::from_secs(5),
            detail: String::new(),
        }));
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        let (status, _) = map_error(CoreError::Agent(AgentError::UnexpectedResponse));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

        let (status, body) = map_error(CoreError::UserdataCancelled("vm".into()));
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.kind, "userdata_cancelled");

        let (status, _) = map_error(CoreError::SecretCrypto("decrypt failed".into()));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

        let (status, _) = map_error(CoreError::Storage(
            husker_storage::StorageError::CommandFailed("x".into()),
        ));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

        let (status, _) = map_error(CoreError::State(husker_state::StateError::LockPoisoned));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

        let (status, _) = map_error(CoreError::Vmm(husker_vmm::VmmError::VmNotFound(
            uuid::Uuid::new_v4(),
        )));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

        #[cfg(feature = "linux-net")]
        {
            let (status, _) = map_error(CoreError::Network(husker_net::NetError::CommandFailed {
                cmd: "x".into(),
                message: "y".into(),
            }));
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    /// A guest that cannot read from an offset is a property of the VM's image,
    /// not of the request, so the status must not be one that invites a retry.
    /// The kind is what a client branches on to tell "rebuild the image" from
    /// "the daemon is briefly unavailable".
    #[test]
    fn map_error_reports_an_offset_a_guest_cannot_serve_as_not_implemented() {
        let (status, body) = map_error(CoreError::Agent(
            husker_core::AgentError::RangedReadUnsupported {
                offset: 1_048_576,
                required: husker_agent_proto::MIN_PROTOCOL_VERSION_FOR_RANGED_READ,
            },
        ));
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);

        let payload = body.0;
        assert_eq!(payload.kind, "guest_ranged_read_unsupported");
        assert!(
            payload.message.contains("rebuild or re-import the image"),
            "the message must name the fix: {}",
            payload.message
        );
    }

    #[test]
    fn map_agent_connect_error_falls_back_for_non_agent_errors() {
        let (status, _) = map_agent_connect_error(CoreError::VmNotFound("vm".into()));
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn map_agent_connect_error_returns_service_unavailable_with_hint() {
        let (status, body) = map_agent_connect_error(CoreError::Agent(
            husker_core::AgentError::Connection(std::io::Error::other("dial failed")),
        ));
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        let payload = body.0;
        assert_eq!(payload.kind, "agent_not_ready");
        assert_eq!(
            payload.hint.as_deref(),
            Some("retry after the VM boot sequence has completed")
        );
        assert_eq!(payload.error.as_deref(), Some(payload.message.as_str()));
        assert!(payload.message.contains("agent not ready:"));
    }

    #[test]
    fn ws_shell_start_deserializes_default_terminal_size() {
        let msg: WsShellInput = serde_json::from_str(r#"{"type":"start"}"#).unwrap();
        match msg {
            WsShellInput::Start { cols, rows, .. } => {
                assert_eq!(cols, 80);
                assert_eq!(rows, 24);
            }
            other => panic!("expected start message, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn metrics_include_build_state_and_service_gauges() {
        // Core seeded with 1 running VM (owned by "svc"), 1 stopped VM, and a
        // service "svc" with desired_instances = 2.
        let app = router(seeded_core_for_metrics());
        let response = app
            .oneshot(Request::get("/v1/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let text = response_text(response).await;
        assert!(
            text.contains(&format!(
                "husker_build_info{{version=\"{}\"}} 1",
                env!("CARGO_PKG_VERSION")
            )),
            "missing husker_build_info in:\n{text}"
        );
        assert!(
            text.contains("husker_vms_stopped 1"),
            "missing husker_vms_stopped in:\n{text}"
        );
        assert!(
            text.contains("husker_vms_failed 0"),
            "missing husker_vms_failed in:\n{text}"
        );
        assert!(
            text.contains("husker_service_desired_instances{service=\"svc\"} 2"),
            "missing husker_service_desired_instances in:\n{text}"
        );
        assert!(
            text.contains("husker_service_current_instances{service=\"svc\"} 1"),
            "missing husker_service_current_instances in:\n{text}"
        );
    }

    #[tokio::test]
    async fn metrics_include_idle_policy_series() {
        let core = test_core();
        core.idle_metrics()
            .suspended_total
            .fetch_add(2, Ordering::Relaxed);
        let app = router(core);
        let response = app
            .oneshot(Request::get("/v1/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let text = response_text(response).await;
        assert!(
            text.contains("husker_vm_suspended_total 2"),
            "missing husker_vm_suspended_total in:\n{text}"
        );
        assert!(
            text.contains("husker_vms_suspended "),
            "missing husker_vms_suspended in:\n{text}"
        );
        assert!(
            text.contains("husker_vm_auto_resumed_total{trigger=\"connect\"}"),
            "missing husker_vm_auto_resumed_total in:\n{text}"
        );
    }

    #[tokio::test]
    async fn volume_list_empty() {
        let app = router(test_core());
        let response = app
            .oneshot(Request::get("/v1/volumes").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json, serde_json::json!([]));
    }

    #[tokio::test]
    async fn volume_get_not_found() {
        let app = router(test_core());
        let response = app
            .oneshot(
                Request::get("/v1/volumes/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let json = response_json(response).await;
        assert_eq!(json["kind"], "volume_not_found");
    }

    #[tokio::test]
    async fn volume_delete_not_found() {
        let app = router(test_core());
        let response = app
            .oneshot(
                Request::delete("/v1/volumes/ghost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let json = response_json(response).await;
        assert_eq!(json["kind"], "volume_not_found");
    }

    #[tokio::test]
    async fn volume_delete_while_attached_returns_409() {
        // Insert a volume record and a VM record that references it directly into
        // state, bypassing mkfs, so this test runs everywhere.
        let state = husker_state::StateStore::open_memory().unwrap();
        let now = chrono::Utc::now();
        let vol_id = uuid::Uuid::new_v4();

        state
            .insert_volume(&husker_state::VolumeRecord {
                id: vol_id,
                name: "data".into(),
                file_path: "/tmp/data.img".into(),
                size_bytes: 1_073_741_824,
                created_at: now,
            })
            .unwrap();

        state
            .insert_vm(&husker_state::VmRecord {
                id: uuid::Uuid::new_v4(),
                name: "holder-vm".into(),
                state: VmLifecycleState::Running,
                pid: Some(42),
                vcpu_count: 1,
                mem_size_mib: 128,
                vsock_cid: 200,
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
                vmm: BackendKind::Firecracker,
                boot_mode: BootKind::DirectKernel,
                balloon: false,
                volume: Some("data".into()),
                network: NetworkMode::Nat,
                last_activity_at: now,
                suspended_at: None,
                idle_timeout_secs: None,
                suspend_ttl_secs: None,
                auto_resume: true,
                forked_from: None,
                egress_policy: None,
            })
            .unwrap();

        let core = make_core(
            state,
            husker_storage::StorageConfig {
                data_dir: std::path::PathBuf::from("/tmp/husker-test"),
                state_dir: std::path::PathBuf::from("/tmp/husker-test"),
            },
            std::path::PathBuf::from("/tmp/husker-test/run"),
        );
        let app = router(core);

        let response = app
            .oneshot(
                Request::delete("/v1/volumes/data")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // delete while attached returns 409 (Conflict)
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let json = response_json(response).await;
        assert_eq!(json["kind"], "volume_attached");
    }

    #[test]
    fn mount_host_path_allowlist_enforcement() {
        let allow = vec!["/srv".to_string(), "/data/shared".to_string()];

        // Exact match on an allowlist prefix.
        assert!(is_allowed_host_path("/srv", &allow));
        // Path under an allowlist prefix.
        assert!(is_allowed_host_path("/srv/work", &allow));
        assert!(is_allowed_host_path("/data/shared/project", &allow));
        // Not in the allowlist.
        assert!(!is_allowed_host_path("/etc/passwd", &allow));
        assert!(!is_allowed_host_path("/data", &allow));

        // Empty allowlist must deny all paths.
        let empty: Vec<String> = Vec::new();
        assert!(!is_allowed_host_path("/srv/work", &empty));
        assert!(!is_allowed_host_path("/", &empty));

        // Relative and parent-traversal paths are rejected regardless of allowlist.
        assert!(!is_allowed_host_path("relative/path", &allow));
        assert!(!is_allowed_host_path("/srv/../etc", &allow));
    }
}
