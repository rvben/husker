//! HTTP API surface for husker, including OpenAPI docs, auth, policy, and shell/log endpoints.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Component, Path as StdPath};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use axum::Json;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::HeaderValue;
use axum::http::Method;
use axum::http::StatusCode;
use axum::response::IntoResponse;
#[cfg(feature = "linux-net")]
use axum::routing::delete;
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use utoipa::OpenApi;
use utoipa::ToSchema;

use husker_core::{
    CoreError, CreateHostGroupRequest, CreateSecretRequest, CreateServiceRequest,
    CreateSnapshotRequest, CreateVmRequest, ExportImageRequest, ExportImageResult, HostGroupRecord,
    HuskerCore, ImageRecord, ImportImageRequest, RestoreSnapshotRequest, RotateSecretRequest,
    SecretMetadata, ServiceRecord, ShellEvent, SnapshotRecord, VmRecord,
};
use husker_vmm::VmmBackend;

type AppState<B> = Arc<HuskerCore<B>>;

// ── Response Types ────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct VmResponse {
    pub id: String,
    pub name: String,
    pub state: String,
    pub pid: Option<u32>,
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    pub vsock_cid: u32,
    pub host_ip: Option<String>,
    pub guest_ip: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userdata_status: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct HostGroupResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServiceResponse {
    pub id: String,
    pub name: String,
    pub host_group_id: Option<String>,
    pub desired_instances: u32,
    pub current_instances: u32,
    pub image: Option<String>,
    pub rootfs_path: String,
    pub kernel_path: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServiceInstance {
    pub name: String,
    pub ordinal: u32,
    pub state: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServiceDetailResponse {
    #[serde(flatten)]
    pub service: ServiceResponse,
    pub instances: Vec<ServiceInstance>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ReconcileFailure {
    pub instance: String,
    pub error: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ReconcileOutcomeResponse {
    pub created: Vec<String>,
    pub destroyed: Vec<String>,
    pub failed: Vec<ReconcileFailure>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServiceMutationResponse {
    pub service: ServiceResponse,
    pub outcome: ReconcileOutcomeResponse,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServiceDeleteResponse {
    pub name: String,
    pub outcome: ReconcileOutcomeResponse,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SnapshotResponse {
    pub id: String,
    pub name: String,
    pub source_vm_name: String,
    pub file_path: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ImageResponse {
    pub id: String,
    pub name: String,
    pub source_path: String,
    pub file_path: String,
    pub format: String,
    pub size_bytes: u64,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ExportImageResponse {
    pub name: String,
    pub destination_path: String,
    pub size_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SecretResponse {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RevealedSecretResponse {
    pub name: String,
    pub value: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ScaleServiceRequest {
    pub desired_instances: u32,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    // Backward-compatible alias kept for existing clients/tests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiPolicy {
    pub max_request_bytes: usize,
    pub max_file_read_bytes: usize,
    pub max_file_write_bytes: usize,
    pub sensitive_rate_limit_per_minute: u32,
    pub allowed_read_paths: Vec<String>,
    pub allowed_write_paths: Vec<String>,
    pub exec_timeout_secs: u64,
    pub exec_allowlist: Vec<String>,
    pub exec_denylist: Vec<String>,
    pub exec_env_allowlist: Vec<String>,
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
            exec_allowlist: Vec::new(),
            exec_denylist: Vec::new(),
            exec_env_allowlist: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct ApiMetrics {
    start: Instant,
    requests_total: AtomicU64,
    errors_total: AtomicU64,
    rate_limited_total: AtomicU64,
    exec_total: AtomicU64,
    file_reads_total: AtomicU64,
    file_writes_total: AtomicU64,
    shell_sessions_total: AtomicU64,
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

#[derive(Debug, Default)]
struct SlidingWindowRateLimiter {
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

    fn allow(&self, key: &str, limit_per_minute: u32) -> bool {
        if limit_per_minute == 0 {
            return true;
        }
        let mut events = self.events.lock().expect("rate limiter lock poisoned");
        let now = Instant::now();
        let window_start = now - Duration::from_secs(60);
        let queue = events.entry(key.to_string()).or_default();
        while queue.front().is_some_and(|t| *t < window_start) {
            queue.pop_front();
        }
        if queue.len() >= limit_per_minute as usize {
            return false;
        }
        queue.push_back(now);
        true
    }
}

static API_POLICY: OnceLock<RwLock<ApiPolicy>> = OnceLock::new();
static API_METRICS: OnceLock<ApiMetrics> = OnceLock::new();
static RATE_LIMITER: OnceLock<SlidingWindowRateLimiter> = OnceLock::new();
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

// ── Exec Types ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct ExecRequest {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub working_dir: Option<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Seconds to wait for the guest agent to become reachable. Defaults to
    /// `DEFAULT_EXEC_CONNECT_TIMEOUT_SECS` and is clamped to a sane range.
    pub connect_timeout_secs: Option<u64>,
}

/// Default agent-readiness wait for exec when the caller does not specify one.
const DEFAULT_EXEC_CONNECT_TIMEOUT_SECS: u64 = 30;
/// Upper bound so a caller cannot pin an exec connection open indefinitely.
const MAX_EXEC_CONNECT_TIMEOUT_SECS: u64 = 600;

/// Resolve the exec agent-connect timeout: default when unset, clamped to
/// `[1, MAX_EXEC_CONNECT_TIMEOUT_SECS]` otherwise.
fn resolve_exec_connect_timeout(requested: Option<u64>) -> Duration {
    let secs = requested
        .unwrap_or(DEFAULT_EXEC_CONNECT_TIMEOUT_SECS)
        .clamp(1, MAX_EXEC_CONNECT_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ExecResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

// ── File Types ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct ReadFileRequest {
    pub path: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReadFileResponse {
    pub data: String,
    pub size: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct WriteFileRequest {
    pub path: String,
    /// Base64-encoded file data.
    pub data: String,
    pub mode: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WriteFileResponse {
    pub bytes_written: u64,
}

// ── Port Forward Types ────────────────────────────────────────────────

#[cfg(feature = "linux-net")]
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddPortForwardRequest {
    pub host_port: u16,
    pub guest_port: u16,
}

#[cfg(feature = "linux-net")]
#[derive(Debug, Serialize, ToSchema)]
pub struct PortForwardResponse {
    pub host_port: u16,
    pub guest_port: u16,
    pub protocol: String,
    pub created_at: String,
}

// ── WebSocket Shell Types ─────────────────────────────────────────────

/// Messages sent by the client to the server over the shell WebSocket.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsShellInput {
    Start {
        command: Option<String>,
        #[serde(default = "default_cols")]
        cols: u16,
        #[serde(default = "default_rows")]
        rows: u16,
    },
    Data {
        data: String,
    },
    Resize {
        cols: u16,
        rows: u16,
    },
}

fn default_cols() -> u16 {
    80
}
fn default_rows() -> u16 {
    24
}

// ── Logs Types ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct LogsQuery {
    #[serde(default)]
    pub follow: bool,
    pub tail: Option<u64>,
    /// Serve the captured userdata script output instead of the serial console.
    #[serde(default)]
    pub userdata: bool,
    /// Log source: "serial" (default), "boot", or "userdata". Takes precedence
    /// over `userdata` when set.
    #[schema(example = "serial")]
    pub source: Option<String>,
}

/// Messages sent by the server to the client over the shell WebSocket.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsShellOutput {
    Started,
    Data { data: String },
    Exit { exit_code: i32 },
    Error { message: String },
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
        list_host_groups,
        create_host_group,
        get_host_group,
        delete_host_group,
        list_services,
        create_service,
        get_service,
        delete_service,
        scale_service,
        list_images,
        import_image,
        get_image,
        delete_image,
        export_image,
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
        destroy_vm,
        exec_vm,
        read_file_handler,
        write_file_handler,
        shell_ws,
        get_logs,
        metrics_handler,
    ),
    components(schemas(
        VmResponse,
        HostGroupResponse,
        ServiceResponse,
        ServiceInstance,
        ServiceDetailResponse,
        ServiceMutationResponse,
        ServiceDeleteResponse,
        ReconcileOutcomeResponse,
        ReconcileFailure,
        SnapshotResponse,
        ImageResponse,
        ExportImageResponse,
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
        LogsQuery,
        WsShellInput,
        WsShellOutput,
        CreateHostGroupRequest,
        CreateServiceRequest,
        CreateSnapshotRequest,
        RestoreSnapshotRequest,
        ImportImageRequest,
        ExportImageRequest,
        CreateSecretRequest,
        RotateSecretRequest,
        ScaleServiceRequest,
        CreateVmRequest,
    )),
    tags(
        (name = "vms", description = "VM lifecycle management"),
        (name = "host_groups", description = "Host group management"),
        (name = "services", description = "Service model resources"),
        (name = "images", description = "Image catalog resources"),
        (name = "secrets", description = "Encrypted secret resources"),
        (name = "snapshots", description = "Snapshot lifecycle resources"),
        (name = "exec", description = "Command execution in VMs"),
        (name = "files", description = "File transfer to/from VMs"),
        (name = "shell", description = "Interactive shell sessions"),
        (name = "logs", description = "Serial console output"),
        (name = "ports", description = "Port forwarding (Linux only)"),
        (name = "health", description = "Service health")
    )
)]
struct ApiDoc;

#[cfg(feature = "linux-net")]
#[derive(OpenApi)]
#[openapi(
    paths(
        add_port_forward_handler,
        list_port_forwards_handler,
        remove_port_forward_handler,
    ),
    components(schemas(AddPortForwardRequest, PortForwardResponse,))
)]
struct PortForwardApiDoc;

fn policy_lock() -> &'static RwLock<ApiPolicy> {
    API_POLICY.get_or_init(|| RwLock::new(ApiPolicy::default()))
}

fn metrics() -> &'static ApiMetrics {
    API_METRICS.get_or_init(ApiMetrics::new)
}

fn rate_limiter() -> &'static SlidingWindowRateLimiter {
    RATE_LIMITER.get_or_init(SlidingWindowRateLimiter::default)
}

fn current_policy() -> ApiPolicy {
    policy_lock()
        .read()
        .expect("api policy lock poisoned")
        .clone()
}

pub fn set_policy(policy: ApiPolicy) {
    *policy_lock().write().expect("api policy lock poisoned") = policy;
}

fn error_response(code: &str, message: impl Into<String>) -> Json<ErrorResponse> {
    let message = message.into();
    Json(ErrorResponse {
        code: code.to_string(),
        message: message.clone(),
        hint: None,
        details: None,
        error: Some(message),
    })
}

fn error_response_with_hint(
    code: &str,
    message: impl Into<String>,
    hint: impl Into<String>,
) -> Json<ErrorResponse> {
    let message = message.into();
    Json(ErrorResponse {
        code: code.to_string(),
        message: message.clone(),
        hint: Some(hint.into()),
        details: None,
        error: Some(message),
    })
}

fn normalize_guest_path(path: &str) -> Option<String> {
    if !path.starts_with('/') {
        return None;
    }
    let mut out: Vec<&str> = Vec::new();
    for comp in StdPath::new(path).components() {
        match comp {
            Component::RootDir => {}
            Component::Normal(seg) => out.push(seg.to_str()?),
            Component::CurDir => {}
            Component::ParentDir => return None,
            Component::Prefix(_) => return None,
        }
    }
    Some(format!("/{}", out.join("/")))
}

fn is_allowed_guest_path(path: &str, allowlist: &[String]) -> bool {
    let Some(normalized) = normalize_guest_path(path) else {
        return false;
    };
    if allowlist.is_empty() {
        return true;
    }
    allowlist.iter().any(|prefix| {
        let Some(p) = normalize_guest_path(prefix) else {
            return false;
        };
        normalized == p || normalized.starts_with(&(p + "/"))
    })
}

fn exec_command_allowed(command: &str, policy: &ApiPolicy) -> bool {
    if policy.exec_denylist.iter().any(|c| c == command) {
        return false;
    }
    if policy.exec_allowlist.is_empty() {
        return true;
    }
    policy.exec_allowlist.iter().any(|c| c == command)
}

fn exec_env_allowed(env: &HashMap<String, String>, policy: &ApiPolicy) -> bool {
    if policy.exec_env_allowlist.is_empty() {
        return true;
    }
    env.keys()
        .all(|k| policy.exec_env_allowlist.iter().any(|allowed| allowed == k))
}

fn is_rate_limited_route(method: &Method, path: &str) -> Option<&'static str> {
    if *method == Method::POST && path.ends_with("/exec") {
        return Some("exec");
    }
    if *method == Method::POST && path.ends_with("/files/read") {
        return Some("file_read");
    }
    if *method == Method::POST && path.ends_with("/files/write") {
        return Some("file_write");
    }
    if *method == Method::GET && path.ends_with("/shell") {
        return Some("shell");
    }
    None
}

// ── Router ────────────────────────────────────────────────────────────

/// Build the API router.
pub fn router<B: VmmBackend + 'static>(core: Arc<HuskerCore<B>>) -> Router {
    router_with_auth(core, None)
}

/// Build the API router with optional bearer token authentication.
///
/// When `auth_token` is set, mutating endpoints and interactive shell access
/// require `Authorization: Bearer <token>`.
pub fn router_with_auth<B: VmmBackend + 'static>(
    core: Arc<HuskerCore<B>>,
    auth_token: Option<String>,
) -> Router {
    let policy = current_policy();
    let router = Router::new()
        .route(
            "/v1/host-groups",
            get(list_host_groups::<B>).post(create_host_group::<B>),
        )
        .route(
            "/v1/host-groups/{name}",
            get(get_host_group::<B>).delete(delete_host_group::<B>),
        )
        .route(
            "/v1/services",
            get(list_services::<B>).post(create_service::<B>),
        )
        .route(
            "/v1/services/{name}",
            get(get_service::<B>).delete(delete_service::<B>),
        )
        .route("/v1/services/{name}/scale", post(scale_service::<B>))
        .route("/v1/images", get(list_images::<B>).post(import_image::<B>))
        .route(
            "/v1/images/{name}",
            get(get_image::<B>).delete(delete_image::<B>),
        )
        .route("/v1/images/{name}/export", post(export_image::<B>))
        .route(
            "/v1/secrets",
            get(list_secrets::<B>).post(create_secret::<B>),
        )
        .route(
            "/v1/secrets/{name}",
            get(get_secret::<B>).delete(delete_secret::<B>),
        )
        .route("/v1/secrets/{name}/reveal", get(reveal_secret::<B>))
        .route("/v1/secrets/{name}/rotate", post(rotate_secret::<B>))
        .route(
            "/v1/snapshots",
            get(list_snapshots::<B>).post(create_snapshot::<B>),
        )
        .route(
            "/v1/snapshots/{name}",
            get(get_snapshot::<B>).delete(delete_snapshot::<B>),
        )
        .route("/v1/snapshots/{name}/restore", post(restore_snapshot::<B>))
        .route("/v1/vms", get(list_vms::<B>).post(create_vm::<B>))
        .route("/v1/vms/{name}", get(get_vm::<B>).delete(destroy_vm::<B>))
        .route("/v1/vms/{name}/stop", post(stop_vm::<B>))
        .route("/v1/vms/{name}/pause", post(pause_vm::<B>))
        .route("/v1/vms/{name}/resume", post(resume_vm::<B>))
        .route("/v1/vms/{name}/exec", post(exec_vm::<B>))
        .route("/v1/vms/{name}/files/read", post(read_file_handler::<B>))
        .route("/v1/vms/{name}/files/write", post(write_file_handler::<B>))
        .route("/v1/vms/{name}/shell", get(shell_ws::<B>))
        .route("/v1/vms/{name}/logs", get(get_logs::<B>))
        .route("/v1/metrics", get(metrics_handler::<B>));

    #[cfg(feature = "linux-net")]
    let router = router
        .route(
            "/v1/vms/{name}/ports",
            get(list_port_forwards_handler::<B>).post(add_port_forward_handler::<B>),
        )
        .route(
            "/v1/vms/{name}/ports/{host_port}",
            delete(remove_port_forward_handler::<B>),
        );

    #[allow(unused_mut)]
    let mut openapi = ApiDoc::openapi();

    #[cfg(feature = "linux-net")]
    {
        let pf_doc = PortForwardApiDoc::openapi();
        openapi.merge(pf_doc);
    }

    let router = router
        .route("/v1/health", get(health::<B>))
        .merge(utoipa_swagger_ui::SwaggerUi::new("/docs").url("/api-docs/openapi.json", openapi));

    let router = if let Some(token) = auth_token {
        let expected = Arc::new(format!("Bearer {token}"));
        router.layer(axum::middleware::from_fn_with_state(
            expected,
            auth_middleware,
        ))
    } else {
        router
    };

    router
        .layer(DefaultBodyLimit::max(policy.max_request_bytes))
        .layer(axum::middleware::from_fn(rate_limit_middleware))
        .layer(axum::middleware::from_fn(trace_request))
        .with_state(core)
}

/// Start the API server with graceful shutdown on SIGINT/SIGTERM.
pub async fn serve<B: VmmBackend + 'static>(
    core: Arc<HuskerCore<B>>,
    addr: SocketAddr,
) -> std::io::Result<()> {
    serve_with_auth(core, addr, None).await
}

/// Start the API server with optional bearer token authentication.
pub async fn serve_with_auth<B: VmmBackend + 'static>(
    core: Arc<HuskerCore<B>>,
    addr: SocketAddr,
    auth_token: Option<String>,
) -> std::io::Result<()> {
    let app = router_with_auth(core, auth_token);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "husker daemon listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
}

/// Wait for a shutdown signal (SIGINT or SIGTERM).
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    info!("shutdown signal received, draining connections");
}

// ── Middleware ─────────────────────────────────────────────────────────

async fn trace_request(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    metrics().requests_total.fetch_add(1, Ordering::Relaxed);
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            let n = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            format!("req-{n}")
        });
    if let Ok(val) = HeaderValue::from_str(&request_id) {
        req.headers_mut().insert("x-request-id", val);
    }
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let start = std::time::Instant::now();
    let mut response = next.run(req).await;
    if response.status().is_client_error() || response.status().is_server_error() {
        metrics().errors_total.fetch_add(1, Ordering::Relaxed);
    }
    if let Ok(val) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", val);
    }
    info!(
        request_id = %request_id,
        %method,
        %path,
        status = response.status().as_u16(),
        elapsed_ms = start.elapsed().as_millis() as u64,
    );
    response
}

async fn rate_limit_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let policy = current_policy();
    if let Some(kind) = is_rate_limited_route(req.method(), req.uri().path()) {
        let client = req
            .extensions()
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip().to_string())
            .unwrap_or_else(|| "unknown".into());
        let key = format!("{kind}:{client}");
        if !rate_limiter().allow(&key, policy.sensitive_rate_limit_per_minute) {
            metrics().rate_limited_total.fetch_add(1, Ordering::Relaxed);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                error_response_with_hint(
                    "rate_limited",
                    "too many requests to sensitive endpoint",
                    "retry after a short delay",
                ),
            )
                .into_response();
        }
    }
    next.run(req).await
}

fn is_protected_route(method: &Method, path: &str) -> bool {
    if path.starts_with("/v1/secrets") {
        return true;
    }
    if path == "/v1/metrics" {
        return true;
    }

    if !(path.starts_with("/v1/vms")
        || path.starts_with("/v1/services")
        || path.starts_with("/v1/host-groups")
        || path.starts_with("/v1/images")
        || path.starts_with("/v1/snapshots"))
    {
        return false;
    }
    if *method != Method::GET {
        return true;
    }
    path.ends_with("/shell") || path.ends_with("/logs")
}

async fn auth_middleware(
    State(expected): State<Arc<String>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if !is_protected_route(req.method(), req.uri().path()) {
        return next.run(req).await;
    }

    let provided = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());
    if provided == Some(expected.as_str()) {
        return next.run(req).await;
    }

    (
        StatusCode::UNAUTHORIZED,
        error_response_with_hint(
            "unauthorized",
            "unauthorized: missing or invalid bearer token",
            "set Authorization: Bearer <token>",
        ),
    )
        .into_response()
}

// ── Handlers ──────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/health",
    tag = "health",
    responses(
        (status = 200, description = "Service health status", body = HealthResponse)
    )
)]
async fn health<B: VmmBackend + 'static>(State(core): State<AppState<B>>) -> Json<HealthResponse> {
    let (total, running, state_db_ok) = match core.list_vms() {
        Ok(vms) => {
            let total = vms.len() as u64;
            let running = vms.iter().filter(|v| v.state == "running").count() as u64;
            (total, running, true)
        }
        Err(_) => (0, 0, false),
    };
    let mut checks = HashMap::new();
    checks.insert(
        "state_db".into(),
        if state_db_ok {
            "ok".into()
        } else {
            "degraded".into()
        },
    );
    checks.insert(
        "vmm_backend".into(),
        if state_db_ok {
            "ok".into()
        } else {
            "degraded".into()
        },
    );
    #[cfg(feature = "linux-net")]
    checks.insert("network_backend".into(), "ok".into());
    #[cfg(not(feature = "linux-net"))]
    checks.insert("network_backend".into(), "n/a".into());
    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        vms: VmCounts { total, running },
        checks,
        uptime_seconds: metrics().start.elapsed().as_secs(),
    })
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub vms: VmCounts,
    pub checks: HashMap<String, String>,
    pub uptime_seconds: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VmCounts {
    pub total: u64,
    pub running: u64,
}

#[utoipa::path(
    get,
    path = "/v1/metrics",
    tag = "health",
    responses(
        (status = 200, description = "Prometheus metrics", content_type = "text/plain")
    )
)]
async fn metrics_handler<B: VmmBackend + 'static>(State(core): State<AppState<B>>) -> String {
    let (total, running) = core
        .list_vms()
        .map(|vms| {
            (
                vms.len() as u64,
                vms.iter().filter(|vm| vm.state == "running").count() as u64,
            )
        })
        .unwrap_or((0, 0));

    let m = metrics();
    format!(
        "# TYPE husker_api_requests_total counter\n\
husker_api_requests_total {}\n\
# TYPE husker_api_errors_total counter\n\
husker_api_errors_total {}\n\
# TYPE husker_api_rate_limited_total counter\n\
husker_api_rate_limited_total {}\n\
# TYPE husker_exec_total counter\n\
husker_exec_total {}\n\
# TYPE husker_file_reads_total counter\n\
husker_file_reads_total {}\n\
# TYPE husker_file_writes_total counter\n\
husker_file_writes_total {}\n\
# TYPE husker_shell_sessions_total counter\n\
husker_shell_sessions_total {}\n\
# TYPE husker_vms_total gauge\n\
husker_vms_total {}\n\
# TYPE husker_vms_running gauge\n\
husker_vms_running {}\n\
# TYPE husker_api_uptime_seconds gauge\n\
husker_api_uptime_seconds {}\n",
        m.requests_total.load(Ordering::Relaxed),
        m.errors_total.load(Ordering::Relaxed),
        m.rate_limited_total.load(Ordering::Relaxed),
        m.exec_total.load(Ordering::Relaxed),
        m.file_reads_total.load(Ordering::Relaxed),
        m.file_writes_total.load(Ordering::Relaxed),
        m.shell_sessions_total.load(Ordering::Relaxed),
        total,
        running,
        m.start.elapsed().as_secs(),
    )
}

#[utoipa::path(
    get,
    path = "/v1/host-groups",
    tag = "host_groups",
    responses(
        (status = 200, description = "List of host groups", body = Vec<HostGroupResponse>),
        (status = 500, description = "Internal error", body = ErrorResponse)
    )
)]
async fn list_host_groups<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
) -> Result<Json<Vec<HostGroupResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let groups = core.list_host_groups().map_err(map_error)?;
    Ok(Json(
        groups
            .into_iter()
            .map(host_group_to_response)
            .collect::<Vec<_>>(),
    ))
}

#[utoipa::path(
    post,
    path = "/v1/host-groups",
    tag = "host_groups",
    request_body = CreateHostGroupRequest,
    responses(
        (status = 201, description = "Host group created", body = HostGroupResponse),
        (status = 409, description = "Host group already exists", body = ErrorResponse)
    )
)]
async fn create_host_group<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Json(req): Json<CreateHostGroupRequest>,
) -> Result<(StatusCode, Json<HostGroupResponse>), (StatusCode, Json<ErrorResponse>)> {
    let group = core.create_host_group(req).map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(host_group_to_response(group))))
}

#[utoipa::path(
    get,
    path = "/v1/host-groups/{name}",
    tag = "host_groups",
    params(("name" = String, Path, description = "Host group name")),
    responses(
        (status = 200, description = "Host group details", body = HostGroupResponse),
        (status = 404, description = "Host group not found", body = ErrorResponse)
    )
)]
async fn get_host_group<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<Json<HostGroupResponse>, (StatusCode, Json<ErrorResponse>)> {
    let group = core.get_host_group(&name).map_err(map_error)?;
    Ok(Json(host_group_to_response(group)))
}

#[utoipa::path(
    delete,
    path = "/v1/host-groups/{name}",
    tag = "host_groups",
    params(("name" = String, Path, description = "Host group name")),
    responses(
        (status = 204, description = "Host group deleted"),
        (status = 404, description = "Host group not found", body = ErrorResponse)
    )
)]
async fn delete_host_group<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    core.delete_host_group(&name).map_err(map_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/v1/services",
    tag = "services",
    responses(
        (status = 200, description = "List of services", body = Vec<ServiceResponse>),
        (status = 500, description = "Internal error", body = ErrorResponse)
    )
)]
async fn list_services<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
) -> Result<Json<Vec<ServiceResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let services = core.list_services().map_err(map_error)?;
    Ok(Json(
        services
            .into_iter()
            .map(|s| service_to_response(&core, s))
            .collect::<Vec<_>>(),
    ))
}

#[utoipa::path(
    post,
    path = "/v1/services",
    tag = "services",
    request_body = CreateServiceRequest,
    responses(
        (status = 201, description = "Service created", body = ServiceMutationResponse),
        (status = 404, description = "Referenced host group not found", body = ErrorResponse),
        (status = 409, description = "Service already exists", body = ErrorResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse)
    )
)]
async fn create_service<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Json(req): Json<CreateServiceRequest>,
) -> Result<(StatusCode, Json<ServiceMutationResponse>), (StatusCode, Json<ErrorResponse>)> {
    let (service, outcome) = core.create_service(req).await.map_err(map_error)?;
    Ok((
        StatusCode::CREATED,
        Json(ServiceMutationResponse {
            service: service_to_response(&core, service),
            outcome: outcome_to_response(outcome),
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/v1/services/{name}",
    tag = "services",
    params(("name" = String, Path, description = "Service name")),
    responses(
        (status = 200, description = "Service details", body = ServiceDetailResponse),
        (status = 404, description = "Service not found", body = ErrorResponse)
    )
)]
async fn get_service<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<Json<ServiceDetailResponse>, (StatusCode, Json<ErrorResponse>)> {
    let service = core.get_service(&name).map_err(map_error)?;
    let id = service.id;
    let service_resp = service_to_response(&core, service);
    let mut instances: Vec<ServiceInstance> = core
        .list_vms_for_service(id)
        .map_err(map_error)?
        .into_iter()
        .filter_map(|v| {
            v.service_ordinal.map(|ord| ServiceInstance {
                name: v.name,
                ordinal: ord,
                state: v.state,
            })
        })
        .collect();
    instances.sort_by_key(|i| i.ordinal);
    Ok(Json(ServiceDetailResponse {
        service: service_resp,
        instances,
    }))
}

#[utoipa::path(
    delete,
    path = "/v1/services/{name}",
    tag = "services",
    params(("name" = String, Path, description = "Service name")),
    responses(
        (status = 200, description = "Service deleted", body = ServiceDeleteResponse),
        (status = 404, description = "Service not found", body = ErrorResponse)
    )
)]
async fn delete_service<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<Json<ServiceDeleteResponse>, (StatusCode, Json<ErrorResponse>)> {
    let outcome = core.delete_service(&name).await.map_err(map_error)?;
    Ok(Json(ServiceDeleteResponse {
        name,
        outcome: outcome_to_response(outcome),
    }))
}

#[utoipa::path(
    post,
    path = "/v1/services/{name}/scale",
    tag = "services",
    params(("name" = String, Path, description = "Service name")),
    request_body = ScaleServiceRequest,
    responses(
        (status = 200, description = "Service scaled", body = ServiceMutationResponse),
        (status = 404, description = "Service not found", body = ErrorResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse)
    )
)]
async fn scale_service<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
    Json(req): Json<ScaleServiceRequest>,
) -> Result<Json<ServiceMutationResponse>, (StatusCode, Json<ErrorResponse>)> {
    let (service, outcome) = core
        .scale_service(&name, req.desired_instances)
        .await
        .map_err(map_error)?;
    Ok(Json(ServiceMutationResponse {
        service: service_to_response(&core, service),
        outcome: outcome_to_response(outcome),
    }))
}

#[utoipa::path(
    get,
    path = "/v1/images",
    tag = "images",
    responses(
        (status = 200, description = "List of images", body = Vec<ImageResponse>),
        (status = 500, description = "Internal error", body = ErrorResponse)
    )
)]
async fn list_images<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
) -> Result<Json<Vec<ImageResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let images = core.list_images().map_err(map_error)?;
    Ok(Json(
        images
            .into_iter()
            .map(image_to_response)
            .collect::<Vec<_>>(),
    ))
}

#[utoipa::path(
    post,
    path = "/v1/images",
    tag = "images",
    request_body = ImportImageRequest,
    responses(
        (status = 201, description = "Image imported", body = ImageResponse),
        (status = 409, description = "Image already exists", body = ErrorResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse)
    )
)]
async fn import_image<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Json(req): Json<ImportImageRequest>,
) -> Result<(StatusCode, Json<ImageResponse>), (StatusCode, Json<ErrorResponse>)> {
    let image = core.import_image(req).await.map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(image_to_response(image))))
}

#[utoipa::path(
    get,
    path = "/v1/images/{name}",
    tag = "images",
    params(("name" = String, Path, description = "Image name")),
    responses(
        (status = 200, description = "Image details", body = ImageResponse),
        (status = 404, description = "Image not found", body = ErrorResponse)
    )
)]
async fn get_image<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<Json<ImageResponse>, (StatusCode, Json<ErrorResponse>)> {
    let image = core.get_image(&name).map_err(map_error)?;
    Ok(Json(image_to_response(image)))
}

#[utoipa::path(
    delete,
    path = "/v1/images/{name}",
    tag = "images",
    params(("name" = String, Path, description = "Image name")),
    responses(
        (status = 204, description = "Image deleted"),
        (status = 404, description = "Image not found", body = ErrorResponse)
    )
)]
async fn delete_image<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    core.delete_image(&name).await.map_err(map_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/v1/images/{name}/export",
    tag = "images",
    params(("name" = String, Path, description = "Image name")),
    request_body = ExportImageRequest,
    responses(
        (status = 201, description = "Image exported", body = ExportImageResponse),
        (status = 404, description = "Image not found", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    )
)]
async fn export_image<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
    Json(req): Json<ExportImageRequest>,
) -> Result<(StatusCode, Json<ExportImageResponse>), (StatusCode, Json<ErrorResponse>)> {
    let result = core.export_image(&name, req).await.map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(export_result_to_response(result))))
}

#[utoipa::path(
    get,
    path = "/v1/secrets",
    tag = "secrets",
    responses(
        (status = 200, description = "List of secret metadata", body = Vec<SecretResponse>),
        (status = 500, description = "Internal error", body = ErrorResponse)
    )
)]
async fn list_secrets<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
) -> Result<Json<Vec<SecretResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let secrets = core.list_secrets().map_err(map_error)?;
    Ok(Json(
        secrets
            .into_iter()
            .map(secret_to_response)
            .collect::<Vec<_>>(),
    ))
}

#[utoipa::path(
    post,
    path = "/v1/secrets",
    tag = "secrets",
    request_body = CreateSecretRequest,
    responses(
        (status = 201, description = "Secret created", body = SecretResponse),
        (status = 409, description = "Secret already exists", body = ErrorResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse)
    )
)]
async fn create_secret<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Json(req): Json<CreateSecretRequest>,
) -> Result<(StatusCode, Json<SecretResponse>), (StatusCode, Json<ErrorResponse>)> {
    let secret = core.create_secret(req).map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(secret_to_response(secret))))
}

#[utoipa::path(
    get,
    path = "/v1/secrets/{name}",
    tag = "secrets",
    params(("name" = String, Path, description = "Secret name")),
    responses(
        (status = 200, description = "Secret metadata", body = SecretResponse),
        (status = 404, description = "Secret not found", body = ErrorResponse)
    )
)]
async fn get_secret<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<Json<SecretResponse>, (StatusCode, Json<ErrorResponse>)> {
    let secret = core.get_secret(&name).map_err(map_error)?;
    Ok(Json(secret_to_response(secret)))
}

#[utoipa::path(
    get,
    path = "/v1/secrets/{name}/reveal",
    tag = "secrets",
    params(("name" = String, Path, description = "Secret name")),
    responses(
        (status = 200, description = "Revealed secret value", body = RevealedSecretResponse),
        (status = 404, description = "Secret not found", body = ErrorResponse),
        (status = 500, description = "Decryption error", body = ErrorResponse)
    )
)]
async fn reveal_secret<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<Json<RevealedSecretResponse>, (StatusCode, Json<ErrorResponse>)> {
    let revealed = core.reveal_secret(&name).map_err(map_error)?;
    Ok(Json(RevealedSecretResponse {
        name: revealed.name,
        value: revealed.value,
        updated_at: revealed.updated_at.to_rfc3339(),
    }))
}

#[utoipa::path(
    post,
    path = "/v1/secrets/{name}/rotate",
    tag = "secrets",
    params(("name" = String, Path, description = "Secret name")),
    request_body = RotateSecretRequest,
    responses(
        (status = 200, description = "Secret rotated", body = SecretResponse),
        (status = 404, description = "Secret not found", body = ErrorResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse)
    )
)]
async fn rotate_secret<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
    Json(req): Json<RotateSecretRequest>,
) -> Result<Json<SecretResponse>, (StatusCode, Json<ErrorResponse>)> {
    let secret = core.rotate_secret(&name, req).map_err(map_error)?;
    Ok(Json(secret_to_response(secret)))
}

#[utoipa::path(
    delete,
    path = "/v1/secrets/{name}",
    tag = "secrets",
    params(("name" = String, Path, description = "Secret name")),
    responses(
        (status = 204, description = "Secret deleted"),
        (status = 404, description = "Secret not found", body = ErrorResponse)
    )
)]
async fn delete_secret<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    core.delete_secret(&name).map_err(map_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/v1/snapshots",
    tag = "snapshots",
    responses(
        (status = 200, description = "List of snapshots", body = Vec<SnapshotResponse>),
        (status = 500, description = "Internal error", body = ErrorResponse)
    )
)]
async fn list_snapshots<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
) -> Result<Json<Vec<SnapshotResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let snapshots = core.list_snapshots().map_err(map_error)?;
    Ok(Json(
        snapshots
            .into_iter()
            .map(snapshot_to_response)
            .collect::<Vec<_>>(),
    ))
}

#[utoipa::path(
    post,
    path = "/v1/snapshots",
    tag = "snapshots",
    request_body = CreateSnapshotRequest,
    responses(
        (status = 201, description = "Snapshot created", body = SnapshotResponse),
        (status = 404, description = "VM not found", body = ErrorResponse),
        (status = 409, description = "Snapshot already exists", body = ErrorResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse)
    )
)]
async fn create_snapshot<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Json(req): Json<CreateSnapshotRequest>,
) -> Result<(StatusCode, Json<SnapshotResponse>), (StatusCode, Json<ErrorResponse>)> {
    let snapshot = core.create_snapshot(req).await.map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(snapshot_to_response(snapshot))))
}

#[utoipa::path(
    get,
    path = "/v1/snapshots/{name}",
    tag = "snapshots",
    params(("name" = String, Path, description = "Snapshot name")),
    responses(
        (status = 200, description = "Snapshot details", body = SnapshotResponse),
        (status = 404, description = "Snapshot not found", body = ErrorResponse)
    )
)]
async fn get_snapshot<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<Json<SnapshotResponse>, (StatusCode, Json<ErrorResponse>)> {
    let snapshot = core.get_snapshot(&name).map_err(map_error)?;
    Ok(Json(snapshot_to_response(snapshot)))
}

#[utoipa::path(
    delete,
    path = "/v1/snapshots/{name}",
    tag = "snapshots",
    params(("name" = String, Path, description = "Snapshot name")),
    responses(
        (status = 204, description = "Snapshot deleted"),
        (status = 404, description = "Snapshot not found", body = ErrorResponse)
    )
)]
async fn delete_snapshot<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    core.delete_snapshot(&name).await.map_err(map_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/v1/snapshots/{name}/restore",
    tag = "snapshots",
    params(("name" = String, Path, description = "Snapshot name")),
    request_body = RestoreSnapshotRequest,
    responses(
        (status = 201, description = "VM restored from snapshot", body = VmResponse),
        (status = 404, description = "Snapshot not found", body = ErrorResponse),
        (status = 409, description = "VM already exists or invalid state", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    )
)]
async fn restore_snapshot<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
    Json(req): Json<RestoreSnapshotRequest>,
) -> Result<(StatusCode, Json<VmResponse>), (StatusCode, Json<ErrorResponse>)> {
    let vm = core.restore_snapshot(&name, req).await.map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(record_to_response(vm))))
}

#[utoipa::path(
    get,
    path = "/v1/vms",
    tag = "vms",
    responses(
        (status = 200, description = "List of all VMs", body = Vec<VmResponse>),
        (status = 500, description = "Internal error", body = ErrorResponse)
    )
)]
async fn list_vms<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
) -> Result<Json<Vec<VmResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let vms = core.list_vms().map_err(map_error)?;
    Ok(Json(vms.into_iter().map(record_to_response).collect()))
}

#[utoipa::path(
    post,
    path = "/v1/vms",
    tag = "vms",
    request_body = CreateVmRequest,
    responses(
        (status = 201, description = "VM created", body = VmResponse),
        (status = 409, description = "VM already exists", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    )
)]
async fn create_vm<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Json(req): Json<CreateVmRequest>,
) -> Result<(StatusCode, Json<VmResponse>), (StatusCode, Json<ErrorResponse>)> {
    let record = core.create_vm(req).await.map_err(map_error)?;

    core.spawn_userdata(&record);

    Ok((StatusCode::CREATED, Json(record_to_response(record))))
}

#[utoipa::path(
    get,
    path = "/v1/vms/{name}",
    tag = "vms",
    params(("name" = String, Path, description = "VM name")),
    responses(
        (status = 200, description = "VM details", body = VmResponse),
        (status = 404, description = "VM not found", body = ErrorResponse)
    )
)]
async fn get_vm<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<Json<VmResponse>, (StatusCode, Json<ErrorResponse>)> {
    let record = core.get_vm(&name).map_err(map_error)?;
    Ok(Json(record_to_response(record)))
}

#[utoipa::path(
    post,
    path = "/v1/vms/{name}/stop",
    tag = "vms",
    params(("name" = String, Path, description = "VM name")),
    responses(
        (status = 204, description = "VM stopped"),
        (status = 404, description = "VM not found", body = ErrorResponse),
        (status = 409, description = "Invalid VM state", body = ErrorResponse)
    )
)]
async fn stop_vm<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    core.stop_vm(&name).await.map_err(map_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/v1/vms/{name}/pause",
    tag = "vms",
    params(("name" = String, Path, description = "VM name")),
    responses(
        (status = 204, description = "VM paused"),
        (status = 404, description = "VM not found", body = ErrorResponse),
        (status = 409, description = "Invalid VM state", body = ErrorResponse)
    )
)]
async fn pause_vm<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    core.pause_vm(&name).await.map_err(map_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/v1/vms/{name}/resume",
    tag = "vms",
    params(("name" = String, Path, description = "VM name")),
    responses(
        (status = 204, description = "VM resumed"),
        (status = 404, description = "VM not found", body = ErrorResponse),
        (status = 409, description = "Invalid VM state", body = ErrorResponse)
    )
)]
async fn resume_vm<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    core.resume_vm(&name).await.map_err(map_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/v1/vms/{name}",
    tag = "vms",
    params(("name" = String, Path, description = "VM name")),
    responses(
        (status = 204, description = "VM destroyed"),
        (status = 404, description = "VM not found", body = ErrorResponse)
    )
)]
async fn destroy_vm<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    core.destroy_vm(&name).await.map_err(map_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/v1/vms/{name}/exec",
    tag = "exec",
    params(("name" = String, Path, description = "VM name")),
    request_body = ExecRequest,
    responses(
        (status = 200, description = "Command executed", body = ExecResponse),
        (status = 404, description = "VM not found", body = ErrorResponse),
        (status = 503, description = "Agent not ready", body = ErrorResponse)
    )
)]
async fn exec_vm<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
    Json(req): Json<ExecRequest>,
) -> Result<Json<ExecResponse>, (StatusCode, Json<ErrorResponse>)> {
    let policy = current_policy();
    if !exec_command_allowed(&req.command, &policy) {
        return Err((
            StatusCode::FORBIDDEN,
            error_response_with_hint(
                "policy_exec_command_denied",
                format!("command '{}' is blocked by execution policy", req.command),
                "adjust exec allow/deny policy",
            ),
        ));
    }
    if !exec_env_allowed(&req.env, &policy) {
        return Err((
            StatusCode::FORBIDDEN,
            error_response_with_hint(
                "policy_exec_env_denied",
                "one or more environment keys are not allowed",
                "adjust exec env allowlist policy",
            ),
        ));
    }
    info!(
        audit = "exec_request",
        vm = %name,
        command = %req.command,
        args_count = req.args.len(),
        env_count = req.env.len(),
        has_working_dir = req.working_dir.is_some()
    );
    // Race-tolerant connect: exec callers often hit the agent within a second
    // or two of VM boot, before the guest has bound vsock port 52. A short
    // retry window eliminates the need for client-side polling.
    let mut conn = core
        .agent_connect_ready(
            &name,
            resolve_exec_connect_timeout(req.connect_timeout_secs),
        )
        .await
        .map_err(map_agent_connect_error)?;
    let args: Vec<&str> = req.args.iter().map(String::as_str).collect();
    let env: Vec<(&str, &str)> = req
        .env
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let result = tokio::time::timeout(
        Duration::from_secs(policy.exec_timeout_secs.max(1)),
        conn.exec(&req.command, &args, req.working_dir.as_deref(), &env),
    )
    .await
    .map_err(|_| {
        (
            StatusCode::REQUEST_TIMEOUT,
            error_response_with_hint(
                "exec_timeout",
                "command execution timed out",
                "increase exec timeout policy or optimize guest command runtime",
            ),
        )
    })?
    .map_err(|e| map_error(e.into()))?;
    metrics().exec_total.fetch_add(1, Ordering::Relaxed);
    info!(
        audit = "exec_result",
        vm = %name,
        command = %req.command,
        exit_code = result.exit_code,
        stdout_bytes = result.stdout.len(),
        stderr_bytes = result.stderr.len()
    );
    Ok(Json(ExecResponse {
        exit_code: result.exit_code,
        stdout: result.stdout,
        stderr: result.stderr,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/vms/{name}/files/read",
    tag = "files",
    params(("name" = String, Path, description = "VM name")),
    request_body = ReadFileRequest,
    responses(
        (status = 200, description = "File content (base64-encoded)", body = ReadFileResponse),
        (status = 404, description = "VM not found", body = ErrorResponse),
        (status = 503, description = "Agent not ready", body = ErrorResponse)
    )
)]
async fn read_file_handler<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
    Json(req): Json<ReadFileRequest>,
) -> Result<Json<ReadFileResponse>, (StatusCode, Json<ErrorResponse>)> {
    let policy = current_policy();
    if !is_allowed_guest_path(&req.path, &policy.allowed_read_paths) {
        return Err((
            StatusCode::FORBIDDEN,
            error_response_with_hint(
                "policy_read_path_denied",
                format!("guest path '{}' is not allowed for read", req.path),
                "set allowed_read_paths in daemon config",
            ),
        ));
    }
    info!(audit = "read_file_request", vm = %name, path = %req.path);
    let mut conn = core
        .agent_connect(&name)
        .await
        .map_err(map_agent_connect_error)?;
    let data = conn
        .read_file(&req.path)
        .await
        .map_err(|e| map_error(e.into()))?;
    if data.len() > policy.max_file_read_bytes {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            error_response_with_hint(
                "read_file_too_large",
                format!(
                    "read result exceeds limit ({} bytes > {} bytes)",
                    data.len(),
                    policy.max_file_read_bytes
                ),
                "increase max_file_read_bytes policy if needed",
            ),
        ));
    }
    let size = data.len() as u64;
    metrics().file_reads_total.fetch_add(1, Ordering::Relaxed);
    info!(
        audit = "read_file_result",
        vm = %name,
        path = %req.path,
        size_bytes = size
    );
    Ok(Json(ReadFileResponse {
        data: husker_agent_proto::base64_encode(&data),
        size,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/vms/{name}/files/write",
    tag = "files",
    params(("name" = String, Path, description = "VM name")),
    request_body = WriteFileRequest,
    responses(
        (status = 200, description = "File written", body = WriteFileResponse),
        (status = 400, description = "Invalid base64 data", body = ErrorResponse),
        (status = 404, description = "VM not found", body = ErrorResponse),
        (status = 503, description = "Agent not ready", body = ErrorResponse)
    )
)]
async fn write_file_handler<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
    Json(req): Json<WriteFileRequest>,
) -> Result<Json<WriteFileResponse>, (StatusCode, Json<ErrorResponse>)> {
    let policy = current_policy();
    if !is_allowed_guest_path(&req.path, &policy.allowed_write_paths) {
        return Err((
            StatusCode::FORBIDDEN,
            error_response_with_hint(
                "policy_write_path_denied",
                format!("guest path '{}' is not allowed for write", req.path),
                "set allowed_write_paths in daemon config",
            ),
        ));
    }
    info!(
        audit = "write_file_request",
        vm = %name,
        path = %req.path,
        mode = req.mode,
        payload_bytes = req.data.len()
    );
    let data = husker_agent_proto::base64_decode(&req.data).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            error_response_with_hint(
                "invalid_base64",
                "invalid base64 in data field",
                "provide a valid base64 payload",
            ),
        )
    })?;
    if data.len() > policy.max_file_write_bytes {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            error_response_with_hint(
                "write_file_too_large",
                format!(
                    "write payload exceeds limit ({} bytes > {} bytes)",
                    data.len(),
                    policy.max_file_write_bytes
                ),
                "increase max_file_write_bytes policy if needed",
            ),
        ));
    }
    let mut conn = core
        .agent_connect(&name)
        .await
        .map_err(map_agent_connect_error)?;
    let bytes_written = conn
        .write_file(&req.path, &data, req.mode)
        .await
        .map_err(|e| map_error(e.into()))?;
    metrics().file_writes_total.fetch_add(1, Ordering::Relaxed);
    info!(
        audit = "write_file_result",
        vm = %name,
        path = %req.path,
        bytes_written
    );
    Ok(Json(WriteFileResponse { bytes_written }))
}

// ── WebSocket Shell Handler ───────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/vms/{name}/shell",
    tag = "shell",
    params(("name" = String, Path, description = "VM name")),
    responses(
        (status = 101, description = "WebSocket upgrade for interactive shell"),
        (status = 404, description = "VM not found", body = ErrorResponse)
    )
)]
async fn shell_ws<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    info!(audit = "shell_upgrade", vm = %name);
    ws.on_upgrade(move |socket| shell_ws_session(core, name, socket))
}

async fn shell_ws_session<B: VmmBackend + 'static>(
    core: Arc<HuskerCore<B>>,
    name: String,
    mut ws: WebSocket,
) {
    // Wait for the Start message from the client.
    let (command, cols, rows) = match ws.recv().await {
        Some(Ok(Message::Text(text))) => match serde_json::from_str::<WsShellInput>(&text) {
            Ok(WsShellInput::Start {
                command,
                cols,
                rows,
            }) => (command, cols, rows),
            Ok(_) => {
                let _ = send_ws_output(
                    &mut ws,
                    &WsShellOutput::Error {
                        message: "expected 'start' message".into(),
                    },
                )
                .await;
                return;
            }
            Err(e) => {
                let _ = send_ws_output(
                    &mut ws,
                    &WsShellOutput::Error {
                        message: format!("invalid message: {e}"),
                    },
                )
                .await;
                return;
            }
        },
        _ => return,
    };
    info!(
        audit = "shell_start",
        vm = %name,
        cols,
        rows,
        command = command.as_deref().unwrap_or("/bin/sh")
    );
    metrics()
        .shell_sessions_total
        .fetch_add(1, Ordering::Relaxed);

    // Connect to the guest agent.
    let mut conn = match core.agent_connect(&name).await {
        Ok(conn) => conn,
        Err(e) => {
            let _ = send_ws_output(
                &mut ws,
                &WsShellOutput::Error {
                    message: e.to_string(),
                },
            )
            .await;
            return;
        }
    };

    // Start the shell session inside the guest.
    if let Err(e) = conn.shell_start(command.as_deref(), cols, rows).await {
        let _ = send_ws_output(
            &mut ws,
            &WsShellOutput::Error {
                message: format!("shell start failed: {e}"),
            },
        )
        .await;
        return;
    }

    let _ = send_ws_output(&mut ws, &WsShellOutput::Started).await;

    debug!(%name, "shell WebSocket session started");

    // Bridge loop: relay data between WebSocket and agent shell.
    //
    // Backpressure: ws.send().await blocks when the TCP write buffer is full,
    // which prevents the select loop from reading the next agent event until
    // the client catches up. No additional buffering or flow control is needed.
    let mut ping_interval = tokio::time::interval(std::time::Duration::from_secs(30));
    ping_interval.reset(); // Don't fire immediately.

    loop {
        tokio::select! {
            ws_msg = ws.recv() => {
                match ws_msg {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<WsShellInput>(&text) {
                            Ok(WsShellInput::Data { data }) => {
                                let bytes = match husker_agent_proto::base64_decode(&data) {
                                    Ok(b) => b,
                                    Err(e) => {
                                        warn!("invalid base64 from client: {e}");
                                        continue;
                                    }
                                };
                                if let Err(e) = conn.shell_send(&bytes).await {
                                    warn!("shell_send failed: {e}");
                                    break;
                                }
                            }
                            Ok(WsShellInput::Resize { cols, rows }) => {
                                if let Err(e) = conn.shell_resize(cols, rows).await {
                                    warn!("shell_resize failed: {e}");
                                    break;
                                }
                            }
                            Ok(WsShellInput::Start { .. }) => {}
                            Err(e) => {
                                warn!("invalid WS message: {e}");
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        warn!("WebSocket error: {e}");
                        break;
                    }
                }
            }
            agent_event = conn.shell_recv() => {
                match agent_event {
                    Ok(ShellEvent::Data(data)) => {
                        let encoded = husker_agent_proto::base64_encode(&data);
                        if send_ws_output(&mut ws, &WsShellOutput::Data { data: encoded }).await.is_err() {
                            break;
                        }
                    }
                    Ok(ShellEvent::Exit(code)) => {
                        info!(audit = "shell_exit", vm = %name, exit_code = code);
                        let _ = send_ws_output(&mut ws, &WsShellOutput::Exit { exit_code: code }).await;
                        break;
                    }
                    Err(e) => {
                        let _ = send_ws_output(&mut ws, &WsShellOutput::Error {
                            message: format!("agent error: {e}"),
                        }).await;
                        break;
                    }
                }
            }
            _ = ping_interval.tick() => {
                if ws.send(Message::Ping(vec![].into())).await.is_err() {
                    break;
                }
            }
        }
    }

    // Send a proper WebSocket Close frame so the client doesn't hang
    // waiting for more data during its runtime shutdown.
    let _ = ws.send(Message::Close(None)).await;

    debug!(%name, "shell WebSocket session ended");
}

async fn send_ws_output(ws: &mut WebSocket, msg: &WsShellOutput) -> Result<(), axum::Error> {
    let text = serde_json::to_string(msg).expect("WsShellOutput is always serializable");
    ws.send(Message::Text(text.into())).await
}

// ── Logs Handler ─────────────────────────────────────────────────────

/// Maximum bytes to read from a serial log in non-follow mode.
/// Logs exceeding this size are truncated to the last 1 MiB.
const LOG_MAX_READ_BYTES: u64 = 1024 * 1024;

#[utoipa::path(
    get,
    path = "/v1/vms/{name}/logs",
    tag = "logs",
    params(
        ("name" = String, Path, description = "VM name"),
        ("follow" = Option<bool>, Query, description = "Follow log output"),
        ("tail" = Option<u64>, Query, description = "Show last N lines")
    ),
    responses(
        (status = 200, description = "Serial console output", content_type = "text/plain"),
        (status = 404, description = "VM or log not found", body = ErrorResponse)
    )
)]
async fn get_logs<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
    Query(params): Query<LogsQuery>,
) -> Result<axum::response::Response, (StatusCode, Json<ErrorResponse>)> {
    let effective = match params.source.as_deref() {
        Some("boot") => "boot",
        Some("userdata") => "userdata",
        Some("serial") => "serial",
        Some(other) => {
            return Err((
                StatusCode::BAD_REQUEST,
                error_response(
                    "invalid_log_source",
                    format!("unknown log source '{other}' (expected serial|boot|userdata)"),
                ),
            ));
        }
        None if params.userdata => "userdata",
        None => "serial",
    };
    let (log_path, log_label) = match effective {
        "boot" => (core.boot_log_path(&name).map_err(map_error)?, "boot"),
        "userdata" => (core.userdata_log_path(&name).map_err(map_error)?, "userdata"),
        _ => (core.serial_log_path(&name).map_err(map_error)?, "serial"),
    };
    // Only the live serial console is followable; boot/userdata are static files.
    let follow = params.follow && effective == "serial";

    // Error `code`s are part of the stable API contract: each source yields
    // a `{source}_log_*` prefix (e.g. `serial_log_not_found`, `boot_log_not_found`).
    let metadata = tokio::fs::metadata(&log_path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            (
                StatusCode::NOT_FOUND,
                error_response(
                    &format!("{log_label}_log_not_found"),
                    format!("no {log_label} log for VM '{name}'"),
                ),
            )
        } else {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                error_response(
                    &format!("{log_label}_log_read_failed"),
                    format!("reading {log_label} log: {e}"),
                ),
            )
        }
    })?;

    let file_size = metadata.len();
    if follow {
        // Bounded preload: for follow mode never load more than 1 MiB.
        let mut initial_content = if file_size > LOG_MAX_READ_BYTES {
            use tokio::io::{AsyncReadExt, AsyncSeekExt};
            let mut file = tokio::fs::File::open(&log_path).await.map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error_response(
                        &format!("{log_label}_log_read_failed"),
                        format!("reading {log_label} log: {e}"),
                    ),
                )
            })?;
            file.seek(std::io::SeekFrom::Start(file_size - LOG_MAX_READ_BYTES))
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        error_response(
                            &format!("{log_label}_log_seek_failed"),
                            format!("seeking {log_label} log: {e}"),
                        ),
                    )
                })?;
            let mut buf = String::new();
            file.read_to_string(&mut buf).await.map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error_response(
                        &format!("{log_label}_log_read_failed"),
                        format!("reading {log_label} log: {e}"),
                    ),
                )
            })?;
            format!("[... truncated, showing last 1 MiB ...]\n{buf}")
        } else {
            tokio::fs::read_to_string(&log_path).await.map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error_response(
                        &format!("{log_label}_log_read_failed"),
                        format!("reading {log_label} log: {e}"),
                    ),
                )
            })?
        };
        if let Some(n) = params.tail {
            initial_content = tail_lines(&initial_content, n);
        }

        let mut offset = file_size;
        let initial = axum::body::Bytes::from(initial_content.into_bytes());

        let stream = async_stream::stream! {
            use tokio::io::{AsyncReadExt, AsyncSeekExt};

            if !initial.is_empty() {
                yield Ok::<axum::body::Bytes, std::io::Error>(initial);
            }

            let mut interval = tokio::time::interval(std::time::Duration::from_millis(250));
            loop {
                interval.tick().await;
                match tokio::fs::metadata(&log_path).await {
                    Ok(meta) => {
                        let len = meta.len();
                        if len < offset {
                            offset = 0;
                            let notice = b"\n[... serial log rotated or truncated ...]\n".to_vec();
                            yield Ok(axum::body::Bytes::from(notice));
                        }
                        if len > offset {
                            match tokio::fs::File::open(&log_path).await {
                                Ok(mut file) => {
                                    if let Err(e) = file.seek(std::io::SeekFrom::Start(offset)).await {
                                        yield Err(e);
                                        break;
                                    }
                                    let mut buf = Vec::with_capacity((len - offset) as usize);
                                    match file.read_to_end(&mut buf).await {
                                        Ok(_) => {
                                            offset += buf.len() as u64;
                                            yield Ok(axum::body::Bytes::from(buf));
                                        }
                                        Err(e) => {
                                            yield Err(e);
                                            break;
                                        }
                                    }
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                                    break;
                                }
                                Err(e) => {
                                    yield Err(e);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        break;
                    }
                    Err(_) => {}
                }
            }
        };

        let body = axum::body::Body::from_stream(stream);
        Ok(axum::response::Response::builder()
            .header("content-type", "text/plain; charset=utf-8")
            .header("transfer-encoding", "chunked")
            .body(body)
            .expect("static response builder"))
    } else {
        let truncated = file_size > LOG_MAX_READ_BYTES;
        let content = if truncated {
            use tokio::io::{AsyncReadExt, AsyncSeekExt};
            let mut file = tokio::fs::File::open(&log_path).await.map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error_response(
                        &format!("{log_label}_log_read_failed"),
                        format!("reading {log_label} log: {e}"),
                    ),
                )
            })?;
            file.seek(std::io::SeekFrom::Start(file_size - LOG_MAX_READ_BYTES))
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        error_response(
                            &format!("{log_label}_log_seek_failed"),
                            format!("seeking {log_label} log: {e}"),
                        ),
                    )
                })?;
            let mut buf = String::new();
            file.read_to_string(&mut buf).await.map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error_response(
                        &format!("{log_label}_log_read_failed"),
                        format!("reading {log_label} log: {e}"),
                    ),
                )
            })?;
            format!("[... truncated, showing last 1 MiB ...]\n{buf}")
        } else {
            tokio::fs::read_to_string(&log_path).await.map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error_response(
                        &format!("{log_label}_log_read_failed"),
                        format!("reading {log_label} log: {e}"),
                    ),
                )
            })?
        };

        let output = if let Some(n) = params.tail {
            tail_lines(&content, n)
        } else {
            content
        };

        Ok(axum::response::Response::builder()
            .header("content-type", "text/plain; charset=utf-8")
            .body(axum::body::Body::from(output))
            .expect("static response builder"))
    }
}

/// Return the last `n` lines of `content`.
fn tail_lines(content: &str, n: u64) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(n as usize);
    let mut result = lines[start..].join("\n");
    if content.ends_with('\n') && !result.is_empty() {
        result.push('\n');
    }
    result
}

// ── Port Forward Handlers ─────────────────────────────────────────────

#[cfg(feature = "linux-net")]
#[utoipa::path(
    post,
    path = "/v1/vms/{name}/ports",
    tag = "ports",
    params(("name" = String, Path, description = "VM name")),
    request_body = AddPortForwardRequest,
    responses(
        (status = 201, description = "Port forward added", body = PortForwardResponse),
        (status = 404, description = "VM not found", body = ErrorResponse),
        (status = 409, description = "Port already forwarded", body = ErrorResponse)
    )
)]
async fn add_port_forward_handler<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
    Json(req): Json<AddPortForwardRequest>,
) -> Result<(StatusCode, Json<PortForwardResponse>), (StatusCode, Json<ErrorResponse>)> {
    core.add_port_forward(&name, req.host_port, req.guest_port)
        .await
        .map_err(map_error)?;
    Ok((
        StatusCode::CREATED,
        Json(PortForwardResponse {
            host_port: req.host_port,
            guest_port: req.guest_port,
            protocol: "tcp".into(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }),
    ))
}

#[cfg(feature = "linux-net")]
#[utoipa::path(
    get,
    path = "/v1/vms/{name}/ports",
    tag = "ports",
    params(("name" = String, Path, description = "VM name")),
    responses(
        (status = 200, description = "List of port forwards", body = Vec<PortForwardResponse>),
        (status = 404, description = "VM not found", body = ErrorResponse)
    )
)]
async fn list_port_forwards_handler<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<Json<Vec<PortForwardResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let forwards = core.list_port_forwards(&name).map_err(map_error)?;
    Ok(Json(
        forwards
            .into_iter()
            .map(|pf| PortForwardResponse {
                host_port: pf.host_port,
                guest_port: pf.guest_port,
                protocol: pf.protocol,
                created_at: pf.created_at.to_rfc3339(),
            })
            .collect(),
    ))
}

#[cfg(feature = "linux-net")]
#[utoipa::path(
    delete,
    path = "/v1/vms/{name}/ports/{host_port}",
    tag = "ports",
    params(
        ("name" = String, Path, description = "VM name"),
        ("host_port" = u16, Path, description = "Host port to remove")
    ),
    responses(
        (status = 204, description = "Port forward removed"),
        (status = 404, description = "VM not found", body = ErrorResponse)
    )
)]
async fn remove_port_forward_handler<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path((name, host_port)): Path<(String, u16)>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    core.remove_port_forward(&name, host_port)
        .await
        .map_err(map_error)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Error Mapping ─────────────────────────────────────────────────────

fn map_error(err: CoreError) -> (StatusCode, Json<ErrorResponse>) {
    let (status, code, message) = match &err {
        CoreError::VmNotFound(_) => (StatusCode::NOT_FOUND, "vm_not_found", err.to_string()),
        CoreError::HostGroupNotFound(_) => (
            StatusCode::NOT_FOUND,
            "host_group_not_found",
            err.to_string(),
        ),
        CoreError::ServiceNotFound(_) => {
            (StatusCode::NOT_FOUND, "service_not_found", err.to_string())
        }
        CoreError::ImageNotFound(_) => (StatusCode::NOT_FOUND, "image_not_found", err.to_string()),
        CoreError::SecretNotFound(_) => {
            (StatusCode::NOT_FOUND, "secret_not_found", err.to_string())
        }
        CoreError::SnapshotNotFound(_) => {
            (StatusCode::NOT_FOUND, "snapshot_not_found", err.to_string())
        }
        CoreError::InvalidState { .. } => (StatusCode::CONFLICT, "invalid_state", err.to_string()),
        CoreError::InvalidArgument(_) => {
            (StatusCode::BAD_REQUEST, "invalid_argument", err.to_string())
        }
        CoreError::ServiceOperationFailed(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "service_operation_failed",
            err.to_string(),
        ),
        CoreError::VmAlreadyExists(_) => {
            (StatusCode::CONFLICT, "vm_already_exists", err.to_string())
        }
        CoreError::HostGroupAlreadyExists(_) => (
            StatusCode::CONFLICT,
            "host_group_already_exists",
            err.to_string(),
        ),
        CoreError::ServiceAlreadyExists(_) => (
            StatusCode::CONFLICT,
            "service_already_exists",
            err.to_string(),
        ),
        CoreError::ImageAlreadyExists(_) => (
            StatusCode::CONFLICT,
            "image_already_exists",
            err.to_string(),
        ),
        CoreError::SecretAlreadyExists(_) => (
            StatusCode::CONFLICT,
            "secret_already_exists",
            err.to_string(),
        ),
        CoreError::SnapshotAlreadyExists(_) => (
            StatusCode::CONFLICT,
            "snapshot_already_exists",
            err.to_string(),
        ),
        CoreError::SecretCrypto(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "secret_crypto_error",
            err.to_string(),
        ),
        CoreError::Agent(husker_core::AgentError::NotReady(_)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "agent_not_ready",
            err.to_string(),
        ),
        CoreError::Storage(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            err.to_string(),
        ),
        CoreError::State(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "state_error",
            err.to_string(),
        ),
        CoreError::Vmm(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "vmm_error",
            err.to_string(),
        ),
        #[cfg(feature = "linux-net")]
        CoreError::Network(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "network_error",
            err.to_string(),
        ),
        CoreError::Agent(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "agent_error",
            err.to_string(),
        ),
    };
    (status, error_response(code, message))
}

fn map_agent_connect_error(err: CoreError) -> (StatusCode, Json<ErrorResponse>) {
    match err {
        CoreError::Vmm(husker_vmm::VmmError::VmNotFound(_))
        | CoreError::Vmm(husker_vmm::VmmError::ProcessError(_))
        | CoreError::Vmm(husker_vmm::VmmError::ApiError(_))
        | CoreError::Agent(husker_core::AgentError::Connection(_))
        | CoreError::Agent(husker_core::AgentError::VsockConnectRejected(_))
        | CoreError::Agent(husker_core::AgentError::NotReady(_)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            error_response_with_hint(
                "agent_not_ready",
                format!("agent not ready: {err}"),
                "retry after the VM boot sequence has completed",
            ),
        ),
        other => map_error(other),
    }
}

fn host_group_to_response(r: HostGroupRecord) -> HostGroupResponse {
    HostGroupResponse {
        id: r.id.to_string(),
        name: r.name,
        description: r.description,
        created_at: r.created_at.to_rfc3339(),
        updated_at: r.updated_at.to_rfc3339(),
    }
}

fn outcome_to_response(o: husker_core::ReconcileOutcome) -> ReconcileOutcomeResponse {
    ReconcileOutcomeResponse {
        created: o.created,
        destroyed: o.destroyed,
        failed: o
            .failed
            .into_iter()
            .map(|(instance, error)| ReconcileFailure { instance, error })
            .collect(),
    }
}

fn service_to_response<B: VmmBackend + 'static>(
    core: &AppState<B>,
    r: ServiceRecord,
) -> ServiceResponse {
    let current_instances = core
        .list_vms_for_service(r.id)
        .map(|vs| vs.iter().filter(|v| v.state == "running").count() as u32)
        .unwrap_or(0);
    ServiceResponse {
        id: r.id.to_string(),
        name: r.name,
        host_group_id: r.host_group_id.map(|id| id.to_string()),
        desired_instances: r.desired_instances,
        current_instances,
        image: r.image,
        rootfs_path: r.rootfs_path,
        kernel_path: r.kernel_path,
        created_at: r.created_at.to_rfc3339(),
        updated_at: r.updated_at.to_rfc3339(),
    }
}

fn image_to_response(r: ImageRecord) -> ImageResponse {
    ImageResponse {
        id: r.id.to_string(),
        name: r.name,
        source_path: r.source_path,
        file_path: r.file_path,
        format: r.format,
        size_bytes: r.size_bytes,
        created_at: r.created_at.to_rfc3339(),
    }
}

fn export_result_to_response(r: ExportImageResult) -> ExportImageResponse {
    ExportImageResponse {
        name: r.name,
        destination_path: r.destination_path.to_string_lossy().into_owned(),
        size_bytes: r.size_bytes,
    }
}

fn secret_to_response(r: SecretMetadata) -> SecretResponse {
    SecretResponse {
        id: r.id.to_string(),
        name: r.name,
        created_at: r.created_at.to_rfc3339(),
        updated_at: r.updated_at.to_rfc3339(),
    }
}

fn snapshot_to_response(r: SnapshotRecord) -> SnapshotResponse {
    SnapshotResponse {
        id: r.id.to_string(),
        name: r.name,
        source_vm_name: r.source_vm_name,
        file_path: r.file_path,
        created_at: r.created_at.to_rfc3339(),
    }
}

fn record_to_response(r: VmRecord) -> VmResponse {
    VmResponse {
        id: r.id.to_string(),
        name: r.name,
        state: r.state,
        pid: r.pid,
        vcpu_count: r.vcpu_count,
        mem_size_mib: r.mem_size_mib,
        vsock_cid: r.vsock_cid,
        host_ip: r.host_ip,
        guest_ip: r.guest_ip,
        created_at: r.created_at.to_rfc3339(),
        updated_at: r.updated_at.to_rfc3339(),
        userdata_status: r.userdata_status,
    }
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
        };
        make_core(state, storage, PathBuf::from("/tmp/husker-test/run"))
    }

    async fn response_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
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
        assert_eq!(json["code"], "host_group_not_found");
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
        assert_eq!(json["code"], "snapshot_not_found");
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
                state: "running".into(),
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
            })
            .unwrap();

        let core = make_core(
            state,
            husker_storage::StorageConfig { data_dir },
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
        assert_eq!(response_json(serial).await["code"], "serial_log_not_found");

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
            response_json(userdata).await["code"],
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
        assert_eq!(response_json(boot).await["code"], "boot_log_not_found");

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
        assert_eq!(response_json(serial2).await["code"], "serial_log_not_found");

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
        assert_eq!(response_json(bad).await["code"], "invalid_log_source");
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
        assert_eq!(json["code"], "policy_read_path_denied");

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
        assert_eq!(json["code"], "policy_write_path_denied");

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
        assert_eq!(json["code"], "write_file_too_large");

        set_policy(ApiPolicy::default());
    }

    #[test]
    fn protected_route_detection_is_correct() {
        assert!(!is_protected_route(&Method::GET, "/v1/health"));
        assert!(!is_protected_route(&Method::GET, "/v1/vms"));
        assert!(!is_protected_route(&Method::GET, "/v1/vms/example"));
        assert!(!is_protected_route(&Method::GET, "/v1/services"));
        assert!(!is_protected_route(&Method::GET, "/v1/host-groups"));
        assert!(!is_protected_route(&Method::GET, "/v1/images"));
        assert!(is_protected_route(&Method::GET, "/v1/secrets"));
        assert!(!is_protected_route(&Method::GET, "/v1/snapshots"));
        assert!(is_protected_route(&Method::POST, "/v1/services"));
        assert!(is_protected_route(&Method::POST, "/v1/host-groups"));
        assert!(is_protected_route(&Method::POST, "/v1/images"));
        assert!(is_protected_route(&Method::DELETE, "/v1/images/base"));
        assert!(is_protected_route(&Method::POST, "/v1/secrets"));
        assert!(is_protected_route(
            &Method::DELETE,
            "/v1/secrets/db-password"
        ));
        assert!(is_protected_route(&Method::POST, "/v1/snapshots"));
        assert!(is_protected_route(&Method::DELETE, "/v1/snapshots/snap-1"));
        assert!(is_protected_route(&Method::POST, "/v1/vms/example/stop"));
        assert!(is_protected_route(&Method::DELETE, "/v1/vms/example"));
        assert!(is_protected_route(&Method::GET, "/v1/vms/example/shell"));
        assert!(is_protected_route(&Method::GET, "/v1/vms/example/logs"));
        assert!(is_protected_route(&Method::GET, "/v1/metrics"));
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
        // Unset -> the default.
        assert_eq!(
            resolve_exec_connect_timeout(None),
            Duration::from_secs(DEFAULT_EXEC_CONNECT_TIMEOUT_SECS)
        );
        // In-range values pass through.
        assert_eq!(
            resolve_exec_connect_timeout(Some(5)),
            Duration::from_secs(5)
        );
        // Zero is clamped up to the 1s floor (never an instant-fail connect).
        assert_eq!(
            resolve_exec_connect_timeout(Some(0)),
            Duration::from_secs(1)
        );
        // Absurd values are clamped to the ceiling.
        assert_eq!(
            resolve_exec_connect_timeout(Some(u64::MAX)),
            Duration::from_secs(MAX_EXEC_CONNECT_TIMEOUT_SECS)
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

    #[test]
    fn rate_limiter_blocks_when_limit_reached() {
        let limiter = SlidingWindowRateLimiter::default();
        assert!(limiter.allow("k", 2));
        assert!(limiter.allow("k", 2));
        assert!(!limiter.allow("k", 2));
    }

    #[test]
    fn rate_limiter_zero_limit_allows_requests() {
        let limiter = SlidingWindowRateLimiter::default();
        assert!(limiter.allow("k", 0));
        assert!(limiter.allow("k", 0));
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

        let (status, _) = map_error(CoreError::ImageAlreadyExists("test".into()));
        assert_eq!(status, StatusCode::CONFLICT);

        let (status, _) = map_error(CoreError::SecretAlreadyExists("test".into()));
        assert_eq!(status, StatusCode::CONFLICT);

        let (status, _) = map_error(CoreError::InvalidArgument("bad value".into()));
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _) = map_error(CoreError::Agent(AgentError::NotReady(Duration::from_secs(
            5,
        ))));
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        let (status, _) = map_error(CoreError::Agent(AgentError::UnexpectedResponse));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

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
        assert_eq!(payload.code, "agent_not_ready");
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
}
