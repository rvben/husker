//! Axum router construction, middleware, and server entry points for the husker HTTP API.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::extract::State;
use axum::http::HeaderValue;
use axum::http::Method;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use subtle::ConstantTimeEq;
use tracing::{info, warn};
use utoipa::OpenApi;

use husker_core::HuskerCore;
use husker_vmm::VmmBackend;

use crate::errors::error_response_with_hint;
use crate::handlers::*;
use crate::{
    ApiDoc, ApiPolicy, AppState, PortForwardApiDoc, REQUEST_COUNTER, RateLimitDecision,
    SensitiveRateLimit, metrics,
};

pub(crate) fn is_rate_limited_route(method: &Method, path: &str) -> Option<&'static str> {
    if *method == Method::POST
        && (path.ends_with("/sessions") || path.ends_with("/session-submissions"))
    {
        return Some("exec");
    }
    if *method == Method::POST
        && (path == "/v1/jobs" || (path.starts_with("/v1/jobs/") && path.ends_with("/cancel")))
    {
        return Some("exec");
    }
    if *method == Method::GET && path.contains("/tunnel/") {
        return Some("tunnel");
    }
    if *method == Method::POST && path.ends_with("/exec") {
        return Some("exec");
    }
    if *method == Method::GET && path.ends_with("/exec/stream") {
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

// ── Bearer tokens ─────────────────────────────────────────────────────

/// A bearer token that the protected routes require.
///
/// Constructing one refuses empty and whitespace-only values, so a token that
/// reaches a router is always a real secret. Without this a blank `api_token`
/// (an unset variable in a unit file, a failed secret substitution) counted as
/// authentication: it satisfied the rule that a non-loopback daemon needs a
/// token while no client could ever present the matching header.
#[derive(Clone, PartialEq, Eq)]
pub struct BearerToken(String);

/// The error for a bearer token with no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyBearerToken;

impl std::fmt::Display for EmptyBearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("bearer token must not be empty")
    }
}

impl std::error::Error for EmptyBearerToken {}

impl BearerToken {
    /// Accept `token` as a bearer token. Whitespace-only values are refused
    /// along with the empty string; an accepted token is kept byte for byte.
    pub fn new(token: impl Into<String>) -> Result<Self, EmptyBearerToken> {
        let token = token.into();
        if token.trim().is_empty() {
            return Err(EmptyBearerToken);
        }
        Ok(Self(token))
    }

    /// The exact `Authorization` header value a caller must present.
    fn header_value(&self) -> String {
        format!("Bearer {}", self.0)
    }
}

/// The secret never reaches a log line through a `Debug` rendering of a
/// configuration struct.
impl std::fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BearerToken(<redacted>)")
    }
}

// ── Router ────────────────────────────────────────────────────────────

/// Build the API router with the default policy and no authentication.
pub fn router<B: VmmBackend + 'static>(core: Arc<HuskerCore<B>>) -> Router {
    router_with_policy(core, ApiPolicy::default())
}

/// Build an unauthenticated API router that enforces `policy`.
pub fn router_with_policy<B: VmmBackend + 'static>(
    core: Arc<HuskerCore<B>>,
    policy: ApiPolicy,
) -> Router {
    router_with_auth(core, policy, None)
}

/// Build the API router with optional bearer token authentication.
///
/// The router owns `policy`: its request limits, rate limit and exec rules
/// apply to this router's requests and to nothing else in the process. When
/// `auth_token` is set, every route except `/v1/health` and the static API
/// docs requires `Authorization: Bearer <token>`.
pub fn router_with_auth<B: VmmBackend + 'static>(
    core: Arc<HuskerCore<B>>,
    policy: ApiPolicy,
    auth_token: Option<BearerToken>,
) -> Router {
    let max_request_bytes = policy.max_request_bytes;
    let rate_limit = Arc::new(SensitiveRateLimit::new(
        policy.sensitive_rate_limit_per_minute,
    ));
    let factory = Router::new()
        .route("/v1/job-submissions", get(crate::jobs::lookup::<B>))
        .route("/v1/jobs", post(crate::jobs::submit::<B>))
        .route(
            "/v1/jobs/{id}",
            get(crate::jobs::get::<B>).delete(crate::jobs::remove::<B>),
        )
        .route("/v1/jobs/{id}/events", get(crate::jobs::events::<B>))
        .route("/v1/jobs/{id}/artifacts", get(crate::jobs::artifacts::<B>))
        .route(
            "/v1/jobs/{id}/artifacts/{index}",
            get(crate::jobs::artifact::<B>),
        )
        .route("/v1/jobs/{id}/cancel", post(crate::jobs::cancel::<B>))
        .route_layer(axum::middleware::from_fn_with_state(
            auth_token.as_ref().is_some(),
            factory_auth_required,
        ));
    let router = Router::new()
        .merge(factory)
        .route(
            "/v1/vms/{name}/sessions",
            get(crate::sessions::list::<B>).post(crate::sessions::start::<B>),
        )
        .route(
            "/v1/vms/{name}/session-submissions",
            post(crate::sessions::submit::<B>),
        )
        .route(
            "/v1/vms/{name}/sessions/{id}",
            get(crate::sessions::get::<B>).delete(crate::sessions::remove::<B>),
        )
        .route(
            "/v1/vms/{name}/sessions/{id}/events",
            get(crate::sessions::events::<B>),
        )
        .route(
            "/v1/vms/{name}/sessions/{id}/cancel",
            post(crate::sessions::cancel::<B>),
        )
        .route(
            "/v1/vms/{name}/tunnel/{port}",
            get(crate::sessions::tunnel::<B>),
        )
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
        .route("/v1/pools", get(list_pools::<B>).post(create_pool::<B>))
        .route(
            "/v1/pools/{name}",
            get(get_pool::<B>).delete(delete_pool::<B>),
        )
        .route("/v1/pools/{name}/checkout", post(checkout_pool::<B>))
        .route("/v1/images", get(list_images::<B>).post(import_image::<B>))
        .route("/v1/images/import-oci", post(import_oci_image::<B>))
        .route(
            "/v1/images/{name}",
            get(get_image::<B>).delete(delete_image::<B>),
        )
        .route("/v1/images/{name}/export", post(export_image::<B>))
        .route(
            "/v1/volumes",
            get(list_volumes::<B>).post(create_volume::<B>),
        )
        .route(
            "/v1/volumes/{name}",
            get(get_volume::<B>).delete(delete_volume::<B>),
        )
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
        .route("/v1/vms/{name}/commit-image", post(commit_vm_image::<B>))
        .route("/v1/vms/{name}/pause", post(pause_vm::<B>))
        .route("/v1/vms/{name}/resume", post(resume_vm::<B>))
        .route("/v1/vms/{name}/balloon", put(set_balloon::<B>))
        .route("/v1/vms/{name}/suspend", post(suspend_vm::<B>))
        .route("/v1/vms/{name}/fork", post(fork_vm::<B>))
        .route("/v1/vms/{name}/exec", post(exec_vm::<B>))
        .route("/v1/vms/{name}/exec/stream", get(exec_ws::<B>))
        .route("/v1/vms/{name}/files/read", post(read_file_handler::<B>))
        .route("/v1/vms/{name}/files/write", post(write_file_handler::<B>))
        .route("/v1/vms/{name}/shell", get(shell_ws::<B>))
        .route("/v1/vms/{name}/logs", get(get_logs::<B>))
        .route("/v1/vms/{name}/ready", get(get_ready::<B>))
        .route("/v1/vms/{name}/guest-info", get(get_guest_info::<B>))
        .route("/v1/metrics", get(metrics_handler::<B>))
        .route("/v1/profiles", get(list_profiles::<B>))
        .route("/v1/diagnostics", get(diagnostics::<B>));

    let router = router
        .route(
            "/v1/vms/{name}/ports",
            get(list_port_forwards_handler::<B>).post(add_port_forward_handler::<B>),
        )
        .route(
            "/v1/vms/{name}/ports/{host_port}",
            delete(remove_port_forward_handler::<B>),
        );

    let mut openapi = ApiDoc::openapi();
    openapi.merge(crate::sessions::SessionApiDoc::openapi());
    openapi.merge(crate::jobs::JobApiDoc::openapi());

    {
        let pf_doc = PortForwardApiDoc::openapi();
        openapi.merge(pf_doc);
    }

    let router = router
        .route("/v1/health", get(health::<B>))
        .merge(utoipa_swagger_ui::SwaggerUi::new("/docs").url("/api-docs/openapi.json", openapi))
        .fallback(crate::extract::route_not_found)
        .method_not_allowed_fallback(crate::extract::method_not_allowed);

    let router = if let Some(token) = auth_token {
        let expected = Arc::new(token.header_value());
        router.layer(axum::middleware::from_fn_with_state(
            expected,
            auth_middleware,
        ))
    } else {
        router
    };

    router
        .layer(DefaultBodyLimit::max(max_request_bytes))
        .layer(axum::middleware::from_fn_with_state(
            rate_limit,
            rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn(trace_request))
        .with_state(AppState {
            core,
            policy: Arc::new(policy),
        })
}

/// Start the API server with graceful shutdown on SIGINT/SIGTERM, enforcing
/// `policy` and, when `auth_token` is set, bearer token authentication.
pub async fn serve_with_auth<B: VmmBackend + 'static>(
    core: Arc<HuskerCore<B>>,
    policy: ApiPolicy,
    addr: SocketAddr,
    auth_token: Option<BearerToken>,
) -> std::io::Result<()> {
    let app = router_with_auth(Arc::clone(&core), policy, auth_token);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "husker daemon listening");

    // Bound the graceful drain. Axum's `with_graceful_shutdown` waits for every
    // in-flight connection to close, and a long-lived shell/exec WebSocket would
    // otherwise block shutdown indefinitely until systemd SIGKILLs the process
    // (skipping VM draining entirely). After the signal fires we give open
    // connections a fixed grace window, then stop regardless so the caller's own
    // VM-drain step still gets to run before the supervisor's stop timeout.
    let shutdown_started = Arc::new(tokio::sync::Notify::new());
    let notify = shutdown_started.clone();
    let serve = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        core.close_factory_admission();
        notify.notify_one();
    });

    tokio::select! {
        res = serve => res,
        () = async {
            shutdown_started.notified().await;
            tokio::time::sleep(GRACEFUL_SHUTDOWN_GRACE).await;
        } => {
            warn!(
                "graceful shutdown exceeded {}s with connections still open; forcing exit",
                GRACEFUL_SHUTDOWN_GRACE.as_secs()
            );
            Ok(())
        }
    }
}

/// How long to wait for in-flight connections to drain after a shutdown signal
/// before forcing the server to stop. This is the first of the daemon's three
/// sequential stop phases (connection grace, worker grace, VM drain); the
/// shipped `contrib/husker.service` sets `TimeoutStopSec` above their sum, and
/// a test in the daemon crate holds it there, so the service manager never
/// kills the daemon while its guests are still draining.
pub const GRACEFUL_SHUTDOWN_GRACE: Duration = Duration::from_secs(20);

/// Minimal router exposing ONLY `GET /v1/metrics`. Served on a separate bind
/// (`metrics_listen`) so Prometheus can scrape while the full API - exec, shell,
/// VM control - stays on its own listener. No other route is mounted, so this port
/// never exposes anything but read-only metrics. When `token` is set the endpoint
/// requires `Authorization: Bearer <token>` (defense in depth on top of any host
/// firewall); when `None` it is unauthenticated (the standard exporter pattern).
pub fn metrics_router<B: VmmBackend + 'static>(
    core: Arc<HuskerCore<B>>,
    token: Option<BearerToken>,
) -> Router {
    let router = Router::new()
        .route("/v1/metrics", get(metrics_handler::<B>))
        .fallback(crate::extract::route_not_found)
        .method_not_allowed_fallback(crate::extract::method_not_allowed);
    let router = if let Some(token) = token {
        let expected = Arc::new(token.header_value());
        router.layer(axum::middleware::from_fn_with_state(
            expected,
            auth_middleware,
        ))
    } else {
        router
    };
    router.with_state(core)
}

/// Serve the metrics-only router on `addr`. The payload is non-sensitive (VM
/// counts, request counters, diagnostic severities); pass `token` for bearer auth
/// and/or restrict network exposure at the host firewall.
pub async fn serve_metrics<B: VmmBackend + 'static>(
    core: Arc<HuskerCore<B>>,
    addr: SocketAddr,
    token: Option<BearerToken>,
) -> std::io::Result<()> {
    let app = metrics_router(core, token);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "husker metrics endpoint listening");
    axum::serve(listener, app)
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
    State(limit): State<Arc<SensitiveRateLimit>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(kind) = is_rate_limited_route(req.method(), req.uri().path()) {
        let client = req
            .extensions()
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip().to_string())
            .unwrap_or_else(|| "unknown".into());
        let key = format!("{kind}:{client}");
        if let RateLimitDecision::Limited { retry_after } = limit.check(&key) {
            metrics().rate_limited_total.fetch_add(1, Ordering::Relaxed);
            // Whole seconds, rounded up, is what the header can carry; never
            // zero, which would invite the caller into a tight retry loop.
            let seconds = retry_after.as_secs_f64().ceil().max(1.0) as u64;
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::RETRY_AFTER, seconds.to_string())],
                error_response_with_hint(
                    "rate_limited",
                    "too many requests to sensitive endpoint",
                    format!("retry after {seconds}s"),
                ),
            )
                .into_response();
        }
    }
    next.run(req).await
}

/// Routes reachable WITHOUT authentication even when a bearer token is
/// configured. Explicit allowlist: everything not listed is protected
/// (deny-by-default), so a newly added route is authenticated by default rather
/// than silently public, and read endpoints (which expose `guest_ip`, `pid`,
/// `rootfs_path` and other topology) are not readable by unauthenticated callers
/// on a token-protected daemon.
fn is_unauthenticated_route(path: &str) -> bool {
    // Liveness/readiness for orchestrators and load balancers.
    path == "/v1/health"
        // Static, browsable API schema (no runtime data).
        || path == "/docs"
        || path.starts_with("/docs/")
        || path.starts_with("/api-docs")
}

pub(crate) fn is_protected_route(path: &str) -> bool {
    !is_unauthenticated_route(path)
}

/// Factory evidence must remain private even when legacy VM routes intentionally
/// run without a bearer token. Refuse the entire factory surface in that mode.
async fn factory_auth_required(
    State(configured): State<bool>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if configured {
        return next.run(req).await;
    }
    (
        StatusCode::FORBIDDEN,
        error_response_with_hint("factory_auth_required",
            "factory execution and evidence require configured bearer authentication",
            "configure a nonempty daemon API token; use authenticated headers, not token-bearing URLs"),
    ).into_response()
}

async fn auth_middleware(
    State(expected): State<Arc<String>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if !is_protected_route(req.uri().path()) {
        return next.run(req).await;
    }

    let provided = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());
    // Constant-time comparison so the response latency does not leak how many
    // leading bytes of a guessed token were correct.
    let authorized = provided.is_some_and(|p| bool::from(p.as_bytes().ct_eq(expected.as_bytes())));
    if authorized {
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
