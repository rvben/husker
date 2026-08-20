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
    ApiDoc, PortForwardApiDoc, REQUEST_COUNTER, RateLimitDecision, current_policy, metrics,
    rate_limiter,
};

pub(crate) fn is_rate_limited_route(method: &Method, path: &str) -> Option<&'static str> {
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
/// before forcing the server to stop. Kept below the caller's VM-drain budget and
/// systemd's default `TimeoutStopSec` so shutdown stays bounded end to end.
const GRACEFUL_SHUTDOWN_GRACE: Duration = Duration::from_secs(20);

/// Minimal router exposing ONLY `GET /v1/metrics`. Served on a separate bind
/// (`metrics_listen`) so Prometheus can scrape while the full API - exec, shell,
/// VM control - stays on its own listener. No other route is mounted, so this port
/// never exposes anything but read-only metrics. When `token` is set the endpoint
/// requires `Authorization: Bearer <token>` (defense in depth on top of any host
/// firewall); when `None` it is unauthenticated (the standard exporter pattern).
pub fn metrics_router<B: VmmBackend + 'static>(
    core: Arc<HuskerCore<B>>,
    token: Option<String>,
) -> Router {
    let router = Router::new().route("/v1/metrics", get(metrics_handler::<B>));
    let router = if let Some(token) = token {
        let expected = Arc::new(format!("Bearer {token}"));
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
    token: Option<String>,
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
        if let RateLimitDecision::Limited { retry_after } =
            rate_limiter().check(&key, policy.sensitive_rate_limit_per_minute)
        {
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
