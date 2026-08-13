//! HTTP request handlers for the husker API.

use std::collections::HashMap;
use std::path::{Component, Path as StdPath};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::Json;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use tracing::{debug, info, warn};

use husker_core::{
    CreateHostGroupRequest, CreatePoolRequest, CreateSecretRequest, CreateServiceRequest,
    CreateSnapshotRequest, CreateVmRequest, CreateVolumeRequest, DiagnosticsReport,
    ExportImageRequest, ExportImageResult, HostGroupRecord, HuskerCore, ImageRecord,
    ImportImageRequest, PoolRecord, RestoreSnapshotRequest, RotateSecretRequest, SecretMetadata,
    ServiceRecord, ShellEvent, SnapshotRecord, VmLifecycleState, VmRecord, VolumeRecord,
};
use husker_vmm::VmmBackend;

use crate::AppState;
use crate::dto::*;
use crate::errors::{
    ErrorResponse, error_response, error_response_with_hint, map_agent_connect_error, map_error,
};
use crate::{ApiPolicy, current_policy, max_vms, metrics};

/// Default agent-readiness wait for exec when the caller does not specify one.
pub(crate) const DEFAULT_EXEC_CONNECT_TIMEOUT_SECS: u64 = 30;
/// Upper bound so a caller cannot pin an exec connection open indefinitely.
pub(crate) const MAX_EXEC_CONNECT_TIMEOUT_SECS: u64 = 600;

/// Resolve the exec agent-connect timeout: boot-mode-aware default when
/// unset (UEFI/cloud VMs boot far slower than microVMs), clamped to
/// `[1, MAX_EXEC_CONNECT_TIMEOUT_SECS]` otherwise.
///
/// Both "uefi" (Linux/QEMU cloud-image) and "efi" (macOS/VZ cloud-image) need
/// the extended timeout because both run cloud-init on first boot.
pub(crate) fn resolve_exec_connect_timeout(requested: Option<u64>, boot_mode: &str) -> Duration {
    let default = if boot_mode == "uefi" || boot_mode == "efi" {
        husker_core::UEFI_READY_TIMEOUT_SECS
    } else {
        DEFAULT_EXEC_CONNECT_TIMEOUT_SECS
    };
    let secs = requested
        .unwrap_or(default)
        .clamp(1, MAX_EXEC_CONNECT_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// Resolve the exec execution bound: the daemon default when unset, the
/// caller's value clamped to `[1, exec_timeout_max_secs]` otherwise.
pub(crate) fn resolve_exec_run_timeout(requested: Option<u64>, policy: &ApiPolicy) -> Duration {
    let secs = requested
        .unwrap_or(policy.exec_timeout_secs)
        .clamp(1, policy.exec_timeout_max_secs.max(1));
    Duration::from_secs(secs)
}

pub(crate) fn normalize_guest_path(path: &str) -> Option<String> {
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

pub(crate) fn is_allowed_guest_path(path: &str, allowlist: &[String]) -> bool {
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

/// Check whether a host path is permitted by the mount allowlist.
///
/// Unlike guest-path gating, an empty allowlist DENIES all mounts. This is the
/// safe default: operators must explicitly opt in to which host directories may
/// be shared with guests.
pub(crate) fn is_allowed_host_path(path: &str, allowlist: &[String]) -> bool {
    if allowlist.is_empty() {
        return false;
    }
    // Reuse normalize_guest_path: host paths are also absolute Unix paths and
    // the same normalisation (strip CurDir, reject ParentDir) applies.
    let Some(normalized) = normalize_guest_path(path) else {
        return false;
    };
    allowlist.iter().any(|prefix| {
        let Some(p) = normalize_guest_path(prefix) else {
            return false;
        };
        normalized == p || normalized.starts_with(&(p + "/"))
    })
}

pub(crate) fn exec_command_allowed(command: &str, policy: &ApiPolicy) -> bool {
    if policy.exec_denylist.iter().any(|c| c == command) {
        return false;
    }
    if policy.exec_allowlist.is_empty() {
        return true;
    }
    policy.exec_allowlist.iter().any(|c| c == command)
}

pub(crate) fn exec_env_allowed(env: &HashMap<String, String>, policy: &ApiPolicy) -> bool {
    if policy.exec_env_allowlist.is_empty() {
        return true;
    }
    env.keys()
        .all(|k| policy.exec_env_allowlist.iter().any(|allowed| allowed == k))
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
pub(crate) async fn health<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
) -> Json<HealthResponse> {
    let (total, running, state_db_ok) = match core.list_vms() {
        Ok(vms) => {
            let total = vms.len() as u64;
            let running = vms
                .iter()
                .filter(|v| v.state == VmLifecycleState::Running)
                .count() as u64;
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
    // Probe the VMM backend rather than mirroring the state DB: on Linux both
    // Firecracker and QEMU require /dev/kvm, so its absence means this daemon
    // cannot actually boot a VM even though the DB is fine. (VZ on macOS has no
    // equivalent cheap probe; it is available on supported hardware.)
    let vmm_ok = {
        #[cfg(target_os = "linux")]
        {
            std::fs::metadata("/dev/kvm").is_ok()
        }
        #[cfg(not(target_os = "linux"))]
        {
            true
        }
    };
    checks.insert(
        "vmm_backend".into(),
        if vmm_ok {
            "ok".into()
        } else {
            "degraded".into()
        },
    );
    #[cfg(feature = "linux-net")]
    checks.insert("network_backend".into(), "ok".into());
    #[cfg(not(feature = "linux-net"))]
    checks.insert("network_backend".into(), "n/a".into());
    let backend = core.backend_kind();
    let base = husker_vmm::Capabilities::for_backend(backend);
    let capabilities = DaemonCapabilities {
        fork: base.fork,
        snapshot: base.snapshot,
        oci_import: cfg!(target_os = "linux"),
        port_forward: true,
        bridged_net: cfg!(feature = "linux-net"),
    };
    // Overall status reflects the subsystem checks rather than being hard-coded
    // "ok", so an orchestrator polling `.status` sees a degraded subsystem.
    let status = if checks.values().any(|v| v == "degraded") {
        "degraded"
    } else {
        "ok"
    };
    Json(HealthResponse {
        status: status.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        vms: VmCounts { total, running },
        checks,
        uptime_seconds: metrics().start.elapsed().as_secs(),
        backend: backend.to_string(),
        capabilities,
    })
}

#[utoipa::path(
    get,
    path = "/v1/profiles",
    tag = "profiles",
    responses(
        (status = 200, description = "Named VM presets configured in the daemon", body = ProfilesResponse)
    )
)]
pub(crate) async fn list_profiles<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
) -> Json<ProfilesResponse> {
    Json(ProfilesResponse {
        profiles: core.profiles().clone(),
    })
}

/// Bound on the diagnostics probe so a wedged filesystem never strands a
/// `/v1/metrics` scrape or a `/v1/diagnostics` request. Well above the normal
/// probe cost (milliseconds), below Prometheus's default scrape timeout.
const DIAGNOSTICS_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[utoipa::path(
    get,
    path = "/v1/diagnostics",
    tag = "health",
    responses(
        (status = 200, description = "Host diagnostic checks (reflink, free space, backend)", body = DiagnosticsReport)
    )
)]
/// GET /v1/diagnostics - host-side health checks (reflink, free space, backend).
pub(crate) async fn diagnostics<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
) -> Json<DiagnosticsReport> {
    // build_diagnostics does blocking fs IO (the reflink probe); run it off the
    // async executor under a timeout. Served from a short-TTL cache shared with
    // /v1/metrics.
    let probe = core.clone();
    let report = match tokio::time::timeout(
        DIAGNOSTICS_PROBE_TIMEOUT,
        tokio::task::spawn_blocking(move || probe.diagnostics()),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            tracing::error!(error = %e, "diagnostics probe task panicked");
            DiagnosticsReport { checks: Vec::new() }
        }
        Err(_) => {
            tracing::error!("diagnostics probe timed out");
            DiagnosticsReport { checks: Vec::new() }
        }
    };
    Json(report)
}

#[utoipa::path(
    get,
    path = "/v1/metrics",
    tag = "health",
    responses(
        (status = 200, description = "Prometheus metrics", content_type = "text/plain")
    )
)]
pub(crate) async fn metrics_handler<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
) -> String {
    // Cheap unrefreshed read - metrics deliberately mirrors the /health path
    // and does not trigger per-VM liveness checks.
    let vms = core.list_vms().unwrap_or_default();
    let total = vms.len() as u64;
    let count = |state: &str| vms.iter().filter(|vm| vm.state == state).count() as u64;
    let services = core.list_services().unwrap_or_default();

    let m = metrics();
    let mut out = format!(
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
        count("running"),
        m.start.elapsed().as_secs(),
    );

    // Build info and per-state gauges.
    out.push_str(&format!(
        "# TYPE husker_build_info gauge\n\
husker_build_info{{version=\"{}\"}} 1\n\
# TYPE husker_vms_stopped gauge\n\
husker_vms_stopped {}\n\
# TYPE husker_vms_failed gauge\n\
husker_vms_failed {}\n",
        env!("CARGO_PKG_VERSION"),
        count("stopped"),
        count("failed"),
    ));

    // Per-service gauges. Service names are husker-validated resource names
    // (lowercase alphanumeric + hyphens, no special characters), so no
    // Prometheus label escaping is needed. The exposition format requires all
    // samples of a metric family to be contiguous, so each family is emitted
    // as its own complete block.
    if !services.is_empty() {
        let mut sorted = services;
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        out.push_str("# TYPE husker_service_desired_instances gauge\n");
        for svc in &sorted {
            out.push_str(&format!(
                "husker_service_desired_instances{{service=\"{}\"}} {}\n",
                svc.name, svc.desired_instances,
            ));
        }
        out.push_str("# TYPE husker_service_current_instances gauge\n");
        for svc in &sorted {
            let current = vms
                .iter()
                .filter(|vm| vm.service_id == Some(svc.id))
                .count() as u64;
            out.push_str(&format!(
                "husker_service_current_instances{{service=\"{}\"}} {}\n",
                svc.name, current,
            ));
        }
    }

    // Host diagnostics as severity gauges (0=ok, 1=warn, 2=fail), served from the
    // TTL cache shared with /v1/diagnostics so frequent scrapes never re-probe the
    // filesystem. Run off the async executor under a timeout: a wedged filesystem
    // drops the diagnostic gauges from this scrape rather than hanging it.
    let probe = core.clone();
    if let Ok(Ok(report)) = tokio::time::timeout(
        DIAGNOSTICS_PROBE_TIMEOUT,
        tokio::task::spawn_blocking(move || probe.diagnostics()),
    )
    .await
    {
        out.push_str(
            "# HELP husker_diagnostic_check_status Host diagnostic check severity (0=ok, 1=warn, 2=fail).\n\
# TYPE husker_diagnostic_check_status gauge\n",
        );
        for check in &report.checks {
            out.push_str(&format!(
                "husker_diagnostic_check_status{{check=\"{}\"}} {}\n",
                escape_prometheus_label(&check.name),
                check.status.severity(),
            ));
        }
    }

    // Idle-policy counters and the currently-suspended gauge.
    let im = core.idle_metrics();
    out.push_str(&format!(
        "# TYPE husker_vm_suspended_total counter\nhusker_vm_suspended_total {}\n\
# TYPE husker_vm_auto_resumed_total counter\n\
husker_vm_auto_resumed_total{{trigger=\"control_plane\"}} {}\n\
husker_vm_auto_resumed_total{{trigger=\"connect\"}} {}\n\
# TYPE husker_vm_reaped_total counter\nhusker_vm_reaped_total {}\n\
# TYPE husker_vms_suspended gauge\nhusker_vms_suspended {}\n",
        im.suspended_total.load(Ordering::Relaxed),
        im.auto_resumed_control_plane_total.load(Ordering::Relaxed),
        im.auto_resumed_connect_total.load(Ordering::Relaxed),
        im.reaped_total.load(Ordering::Relaxed),
        count("suspended"),
    ));

    out
}

/// Escape a string for use as a Prometheus label value (backslash, double-quote,
/// newline), per the text exposition format. Diagnostic check names are static
/// today, but escaping keeps the endpoint well-formed if one ever gains a special
/// character.
fn escape_prometheus_label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
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
pub(crate) async fn list_host_groups<B: VmmBackend + 'static>(
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
pub(crate) async fn create_host_group<B: VmmBackend + 'static>(
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
pub(crate) async fn get_host_group<B: VmmBackend + 'static>(
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
pub(crate) async fn delete_host_group<B: VmmBackend + 'static>(
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
pub(crate) async fn list_services<B: VmmBackend + 'static>(
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
pub(crate) async fn create_service<B: VmmBackend + 'static>(
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
pub(crate) async fn get_service<B: VmmBackend + 'static>(
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
                state: v.state.to_string(),
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
pub(crate) async fn delete_service<B: VmmBackend + 'static>(
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
pub(crate) async fn scale_service<B: VmmBackend + 'static>(
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
pub(crate) async fn list_images<B: VmmBackend + 'static>(
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
pub(crate) async fn import_image<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Json(req): Json<ImportImageRequest>,
) -> Result<(StatusCode, Json<ImageResponse>), (StatusCode, Json<ErrorResponse>)> {
    let image = core.import_image(req).await.map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(image_to_response(image))))
}

#[utoipa::path(
    post,
    path = "/v1/images/import-oci",
    tag = "images",
    request_body = ImportOciRequest,
    responses(
        (status = 201, description = "OCI image imported as a rootfs", body = ImageResponse),
        (status = 409, description = "Image already exists", body = ErrorResponse),
        (status = 400, description = "Invalid reference or pull failed", body = ErrorResponse)
    )
)]
pub(crate) async fn import_oci_image<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Json(req): Json<ImportOciRequest>,
) -> Result<(StatusCode, Json<ImageResponse>), (StatusCode, Json<ErrorResponse>)> {
    let image = core
        .import_oci_image(&req.name, &req.reference)
        .await
        .map_err(map_error)?;
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
pub(crate) async fn get_image<B: VmmBackend + 'static>(
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
pub(crate) async fn delete_image<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    core.delete_image(&name).await.map_err(map_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/v1/volumes",
    tag = "volumes",
    responses(
        (status = 200, description = "List of volumes", body = Vec<VolumeResponse>),
        (status = 500, description = "Internal error", body = ErrorResponse)
    )
)]
pub(crate) async fn list_volumes<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
) -> Result<Json<Vec<VolumeResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let volumes = core.list_volumes().map_err(map_error)?;
    Ok(Json(
        volumes
            .into_iter()
            .map(volume_to_response)
            .collect::<Vec<_>>(),
    ))
}

#[utoipa::path(
    post,
    path = "/v1/volumes",
    tag = "volumes",
    request_body = CreateVolumeApiRequest,
    responses(
        (status = 201, description = "Volume created", body = VolumeResponse),
        (status = 409, description = "Volume already exists", body = ErrorResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse)
    )
)]
pub(crate) async fn create_volume<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Json(req): Json<CreateVolumeApiRequest>,
) -> Result<(StatusCode, Json<VolumeResponse>), (StatusCode, Json<ErrorResponse>)> {
    let volume = core
        .create_volume(CreateVolumeRequest {
            name: req.name,
            size_bytes: req.size_bytes,
        })
        .await
        .map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(volume_to_response(volume))))
}

#[utoipa::path(
    get,
    path = "/v1/volumes/{name}",
    tag = "volumes",
    params(("name" = String, Path, description = "Volume name")),
    responses(
        (status = 200, description = "Volume details", body = VolumeResponse),
        (status = 404, description = "Volume not found", body = ErrorResponse)
    )
)]
pub(crate) async fn get_volume<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<Json<VolumeResponse>, (StatusCode, Json<ErrorResponse>)> {
    let volume = core.get_volume(&name).map_err(map_error)?;
    Ok(Json(volume_to_response(volume)))
}

#[utoipa::path(
    delete,
    path = "/v1/volumes/{name}",
    tag = "volumes",
    params(("name" = String, Path, description = "Volume name")),
    responses(
        (status = 204, description = "Volume deleted"),
        (status = 404, description = "Volume not found", body = ErrorResponse),
        (status = 409, description = "Volume is attached to a VM", body = ErrorResponse)
    )
)]
pub(crate) async fn delete_volume<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    core.delete_volume(&name).await.map_err(map_error)?;
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
pub(crate) async fn export_image<B: VmmBackend + 'static>(
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
pub(crate) async fn list_secrets<B: VmmBackend + 'static>(
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
pub(crate) async fn create_secret<B: VmmBackend + 'static>(
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
pub(crate) async fn get_secret<B: VmmBackend + 'static>(
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
pub(crate) async fn reveal_secret<B: VmmBackend + 'static>(
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
pub(crate) async fn rotate_secret<B: VmmBackend + 'static>(
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
pub(crate) async fn delete_secret<B: VmmBackend + 'static>(
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
pub(crate) async fn list_snapshots<B: VmmBackend + 'static>(
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
pub(crate) async fn create_snapshot<B: VmmBackend + 'static>(
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
pub(crate) async fn get_snapshot<B: VmmBackend + 'static>(
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
pub(crate) async fn delete_snapshot<B: VmmBackend + 'static>(
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
pub(crate) async fn restore_snapshot<B: VmmBackend + 'static>(
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
pub(crate) async fn list_vms<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
) -> Result<Json<Vec<VmResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let vms = core.list_vms_refreshed().await.map_err(map_error)?;
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
pub(crate) async fn create_vm<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Json(req): Json<CreateVmRequest>,
) -> Result<(StatusCode, Json<VmResponse>), (StatusCode, Json<ErrorResponse>)> {
    let policy = current_policy();

    // Admission control: cap the number of VMs a client can create so a single
    // caller cannot exhaust host CPU/memory by creating VMs without bound.
    if let Some(max) = max_vms() {
        let current = core.list_vms().map(|v| v.len()).unwrap_or(0);
        if current >= max {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                error_response_with_hint(
                    "vm_limit_reached",
                    format!("VM limit reached ({current}/{max})"),
                    "destroy unused VMs or raise max_vms in the daemon config",
                ),
            ));
        }
    }

    for (i, spec) in req.mounts.iter().enumerate() {
        let share = husker_core::parse_mount_spec(spec, i).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                error_response_with_hint(
                    "invalid_mount_spec",
                    e,
                    "use the form host:guest[:ro] with absolute paths",
                ),
            )
        })?;
        let host_str = share.host.to_string_lossy();
        if !is_allowed_host_path(&host_str, &policy.allowed_mount_host_paths) {
            return Err((
                StatusCode::FORBIDDEN,
                error_response_with_hint(
                    "policy_mount_path_denied",
                    format!(
                        "host path '{}' is not allowed for mount",
                        share.host.display()
                    ),
                    "set allowed_mount_host_paths in daemon config",
                ),
            ));
        }
    }

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
pub(crate) async fn get_vm<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<Json<VmResponse>, (StatusCode, Json<ErrorResponse>)> {
    let record = core.get_vm_refreshed(&name).await.map_err(map_error)?;
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
pub(crate) async fn stop_vm<B: VmmBackend + 'static>(
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
pub(crate) async fn pause_vm<B: VmmBackend + 'static>(
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
pub(crate) async fn resume_vm<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    core.resume_vm(&name).await.map_err(map_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    put,
    path = "/v1/vms/{name}/balloon",
    tag = "vms",
    params(("name" = String, Path, description = "VM name")),
    request_body = BalloonRequest,
    responses(
        (status = 204, description = "Balloon resized"),
        (status = 400, description = "VM was not created with --balloon", body = ErrorResponse),
        (status = 404, description = "VM not found", body = ErrorResponse),
        (status = 409, description = "VM is not running", body = ErrorResponse)
    )
)]
pub(crate) async fn set_balloon<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
    Json(req): Json<BalloonRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    core.set_balloon(&name, req.amount_mib)
        .await
        .map_err(map_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/v1/vms/{name}/suspend",
    tag = "vms",
    params(("name" = String, Path, description = "VM name")),
    responses(
        (status = 204, description = "VM suspended"),
        (status = 404, description = "VM not found", body = ErrorResponse),
        (status = 409, description = "Invalid VM state", body = ErrorResponse)
    )
)]
pub(crate) async fn suspend_vm<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    core.suspend_vm(&name).await.map_err(map_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/v1/vms/{name}/fork",
    tag = "vms",
    params(("name" = String, Path, description = "Source VM name (must be suspended)")),
    request_body = ForkRequest,
    responses(
        (status = 201, description = "Fork created and running", body = VmResponse),
        (status = 404, description = "Source VM not found", body = ErrorResponse),
        (status = 409, description = "Source not suspended or fork name taken", body = ErrorResponse)
    )
)]
pub(crate) async fn fork_vm<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
    Json(req): Json<ForkRequest>,
) -> Result<(StatusCode, Json<VmResponse>), (StatusCode, Json<ErrorResponse>)> {
    let record = core
        .fork_vm(&name, &req.fork_name)
        .await
        .map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(record_to_response(record))))
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
pub(crate) async fn destroy_vm<B: VmmBackend + 'static>(
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
pub(crate) async fn exec_vm<B: VmmBackend + 'static>(
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
    // Resolve secret references to plaintext inside the daemon (it holds the
    // key), so only secret NAMES are ever sent by the client - the value never
    // appears in argv, the process table, or shell history. A secret overrides
    // `env` on a key clash.
    let mut resolved_env = req.env.clone();
    for (env_key, secret_name) in &req.secret_env {
        let revealed = core.reveal_secret(secret_name).map_err(map_error)?;
        resolved_env.insert(env_key.clone(), revealed.value);
    }
    if !exec_env_allowed(&resolved_env, &policy) {
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
        env_count = resolved_env.len(),
        secret_count = req.secret_env.len(),
        has_working_dir = req.working_dir.is_some()
    );
    let record = core.get_vm(&name).map_err(map_error)?;
    // Race-tolerant connect: exec callers often hit the agent within a second
    // or two of VM boot, before the guest has bound vsock port 52. A short
    // retry window eliminates the need for client-side polling.
    let mut conn = core
        .agent_connect_ready(
            &name,
            resolve_exec_connect_timeout(req.connect_timeout_secs, &record.boot_mode),
        )
        .await
        .map_err(map_agent_connect_error)?;
    let args: Vec<&str> = req.args.iter().map(String::as_str).collect();
    let env: Vec<(&str, &str)> = resolved_env
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    // The guest agent enforces the run timeout itself (so it returns the partial
    // output with exit 124 instead of the daemon cancelling and losing it). The
    // daemon adds a grace window on top, so a genuinely unresponsive agent (not
    // even answering the timeout) still bounds the request.
    let run_timeout = resolve_exec_run_timeout(req.timeout_secs, &policy);
    let grace = run_timeout + Duration::from_secs(30);
    let result = tokio::time::timeout(
        grace,
        conn.exec_with_timeout(
            &req.command,
            &args,
            req.working_dir.as_deref(),
            &env,
            Some(run_timeout.as_secs()),
        ),
    )
    .await
    .map_err(|_| {
        (
            StatusCode::REQUEST_TIMEOUT,
            error_response_with_hint(
                "exec_timeout",
                "command execution timed out and the agent did not respond",
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
        (status = 501, description = "Guest agent cannot read from a byte offset", body = ErrorResponse),
        (status = 503, description = "Agent not ready", body = ErrorResponse)
    )
)]
pub(crate) async fn read_file_handler<B: VmmBackend + 'static>(
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
    let read = conn
        .read_file_range(&req.path, req.offset, req.len)
        .await
        .map_err(|e| map_error(e.into()))?;
    let data = read.data;
    if data.len() > policy.max_file_read_bytes {
        // The limit bounds one response, so a ranged caller stays under it by
        // asking for smaller slices. The hint says so, because "increase the
        // policy" is the wrong lesson for a client that can simply chunk.
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            error_response_with_hint(
                "read_file_too_large",
                format!(
                    "read result exceeds limit ({} bytes > {} bytes)",
                    data.len(),
                    policy.max_file_read_bytes
                ),
                "request a byte range with offset/len, or increase max_file_read_bytes policy",
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
        total_size: read.total_size,
        modified_nanos: read.modified_nanos,
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
pub(crate) async fn write_file_handler<B: VmmBackend + 'static>(
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
                "split the file and write the parts, or raise api_max_file_write_bytes in the daemon config",
            ),
        ));
    }
    let mut conn = core
        .agent_connect(&name)
        .await
        .map_err(map_agent_connect_error)?;
    let bytes_written = conn
        .write_file(&req.path, &data, req.mode, req.append)
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
pub(crate) async fn shell_ws<B: VmmBackend + 'static>(
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

    // Connect to the guest agent via bounded readiness wait so an interactive
    // shell opened immediately after VM creation does not race the agent bind.
    let mut conn = match core
        .agent_connect_ready(&name, std::time::Duration::from_secs(30))
        .await
    {
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

// ── Ready Handler ────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/vms/{name}/ready",
    tag = "vms",
    params(("name" = String, Path, description = "VM name")),
    responses(
        (status = 200, description = "Agent readiness", body = ReadyResponse),
        (status = 404, description = "VM not found", body = ErrorResponse),
        (status = 409, description = "VM not running", body = ErrorResponse)
    )
)]
pub(crate) async fn get_ready<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<Json<ReadyResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Refresh liveness first so a VM whose process exited on its own has its
    // state corrected in the DB. probe_ready then finds the updated state via
    // its internal lookup and returns Err(InvalidState) -> 409, causing
    // `husker wait` to fail fast rather than spin to timeout.
    core.get_vm_refreshed(&name).await.map_err(map_error)?;
    let ready = core.probe_ready(&name).await.map_err(map_error)?;
    Ok(Json(ReadyResponse { vm: name, ready }))
}

// ── Guest Info Handler ───────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/vms/{name}/guest-info",
    tag = "vms",
    params(("name" = String, Path, description = "VM name")),
    responses(
        (status = 200, description = "Guest agent network and protocol info", body = GuestInfoResponse),
        (status = 404, description = "VM not found", body = ErrorResponse),
        (status = 503, description = "Agent not ready", body = ErrorResponse)
    )
)]
pub(crate) async fn get_guest_info<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<Json<GuestInfoResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut conn = core
        .agent_connect(&name)
        .await
        .map_err(map_agent_connect_error)?;
    let info = conn.guest_info().await.map_err(|e| map_error(e.into()))?;
    Ok(Json(GuestInfoResponse {
        ipv4: info.ipv4,
        protocol_version: info.protocol_version,
    }))
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
pub(crate) async fn get_logs<B: VmmBackend + 'static>(
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
        "userdata" => (
            core.userdata_log_path(&name).map_err(map_error)?,
            "userdata",
        ),
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
pub(crate) fn tail_lines(content: &str, n: u64) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(n as usize);
    let mut result = lines[start..].join("\n");
    if content.ends_with('\n') && !result.is_empty() {
        result.push('\n');
    }
    result
}

// ── Port Forward Handlers ─────────────────────────────────────────────

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
pub(crate) async fn add_port_forward_handler<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
    Json(req): Json<AddPortForwardRequest>,
) -> Result<(StatusCode, Json<PortForwardResponse>), (StatusCode, Json<ErrorResponse>)> {
    let bind_addr = match req.bind_addr.as_deref() {
        Some(s) => Some(s.parse::<std::net::IpAddr>().map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                error_response("invalid_argument", format!("invalid bind address: {s}")),
            )
        })?),
        None => None,
    };
    let rec = core
        .add_port_forward(&name, req.host_port, req.guest_port, bind_addr)
        .await
        .map_err(map_error)?;
    Ok((
        StatusCode::CREATED,
        Json(PortForwardResponse {
            host_port: rec.host_port,
            guest_port: rec.guest_port,
            protocol: rec.protocol,
            bind_addr: rec.bind_addr,
            created_at: rec.created_at.to_rfc3339(),
        }),
    ))
}

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
pub(crate) async fn list_port_forwards_handler<B: VmmBackend + 'static>(
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
                bind_addr: pf.bind_addr,
                created_at: pf.created_at.to_rfc3339(),
            })
            .collect(),
    ))
}

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
pub(crate) async fn remove_port_forward_handler<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path((name, host_port)): Path<(String, u16)>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    core.remove_port_forward(&name, host_port)
        .await
        .map_err(map_error)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Error Mapping ─────────────────────────────────────────────────────

// ── Pool handlers ─────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/pools",
    tag = "pools",
    responses(
        (status = 200, description = "List of hot pools", body = Vec<PoolResponse>),
        (status = 500, description = "Internal error", body = ErrorResponse)
    )
)]
pub(crate) async fn list_pools<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
) -> Result<Json<Vec<PoolResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let pools = core.list_pools().map_err(map_error)?;
    Ok(Json(pools.into_iter().map(pool_to_response).collect()))
}

#[utoipa::path(
    post,
    path = "/v1/pools",
    tag = "pools",
    request_body = CreatePoolRequest,
    responses(
        (status = 201, description = "Pool created", body = PoolResponse),
        (status = 409, description = "Pool already exists", body = ErrorResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse)
    )
)]
pub(crate) async fn create_pool<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Json(req): Json<CreatePoolRequest>,
) -> Result<(StatusCode, Json<PoolResponse>), (StatusCode, Json<ErrorResponse>)> {
    let pool = core.create_pool(req).await.map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(pool_to_response(pool))))
}

#[utoipa::path(
    get,
    path = "/v1/pools/{name}",
    tag = "pools",
    params(("name" = String, Path, description = "Pool name")),
    responses(
        (status = 200, description = "Pool details", body = PoolResponse),
        (status = 404, description = "Pool not found", body = ErrorResponse)
    )
)]
pub(crate) async fn get_pool<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<Json<PoolResponse>, (StatusCode, Json<ErrorResponse>)> {
    let pool = core.get_pool(&name).map_err(map_error)?;
    Ok(Json(pool_to_response(pool)))
}

#[utoipa::path(
    delete,
    path = "/v1/pools/{name}",
    tag = "pools",
    params(("name" = String, Path, description = "Pool name")),
    responses(
        (status = 200, description = "Pool deleted", body = PoolDeleteResponse),
        (status = 404, description = "Pool not found", body = ErrorResponse)
    )
)]
pub(crate) async fn delete_pool<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<Json<PoolDeleteResponse>, (StatusCode, Json<ErrorResponse>)> {
    core.delete_pool(&name).await.map_err(map_error)?;
    Ok(Json(PoolDeleteResponse { name }))
}

#[utoipa::path(
    post,
    path = "/v1/pools/{name}/checkout",
    tag = "pools",
    params(("name" = String, Path, description = "Pool name")),
    request_body = CheckoutPoolRequest,
    responses(
        (status = 201, description = "Fresh VM forked from the pool", body = VmResponse),
        (status = 404, description = "Pool not found", body = ErrorResponse)
    )
)]
pub(crate) async fn checkout_pool<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
    Json(req): Json<CheckoutPoolRequest>,
) -> Result<(StatusCode, Json<VmResponse>), (StatusCode, Json<ErrorResponse>)> {
    let vm = core
        .checkout_pool(&name, req.vm_name.as_deref())
        .await
        .map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(record_to_response(vm))))
}

fn pool_to_response(r: PoolRecord) -> PoolResponse {
    PoolResponse {
        id: r.id.to_string(),
        name: r.name,
        template_vm_id: r.template_vm_id.to_string(),
        rootfs_path: r.rootfs_path,
        kernel_path: r.kernel_path,
        initrd_path: r.initrd_path,
        vcpu_count: r.vcpu_count,
        mem_size_mib: r.mem_size_mib,
        created_at: r.created_at.to_rfc3339(),
        updated_at: r.updated_at.to_rfc3339(),
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
        .map(|vs| {
            vs.iter()
                .filter(|v| v.state == VmLifecycleState::Running)
                .count() as u32
        })
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
        cloud_image: r.cloud_image,
        disk_size: r.disk_size,
        balloon: r.balloon,
        volume: r.volume,
    }
}

fn image_to_response(r: ImageRecord) -> ImageResponse {
    ImageResponse {
        id: r.id.to_string(),
        name: r.name,
        source_path: r.source_path,
        file_path: r.file_path,
        format: r.format,
        kind: r.kind,
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

pub(crate) fn record_to_response(r: VmRecord) -> VmResponse {
    VmResponse {
        id: r.id.to_string(),
        name: r.name,
        state: r.state.to_string(),
        pid: r.pid,
        vcpu_count: r.vcpu_count,
        mem_size_mib: r.mem_size_mib,
        vsock_cid: r.vsock_cid,
        host_ip: r.host_ip,
        guest_ip: r.guest_ip,
        created_at: r.created_at.to_rfc3339(),
        updated_at: r.updated_at.to_rfc3339(),
        userdata_status: r.userdata_status,
        vmm: r.vmm.to_string(),
        boot_mode: r.boot_mode,
        rootfs_path: r.rootfs_path,
        kernel_path: r.kernel_path,
        volume: r.volume,
        network: r.network.to_string(),
        idle_timeout_secs: r.idle_timeout_secs,
        suspend_ttl_secs: r.suspend_ttl_secs,
        // Only surface auto_resume for VMs that opted into the policy, so the payload
        // stays tidy for the common (no-policy) case.
        auto_resume: r.idle_timeout_secs.is_some().then_some(r.auto_resume),
        suspended_at: r.suspended_at.map(|d| d.to_rfc3339()),
    }
}

fn volume_to_response(r: VolumeRecord) -> VolumeResponse {
    VolumeResponse {
        id: r.id.to_string(),
        name: r.name,
        file_path: r.file_path,
        size_bytes: r.size_bytes,
        created_at: r.created_at.to_rfc3339(),
    }
}
