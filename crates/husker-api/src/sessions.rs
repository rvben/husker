//! Detached guest sessions and authenticated TCP transport for local previews.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use husker_agent_proto::{SessionEventsResponse, SessionInfo, SessionStartRequest};
use husker_core::{AgentConnection, AgentError, HuskerCore};
use husker_vmm::VmmBackend;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use utoipa::OpenApi;

use crate::errors::{error_response_with_hint, map_agent_connect_error, map_error};
use crate::{AppState, ErrorResponse, ExecRequest, current_policy};

type Failure = (StatusCode, Json<ErrorResponse>);

async fn connection<B: VmmBackend + 'static>(
    core: &HuskerCore<B>,
    name: &str,
    requested_timeout: Option<u64>,
) -> Result<AgentConnection<B::VsockStream>, Failure> {
    let vm = core.get_vm(name).map_err(map_error)?;
    let timeout = crate::handlers::resolve_exec_connect_timeout(requested_timeout, vm.boot_mode);
    core.agent_connect_ready(name, timeout)
        .await
        .map_err(map_agent_connect_error)
}

fn session_error(error: AgentError) -> Failure {
    if matches!(error, AgentError::NotReady { .. }) {
        return (
            StatusCode::GATEWAY_TIMEOUT,
            error_response_with_hint(
                "session_timeout",
                error.to_string(),
                "a start may already have been accepted; list sessions and inspect their status before retrying",
            ),
        );
    }
    let message = error.to_string();
    let (status, kind) = if message.contains("session not found") {
        (StatusCode::NOT_FOUND, "session_not_found")
    } else if message.contains("invalid session id") {
        (StatusCode::BAD_REQUEST, "invalid_session_id")
    } else if message.contains("does not support sessions") {
        (StatusCode::NOT_IMPLEMENTED, "guest_capability_missing")
    } else if message.contains("too many running") {
        (StatusCode::TOO_MANY_REQUESTS, "session_capacity_exhausted")
    } else if message.contains("retention limit") || message.contains("cancel the running") {
        (StatusCode::CONFLICT, "session_conflict")
    } else {
        (StatusCode::BAD_GATEWAY, "session_failed")
    };
    (
        status,
        error_response_with_hint(
            kind,
            message,
            "inspect guest status; refresh older images with the current guest agent",
        ),
    )
}

#[utoipa::path(post, path = "/v1/vms/{name}/sessions", tag = "sessions",
    params(("name" = String, Path)), request_body = ExecRequest,
    responses((status = 201, body = SessionInfo, description = "Detached command started"),
        (status = 403, body = ErrorResponse, description = "Execution policy denied")))]
pub(crate) async fn start<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
    Json(request): Json<ExecRequest>,
) -> Result<(StatusCode, Json<SessionInfo>), Failure> {
    // Acceptance transfers the whole start/monitor handoff to the daemon.
    // A cancelled HTTP future must not orphan a successfully detached guest
    // command without its host idle guard.
    tokio::spawn(start_owned(core, name, request))
        .await
        .map_err(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                error_response_with_hint(
                    "session_start_failed",
                    error.to_string(),
                    "inspect daemon logs",
                ),
            )
        })?
}

async fn start_owned<B: VmmBackend + 'static>(
    core: AppState<B>,
    name: String,
    request: ExecRequest,
) -> Result<(StatusCode, Json<SessionInfo>), Failure> {
    let policy = current_policy();
    let env = crate::handlers::resolve_exec_environment(core.as_ref(), &request, &policy)
        .map_err(|e| *e)?;
    let timeout_secs = request
        .timeout_secs
        .unwrap_or(policy.exec_timeout_secs)
        .clamp(1, policy.exec_timeout_max_secs.clamp(1, 86400));
    let mut conn = connection(&core, &name, request.connect_timeout_secs).await?;
    let session = conn
        .session_start(SessionStartRequest {
            id: uuid::Uuid::new_v4().to_string(),
            exec: husker_agent_proto::ExecRequest {
                command: request.command,
                args: request.args,
                working_dir: request.working_dir,
                env: env.into_iter().collect(),
                timeout_secs: Some(timeout_secs),
            },
        })
        .await
        .map_err(session_error)?;
    crate::metrics()
        .detached_sessions_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    tracing::info!(audit = "detached_session_started", vm = %name, session = %session.id,
        command = %session.command, timeout_secs, "guest owns detached command");
    // A separate guard survives a replaced transport after suspend/resume.
    // Guest-owned status and logs never depend on the initiating HTTP client.
    let vm_id = core.get_vm(&name).map_err(map_error)?.id;
    let guard = core.begin_session(vm_id);
    let id = session.id.clone();
    let watcher_core = core.clone();
    tokio::spawn(async move {
        let mut guard = Some(guard);
        let mut conn = Some(conn);
        let mut failed_since = None;
        loop {
            let Ok(vm) = watcher_core.get_vm(&name) else {
                break;
            };
            if vm.id != vm_id {
                break;
            }
            match vm.state {
                husker_core::VmLifecycleState::Suspended
                | husker_core::VmLifecycleState::Suspending => {
                    // Observing a session must not undo an explicit suspend.
                    conn = None;
                    // A paused command must not defeat the configured suspend TTL.
                    guard = None;
                    failed_since = None;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                husker_core::VmLifecycleState::Running => {}
                _ => break,
            }
            if guard.is_none() {
                guard = Some(watcher_core.begin_session(vm_id));
            }
            if conn.is_none() {
                conn =
                    tokio::time::timeout(Duration::from_secs(5), watcher_core.agent_connect(&name))
                        .await
                        .ok()
                        .and_then(Result::ok);
            }
            let result = match &mut conn {
                Some(connection) => {
                    tokio::time::timeout(Duration::from_secs(5), connection.session_get(&id))
                        .await
                        .ok()
                }
                None => None,
            };
            match result {
                Some(Ok(info)) if info.state != husker_agent_proto::SessionState::Running => {
                    tracing::info!(audit = "detached_session_result", vm = %name, session = %id,
                        state = ?info.state, exit_code = ?info.exit_code,
                        output_truncated = info.output_truncated);
                    break;
                }
                Some(Ok(_)) => failed_since = None,
                Some(Err(error)) if error.to_string().contains("session not found") => break,
                None | Some(Err(_)) => {
                    // A timed-out framed read cannot safely be reused.
                    conn = None;
                    let since = failed_since.get_or_insert_with(tokio::time::Instant::now);
                    if since.elapsed() >= Duration::from_secs(30) {
                        tracing::warn!(vm = %name, session = %id, "lost detached session monitoring; releasing idle guard");
                        break;
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    Ok((StatusCode::CREATED, Json(session)))
}

#[utoipa::path(get, path = "/v1/vms/{name}/sessions", tag = "sessions", params(("name" = String, Path)),
    responses((status = 200, body = [SessionInfo], description = "Guest sessions")))]
pub(crate) async fn list<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path(name): Path<String>,
) -> Result<Json<Vec<SessionInfo>>, Failure> {
    Ok(Json(
        connection(&core, &name, None)
            .await?
            .session_list()
            .await
            .map_err(session_error)?,
    ))
}

#[utoipa::path(get, path = "/v1/vms/{name}/sessions/{id}", tag = "sessions", params(("name" = String, Path), ("id" = String, Path)),
    responses((status = 200, body = SessionInfo, description = "Session status"), (status = 404, body = ErrorResponse, description = "Session not found")))]
pub(crate) async fn get<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path((name, id)): Path<(String, String)>,
) -> Result<Json<SessionInfo>, Failure> {
    Ok(Json(
        connection(&core, &name, None)
            .await?
            .session_get(&id)
            .await
            .map_err(session_error)?,
    ))
}

#[derive(Deserialize, Default)]
pub(crate) struct Cursor {
    #[serde(default)]
    after: u64,
}

#[utoipa::path(get, path = "/v1/vms/{name}/sessions/{id}/events", tag = "sessions", params(("name" = String, Path), ("id" = String, Path), ("after" = Option<u64>, Query)),
    responses((status = 200, body = SessionEventsResponse, description = "Bounded binary-safe event page")))]
pub(crate) async fn events<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path((name, id)): Path<(String, String)>,
    Query(cursor): Query<Cursor>,
) -> Result<Json<SessionEventsResponse>, Failure> {
    Ok(Json(
        connection(&core, &name, None)
            .await?
            .session_events(&id, cursor.after)
            .await
            .map_err(session_error)?,
    ))
}

#[utoipa::path(post, path = "/v1/vms/{name}/sessions/{id}/cancel", tag = "sessions", params(("name" = String, Path), ("id" = String, Path)),
    responses((status = 200, body = SessionInfo, description = "Cancellation requested; poll status for completion")))]
pub(crate) async fn cancel<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path((name, id)): Path<(String, String)>,
) -> Result<Json<SessionInfo>, Failure> {
    Ok(Json(
        connection(&core, &name, None)
            .await?
            .session_cancel(&id)
            .await
            .map_err(session_error)?,
    ))
}

#[utoipa::path(delete, path = "/v1/vms/{name}/sessions/{id}", tag = "sessions", params(("name" = String, Path), ("id" = String, Path)),
    responses((status = 204, description = "Finished session and its logs removed")))]
pub(crate) async fn remove<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path((name, id)): Path<(String, String)>,
) -> Result<StatusCode, Failure> {
    connection(&core, &name, None)
        .await?
        .session_remove(&id)
        .await
        .map_err(session_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/v1/vms/{name}/tunnel/{port}", tag = "previews", params(("name" = String, Path), ("port" = u16, Path)),
    responses((status = 101, description = "Authenticated binary WebSocket tunnel to guest loopback")))]
pub(crate) async fn tunnel<B: VmmBackend + 'static>(
    State(core): State<AppState<B>>,
    Path((name, port)): Path<(String, u16)>,
    ws: WebSocketUpgrade,
) -> Result<Response, Failure> {
    if port == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            error_response_with_hint(
                "invalid_port",
                "port must be nonzero",
                "choose the guest application port",
            ),
        ));
    }
    static CAPACITY: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    let permit = CAPACITY
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(128)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            (
                StatusCode::TOO_MANY_REQUESTS,
                error_response_with_hint(
                    "preview_capacity_exhausted",
                    "too many preview connections",
                    "close unused previews and retry",
                ),
            )
        })?;
    let conn = connection(&core, &name, None).await?;
    let stream = tokio::time::timeout(Duration::from_secs(10), conn.tunnel(port))
        .await
        .map_err(|_| {
            (
                StatusCode::GATEWAY_TIMEOUT,
                error_response_with_hint(
                    "preview_connect_timeout",
                    "guest preview connection timed out",
                    "check the guest application",
                ),
            )
        })?
        .map_err(session_error)?;
    Ok(ws
        .max_message_size(64 * 1024)
        .max_frame_size(64 * 1024)
        .on_upgrade(move |socket| async move {
            crate::metrics()
                .preview_connections_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let _permit = permit;
            relay(socket, stream, core).await;
        }))
}

async fn relay<B: VmmBackend + 'static>(
    socket: WebSocket,
    guest: husker_core::agent_client::AgentTunnel<B::VsockStream>,
    _core: Arc<HuskerCore<B>>,
) {
    let (mut sink, mut source) = socket.split();
    let (mut reader, mut writer) = tokio::io::split(guest);
    // Separate pumps keep both directions progressing under backpressure.
    // Four 16 KiB frames bound guest output buffering for a slow browser.
    let (output, mut messages) = tokio::sync::mpsc::channel(4);
    let control = output.clone();
    let input = async {
        let mut ended = false;
        while let Some(Ok(message)) = source.next().await {
            match message {
                Message::Binary(bytes) if !ended => writer.write_all(&bytes).await.ok()?,
                Message::Text(text) if text == "eof" && !ended => {
                    writer.shutdown().await.ok()?;
                    ended = true;
                }
                Message::Ping(bytes) => control.send(Message::Pong(bytes)).await.ok()?,
                Message::Pong(_) => {}
                _ => break,
            }
        }
        Some(())
    };
    let response = async {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let n = reader.read(&mut buffer).await.ok()?;
            if n == 0 {
                break;
            }
            output
                .send(Message::Binary(buffer[..n].to_vec().into()))
                .await
                .ok()?;
        }
        output.send(Message::Close(None)).await.ok()?;
        // The idle guard covers delivery of the final queued response frame.
        std::future::pending::<Option<()>>().await
    };
    let flush = async {
        while let Some(message) = messages.recv().await {
            let closing = matches!(message, Message::Close(_));
            sink.send(message).await.ok()?;
            if closing {
                break;
            }
        }
        Some(())
    };
    tokio::select! { _ = input => {}, _ = response => {}, _ = flush => {} }
}

#[derive(OpenApi)]
#[openapi(
    paths(start, list, get, events, cancel, remove, tunnel),
    components(schemas(
        SessionInfo,
        husker_agent_proto::SessionState,
        husker_agent_proto::SessionEvent,
        SessionEventsResponse
    ))
)]
pub(crate) struct SessionApiDoc;
