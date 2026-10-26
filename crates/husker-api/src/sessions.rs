//! Detached guest sessions and authenticated TCP transport for local previews.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket};
use axum::http::StatusCode;
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use husker_agent_proto::{AgentErrorCode, SessionEventsResponse, SessionInfo, SessionStartRequest};
use husker_core::{AgentError, HuskerCore};
use husker_vmm::VmmBackend;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use utoipa::OpenApi;

use crate::errors::{Failure, error_response_with_hint, map_error};
use crate::extract::{Json, Path, Query, WebSocketUpgrade};
use crate::handlers::agent_connection;
use crate::{ApiPolicy, ErrorResponse, ExecRequest, SharedCore};

/// The REST answer for a session or preview request the guest side could not
/// serve. Classified refusals map by their code; a refusal without one is a
/// guest-side failure the caller can only inspect, not correct.
fn session_error(error: AgentError) -> Failure {
    const UNCLASSIFIED: (StatusCode, &str, &str) = (
        StatusCode::BAD_GATEWAY,
        "session_failed",
        "inspect guest status; refresh older images with the current guest agent",
    );
    let (status, kind, hint) = match &error {
        // Same status and kind as every other agent deadline in this API; the
        // hint differs because a start can have landed before the deadline.
        AgentError::NotReady { .. } => (
            StatusCode::SERVICE_UNAVAILABLE,
            "agent_not_ready",
            "the guest did not answer within the transport deadline; a session start may already \
             have been accepted, so list sessions and inspect their status before retrying one",
        ),
        AgentError::SessionsUnsupported { .. } => (
            StatusCode::NOT_IMPLEMENTED,
            "guest_capability_missing",
            "rebuild or re-import the VM's image with the current guest agent",
        ),
        AgentError::Rejected { code, .. } => match code {
            AgentErrorCode::InvalidSessionId => (
                StatusCode::BAD_REQUEST,
                "invalid_session_id",
                "session ids are the UUIDs returned when a session starts",
            ),
            AgentErrorCode::SessionNotFound => (
                StatusCode::NOT_FOUND,
                "session_not_found",
                "list the VM's sessions for the current ids",
            ),
            AgentErrorCode::TooManyRunningSessions => (
                StatusCode::TOO_MANY_REQUESTS,
                "session_capacity_exhausted",
                "wait for a running session to finish, or cancel one",
            ),
            AgentErrorCode::SessionRetentionLimit => (
                StatusCode::CONFLICT,
                "session_conflict",
                "remove finished sessions",
            ),
            AgentErrorCode::SessionRunning => (
                StatusCode::CONFLICT,
                "session_conflict",
                "cancel the session, then remove it",
            ),
            AgentErrorCode::SessionIdExists => (
                StatusCode::CONFLICT,
                "session_conflict",
                "retry; the daemon generates a fresh id for every start",
            ),
            AgentErrorCode::TunnelConnectFailed => (
                StatusCode::BAD_GATEWAY,
                "preview_unreachable",
                "nothing on the guest accepted the connection; start the application on that \
                 port, or check which port it listens on",
            ),
            // The guest agent decoded the frame but implements no such
            // request: the same remedy as an agent that predates sessions.
            AgentErrorCode::UnsupportedRequest => (
                StatusCode::NOT_IMPLEMENTED,
                "guest_capability_missing",
                "rebuild or re-import the VM's image with the current guest agent",
            ),
            AgentErrorCode::Unknown => UNCLASSIFIED,
        },
        _ => UNCLASSIFIED,
    };
    (
        status,
        error_response_with_hint(kind, error.to_string(), hint),
    )
}

#[utoipa::path(post, path = "/v1/vms/{name}/sessions", tag = "sessions",
    params(("name" = String, Path)), request_body = ExecRequest,
    responses((status = 201, body = SessionInfo, description = "Detached command started"),
        (status = 403, body = ErrorResponse, description = "Execution policy denied"),
        (status = 404, body = ErrorResponse, description = "VM not found"),
        (status = 409, body = ErrorResponse, description = "Session retention limit reached; remove finished sessions"),
        (status = 429, body = ErrorResponse, description = "Too many running sessions"),
        (status = 501, body = ErrorResponse, description = "Guest agent predates sessions"),
        (status = 502, body = ErrorResponse, description = "Guest failed to start the session"),
        (status = 503, body = ErrorResponse, description = "Guest agent not ready or did not answer within the deadline")))]
pub(crate) async fn start<B: VmmBackend + 'static>(
    State(core): State<SharedCore<B>>,
    State(policy): State<Arc<ApiPolicy>>,
    Path(name): Path<String>,
    Json(request): Json<ExecRequest>,
) -> Result<(StatusCode, Json<SessionInfo>), Failure> {
    // Acceptance transfers the whole start/monitor handoff to the daemon.
    // A cancelled HTTP future must not orphan a successfully detached guest
    // command without its host idle guard.
    tokio::spawn(start_owned(core, policy, name, request))
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
    core: SharedCore<B>,
    policy: Arc<ApiPolicy>,
    name: String,
    request: ExecRequest,
) -> Result<(StatusCode, Json<SessionInfo>), Failure> {
    let env = crate::handlers::resolve_exec_environment(core.as_ref(), &request, &policy)
        .map_err(|e| *e)?;
    let timeout_secs = request
        .timeout_secs
        .unwrap_or(policy.exec_timeout_secs)
        .clamp(1, policy.exec_timeout_max_secs.clamp(1, 86400));
    let mut conn = agent_connection(&core, &name, request.connect_timeout_secs).await?;
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
                Some(Err(AgentError::Rejected {
                    code: AgentErrorCode::SessionNotFound,
                    ..
                })) => break,
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
    responses((status = 200, body = [SessionInfo], description = "Guest sessions"),
        (status = 404, body = ErrorResponse, description = "VM not found"),
        (status = 409, body = ErrorResponse, description = "Session retention limit exceeded"),
        (status = 501, body = ErrorResponse, description = "Guest agent predates sessions"),
        (status = 502, body = ErrorResponse, description = "Guest failed to list sessions"),
        (status = 503, body = ErrorResponse, description = "Guest agent not ready or did not answer within the deadline")))]
pub(crate) async fn list<B: VmmBackend + 'static>(
    State(core): State<SharedCore<B>>,
    Path(name): Path<String>,
) -> Result<Json<Vec<SessionInfo>>, Failure> {
    Ok(Json(
        agent_connection(&core, &name, None)
            .await?
            .session_list()
            .await
            .map_err(session_error)?,
    ))
}

#[utoipa::path(get, path = "/v1/vms/{name}/sessions/{id}", tag = "sessions", params(("name" = String, Path), ("id" = String, Path)),
    responses((status = 200, body = SessionInfo, description = "Session status"),
        (status = 400, body = ErrorResponse, description = "Invalid session id"),
        (status = 404, body = ErrorResponse, description = "VM or session not found"),
        (status = 501, body = ErrorResponse, description = "Guest agent predates sessions"),
        (status = 502, body = ErrorResponse, description = "Guest failed to read the session"),
        (status = 503, body = ErrorResponse, description = "Guest agent not ready or did not answer within the deadline")))]
pub(crate) async fn get<B: VmmBackend + 'static>(
    State(core): State<SharedCore<B>>,
    Path((name, id)): Path<(String, String)>,
) -> Result<Json<SessionInfo>, Failure> {
    Ok(Json(
        agent_connection(&core, &name, None)
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
    responses((status = 200, body = SessionEventsResponse, description = "Bounded binary-safe event page"),
        (status = 400, body = ErrorResponse, description = "Invalid session id"),
        (status = 404, body = ErrorResponse, description = "VM or session not found"),
        (status = 501, body = ErrorResponse, description = "Guest agent predates sessions"),
        (status = 502, body = ErrorResponse, description = "Guest failed to read the session log"),
        (status = 503, body = ErrorResponse, description = "Guest agent not ready or did not answer within the deadline")))]
pub(crate) async fn events<B: VmmBackend + 'static>(
    State(core): State<SharedCore<B>>,
    Path((name, id)): Path<(String, String)>,
    Query(cursor): Query<Cursor>,
) -> Result<Json<SessionEventsResponse>, Failure> {
    Ok(Json(
        agent_connection(&core, &name, None)
            .await?
            .session_events(&id, cursor.after)
            .await
            .map_err(session_error)?,
    ))
}

#[utoipa::path(post, path = "/v1/vms/{name}/sessions/{id}/cancel", tag = "sessions", params(("name" = String, Path), ("id" = String, Path)),
    responses((status = 200, body = SessionInfo, description = "Cancellation requested; poll status for completion"),
        (status = 400, body = ErrorResponse, description = "Invalid session id"),
        (status = 404, body = ErrorResponse, description = "VM or session not found"),
        (status = 501, body = ErrorResponse, description = "Guest agent predates sessions"),
        (status = 502, body = ErrorResponse, description = "Guest failed to cancel the session"),
        (status = 503, body = ErrorResponse, description = "Guest agent not ready or did not answer within the deadline")))]
pub(crate) async fn cancel<B: VmmBackend + 'static>(
    State(core): State<SharedCore<B>>,
    Path((name, id)): Path<(String, String)>,
) -> Result<Json<SessionInfo>, Failure> {
    Ok(Json(
        agent_connection(&core, &name, None)
            .await?
            .session_cancel(&id)
            .await
            .map_err(session_error)?,
    ))
}

#[utoipa::path(delete, path = "/v1/vms/{name}/sessions/{id}", tag = "sessions", params(("name" = String, Path), ("id" = String, Path)),
    responses((status = 204, description = "Finished session and its logs removed"),
        (status = 400, body = ErrorResponse, description = "Invalid session id"),
        (status = 404, body = ErrorResponse, description = "VM or session not found"),
        (status = 409, body = ErrorResponse, description = "Session still running; cancel it first"),
        (status = 501, body = ErrorResponse, description = "Guest agent predates sessions"),
        (status = 502, body = ErrorResponse, description = "Guest failed to remove the session"),
        (status = 503, body = ErrorResponse, description = "Guest agent not ready or did not answer within the deadline")))]
pub(crate) async fn remove<B: VmmBackend + 'static>(
    State(core): State<SharedCore<B>>,
    Path((name, id)): Path<(String, String)>,
) -> Result<StatusCode, Failure> {
    agent_connection(&core, &name, None)
        .await?
        .session_remove(&id)
        .await
        .map_err(session_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/v1/vms/{name}/tunnel/{port}", tag = "previews", params(("name" = String, Path), ("port" = u16, Path)),
    responses((status = 101, description = "Authenticated binary WebSocket tunnel to guest loopback"),
        (status = 400, body = ErrorResponse, description = "Port is zero, or the request is not a WebSocket upgrade"),
        (status = 404, body = ErrorResponse, description = "VM not found"),
        (status = 429, body = ErrorResponse, description = "Too many preview connections"),
        (status = 501, body = ErrorResponse, description = "Guest agent predates preview tunnels"),
        (status = 502, body = ErrorResponse, description = "Nothing on the guest accepted the connection"),
        (status = 503, body = ErrorResponse, description = "Guest agent not ready or did not answer within the deadline")))]
pub(crate) async fn tunnel<B: VmmBackend + 'static>(
    State(core): State<SharedCore<B>>,
    Path((name, port)): Path<(String, u16)>,
    WebSocketUpgrade(ws): WebSocketUpgrade,
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
    let conn = agent_connection(&core, &name, None).await?;
    // The agent client bounds the connect itself and reports a deadline as
    // `NotReady`, so no second timer races it here.
    let stream = conn.tunnel(port).await.map_err(session_error)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use husker_core::CoreError;

    fn rejected(code: AgentErrorCode) -> AgentError {
        AgentError::Rejected {
            code,
            message: "from the guest".to_string(),
        }
    }

    /// Every refusal class has its own status and kind; the hint is the part
    /// a caller reads when the kind alone does not tell them what to do.
    #[test]
    fn session_errors_map_by_class_not_by_wording() {
        let cases = [
            (
                rejected(AgentErrorCode::InvalidSessionId),
                StatusCode::BAD_REQUEST,
                "invalid_session_id",
            ),
            (
                rejected(AgentErrorCode::SessionNotFound),
                StatusCode::NOT_FOUND,
                "session_not_found",
            ),
            (
                rejected(AgentErrorCode::TooManyRunningSessions),
                StatusCode::TOO_MANY_REQUESTS,
                "session_capacity_exhausted",
            ),
            (
                rejected(AgentErrorCode::SessionRetentionLimit),
                StatusCode::CONFLICT,
                "session_conflict",
            ),
            (
                rejected(AgentErrorCode::SessionRunning),
                StatusCode::CONFLICT,
                "session_conflict",
            ),
            (
                rejected(AgentErrorCode::SessionIdExists),
                StatusCode::CONFLICT,
                "session_conflict",
            ),
            (
                rejected(AgentErrorCode::TunnelConnectFailed),
                StatusCode::BAD_GATEWAY,
                "preview_unreachable",
            ),
            (
                rejected(AgentErrorCode::UnsupportedRequest),
                StatusCode::NOT_IMPLEMENTED,
                "guest_capability_missing",
            ),
            (
                rejected(AgentErrorCode::Unknown),
                StatusCode::BAD_GATEWAY,
                "session_failed",
            ),
            (
                AgentError::SessionsUnsupported {
                    reported: 4,
                    required: 5,
                },
                StatusCode::NOT_IMPLEMENTED,
                "guest_capability_missing",
            ),
            (
                AgentError::Agent("starting session command: No such file".to_string()),
                StatusCode::BAD_GATEWAY,
                "session_failed",
            ),
        ];
        for (error, status, kind) in cases {
            let message = error.to_string();
            let (got_status, body) = session_error(error);
            assert_eq!(got_status, status, "{kind}: {}", body.0.message);
            assert_eq!(body.0.kind, kind, "{}", body.0.message);
            assert_eq!(body.0.message, message);
            assert!(body.0.hint.is_some(), "{kind} needs a hint");
        }
    }

    /// A wording that used to select a class no longer does: only the code
    /// decides, so an unclassified refusal that happens to mention a session
    /// id stays a guest-side failure.
    #[test]
    fn wording_alone_does_not_classify() {
        let (status, body) =
            session_error(AgentError::Agent("session not found in cache".to_string()));
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body.0.kind, "session_failed");
    }

    /// The session deadline answers with the same status and kind as every
    /// other agent deadline in this API, so one retry rule serves both.
    #[test]
    fn session_deadline_matches_the_general_agent_deadline() {
        let not_ready = || AgentError::NotReady {
            timeout: Duration::from_secs(10),
            detail: String::new(),
        };
        let (status, body) = session_error(not_ready());
        let (general_status, general_body) = map_error(CoreError::Agent(not_ready()));
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(status, general_status);
        assert_eq!(body.0.kind, general_body.0.kind);
        assert_eq!(body.0.message, not_ready().to_string());
        let hint = body
            .0
            .hint
            .expect("the session deadline explains the start race");
        assert!(hint.contains("list sessions"), "{hint}");
    }
}
