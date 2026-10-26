//! Exercise the HTTP contract against the real guest agent over a local socket.
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use husker_agent::AgentLimits;
use husker_api::{ApiPolicy, BearerToken, router_with_auth};
use husker_core::{BackendKind, BootKind, HuskerCore, NetworkMode};
use husker_state::{VmLifecycleState, VmRecord};
use husker_vmm::{BackendSelection, CreatedVm, VmConfig, VmInfo, VmState, VmmBackend, VmmError};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};
use tower::ServiceExt;

/// The token every authenticated request in this file presents as
/// `Bearer test-token`.
fn test_token() -> Option<BearerToken> {
    Some(BearerToken::new("test-token").unwrap())
}

struct AgentBackend {
    info: VmInfo,
    socket: PathBuf,
    connect_gate: Option<Arc<ConnectGate>>,
}
struct ConnectGate {
    entered: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
}
impl VmmBackend for AgentBackend {
    type VsockStream = tokio::net::UnixStream;
    async fn create_vm(&self, _: BackendSelection, _: VmConfig) -> Result<CreatedVm, VmmError> {
        Err(VmmError::Unsupported("fixture".into()))
    }
    async fn stop_vm(&self, _: uuid::Uuid) -> Result<(), VmmError> {
        Ok(())
    }
    async fn destroy_vm(&self, _: uuid::Uuid) -> Result<(), VmmError> {
        Ok(())
    }
    async fn pause_vm(&self, _: uuid::Uuid) -> Result<(), VmmError> {
        Ok(())
    }
    async fn resume_vm(&self, _: uuid::Uuid) -> Result<(), VmmError> {
        Ok(())
    }
    async fn vm_info(&self, id: uuid::Uuid) -> Result<VmInfo, VmmError> {
        if id == self.info.id {
            Ok(self.info.clone())
        } else {
            Err(VmmError::VmNotFound(id))
        }
    }
    async fn vsock_connect(&self, _: uuid::Uuid, _: u32) -> Result<Self::VsockStream, VmmError> {
        if let Some(gate) = &self.connect_gate {
            gate.entered.notify_one();
            let _permit = gate.release.acquire().await.unwrap();
        }
        tokio::net::UnixStream::connect(&self.socket)
            .await
            .map_err(VmmError::Io)
    }
    async fn set_balloon(&self, _: uuid::Uuid, _: u32) -> Result<(), VmmError> {
        Ok(())
    }
    fn backend_kind(&self) -> &'static str {
        "firecracker"
    }
}
fn vm_record(name: &str) -> VmRecord {
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

/// What a fixture is built with. Each fixture owns its router policy and its
/// guest agent's limits, so a test that lowers a limit affects only its own
/// daemon and guest, however the tests are scheduled.
#[derive(Default)]
struct FixtureOptions {
    connect_gate: Option<Arc<ConnectGate>>,
    /// VM records the backend knows nothing about, so they can never reach
    /// the agent.
    extra: Vec<VmRecord>,
    policy: ApiPolicy,
    agent_limits: AgentLimits,
}

struct Fixture {
    _temp: tempfile::TempDir,
    core: Arc<HuskerCore<AgentBackend>>,
    policy: ApiPolicy,
    agent: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.agent.abort();
    }
}
/// A router served on a loopback listener, for the WebSocket routes that an
/// in-process `oneshot` cannot upgrade.
struct Served {
    addr: std::net::SocketAddr,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Served {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Served {
    /// A WebSocket handshake for `path` carrying the test bearer token.
    fn ws_request(&self, path: &str) -> tokio_tungstenite::tungstenite::http::Request<()> {
        let mut request = format!("ws://{}{path}", self.addr)
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("Authorization", "Bearer test-token".parse().unwrap());
        request
    }
    /// Open `path`, send `start` as the first frame and return the socket with
    /// the first frame the daemon answered.
    async fn open(
        &self,
        path: &str,
        start: Value,
    ) -> (
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Value,
    ) {
        let (mut ws, _) = tokio_tungstenite::connect_async(self.ws_request(path))
            .await
            .unwrap();
        ws.send(Message::Text(start.to_string().into()))
            .await
            .unwrap();
        let first: Value = match ws.next().await {
            Some(Ok(Message::Text(text))) => serde_json::from_str(&text).unwrap(),
            other => panic!("expected a text frame, got {other:?}"),
        };
        (ws, first)
    }
}

impl Fixture {
    async fn new() -> Self {
        Self::build(FixtureOptions::default()).await
    }
    async fn new_with_gate(connect_gate: Option<Arc<ConnectGate>>) -> Self {
        Self::build(FixtureOptions {
            connect_gate,
            ..FixtureOptions::default()
        })
        .await
    }
    /// Build the fixture around the running `dev` VM, served by a guest agent
    /// on a local socket with its own session store.
    async fn build(options: FixtureOptions) -> Self {
        let FixtureOptions {
            connect_gate,
            extra,
            policy,
            agent_limits,
        } = options;
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let sessions = husker_agent::SessionStore::new(temp.path().join("sessions"));
        let agent = tokio::spawn(async move {
            let mut clients = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    client = listener.accept() => {
                        let (stream, _) = client.unwrap();
                        let sessions = sessions.clone();
                        clients.spawn(async move {
                            let _ = husker_agent::handle_connection_with(stream, sessions, agent_limits).await;
                        });
                    }
                    _ = clients.join_next(), if !clients.is_empty() => {}
                }
            }
        });
        let record = vm_record("dev");
        let state = husker_state::StateStore::open(&temp.path().join("state.sqlite")).unwrap();
        state.insert_vm(&record).unwrap();
        for record in &extra {
            state.insert_vm(record).unwrap();
        }
        let backend = AgentBackend {
            socket,
            connect_gate,
            info: VmInfo {
                id: record.id,
                name: record.name,
                state: VmState::Running,
                pid: None,
                vcpu_count: 1,
                mem_size_mib: 128,
                vsock_cid: 3,
            },
        };
        let storage = husker_storage::StorageConfig {
            data_dir: temp.path().into(),
            state_dir: temp.path().into(),
        };
        #[cfg(not(feature = "linux-net"))]
        let core = Arc::new(HuskerCore::new(
            backend,
            state,
            storage,
            temp.path().join("run"),
        ));
        #[cfg(feature = "linux-net")]
        let core = Arc::new(HuskerCore::new(
            backend,
            state,
            husker_net::IpAllocator::new(std::net::Ipv4Addr::new(172, 20, 0, 0), 24),
            storage,
            "husker0".into(),
            vec!["1.1.1.1".into()],
            temp.path().join("run"),
        ));
        Self {
            _temp: temp,
            core,
            policy,
            agent,
        }
    }
    async fn request(&self, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
        let response = router_with_auth(self.core.clone(), self.policy.clone(), test_token())
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("Authorization", "Bearer test-token")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            },
        )
    }
    async fn serve(&self) -> Served {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router_with_auth(self.core.clone(), self.policy.clone(), test_token());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Served { addr, server }
    }
    async fn finished(&self, id: &str) -> Value {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let (status, info) = self
                    .request("GET", &format!("/v1/vms/dev/sessions/{id}"), Value::Null)
                    .await;
                assert_eq!(status, StatusCode::OK, "{info}");
                if info["state"] != "running" {
                    return info;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }
}

#[tokio::test]
async fn detached_session_reconnect_logs_cancel_and_remove() {
    let f = Fixture::new().await;
    let (status, info) = f.request("POST", "/v1/vms/dev/sessions", json!({
        "command":"sh", "args":["-c", "printf hello; printf error >&2; sleep 0.2; printf done"], "timeout_secs":5,
    })).await;
    assert_eq!(status, StatusCode::CREATED, "{info}");
    let id = info["id"].as_str().unwrap();
    let vm_id = f.core.get_vm("dev").unwrap().id;
    assert!(
        f.core.active_session_count(vm_id) > 0,
        "the HTTP response must not release the idle guard"
    );
    let completed = f.finished(id).await;
    assert_eq!(completed["exit_code"], 0);
    let (status, page) = f
        .request(
            "GET",
            &format!("/v1/vms/dev/sessions/{id}/events"),
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    for event in page["events"].as_array().unwrap() {
        let data = husker_agent_proto::base64_decode(event["data"].as_str().unwrap()).unwrap();
        if event["stream"] == "stdout" {
            stdout.extend(data);
        } else {
            stderr.extend(data);
        }
    }
    assert_eq!(stdout, b"hellodone");
    assert_eq!(stderr, b"error");
    let cursor = page["next_cursor"].as_u64().unwrap();
    let (_, next) = f
        .request(
            "GET",
            &format!("/v1/vms/dev/sessions/{id}/events?after={cursor}"),
            Value::Null,
        )
        .await;
    assert_eq!(next["events"].as_array().unwrap().len(), 0);
    let (status, list) = f.request("GET", "/v1/vms/dev/sessions", Value::Null).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list[0]["id"], id, "{list}");
    let (status, _) = f
        .request("DELETE", &format!("/v1/vms/dev/sessions/{id}"), Value::Null)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = f
        .request("GET", &format!("/v1/vms/dev/sessions/{id}"), Value::Null)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["kind"], "session_not_found", "{body}");
    let (status, body) = f
        .request("GET", "/v1/vms/dev/sessions/not-a-session-id", Value::Null)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["kind"], "invalid_session_id", "{body}");
    let (_, info) = f
        .request(
            "POST",
            "/v1/vms/dev/sessions",
            json!({"command":"sleep", "args":["30"], "timeout_secs":60}),
        )
        .await;
    let id = info["id"].as_str().unwrap();
    let (status, body) = f
        .request("DELETE", &format!("/v1/vms/dev/sessions/{id}"), Value::Null)
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["kind"], "session_conflict", "{body}");
    assert_eq!(
        f.request(
            "POST",
            &format!("/v1/vms/dev/sessions/{id}/cancel"),
            Value::Null
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(f.finished(id).await["state"], "cancelled");
    tokio::time::timeout(Duration::from_secs(3), async {
        while f.core.active_session_count(vm_id) > 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_http_start_still_hands_off_guest_session_and_idle_monitor() {
    let gate = Arc::new(ConnectGate {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Semaphore::new(0),
    });
    let f = Fixture::new_with_gate(Some(gate.clone())).await;
    let app = router_with_auth(f.core.clone(), f.policy.clone(), test_token());
    let request = Request::builder()
        .method("POST")
        .uri("/v1/vms/dev/sessions")
        .header("Authorization", "Bearer test-token")
        .header("Content-Type", "application/json")
        .body(Body::from(
            json!({"command":"sleep", "args":["30"], "timeout_secs":60}).to_string(),
        ))
        .unwrap();
    let http = tokio::spawn(app.oneshot(request));
    gate.entered.notified().await;
    http.abort();
    let _ = http.await;
    gate.release.add_permits(1);
    let id = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let (_, sessions) = f.request("GET", "/v1/vms/dev/sessions", Value::Null).await;
            if let Some(info) = sessions.as_array().and_then(|s| s.first()) {
                assert_eq!(info["state"], "running");
                break info["id"].as_str().unwrap().to_string();
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let vm_id = f.core.get_vm("dev").unwrap().id;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        f.core.active_session_count(vm_id) > 0,
        "detached monitor must survive the abandoned HTTP future"
    );
    f.request(
        "POST",
        &format!("/v1/vms/dev/sessions/{id}/cancel"),
        Value::Null,
    )
    .await;
    assert_eq!(f.finished(&id).await["state"], "cancelled");
}

#[tokio::test]
async fn session_and_tunnel_routes_require_auth() {
    let f = Fixture::new().await;
    let app = router_with_auth(f.core.clone(), f.policy.clone(), test_token());
    for (method, path) in [
        ("POST", "/v1/vms/dev/sessions"),
        ("GET", "/v1/vms/dev/sessions"),
        ("GET", "/v1/vms/dev/sessions/id/events"),
        ("POST", "/v1/vms/dev/sessions/id/cancel"),
        ("DELETE", "/v1/vms/dev/sessions/id"),
        ("GET", "/v1/vms/dev/tunnel/3000"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
}

#[tokio::test]
async fn authenticated_tunnel_preserves_http_without_exposing_daemon_token() {
    let f = Fixture::new().await;
    let guest = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = guest.local_addr().unwrap().port();
    let (received, request_received) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let application = tokio::spawn(async move {
        let (mut tcp, _) = guest.accept().await.unwrap();
        let mut request = Vec::new();
        loop {
            let mut byte = [0];
            tcp.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        received.send(()).unwrap();
        let mut tail = Vec::new();
        tcp.read_to_end(&mut tail).await.unwrap();
        assert!(tail.is_empty());
        released.await.unwrap();
        tcp.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nhi\0")
            .await
            .unwrap();
        request
    });
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router_with_auth(f.core.clone(), f.policy.clone(), test_token());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let url = format!("ws://{addr}/v1/vms/dev/tunnel/{port}");
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("Authorization", "Bearer test-token".parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    ws.send(Message::Binary(
        b"GET /asset?version=2 HTTP/1.1\r\nHost: localhost\r\n\r\n"
            .to_vec()
            .into(),
    ))
    .await
    .unwrap();
    ws.send(Message::Text("eof".into())).await.unwrap();
    request_received.await.unwrap();
    let vm_id = f.core.get_vm("dev").unwrap().id;
    assert!(f.core.active_session_count(vm_id) > 0);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        f.core.active_session_count(vm_id) > 0,
        "a stalled application response must keep the VM active"
    );
    release.send(()).unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(message) = ws.next().await {
            match message.unwrap() {
                Message::Binary(bytes) => response.extend(bytes),
                Message::Close(_) => break,
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    assert!(response.ends_with(b"\r\n\r\nhi\0"));
    let request = application.await.unwrap();
    assert!(request.starts_with(b"GET /asset?version=2 HTTP/1.1"));
    assert!(!String::from_utf8_lossy(&request).contains("test-token"));
    server.abort();
}

/// The monitor polls a detached session once a second. A session that
/// finishes and is removed between two polls answers the next poll with
/// `session_not_found`; the monitor must read that as the end of the session
/// and release the idle guard now, not after its 30 s loss-of-contact grace.
#[tokio::test]
async fn monitor_releases_the_idle_guard_when_a_finished_session_is_removed() {
    let f = Fixture::new().await;
    let (status, info) = f
        .request(
            "POST",
            "/v1/vms/dev/sessions",
            json!({ "command": "sleep", "args": ["0.3"], "timeout_secs": 5 }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{info}");
    let id = info["id"].as_str().unwrap();
    let vm_id = f.core.get_vm("dev").unwrap().id;
    assert!(f.core.active_session_count(vm_id) > 0);
    f.finished(id).await;
    let (status, body) = f
        .request("DELETE", &format!("/v1/vms/dev/sessions/{id}"), Value::Null)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    tokio::time::timeout(Duration::from_secs(5), async {
        while f.core.active_session_count(vm_id) > 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the monitor releases the idle guard once the session is gone");
}

/// A tunnel to a port nothing listens on is refused from the handshake with
/// its own kind, so a preview client can tell "start your application" apart
/// from a guest-side failure it can only inspect.
#[tokio::test]
async fn tunnel_to_a_closed_guest_port_is_refused_before_the_upgrade() {
    let f = Fixture::new().await;
    let served = f.serve().await;
    let closed = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);

    let path = format!("/v1/vms/dev/tunnel/{port}");
    let error = tokio_tungstenite::connect_async(served.ws_request(&path))
        .await
        .expect_err("nothing listens on the port");
    let tokio_tungstenite::tungstenite::Error::Http(response) = error else {
        panic!("expected an HTTP refusal, got {error:?}");
    };
    assert_eq!(response.status().as_u16(), 502);
    let body = response
        .into_body()
        .expect("the refusal carries the envelope");
    let envelope: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(envelope["kind"], "preview_unreachable", "{envelope}");
    assert!(
        envelope["hint"]
            .as_str()
            .is_some_and(|hint| hint.contains("start the application")),
        "{envelope}"
    );
    let vm_id = f.core.get_vm("dev").unwrap().id;
    assert_eq!(
        f.core.active_session_count(vm_id),
        0,
        "a refused tunnel leaves no active session behind"
    );
}

#[tokio::test]
async fn preview_drains_both_directions_when_guest_writes_before_reading() {
    let f = Fixture::new().await;
    let guest = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = guest.local_addr().unwrap().port();
    const SIZE: usize = 8 * 1024 * 1024;
    let application = tokio::spawn(async move {
        let (mut tcp, _) = guest.accept().await.unwrap();
        // Exceed socket buffers in both directions. A single read/write loop
        // deadlocks here if its blocked guest write prevents response reads.
        tcp.write_all(&vec![0xAB; SIZE]).await.unwrap();
        let mut request = Vec::new();
        tcp.read_to_end(&mut request).await.unwrap();
        assert_eq!(request.len(), SIZE);
        assert!(request.iter().all(|b| *b == 0xCD));
        tcp.shutdown().await.unwrap();
    });
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router_with_auth(f.core.clone(), f.policy.clone(), test_token());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut request = format!("ws://{addr}/v1/vms/dev/tunnel/{port}")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("Authorization", "Bearer test-token".parse().unwrap());
    let (ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    let (mut sink, mut source) = ws.split();
    let send = async {
        for _ in 0..SIZE / 32768 {
            sink.send(Message::Binary(vec![0xCD; 32768].into()))
                .await
                .unwrap();
        }
        sink.send(Message::Text("eof".into())).await.unwrap();
    };
    let receive = async {
        let mut received = 0;
        while let Some(message) = source.next().await {
            match message.unwrap() {
                Message::Binary(bytes) => {
                    assert!(bytes.iter().all(|b| *b == 0xAB));
                    received += bytes.len();
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        assert_eq!(received, SIZE);
    };
    tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(send, receive);
        application.await.unwrap();
    })
    .await
    .unwrap();
    server.abort();
}

#[tokio::test]
async fn detached_commands_apply_execution_policy_before_contacting_guest() {
    let f = Fixture::build(FixtureOptions {
        policy: ApiPolicy {
            exec_denylist: vec!["husker-test-denied-executable".into()],
            ..ApiPolicy::default()
        },
        ..FixtureOptions::default()
    })
    .await;
    let (status, error) = f
        .request(
            "POST",
            "/v1/vms/dev/sessions",
            json!({
                "command": "husker-test-denied-executable", "timeout_secs": 10,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{error}");
    assert_eq!(error["kind"], "policy_exec_command_denied");
    assert_eq!(
        f.core
            .active_session_count(f.core.get_vm("dev").unwrap().id),
        0
    );
}

#[tokio::test]
async fn monitor_releases_idle_guard_while_suspended_and_reacquires_on_resume() {
    let f = Fixture::new().await;
    let state = husker_state::StateStore::open(&f._temp.path().join("state.sqlite")).unwrap();
    let (status, info) = f
        .request(
            "POST",
            "/v1/vms/dev/sessions",
            json!({"command":"sleep", "args":["30"], "timeout_secs":60}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = info["id"].as_str().unwrap();
    let vm_id = f.core.get_vm("dev").unwrap().id;
    state
        .update_vm_state(vm_id, VmLifecycleState::Suspended)
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while f.core.active_session_count(vm_id) > 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        f.core.get_vm("dev").unwrap().state,
        VmLifecycleState::Suspended,
        "monitoring must not auto-resume an explicitly suspended VM"
    );
    state
        .update_vm_state(vm_id, VmLifecycleState::Running)
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while f.core.active_session_count(vm_id) == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    f.request(
        "POST",
        &format!("/v1/vms/dev/sessions/{id}/cancel"),
        Value::Null,
    )
    .await;
    assert_eq!(f.finished(id).await["state"], "cancelled");
    tokio::time::timeout(Duration::from_secs(5), async {
        while f.core.active_session_count(vm_id) > 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

/// A chunked upload through the REST write is the path the Python SDK takes.
/// Against a current guest the chunks accumulate; the refusal of an older
/// guest lives in the core write, where a scripted agent can report its age.
#[tokio::test]
async fn write_file_appends_chunks_on_a_guest_that_supports_append() {
    let f = Fixture::new().await;
    let path = f._temp.path().join("upload.bin");
    for (index, chunk) in [b"first-".as_slice(), b"second".as_slice()]
        .into_iter()
        .enumerate()
    {
        let (status, body) = f
            .request(
                "POST",
                "/v1/vms/dev/files/write",
                json!({
                    "path": path,
                    "data": husker_agent_proto::base64_encode(chunk),
                    "mode": null,
                    "append": index > 0,
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["bytes_written"], chunk.len(), "{body}");
    }
    assert_eq!(std::fs::read(&path).unwrap(), b"first-second");
}

#[tokio::test]
async fn shell_applies_the_exec_command_policy_before_contacting_the_guest() {
    let gate = Arc::new(ConnectGate {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Semaphore::new(1),
    });
    let f = Fixture::build(FixtureOptions {
        connect_gate: Some(gate.clone()),
        policy: ApiPolicy {
            exec_denylist: vec!["husker-test-denied-executable".into()],
            ..ApiPolicy::default()
        },
        ..FixtureOptions::default()
    })
    .await;
    let served = f.serve().await;
    let open_shell = |command: &'static str| {
        served.open(
            "/v1/vms/dev/shell",
            json!({ "type": "start", "command": command }),
        )
    };

    let (mut denied, first) = open_shell("husker-test-denied-executable").await;
    // The refusal is the REST exec policy envelope, carried in-band.
    let (status, rest) = f
        .request(
            "POST",
            "/v1/vms/dev/exec",
            json!({ "command": "husker-test-denied-executable", "args": [] }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{rest}");
    assert_eq!(first["type"], "error", "{first}");
    assert_eq!(first["kind"], "policy_exec_command_denied", "{first}");
    assert_eq!(first["kind"], rest["kind"], "{first}");
    assert_eq!(first["message"], rest["message"], "{first}");
    assert_eq!(first["hint"], rest["hint"], "{first}");
    assert_eq!(first["status"], status.as_u16(), "{first}");
    assert!(
        tokio::time::timeout(Duration::from_millis(200), gate.entered.notified())
            .await
            .is_err(),
        "a denied shell must not connect to the guest agent"
    );
    assert!(
        !matches!(denied.next().await, Some(Ok(Message::Text(_)))),
        "a denied shell gets no further frames"
    );

    let (mut allowed, first) = open_shell("cat").await;
    if first["type"] != "started" {
        let message = first["message"].as_str().unwrap_or_default();
        assert!(
            first["type"] == "error" && !message.contains("execution policy"),
            "an allowed command passes the policy gate: {first}"
        );
    }
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .expect("an allowed shell connects to the guest agent");
    let _ = allowed.close(None).await;
}

/// Every REST route answers an unknown VM with 404 `vm_not_found`. The
/// WebSocket routes answer the same way, from the handshake, so a client never
/// holds an upgraded socket for a VM that does not exist and one status mapping
/// serves both transports.
#[tokio::test]
async fn websocket_routes_refuse_an_unknown_vm_before_the_upgrade() {
    let f = Fixture::new().await;
    let served = f.serve().await;
    let (status, rest) = f
        .request("POST", "/v1/vms/ghost/exec", json!({ "command": "true" }))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{rest}");
    assert_eq!(rest["kind"], "vm_not_found", "{rest}");

    for path in ["/v1/vms/ghost/exec/stream", "/v1/vms/ghost/shell"] {
        let error = tokio_tungstenite::connect_async(served.ws_request(path))
            .await
            .expect_err(path);
        let tokio_tungstenite::tungstenite::Error::Http(response) = error else {
            panic!("{path}: expected an HTTP refusal, got {error:?}");
        };
        assert_eq!(response.status().as_u16(), 404, "{path}");
        let body = response.into_body().expect(path);
        let envelope: Value = serde_json::from_slice(&body).expect(path);
        assert_eq!(envelope["kind"], rest["kind"], "{path}: {envelope}");
        assert_eq!(envelope["message"], rest["message"], "{path}: {envelope}");
    }
}

/// A failure after the upgrade cannot change the HTTP status, so the error
/// frame carries the REST envelope for the same failure: a client applies the
/// status and kind it already understands and does not parse messages.
#[tokio::test]
async fn exec_stream_reports_a_post_upgrade_failure_with_the_rest_envelope() {
    let mut halted = vm_record("halted");
    halted.state = VmLifecycleState::Stopped;
    let f = Fixture::build(FixtureOptions {
        extra: vec![halted],
        ..FixtureOptions::default()
    })
    .await;
    let served = f.serve().await;
    let (status, rest) = f
        .request("POST", "/v1/vms/halted/exec", json!({ "command": "true" }))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{rest}");
    assert_eq!(rest["kind"], "invalid_state", "{rest}");

    let (mut ws, first) = served
        .open(
            "/v1/vms/halted/exec/stream",
            json!({ "type": "start", "request": { "command": "true" } }),
        )
        .await;
    assert_eq!(first["type"], "error", "{first}");
    assert_eq!(first["kind"], rest["kind"], "{first}");
    assert_eq!(first["message"], rest["message"], "{first}");
    assert_eq!(first["hint"], rest["hint"], "{first}");
    assert_eq!(first["status"], status.as_u16(), "{first}");
    assert!(
        !matches!(ws.next().await, Some(Ok(Message::Text(_)))),
        "a failed session gets no further frames"
    );
}

/// The first frame must be the text `start` message. Anything else is the
/// client's mistake and is reported as such, not swallowed by a silent close.
#[tokio::test]
async fn websocket_routes_reject_a_malformed_start_frame() {
    let f = Fixture::new().await;
    let served = f.serve().await;

    let cases: [(&str, Value); 2] = [
        ("/v1/vms/dev/exec/stream", json!({ "type": "bogus" })),
        ("/v1/vms/dev/shell", json!({ "type": "data", "data": "" })),
    ];
    for (path, start) in cases {
        let (_ws, first) = served.open(path, start).await;
        assert_eq!(first["type"], "error", "{path}: {first}");
        assert_eq!(first["kind"], "invalid_start_message", "{path}: {first}");
        assert_eq!(first["status"], 400, "{path}: {first}");
        assert!(first["hint"].is_string(), "{path}: {first}");
    }

    for path in ["/v1/vms/dev/exec/stream", "/v1/vms/dev/shell"] {
        let (mut ws, _) = tokio_tungstenite::connect_async(served.ws_request(path))
            .await
            .unwrap();
        ws.send(Message::Binary(vec![0u8; 4].into())).await.unwrap();
        let first: Value = match ws.next().await {
            Some(Ok(Message::Text(text))) => serde_json::from_str(&text).unwrap(),
            other => panic!("{path}: expected a text frame, got {other:?}"),
        };
        assert_eq!(first["kind"], "invalid_start_message", "{path}: {first}");
        assert_eq!(first["status"], 400, "{path}: {first}");
    }
}

/// The read limit bounds one response, so the guest must be asked for no more
/// than that plus one byte: a file far above the limit is then refused after a
/// single extra byte instead of after a transfer the daemon throws away. The
/// file here is larger than the agent's own 16 MiB ceiling, so without the cap
/// the agent refuses the unranged read outright and the daemon reports an
/// agent error, not the policy refusal a client branches on to start chunking.
#[tokio::test]
async fn read_file_detects_an_oversized_file_without_transferring_it() {
    let f = Fixture::build(FixtureOptions {
        policy: ApiPolicy {
            max_file_read_bytes: 1024,
            ..ApiPolicy::default()
        },
        ..FixtureOptions::default()
    })
    .await;
    let total: u64 = 20 * 1024 * 1024;
    let path = f._temp.path().join("large.bin");
    std::fs::File::create(&path)
        .unwrap()
        .set_len(total)
        .unwrap();

    let (status, body) = f
        .request("POST", "/v1/vms/dev/files/read", json!({ "path": path }))
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(body["kind"], "read_file_too_large", "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains(&format!("file is {total} bytes")),
        "the refusal names the file size so a client can plan its ranges: {body}"
    );

    // A range under the limit is served from the same file.
    let (status, body) = f
        .request(
            "POST",
            "/v1/vms/dev/files/read",
            json!({ "path": path, "offset": total - 100, "len": 1024 }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["size"], 100, "{body}");
    assert_eq!(body["total_size"], total, "{body}");
}

/// A read without `len` asks for the file to its end. The cap the daemon adds
/// makes it a ranged read on the guest, and a guest clamps a ranged read at
/// its own per-response ceiling instead of refusing it, so the daemon has to
/// notice the short answer itself rather than serve a prefix as the file.
#[tokio::test]
async fn read_file_refuses_a_prefix_when_the_guest_ceiling_cuts_a_whole_file_read_short() {
    let f = Fixture::build(FixtureOptions {
        agent_limits: AgentLimits {
            max_read_bytes: 65536,
            ..AgentLimits::default()
        },
        ..FixtureOptions::default()
    })
    .await;
    let path = f._temp.path().join("medium.bin");
    let content: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&path, &content).unwrap();

    let (status, body) = f
        .request("POST", "/v1/vms/dev/files/read", json!({ "path": path }))
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(body["kind"], "read_file_too_large", "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("65536 of 100000 bytes"),
        "{body}"
    );

    // The same file arrives whole as two ranges.
    let mut assembled = Vec::new();
    for offset in [0u64, 65536] {
        let (status, body) = f
            .request(
                "POST",
                "/v1/vms/dev/files/read",
                json!({ "path": path, "offset": offset, "len": 65536 }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["total_size"], 100_000, "{body}");
        assembled
            .extend(husker_agent_proto::base64_decode(body["data"].as_str().unwrap()).unwrap());
    }
    assert_eq!(assembled, content);
}
