//! Exercise the HTTP contract against the real guest agent over a local socket.
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use husker_api::router_with_auth;
use husker_core::{BackendKind, BootKind, HuskerCore, NetworkMode};
use husker_state::{VmLifecycleState, VmRecord};
use husker_vmm::{BackendSelection, CreatedVm, VmConfig, VmInfo, VmState, VmmBackend, VmmError};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};
use tower::ServiceExt;

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

struct Fixture {
    _temp: tempfile::TempDir,
    core: Arc<HuskerCore<AgentBackend>>,
    agent: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.agent.abort();
    }
}
impl Fixture {
    async fn new() -> Self {
        Self::new_with_gate(None).await
    }
    async fn new_with_gate(connect_gate: Option<Arc<ConnectGate>>) -> Self {
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
                        clients.spawn(async move { let _ = husker_agent::handle_connection_with_sessions(stream, sessions).await; });
                    }
                    _ = clients.join_next(), if !clients.is_empty() => {}
                }
            }
        });
        let record = vm_record("dev");
        let state = husker_state::StateStore::open(&temp.path().join("state.sqlite")).unwrap();
        state.insert_vm(&record).unwrap();
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
            agent,
        }
    }
    async fn request(&self, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
        let response = router_with_auth(self.core.clone(), Some("test-token".into()))
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
    assert_eq!(
        f.request("GET", &format!("/v1/vms/dev/sessions/{id}"), Value::Null)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let (_, info) = f
        .request(
            "POST",
            "/v1/vms/dev/sessions",
            json!({"command":"sleep", "args":["30"], "timeout_secs":60}),
        )
        .await;
    let id = info["id"].as_str().unwrap();
    assert_eq!(
        f.request("DELETE", &format!("/v1/vms/dev/sessions/{id}"), Value::Null)
            .await
            .0,
        StatusCode::CONFLICT
    );
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
    let app = router_with_auth(f.core.clone(), Some("test-token".into()));
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
    let app = router_with_auth(f.core.clone(), Some("test-token".into()));
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
    let app = router_with_auth(f.core.clone(), Some("test-token".into()));
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
    let app = router_with_auth(f.core.clone(), Some("test-token".into()));
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
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            husker_api::set_policy(husker_api::ApiPolicy::default());
        }
    }
    let f = Fixture::new().await;
    let _reset = Reset;
    husker_api::set_policy(husker_api::ApiPolicy {
        exec_denylist: vec!["husker-test-denied-executable".into()],
        ..Default::default()
    });
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
