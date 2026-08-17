use husker_agent_proto::{
    AgentRequest, AgentResponse, ErrorResponse, ExecResponse, GuestInfoResponse, ReadFileResponse,
    ShellExitResponse, WriteFileResponse, base64_decode, read_message, write_message,
};
use husker_core::agent_client::{AgentClient, AgentConnection, AgentError, ShellEvent};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Spawn the agent handler on a temporary Unix socket and return the socket path.
async fn spawn_agent() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = husker_agent::handle_connection(stream).await;
            });
        }
    });

    // Give the listener a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    (dir, path)
}

/// Spawn a minimal Firecracker-vsock-like Unix listener that responds to CONNECT.
async fn spawn_vsock_proxy(
    response_line: &'static [u8],
) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("firecracker.vsock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 128];
        let _ = stream.read(&mut buf).await.unwrap();
        stream.write_all(response_line).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    (dir, path)
}

/// Spawn a vsock proxy that accepts one or more CONNECT handshakes and then
/// answers a single Ping request per connection.
async fn spawn_vsock_ping_proxy(
    ping_outcomes: Vec<bool>,
) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("firecracker.vsock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();

    tokio::spawn(async move {
        for should_pong in ping_outcomes {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut handshake = [0u8; 128];
            let _ = stream.read(&mut handshake).await.unwrap();
            stream.write_all(b"OK 123\n").await.unwrap();

            let request: AgentRequest = read_message(&mut stream).await.unwrap().unwrap();
            assert!(matches!(request, AgentRequest::Ping));

            if should_pong {
                write_message(&mut stream, &AgentResponse::Pong)
                    .await
                    .unwrap();
            } else {
                write_message(
                    &mut stream,
                    &AgentResponse::Error(ErrorResponse {
                        message: "not ready yet".into(),
                    }),
                )
                .await
                .unwrap();
            }
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    (dir, path)
}

#[tokio::test]
async fn client_ping() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();
    conn.ping().await.unwrap();
}

#[tokio::test]
async fn client_exec() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();
    let result = conn
        .exec("echo", &["hello world"], None, &[])
        .await
        .unwrap();
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout.trim(), "hello world");
    assert!(result.stderr.is_empty());
}

#[tokio::test]
async fn client_exec_with_env_and_workdir() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();
    let result = conn
        .exec(
            "sh",
            &["-c", "echo $TEST_VAR && pwd"],
            Some("/tmp"),
            &[("TEST_VAR", "husker_test")],
        )
        .await
        .unwrap();
    assert_eq!(result.exit_code, 0);
    let lines: Vec<&str> = result.stdout.trim().lines().collect();
    assert_eq!(lines[0], "husker_test");
    // macOS uses /private/tmp
    assert!(
        lines[1] == "/tmp" || lines[1] == "/private/tmp",
        "unexpected pwd: {}",
        lines[1]
    );
}

#[tokio::test]
async fn client_exec_failure() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();
    let result = conn
        .exec("sh", &["-c", "exit 42"], None, &[])
        .await
        .unwrap();
    assert_eq!(result.exit_code, 42);
}

#[tokio::test]
async fn client_exec_stream_preserves_binary_chunks_and_exit_status() {
    let (_dir, path) = spawn_agent().await;
    let mut conn = AgentClient::connect_unix(&path).await.unwrap();
    conn.exec_stream_start(
        "sh",
        &["-c", "printf '\\001\\377'; printf err >&2; exit 9"],
        None,
        &[],
        Some(5),
    )
    .await
    .unwrap();

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = loop {
        match conn.exec_stream_recv().await.unwrap() {
            husker_core::ExecStreamEvent::Stdout(data) => stdout.extend(data),
            husker_core::ExecStreamEvent::Stderr(data) => stderr.extend(data),
            husker_core::ExecStreamEvent::Exit(code) => break code,
        }
    };
    assert_eq!(stdout, [1, 0xff]);
    assert_eq!(stderr, b"err");
    assert_eq!(exit, 9);
}

#[tokio::test]
async fn client_write_and_read_file() {
    let (_dir, path) = spawn_agent().await;

    let file_dir = tempfile::tempdir().unwrap();
    let file_path = file_dir.path().join("test.bin");
    let file_path_str = file_path.to_string_lossy();

    let data = b"binary data \x00\x01\x02\xff";

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    let bytes_written = conn
        .write_file(&file_path_str, data, None, false)
        .await
        .unwrap();
    assert_eq!(bytes_written, data.len() as u64);

    let read_back = conn.read_file(&file_path_str).await.unwrap();
    assert_eq!(read_back, data);
}

#[tokio::test]
async fn client_read_nonexistent_file() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();
    let result = conn.read_file("/nonexistent/path/12345").await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("read failed"), "got: {err}");
}

#[tokio::test]
async fn client_multiple_operations() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    // Ping
    conn.ping().await.unwrap();

    // Exec
    let result = conn.exec("echo", &["one"], None, &[]).await.unwrap();
    assert_eq!(result.stdout.trim(), "one");

    // Another exec
    let result = conn.exec("echo", &["two"], None, &[]).await.unwrap();
    assert_eq!(result.stdout.trim(), "two");

    // Ping again
    conn.ping().await.unwrap();
}

#[tokio::test]
async fn agent_connection_from_raw_stream() {
    let (_dir, path) = spawn_agent().await;

    // Test using AgentConnection::new() with a raw stream
    let stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    let mut conn = AgentConnection::new(stream);
    conn.ping().await.unwrap();

    let result = conn.exec("echo", &["raw"], None, &[]).await.unwrap();
    assert_eq!(result.stdout.trim(), "raw");
}

#[tokio::test]
async fn connect_maps_rejected_vsock_handshake() {
    let (_dir, path) = spawn_vsock_proxy(b"ERR nope\n").await;
    let err = match AgentClient::connect(&path, 52).await {
        Ok(_) => panic!("expected connect rejection"),
        Err(err) => err,
    };
    assert!(matches!(err, AgentError::VsockConnectRejected(52)));
}

#[tokio::test]
async fn connect_accepts_ok_vsock_handshake() {
    let (_dir, path) = spawn_vsock_proxy(b"OK 123\n").await;
    let connected = AgentClient::connect(&path, 52).await;
    assert!(connected.is_ok());
}

#[tokio::test]
async fn connect_invalid_utf8_handshake_maps_connection_error() {
    let (_dir, path) = spawn_vsock_proxy(b"\xff\n").await;
    let err = match AgentClient::connect(&path, 52).await {
        Ok(_) => panic!("expected invalid handshake failure"),
        Err(err) => err,
    };
    assert!(matches!(err, AgentError::Connection(_)));
}

#[tokio::test]
async fn connect_unix_missing_socket_maps_connection_error() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.sock");
    let err = match AgentClient::connect_unix(&missing).await {
        Ok(_) => panic!("expected unix connect error"),
        Err(err) => err,
    };
    assert!(matches!(err, AgentError::Connection(_)));
}

#[tokio::test]
async fn connect_missing_vsock_socket_maps_connection_error() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.firecracker.vsock");
    let err = match AgentClient::connect(&missing, 52).await {
        Ok(_) => panic!("expected vsock connect error"),
        Err(err) => err,
    };
    assert!(matches!(err, AgentError::Connection(_)));
}

#[tokio::test]
async fn wait_ready_retries_until_ping_succeeds() {
    let (_dir, path) = spawn_vsock_ping_proxy(vec![false, true]).await;
    let start = std::time::Instant::now();
    let result = AgentClient::wait_ready(&path, 52, std::time::Duration::from_secs(2)).await;
    assert!(result.is_ok());
    assert!(
        start.elapsed() >= std::time::Duration::from_millis(90),
        "expected at least one backoff sleep before success"
    );
}

#[tokio::test]
async fn wait_ready_ping_error_after_deadline_returns_ping_error() {
    let (_dir, path) = spawn_vsock_ping_proxy(vec![false]).await;
    let err = match AgentClient::wait_ready(&path, 52, std::time::Duration::ZERO).await {
        Ok(_) => panic!("expected wait_ready ping failure"),
        Err(err) => err,
    };
    assert!(matches!(err, AgentError::Agent(msg) if msg == "not ready yet"));
}

#[tokio::test]
async fn wait_ready_connect_error_after_deadline_returns_connect_error() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.firecracker.vsock");
    let err = match AgentClient::wait_ready(&missing, 52, std::time::Duration::ZERO).await {
        Ok(_) => panic!("expected wait_ready connect failure"),
        Err(err) => err,
    };
    assert!(matches!(err, AgentError::Connection(_)));
}

#[tokio::test]
async fn ping_maps_agent_error_response() {
    let (client, mut server) = tokio::io::duplex(1024);
    let server_task = tokio::spawn(async move {
        let req: AgentRequest = read_message(&mut server).await.unwrap().unwrap();
        assert!(matches!(req, AgentRequest::Ping));
        write_message(
            &mut server,
            &AgentResponse::Error(ErrorResponse {
                message: "boom".into(),
            }),
        )
        .await
        .unwrap();
    });

    let mut conn = AgentConnection::new(client);
    let err = conn.ping().await.unwrap_err();
    assert!(matches!(err, AgentError::Agent(msg) if msg == "boom"));
    server_task.await.unwrap();
}

#[tokio::test]
async fn ping_rejects_unexpected_response_variant() {
    let (client, mut server) = tokio::io::duplex(1024);
    let server_task = tokio::spawn(async move {
        let req: AgentRequest = read_message(&mut server).await.unwrap().unwrap();
        assert!(matches!(req, AgentRequest::Ping));
        write_message(
            &mut server,
            &AgentResponse::Exec(ExecResponse {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }),
        )
        .await
        .unwrap();
    });

    let mut conn = AgentConnection::new(client);
    let err = conn.ping().await.unwrap_err();
    assert!(matches!(err, AgentError::UnexpectedResponse));
    server_task.await.unwrap();
}

#[tokio::test]
async fn exec_maps_agent_error_response() {
    let (client, mut server) = tokio::io::duplex(2048);
    let server_task = tokio::spawn(async move {
        let req: AgentRequest = read_message(&mut server).await.unwrap().unwrap();
        match req {
            AgentRequest::Exec(r) => assert_eq!(r.command, "echo"),
            other => panic!("expected Exec request, got {other:?}"),
        }
        write_message(
            &mut server,
            &AgentResponse::Error(ErrorResponse {
                message: "exec failed in guest".into(),
            }),
        )
        .await
        .unwrap();
    });

    let mut conn = AgentConnection::new(client);
    let err = conn.exec("echo", &["x"], None, &[]).await.unwrap_err();
    assert!(matches!(err, AgentError::Agent(msg) if msg.contains("exec failed")));
    server_task.await.unwrap();
}

#[tokio::test]
async fn exec_rejects_unexpected_response_variant() {
    let (client, mut server) = tokio::io::duplex(2048);
    let server_task = tokio::spawn(async move {
        let _req: AgentRequest = read_message(&mut server).await.unwrap().unwrap();
        write_message(&mut server, &AgentResponse::Pong)
            .await
            .unwrap();
    });

    let mut conn = AgentConnection::new(client);
    let err = conn.exec("echo", &["x"], None, &[]).await.unwrap_err();
    assert!(matches!(err, AgentError::UnexpectedResponse));
    server_task.await.unwrap();
}

#[tokio::test]
async fn read_file_invalid_base64_maps_to_agent_error() {
    let (client, mut server) = tokio::io::duplex(2048);
    let server_task = tokio::spawn(async move {
        let req: AgentRequest = read_message(&mut server).await.unwrap().unwrap();
        assert!(matches!(req, AgentRequest::ReadFile(_)));
        write_message(
            &mut server,
            &AgentResponse::ReadFile(ReadFileResponse {
                data: "%%%".into(),
                size: 3,
                total_size: Some(3),
                modified_nanos: Some(1_700_000_000_000_000_000),
            }),
        )
        .await
        .unwrap();
    });

    let mut conn = AgentConnection::new(client);
    let err = conn.read_file("/tmp/test").await.unwrap_err();
    assert!(matches!(err, AgentError::Agent(msg) if msg.contains("base64 decode failed")));
    server_task.await.unwrap();
}

/// An agent too old for ranged reads ignores `offset` and answers with the
/// start of the file. Handing those bytes back as the requested slice is how a
/// caller ends up with a file of exactly the right length and entirely the
/// wrong contents, so the mismatch is refused rather than returned. The tell is
/// the absent `total_size`: only an agent that honours ranges reports it.
#[tokio::test]
async fn a_legacy_agent_answering_a_ranged_read_from_the_start_is_an_error() {
    let (client, mut server) = tokio::io::duplex(2048);
    let server_task = tokio::spawn(async move {
        let req: AgentRequest = read_message(&mut server).await.unwrap().unwrap();
        assert!(matches!(req, AgentRequest::ReadFile(_)));
        write_message(
            &mut server,
            &AgentResponse::ReadFile(ReadFileResponse {
                data: husker_agent_proto::base64_encode(b"the start of the file"),
                size: 21,
                total_size: None,
                modified_nanos: None,
            }),
        )
        .await
        .unwrap();
    });

    let mut conn = AgentConnection::new(client);
    let err = conn.read_file_range("/tmp/test", 4096, Some(1024)).await;
    let err = err.unwrap_err();
    assert!(
        matches!(err, AgentError::RangedReadUnsupported { offset, .. } if offset == 4096),
        "expected a refused range, got: {err}"
    );
    assert!(
        err.to_string().contains("rebuild or re-import the image"),
        "the message must name the fix: {err}"
    );
    server_task.await.unwrap();
}

/// The same legacy answer at offset 0 is kept, because the whole file it
/// returns does start where the caller asked. Refusing it too would leave a
/// chunking client unable to read anything at all from an older image, rather
/// than only files too big for one response. This is the positive control for
/// the test above: it proves the refusal keys on the offset and not merely on
/// the missing `total_size`.
#[tokio::test]
async fn a_legacy_agent_answering_from_offset_zero_is_accepted_as_the_whole_file() {
    let (client, mut server) = tokio::io::duplex(2048);
    let server_task = tokio::spawn(async move {
        let req: AgentRequest = read_message(&mut server).await.unwrap().unwrap();
        assert!(matches!(req, AgentRequest::ReadFile(_)));
        write_message(
            &mut server,
            &AgentResponse::ReadFile(ReadFileResponse {
                data: husker_agent_proto::base64_encode(b"the whole file"),
                size: 14,
                total_size: None,
                modified_nanos: None,
            }),
        )
        .await
        .unwrap();
    });

    let mut conn = AgentConnection::new(client);
    let read = conn.read_file_range("/tmp/test", 0, Some(4)).await.unwrap();
    assert_eq!(read.data, b"the whole file");
    assert_eq!(
        read.total_size, None,
        "the absent size is what tells the caller the range was not applied"
    );
    server_task.await.unwrap();
}

#[tokio::test]
async fn read_file_rejects_unexpected_response_variant() {
    let (client, mut server) = tokio::io::duplex(2048);
    let server_task = tokio::spawn(async move {
        let req: AgentRequest = read_message(&mut server).await.unwrap().unwrap();
        assert!(matches!(req, AgentRequest::ReadFile(_)));
        write_message(&mut server, &AgentResponse::Pong)
            .await
            .unwrap();
    });

    let mut conn = AgentConnection::new(client);
    let err = conn.read_file("/tmp/test").await.unwrap_err();
    assert!(matches!(err, AgentError::UnexpectedResponse));
    server_task.await.unwrap();
}

#[tokio::test]
async fn write_file_rejects_unexpected_response_variant() {
    let (client, mut server) = tokio::io::duplex(2048);
    let server_task = tokio::spawn(async move {
        let req: AgentRequest = read_message(&mut server).await.unwrap().unwrap();
        assert!(matches!(req, AgentRequest::WriteFile(_)));
        write_message(&mut server, &AgentResponse::Pong)
            .await
            .unwrap();
    });

    let mut conn = AgentConnection::new(client);
    let err = conn
        .write_file("/tmp/out", b"abc", Some(0o644), false)
        .await
        .unwrap_err();
    assert!(matches!(err, AgentError::UnexpectedResponse));
    server_task.await.unwrap();
}

#[tokio::test]
async fn write_file_maps_agent_error_response() {
    let (client, mut server) = tokio::io::duplex(2048);
    let server_task = tokio::spawn(async move {
        let req: AgentRequest = read_message(&mut server).await.unwrap().unwrap();
        assert!(matches!(req, AgentRequest::WriteFile(_)));
        write_message(
            &mut server,
            &AgentResponse::Error(ErrorResponse {
                message: "write denied".into(),
            }),
        )
        .await
        .unwrap();
    });

    let mut conn = AgentConnection::new(client);
    let err = conn
        .write_file("/tmp/out", b"abc", Some(0o644), false)
        .await
        .unwrap_err();
    assert!(matches!(err, AgentError::Agent(msg) if msg == "write denied"));
    server_task.await.unwrap();
}

#[tokio::test]
async fn shell_start_maps_agent_error_response() {
    let (client, mut server) = tokio::io::duplex(2048);
    let server_task = tokio::spawn(async move {
        let req: AgentRequest = read_message(&mut server).await.unwrap().unwrap();
        match req {
            AgentRequest::ShellStart(r) => {
                assert_eq!(r.command.as_deref(), Some("sh"));
                assert_eq!(r.cols, 120);
                assert_eq!(r.rows, 40);
                assert!(r.env.iter().any(|(k, v)| k == "TERM" && v == "xterm"));
            }
            other => panic!("expected ShellStart request, got {other:?}"),
        }
        write_message(
            &mut server,
            &AgentResponse::Error(ErrorResponse {
                message: "shell denied".into(),
            }),
        )
        .await
        .unwrap();
    });

    let mut conn = AgentConnection::new(client);
    let err = conn.shell_start(Some("sh"), 120, 40).await.unwrap_err();
    assert!(matches!(err, AgentError::Agent(msg) if msg == "shell denied"));
    server_task.await.unwrap();
}

#[tokio::test]
async fn shell_start_rejects_unexpected_response_variant() {
    let (client, mut server) = tokio::io::duplex(2048);
    let server_task = tokio::spawn(async move {
        let req: AgentRequest = read_message(&mut server).await.unwrap().unwrap();
        assert!(matches!(req, AgentRequest::ShellStart(_)));
        write_message(&mut server, &AgentResponse::Pong)
            .await
            .unwrap();
    });

    let mut conn = AgentConnection::new(client);
    let err = conn.shell_start(Some("sh"), 80, 24).await.unwrap_err();
    assert!(matches!(err, AgentError::UnexpectedResponse));
    server_task.await.unwrap();
}

#[tokio::test]
async fn shell_recv_invalid_base64_maps_to_agent_error() {
    let (client, mut server) = tokio::io::duplex(2048);
    let server_task = tokio::spawn(async move {
        write_message(
            &mut server,
            &AgentResponse::ShellData(husker_agent_proto::ShellDataResponse { data: "***".into() }),
        )
        .await
        .unwrap();
    });

    let mut conn = AgentConnection::new(client);
    let err = conn.shell_recv().await.unwrap_err();
    assert!(matches!(err, AgentError::Agent(msg) if msg.contains("base64 decode failed")));
    server_task.await.unwrap();
}

#[tokio::test]
async fn shell_recv_rejects_unexpected_response_variant() {
    let (client, mut server) = tokio::io::duplex(1024);
    let server_task = tokio::spawn(async move {
        write_message(
            &mut server,
            &AgentResponse::WriteFile(WriteFileResponse { bytes_written: 1 }),
        )
        .await
        .unwrap();
    });

    let mut conn = AgentConnection::new(client);
    let err = conn.shell_recv().await.unwrap_err();
    assert!(matches!(err, AgentError::UnexpectedResponse));
    server_task.await.unwrap();
}

#[tokio::test]
async fn shell_recv_maps_agent_error_response() {
    let (client, mut server) = tokio::io::duplex(1024);
    let server_task = tokio::spawn(async move {
        write_message(
            &mut server,
            &AgentResponse::Error(ErrorResponse {
                message: "shell failed".into(),
            }),
        )
        .await
        .unwrap();
    });

    let mut conn = AgentConnection::new(client);
    let err = conn.shell_recv().await.unwrap_err();
    assert!(matches!(err, AgentError::Agent(msg) if msg == "shell failed"));
    server_task.await.unwrap();
}

#[tokio::test]
async fn shell_recv_parses_exit_event() {
    let (client, mut server) = tokio::io::duplex(1024);
    let server_task = tokio::spawn(async move {
        write_message(
            &mut server,
            &AgentResponse::ShellExit(ShellExitResponse { exit_code: 7 }),
        )
        .await
        .unwrap();
    });

    let mut conn = AgentConnection::new(client);
    match conn.shell_recv().await.unwrap() {
        ShellEvent::Exit(code) => assert_eq!(code, 7),
        other => panic!("expected exit event, got {other:?}"),
    }
    server_task.await.unwrap();
}

#[tokio::test]
async fn shell_send_encodes_binary_payload() {
    let (client, mut server) = tokio::io::duplex(1024);
    let payload = b"\x00hello\xff".to_vec();
    let expected = payload.clone();
    let server_task = tokio::spawn(async move {
        let req: AgentRequest = read_message(&mut server).await.unwrap().unwrap();
        match req {
            AgentRequest::ShellData(r) => {
                let decoded = base64_decode(&r.data).unwrap();
                assert_eq!(decoded, expected);
            }
            other => panic!("expected shell data, got {other:?}"),
        }
    });

    let mut conn = AgentConnection::new(client);
    conn.shell_send(&payload).await.unwrap();
    server_task.await.unwrap();
}

#[tokio::test]
async fn shell_resize_sends_dimensions() {
    let (client, mut server) = tokio::io::duplex(1024);
    let server_task = tokio::spawn(async move {
        let req: AgentRequest = read_message(&mut server).await.unwrap().unwrap();
        match req {
            AgentRequest::ShellResize(r) => {
                assert_eq!(r.cols, 132);
                assert_eq!(r.rows, 43);
            }
            other => panic!("expected shell resize, got {other:?}"),
        }
    });

    let mut conn = AgentConnection::new(client);
    conn.shell_resize(132, 43).await.unwrap();
    server_task.await.unwrap();
}

#[tokio::test]
async fn guest_info_returns_addresses() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();
    let info = conn.guest_info().await.expect("guest_info");
    // The host agent returns its own non-loopback IPv4 addresses.
    // In CI there is always at least one.
    for addr in &info.ipv4 {
        let ip: std::net::Ipv4Addr = addr.parse().expect("valid IPv4");
        assert!(!ip.is_loopback(), "loopback address returned: {ip}");
    }
}

#[tokio::test]
async fn guest_info_maps_agent_error_response() {
    let (client, mut server) = tokio::io::duplex(1024);
    let server_task = tokio::spawn(async move {
        let req: AgentRequest = read_message(&mut server).await.unwrap().unwrap();
        assert!(matches!(req, AgentRequest::GuestInfo));
        write_message(
            &mut server,
            &AgentResponse::Error(ErrorResponse {
                message: "no network info".into(),
            }),
        )
        .await
        .unwrap();
    });

    let mut conn = AgentConnection::new(client);
    let err = conn.guest_info().await.unwrap_err();
    assert!(matches!(err, AgentError::Agent(msg) if msg == "no network info"));
    server_task.await.unwrap();
}

#[tokio::test]
async fn guest_info_rejects_unexpected_response_variant() {
    let (client, mut server) = tokio::io::duplex(1024);
    let server_task = tokio::spawn(async move {
        let req: AgentRequest = read_message(&mut server).await.unwrap().unwrap();
        assert!(matches!(req, AgentRequest::GuestInfo));
        write_message(&mut server, &AgentResponse::Pong)
            .await
            .unwrap();
    });

    let mut conn = AgentConnection::new(client);
    let err = conn.guest_info().await.unwrap_err();
    assert!(matches!(err, AgentError::UnexpectedResponse));
    server_task.await.unwrap();
}

#[tokio::test]
async fn guest_info_returns_info_with_addresses() {
    let (client, mut server) = tokio::io::duplex(1024);
    let server_task = tokio::spawn(async move {
        let req: AgentRequest = read_message(&mut server).await.unwrap().unwrap();
        assert!(matches!(req, AgentRequest::GuestInfo));
        write_message(
            &mut server,
            &AgentResponse::GuestInfo(GuestInfoResponse {
                ipv4: vec!["192.0.2.7".into(), "198.51.100.1".into()],
                protocol_version: husker_agent_proto::PROTOCOL_VERSION,
            }),
        )
        .await
        .unwrap();
    });

    let mut conn = AgentConnection::new(client);
    let info = conn.guest_info().await.unwrap();
    assert_eq!(info.ipv4, vec!["192.0.2.7", "198.51.100.1"]);
    assert_eq!(info.protocol_version, husker_agent_proto::PROTOCOL_VERSION);
    server_task.await.unwrap();
}
