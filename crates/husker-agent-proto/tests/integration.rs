use husker_agent_proto::{
    AgentRequest, AgentResponse, ExecRequest, ExecResponse, ReadFileResponse, WriteFileResponse,
    read_message, write_message,
};

/// Helper: create a connected Unix socket pair.
async fn socket_pair() -> (tokio::net::UnixStream, tokio::net::UnixStream) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let client = tokio::net::UnixStream::connect(&path).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (client, server)
}

#[tokio::test]
async fn ping_pong_roundtrip() {
    let (mut client, mut server) = socket_pair().await;

    write_message(&mut client, &AgentRequest::Ping)
        .await
        .unwrap();

    let msg: AgentRequest = read_message(&mut server).await.unwrap().unwrap();
    assert!(matches!(msg, AgentRequest::Ping));

    write_message(&mut server, &AgentResponse::Pong)
        .await
        .unwrap();

    let msg: AgentResponse = read_message(&mut client).await.unwrap().unwrap();
    assert!(matches!(msg, AgentResponse::Pong));
}

#[tokio::test]
async fn exec_request_roundtrip() {
    let (mut client, mut server) = socket_pair().await;

    let request = AgentRequest::Exec(ExecRequest {
        command: "ls".into(),
        args: vec!["-la".into(), "/tmp".into()],
        working_dir: Some("/home".into()),
        env: vec![("FOO".into(), "bar".into())],
        timeout_secs: None,
    });
    write_message(&mut client, &request).await.unwrap();

    let msg: AgentRequest = read_message(&mut server).await.unwrap().unwrap();
    match msg {
        AgentRequest::Exec(e) => {
            assert_eq!(e.command, "ls");
            assert_eq!(e.args, vec!["-la", "/tmp"]);
            assert_eq!(e.working_dir.as_deref(), Some("/home"));
            assert_eq!(e.env, vec![("FOO".into(), "bar".into())]);
        }
        _ => panic!("expected Exec"),
    }

    let response = AgentResponse::Exec(ExecResponse {
        exit_code: 0,
        stdout: "hello\n".into(),
        stderr: String::new(),
    });
    write_message(&mut server, &response).await.unwrap();

    let msg: AgentResponse = read_message(&mut client).await.unwrap().unwrap();
    match msg {
        AgentResponse::Exec(e) => {
            assert_eq!(e.exit_code, 0);
            assert_eq!(e.stdout, "hello\n");
            assert!(e.stderr.is_empty());
        }
        _ => panic!("expected Exec response"),
    }
}

#[tokio::test]
async fn multiple_requests_on_one_connection() {
    let (mut client, mut server) = socket_pair().await;

    // Send three requests in sequence
    for i in 0..3 {
        let request = AgentRequest::Exec(ExecRequest {
            command: format!("cmd{i}"),
            args: vec![],
            working_dir: None,
            env: vec![],
            timeout_secs: None,
        });
        write_message(&mut client, &request).await.unwrap();

        let msg: AgentRequest = read_message(&mut server).await.unwrap().unwrap();
        match msg {
            AgentRequest::Exec(e) => assert_eq!(e.command, format!("cmd{i}")),
            _ => panic!("expected Exec"),
        }

        let response = AgentResponse::Exec(ExecResponse {
            exit_code: i,
            stdout: String::new(),
            stderr: String::new(),
        });
        write_message(&mut server, &response).await.unwrap();

        let msg: AgentResponse = read_message(&mut client).await.unwrap().unwrap();
        match msg {
            AgentResponse::Exec(e) => assert_eq!(e.exit_code, i),
            _ => panic!("expected Exec response"),
        }
    }
}

#[tokio::test]
async fn large_message_roundtrip() {
    let (mut client, mut server) = socket_pair().await;

    // 64 KiB of data — large enough to exceed the socket buffer.
    // Writer and reader must run concurrently to avoid deadlock.
    let large_data = "x".repeat(64 * 1024);
    let large_data_clone = large_data.clone();

    let writer = tokio::spawn(async move {
        let response = AgentResponse::ReadFile(ReadFileResponse {
            data: large_data_clone,
            size: 64 * 1024,
            total_size: Some(64 * 1024),
            modified_nanos: Some(1_700_000_000_000_000_000),
        });
        write_message(&mut client, &response).await.unwrap();
    });

    let msg: AgentResponse = read_message(&mut server).await.unwrap().unwrap();
    writer.await.unwrap();

    match msg {
        AgentResponse::ReadFile(r) => {
            assert_eq!(r.data.len(), large_data.len());
            assert_eq!(r.size, 64 * 1024);
        }
        _ => panic!("expected ReadFile response"),
    }
}

#[tokio::test]
async fn eof_returns_none() {
    let (client, mut server) = socket_pair().await;

    // Drop the client to close the connection
    drop(client);

    let result: Option<AgentRequest> = read_message(&mut server).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn write_file_response_roundtrip() {
    let (mut client, mut server) = socket_pair().await;

    let response = AgentResponse::WriteFile(WriteFileResponse { bytes_written: 42 });
    write_message(&mut client, &response).await.unwrap();

    let msg: AgentResponse = read_message(&mut server).await.unwrap().unwrap();
    match msg {
        AgentResponse::WriteFile(w) => assert_eq!(w.bytes_written, 42),
        _ => panic!("expected WriteFile response"),
    }
}
