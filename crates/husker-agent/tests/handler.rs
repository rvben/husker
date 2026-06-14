use husker_agent_proto::{
    AgentRequest, AgentResponse, ExecRequest, ReadFileRequest, ShellDataRequest,
    ShellResizeRequest, ShellStartRequest, WriteFileRequest, base64_decode, base64_encode,
    read_message, write_message,
};

/// Spawn the agent handler on a temporary Unix socket and return a connected client stream.
async fn spawn_agent() -> tokio::net::UnixStream {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();

    // Leak the tempdir so it lives for the test duration
    let _dir = Box::leak(Box::new(dir));

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        husker_agent::handle_connection(stream).await.unwrap();
    });

    tokio::net::UnixStream::connect(&path).await.unwrap()
}

fn pty_unavailable(message: &str) -> bool {
    message.contains("failed to open PTY")
        || message.contains("Device not configured")
        || message.contains("No such device")
}

async fn shell_start_or_skip(
    stream: &mut tokio::net::UnixStream,
    request: ShellStartRequest,
) -> bool {
    write_message(stream, &AgentRequest::ShellStart(request))
        .await
        .unwrap();

    let response: AgentResponse = read_message(stream).await.unwrap().unwrap();
    match response {
        AgentResponse::ShellStarted => true,
        AgentResponse::Error(e) if pty_unavailable(&e.message) => {
            eprintln!("skipping shell test: {}", e.message);
            false
        }
        other => panic!("expected ShellStarted, got {other:?}"),
    }
}

#[tokio::test]
async fn ping() {
    let mut stream = spawn_agent().await;

    write_message(&mut stream, &AgentRequest::Ping)
        .await
        .unwrap();
    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    assert!(matches!(response, AgentResponse::Pong));
}

#[tokio::test]
async fn exec_echo() {
    let mut stream = spawn_agent().await;

    let request = AgentRequest::Exec(ExecRequest {
        command: "echo".into(),
        args: vec!["hello".into()],
        working_dir: None,
        env: vec![],
        timeout_secs: None,
    });
    write_message(&mut stream, &request).await.unwrap();

    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    match response {
        AgentResponse::Exec(r) => {
            assert_eq!(r.exit_code, 0);
            assert_eq!(r.stdout.trim(), "hello");
            assert!(r.stderr.is_empty());
        }
        _ => panic!("expected Exec response, got {response:?}"),
    }
}

#[tokio::test]
async fn exec_with_env() {
    let mut stream = spawn_agent().await;

    let request = AgentRequest::Exec(ExecRequest {
        command: "sh".into(),
        args: vec!["-c".into(), "echo $MY_VAR".into()],
        working_dir: None,
        env: vec![("MY_VAR".into(), "test_value".into())],
        timeout_secs: None,
    });
    write_message(&mut stream, &request).await.unwrap();

    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    match response {
        AgentResponse::Exec(r) => {
            assert_eq!(r.exit_code, 0);
            assert_eq!(r.stdout.trim(), "test_value");
        }
        _ => panic!("expected Exec response, got {response:?}"),
    }
}

#[tokio::test]
async fn exec_times_out_on_long_running_command() {
    // Safety: test is serialized by `serial_test`-free convention here because
    // no other test reads this env var, and they all use commands that finish
    // in milliseconds.
    unsafe {
        std::env::set_var("HUSKER_AGENT_EXEC_TIMEOUT_SECS", "1");
    }
    let mut stream = spawn_agent().await;

    let request = AgentRequest::Exec(ExecRequest {
        command: "sleep".into(),
        args: vec!["30".into()],
        working_dir: None,
        env: vec![],
        timeout_secs: None,
    });
    write_message(&mut stream, &request).await.unwrap();

    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    unsafe {
        std::env::remove_var("HUSKER_AGENT_EXEC_TIMEOUT_SECS");
    }
    // A timed-out exec returns the conventional 124 exit code with whatever
    // output the command produced, plus a note - never a bare error that drops it.
    match response {
        AgentResponse::Exec(r) => {
            assert_eq!(r.exit_code, 124, "timeout should report exit 124");
            assert!(
                r.stderr.contains("timed out"),
                "expected a timeout note in stderr, got: {}",
                r.stderr
            );
        }
        other => panic!("expected Exec with exit 124, got {other:?}"),
    }
}

#[tokio::test]
async fn exec_nonexistent_command() {
    let mut stream = spawn_agent().await;

    let request = AgentRequest::Exec(ExecRequest {
        command: "nonexistent_command_12345".into(),
        args: vec![],
        working_dir: None,
        env: vec![],
        timeout_secs: None,
    });
    write_message(&mut stream, &request).await.unwrap();

    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    match response {
        AgentResponse::Error(e) => {
            assert!(e.message.contains("exec failed"), "got: {}", e.message);
        }
        _ => panic!("expected Error response, got {response:?}"),
    }
}

#[tokio::test]
async fn write_then_read_file() {
    let mut stream = spawn_agent().await;

    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("test.txt").to_string_lossy().into_owned();
    let content = b"hello from test";

    // Write file
    let request = AgentRequest::WriteFile(WriteFileRequest {
        path: file_path.clone(),
        data: base64_encode(content),
        mode: None,
    });
    write_message(&mut stream, &request).await.unwrap();

    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    match response {
        AgentResponse::WriteFile(w) => {
            assert_eq!(w.bytes_written, content.len() as u64);
        }
        _ => panic!("expected WriteFile response, got {response:?}"),
    }

    // Read it back
    let request = AgentRequest::ReadFile(ReadFileRequest { path: file_path });
    write_message(&mut stream, &request).await.unwrap();

    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    match response {
        AgentResponse::ReadFile(r) => {
            assert_eq!(r.size, content.len() as u64);
            let decoded = husker_agent_proto::base64_decode(&r.data).unwrap();
            assert_eq!(decoded, content);
        }
        _ => panic!("expected ReadFile response, got {response:?}"),
    }
}

#[tokio::test]
async fn read_file_rejects_oversized_file() {
    // Safety: no other test reads this env var concurrently.
    unsafe {
        std::env::set_var("HUSKER_AGENT_MAX_READ_BYTES", "64");
    }
    let mut stream = spawn_agent().await;

    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("big.bin");
    std::fs::write(&file_path, vec![0u8; 128]).unwrap();

    let request = AgentRequest::ReadFile(ReadFileRequest {
        path: file_path.to_string_lossy().into_owned(),
    });
    write_message(&mut stream, &request).await.unwrap();

    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    unsafe {
        std::env::remove_var("HUSKER_AGENT_MAX_READ_BYTES");
    }
    match response {
        AgentResponse::Error(e) => {
            assert!(
                e.message.contains("exceeds max read size"),
                "got unexpected error: {}",
                e.message
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn read_nonexistent_file() {
    let mut stream = spawn_agent().await;

    let request = AgentRequest::ReadFile(ReadFileRequest {
        path: "/tmp/nonexistent_file_12345_husker_test".into(),
    });
    write_message(&mut stream, &request).await.unwrap();

    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    match response {
        AgentResponse::Error(e) => {
            assert!(e.message.contains("read failed"), "got: {}", e.message);
        }
        _ => panic!("expected Error response, got {response:?}"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn write_file_refuses_symlink_target() {
    let mut stream = spawn_agent().await;

    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.txt");
    std::fs::write(&real, b"original").unwrap();
    let link = dir.path().join("link.txt");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let request = AgentRequest::WriteFile(WriteFileRequest {
        path: link.to_string_lossy().into_owned(),
        data: base64_encode(b"attacker payload"),
        mode: None,
    });
    write_message(&mut stream, &request).await.unwrap();

    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    match response {
        AgentResponse::Error(e) => {
            assert!(
                e.message.contains("write failed"),
                "got unexpected error: {}",
                e.message
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }

    let contents = std::fs::read(&real).unwrap();
    assert_eq!(contents, b"original", "symlink target must not be modified");
}

#[cfg(unix)]
#[tokio::test]
async fn read_file_refuses_symlink_target() {
    let mut stream = spawn_agent().await;

    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("secret.txt");
    std::fs::write(&real, b"sensitive").unwrap();
    let link = dir.path().join("link.txt");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let request = AgentRequest::ReadFile(ReadFileRequest {
        path: link.to_string_lossy().into_owned(),
    });
    write_message(&mut stream, &request).await.unwrap();

    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    match response {
        AgentResponse::Error(e) => {
            assert!(
                e.message.contains("read failed"),
                "got unexpected error: {}",
                e.message
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn write_file_invalid_base64_returns_error() {
    let mut stream = spawn_agent().await;

    let request = AgentRequest::WriteFile(WriteFileRequest {
        path: "/tmp/husker-invalid-b64".into(),
        data: "***".into(),
        mode: None,
    });
    write_message(&mut stream, &request).await.unwrap();

    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    match response {
        AgentResponse::Error(e) => {
            assert!(
                e.message.contains("base64 decode failed"),
                "got unexpected error: {}",
                e.message
            );
        }
        other => panic!("expected Error response, got {other:?}"),
    }
}

#[tokio::test]
async fn shell_data_without_session_returns_error() {
    let mut stream = spawn_agent().await;

    let request = AgentRequest::ShellData(ShellDataRequest {
        data: base64_encode(b"echo hi\n"),
    });
    write_message(&mut stream, &request).await.unwrap();

    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    match response {
        AgentResponse::Error(e) => {
            assert!(
                e.message
                    .contains("shell messages are not valid outside a shell session"),
                "got unexpected error: {}",
                e.message
            );
        }
        other => panic!("expected Error response, got {other:?}"),
    }
}

#[tokio::test]
async fn shell_resize_without_session_returns_error() {
    let mut stream = spawn_agent().await;

    let request = AgentRequest::ShellResize(ShellResizeRequest {
        cols: 100,
        rows: 50,
    });
    write_message(&mut stream, &request).await.unwrap();

    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    match response {
        AgentResponse::Error(e) => {
            assert!(
                e.message
                    .contains("shell messages are not valid outside a shell session"),
                "got unexpected error: {}",
                e.message
            );
        }
        other => panic!("expected Error response, got {other:?}"),
    }
}

#[tokio::test]
async fn multiple_operations_on_one_connection() {
    let mut stream = spawn_agent().await;

    // Ping
    write_message(&mut stream, &AgentRequest::Ping)
        .await
        .unwrap();
    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    assert!(matches!(response, AgentResponse::Pong));

    // Exec
    let request = AgentRequest::Exec(ExecRequest {
        command: "echo".into(),
        args: vec!["test".into()],
        working_dir: None,
        env: vec![],
        timeout_secs: None,
    });
    write_message(&mut stream, &request).await.unwrap();
    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    assert!(matches!(response, AgentResponse::Exec(_)));

    // Ping again
    write_message(&mut stream, &AgentRequest::Ping)
        .await
        .unwrap();
    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    assert!(matches!(response, AgentResponse::Pong));
}

#[tokio::test]
async fn shell_echo_with_cat() {
    let mut stream = spawn_agent().await;

    // Start shell with `cat` which echoes stdin to stdout
    if !shell_start_or_skip(
        &mut stream,
        ShellStartRequest {
            command: Some("cat".into()),
            env: vec![],
            cols: 80,
            rows: 24,
        },
    )
    .await
    {
        return;
    }

    // Send data to cat via stdin
    let input = b"hello\n";
    let request = AgentRequest::ShellData(ShellDataRequest {
        data: base64_encode(input),
    });
    write_message(&mut stream, &request).await.unwrap();

    // Collect output — with a PTY, the terminal echoes input and cat re-echoes it,
    // both with \r\n line endings (onlcr converts \n to \r\n).
    let mut output = Vec::new();
    while let Ok(Ok(Some(AgentResponse::ShellData(d)))) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        read_message::<AgentResponse, _>(&mut stream),
    )
    .await
    {
        output.extend(base64_decode(&d.data).unwrap());
        if output.windows(5).any(|w| w == b"hello") {
            break;
        }
    }

    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("hello"),
        "expected output to contain 'hello', got: {text:?}"
    );

    // Drop the stream to close stdin, which causes cat to exit
    drop(stream);
}

#[tokio::test]
async fn shell_immediate_exit() {
    let mut stream = spawn_agent().await;

    // Start shell with a command that exits immediately with output
    if !shell_start_or_skip(
        &mut stream,
        ShellStartRequest {
            command: Some("echo".into()),
            env: vec![],
            cols: 80,
            rows: 24,
        },
    )
    .await
    {
        return;
    }

    // Collect all responses until ShellExit
    let mut output_data = Vec::new();
    let exit_code = loop {
        let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
        match response {
            AgentResponse::ShellData(d) => {
                output_data.extend(base64_decode(&d.data).unwrap());
            }
            AgentResponse::ShellExit(e) => {
                break e.exit_code;
            }
            other => panic!("unexpected response: {other:?}"),
        }
    };

    // `echo` with no args outputs a newline; PTY onlcr converts \n to \r\n
    assert_eq!(output_data, b"\r\n");
    assert_eq!(exit_code, 0);
}

#[tokio::test]
async fn shell_nonzero_exit_code() {
    let mut stream = spawn_agent().await;

    if !shell_start_or_skip(
        &mut stream,
        ShellStartRequest {
            command: Some("sh".into()),
            env: vec![],
            cols: 80,
            rows: 24,
        },
    )
    .await
    {
        return;
    }

    // Send exit 42 to the shell
    let request = AgentRequest::ShellData(ShellDataRequest {
        data: base64_encode(b"exit 42\n"),
    });
    write_message(&mut stream, &request).await.unwrap();

    // Collect until ShellExit
    let exit_code = loop {
        let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
        match response {
            AgentResponse::ShellData(_) => {}
            AgentResponse::ShellExit(e) => {
                break e.exit_code;
            }
            other => panic!("unexpected response: {other:?}"),
        }
    };

    assert_eq!(exit_code, 42);
}

#[tokio::test]
async fn shell_resize_accepted() {
    let mut stream = spawn_agent().await;

    if !shell_start_or_skip(
        &mut stream,
        ShellStartRequest {
            command: Some("cat".into()),
            env: vec![],
            cols: 80,
            rows: 24,
        },
    )
    .await
    {
        return;
    }

    // Send resize — should be accepted without error
    let request = AgentRequest::ShellResize(ShellResizeRequest {
        cols: 120,
        rows: 40,
    });
    write_message(&mut stream, &request).await.unwrap();

    // Send data to verify the shell is still alive after resize
    let request = AgentRequest::ShellData(ShellDataRequest {
        data: base64_encode(b"test\n"),
    });
    write_message(&mut stream, &request).await.unwrap();

    // Collect output — PTY echoes input with \r\n line endings
    let mut output = Vec::new();
    while let Ok(Ok(Some(AgentResponse::ShellData(d)))) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        read_message::<AgentResponse, _>(&mut stream),
    )
    .await
    {
        output.extend(base64_decode(&d.data).unwrap());
        if output.windows(4).any(|w| w == b"test") {
            break;
        }
    }

    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("test"),
        "expected output to contain 'test', got: {text:?}"
    );

    drop(stream);
}

#[tokio::test]
async fn normal_requests_still_work_with_shell_protocol() {
    // Regression test: verify existing request types still work
    // after the shell protocol was added
    let mut stream = spawn_agent().await;

    // Ping
    write_message(&mut stream, &AgentRequest::Ping)
        .await
        .unwrap();
    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    assert!(matches!(response, AgentResponse::Pong));

    // Exec
    let request = AgentRequest::Exec(ExecRequest {
        command: "echo".into(),
        args: vec!["regression_test".into()],
        working_dir: None,
        env: vec![],
        timeout_secs: None,
    });
    write_message(&mut stream, &request).await.unwrap();
    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    match response {
        AgentResponse::Exec(r) => {
            assert_eq!(r.exit_code, 0);
            assert_eq!(r.stdout.trim(), "regression_test");
        }
        _ => panic!("expected Exec response, got {response:?}"),
    }

    // Write + Read file
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir
        .path()
        .join("shell_test.txt")
        .to_string_lossy()
        .into_owned();
    let content = b"shell protocol regression";

    let request = AgentRequest::WriteFile(WriteFileRequest {
        path: file_path.clone(),
        data: base64_encode(content),
        mode: None,
    });
    write_message(&mut stream, &request).await.unwrap();
    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    assert!(matches!(response, AgentResponse::WriteFile(_)));

    let request = AgentRequest::ReadFile(ReadFileRequest { path: file_path });
    write_message(&mut stream, &request).await.unwrap();
    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    match response {
        AgentResponse::ReadFile(r) => {
            let decoded = base64_decode(&r.data).unwrap();
            assert_eq!(decoded, content);
        }
        _ => panic!("expected ReadFile response, got {response:?}"),
    }
}

#[tokio::test]
async fn shell_nonexistent_command() {
    let mut stream = spawn_agent().await;

    let request = AgentRequest::ShellStart(ShellStartRequest {
        command: Some("nonexistent_command_12345".into()),
        env: vec![],
        cols: 80,
        rows: 24,
    });
    write_message(&mut stream, &request).await.unwrap();

    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    match response {
        AgentResponse::Error(e) if pty_unavailable(&e.message) => {
            eprintln!("skipping shell test: {}", e.message);
        }
        AgentResponse::Error(e) => {
            assert!(
                e.message.contains("failed to start shell"),
                "got: {}",
                e.message
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn shell_with_env_vars() {
    let mut stream = spawn_agent().await;

    if !shell_start_or_skip(
        &mut stream,
        ShellStartRequest {
            command: Some("sh".into()),
            env: vec![("MY_SHELL_VAR".into(), "shell_value".into())],
            cols: 80,
            rows: 24,
        },
    )
    .await
    {
        return;
    }

    // Ask the shell to print the env var
    let request = AgentRequest::ShellData(ShellDataRequest {
        data: base64_encode(b"echo $MY_SHELL_VAR\nexit 0\n"),
    });
    write_message(&mut stream, &request).await.unwrap();

    // Collect output
    let mut output_data = Vec::new();
    loop {
        let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
        match response {
            AgentResponse::ShellData(d) => {
                output_data.extend(base64_decode(&d.data).unwrap());
            }
            AgentResponse::ShellExit(e) => {
                assert_eq!(e.exit_code, 0);
                break;
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    let output = String::from_utf8_lossy(&output_data);
    assert!(
        output.contains("shell_value"),
        "expected output to contain 'shell_value', got: {output}"
    );
}

/// Verify that multiple env vars are passed through to the shell, including TERM.
///
/// The host sends TERM=xterm by default. This test verifies that TERM (and
/// additional env vars) are visible inside the spawned shell process.
#[tokio::test]
async fn shell_term_and_multiple_env_vars() {
    let mut stream = spawn_agent().await;

    if !shell_start_or_skip(
        &mut stream,
        ShellStartRequest {
            command: Some("sh".into()),
            env: vec![
                ("TERM".into(), "xterm".into()),
                ("HUSKER_TEST".into(), "42".into()),
            ],
            cols: 80,
            rows: 24,
        },
    )
    .await
    {
        return;
    }

    let request = AgentRequest::ShellData(ShellDataRequest {
        data: base64_encode(b"echo TERM=$TERM HUSKER_TEST=$HUSKER_TEST\nexit 0\n"),
    });
    write_message(&mut stream, &request).await.unwrap();

    let mut output_data = Vec::new();
    loop {
        let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
        match response {
            AgentResponse::ShellData(d) => {
                output_data.extend(base64_decode(&d.data).unwrap());
            }
            AgentResponse::ShellExit(e) => {
                assert_eq!(e.exit_code, 0);
                break;
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    let output = String::from_utf8_lossy(&output_data);
    assert!(
        output.contains("TERM=xterm"),
        "expected TERM=xterm in output, got: {output}"
    );
    assert!(
        output.contains("HUSKER_TEST=42"),
        "expected HUSKER_TEST=42 in output, got: {output}"
    );
}

#[tokio::test]
async fn shell_start_without_command_uses_default_shell() {
    let mut stream = spawn_agent().await;

    if !shell_start_or_skip(
        &mut stream,
        ShellStartRequest {
            command: None,
            env: vec![],
            cols: 80,
            rows: 24,
        },
    )
    .await
    {
        return;
    }

    let request = AgentRequest::ShellData(ShellDataRequest {
        data: base64_encode(b"echo DEFAULT-SHELL\nexit 0\n"),
    });
    write_message(&mut stream, &request).await.unwrap();

    let mut output_data = Vec::new();
    loop {
        let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
        match response {
            AgentResponse::ShellData(d) => output_data.extend(base64_decode(&d.data).unwrap()),
            AgentResponse::ShellExit(e) => {
                assert_eq!(e.exit_code, 0);
                break;
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    let output = String::from_utf8_lossy(&output_data);
    assert!(
        output.contains("DEFAULT-SHELL"),
        "expected default shell output, got: {output}"
    );
}

#[tokio::test]
async fn shell_ignores_unexpected_messages_during_session() {
    let mut stream = spawn_agent().await;

    if !shell_start_or_skip(
        &mut stream,
        ShellStartRequest {
            command: Some("cat".into()),
            env: vec![],
            cols: 80,
            rows: 24,
        },
    )
    .await
    {
        return;
    }

    // This message type is irrelevant once in shell mode and should be ignored.
    write_message(&mut stream, &AgentRequest::Ping)
        .await
        .unwrap();

    let request = AgentRequest::ShellData(ShellDataRequest {
        data: base64_encode(b"after-ping\n"),
    });
    write_message(&mut stream, &request).await.unwrap();

    let mut output = Vec::new();
    while let Ok(Ok(Some(AgentResponse::ShellData(d)))) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        read_message::<AgentResponse, _>(&mut stream),
    )
    .await
    {
        output.extend(base64_decode(&d.data).unwrap());
        if output.windows(10).any(|w| w == b"after-ping") {
            break;
        }
    }

    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("after-ping"),
        "expected output to contain 'after-ping', got: {text:?}"
    );
}

#[tokio::test]
async fn shell_invalid_base64_input_is_ignored() {
    let mut stream = spawn_agent().await;

    if !shell_start_or_skip(
        &mut stream,
        ShellStartRequest {
            command: Some("cat".into()),
            env: vec![],
            cols: 80,
            rows: 24,
        },
    )
    .await
    {
        return;
    }

    // Invalid base64 should be ignored by the shell loop.
    let request = AgentRequest::ShellData(ShellDataRequest { data: "***".into() });
    write_message(&mut stream, &request).await.unwrap();

    // Valid data should still be processed afterwards.
    let request = AgentRequest::ShellData(ShellDataRequest {
        data: base64_encode(b"valid-after-invalid\n"),
    });
    write_message(&mut stream, &request).await.unwrap();

    let mut output = Vec::new();
    while let Ok(Ok(Some(AgentResponse::ShellData(d)))) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        read_message::<AgentResponse, _>(&mut stream),
    )
    .await
    {
        output.extend(base64_decode(&d.data).unwrap());
        if output.windows(19).any(|w| w == b"valid-after-invalid") {
            break;
        }
    }

    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("valid-after-invalid"),
        "expected output to contain 'valid-after-invalid', got: {text:?}"
    );
}

#[tokio::test]
async fn guest_info_reports_ipv4_addresses() {
    let mut stream = spawn_agent().await;

    write_message(&mut stream, &AgentRequest::GuestInfo)
        .await
        .unwrap();

    let resp: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    match resp {
        AgentResponse::GuestInfo(info) => {
            for addr in &info.ipv4 {
                let ip: std::net::Ipv4Addr = addr.parse().expect("valid IPv4");
                assert!(!ip.is_loopback(), "loopback must be filtered: {ip}");
            }
        }
        other => panic!("expected GuestInfo, got {other:?}"),
    }
}

/// Verify that shell data flows correctly after an idle period.
///
/// Regression test for connection lifetime: if the transport is torn down
/// after the initial handshake, data sent after a delay would never arrive.
#[tokio::test]
async fn shell_data_after_idle_period() {
    let mut stream = spawn_agent().await;

    if !shell_start_or_skip(
        &mut stream,
        ShellStartRequest {
            command: Some("cat".into()),
            env: vec![],
            cols: 80,
            rows: 24,
        },
    )
    .await
    {
        return;
    }

    // Wait to simulate the delay between handshake and actual use
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Send data after the idle period
    let request = AgentRequest::ShellData(ShellDataRequest {
        data: base64_encode(b"delayed-input\n"),
    });
    write_message(&mut stream, &request).await.unwrap();

    // Verify the data echoes back through the PTY
    let mut output_data = Vec::new();
    loop {
        let response: AgentResponse = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_message::<AgentResponse, _>(&mut stream),
        )
        .await
        .expect("timed out waiting for shell data after idle")
        .unwrap()
        .unwrap();
        match response {
            AgentResponse::ShellData(d) => {
                output_data.extend(base64_decode(&d.data).unwrap());
                let text = String::from_utf8_lossy(&output_data);
                if text.contains("delayed-input") {
                    break;
                }
            }
            other => panic!("unexpected response after idle: {other:?}"),
        }
    }

    let output = String::from_utf8_lossy(&output_data);
    assert!(
        output.contains("delayed-input"),
        "expected 'delayed-input' after idle period, got: {output}"
    );
}
