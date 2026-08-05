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
async fn exec_empty_command_without_an_oci_image_errors_clearly() {
    // An empty command means "run the image default", but a plain rootfs (no
    // /etc/husker/oci-config.json) has none: the agent returns a clear error
    // instead of panicking or spawning an empty program.
    let mut stream = spawn_agent().await;

    let request = AgentRequest::Exec(ExecRequest {
        command: String::new(),
        args: vec![],
        working_dir: None,
        env: vec![],
        timeout_secs: None,
    });
    write_message(&mut stream, &request).await.unwrap();

    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    match response {
        AgentResponse::Error(e) => assert!(
            e.message.contains("no command given"),
            "expected a clear no-default error, got: {}",
            e.message
        ),
        other => panic!("expected Error response, got {other:?}"),
    }
}

#[tokio::test]
async fn exec_returns_promptly_when_a_backgrounded_child_holds_the_pipe() {
    // A foreground command that exits while a backgrounded process inherits its
    // stdout must not keep `exec` blocked: once the foreground command is done we
    // return its output promptly (bounded by the drain grace) instead of waiting
    // for the orphaned grandchild to close the pipe. Regression for an unbounded
    // drain-join on the clean-exit path.
    let mut stream = spawn_agent().await;

    let request = AgentRequest::Exec(ExecRequest {
        command: "sh".into(),
        args: vec!["-c".into(), "sleep 30 & echo done".into()],
        working_dir: None,
        env: vec![],
        timeout_secs: Some(60),
    });
    write_message(&mut stream, &request).await.unwrap();

    let response =
        tokio::time::timeout(std::time::Duration::from_secs(5), read_message(&mut stream))
            .await
            .expect(
                "exec must return promptly after the foreground child exits, not block \
                 on the backgrounded grandchild still holding the stdout pipe",
            )
            .unwrap()
            .unwrap();

    match response {
        AgentResponse::Exec(r) => {
            assert_eq!(r.exit_code, 0, "foreground command exited cleanly");
            assert_eq!(r.stdout.trim(), "done");
        }
        other => panic!("expected Exec response, got {other:?}"),
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
        append: false,
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
    let request = AgentRequest::ReadFile(ReadFileRequest {
        path: file_path,
        offset: 0,
        len: None,
    });
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

#[cfg(unix)]
#[tokio::test]
async fn write_file_applies_requested_mode() {
    use std::os::unix::fs::PermissionsExt;
    let mut stream = spawn_agent().await;

    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("script.sh").to_string_lossy().into_owned();

    let request = AgentRequest::WriteFile(WriteFileRequest {
        path: file_path.clone(),
        data: base64_encode(b"#!/bin/sh\necho hi\n"),
        mode: Some(0o755),
        append: false,
    });
    write_message(&mut stream, &request).await.unwrap();

    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    assert!(
        matches!(response, AgentResponse::WriteFile(_)),
        "expected WriteFile success, got {response:?}"
    );

    // The requested mode must actually land on the file: a silently dropped
    // chmod (e.g. on an executable userdata script) is a real failure.
    let mode = std::fs::metadata(&file_path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o755);
}

#[tokio::test]
async fn write_file_append_true_appends_instead_of_truncating() {
    let mut stream = spawn_agent().await;

    let dir = tempfile::tempdir().unwrap();
    let file_path = dir
        .path()
        .join("appended.txt")
        .to_string_lossy()
        .into_owned();

    // First write: append = false truncates (creates the file with its
    // initial content), matching the pre-chunking behaviour exactly.
    let request = AgentRequest::WriteFile(WriteFileRequest {
        path: file_path.clone(),
        data: base64_encode(b"first-"),
        mode: None,
        append: false,
    });
    write_message(&mut stream, &request).await.unwrap();
    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    assert!(matches!(response, AgentResponse::WriteFile(_)));

    // Second write: append = true must add to the file rather than replace it.
    let request = AgentRequest::WriteFile(WriteFileRequest {
        path: file_path.clone(),
        data: base64_encode(b"second"),
        mode: None,
        append: true,
    });
    write_message(&mut stream, &request).await.unwrap();
    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    assert!(matches!(response, AgentResponse::WriteFile(_)));

    let contents = std::fs::read(&file_path).unwrap();
    assert_eq!(
        contents, b"first-second",
        "append = true must add to the existing file, not replace it"
    );
}

#[tokio::test]
async fn write_file_chunked_round_trip_with_non_multiple_boundary() {
    // Exercises the exact shape a chunked `husker cp` produces: the first
    // chunk truncates, later chunks append, and the final chunk is smaller
    // than the others (total size is not an exact multiple of chunk size).
    // This is the boundary case most likely to drop or duplicate bytes.
    let mut stream = spawn_agent().await;

    let dir = tempfile::tempdir().unwrap();
    let file_path = dir
        .path()
        .join("chunked.bin")
        .to_string_lossy()
        .into_owned();

    const CHUNK_SIZE: usize = 7;
    let original: Vec<u8> = (0..=255u32).cycle().take(100).map(|b| b as u8).collect();
    assert_ne!(
        original.len() % CHUNK_SIZE,
        0,
        "test data must not be an exact multiple of the chunk size"
    );

    for (i, chunk) in original.chunks(CHUNK_SIZE).enumerate() {
        let request = AgentRequest::WriteFile(WriteFileRequest {
            path: file_path.clone(),
            data: base64_encode(chunk),
            mode: None,
            append: i > 0,
        });
        write_message(&mut stream, &request).await.unwrap();
        let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
        match response {
            AgentResponse::WriteFile(w) => assert_eq!(w.bytes_written, chunk.len() as u64),
            other => panic!("expected WriteFile response, got {other:?}"),
        }
    }

    let contents = std::fs::read(&file_path).unwrap();
    assert_eq!(
        contents, original,
        "chunked append writes must reconstruct the original file byte-for-byte"
    );
}

/// The deliberate asymmetry around the agent's read ceiling: a caller that asks
/// for the whole of an oversized file is refused, because it has no way to ask
/// for the remainder and a truncated answer would look like the file. A caller
/// that asks for a byte range is served, clamped to the ceiling, and told the
/// real size so it can come back for the rest.
///
/// Both halves live in one test because they share the ceiling env var, which
/// is process-global; splitting them would race.
#[tokio::test]
async fn read_file_refuses_a_whole_oversized_file_but_serves_a_range_of_it() {
    // Safety: no other test reads this env var concurrently.
    unsafe {
        std::env::set_var("HUSKER_AGENT_MAX_READ_BYTES", "64");
    }
    let mut stream = spawn_agent().await;

    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("big.bin");
    let content: Vec<u8> = (0..128u16).map(|i| (i % 251) as u8).collect();
    std::fs::write(&file_path, &content).unwrap();
    let path = file_path.to_string_lossy().into_owned();

    let request = AgentRequest::ReadFile(ReadFileRequest {
        path: path.clone(),
        offset: 0,
        len: None,
    });
    write_message(&mut stream, &request).await.unwrap();
    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
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

    // The same file, read as ranges. Each answer is capped at the ceiling and
    // carries the whole file's size, which is what lets the host loop.
    let mut assembled = Vec::new();
    let mut reported_total = None;
    while assembled.len() < content.len() {
        let request = AgentRequest::ReadFile(ReadFileRequest {
            path: path.clone(),
            offset: assembled.len() as u64,
            // Deliberately more than the ceiling: an over-large range is
            // clamped, not refused, or a host would have to know the ceiling
            // to ask a valid question.
            len: Some(1024),
        });
        write_message(&mut stream, &request).await.unwrap();
        let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
        match response {
            AgentResponse::ReadFile(r) => {
                assert!(
                    r.size <= 64,
                    "a range must not exceed the ceiling: {}",
                    r.size
                );
                assert_eq!(
                    r.total_size,
                    Some(content.len() as u64),
                    "every response reports the whole file's size"
                );
                reported_total = r.total_size;
                assembled.extend_from_slice(&husker_agent_proto::base64_decode(&r.data).unwrap());
            }
            other => panic!("expected ReadFile response, got {other:?}"),
        }
    }
    unsafe {
        std::env::remove_var("HUSKER_AGENT_MAX_READ_BYTES");
    }

    assert_eq!(reported_total, Some(128));
    assert_eq!(
        assembled, content,
        "ranged reads must reassemble the file byte-for-byte, in order"
    );
}

/// A range starting at or past the end returns nothing, and still reports the
/// file's size. Answering from the start of the file instead would make a host
/// loop reassemble the beginning forever.
#[tokio::test]
async fn read_file_range_past_the_end_is_empty_not_the_start_of_the_file() {
    let mut stream = spawn_agent().await;

    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("short.bin");
    std::fs::write(&file_path, b"0123456789").unwrap();

    let request = AgentRequest::ReadFile(ReadFileRequest {
        path: file_path.to_string_lossy().into_owned(),
        offset: 10,
        len: Some(16),
    });
    write_message(&mut stream, &request).await.unwrap();

    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    match response {
        AgentResponse::ReadFile(r) => {
            assert_eq!(r.size, 0);
            assert_eq!(r.total_size, Some(10));
            assert!(
                husker_agent_proto::base64_decode(&r.data)
                    .unwrap()
                    .is_empty()
            );
        }
        other => panic!("expected ReadFile response, got {other:?}"),
    }
}

/// A range in the middle of a file returns exactly that slice.
#[tokio::test]
async fn read_file_range_returns_the_requested_slice() {
    let mut stream = spawn_agent().await;

    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("slice.bin");
    std::fs::write(&file_path, b"abcdefghij").unwrap();

    let request = AgentRequest::ReadFile(ReadFileRequest {
        path: file_path.to_string_lossy().into_owned(),
        offset: 3,
        len: Some(4),
    });
    write_message(&mut stream, &request).await.unwrap();

    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    match response {
        AgentResponse::ReadFile(r) => {
            assert_eq!(husker_agent_proto::base64_decode(&r.data).unwrap(), b"defg");
            assert_eq!(r.size, 4);
            assert_eq!(r.total_size, Some(10));
        }
        other => panic!("expected ReadFile response, got {other:?}"),
    }
}

#[tokio::test]
async fn read_nonexistent_file() {
    let mut stream = spawn_agent().await;

    let request = AgentRequest::ReadFile(ReadFileRequest {
        path: "/tmp/nonexistent_file_12345_husker_test".into(),
        offset: 0,
        len: None,
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
        append: false,
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
        offset: 0,
        len: None,
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
        append: false,
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
        append: false,
    });
    write_message(&mut stream, &request).await.unwrap();
    let response: AgentResponse = read_message(&mut stream).await.unwrap().unwrap();
    assert!(matches!(response, AgentResponse::WriteFile(_)));

    let request = AgentRequest::ReadFile(ReadFileRequest {
        path: file_path,
        offset: 0,
        len: None,
    });
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
