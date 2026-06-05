//! Agent integration tests exercising complex scenarios beyond the basic
//! client tests in `agent_client.rs`.
//!
//! Tests cover:
//! - Concurrent connections to the same agent
//! - Large file transfers through the client API
//! - Sequential operations with state verification
//! - Error recovery after failed operations
//! - File write with permissions

use std::path::PathBuf;

use husker_core::ShellEvent;
use husker_core::agent_client::{AgentClient, AgentConnection};

/// Spawn the agent handler on a temporary Unix socket.
async fn spawn_agent() -> (tempfile::TempDir, PathBuf) {
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

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    (dir, path)
}

fn pty_unavailable(err: &str) -> bool {
    err.contains("failed to open PTY")
        || err.contains("Device not configured")
        || err.contains("No such device")
}

async fn shell_start_or_skip(
    conn: &mut AgentConnection<tokio::net::UnixStream>,
    command: Option<&str>,
) -> bool {
    match conn.shell_start(command, 80, 24).await {
        Ok(()) => true,
        Err(err) => {
            let msg = err.to_string();
            if pty_unavailable(&msg) {
                eprintln!("skipping shell test: {msg}");
                false
            } else {
                panic!("shell_start failed unexpectedly: {msg}");
            }
        }
    }
}

// ── Concurrent Connections ───────────────────────────────────────────

#[tokio::test]
async fn concurrent_connections_are_independent() {
    let (_dir, path) = spawn_agent().await;

    // Open two independent connections
    let mut conn1 = AgentClient::connect_unix(&path).await.unwrap();
    let mut conn2 = AgentClient::connect_unix(&path).await.unwrap();

    // Both should be able to ping independently
    conn1.ping().await.unwrap();
    conn2.ping().await.unwrap();

    // Execute different commands on each connection
    let r1 = conn1.exec("echo", &["one"], None, &[]).await.unwrap();
    let r2 = conn2.exec("echo", &["two"], None, &[]).await.unwrap();

    assert_eq!(r1.stdout.trim(), "one");
    assert_eq!(r2.stdout.trim(), "two");
}

#[tokio::test]
async fn many_concurrent_pings() {
    let (_dir, path) = spawn_agent().await;

    let mut handles = Vec::new();
    for _ in 0..10 {
        let path = path.clone();
        handles.push(tokio::spawn(async move {
            let mut conn = AgentClient::connect_unix(&path).await.unwrap();
            conn.ping().await.unwrap();
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

// ── Large File Transfers ─────────────────────────────────────────────

#[tokio::test]
async fn write_and_read_large_file() {
    let (_dir, path) = spawn_agent().await;
    let file_dir = tempfile::tempdir().unwrap();
    let file_path = file_dir.path().join("large.bin");
    let file_path_str = file_path.to_string_lossy().to_string();

    // 256 KiB of patterned binary data
    let data: Vec<u8> = (0..262_144).map(|i| (i % 251) as u8).collect();

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    let bytes_written = conn.write_file(&file_path_str, &data, None).await.unwrap();
    assert_eq!(bytes_written, data.len() as u64);

    let read_back = conn.read_file(&file_path_str).await.unwrap();
    assert_eq!(read_back.len(), data.len());
    assert_eq!(read_back, data);
}

#[tokio::test]
async fn write_and_read_empty_file() {
    let (_dir, path) = spawn_agent().await;
    let file_dir = tempfile::tempdir().unwrap();
    let file_path = file_dir.path().join("empty.bin");
    let file_path_str = file_path.to_string_lossy().to_string();

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    let bytes_written = conn.write_file(&file_path_str, &[], None).await.unwrap();
    assert_eq!(bytes_written, 0);

    let read_back = conn.read_file(&file_path_str).await.unwrap();
    assert!(read_back.is_empty());
}

// ── Error Recovery ───────────────────────────────────────────────────

#[tokio::test]
async fn connection_recovers_after_failed_read() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    // Try to read a nonexistent file (should fail)
    let result = conn.read_file("/nonexistent/path/12345").await;
    assert!(result.is_err());

    // Connection should still be usable after the error
    conn.ping().await.unwrap();

    let result = conn
        .exec("echo", &["still-alive"], None, &[])
        .await
        .unwrap();
    assert_eq!(result.stdout.trim(), "still-alive");
}

#[tokio::test]
async fn connection_recovers_after_failed_exec() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    // Execute a nonexistent command (agent returns error response)
    let result = conn.exec("nonexistent_cmd_xyz_999", &[], None, &[]).await;
    assert!(result.is_err());

    // Connection should still work
    conn.ping().await.unwrap();

    let file_dir = tempfile::tempdir().unwrap();
    let file_path = file_dir.path().join("recovery.txt");
    let file_path_str = file_path.to_string_lossy().to_string();

    let bytes = conn
        .write_file(&file_path_str, b"recovered", None)
        .await
        .unwrap();
    assert_eq!(bytes, 9);
}

// ── Sequential Operations ────────────────────────────────────────────

#[tokio::test]
async fn sequential_file_operations() {
    let (_dir, path) = spawn_agent().await;
    let file_dir = tempfile::tempdir().unwrap();
    let file_path = file_dir.path().join("sequential.txt");
    let file_path_str = file_path.to_string_lossy().to_string();

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    // Write initial content
    conn.write_file(&file_path_str, b"version 1", None)
        .await
        .unwrap();

    // Read it back
    let data = conn.read_file(&file_path_str).await.unwrap();
    assert_eq!(data, b"version 1");

    // Overwrite with new content
    conn.write_file(&file_path_str, b"version 2", None)
        .await
        .unwrap();

    // Verify overwrite
    let data = conn.read_file(&file_path_str).await.unwrap();
    assert_eq!(data, b"version 2");
}

#[tokio::test]
async fn interleaved_exec_and_file_ops() {
    let (_dir, path) = spawn_agent().await;
    let file_dir = tempfile::tempdir().unwrap();

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    // Write a script via file API
    let script_path = file_dir.path().join("test.sh");
    let script_path_str = script_path.to_string_lossy().to_string();
    conn.write_file(
        &script_path_str,
        b"#!/bin/sh\necho hello from script",
        Some(0o755),
    )
    .await
    .unwrap();

    // Execute the script via exec API
    let result = conn
        .exec("sh", &[&script_path_str], None, &[])
        .await
        .unwrap();
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout.trim(), "hello from script");

    // Ping to confirm connection health
    conn.ping().await.unwrap();
}

// ── File Permissions ─────────────────────────────────────────────────

#[tokio::test]
async fn write_file_with_permissions() {
    let (_dir, path) = spawn_agent().await;
    let file_dir = tempfile::tempdir().unwrap();
    let file_path = file_dir.path().join("perms.sh");
    let file_path_str = file_path.to_string_lossy().to_string();

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    conn.write_file(&file_path_str, b"#!/bin/sh\necho perms", Some(0o755))
        .await
        .unwrap();

    // Verify the file is executable by running it
    let result = conn.exec(&file_path_str, &[], None, &[]).await.unwrap();
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout.trim(), "perms");
}

// ── Binary Data Roundtrip ────────────────────────────────────────────

#[tokio::test]
async fn binary_data_with_all_byte_values() {
    let (_dir, path) = spawn_agent().await;
    let file_dir = tempfile::tempdir().unwrap();
    let file_path = file_dir.path().join("allbytes.bin");
    let file_path_str = file_path.to_string_lossy().to_string();

    // Every possible byte value (0x00 through 0xFF)
    let data: Vec<u8> = (0..=255).collect();

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    conn.write_file(&file_path_str, &data, None).await.unwrap();
    let read_back = conn.read_file(&file_path_str).await.unwrap();

    assert_eq!(read_back, data);
}

// ── AgentConnection::new with Raw Stream ─────────────────────────────

#[tokio::test]
async fn raw_stream_connection_full_workflow() {
    let (_dir, path) = spawn_agent().await;

    let stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    let mut conn = AgentConnection::new(stream);

    // Full workflow: ping, exec, file write, file read
    conn.ping().await.unwrap();

    let result = conn.exec("echo", &["raw-test"], None, &[]).await.unwrap();
    assert_eq!(result.stdout.trim(), "raw-test");

    let file_dir = tempfile::tempdir().unwrap();
    let file_path = file_dir.path().join("raw.txt");
    let file_path_str = file_path.to_string_lossy().to_string();

    conn.write_file(&file_path_str, b"from raw stream", None)
        .await
        .unwrap();

    let data = conn.read_file(&file_path_str).await.unwrap();
    assert_eq!(data, b"from raw stream");
}

// ── Exec with Complex Environment ────────────────────────────────────

#[tokio::test]
async fn exec_with_multiple_env_vars() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    let result = conn
        .exec(
            "sh",
            &["-c", "echo $VAR_A:$VAR_B:$VAR_C"],
            None,
            &[("VAR_A", "alpha"), ("VAR_B", "beta"), ("VAR_C", "gamma")],
        )
        .await
        .unwrap();

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout.trim(), "alpha:beta:gamma");
}

#[tokio::test]
async fn exec_with_special_characters_in_args() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    let result = conn
        .exec(
            "echo",
            &["hello world", "foo\tbar", "baz\nnewline"],
            None,
            &[],
        )
        .await
        .unwrap();

    assert_eq!(result.exit_code, 0);
    // echo separates args with spaces
    assert!(result.stdout.contains("hello world"));
}

// ── Exec Stderr ──────────────────────────────────────────────────────

#[tokio::test]
async fn exec_captures_stderr() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    let result = conn
        .exec("sh", &["-c", "echo error-output >&2"], None, &[])
        .await
        .unwrap();

    assert_eq!(result.exit_code, 0);
    assert!(result.stdout.is_empty());
    assert_eq!(result.stderr.trim(), "error-output");
}

#[tokio::test]
async fn exec_mixed_stdout_stderr() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    let result = conn
        .exec(
            "sh",
            &["-c", "echo stdout-msg && echo stderr-msg >&2"],
            None,
            &[],
        )
        .await
        .unwrap();

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout.trim(), "stdout-msg");
    assert_eq!(result.stderr.trim(), "stderr-msg");
}

// ── Shell Client Integration ────────────────────────────────────────

#[tokio::test]
async fn shell_start_and_echo_via_cat() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    if !shell_start_or_skip(&mut conn, Some("cat")).await {
        return;
    }

    conn.shell_send(b"hello\n").await.unwrap();

    // Collect output — PTY echoes input with \r\n endings
    let mut output = Vec::new();
    while let Ok(Ok(ShellEvent::Data(data))) =
        tokio::time::timeout(std::time::Duration::from_secs(2), conn.shell_recv()).await
    {
        output.extend(data);
        if output.windows(5).any(|w| w == b"hello") {
            break;
        }
    }

    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("hello"),
        "expected output to contain 'hello', got: {text:?}"
    );
}

#[tokio::test]
async fn shell_with_echo_command() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    // `echo` with no args outputs a newline and exits
    if !shell_start_or_skip(&mut conn, Some("echo")).await {
        return;
    }

    // Collect all output until exit
    let mut output = Vec::new();
    let exit_code = loop {
        match conn.shell_recv().await.unwrap() {
            ShellEvent::Data(data) => output.extend(data),
            ShellEvent::Exit(code) => break code,
        }
    };

    assert_eq!(exit_code, 0);
    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains('\n'),
        "expected shell echo output to contain a newline, got: {text:?}"
    );
}

#[tokio::test]
async fn shell_exit_code() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    if !shell_start_or_skip(&mut conn, Some("sh")).await {
        return;
    }

    // Send exit 42 to the shell
    conn.shell_send(b"exit 42\n").await.unwrap();

    let exit_code = loop {
        match conn.shell_recv().await.unwrap() {
            ShellEvent::Data(_) => {}
            ShellEvent::Exit(code) => break code,
        }
    };

    assert_eq!(exit_code, 42);
}

#[tokio::test]
async fn shell_resize_does_not_disrupt_session() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    if !shell_start_or_skip(&mut conn, Some("cat")).await {
        return;
    }

    // Resize should succeed without error
    conn.shell_resize(120, 40).await.unwrap();

    // Session should still be functional after resize
    conn.shell_send(b"after-resize\n").await.unwrap();

    // Collect output — PTY echoes input with \r\n endings
    let mut output = Vec::new();
    while let Ok(Ok(ShellEvent::Data(data))) =
        tokio::time::timeout(std::time::Duration::from_secs(2), conn.shell_recv()).await
    {
        output.extend(data);
        if output.windows(12).any(|w| w == b"after-resize") {
            break;
        }
    }

    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("after-resize"),
        "expected output to contain 'after-resize', got: {text:?}"
    );
}

#[tokio::test]
async fn shell_nonexistent_command_returns_error() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    match conn
        .shell_start(Some("nonexistent_cmd_xyz_999"), 80, 24)
        .await
    {
        Err(err) => {
            let msg = err.to_string();
            if pty_unavailable(&msg) {
                eprintln!("skipping shell test: {msg}");
                return;
            }
            assert!(
                msg.contains("failed to start shell") || msg.contains("not found"),
                "unexpected shell_start error: {msg}"
            );
        }
        Ok(()) => {
            // Some shells may start and then exit non-zero when command resolution fails.
            let exit_code = loop {
                match tokio::time::timeout(std::time::Duration::from_secs(2), conn.shell_recv())
                    .await
                    .expect("timed out waiting for shell exit")
                    .expect("shell recv failed")
                {
                    ShellEvent::Data(_) => {}
                    ShellEvent::Exit(code) => break code,
                }
            };
            assert_ne!(
                exit_code, 0,
                "nonexistent command should not exit successfully"
            );
        }
    }
}

#[tokio::test]
async fn shell_bidirectional_data_exchange() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    if !shell_start_or_skip(&mut conn, Some("sh")).await {
        return;
    }

    // Send a command that produces known output
    conn.shell_send(b"echo MARKER_START && echo MARKER_END\nexit 0\n")
        .await
        .unwrap();

    let mut output = Vec::new();
    let exit_code = loop {
        match conn.shell_recv().await.unwrap() {
            ShellEvent::Data(data) => output.extend(data),
            ShellEvent::Exit(code) => break code,
        }
    };

    assert_eq!(exit_code, 0);
    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("MARKER_START"),
        "expected MARKER_START in output, got: {text}"
    );
    assert!(
        text.contains("MARKER_END"),
        "expected MARKER_END in output, got: {text}"
    );
}

/// Verify that `shell_start` sends TERM=xterm to the guest agent.
///
/// The client hardcodes TERM=xterm in the ShellStartRequest env. This test
/// verifies the value reaches the shell process inside the agent.
#[tokio::test]
async fn shell_start_sends_term_env() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    if !shell_start_or_skip(&mut conn, Some("sh")).await {
        return;
    }
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;

    conn.shell_send(b"printf 'TERM=%s\\n' \"$TERM\"\nexit 0\n")
        .await
        .unwrap();

    let mut output = Vec::new();
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(3), conn.shell_recv())
            .await
            .expect("timed out waiting for shell output")
            .unwrap()
        {
            ShellEvent::Data(data) => output.extend(data),
            ShellEvent::Exit(code) => {
                assert_eq!(code, 0);
                break;
            }
        }
    }

    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("TERM=xterm"),
        "expected TERM=xterm in output, got: {text:?}"
    );
}

/// Verify that a shell session continues to deliver data after a delay.
///
/// Regression test: if the underlying transport connection is dropped prematurely
/// (e.g. VZ deallocating the vsock connection object), data stops flowing after
/// the initial handshake. This test sends data after a pause to verify the
/// connection remains alive.
#[tokio::test]
async fn shell_session_survives_idle_period() {
    let (_dir, path) = spawn_agent().await;

    let mut conn = AgentClient::connect_unix(&path).await.unwrap();

    if !shell_start_or_skip(&mut conn, Some("cat")).await {
        return;
    }

    // Wait long enough for any premature connection teardown to take effect
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Send data after the delay — this would hang if the connection was torn down
    conn.shell_send(b"still-alive\n").await.unwrap();

    let mut output = Vec::new();
    while let Ok(Ok(ShellEvent::Data(data))) =
        tokio::time::timeout(std::time::Duration::from_secs(2), conn.shell_recv()).await
    {
        output.extend(data);
        if output.windows(11).any(|w| w == b"still-alive") {
            break;
        }
    }

    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("still-alive"),
        "expected 'still-alive' after idle period, got: {text:?}"
    );
}

/// Verify that concurrent shell and exec sessions work independently.
///
/// The agent handles each connection in a separate task. A long-running shell
/// session should not block exec commands on separate connections.
#[tokio::test]
async fn concurrent_shell_and_exec() {
    let (_dir, path) = spawn_agent().await;

    // Start a long-running shell on one connection
    let mut shell_conn = AgentClient::connect_unix(&path).await.unwrap();
    if !shell_start_or_skip(&mut shell_conn, Some("cat")).await {
        return;
    }

    // Run exec on a separate connection while shell is active
    let mut exec_conn = AgentClient::connect_unix(&path).await.unwrap();
    let result = exec_conn
        .exec("echo", &["concurrent_ok"], None, &[])
        .await
        .unwrap();
    assert_eq!(result.exit_code, 0);
    assert!(result.stdout.contains("concurrent_ok"));

    // Shell should still be functional
    shell_conn.shell_send(b"after-exec\n").await.unwrap();

    let mut output = Vec::new();
    while let Ok(Ok(ShellEvent::Data(data))) =
        tokio::time::timeout(std::time::Duration::from_secs(2), shell_conn.shell_recv()).await
    {
        output.extend(data);
        if output.windows(10).any(|w| w == b"after-exec") {
            break;
        }
    }

    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("after-exec"),
        "shell should still work after concurrent exec, got: {text:?}"
    );
}
