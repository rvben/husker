//! End-to-end integration tests for the husker daemon.
//!
//! These tests require a running daemon and a booted VM. They are gated
//! behind `#[ignore]` and serve as documentation of the expected E2E flow.
//!
//! Platform notes:
//! - Tests marked `#[cfg(target_os = "linux")]` require KVM + Firecracker.
//! - Tests marked `#[cfg(target_os = "macos")]` require Apple VZ entitlements.
//! - Unmarked tests work on any platform with a running daemon.
//!
//! Run with: `cargo test -p husker --test e2e -- --ignored`

// ── Helpers ──────────────────────────────────────────────────────────────

/// Spawn `husker shell <vm_name>` wrapped in a platform-appropriate PTY via `script`.
///
/// macOS: `script -q /dev/null husker shell <vm>`
/// Linux: `script -qec "husker shell <vm>" /dev/null`
fn spawn_shell_with_pty(vm_name: &str) -> tokio::process::Child {
    use tokio::process::Command;

    #[cfg(target_os = "macos")]
    let child = Command::new("script")
        .args(["-q", "/dev/null", "husker", "shell", vm_name])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn husker shell via script");

    #[cfg(target_os = "linux")]
    let child = Command::new("script")
        .args(["-qec", &format!("husker shell {vm_name}"), "/dev/null"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn husker shell via script");

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    compile_error!("E2E shell tests only support macOS and Linux");

    child
}

/// Read from an async reader until a target string appears or timeout.
async fn read_until_match(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
    target: &str,
    timeout_secs: u64,
) -> String {
    use tokio::io::AsyncReadExt;

    let mut collected = Vec::new();
    let mut buf = vec![0u8; 4096];

    let result = tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), async {
        loop {
            let n = reader.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            collected.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&collected);
            if text.contains(target) {
                break;
            }
        }
    })
    .await;

    if result.is_err() {
        eprintln!("read_until_match timed out waiting for '{target}'");
    }

    String::from_utf8_lossy(&collected).to_string()
}

// ── Firecracker-specific E2E tests (Linux only) ─────────────────────────

/// Full VM lifecycle: create, info, exec, copy file, stop, destroy.
///
/// Requires:
/// - Running `husker daemon` on localhost:7777
/// - Valid kernel at /var/lib/husker/kernels/vmlinux
/// - Valid rootfs image
/// - Linux host with KVM enabled
/// - Firecracker binary in PATH or configured
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore]
async fn vm_lifecycle() {
    let client = reqwest::Client::new();
    let base = "http://127.0.0.1:7777";

    // 1. Health check
    let resp = client
        .get(format!("{base}/v1/health"))
        .send()
        .await
        .expect("daemon should be reachable");
    assert_eq!(resp.status(), 200);

    // 2. Create a VM
    let create_body = serde_json::json!({
        "name": "e2e-test",
        "kernel_path": "/var/lib/husker/kernels/vmlinux",
        "rootfs_path": "/var/lib/husker/images/ubuntu-22.04.ext4",
        "vcpu_count": 1,
        "mem_size_mib": 128,
    });
    let resp = client
        .post(format!("{base}/v1/vms"))
        .json(&create_body)
        .send()
        .await
        .expect("create should succeed");
    assert_eq!(resp.status(), 201);
    let vm: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(vm["name"], "e2e-test");
    assert!(vm["id"].as_str().is_some());

    // 3. List VMs (should contain our VM)
    let resp = client.get(format!("{base}/v1/vms")).send().await.unwrap();
    let vms: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(vms.iter().any(|v| v["name"] == "e2e-test"));

    // 4. Get VM info
    let resp = client
        .get(format!("{base}/v1/vms/e2e-test"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let info: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(info["name"], "e2e-test");

    // 5. Wait for agent to be ready (the guest needs time to boot)
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // 6. Execute a command inside the VM
    let exec_body = serde_json::json!({
        "command": "echo",
        "args": ["hello from VM"],
    });
    let resp = client
        .post(format!("{base}/v1/vms/e2e-test/exec"))
        .json(&exec_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(result["exit_code"], 0);
    assert!(result["stdout"].as_str().unwrap().contains("hello from VM"));

    // 7. Write a file to the VM
    let write_body = serde_json::json!({
        "path": "/tmp/e2e-test.txt",
        "data": husker_agent_proto::base64_encode(b"e2e test data"),
    });
    let resp = client
        .post(format!("{base}/v1/vms/e2e-test/files/write"))
        .json(&write_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 8. Read the file back
    let read_body = serde_json::json!({
        "path": "/tmp/e2e-test.txt",
    });
    let resp = client
        .post(format!("{base}/v1/vms/e2e-test/files/read"))
        .json(&read_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let file_data: serde_json::Value = resp.json().await.unwrap();
    let decoded = husker_agent_proto::base64_decode(file_data["data"].as_str().unwrap()).unwrap();
    assert_eq!(decoded, b"e2e test data");

    // 9. Stop the VM
    let resp = client
        .post(format!("{base}/v1/vms/e2e-test/stop"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // 10. Destroy the VM
    let resp = client
        .delete(format!("{base}/v1/vms/e2e-test"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // 11. Verify it's gone
    let resp = client
        .get(format!("{base}/v1/vms/e2e-test"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// Verify that creating a VM with a duplicate name returns 409 Conflict.
///
/// Requires a running daemon with the ability to create VMs.
/// Uses Firecracker paths — Linux only.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore]
async fn duplicate_vm_name_returns_conflict() {
    let client = reqwest::Client::new();
    let base = "http://127.0.0.1:7777";

    let body = serde_json::json!({
        "name": "e2e-dup-test",
        "kernel_path": "/var/lib/husker/kernels/vmlinux",
        "rootfs_path": "/var/lib/husker/images/ubuntu-22.04.ext4",
    });

    // Create first VM
    let resp = client
        .post(format!("{base}/v1/vms"))
        .json(&body)
        .send()
        .await
        .expect("first create should reach daemon");
    assert_eq!(resp.status(), 201);

    // Attempt duplicate
    let resp = client
        .post(format!("{base}/v1/vms"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    // Cleanup
    let _ = client
        .delete(format!("{base}/v1/vms/e2e-dup-test"))
        .send()
        .await;
}

// ── Cross-platform API tests ─────────────────────────────────────────────
//
// These test the REST API and work with any backend (Firecracker or Apple VZ).
// They require a running daemon with a booted VM named "e2e-exec-test".

/// Verify exec with a non-zero exit code propagates correctly.
#[tokio::test]
#[ignore]
async fn exec_nonzero_exit_code() {
    let client = reqwest::Client::new();
    let base = "http://127.0.0.1:7777";

    let body = serde_json::json!({
        "command": "sh",
        "args": ["-c", "exit 42"],
    });
    let resp = client
        .post(format!("{base}/v1/vms/e2e-exec-test/exec"))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(result["exit_code"], 42);
}

/// Verify that exec with environment variables works through the full stack.
#[tokio::test]
#[ignore]
async fn exec_with_env_through_api() {
    let client = reqwest::Client::new();
    let base = "http://127.0.0.1:7777";

    let body = serde_json::json!({
        "command": "sh",
        "args": ["-c", "echo $MY_VAR"],
        "env": {"MY_VAR": "from-api"},
    });
    let resp = client
        .post(format!("{base}/v1/vms/e2e-exec-test/exec"))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(result["stdout"].as_str().unwrap().trim(), "from-api");
}

/// Verify large file transfer through the API (1 MiB).
#[tokio::test]
#[ignore]
async fn large_file_transfer_through_api() {
    let client = reqwest::Client::new();
    let base = "http://127.0.0.1:7777";

    // 1 MiB of pattern data
    let data: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
    let encoded = husker_agent_proto::base64_encode(&data);

    let write_body = serde_json::json!({
        "path": "/tmp/large-e2e.bin",
        "data": encoded,
    });
    let resp = client
        .post(format!("{base}/v1/vms/e2e-exec-test/files/write"))
        .json(&write_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(result["bytes_written"], 1_048_576);

    let read_body = serde_json::json!({
        "path": "/tmp/large-e2e.bin",
    });
    let resp = client
        .post(format!("{base}/v1/vms/e2e-exec-test/files/read"))
        .json(&read_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let file_data: serde_json::Value = resp.json().await.unwrap();
    let decoded = husker_agent_proto::base64_decode(file_data["data"].as_str().unwrap()).unwrap();
    assert_eq!(decoded.len(), data.len());
    assert_eq!(decoded, data);
}

// ── Cross-platform shell E2E tests ───────────────────────────────────────
//
// These use `script` for PTY wrapping, with platform-specific invocation.
// They require a running daemon with a booted VM named "e2e-shell-test".

/// Verify interactive shell: prompt appears, echo works, TERM is set, devpts is mounted.
#[tokio::test]
#[ignore]
async fn shell_interactive_session() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut child = spawn_shell_with_pty("e2e-shell-test");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    // Wait for the shell prompt to appear
    let mut buf = vec![0u8; 4096];
    let prompt = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut collected = Vec::new();
        loop {
            let n = stdout.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            collected.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&collected);
            if text.contains('#') || text.contains('$') {
                return text.to_string();
            }
        }
        String::from_utf8_lossy(&collected).to_string()
    })
    .await
    .expect("timed out waiting for shell prompt");

    assert!(
        prompt.contains('#') || prompt.contains('$'),
        "expected shell prompt, got: {prompt}"
    );

    // Test 1: echo works
    stdin.write_all(b"echo SHELL_E2E_OK\n").await.unwrap();
    let output = read_until_match(&mut stdout, "SHELL_E2E_OK", 5).await;
    assert!(
        output.contains("SHELL_E2E_OK"),
        "echo test failed: {output}"
    );

    // Test 2: TERM is set to xterm
    stdin.write_all(b"echo TERM=$TERM\n").await.unwrap();
    let output = read_until_match(&mut stdout, "TERM=xterm", 5).await;
    assert!(output.contains("TERM=xterm"), "TERM test failed: {output}");

    // Test 3: devpts is mounted
    stdin.write_all(b"ls /dev/pts/\n").await.unwrap();
    let output = read_until_match(&mut stdout, "ptmx", 5).await;
    assert!(output.contains("ptmx"), "devpts test failed: {output}");

    // Clean exit
    stdin.write_all(b"exit\n").await.unwrap();
    let status = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait())
        .await
        .expect("timed out waiting for shell exit")
        .expect("failed to wait on child");

    assert!(status.success(), "shell exited with: {status}");
}

/// Verify that the shell propagates the guest's exit code.
#[tokio::test]
#[ignore]
async fn shell_exit_code_propagation() {
    use tokio::io::AsyncWriteExt;

    let mut child = spawn_shell_with_pty("e2e-shell-test");
    let mut stdin = child.stdin.take().unwrap();

    // Wait for the shell to initialize, then send exit 42
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    stdin.write_all(b"exit 42\n").await.unwrap();
    drop(stdin);

    let status = tokio::time::timeout(std::time::Duration::from_secs(15), child.wait())
        .await
        .expect("timed out waiting for exit")
        .expect("failed to wait");

    assert!(!status.success(), "expected non-zero exit, got: {status}");
}

/// Verify that shell to a non-existent VM returns an error quickly.
///
/// Does not require a PTY — just tests CLI error handling.
#[tokio::test]
#[ignore]
async fn shell_nonexistent_vm_fails() {
    use tokio::process::Command;

    let output = Command::new("husker")
        .args(["shell", "no-such-vm-e2e-test"])
        .output()
        .await
        .expect("failed to spawn husker shell");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("404") || stderr.contains("error"),
        "expected error message, got: {stderr}"
    );
}

// ── macOS-specific: pause/resume E2E ─────────────────────────────────────

/// Verify pause → resume → exec cycle works end-to-end on Apple VZ.
///
/// Apple VZ supports true pause/resume (Firecracker uses ACPI which
/// is less deterministic), so this test validates the VZ-specific path.
#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore]
async fn pause_resume_cycle_macos() {
    let client = reqwest::Client::new();
    let base = "http://127.0.0.1:7777";

    // Pause
    let resp = client
        .post(format!("{base}/v1/vms/e2e-shell-test/pause"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Verify state
    let resp = client
        .get(format!("{base}/v1/vms/e2e-shell-test"))
        .send()
        .await
        .unwrap();
    let info: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(info["state"], "paused");

    // Resume
    let resp = client
        .post(format!("{base}/v1/vms/e2e-shell-test/resume"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Verify VM is functional after resume
    let exec_body = serde_json::json!({
        "command": "echo",
        "args": ["survived-pause"],
    });
    let resp = client
        .post(format!("{base}/v1/vms/e2e-shell-test/exec"))
        .json(&exec_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(result["exit_code"], 0);
    assert!(
        result["stdout"]
            .as_str()
            .unwrap()
            .contains("survived-pause")
    );
}

/// Verify that shell works after a pause/resume cycle on Apple VZ.
#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore]
async fn shell_after_pause_resume_macos() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let client = reqwest::Client::new();
    let base = "http://127.0.0.1:7777";

    // Pause and resume the VM
    let resp = client
        .post(format!("{base}/v1/vms/e2e-shell-test/pause"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let resp = client
        .post(format!("{base}/v1/vms/e2e-shell-test/resume"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Shell should still work
    let mut child = spawn_shell_with_pty("e2e-shell-test");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    // Wait for prompt
    let mut buf = vec![0u8; 4096];
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut collected = Vec::new();
        loop {
            let n = stdout.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            collected.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&collected);
            if text.contains('#') || text.contains('$') {
                break;
            }
        }
    })
    .await
    .expect("timed out waiting for shell prompt after pause/resume");

    stdin.write_all(b"echo POST_RESUME_OK\n").await.unwrap();
    let output = read_until_match(&mut stdout, "POST_RESUME_OK", 5).await;
    assert!(
        output.contains("POST_RESUME_OK"),
        "shell after pause/resume failed: {output}"
    );

    stdin.write_all(b"exit\n").await.unwrap();
    let status = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait())
        .await
        .expect("timed out waiting for shell exit")
        .expect("failed to wait");

    assert!(status.success(), "shell exited with: {status}");
}

// ── Logs E2E tests ─────────────────────────────────────────────────────

/// Full VM lifecycle on macOS with Apple VZ: create, list, info, exec,
/// pause, resume, stop, destroy.
///
/// Requires:
/// - Running `husker daemon` on localhost:7777
/// - Valid kernel at ~/.local/share/husker/kernels/Image-virt
/// - Valid aarch64 rootfs image
/// - macOS host with Virtualization.framework
#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore]
async fn vm_lifecycle_macos() {
    let client = reqwest::Client::new();
    let base = "http://127.0.0.1:7777";

    let home = std::env::var("HOME").expect("HOME not set");
    let data_dir = format!("{home}/.local/share/husker");

    // 1. Health check
    let resp = client
        .get(format!("{base}/v1/health"))
        .send()
        .await
        .expect("daemon should be reachable");
    assert_eq!(resp.status(), 200);

    // 2. Create a VM
    let vm_name = "e2e-lifecycle-macos";
    let create_body = serde_json::json!({
        "name": vm_name,
        "kernel_path": format!("{data_dir}/kernels/Image-virt"),
        "rootfs_path": format!("{data_dir}/images/alpine-aarch64.ext4"),
        "vcpu_count": 1,
        "mem_size_mib": 128,
    });
    let resp = client
        .post(format!("{base}/v1/vms"))
        .json(&create_body)
        .send()
        .await
        .expect("create should succeed");
    assert_eq!(resp.status(), 201);
    let vm: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(vm["name"], vm_name);
    assert!(vm["id"].as_str().is_some());

    // 3. List VMs (should contain our VM)
    let resp = client.get(format!("{base}/v1/vms")).send().await.unwrap();
    let vms: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(vms.iter().any(|v| v["name"] == vm_name));

    // 4. Get VM info
    let resp = client
        .get(format!("{base}/v1/vms/{vm_name}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let info: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(info["name"], vm_name);

    // 5. Wait for agent to be ready
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // 6. Execute a command inside the VM
    let exec_body = serde_json::json!({
        "command": "echo",
        "args": ["hello from VZ"],
    });
    let resp = client
        .post(format!("{base}/v1/vms/{vm_name}/exec"))
        .json(&exec_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(result["exit_code"], 0);
    assert!(result["stdout"].as_str().unwrap().contains("hello from VZ"));

    // 7. Pause the VM
    let resp = client
        .post(format!("{base}/v1/vms/{vm_name}/pause"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let resp = client
        .get(format!("{base}/v1/vms/{vm_name}"))
        .send()
        .await
        .unwrap();
    let info: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(info["state"], "paused");

    // 8. Resume the VM
    let resp = client
        .post(format!("{base}/v1/vms/{vm_name}/resume"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // 9. Verify VM is functional after resume
    let exec_body = serde_json::json!({
        "command": "echo",
        "args": ["post-resume"],
    });
    let resp = client
        .post(format!("{base}/v1/vms/{vm_name}/exec"))
        .json(&exec_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(result["exit_code"], 0);

    // 10. Stop the VM
    let resp = client
        .post(format!("{base}/v1/vms/{vm_name}/stop"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // 11. Destroy the VM
    let resp = client
        .delete(format!("{base}/v1/vms/{vm_name}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // 12. Verify it's gone
    let resp = client
        .get(format!("{base}/v1/vms/{vm_name}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// Verify serial log output: full logs contain kernel markers, tail limits
/// line count, and logs return 404 after VM is destroyed.
///
/// Requires a running daemon. Uses a dedicated VM to avoid interfering
/// with other tests.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore]
async fn logs_serial_output() {
    let client = reqwest::Client::new();
    let base = "http://127.0.0.1:7777";
    let vm_name = "e2e-logs-test";

    // 1. Create a VM
    let create_body = serde_json::json!({
        "name": vm_name,
        "kernel_path": "/var/lib/husker/kernels/vmlinux",
        "rootfs_path": "/var/lib/husker/images/ubuntu-22.04.ext4",
        "vcpu_count": 1,
        "mem_size_mib": 128,
    });
    let resp = client
        .post(format!("{base}/v1/vms"))
        .json(&create_body)
        .send()
        .await
        .expect("create should succeed");
    assert_eq!(resp.status(), 201);

    // 2. Wait for the VM to boot and produce serial output
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // 3. Full logs should contain kernel boot markers
    let resp = client
        .get(format!("{base}/v1/vms/{vm_name}/logs"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("Linux version") || body.contains("Booting"),
        "expected kernel boot marker in logs, got: {}",
        &body[..body.len().min(200)]
    );

    // 4. Tail should limit output
    let resp = client
        .get(format!("{base}/v1/vms/{vm_name}/logs?tail=5"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    let line_count = body.lines().count();
    assert!(
        line_count <= 5,
        "tail=5 should return at most 5 lines, got {line_count}"
    );

    // 5. Destroy the VM
    let resp = client
        .delete(format!("{base}/v1/vms/{vm_name}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // 6. Logs should return 404 after destroy
    let resp = client
        .get(format!("{base}/v1/vms/{vm_name}/logs"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// macOS equivalent of `logs_serial_output`, using Apple VZ paths.
///
/// Requires:
/// - Running `husker daemon` on localhost:7777
/// - Valid kernel at ~/.local/share/husker/kernels/Image-virt
/// - Valid aarch64 rootfs image
#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore]
async fn logs_serial_output_macos() {
    let client = reqwest::Client::new();
    let base = "http://127.0.0.1:7777";
    let vm_name = "e2e-logs-macos";

    let home = std::env::var("HOME").expect("HOME not set");
    let data_dir = format!("{home}/.local/share/husker");

    // 1. Create a VM
    let create_body = serde_json::json!({
        "name": vm_name,
        "kernel_path": format!("{data_dir}/kernels/Image-virt"),
        "rootfs_path": format!("{data_dir}/images/alpine-aarch64.ext4"),
        "vcpu_count": 1,
        "mem_size_mib": 128,
    });
    let resp = client
        .post(format!("{base}/v1/vms"))
        .json(&create_body)
        .send()
        .await
        .expect("create should succeed");
    assert_eq!(resp.status(), 201);

    // 2. Wait for the VM to boot and produce serial output
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // 3. Full logs should contain kernel boot markers
    let resp = client
        .get(format!("{base}/v1/vms/{vm_name}/logs"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("Linux version") || body.contains("Booting"),
        "expected kernel boot marker in logs, got: {}",
        &body[..body.len().min(200)]
    );

    // 4. Tail should limit output
    let resp = client
        .get(format!("{base}/v1/vms/{vm_name}/logs?tail=5"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    let line_count = body.lines().count();
    assert!(
        line_count <= 5,
        "tail=5 should return at most 5 lines, got {line_count}"
    );

    // 5. Destroy the VM
    let resp = client
        .delete(format!("{base}/v1/vms/{vm_name}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // 6. Logs should return 404 after destroy
    let resp = client
        .get(format!("{base}/v1/vms/{vm_name}/logs"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}
