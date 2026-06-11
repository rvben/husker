//! End-to-end integration tests for the husker daemon.
//!
//! These tests require a running daemon and a booted VM. They are gated
//! behind `#[ignore]` and serve as documentation of the expected E2E flow.
//!
//! # Preconditions
//!
//! ## Linux tests (Firecracker)
//!
//! Required:
//! - `HUSKER_RUN_IGNORED_E2E=1`
//! - Running `husker daemon` on 127.0.0.1:7777
//! - `/dev/kvm` accessible to the test user
//! - Firecracker binary in PATH
//!
//! Asset env vars (each has a default pointing at the standard pulled images):
//! - `HUSKER_E2E_KERNEL`   kernel image   (default: /var/lib/husker/kernels/vmlinux)
//! - `HUSKER_E2E_ROOTFS`   rootfs ext4    (default: /var/lib/husker/images/alpine-x86_64.ext4)
//! - `HUSKER_E2E_INITRD`   initramfs      (default: /var/lib/husker/kernels/initramfs-x86_64-virt.gz)
//!
//! Defaults point at the images that `husker images pull` installs on any
//! standard husker-dev host. Override to test a different rootfs.
//!
//! ## macOS tests (Apple VZ)
//!
//! Required:
//! - Running `husker daemon` on 127.0.0.1:7777
//! - Valid aarch64 kernel + rootfs in `~/.local/share/husker/`
//!
//! Platform notes:
//! - Tests marked `#[cfg(target_os = "linux")]` require KVM + Firecracker.
//! - Tests marked `#[cfg(target_os = "macos")]` require Apple VZ entitlements.
//! - Unmarked tests work on any platform with a running daemon.
//!
//! Run with: `HUSKER_RUN_IGNORED_E2E=1 cargo test -p husker --test e2e -- --ignored`

// ── Helpers ──────────────────────────────────────────────────────────────

/// Guard that this test is explicitly enabled.
///
/// Call at the start of every Linux e2e test. Returns early (test is a no-op)
/// when the env var is unset - `#[ignore]` already skips the test under normal
/// `cargo test`, so this is only reached via `--run-ignored` or `-- --ignored`.
/// When the var IS set the test must pass.
#[cfg(target_os = "linux")]
macro_rules! require_linux_e2e {
    () => {
        if std::env::var("HUSKER_RUN_IGNORED_E2E").as_deref() != Ok("1") {
            eprintln!("skipping: set HUSKER_RUN_IGNORED_E2E=1 to run this test");
            return;
        }
    };
}

/// Resolve the kernel path for Linux e2e tests.
///
/// Reads `HUSKER_E2E_KERNEL` or falls back to the standard location that
/// `husker images pull` installs. Panics with an actionable message when the
/// resolved path does not exist.
#[cfg(target_os = "linux")]
fn e2e_kernel() -> String {
    const DEFAULT: &str = "/var/lib/husker/kernels/vmlinux";
    let path = std::env::var("HUSKER_E2E_KERNEL").unwrap_or_else(|_| DEFAULT.into());
    if !std::path::Path::new(&path).exists() {
        panic!(
            "e2e kernel not found at {path:?}. \
             Run `husker images pull` or set HUSKER_E2E_KERNEL to a valid path."
        );
    }
    path
}

/// Resolve the rootfs path for Linux e2e tests.
///
/// Reads `HUSKER_E2E_ROOTFS` or falls back to the standard Alpine image that
/// `husker images pull` installs. Panics with an actionable message when the
/// resolved path does not exist.
#[cfg(target_os = "linux")]
fn e2e_rootfs() -> String {
    const DEFAULT: &str = "/var/lib/husker/images/alpine-x86_64.ext4";
    let path = std::env::var("HUSKER_E2E_ROOTFS").unwrap_or_else(|_| DEFAULT.into());
    if !std::path::Path::new(&path).exists() {
        panic!(
            "e2e rootfs not found at {path:?}. \
             Run `husker images pull` or set HUSKER_E2E_ROOTFS to a valid path."
        );
    }
    path
}

/// Resolve the optional initramfs path for Linux e2e tests.
///
/// Reads `HUSKER_E2E_INITRD` or falls back to the standard initramfs that
/// `husker images pull` installs. Returns `None` only if `HUSKER_E2E_INITRD`
/// is explicitly set to an empty string; otherwise panics when the resolved
/// file is missing.
#[cfg(target_os = "linux")]
fn e2e_initrd() -> Option<String> {
    const DEFAULT: &str = "/var/lib/husker/kernels/initramfs-x86_64-virt.gz";
    let path = match std::env::var("HUSKER_E2E_INITRD") {
        Ok(v) if v.is_empty() => return None,
        Ok(v) => v,
        Err(_) => DEFAULT.into(),
    };
    if !std::path::Path::new(&path).exists() {
        panic!(
            "e2e initrd not found at {path:?}. \
             Run `husker images pull` or set HUSKER_E2E_INITRD to a valid path \
             (or empty string to skip the initrd)."
        );
    }
    Some(path)
}

/// Create a VM via the REST API and wait for it to boot (agent reachable).
///
/// Returns the VM name that was created. The caller is responsible for
/// destroying the VM when done.
#[cfg(target_os = "linux")]
async fn create_and_wait_for_vm(
    client: &reqwest::Client,
    base: &str,
    vm_name: &str,
) -> serde_json::Value {
    let create_body = serde_json::json!({
        "name": vm_name,
        "kernel_path": e2e_kernel(),
        "rootfs_path": e2e_rootfs(),
        "initrd_path": e2e_initrd(),
        "vcpu_count": 1,
        "mem_size_mib": 256,
    });
    let resp = client
        .post(format!("{base}/v1/vms"))
        .json(&create_body)
        .send()
        .await
        .expect("create should reach daemon");
    assert_eq!(resp.status(), 201, "VM creation failed");
    let vm: serde_json::Value = resp.json().await.unwrap();

    // Wait for the agent to be reachable (poll exec with backoff).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let ping = serde_json::json!({"command": "echo", "args": ["ping"]});
        if let Ok(r) = client
            .post(format!("{base}/v1/vms/{vm_name}/exec"))
            .json(&ping)
            .send()
            .await
        {
            if r.status() == 200 {
                break;
            }
        }
        if std::time::Instant::now() > deadline {
            panic!("agent in VM {vm_name} did not become reachable within 30 s");
        }
    }

    vm
}

/// Destroy a VM via the REST API, ignoring errors (best-effort cleanup).
#[cfg(target_os = "linux")]
async fn destroy_vm(client: &reqwest::Client, base: &str, vm_name: &str) {
    let _ = client
        .delete(format!("{base}/v1/vms/{vm_name}"))
        .send()
        .await;
}

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
/// - HUSKER_RUN_IGNORED_E2E=1
/// - Running `husker daemon` on localhost:7777
/// - Linux host with KVM enabled
/// - Firecracker binary in PATH or configured
/// - Standard pulled images (or HUSKER_E2E_KERNEL / HUSKER_E2E_ROOTFS overrides)
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore]
async fn vm_lifecycle() {
    require_linux_e2e!();
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
    let vm_name = "e2e-lifecycle";
    let create_body = serde_json::json!({
        "name": vm_name,
        "kernel_path": e2e_kernel(),
        "rootfs_path": e2e_rootfs(),
        "initrd_path": e2e_initrd(),
        "vcpu_count": 1,
        "mem_size_mib": 256,
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

    // 5. Wait for agent to be ready (the guest needs time to boot)
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // 6. Execute a command inside the VM
    let exec_body = serde_json::json!({
        "command": "echo",
        "args": ["hello from VM"],
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
    assert!(result["stdout"].as_str().unwrap().contains("hello from VM"));

    // 7. Write a file to the VM
    let write_body = serde_json::json!({
        "path": "/tmp/e2e-test.txt",
        "data": husker_agent_proto::base64_encode(b"e2e test data"),
    });
    let resp = client
        .post(format!("{base}/v1/vms/{vm_name}/files/write"))
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
        .post(format!("{base}/v1/vms/{vm_name}/files/read"))
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
        .post(format!("{base}/v1/vms/{vm_name}/stop"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // 10. Destroy the VM
    let resp = client
        .delete(format!("{base}/v1/vms/{vm_name}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // 11. Verify it's gone
    let resp = client
        .get(format!("{base}/v1/vms/{vm_name}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// Verify that creating a VM with a duplicate name returns 409 Conflict.
///
/// Requires:
/// - HUSKER_RUN_IGNORED_E2E=1
/// - Running daemon with the ability to create VMs.
/// - Standard pulled images (or HUSKER_E2E_KERNEL / HUSKER_E2E_ROOTFS overrides)
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore]
async fn duplicate_vm_name_returns_conflict() {
    require_linux_e2e!();
    let client = reqwest::Client::new();
    let base = "http://127.0.0.1:7777";

    let vm_name = "e2e-dup-test";
    let body = serde_json::json!({
        "name": vm_name,
        "kernel_path": e2e_kernel(),
        "rootfs_path": e2e_rootfs(),
        "initrd_path": e2e_initrd(),
    });

    // Create first VM
    let resp = client
        .post(format!("{base}/v1/vms"))
        .json(&body)
        .send()
        .await
        .expect("first create should reach daemon");
    assert_eq!(resp.status(), 201);

    // Attempt duplicate - should conflict
    let resp = client
        .post(format!("{base}/v1/vms"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    // Cleanup
    destroy_vm(&client, base, vm_name).await;
}

// ── Cross-platform API tests ─────────────────────────────────────────────
//
// These test the REST API and work with any backend (Firecracker or Apple VZ).
// Each test creates its own VM and tears it down - no pre-existing VMs required.
//
// Preconditions (Linux):
// - HUSKER_RUN_IGNORED_E2E=1
// - Running husker daemon on 127.0.0.1:7777
// - Standard pulled images (or HUSKER_E2E_KERNEL / HUSKER_E2E_ROOTFS overrides)

/// Verify exec with a non-zero exit code propagates correctly.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore]
async fn exec_nonzero_exit_code() {
    require_linux_e2e!();
    let client = reqwest::Client::new();
    let base = "http://127.0.0.1:7777";
    let vm_name = "e2e-exec-nonzero";

    create_and_wait_for_vm(&client, base, vm_name).await;

    let body = serde_json::json!({
        "command": "sh",
        "args": ["-c", "exit 42"],
    });
    let resp = client
        .post(format!("{base}/v1/vms/{vm_name}/exec"))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(result["exit_code"], 42);

    destroy_vm(&client, base, vm_name).await;
}

/// Verify that exec with environment variables works through the full stack.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore]
async fn exec_with_env_through_api() {
    require_linux_e2e!();
    let client = reqwest::Client::new();
    let base = "http://127.0.0.1:7777";
    let vm_name = "e2e-exec-env";

    create_and_wait_for_vm(&client, base, vm_name).await;

    let body = serde_json::json!({
        "command": "sh",
        "args": ["-c", "echo $MY_VAR"],
        "env": {"MY_VAR": "from-api"},
    });
    let resp = client
        .post(format!("{base}/v1/vms/{vm_name}/exec"))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(result["stdout"].as_str().unwrap().trim(), "from-api");

    destroy_vm(&client, base, vm_name).await;
}

/// Verify large file transfer through the API (1 MiB).
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore]
async fn large_file_transfer_through_api() {
    require_linux_e2e!();
    let client = reqwest::Client::new();
    let base = "http://127.0.0.1:7777";
    let vm_name = "e2e-large-file";

    create_and_wait_for_vm(&client, base, vm_name).await;

    // 1 MiB of pattern data
    let data: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
    let encoded = husker_agent_proto::base64_encode(&data);

    let write_body = serde_json::json!({
        "path": "/tmp/large-e2e.bin",
        "data": encoded,
    });
    let resp = client
        .post(format!("{base}/v1/vms/{vm_name}/files/write"))
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
        .post(format!("{base}/v1/vms/{vm_name}/files/read"))
        .json(&read_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let file_data: serde_json::Value = resp.json().await.unwrap();
    let decoded = husker_agent_proto::base64_decode(file_data["data"].as_str().unwrap()).unwrap();
    assert_eq!(decoded.len(), data.len());
    assert_eq!(decoded, data);

    destroy_vm(&client, base, vm_name).await;
}

// ── Cross-platform shell E2E tests ───────────────────────────────────────
//
// These use `script` for PTY wrapping, with platform-specific invocation.
// Each test creates its own VM via the daemon API.
//
// Preconditions (Linux):
// - HUSKER_RUN_IGNORED_E2E=1
// - Running husker daemon on 127.0.0.1:7777
// - `script` utility available
// - Standard pulled images (or HUSKER_E2E_KERNEL / HUSKER_E2E_ROOTFS overrides)

/// Verify interactive shell: prompt appears, echo works, TERM is set, devpts is mounted.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore]
async fn shell_interactive_session() {
    require_linux_e2e!();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let client = reqwest::Client::new();
    let base = "http://127.0.0.1:7777";
    let vm_name = "e2e-shell-interactive";

    create_and_wait_for_vm(&client, base, vm_name).await;

    let mut child = spawn_shell_with_pty(vm_name);
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

    destroy_vm(&client, base, vm_name).await;
}

/// Verify that the shell propagates the guest's exit code.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore]
async fn shell_exit_code_propagation() {
    require_linux_e2e!();
    use tokio::io::AsyncWriteExt;

    let client = reqwest::Client::new();
    let base = "http://127.0.0.1:7777";
    let vm_name = "e2e-shell-exitcode";

    create_and_wait_for_vm(&client, base, vm_name).await;

    let mut child = spawn_shell_with_pty(vm_name);
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

    destroy_vm(&client, base, vm_name).await;
}

/// Verify that shell to a non-existent VM returns an error quickly.
///
/// Does not require a running VM - just tests CLI error handling.
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

/// Verify pause -> resume -> exec cycle works end-to-end on Apple VZ.
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
/// Requires:
/// - HUSKER_RUN_IGNORED_E2E=1
/// - Running daemon.
/// - Standard pulled images (or HUSKER_E2E_KERNEL / HUSKER_E2E_ROOTFS overrides)
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore]
async fn logs_serial_output() {
    require_linux_e2e!();
    let client = reqwest::Client::new();
    let base = "http://127.0.0.1:7777";
    let vm_name = "e2e-logs-test";

    // 1. Create a VM
    let create_body = serde_json::json!({
        "name": vm_name,
        "kernel_path": e2e_kernel(),
        "rootfs_path": e2e_rootfs(),
        "initrd_path": e2e_initrd(),
        "vcpu_count": 1,
        "mem_size_mib": 256,
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
