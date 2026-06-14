//! Gated end-to-end test: boots a real Ubuntu arm64 cloud image on Apple VZ.
//!
//! Requires: macOS host, codesigned binary with embedded aarch64 agent,
//! qemu-img, and a local image.
//!
//! Run:
//!   HUSKER_RUN_VZ_CLOUD_E2E=1 HUSKER_VZ_CLOUD_IMAGE=/tmp/noble-arm64.img \
//!     cargo nextest run -p husker --no-default-features --run-ignored all vz_cloud
#![cfg(target_os = "macos")]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::{Duration, Instant};

// ── Daemon helpers ────────────────────────────────────────────────────────────

/// Find an unused localhost port.
fn free_port() -> u16 {
    // Binding port 0 lets the OS assign a free port; we read it back and drop
    // the listener so the test daemon can bind the same port moments later.
    // There is a small TOCTOU window, but it is negligible for integration tests
    // running on a quiet loopback interface.
    let l = TcpListener::bind("127.0.0.1:0").expect("bind port 0");
    l.local_addr().unwrap().port()
}

/// Guard that kills the daemon process when dropped, even on panic.
struct DaemonGuard {
    child: Child,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Apply the Apple Virtualization entitlement to the daemon binary.
///
/// Apple VZ requires the `com.apple.security.virtualization` entitlement at
/// process start.  The cargo test build does not codesign binaries, so this
/// test applies an ad-hoc signature with the entitlement before spawning the
/// daemon.  The entitlements file is resolved relative to the workspace root
/// (two directories above the crate manifest directory, baked in at compile
/// time via `CARGO_MANIFEST_DIR`).
fn codesign_for_vz(bin: &str) {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root is two levels above crate manifest");
    let entitlements = workspace_root.join("husker.entitlements");
    let status = std::process::Command::new("codesign")
        .args([
            "--entitlements",
            entitlements
                .to_str()
                .expect("entitlements path is valid UTF-8"),
            "-s",
            "-",
            "-f",
            bin,
        ])
        .status()
        .expect("codesign must be available on macOS");
    assert!(status.success(), "codesign failed for {bin}: {status}");
}

/// Spawn the husker daemon on `port`, using `data_dir` as HUSKER_DATA_DIR.
///
/// Applies the Apple Virtualization entitlement to the binary before spawning,
/// because the cargo test build does not codesign and VZ refuses to start a VM
/// process without the entitlement.
///
/// Returns a guard that kills the daemon on drop.  Polls the TCP port until it
/// accepts a connection or the timeout (10 s) expires.
fn spawn_daemon(port: u16, data_dir: &Path) -> DaemonGuard {
    let bin = env!("CARGO_BIN_EXE_husker");
    codesign_for_vz(bin);
    let child = std::process::Command::new(bin)
        .args(["daemon", "--listen", &format!("127.0.0.1:{port}")])
        .env("HUSKER_DATA_DIR", data_dir)
        // Suppress daemon log noise in test output unless --no-capture is used.
        .env("RUST_LOG", "warn")
        .spawn()
        .expect("failed to spawn husker daemon");

    let guard = DaemonGuard { child };

    // Wait for the daemon's TCP port to accept connections.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            break;
        }
        if Instant::now() > deadline {
            panic!("daemon on port {port} did not accept connections within 10 s");
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    guard
}

// ── Test ──────────────────────────────────────────────────────────────────────

/// Boot a real Ubuntu arm64 cloud image on Apple VZ end-to-end.
///
/// Validates: VM creation, cloud-init completion, outbound network connectivity,
/// lazy guest-IP discovery, and clean VM deletion.
#[tokio::test]
#[ignore = "gated: set HUSKER_RUN_VZ_CLOUD_E2E=1 and HUSKER_VZ_CLOUD_IMAGE=<path>"]
async fn vz_cloud_image_boots_and_reports_ip() {
    // ── Gate ─────────────────────────────────────────────────────────────────
    if std::env::var("HUSKER_RUN_VZ_CLOUD_E2E").as_deref() != Ok("1") {
        eprintln!("skipping vz_cloud_image_boots_and_reports_ip: set HUSKER_RUN_VZ_CLOUD_E2E=1");
        return;
    }
    let image_path = match std::env::var("HUSKER_VZ_CLOUD_IMAGE") {
        Ok(p) => PathBuf::from(p),
        Err(_) => {
            eprintln!("skipping: HUSKER_VZ_CLOUD_IMAGE not set");
            return;
        }
    };
    if !image_path.exists() {
        eprintln!(
            "skipping: HUSKER_VZ_CLOUD_IMAGE={} does not exist",
            image_path.display()
        );
        return;
    }

    // ── Daemon ────────────────────────────────────────────────────────────────
    let data_dir = tempfile::tempdir().expect("tempdir");
    let port = free_port();

    // The daemon guard kills the process on drop (including on panic / assert
    // failure), so we never leak it.
    let _daemon = spawn_daemon(port, data_dir.path());
    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();

    // ── 1. Create the VM ──────────────────────────────────────────────────────
    let vm_name = "vz-cloud-e2e";
    let create_body = serde_json::json!({
        "name": vm_name,
        "cloud_image": image_path.to_str().expect("image path is valid UTF-8"),
        "vcpu_count": 2,
        "mem_size_mib": 1024,
    });

    let resp = client
        .post(format!("{base}/v1/vms"))
        .json(&create_body)
        .send()
        .await
        .expect("POST /v1/vms should reach daemon");
    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "VM creation failed with {status}: {body_text}"
    );

    eprintln!("[vz_cloud_e2e] VM created, waiting for cloud-init (up to 5 min)...");

    // ── 2. Poll until running + cloud-init done ───────────────────────────────
    //
    // Ubuntu cloud images can take 30-90 s to complete cloud-init on first boot.
    // Early exec attempts will return connection-refused or timeout errors from
    // the agent; those are expected and we keep looping.
    let poll_start = Instant::now();
    let poll_budget = Duration::from_secs(300);
    let poll_sleep = Duration::from_secs(5);

    let mut cloud_init_done = false;

    while Instant::now() - poll_start < poll_budget {
        // Check VM state first.
        let info: serde_json::Value =
            match client.get(format!("{base}/v1/vms/{vm_name}")).send().await {
                Ok(r) if r.status().is_success() => {
                    r.json().await.unwrap_or(serde_json::Value::Null)
                }
                _ => {
                    tokio::time::sleep(poll_sleep).await;
                    continue;
                }
            };

        let state = info["state"].as_str().unwrap_or("unknown");
        eprintln!(
            "[vz_cloud_e2e] state={state} elapsed={:.0}s",
            poll_start.elapsed().as_secs_f32()
        );

        if state != "running" {
            tokio::time::sleep(poll_sleep).await;
            continue;
        }

        // VM is running; try cloud-init status.  The exec may fail early (agent
        // not yet listening); tolerate that and keep polling.
        let exec_body = serde_json::json!({
            "command": "cloud-init",
            "args": ["status", "--wait"],
            // Allow cloud-init up to 120 s to finish (clamped by exec_timeout_max_secs).
            "timeout_secs": 120,
            // Give the agent up to 30 s to accept the vsock connection.
            "connect_timeout_secs": 30,
        });
        let exec_resp = client
            .post(format!("{base}/v1/vms/{vm_name}/exec"))
            .json(&exec_body)
            .send()
            .await;

        match exec_resp {
            Ok(r) if r.status().is_success() => {
                let result: serde_json::Value = r.json().await.unwrap_or(serde_json::Value::Null);
                let exit_code = result["exit_code"].as_i64().unwrap_or(-1);
                let stdout = result["stdout"].as_str().unwrap_or("");
                eprintln!("[vz_cloud_e2e] cloud-init status: exit={exit_code} stdout={stdout:?}");
                if exit_code == 0 {
                    cloud_init_done = true;
                    eprintln!(
                        "[vz_cloud_e2e] cloud-init done after {:.0}s",
                        poll_start.elapsed().as_secs_f32()
                    );
                    break;
                }
            }
            Ok(r) => {
                eprintln!(
                    "[vz_cloud_e2e] exec returned HTTP {}: will retry",
                    r.status()
                );
            }
            Err(e) => {
                eprintln!("[vz_cloud_e2e] exec error (expected early on): {e}");
            }
        }

        tokio::time::sleep(poll_sleep).await;
    }

    assert!(
        cloud_init_done,
        "cloud-init did not complete within {}s",
        poll_budget.as_secs()
    );

    // ── 3. Network connectivity proof ─────────────────────────────────────────
    //
    // Ubuntu Noble ships wget; use a lightweight HTTP probe to detectportal.firefox.com.
    // That page returns a short plaintext body; we just need exit 0.
    let net_body = serde_json::json!({
        "command": "sh",
        "args": ["-c", "wget -qO- --timeout=10 http://detectportal.firefox.com/success.txt | head -c 32"],
        "timeout_secs": 20,
        "connect_timeout_secs": 15,
    });
    let net_resp = client
        .post(format!("{base}/v1/vms/{vm_name}/exec"))
        .json(&net_body)
        .send()
        .await
        .expect("network-proof exec should reach daemon");
    assert!(
        net_resp.status().is_success(),
        "network-proof exec returned HTTP {}",
        net_resp.status()
    );
    let net_result: serde_json::Value = net_resp.json().await.unwrap();
    let net_exit = net_result["exit_code"].as_i64().unwrap_or(-1);
    let net_stdout = net_result["stdout"].as_str().unwrap_or("");
    eprintln!("[vz_cloud_e2e] network probe: exit={net_exit} stdout={net_stdout:?}");
    assert_eq!(
        net_exit,
        0,
        "outbound network connectivity test failed (exit {net_exit}); \
         stdout={net_stdout:?} stderr={:?}",
        net_result["stderr"].as_str().unwrap_or("")
    );

    // ── 4. Verify guest_ip is a parseable non-loopback IPv4 ──────────────────
    let info_resp = client
        .get(format!("{base}/v1/vms/{vm_name}"))
        .send()
        .await
        .expect("GET /v1/vms/:name should succeed");
    assert!(
        info_resp.status().is_success(),
        "GET /v1/vms/{vm_name} returned {}",
        info_resp.status()
    );
    let info: serde_json::Value = info_resp.json().await.unwrap();
    let guest_ip_str = info["guest_ip"].as_str().unwrap_or("");
    eprintln!("[vz_cloud_e2e] guest_ip={guest_ip_str:?}");
    let guest_ip: std::net::Ipv4Addr = guest_ip_str
        .parse()
        .expect("guest_ip should be a parseable IPv4 address");
    assert!(
        !guest_ip.is_loopback() && !guest_ip.is_unspecified(),
        "guest_ip {guest_ip} should be a non-loopback, non-zero address"
    );

    // ── 5. Delete the VM ──────────────────────────────────────────────────────
    let del_resp = client
        .delete(format!("{base}/v1/vms/{vm_name}"))
        .send()
        .await
        .expect("DELETE /v1/vms/:name should reach daemon");
    assert!(
        del_resp.status().is_success(),
        "DELETE returned {}",
        del_resp.status()
    );

    // Verify the VM's data directory was cleaned up.
    // The daemon stores VM data under <data_dir>/vms/<vm_id>/.
    // After deletion the directory should be gone.
    let vms_dir = data_dir.path().join("vms");
    if vms_dir.exists() {
        let leftover: Vec<_> = std::fs::read_dir(&vms_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            leftover.is_empty(),
            "VM data directory was not cleaned up after delete; found: {leftover:?}"
        );
    }

    eprintln!("[vz_cloud_e2e] PASS");
}

// ── Live port-forward e2e ───────────────────────────────────────────────────────

/// Create a cloud VM, wait for cloud-init, and return its discovered guest IP.
///
/// Mirrors the boot/poll logic of the test above. Polling `GET /v1/vms/:name`
/// also triggers lazy guest-IP discovery, so the returned IP is populated in
/// daemon state (which `add_port_forward` reads).
async fn create_and_wait_ready(
    client: &reqwest::Client,
    base: &str,
    vm_name: &str,
    image_path: &Path,
) -> String {
    let create_body = serde_json::json!({
        "name": vm_name,
        "cloud_image": image_path.to_str().expect("image path is valid UTF-8"),
        "vcpu_count": 2,
        "mem_size_mib": 1024,
    });
    let resp = client
        .post(format!("{base}/v1/vms"))
        .json(&create_body)
        .send()
        .await
        .expect("POST /v1/vms should reach daemon");
    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "VM creation failed with {status}: {body_text}"
    );

    let poll_start = Instant::now();
    let poll_budget = Duration::from_secs(300);
    let poll_sleep = Duration::from_secs(5);

    // Phase 1: wait for cloud-init to finish.
    loop {
        assert!(
            poll_start.elapsed() < poll_budget,
            "cloud-init did not complete within {}s",
            poll_budget.as_secs()
        );
        let info: serde_json::Value =
            match client.get(format!("{base}/v1/vms/{vm_name}")).send().await {
                Ok(r) if r.status().is_success() => {
                    r.json().await.unwrap_or(serde_json::Value::Null)
                }
                _ => {
                    tokio::time::sleep(poll_sleep).await;
                    continue;
                }
            };
        if info["state"].as_str().unwrap_or("") != "running" {
            tokio::time::sleep(poll_sleep).await;
            continue;
        }
        let exec_body = serde_json::json!({
            "command": "cloud-init",
            "args": ["status", "--wait"],
            "timeout_secs": 120,
            "connect_timeout_secs": 30,
        });
        if let Ok(r) = client
            .post(format!("{base}/v1/vms/{vm_name}/exec"))
            .json(&exec_body)
            .send()
            .await
            && r.status().is_success()
        {
            let result: serde_json::Value = r.json().await.unwrap_or(serde_json::Value::Null);
            if result["exit_code"].as_i64().unwrap_or(-1) == 0 {
                break;
            }
        }
        tokio::time::sleep(poll_sleep).await;
    }

    // Phase 2: wait for a discovered guest IP (the GET triggers discovery).
    loop {
        assert!(
            poll_start.elapsed() < poll_budget,
            "guest IP was not discovered within {}s",
            poll_budget.as_secs()
        );
        if let Ok(r) = client.get(format!("{base}/v1/vms/{vm_name}")).send().await
            && r.status().is_success()
        {
            let info: serde_json::Value = r.json().await.unwrap_or(serde_json::Value::Null);
            if let Some(ip) = info["guest_ip"].as_str()
                && !ip.is_empty()
            {
                return ip.to_string();
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Run a command in the guest and return (exit_code, stdout).
async fn guest_exec(
    client: &reqwest::Client,
    base: &str,
    vm_name: &str,
    command: &str,
    args: &[&str],
) -> (i64, String) {
    let body = serde_json::json!({
        "command": command,
        "args": args,
        "timeout_secs": 20,
        "connect_timeout_secs": 15,
    });
    let resp = client
        .post(format!("{base}/v1/vms/{vm_name}/exec"))
        .json(&body)
        .send()
        .await
        .expect("exec should reach daemon");
    assert!(resp.status().is_success(), "exec HTTP {}", resp.status());
    let r: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    (
        r["exit_code"].as_i64().unwrap_or(-1),
        r["stdout"].as_str().unwrap_or("").to_string(),
    )
}

/// End-to-end proof that the macOS userspace proxy forwards a host TCP port to a
/// real service inside a VZ cloud guest, and that removal tears the listener down.
///
/// This is the live confirmation of the Approach A routability assumption: the
/// host process opens a TCP connection to `guest_ip:guest_port` over the VZ NAT.
#[tokio::test]
#[ignore = "gated: set HUSKER_RUN_VZ_CLOUD_E2E=1 and HUSKER_VZ_CLOUD_IMAGE=<path>"]
async fn vz_cloud_port_forward_reaches_guest() {
    if std::env::var("HUSKER_RUN_VZ_CLOUD_E2E").as_deref() != Ok("1") {
        eprintln!("skipping vz_cloud_port_forward_reaches_guest: set HUSKER_RUN_VZ_CLOUD_E2E=1");
        return;
    }
    let image_path = match std::env::var("HUSKER_VZ_CLOUD_IMAGE") {
        Ok(p) => PathBuf::from(p),
        Err(_) => {
            eprintln!("skipping: HUSKER_VZ_CLOUD_IMAGE not set");
            return;
        }
    };
    if !image_path.exists() {
        eprintln!("skipping: HUSKER_VZ_CLOUD_IMAGE does not exist");
        return;
    }

    let data_dir = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let _daemon = spawn_daemon(port, data_dir.path());
    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();

    let vm_name = "vz-pf-e2e";
    let guest_ip = create_and_wait_ready(&client, &base, vm_name, &image_path).await;
    eprintln!("[vz_pf_e2e] guest_ip={guest_ip}");

    // ── Start a TCP service inside the guest (detached, survives the exec) ──────
    const GUEST_PORT: u16 = 8088;
    let (code, _out) = guest_exec(
        &client,
        &base,
        vm_name,
        // setsid + full stdio redirection so the server outlives the exec channel.
        "sh",
        &[
            "-c",
            &format!(
                "setsid python3 -m http.server {GUEST_PORT} >/tmp/pf.log 2>&1 </dev/null & sleep 1; echo up"
            ),
        ],
    )
    .await;
    assert_eq!(code, 0, "failed to start guest http server");

    // ── Add the port forward ───────────────────────────────────────────────────
    let host_port = free_port();
    let add_resp = client
        .post(format!("{base}/v1/vms/{vm_name}/ports"))
        .json(&serde_json::json!({ "host_port": host_port, "guest_port": GUEST_PORT }))
        .send()
        .await
        .expect("POST ports should reach daemon");
    assert_eq!(
        add_resp.status(),
        reqwest::StatusCode::CREATED,
        "add port forward failed"
    );
    let add_json: serde_json::Value = add_resp.json().await.unwrap();
    assert_eq!(add_json["bind_addr"], serde_json::json!("127.0.0.1"));

    // ── THE PROOF: reach the guest service through the host port ────────────────
    let url = format!("http://127.0.0.1:{host_port}/");
    let mut reached = false;
    for attempt in 0..15 {
        match client
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                reached = true;
                eprintln!(
                    "[vz_pf_e2e] reached guest via 127.0.0.1:{host_port} (attempt {attempt})"
                );
                break;
            }
            Ok(r) => eprintln!("[vz_pf_e2e] attempt {attempt}: HTTP {}", r.status()),
            Err(e) => eprintln!("[vz_pf_e2e] attempt {attempt}: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(
        reached,
        "host could not reach the guest service through the forwarded port"
    );

    // ── List shows the forward with the effective bind address ─────────────────
    let list: serde_json::Value = client
        .get(format!("{base}/v1/vms/{vm_name}/ports"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.as_array().map(|a| a.len()), Some(1));
    assert_eq!(list[0]["bind_addr"], serde_json::json!("127.0.0.1"));

    // ── Remove the forward; the host port must stop reaching the guest ─────────
    let del = client
        .delete(format!("{base}/v1/vms/{vm_name}/ports/{host_port}"))
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), reqwest::StatusCode::NO_CONTENT);

    let mut closed = false;
    for _ in 0..25 {
        if client
            .get(&url)
            .timeout(Duration::from_secs(2))
            .send()
            .await
            .is_err()
        {
            closed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(closed, "forwarded port should stop accepting after removal");

    // ── Clean up ───────────────────────────────────────────────────────────────
    let del_vm = client
        .delete(format!("{base}/v1/vms/{vm_name}"))
        .send()
        .await
        .unwrap();
    assert!(
        del_vm.status().is_success(),
        "DELETE vm returned {}",
        del_vm.status()
    );
    eprintln!("[vz_pf_e2e] PASS");
}
