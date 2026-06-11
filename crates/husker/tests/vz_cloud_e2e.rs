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
