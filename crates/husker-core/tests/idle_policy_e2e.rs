//! Gated end-to-end test for the idle-suspend / resume-on-connect round trip.
//!
//! Exercises the full production path through `HuskerCore`'s public API: a
//! real Firecracker VM boots, opts into a short idle timeout, gets a port
//! forward to an in-guest TCP echo listener, is suspended by the real
//! idle-policy tick once idle, and is woken back up by a plain TCP connect to
//! its forwarded host port - the resume-on-connect path that `suspend_vm`
//! installs (`install_resume_listeners` / `ResumeDialer` in `src/lib.rs` and
//! `src/port_proxy.rs`).
//!
//! The resume-on-connect machinery under test (kernel DNAT removal + a
//! userspace resume listener) is Linux-only, so this whole file is gated
//! behind the `linux-net` feature (on by default).
//!
//! # Preconditions
//!
//! - `HUSKER_RUN_IGNORED_E2E=1`
//! - Linux host with `/dev/kvm`, a `firecracker` binary on `PATH`, and root
//!   (or `CAP_NET_ADMIN`/`CAP_NET_RAW`) for TAP/bridge/nftables setup.
//! - `HUSKER_E2E_KERNEL`  - path to a kernel image for direct-kernel boot.
//! - `HUSKER_E2E_ROOTFS`  - path to a rootfs. Must carry the husker guest
//!   agent (so the userdata script and exec work) and a userland `nc` that
//!   supports `-e` (busybox built with `nc` extras, as `busybox-extras`
//!   provides on Alpine) so the userdata script below can start a TCP echo
//!   listener. Adjust the listener command below if the target rootfs lacks
//!   `nc -e`.
//! - `HUSKER_E2E_INITRD`  - optional initramfs path; unset or empty to boot
//!   without one.
//!
//! Run with:
//! ```text
//! HUSKER_RUN_IGNORED_E2E=1 \
//! HUSKER_E2E_KERNEL=/path/to/vmlinux \
//! HUSKER_E2E_ROOTFS=/path/to/rootfs.ext4 \
//!   cargo test -p husker-core --test idle_policy_e2e -- --ignored
//! ```

#![cfg(feature = "linux-net")]

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use husker_core::{CreateVmRequest, HuskerCore};
use husker_vmm::cgroup::CgroupSupervisor;
use husker_vmm::firecracker::FirecrackerBackend;
use uuid::Uuid;

/// A dedicated bridge/subnet, distinct from the daemon's default
/// `husker0`/`172.20.0.0/24` and from other gated net-e2e throwaway bridges
/// (`hfrk0`/`198.51.100.0/24` in `husker-core`'s own unit tests, `hpfq0`/
/// `192.0.2.0/24` in `orchestration_paths.rs`), so this test never collides
/// with a real daemon or another concurrently-gated test on the same host.
const BRIDGE: &str = "hidl0";
const SUBNET_BASE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 0);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const GUEST_PORT: u16 = 9000;
const HOST_PORT: u16 = 19281;
const VM_NAME: &str = "idle-e2e";

/// Resolve a required e2e asset path from an env var, panicking with an
/// actionable message when it is unset or does not exist.
fn required_path(env_var: &str) -> PathBuf {
    let raw = std::env::var(env_var)
        .unwrap_or_else(|_| panic!("{env_var} must be set to run this gated e2e test"));
    let path = PathBuf::from(raw);
    assert!(path.exists(), "{env_var}={path:?} does not exist");
    path
}

/// Optional initramfs: `HUSKER_E2E_INITRD` unset or empty means "no initrd".
fn optional_initrd() -> Option<PathBuf> {
    match std::env::var("HUSKER_E2E_INITRD") {
        Ok(v) if v.is_empty() => None,
        Ok(v) => Some(PathBuf::from(v)),
        Err(_) => None,
    }
}

/// Look up a VM's current record by id via the core's plain (non-refreshed) listing.
async fn find_vm(core: &HuskerCore<FirecrackerBackend>, id: Uuid) -> husker_state::VmRecord {
    core.list_vms()
        .expect("list_vms")
        .into_iter()
        .find(|v| v.id == id)
        .expect("VM must still exist")
}

#[tokio::test]
#[ignore]
async fn idle_suspend_then_resume_on_connect_roundtrip() {
    if std::env::var("HUSKER_RUN_IGNORED_E2E").as_deref() != Ok("1") {
        return;
    }

    let kernel = required_path("HUSKER_E2E_KERNEL");
    let rootfs = required_path("HUSKER_E2E_ROOTFS");
    let initrd = optional_initrd();

    let tmp = tempfile::tempdir().unwrap();
    let runtime_dir = tmp.path().join("run");
    std::fs::create_dir_all(&runtime_dir).unwrap();

    // A fresh state store starts CID allocation at its default floor; raise it
    // so this run's TAP names (`husker<cid>`) never collide with a real
    // daemon's VMs already using low CIDs on a shared host - the same
    // mitigation `fork_records_forked_from` uses in husker-core's own unit
    // tests (see `src/lib.rs`).
    let state = husker_state::StateStore::open_memory().unwrap();
    state.ensure_cid_base(2000).unwrap();

    // Self-heal a stray bridge/table left behind by a previous interrupted run.
    husker_net::delete_bridge(BRIDGE).await.ok();
    let table = husker_net::nft_table_for_bridge(BRIDGE);
    let _ = tokio::process::Command::new("nft")
        .args(["delete", "table", "ip", &table])
        .output()
        .await;

    husker_net::create_bridge(BRIDGE, GATEWAY, 24)
        .await
        .expect("create throwaway bridge (needs root/CAP_NET_ADMIN)");

    let core = Arc::new(HuskerCore::new(
        FirecrackerBackend::new(
            "firecracker",
            &runtime_dir,
            Arc::new(CgroupSupervisor::disabled()),
        ),
        state,
        husker_net::IpAllocator::new(SUBNET_BASE, 24),
        husker_storage::StorageConfig {
            data_dir: tmp.path().to_path_buf(),
            state_dir: tmp.path().to_path_buf(),
        },
        BRIDGE.to_string(),
        vec!["8.8.8.8".into()],
        runtime_dir.clone(),
    ));

    // The guest agent runs the userdata script over vsock once the VM boots;
    // background a TCP echo listener on GUEST_PORT so the script itself
    // returns immediately (userdata is `exec`'d in the foreground by
    // `run_userdata`, which only marks `userdata_status` "completed" once the
    // script exits).
    let userdata = format!(
        "#!/bin/sh\n\
         nohup sh -c 'while true; do nc -l -p {GUEST_PORT} -e /bin/cat; done' \
         >/tmp/echo.log 2>&1 </dev/null &\n"
    );

    let record = core
        .create_vm(CreateVmRequest {
            name: VM_NAME.into(),
            kernel_path: Some(kernel),
            rootfs_path: Some(rootfs),
            initrd_path: initrd,
            vcpu_count: Some(1),
            mem_size_mib: Some(256),
            userdata: Some(userdata),
            idle_timeout_secs: Some(2),
            suspend_ttl_secs: None,
            auto_resume: Some(true),
            ..Default::default()
        })
        .await
        .expect("create_vm");
    let vm_id = record.id;
    assert_eq!(record.state, "running");

    core.spawn_userdata(&record);

    // Wait for the userdata script to finish starting the echo listener.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let vm = find_vm(&core, vm_id).await;
        match vm.userdata_status.as_deref() {
            Some("completed") => break,
            Some("failed") => panic!("userdata script failed to start the echo listener"),
            _ => {}
        }
        assert!(
            Instant::now() < deadline,
            "userdata script did not complete within 60s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    core.add_port_forward(VM_NAME, HOST_PORT, GUEST_PORT, None)
        .await
        .expect("add_port_forward");

    // Wait past the 2s idle timeout, driving the real idle-policy tick
    // directly (the same function the daemon's background loop calls)
    // instead of waiting on a real timer-driven task.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        core.idle_policy_tick().await;
        let vm = find_vm(&core, vm_id).await;
        if vm.state == "suspended" {
            assert!(
                vm.suspended_at.is_some(),
                "a suspended VM must stamp suspended_at"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "VM did not suspend within 30s of idling past its 2s timeout"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // The kernel DNAT rule must be gone once suspended: only the userspace
    // resume listener should be accepting connections on HOST_PORT now.
    let rules = tokio::process::Command::new("nft")
        .args(["list", "table", "ip", &table])
        .output()
        .await
        .expect("run nft list table");
    let rules = String::from_utf8_lossy(&rules.stdout);
    assert!(
        !rules.contains(&HOST_PORT.to_string()),
        "DNAT rule for {HOST_PORT} should be removed once suspended:\n{rules}"
    );

    // A plain TCP connect to the forwarded host port must wake the VM (via the
    // resume listener's `ResumeDialer`) and relay through to the still-running
    // in-guest echo listener (its process survives the suspend/resume
    // snapshot round trip along with the rest of guest memory).
    let echoed = tokio::time::timeout(Duration::from_secs(30), async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", HOST_PORT))
            .await
            .expect("connect to suspended VM's forwarded port");
        conn.write_all(b"x").await.expect("write probe byte");
        let mut buf = [0u8; 1];
        conn.read_exact(&mut buf).await.expect("read echoed byte");
        buf[0]
    })
    .await
    .expect("connect-triggered resume + echo round trip timed out");
    assert_eq!(
        echoed, b'x',
        "echo listener must return the exact byte sent"
    );

    let vm = find_vm(&core, vm_id).await;
    assert_eq!(vm.state, "running", "connecting must resume the VM");
    assert!(vm.suspended_at.is_none(), "resume must clear suspended_at");

    let _ = core.destroy_vm(VM_NAME).await;
    husker_net::delete_bridge(BRIDGE).await.ok();
    let _ = tokio::process::Command::new("nft")
        .args(["delete", "table", "ip", &table])
        .output()
        .await;
}
