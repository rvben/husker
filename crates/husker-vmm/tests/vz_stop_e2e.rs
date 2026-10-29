//! A successful Apple VZ `stop_vm` means the guest no longer runs: the caller
//! deletes the rootfs clone and reuses the vsock CID the moment it returns.
//!
//! A booted Linux guest ignores the ACPI stop request VZ sends (it has no
//! power-button handler; the daemon asks the agent to power off before it
//! ever calls `stop_vm`), so this exercises the path where the backend must
//! wait out the grace period and force the VM off. Recording the stop as soon
//! as the request was accepted left the Virtualization helper running the
//! guest with the rootfs still open.
//!
//! Needs a real VM, so the test binary must carry the
//! `com.apple.security.virtualization` entitlement; run it through
//! `make test-vz-stop-e2e-gated`, which signs it first.
#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use husker_vmm::apple_vz::AppleVzBackend;
use husker_vmm::{BootMode, GUEST_SHUTDOWN_GRACE, VmConfig, VmState, VmmBackend};

const GATE: &str = "HUSKER_RUN_VZ_STOP_E2E";

fn required_path(var: &str) -> PathBuf {
    let path = PathBuf::from(
        std::env::var_os(var).unwrap_or_else(|| panic!("{GATE}=1 also requires {var}")),
    );
    assert!(path.is_file(), "{var}={} is not a file", path.display());
    path
}

/// Every process with `path` open, by pid.
fn holders(path: &Path) -> Vec<u32> {
    let output = Command::new("lsof")
        .arg("-t")
        .arg(path)
        .output()
        .expect("run lsof");
    // lsof exits 1 with no output when nothing has the file open.
    assert!(
        output.status.success() || output.stdout.is_empty(),
        "lsof failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|pid| pid.trim().parse().expect("lsof -t prints pids"))
        .collect()
}

#[tokio::test]
#[ignore = "gated: run via `make test-vz-stop-e2e-gated`"]
async fn stop_returns_only_after_the_guest_has_released_its_rootfs() {
    if std::env::var(GATE).as_deref() != Ok("1") {
        eprintln!("skipping: set {GATE}=1");
        return;
    }
    let kernel = required_path("HUSKER_VZ_KERNEL");
    let initrd = required_path("HUSKER_VZ_INITRD");
    let image = required_path("HUSKER_VZ_ROOTFS");

    let work = tempfile::tempdir().expect("tempdir");
    let rootfs = work.path().join("rootfs.ext4");
    std::fs::copy(&image, &rootfs).expect("clone the rootfs");
    let runtime = work.path().join("run");
    std::fs::create_dir(&runtime).expect("create the runtime directory");
    let backend = AppleVzBackend::new(runtime);
    let config = VmConfig {
        requested_id: None,
        name: "vz-stop-e2e".into(),
        vcpu_count: 1,
        mem_size_mib: 256,
        kernel_path: kernel,
        rootfs_path: rootfs.clone(),
        kernel_args: Some("console=hvc0 root=/dev/vda rw init=/sbin/init".into()),
        initrd_path: Some(initrd),
        vsock_cid: 3,
        tap_device: None,
        guest_mac: None,
        vmm: None,
        boot: BootMode::DirectKernel,
        seed_path: None,
        balloon: false,
        volume_path: None,
        network_disabled: true,
        host_shares: Vec::new(),
    };
    let selection = backend.select_backend_for_config(&config).expect("select");
    let id = backend
        .create_vm(selection, config)
        .await
        .expect("create and start the VM")
        .info
        .id;

    // Let the guest get past the kernel into userspace, so the stop request
    // reaches a running system rather than one still in early boot.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let booted = backend.vm_info(id).await.map(|info| info.state);
    let held = !holders(&rootfs).is_empty();
    if booted.as_ref().ok() != Some(&VmState::Running) || !held {
        backend.destroy_vm(id).await.expect("destroy the VM");
        assert_eq!(booted.unwrap(), VmState::Running);
        panic!("a running guest must hold its rootfs open, or the check below proves nothing");
    }

    let started = Instant::now();
    let stopped = backend.stop_vm(id).await;
    let elapsed = started.elapsed();
    let still_open = holders(&rootfs);
    let state = backend.vm_info(id).await.map(|info| info.state);
    backend.destroy_vm(id).await.expect("destroy the VM");

    stopped.expect("stop_vm");
    assert!(
        still_open.is_empty(),
        "stop_vm returned after {elapsed:?} while pids {still_open:?} still held the rootfs"
    );
    assert_eq!(state.unwrap(), VmState::Stopped);
    // The premise: the guest ignored the request, so the stop had to wait out
    // the grace and force the VM off. A guest that honoured it would leave
    // the forced path above unexercised.
    assert!(
        elapsed >= GUEST_SHUTDOWN_GRACE,
        "stop_vm returned after {elapsed:?}, inside the {GUEST_SHUTDOWN_GRACE:?} grace: \
         the guest honoured the stop request, so this run did not exercise the forced stop"
    );
}
