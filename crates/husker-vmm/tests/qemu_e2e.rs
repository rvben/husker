//! Real-boot QEMU e2e. Requires a Linux host with `/dev/kvm`, `/dev/vhost-vsock`,
//! `qemu-system-x86_64`, and a kernel + rootfs whose guest runs the husker agent.
//! The guest kernel must support virtio over PCI (`CONFIG_VIRTIO_PCI`); a kernel
//! built only for virtio-MMIO (e.g. some Firecracker kernels) will not find the
//! root disk under the q35 machine.
//!
//! Run with (initrd optional, needed for kernels that ship virtio-blk as a module):
//!   HUSKER_RUN_IGNORED_E2E=1 \
//!   HUSKER_E2E_KERNEL=/var/lib/husker/kernels/vmlinux \
//!   HUSKER_E2E_ROOTFS=/tmp/test-rootfs.ext4 \
//!   HUSKER_E2E_INITRD=/var/lib/husker/kernels/initramfs-x86_64-virt.gz \
//!   cargo test -p husker-vmm --test qemu_e2e -- --ignored --nocapture
//!
//! `HUSKER_E2E_ROOTFS` is written to (cache=writeback); point it at a disposable copy.
#![cfg(target_os = "linux")]

use husker_vmm::VmmBackend;
use husker_vmm::qemu::QemuKvmBackend;

#[tokio::test]
#[ignore = "needs KVM + vhost-vsock + qemu + images; gated by HUSKER_RUN_IGNORED_E2E"]
async fn qemu_boots_and_vsock() {
    if std::env::var("HUSKER_RUN_IGNORED_E2E").as_deref() != Ok("1") {
        eprintln!("skipping qemu_boots_and_vsock: set HUSKER_RUN_IGNORED_E2E=1");
        return;
    }
    let kernel = std::env::var("HUSKER_E2E_KERNEL").expect("HUSKER_E2E_KERNEL");
    let rootfs = std::env::var("HUSKER_E2E_ROOTFS").expect("HUSKER_E2E_ROOTFS");
    // Optional: kernels with a modular virtio-blk need the matching initramfs.
    let initrd_path = std::env::var("HUSKER_E2E_INITRD").ok().map(Into::into);
    // CID is configurable so concurrent runs / leftover VMs don't collide.
    let vsock_cid = std::env::var("HUSKER_E2E_CID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(42);
    let dir = tempfile::tempdir().unwrap();
    let backend = QemuKvmBackend::new("qemu-system-x86_64", dir.path());

    let config = husker_vmm::VmConfig {
        name: "e2e".into(),
        vcpu_count: 1,
        mem_size_mib: 512,
        kernel_path: kernel.into(),
        rootfs_path: rootfs.into(),
        kernel_args: Some("console=ttyS0".into()),
        initrd_path,
        vsock_cid,
        tap_device: None,
        guest_mac: None,
        vmm: None,
        boot: husker_vmm::BootMode::DirectKernel,
    };
    let info = backend.create_vm(config).await.expect("create_vm");

    // Poll for vsock connectivity with backoff rather than a fixed sleep so
    // fast guests are not penalised and the overall deadline is bounded.
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut backoff = std::time::Duration::from_millis(200);
    let mut connected = false;
    while tokio::time::Instant::now() < deadline {
        if let Ok(mut s) = backend.vsock_connect(info.id, 52).await {
            use husker_agent_proto::{AgentRequest, AgentResponse, read_message, write_message};
            if write_message(&mut s, &AgentRequest::Ping).await.is_ok() {
                let resp: Result<Option<AgentResponse>, _> = read_message(&mut s).await;
                if let Ok(Some(AgentResponse::Pong)) = resp {
                    connected = true;
                    break;
                }
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(std::time::Duration::from_secs(2));
    }
    // Always tear the VM down before asserting, so a failure does not leak it.
    backend.destroy_vm(info.id).await.unwrap();
    assert!(connected, "agent vsock unreachable on port 52");
}

/// A QEMU process that exits before opening its QMP socket must surface its
/// stderr (the boot log) in the create error, not just "QMP socket did not
/// appear". Driven deterministically by a stand-in binary that writes to
/// stderr and exits immediately, so the QMP socket never appears and the
/// boot-log tail is folded into the error. Uses the inherent `create` to skip
/// the /dev/kvm precheck, so it does not depend on real QEMU/KVM.
#[tokio::test]
#[ignore = "slow (~5s QMP wait); gated by HUSKER_RUN_IGNORED_E2E"]
async fn qemu_create_failure_surfaces_boot_log_tail() {
    if std::env::var("HUSKER_RUN_IGNORED_E2E").as_deref() != Ok("1") {
        eprintln!(
            "skipping qemu_create_failure_surfaces_boot_log_tail: set HUSKER_RUN_IGNORED_E2E=1"
        );
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let fake = dir.path().join("fake-qemu");
    std::fs::write(
        &fake,
        "#!/bin/sh\necho 'fake-qemu: simulated startup failure' >&2\nexit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

    let backend = QemuKvmBackend::new(&fake, dir.path());
    let config = husker_vmm::VmConfig {
        name: "e2e-broken".into(),
        vcpu_count: 1,
        mem_size_mib: 128,
        kernel_path: "/dev/null".into(),
        rootfs_path: "/dev/null".into(),
        kernel_args: Some("console=ttyS0".into()),
        initrd_path: None,
        vsock_cid: 99,
        tap_device: None,
        guest_mac: None,
        vmm: None,
        boot: husker_vmm::BootMode::DirectKernel,
    };
    let err = backend.create(config).await.expect_err("create must fail");
    let msg = err.to_string();
    eprintln!("create error:\n{msg}");
    assert!(
        msg.contains("qemu boot log (tail)"),
        "error should include the qemu boot-log tail, got: {msg}"
    );
    assert!(
        msg.contains("simulated startup failure"),
        "boot-log tail should carry the stand-in's stderr, got: {msg}"
    );
}
