//! Real-boot QEMU e2e. Requires a Linux host with `/dev/kvm`, `/dev/vhost-vsock`,
//! `qemu-system-x86_64`, and a kernel + rootfs whose guest runs the husker agent.
//! Run with:
//!   HUSKER_RUN_IGNORED_E2E=1 HUSKER_E2E_KERNEL=... HUSKER_E2E_ROOTFS=... \
//!   cargo nextest run -p husker-vmm --run-ignored all qemu_boots_and_vsock
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
    let dir = tempfile::tempdir().unwrap();
    let backend = QemuKvmBackend::new("qemu-system-x86_64", dir.path());

    let config = husker_vmm::VmConfig {
        name: "e2e".into(),
        vcpu_count: 1,
        mem_size_mib: 512,
        kernel_path: kernel.into(),
        rootfs_path: rootfs.into(),
        kernel_args: Some("console=ttyS0".into()),
        initrd_path: None,
        vsock_cid: 42,
        tap_device: None,
        guest_mac: None,
    };
    let info = backend.create_vm(config).await.expect("create_vm");

    // Give the guest agent time to come up, then connect on port 52.
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    let stream = backend.vsock_connect(info.id, 52).await;
    assert!(stream.is_ok(), "agent vsock unreachable: {:?}", stream.err());

    backend.destroy_vm(info.id).await.unwrap();
}
