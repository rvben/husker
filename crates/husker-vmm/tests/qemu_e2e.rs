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
    };
    let info = backend.create_vm(config).await.expect("create_vm");

    // Give the guest agent time to come up, then connect on port 52.
    tokio::time::sleep(std::time::Duration::from_secs(12)).await;
    let stream = backend.vsock_connect(info.id, 52).await;
    let connected = stream.is_ok();
    // Always tear the VM down before asserting, so a failure does not leak it.
    backend.destroy_vm(info.id).await.unwrap();
    assert!(connected, "agent vsock unreachable on port 52");
}
