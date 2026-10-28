//! Per-VM backend dispatcher for Linux: routes each VM to Firecracker or QEMU
//! by an in-memory `id -> VmmKind` map, exposing a unified `VmmBackend` so
//! `HuskerCore`/`husker-api` stay backend-agnostic.

use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::firecracker::FirecrackerBackend;
use crate::qemu::QemuKvmBackend;
use crate::{
    BackendKind, BackendRequirements, BackendSelection, BootKind, CreatedVm, RestoreTarget,
    SnapshotMeta, SnapshotPaths, VmConfig, VmInfo, VmmBackend, VmmError, VmmKind,
};

/// Unified vsock stream over the two backends' concrete stream types. Both
/// inner types are `Unpin`, so delegation needs no pin-projection.
pub enum LinuxVsockStream {
    Firecracker(tokio::net::UnixStream),
    Qemu(tokio_vsock::VsockStream),
}

impl AsyncRead for LinuxVsockStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            LinuxVsockStream::Firecracker(s) => Pin::new(s).poll_read(cx, buf),
            LinuxVsockStream::Qemu(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for LinuxVsockStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            LinuxVsockStream::Firecracker(s) => Pin::new(s).poll_write(cx, buf),
            LinuxVsockStream::Qemu(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            LinuxVsockStream::Firecracker(s) => Pin::new(s).poll_flush(cx),
            LinuxVsockStream::Qemu(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            LinuxVsockStream::Firecracker(s) => Pin::new(s).poll_shutdown(cx),
            LinuxVsockStream::Qemu(s) => Pin::new(s).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            LinuxVsockStream::Firecracker(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            LinuxVsockStream::Qemu(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            LinuxVsockStream::Firecracker(s) => s.is_write_vectored(),
            LinuxVsockStream::Qemu(s) => s.is_write_vectored(),
        }
    }
}

/// Routes each VM to the backend that created it.
pub struct LinuxDispatchBackend {
    firecracker: FirecrackerBackend,
    qemu: QemuKvmBackend,
    default_kind: VmmKind,
    routes: Mutex<HashMap<Uuid, VmmKind>>,
}

impl LinuxDispatchBackend {
    pub fn new(
        firecracker: FirecrackerBackend,
        qemu: QemuKvmBackend,
        default_kind: VmmKind,
    ) -> Self {
        Self {
            firecracker,
            qemu,
            default_kind,
            routes: Mutex::new(HashMap::new()),
        }
    }

    async fn kind_of(&self, id: Uuid) -> Result<VmmKind, VmmError> {
        self.routes
            .lock()
            .await
            .get(&id)
            .copied()
            .ok_or(VmmError::VmNotFound(id))
    }
}

/// Selects the VMM backend kind for a new VM.
///
/// UEFI boots require QEMU. For direct-kernel boots with host shares, QEMU is
/// selected when the caller did not pin a backend because Firecracker has no
/// virtiofs support. An explicit Firecracker request with shares is preserved
/// so its detailed unsupported-feature error remains reachable.
fn select_vmm_kind(
    requirements: BackendRequirements,
    default: VmmKind,
) -> Result<VmmKind, VmmError> {
    if requirements.boot == BootKind::Uefi {
        return match requirements.requested {
            None | Some(VmmKind::Qemu) => Ok(VmmKind::Qemu),
            Some(VmmKind::Firecracker) => Err(VmmError::InvalidConfig(
                "UEFI boot requires the QEMU backend".into(),
            )),
        };
    }
    if requirements.boot == BootKind::Efi {
        return Err(VmmError::InvalidConfig(
            "EFI boot is not supported by the Linux VMM dispatcher".into(),
        ));
    }
    if requirements.boot == BootKind::MacOs {
        return Err(VmmError::InvalidConfig(
            crate::MACOS_GUEST_UNSUPPORTED.into(),
        ));
    }
    if requirements.requested.is_none() && requirements.has_host_shares {
        Ok(VmmKind::Qemu)
    } else {
        Ok(requirements.requested.unwrap_or(default))
    }
}

impl VmmBackend for LinuxDispatchBackend {
    type VsockStream = LinuxVsockStream;

    /// The dispatch backend always has Firecracker available, so it advertises
    /// Firecracker's (capability-defining) kind regardless of `default_kind`.
    fn backend_kind(&self) -> &'static str {
        "firecracker"
    }

    fn select_backend(
        &self,
        requirements: BackendRequirements,
    ) -> Result<BackendSelection, VmmError> {
        let backend = select_vmm_kind(requirements, self.default_kind).map(BackendKind::from)?;
        Ok(BackendSelection::new(requirements, backend))
    }

    async fn create_vm(
        &self,
        selection: BackendSelection,
        mut config: VmConfig,
    ) -> Result<CreatedVm, VmmError> {
        selection.validate_config(&config)?;
        let kind = match selection.backend() {
            BackendKind::Firecracker => VmmKind::Firecracker,
            BackendKind::Qemu => VmmKind::Qemu,
            BackendKind::AppleVz => {
                return Err(VmmError::InvalidConfig(
                    "Apple VZ cannot be selected by the Linux VMM dispatcher".into(),
                ));
            }
        };
        // Route before entering the backend: a failed or cancelled creation can
        // retain a child that only a routed destroy or abort can reach.
        let id = crate::creation_id(&config)?;
        config.requested_id = Some(id);
        {
            let mut routes = self.routes.lock().await;
            if routes.contains_key(&id) {
                return Err(VmmError::InvalidConfig(
                    "requested VM UUID is already allocated".into(),
                ));
            }
            routes.insert(id, kind);
        }
        match kind {
            VmmKind::Firecracker => self.firecracker.create_vm(selection, config).await,
            VmmKind::Qemu => self.qemu.create_vm(selection, config).await,
        }
    }

    async fn stop_vm(&self, id: Uuid) -> Result<(), VmmError> {
        match self.kind_of(id).await? {
            VmmKind::Firecracker => self.firecracker.stop_vm(id).await,
            VmmKind::Qemu => self.qemu.stop_vm(id).await,
        }
    }

    async fn destroy_vm(&self, id: Uuid) -> Result<(), VmmError> {
        let kind = self.kind_of(id).await?;
        let result = match kind {
            VmmKind::Firecracker => self.firecracker.destroy_vm(id).await,
            VmmKind::Qemu => self.qemu.destroy_vm(id).await,
        };
        // A failed destroy keeps its owner in the backend, so the route stays
        // for the retry.
        if matches!(result, Ok(()) | Err(VmmError::VmNotFound(_))) {
            self.routes.lock().await.remove(&id);
        }
        result
    }

    async fn abort_create(&self, id: Uuid) -> Result<(), VmmError> {
        // Every creation is routed before it enters a backend, so an unrouted
        // UUID never reached one.
        let kind = match self.kind_of(id).await {
            Ok(kind) => kind,
            Err(VmmError::VmNotFound(_)) => return Ok(()),
            Err(error) => return Err(error),
        };
        match kind {
            VmmKind::Firecracker => self.firecracker.abort_create(id).await,
            VmmKind::Qemu => self.qemu.abort_create(id).await,
        }?;
        self.routes.lock().await.remove(&id);
        Ok(())
    }

    async fn vm_info(&self, id: Uuid) -> Result<VmInfo, VmmError> {
        match self.kind_of(id).await? {
            VmmKind::Firecracker => self.firecracker.vm_info(id).await,
            VmmKind::Qemu => self.qemu.vm_info(id).await,
        }
    }

    async fn pause_vm(&self, id: Uuid) -> Result<(), VmmError> {
        match self.kind_of(id).await? {
            VmmKind::Firecracker => self.firecracker.pause_vm(id).await,
            VmmKind::Qemu => self.qemu.pause_vm(id).await,
        }
    }

    async fn resume_vm(&self, id: Uuid) -> Result<(), VmmError> {
        match self.kind_of(id).await? {
            VmmKind::Firecracker => self.firecracker.resume_vm(id).await,
            VmmKind::Qemu => self.qemu.resume_vm(id).await,
        }
    }

    async fn snapshot_vm(&self, id: Uuid, dst: &SnapshotPaths) -> Result<SnapshotMeta, VmmError> {
        match self.kind_of(id).await? {
            VmmKind::Firecracker => self.firecracker.snapshot_vm(id, dst).await,
            VmmKind::Qemu => self.qemu.snapshot_vm(id, dst).await,
        }
    }

    async fn restore_vm(
        &self,
        src: &SnapshotPaths,
        target: RestoreTarget,
    ) -> Result<VmInfo, VmmError> {
        // A VM is restored after its route was cleared (on suspend), so there is
        // no route to look up. This layer owns backend selection for restores
        // (currently Firecracker) and routes the target before entering the
        // backend: a failed or cancelled restore can retain a child that only a
        // routed destroy can reach. A route left by a restore that retained
        // nothing is harmless, since destroying it reports VmNotFound and clears it.
        let id = match &target {
            RestoreTarget::Resume { id, .. } | RestoreTarget::Fork { id, .. } => *id,
        };
        {
            let mut routes = self.routes.lock().await;
            if routes
                .get(&id)
                .is_some_and(|kind| *kind != VmmKind::Firecracker)
            {
                return Err(VmmError::InvalidConfig(
                    "restore target UUID is routed to another backend".into(),
                ));
            }
            routes.insert(id, VmmKind::Firecracker);
        }
        self.firecracker.restore_vm(src, target).await
    }

    async fn vsock_connect(&self, id: Uuid, port: u32) -> Result<Self::VsockStream, VmmError> {
        match self.kind_of(id).await? {
            VmmKind::Firecracker => Ok(LinuxVsockStream::Firecracker(
                self.firecracker.vsock_connect(id, port).await?,
            )),
            VmmKind::Qemu => Ok(LinuxVsockStream::Qemu(
                self.qemu.vsock_connect(id, port).await?,
            )),
        }
    }

    async fn set_balloon(&self, id: Uuid, amount_mib: u32) -> Result<(), VmmError> {
        match self.kind_of(id).await? {
            VmmKind::Firecracker => self.firecracker.set_balloon(id, amount_mib).await,
            VmmKind::Qemu => self.qemu.set_balloon(id, amount_mib).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Compile-time proof the enum stream satisfies the trait's bound.
    fn _assert_stream_bounds<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>() {}
    #[test]
    fn linux_vsock_stream_satisfies_bounds() {
        _assert_stream_bounds::<LinuxVsockStream>();
    }

    // Delegation is exercised via the Firecracker variant over a real UnixStream
    // pair (tokio_vsock::VsockStream cannot be built from an in-memory duplex; its
    // delegation is identical and covered by the Linux/real-KVM e2e).
    #[tokio::test]
    async fn firecracker_variant_round_trips() {
        let (a, b) = tokio::net::UnixStream::pair().unwrap();
        let mut left = LinuxVsockStream::Firecracker(a);
        let mut right = LinuxVsockStream::Firecracker(b);
        left.write_all(b"ping").await.unwrap();
        left.flush().await.unwrap();
        let mut buf = [0u8; 4];
        right.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[test]
    fn auto_selects_qemu_for_shares_when_vmm_unset() {
        let direct = |requested, has_host_shares| BackendRequirements {
            requested,
            boot: BootKind::DirectKernel,
            has_host_shares,
        };
        assert_eq!(
            select_vmm_kind(direct(None, true), VmmKind::Firecracker).unwrap(),
            VmmKind::Qemu,
        );
        assert_eq!(
            select_vmm_kind(direct(None, false), VmmKind::Firecracker).unwrap(),
            VmmKind::Firecracker,
        );
        assert_eq!(
            select_vmm_kind(direct(Some(VmmKind::Firecracker), true), VmmKind::Qemu,).unwrap(),
            VmmKind::Firecracker,
        );
        assert_eq!(
            select_vmm_kind(direct(Some(VmmKind::Qemu), false), VmmKind::Firecracker,).unwrap(),
            VmmKind::Qemu,
        );
    }

    #[test]
    fn uefi_selection_is_qemu_only() {
        let requirements = |requested| BackendRequirements {
            requested,
            boot: BootKind::Uefi,
            has_host_shares: false,
        };
        assert_eq!(
            select_vmm_kind(requirements(None), VmmKind::Firecracker).unwrap(),
            VmmKind::Qemu,
        );
        assert!(
            select_vmm_kind(
                requirements(Some(VmmKind::Firecracker)),
                VmmKind::Firecracker,
            )
            .is_err()
        );
    }

    #[test]
    fn macos_guests_are_rejected_for_every_linux_backend() {
        for requested in [None, Some(VmmKind::Firecracker), Some(VmmKind::Qemu)] {
            let err = select_vmm_kind(
                BackendRequirements {
                    requested,
                    boot: BootKind::MacOs,
                    has_host_shares: false,
                },
                VmmKind::Firecracker,
            )
            .unwrap_err();
            assert!(err.to_string().contains("Apple Silicon"), "{err}");
        }
    }

    // An id not in the route map must return VmNotFound before touching any backend.
    #[tokio::test]
    async fn unknown_id_routes_to_not_found() {
        use crate::VmmBackend;
        let dir = tempfile::tempdir().unwrap();
        let cgroup = std::sync::Arc::new(crate::cgroup::CgroupSupervisor::disabled());
        let fc = crate::firecracker::FirecrackerBackend::new(
            "firecracker",
            dir.path(),
            std::sync::Arc::clone(&cgroup),
        );
        let qemu = crate::qemu::QemuKvmBackend::new("qemu-system-x86_64", dir.path(), cgroup);
        let be = LinuxDispatchBackend::new(fc, qemu, crate::VmmKind::Firecracker);
        let id = uuid::Uuid::new_v4();
        assert!(matches!(
            be.stop_vm(id).await,
            Err(crate::VmmError::VmNotFound(_))
        ));
        assert!(matches!(
            be.vm_info(id).await,
            Err(crate::VmmError::VmNotFound(_))
        ));
        assert!(matches!(
            be.destroy_vm(id).await,
            Err(crate::VmmError::VmNotFound(_))
        ));
        assert!(matches!(
            be.pause_vm(id).await,
            Err(crate::VmmError::VmNotFound(_))
        ));
        assert!(matches!(
            be.resume_vm(id).await,
            Err(crate::VmmError::VmNotFound(_))
        ));
        assert!(matches!(
            be.vsock_connect(id, 52).await,
            Err(crate::VmmError::VmNotFound(_))
        ));
        assert!(matches!(
            be.set_balloon(id, 64).await,
            Err(crate::VmmError::VmNotFound(_))
        ));
        let dst = crate::SnapshotPaths::in_dir(dir.path());
        assert!(matches!(
            be.snapshot_vm(id, &dst).await,
            Err(crate::VmmError::VmNotFound(_))
        ));
    }

    fn missing_binary_dispatcher(dir: &std::path::Path) -> LinuxDispatchBackend {
        let cgroup = std::sync::Arc::new(crate::cgroup::CgroupSupervisor::disabled());
        let fc = crate::firecracker::FirecrackerBackend::new(
            dir.join("missing-firecracker"),
            dir,
            std::sync::Arc::clone(&cgroup),
        );
        let qemu = crate::qemu::QemuKvmBackend::new(dir.join("missing-qemu"), dir, cgroup);
        LinuxDispatchBackend::new(fc, qemu, crate::VmmKind::Firecracker)
    }

    fn direct_config(id: Uuid) -> crate::VmConfig {
        crate::VmConfig {
            requested_id: Some(id),
            name: "routed".into(),
            vcpu_count: 1,
            mem_size_mib: 128,
            kernel_path: "/tmp/vmlinux".into(),
            rootfs_path: "/tmp/rootfs.ext4".into(),
            kernel_args: None,
            initrd_path: None,
            vsock_cid: 3,
            tap_device: None,
            guest_mac: None,
            vmm: None,
            boot: crate::BootMode::DirectKernel,
            seed_path: None,
            balloon: false,
            volume_path: None,
            network_disabled: false,
            host_shares: Vec::new(),
        }
    }

    // A failed create stays routed, so cleanup reaches the backend that ran
    // it; the abort clears the route only once the backend proves absence.
    #[tokio::test]
    async fn failed_create_stays_routed_until_aborted() {
        use crate::VmmBackend;
        let dir = tempfile::tempdir().unwrap();
        let be = missing_binary_dispatcher(dir.path());
        let id = Uuid::new_v4();
        let config = direct_config(id);
        let selection = be.select_backend_for_config(&config).unwrap();
        assert!(be.create_vm(selection, config).await.is_err());
        assert_eq!(be.kind_of(id).await.unwrap(), VmmKind::Firecracker);

        // The routed UUID cannot be claimed by a second creation.
        let config = direct_config(id);
        let selection = be.select_backend_for_config(&config).unwrap();
        let duplicate = be.create_vm(selection, config).await.unwrap_err();
        assert!(
            duplicate.to_string().contains("already allocated"),
            "{duplicate}"
        );

        be.abort_create(id).await.unwrap();
        assert!(matches!(
            be.kind_of(id).await,
            Err(crate::VmmError::VmNotFound(_))
        ));
        // An unrouted UUID never entered a backend.
        be.abort_create(id).await.unwrap();
    }

    // A failed restore stays routed so a routed destroy can reach any child it
    // retained; destroying one that retained nothing clears the route.
    #[tokio::test]
    async fn failed_restore_stays_routed_until_destroyed() {
        use crate::VmmBackend;
        let dir = tempfile::tempdir().unwrap();
        let be = missing_binary_dispatcher(dir.path());
        let id = Uuid::new_v4();
        let src = crate::SnapshotPaths::in_dir(dir.path());
        let target = crate::RestoreTarget::Resume {
            id,
            name: "restored".into(),
            vcpu_count: 1,
            mem_size_mib: 128,
            vsock_cid: 3,
        };
        assert!(be.restore_vm(&src, target).await.is_err());
        assert_eq!(be.kind_of(id).await.unwrap(), VmmKind::Firecracker);
        assert!(matches!(
            be.destroy_vm(id).await,
            Err(crate::VmmError::VmNotFound(_))
        ));
        assert!(matches!(
            be.kind_of(id).await,
            Err(crate::VmmError::VmNotFound(_))
        ));
    }
}
