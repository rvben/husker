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
    RestoreTarget, SnapshotMeta, SnapshotPaths, VmConfig, VmInfo, VmmBackend, VmmError, VmmKind,
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

impl VmmBackend for LinuxDispatchBackend {
    type VsockStream = LinuxVsockStream;

    /// The dispatch backend always has Firecracker available, so it advertises
    /// Firecracker's (capability-defining) kind regardless of `default_kind`.
    fn backend_kind(&self) -> &'static str {
        "firecracker"
    }

    async fn create_vm(&self, config: VmConfig) -> Result<VmInfo, VmmError> {
        let kind = config.vmm.unwrap_or(self.default_kind);
        let info = match kind {
            VmmKind::Firecracker => self.firecracker.create_vm(config).await?,
            VmmKind::Qemu => self.qemu.create_vm(config).await?,
        };
        self.routes.lock().await.insert(info.id, kind);
        Ok(info)
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
        // Remove the route unconditionally: if the backend destroy fails, a retry
        // should still clean up state (core handles VmNotFound as "clean state only").
        self.routes.lock().await.remove(&id);
        result
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
        // restore_vm deliberately does NOT consult the route map: a VM is restored
        // after its route was cleared (on suspend), so there is nothing to look up.
        // This layer owns backend selection for restores (currently Firecracker) and
        // (re-)registers the route after a successful restore.
        let info = self.firecracker.restore_vm(src, target).await?;
        self.routes
            .lock()
            .await
            .insert(info.id, VmmKind::Firecracker);
        Ok(info)
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

    // An id not in the route map must return VmNotFound before touching any backend.
    #[tokio::test]
    async fn unknown_id_routes_to_not_found() {
        use crate::VmmBackend;
        let dir = tempfile::tempdir().unwrap();
        let fc = crate::firecracker::FirecrackerBackend::new("firecracker", dir.path());
        let qemu = crate::qemu::QemuKvmBackend::new("qemu-system-x86_64", dir.path());
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
}
