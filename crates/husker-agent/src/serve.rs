//! Agent transport: accept connections on vsock (production guests) or a
//! Unix socket (`HUSKER_AGENT_SOCKET`, dev/testing) and serve each one.

use anyhow::{Context, Result};
use tracing::{error, info, warn};

/// Pause after an accept error other than "no connection pending", so a
/// connection accept cannot take does not turn the loop into a busy spin.
#[cfg(target_os = "macos")]
const ACCEPT_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

/// Run the agent service: normal mode, or the supervisor's restartable child.
/// Builds its own Tokio runtime (the supervisor itself stays a minimal sync
/// PID 1 with no async runtime).
pub fn run_agent() -> Result<()> {
    let runtime = tokio::runtime::Runtime::new().context("building Tokio runtime")?;
    runtime.block_on(serve())
}

/// Serve agent connections until a transport error, on the caller's runtime.
/// Hosts that already run Tokio (the `husker guest-agent` subcommand inside a
/// macOS guest) call this directly instead of [`run_agent`].
pub async fn serve() -> Result<()> {
    // cgroup v2 is Linux-only; a macOS guest has no /sys/fs/cgroup.
    #[cfg(target_os = "linux")]
    if let Err(e) = crate::configure_self_cgroup(
        std::path::Path::new("/sys/fs/cgroup"),
        crate::AGENT_MEMORY_HIGH_BYTES,
    ) {
        warn!("cgroup self-limit not applied: {e}");
    }

    // The limits are read once here and shared by every connection, so what
    // the agent enforces is fixed at startup and visible in its log.
    let limits = crate::AgentLimits::from_env();
    info!(
        "exec timeout {}s, max read {} bytes",
        limits.exec_timeout.as_secs(),
        limits.max_read_bytes
    );

    // Transport selection:
    // 1. HUSKER_AGENT_SOCKET env var -> Unix socket (dev/testing)
    // 2. otherwise vsock port 52 (production Linux and macOS guests)
    if let Ok(path) = std::env::var("HUSKER_AGENT_SOCKET") {
        listen_unix(&path, limits).await
    } else {
        listen_vsock(limits).await
    }
}

/// Serve one accepted connection with the process-wide session store.
fn serve_connection<S>(
    stream: S,
    limits: crate::AgentLimits,
    power: std::sync::Arc<dyn crate::PowerControl>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let sessions = crate::sessions::store().clone();
        if let Err(e) = crate::handle_connection_with(stream, sessions, limits, power).await {
            error!("connection error: {e}");
        }
    });
}

/// Serve on a Unix socket. The agent then runs on a host, not in a guest, so
/// a `Shutdown` is answered with a flush and never touches the machine's
/// storage or power.
async fn listen_unix(path: &str, limits: crate::AgentLimits) -> Result<()> {
    info!("listening on Unix socket: {path}");
    let listener = tokio::net::UnixListener::bind(path).context("binding Unix socket")?;
    let power: std::sync::Arc<dyn crate::PowerControl> = std::sync::Arc::new(crate::NoPowerControl);

    loop {
        let (stream, _) = listener.accept().await?;
        serve_connection(stream, limits, power.clone());
    }
}

/// Build an actionable error for a failed vsock bind. The common cause in a
/// custom guest rootfs is that the vsock kernel modules are not loaded, which
/// surfaces as `EAFNOSUPPORT`. Call that out explicitly so the serial console
/// shows the fix instead of an opaque "Address family not supported", which
/// otherwise just looks like a silent agent crash loop.
#[cfg(target_os = "linux")]
fn vsock_bind_error(port: u32, err: std::io::Error) -> anyhow::Error {
    if err.raw_os_error() == Some(libc::EAFNOSUPPORT) {
        anyhow::anyhow!(
            "failed to bind guest agent to vsock port {port}: AF_VSOCK is not supported \
             ({err}). The vsock kernel modules are not loaded; load vsock, \
             vmw_vsock_virtio_transport_common and vmw_vsock_virtio_transport in the guest \
             before starting the agent (see docs/custom-rootfs.md)."
        )
    } else {
        anyhow::anyhow!("failed to bind guest agent to vsock port {port}: {err}")
    }
}

#[cfg(target_os = "linux")]
async fn listen_vsock(limits: crate::AgentLimits) -> Result<()> {
    use tokio_vsock::VsockListener;

    let port = husker_agent_proto::AGENT_VSOCK_PORT;
    info!("listening on vsock port {port}");

    let addr = tokio_vsock::VsockAddr::new(libc::VMADDR_CID_ANY, port);
    let listener = VsockListener::bind(addr).map_err(|e| vsock_bind_error(port, e))?;
    // A vsock connection comes from the host of the VM this process runs in,
    // so this is the one place the kernel's power control is handed out.
    let power: std::sync::Arc<dyn crate::PowerControl> =
        std::sync::Arc::new(crate::power::KernelPowerControl);

    loop {
        let (stream, addr) = listener.accept().await?;
        info!("vsock connection from CID {}", addr.cid());
        serve_connection(stream, limits, power.clone());
    }
}

/// macOS guests have AF_VSOCK in the kernel but no Rust vsock crate supports
/// it, so the listener is built from raw sockets: bind/listen with libc, accept
/// readiness through Tokio's kqueue reactor, and hand each accepted stream to
/// the agent as a `UnixStream` (it only reads and writes, which is
/// family-agnostic for stream sockets).
#[cfg(target_os = "macos")]
async fn listen_vsock(limits: crate::AgentLimits) -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let port = husker_agent_proto::AGENT_VSOCK_PORT;
    // Safety: plain socket(2); the result is checked before use.
    let raw = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if raw < 0 {
        return Err(vsock_bind_error(port, std::io::Error::last_os_error()));
    }
    // Safety: `raw` is a freshly created, owned socket descriptor.
    let listener = unsafe { OwnedFd::from_raw_fd(raw) };
    configure_transport_fd(listener.as_raw_fd())?;
    let addr = vsock_any_addr(port);
    // Safety: `addr` is a valid sockaddr_vm and the length matches it.
    let bound = unsafe {
        libc::bind(
            listener.as_raw_fd(),
            (&raw const addr).cast(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        return Err(vsock_bind_error(port, std::io::Error::last_os_error()));
    }
    // Safety: listen(2) on a bound socket we own.
    if unsafe { libc::listen(listener.as_raw_fd(), 128) } < 0 {
        return Err(vsock_bind_error(port, std::io::Error::last_os_error()));
    }
    // Safety: the AsyncFd takes the listening OwnedFd and this loop only
    // accepts on it, so the fd stays open and refers to the same socket
    // until the AsyncFd is dropped.
    let listener = unsafe { tokio::io::unix::AsyncFd::register(listener) }
        .map_err(std::io::Error::from)
        .context("registering vsock listener")?;
    info!("listening on vsock port {port}");
    // A vsock connection comes from the host of the VM this process runs in,
    // so this is the one place the kernel's power control is handed out.
    let power: std::sync::Arc<dyn crate::PowerControl> =
        std::sync::Arc::new(crate::power::KernelPowerControl);

    loop {
        let mut ready = listener.readable().await?;
        // Safety: accept(2) on our listening socket; peer address not needed.
        let fd = unsafe {
            libc::accept(
                listener.get_ref().as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                ready.clear_ready();
                continue;
            }
            // A pending connection that accept cannot take (EMFILE, ENFILE)
            // is still queued. Readiness is kept rather than cleared: kqueue
            // reports it edge-triggered, so clearing it would leave queued
            // connections waiting for a new one. Back off, then retry.
            warn!("vsock accept failed: {err}");
            drop(ready);
            tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
            continue;
        }
        drop(ready);
        // Safety: `fd` is a freshly accepted, owned stream socket.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        if let Err(e) = configure_transport_fd(owned.as_raw_fd()) {
            warn!("vsock connection setup failed: {e}");
            continue;
        }
        let stream =
            match tokio::net::UnixStream::from_std(std::os::unix::net::UnixStream::from(owned)) {
                Ok(stream) => stream,
                Err(e) => {
                    warn!("vsock connection setup failed: {e}");
                    continue;
                }
            };
        info!("vsock connection accepted");
        serve_connection(stream, limits, power.clone());
    }
}

/// `sockaddr_vm` for `port` on any local CID.
#[cfg(target_os = "macos")]
fn vsock_any_addr(port: u32) -> libc::sockaddr_vm {
    // Safety: sockaddr_vm is plain old data; all-zero is a valid value.
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_len = std::mem::size_of::<libc::sockaddr_vm>() as u8;
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_port = port;
    addr.svm_cid = libc::VMADDR_CID_ANY;
    addr
}

/// Make a transport descriptor non-blocking (for tokio) and close-on-exec.
/// macOS has no `SOCK_CLOEXEC`, so without the latter every command the agent
/// runs would inherit the listener and live connections, and a surviving child
/// could keep the agent port bound after the agent itself restarts.
#[cfg(target_os = "macos")]
fn configure_transport_fd(fd: std::os::fd::RawFd) -> Result<()> {
    // Safety: fcntl(2) flag read/write on a descriptor the caller owns.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error()).context("setting O_NONBLOCK");
        }
        let fd_flags = libc::fcntl(fd, libc::F_GETFD);
        if fd_flags < 0 || libc::fcntl(fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) < 0 {
            return Err(std::io::Error::last_os_error()).context("setting FD_CLOEXEC");
        }
    }
    Ok(())
}

/// A macOS host (as opposed to a macOS guest) has no vsock transport and
/// reports `ENODEV`; say so instead of the opaque errno.
#[cfg(target_os = "macos")]
fn vsock_bind_error(port: u32, err: std::io::Error) -> anyhow::Error {
    if err.raw_os_error() == Some(libc::ENODEV) {
        anyhow::anyhow!(
            "failed to bind guest agent to vsock port {port}: no vsock device ({err}). \
             The agent is not running inside a virtual machine; set HUSKER_AGENT_SOCKET \
             to serve on a Unix socket instead."
        )
    } else {
        anyhow::anyhow!("failed to bind guest agent to vsock port {port}: {err}")
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn listen_vsock(_limits: crate::AgentLimits) -> Result<()> {
    anyhow::bail!("vsock is only available on Linux and macOS; set HUSKER_AGENT_SOCKET for dev use")
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn vsock_address_targets_any_cid_on_the_agent_port() {
        let addr = vsock_any_addr(52);
        assert_eq!(
            addr.svm_len as usize,
            std::mem::size_of::<libc::sockaddr_vm>()
        );
        assert_eq!(i32::from(addr.svm_family), libc::AF_VSOCK);
        assert_eq!({ addr.svm_port }, 52);
        assert_eq!({ addr.svm_cid }, u32::MAX);
    }

    #[test]
    fn transport_descriptors_are_not_inherited_by_commands() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let fd = a.as_raw_fd();
        // Safety: F_GETFD/F_GETFL reads on a descriptor this test owns.
        let cloexec = || unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC;
        let nonblock = || unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK;
        // Safety: clearing FD_CLOEXEC on our own descriptor, to model a raw
        // socket(2)/accept(2) result.
        unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
        assert_eq!(cloexec(), 0);

        configure_transport_fd(fd).unwrap();
        assert_ne!(cloexec(), 0, "FD_CLOEXEC set");
        assert_ne!(nonblock(), 0, "O_NONBLOCK set");

        let inherited = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("test -e /dev/fd/{fd}"))
            .status()
            .unwrap();
        assert!(!inherited.success(), "child process must not see fd {fd}");
    }

    #[test]
    fn a_host_without_vsock_gets_an_actionable_error() {
        let msg = format!(
            "{:#}",
            vsock_bind_error(52, std::io::Error::from_raw_os_error(libc::ENODEV))
        );
        assert!(msg.contains("HUSKER_AGENT_SOCKET"), "{msg}");
        let other = format!(
            "{:#}",
            vsock_bind_error(52, std::io::Error::from_raw_os_error(libc::EADDRINUSE))
        );
        assert!(!other.contains("HUSKER_AGENT_SOCKET"), "{other}");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn vsock_bind_error_explains_missing_modules() {
        let err = std::io::Error::from_raw_os_error(libc::EAFNOSUPPORT);
        let msg = format!("{:#}", vsock_bind_error(52, err));
        assert!(msg.contains("port 52"), "names the port: {msg}");
        assert!(
            msg.to_lowercase().contains("module"),
            "points at the kernel modules: {msg}"
        );
        assert!(msg.contains("vsock"), "names the vsock modules: {msg}");
    }

    #[test]
    fn vsock_bind_error_passes_through_unrelated_errors() {
        let err = std::io::Error::from_raw_os_error(libc::EADDRINUSE);
        let msg = format!("{:#}", vsock_bind_error(52, err));
        assert!(msg.contains("port 52"), "names the port: {msg}");
        assert!(
            !msg.to_lowercase().contains("module"),
            "no misleading module hint for unrelated errors: {msg}"
        );
    }
}
