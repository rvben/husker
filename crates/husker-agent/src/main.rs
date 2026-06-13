use anyhow::{Context, Result};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    info!("husker-agent starting");

    // Guest init/supervisor mode: when booted as PID 1 with the husker.init=1
    // marker (set by import-oci images), the agent performs minimal init -
    // mounts, networking, child reaping - before serving. Detection is wired
    // here; the init duties are added incrementally and are not yet set on any
    // image in production (imported images still boot the existing path).
    #[cfg(target_os = "linux")]
    {
        let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
        if husker_agent::is_supervisor_mode(std::process::id() == 1, &cmdline) {
            info!("husker-agent running as the guest init/supervisor (husker.init=1)");
            // A critical mount failing means a half-booted guest; reboot rather
            // than serve in a broken state. Best-effort mounts are skipped inside.
            if let Err(e) = husker_agent::supervisor::mount_all() {
                error!("fatal init failure: {e}; rebooting guest");
                husker_agent::supervisor::reboot_now();
            }
            husker_agent::supervisor::ensure_device_nodes();
        }
    }

    if let Err(e) = husker_agent::configure_self_cgroup(
        std::path::Path::new("/sys/fs/cgroup"),
        husker_agent::AGENT_MEMORY_HIGH_BYTES,
    ) {
        warn!("cgroup self-limit not applied: {e}");
    }

    // Transport selection:
    // 1. HUSKER_AGENT_SOCKET env var → Unix socket (dev/testing)
    // 2. Linux → vsock port 52 (production)
    // 3. macOS → default Unix socket fallback (dev)
    if let Ok(path) = std::env::var("HUSKER_AGENT_SOCKET") {
        listen_unix(&path).await
    } else if cfg!(target_os = "linux") {
        listen_vsock().await
    } else {
        let default_path = "/tmp/husker-agent.sock";
        let _ = std::fs::remove_file(default_path);
        listen_unix(default_path).await
    }
}

async fn listen_unix(path: &str) -> Result<()> {
    info!("listening on Unix socket: {path}");
    let listener = tokio::net::UnixListener::bind(path).context("binding Unix socket")?;

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = husker_agent::handle_connection(stream).await {
                error!("connection error: {e}");
            }
        });
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
async fn listen_vsock() -> Result<()> {
    use tokio_vsock::VsockListener;

    let port = husker_agent_proto::AGENT_VSOCK_PORT;
    info!("listening on vsock port {port}");

    let addr = tokio_vsock::VsockAddr::new(libc::VMADDR_CID_ANY, port);
    let mut listener = VsockListener::bind(addr).map_err(|e| vsock_bind_error(port, e))?;

    loop {
        let (stream, addr) = listener.accept().await?;
        info!("vsock connection from CID {}", addr.cid());
        tokio::spawn(async move {
            if let Err(e) = husker_agent::handle_connection(stream).await {
                error!("connection error: {e}");
            }
        });
    }
}

#[cfg(not(target_os = "linux"))]
async fn listen_vsock() -> Result<()> {
    anyhow::bail!("vsock is only available on Linux; set HUSKER_AGENT_SOCKET for dev use")
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
