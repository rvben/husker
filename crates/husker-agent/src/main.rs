use anyhow::{Context, Result};
use tracing::{error, info, warn};

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    info!("husker-agent starting");

    // Guest init/supervisor mode: when booted as PID 1 with the husker.init=1
    // marker (set by import-oci images), the agent becomes a minimal init - it
    // performs mounts/network/device setup and then supervises itself as a
    // restartable child, never returning. Otherwise (normal agent, or the
    // supervisor's own child) it serves requests. No image sets husker.init=1
    // until the import-oci boot_init flip, so production boot is unchanged.
    #[cfg(target_os = "linux")]
    {
        let is_pid1 = std::process::id() == 1;
        // As PID 1 nothing is mounted yet, so /proc/cmdline is unreadable until we
        // mount /proc. Do it first (idempotent with the supervisor's own mounts)
        // so supervisor mode can actually be detected.
        if is_pid1 {
            husker_agent::supervisor::mount_proc();
        }
        let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
        if husker_agent::is_supervisor_mode(is_pid1, &cmdline) {
            husker_agent::supervisor::run(&cmdline);
        }
    }

    run_agent()
}

/// Run the agent service: normal mode, or the supervisor's restartable child.
/// Builds its own Tokio runtime (the supervisor itself stays a minimal sync
/// PID 1 with no async runtime).
fn run_agent() -> Result<()> {
    let runtime = tokio::runtime::Runtime::new().context("building Tokio runtime")?;
    runtime.block_on(async {
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
    })
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
