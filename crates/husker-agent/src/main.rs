use anyhow::{Context, Result};
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    info!("husker-agent starting");

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

#[cfg(target_os = "linux")]
async fn listen_vsock() -> Result<()> {
    use tokio_vsock::VsockListener;

    let port = husker_agent_proto::AGENT_VSOCK_PORT;
    info!("listening on vsock port {port}");

    let addr = tokio_vsock::VsockAddr::new(libc::VMADDR_CID_ANY, port);
    let mut listener = VsockListener::bind(addr).context("binding vsock listener")?;

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
