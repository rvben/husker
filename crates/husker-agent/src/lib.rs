//! Guest-side agent handlers for exec, file transfer, and interactive shell services.

mod pty;

use std::os::fd::AsRawFd;
use std::path::Path;

use anyhow::Result;
use husker_agent_proto::{
    AgentRequest, AgentResponse, ErrorResponse, ExecResponse, GuestInfoResponse, ReadFileResponse,
    ShellDataResponse, ShellExitResponse, ShellStartRequest, WriteFileResponse, base64_decode,
    base64_encode, read_message, write_message,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::warn;

/// Handle a single connection, processing requests until the stream closes.
///
/// Generic over the stream type so it works with both Unix sockets (dev/test)
/// and vsock streams (production in-VM).
pub async fn handle_connection<S>(mut stream: S) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let request: Option<AgentRequest> = read_message(&mut stream).await?;
        let Some(request) = request else {
            return Ok(());
        };

        match request {
            AgentRequest::ShellStart(req) => {
                // Shell takes over the connection — no more request/response loop
                return handle_shell(&mut stream, req).await;
            }
            other => {
                let response = handle_request(other).await;
                write_message(&mut stream, &response).await?;
            }
        }
    }
}

async fn handle_shell<S>(stream: &mut S, req: ShellStartRequest) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let command = req.command.as_deref().unwrap_or("/bin/sh");

    let (mut master, slave) = match pty::Pty::open(req.cols, req.rows) {
        Ok(pair) => pair,
        Err(e) => {
            let resp = AgentResponse::Error(ErrorResponse {
                message: format!("failed to open PTY: {e}"),
            });
            write_message(stream, &resp).await?;
            return Ok(());
        }
    };

    let slave_raw = slave.as_raw_fd();
    let master_raw = master.as_raw_fd();

    let mut cmd = tokio::process::Command::new(command);
    cmd.envs(req.env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    cmd.stdin(std::process::Stdio::from(slave.try_clone()?));
    cmd.stdout(std::process::Stdio::from(slave.try_clone()?));
    cmd.stderr(std::process::Stdio::from(slave));

    // Safety: pre_exec runs after fork() but before exec() in the child.
    // setsid() creates a new session, TIOCSCTTY makes the PTY slave the
    // controlling terminal. slave_raw is valid because fds are inherited
    // across fork. We close master_raw so it doesn't leak into the child
    // (openpty doesn't set FD_CLOEXEC).
    unsafe {
        cmd.pre_exec(move || {
            libc::close(master_raw);
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(slave_raw, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            let resp = AgentResponse::Error(ErrorResponse {
                message: format!("failed to start shell: {e}"),
            });
            write_message(stream, &resp).await?;
            return Ok(());
        }
    };

    write_message(stream, &AgentResponse::ShellStarted).await?;

    let mut pty_buf = vec![0u8; 4096];

    loop {
        tokio::select! {
            result = master.read(&mut pty_buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        let data = base64_encode(&pty_buf[..n]);
                        write_message(stream, &AgentResponse::ShellData(ShellDataResponse { data })).await?;
                    }
                    Err(e) if e.raw_os_error() == Some(libc::EIO) => {
                        // EIO on PTY master means the slave side closed (child exited)
                        break;
                    }
                    Err(e) => {
                        warn!("PTY read error: {e}");
                        break;
                    }
                }
            }
            msg = read_message::<AgentRequest, _>(stream) => {
                match msg {
                    Ok(Some(AgentRequest::ShellData(req))) => {
                        if let Ok(data) = base64_decode(&req.data) {
                            let _ = master.write_all(&data).await;
                        }
                    }
                    Ok(Some(AgentRequest::ShellResize(req))) => {
                        if let Err(e) = master.resize(req.cols, req.rows) {
                            warn!("PTY resize failed: {e}");
                        }
                    }
                    Ok(None) | Err(_) => {
                        let _ = child.kill().await;
                        return Ok(());
                    }
                    Ok(Some(_)) => {}
                }
            }
            status = child.wait() => {
                let exit_code = status.map(|s| s.code().unwrap_or(-1)).unwrap_or(-1);
                // Drain remaining PTY output with a timeout to avoid blocking
                // if the master side has no pending data.
                let mut remaining = Vec::new();
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    master.read_to_end(&mut remaining),
                ).await;
                if !remaining.is_empty() {
                    let data = base64_encode(&remaining);
                    write_message(stream, &AgentResponse::ShellData(ShellDataResponse { data })).await?;
                }
                write_message(stream, &AgentResponse::ShellExit(ShellExitResponse { exit_code })).await?;
                return Ok(());
            }
        }
    }

    // PTY EOF — wait for the child to exit
    let exit_code = child
        .wait()
        .await
        .map(|s| s.code().unwrap_or(-1))
        .unwrap_or(-1);
    write_message(
        stream,
        &AgentResponse::ShellExit(ShellExitResponse { exit_code }),
    )
    .await?;
    Ok(())
}

/// Default ceiling on how long a single `Exec` command may run before the
/// agent kills the child and returns a timeout error. Overridable via the
/// `HUSKER_AGENT_EXEC_TIMEOUT_SECS` env var (primarily for tests).
const DEFAULT_EXEC_TIMEOUT_SECS: u64 = 600;

/// Default ceiling on bytes returned by a single `ReadFile` response. Keeps
/// the agent's peak memory bounded even when the host asks for a large file.
/// Overridable via `HUSKER_AGENT_MAX_READ_BYTES`.
const DEFAULT_MAX_READ_BYTES: u64 = 16 * 1024 * 1024;

/// Memory ceiling written to the agent's own cgroup leaf. `memory.high`
/// throttles and reclaims above this threshold without OOM-killing, so a
/// runaway exec buffer degrades gracefully instead of taking the agent down.
pub const AGENT_MEMORY_HIGH_BYTES: u64 = 128 * 1024 * 1024;

/// Places the calling process in a dedicated cgroup v2 leaf with a memory
/// throttle, so the agent can never starve the workload of guest memory.
/// `cgroup_root` is the mounted cgroup2 filesystem (normally /sys/fs/cgroup).
/// On hosts where the process already lives in a non-root cgroup managed by
/// another controller (for example systemd service cgroups), the cgroup.procs
/// write fails and the caller should treat the limit as best-effort.
pub fn configure_self_cgroup(cgroup_root: &Path, memory_high_bytes: u64) -> std::io::Result<()> {
    let leaf = cgroup_root.join("husker-agent");
    std::fs::create_dir_all(&leaf)?;
    std::fs::write(leaf.join("memory.high"), memory_high_bytes.to_string())?;
    std::fs::write(leaf.join("cgroup.procs"), std::process::id().to_string())?;
    Ok(())
}

fn exec_timeout() -> std::time::Duration {
    let secs = std::env::var("HUSKER_AGENT_EXEC_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_EXEC_TIMEOUT_SECS);
    std::time::Duration::from_secs(secs)
}

fn max_read_bytes() -> u64 {
    std::env::var("HUSKER_AGENT_MAX_READ_BYTES")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_MAX_READ_BYTES)
}

async fn handle_request(request: AgentRequest) -> AgentResponse {
    match request {
        AgentRequest::Ping => AgentResponse::Pong,

        AgentRequest::GuestInfo => match if_addrs::get_if_addrs() {
            Ok(addrs) => {
                let ipv4: Vec<String> = addrs
                    .into_iter()
                    .filter_map(|ifaddr| match ifaddr.addr {
                        if_addrs::IfAddr::V4(v4) if !v4.ip.is_loopback() => Some(v4.ip.to_string()),
                        _ => None,
                    })
                    .collect();
                AgentResponse::GuestInfo(GuestInfoResponse { ipv4 })
            }
            Err(e) => AgentResponse::Error(ErrorResponse {
                message: format!("get_if_addrs failed: {e}"),
            }),
        },

        AgentRequest::Exec(req) => {
            let timeout = exec_timeout();
            let fut = tokio::process::Command::new(&req.command)
                .args(&req.args)
                .envs(req.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                .current_dir(req.working_dir.as_deref().unwrap_or("/"))
                .kill_on_drop(true)
                .output();

            match tokio::time::timeout(timeout, fut).await {
                Ok(Ok(output)) => AgentResponse::Exec(ExecResponse {
                    exit_code: output.status.code().unwrap_or(-1),
                    stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                }),
                Ok(Err(e)) => AgentResponse::Error(ErrorResponse {
                    message: format!("exec failed: {e}"),
                }),
                Err(_) => AgentResponse::Error(ErrorResponse {
                    message: format!("exec timed out after {}s", timeout.as_secs()),
                }),
            }
        }

        AgentRequest::ReadFile(req) => {
            let open = tokio::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&req.path)
                .await;
            match open {
                Ok(file) => {
                    let max = max_read_bytes();
                    let mut limited = file.take(max + 1);
                    let mut data = Vec::new();
                    match limited.read_to_end(&mut data).await {
                        Ok(_) => {
                            if data.len() as u64 > max {
                                AgentResponse::Error(ErrorResponse {
                                    message: format!(
                                        "read failed: file exceeds max read size of {max} bytes"
                                    ),
                                })
                            } else {
                                let size = data.len() as u64;
                                let encoded = base64_encode(&data);
                                AgentResponse::ReadFile(ReadFileResponse {
                                    data: encoded,
                                    size,
                                })
                            }
                        }
                        Err(e) => AgentResponse::Error(ErrorResponse {
                            message: format!("read failed: {e}"),
                        }),
                    }
                }
                Err(e) => AgentResponse::Error(ErrorResponse {
                    message: format!("read failed: {e}"),
                }),
            }
        }

        AgentRequest::WriteFile(req) => {
            let data = match base64_decode(&req.data) {
                Ok(d) => d,
                Err(e) => {
                    return AgentResponse::Error(ErrorResponse {
                        message: format!("base64 decode failed: {e}"),
                    });
                }
            };
            let len = data.len() as u64;
            let open = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&req.path)
                .await;
            match open {
                Ok(mut file) => match file.write_all(&data).await {
                    Ok(()) => {
                        #[cfg(unix)]
                        if let Some(mode) = req.mode {
                            use std::os::unix::fs::PermissionsExt;
                            if let Err(e) = tokio::fs::set_permissions(
                                &req.path,
                                std::fs::Permissions::from_mode(mode),
                            )
                            .await
                            {
                                warn!("failed to set permissions on {}: {e}", req.path);
                            }
                        }
                        AgentResponse::WriteFile(WriteFileResponse { bytes_written: len })
                    }
                    Err(e) => AgentResponse::Error(ErrorResponse {
                        message: format!("write failed: {e}"),
                    }),
                },
                Err(e) => AgentResponse::Error(ErrorResponse {
                    message: format!("write failed: {e}"),
                }),
            }
        }

        // ShellStart is handled in handle_connection before reaching here.
        // ShellData and ShellResize are only valid during an active shell session.
        AgentRequest::ShellStart(_) | AgentRequest::ShellData(_) | AgentRequest::ShellResize(_) => {
            AgentResponse::Error(ErrorResponse {
                message: "shell messages are not valid outside a shell session".into(),
            })
        }
    }
}
