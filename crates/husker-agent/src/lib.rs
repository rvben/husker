//! Guest-side agent handlers for exec, file transfer, and interactive shell services.

mod pty;

/// Minimal `NETLINK_ROUTE` message encoding for `iproute2`-free static network
/// setup in the guest supervisor (a distroless rootfs has no `ip`/`busybox`).
#[cfg(target_os = "linux")]
mod netlink;

/// Guest init/supervisor duties (mounts, device nodes, networking, child
/// supervision) for booting arbitrary OCI rootfs images as PID 1.
#[cfg(target_os = "linux")]
pub mod supervisor;

use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::Result;
use husker_agent_proto::{
    AgentRequest, AgentResponse, ErrorResponse, ExecRequest, ExecResponse, GuestInfoResponse,
    OCI_CONFIG_PATH, OciRuntimeConfig, ReadFileResponse, ReconfigureNetworkRequest,
    ReconfigureNetworkResponse, ShellDataResponse, ShellExitResponse, ShellStartRequest,
    WriteFileResponse, base64_decode, base64_encode, read_message, write_message,
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
    // Apply the imported image's environment (PATH etc.) and working directory,
    // so an interactive shell into an OCI image behaves like exec (a bare
    // `python3` resolves). No-op on a non-OCI rootfs.
    let oci = oci_runtime_config();
    let (program, env, clear_env) = resolve_command_env(command, &req.env, oci);

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

    let mut cmd = tokio::process::Command::new(&program);
    if clear_env {
        cmd.env_clear();
    }
    cmd.envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    if let Some(wd) = oci.and_then(|c| c.working_dir.as_deref()) {
        cmd.current_dir(wd);
    }
    cmd.stdin(std::process::Stdio::from(slave.try_clone()?));
    cmd.stdout(std::process::Stdio::from(slave.try_clone()?));
    cmd.stderr(std::process::Stdio::from(slave));

    // Safety: pre_exec runs after fork() but before exec() in the child.
    // escape_agent_cgroup() moves the child to the root cgroup so it does
    // not inherit the agent's memory.high throttle.
    // setsid() creates a new session, TIOCSCTTY makes the PTY slave the
    // controlling terminal. slave_raw is valid because fds are inherited
    // across fork. We close master_raw so it doesn't leak into the child
    // (openpty doesn't set FD_CLOEXEC).
    unsafe {
        cmd.pre_exec(move || {
            escape_agent_cgroup();
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

/// Whether this process should run as the guest init/supervisor. It must be
/// PID 1 *and* the kernel cmdline must carry the explicit `husker.init=1`
/// marker, so the agent never assumes init duties merely because it happens to
/// be PID 1 (e.g. in a container, PID namespace, or test harness).
pub fn is_supervisor_mode(is_pid1: bool, kernel_cmdline: &str) -> bool {
    is_pid1
        && kernel_cmdline
            .split_whitespace()
            .any(|t| t == "husker.init=1")
}

/// Places the calling process in a dedicated cgroup v2 leaf with a memory
/// throttle, so the agent can never starve the workload of guest memory.
/// `cgroup_root` is the mounted cgroup2 filesystem (normally /sys/fs/cgroup).
/// On hosts where the process already lives in a non-root cgroup managed by
/// another controller (for example systemd service cgroups), the cgroup.procs
/// write fails and the caller should treat the limit as best-effort.
///
/// cgroup v2 requires the `memory` controller to be listed in the parent's
/// `cgroup.subtree_control` before a child cgroup exposes `memory.high`.
/// We enable it on the root cgroup first (idempotent: writing `+memory` when
/// it is already enabled is a no-op).
pub fn configure_self_cgroup(cgroup_root: &Path, memory_high_bytes: u64) -> std::io::Result<()> {
    std::fs::write(cgroup_root.join("cgroup.subtree_control"), "+memory")?;
    let leaf = cgroup_root.join("husker-agent");
    std::fs::create_dir_all(&leaf)?;
    std::fs::write(leaf.join("memory.high"), memory_high_bytes.to_string())?;
    std::fs::write(leaf.join("cgroup.procs"), std::process::id().to_string())?;
    Ok(())
}

/// Moves the calling process out of the agent's throttled cgroup leaf and
/// back to the root cgroup, so workload children never inherit the agent's
/// memory limit. Writing "0" to cgroup.procs moves the current process.
fn escape_agent_cgroup() {
    // /sys/fs/cgroup is the production guest mount point; the path is intentionally
    // hardcoded. This function is best-effort and is not unit-tested through an injected root.
    let _ = std::fs::write("/sys/fs/cgroup/cgroup.procs", "0");
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

/// Fallback `PATH` for imported images whose OCI config declares none, matching
/// common container-runtime behaviour so bare command names still resolve.
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// The imported OCI runtime config, loaded once from [`OCI_CONFIG_PATH`].
/// `None` when the rootfs is not an imported OCI image (e.g. the baseline
/// alpine rootfs), in which case exec keeps its inherited-environment behaviour.
fn oci_runtime_config() -> Option<&'static OciRuntimeConfig> {
    static CONFIG: OnceLock<Option<OciRuntimeConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let bytes = std::fs::read(OCI_CONFIG_PATH).ok()?;
            serde_json::from_slice(&bytes).ok()
        })
        .as_ref()
}

/// Insert or overwrite `key`'s value, preserving first-seen order.
fn upsert_env(env: &mut Vec<(String, String)>, key: &str, val: &str) {
    if let Some(slot) = env.iter_mut().find(|(k, _)| k == key) {
        slot.1 = val.to_string();
    } else {
        env.push((key.to_string(), val.to_string()));
    }
}

/// Merge the image's `Env` (`KEY=VALUE` strings) with per-request `env`
/// overrides. Request entries win per key; image order is preserved and new
/// request keys are appended. A `PATH` is always present (falling back to
/// [`DEFAULT_PATH`]) so program resolution has something to search.
fn merge_exec_env(image_env: &[String], req_env: &[(String, String)]) -> Vec<(String, String)> {
    let mut merged: Vec<(String, String)> = Vec::new();
    for entry in image_env {
        if let Some((k, v)) = entry.split_once('=') {
            upsert_env(&mut merged, k, v);
        }
    }
    for (k, v) in req_env {
        upsert_env(&mut merged, k, v);
    }
    if !merged.iter().any(|(k, _)| k == "PATH") {
        merged.push(("PATH".to_string(), DEFAULT_PATH.to_string()));
    }
    merged
}

/// The working directory for an exec: the request's, else the image's, else `/`.
fn resolve_working_dir(req_wd: Option<&str>, image_wd: Option<&str>) -> String {
    req_wd
        .filter(|s| !s.is_empty())
        .or_else(|| image_wd.filter(|s| !s.is_empty()))
        .unwrap_or("/")
        .to_string()
}

fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Resolve a bare command name against `path` to an absolute executable path, so
/// `python3` runs without the agent relying on its own process `PATH`. Commands
/// containing `/` are returned unchanged; an unresolved name is returned as-is
/// (and then fails as "not found", matching normal exec semantics).
fn resolve_program(command: &str, path: Option<&str>) -> String {
    if command.contains('/') {
        return command.to_string();
    }
    if let Some(path) = path {
        for dir in path.split(':').filter(|d| !d.is_empty()) {
            let candidate = Path::new(dir).join(command);
            if is_executable_file(&candidate) {
                return candidate.to_string_lossy().into_owned();
            }
        }
    }
    command.to_string()
}

/// The resolved program, environment, and working directory for an exec.
struct ExecPlan {
    program: String,
    env: Vec<(String, String)>,
    /// Whether to clear the inherited environment before applying `env`.
    /// True for OCI images (container semantics); false otherwise (legacy).
    clear_env: bool,
    current_dir: String,
}

/// Decide how to run an exec request. For an imported OCI image the command runs
/// with the image's environment + working directory (request env overriding,
/// bare programs resolved via the image `PATH`); otherwise the agent's inherited
/// environment is kept and only the request env is overlaid.
fn plan_exec(req: &ExecRequest, oci: Option<&OciRuntimeConfig>) -> ExecPlan {
    let (program, env, clear_env) = resolve_command_env(&req.command, &req.env, oci);
    let current_dir = resolve_working_dir(
        req.working_dir.as_deref(),
        oci.and_then(|c| c.working_dir.as_deref()),
    );
    ExecPlan {
        program,
        env,
        clear_env,
        current_dir,
    }
}

/// Resolve the program path, environment, and whether to clear inherited env for
/// running `command` with `req_env`. For an imported OCI image the command runs
/// with the image's environment (request env overriding, bare programs resolved
/// via the image `PATH`, inherited env cleared for container semantics);
/// otherwise the agent's inherited environment is kept and `req_env` overlaid.
/// Shared by `Exec` and `ShellStart`.
fn resolve_command_env(
    command: &str,
    req_env: &[(String, String)],
    oci: Option<&OciRuntimeConfig>,
) -> (String, Vec<(String, String)>, bool) {
    match oci {
        Some(cfg) => {
            let env = merge_exec_env(&cfg.env, req_env);
            let path = env
                .iter()
                .find(|(k, _)| k == "PATH")
                .map(|(_, v)| v.as_str());
            (resolve_program(command, path), env, true)
        }
        None => (command.to_string(), req_env.to_vec(), false),
    }
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
            let plan = plan_exec(&req, oci_runtime_config());
            let mut cmd = tokio::process::Command::new(&plan.program);
            cmd.args(&req.args)
                .current_dir(&plan.current_dir)
                .kill_on_drop(true);
            if plan.clear_env {
                cmd.env_clear();
            }
            cmd.envs(plan.env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
            // Safety: pre_exec runs after fork() but before exec() in the child.
            // escape_agent_cgroup() moves the child to the root cgroup so it does
            // not inherit the agent's memory.high throttle. The write is
            // best-effort: on hosts without /sys/fs/cgroup it fails silently.
            unsafe {
                cmd.pre_exec(|| {
                    escape_agent_cgroup();
                    Ok(())
                });
            }
            let fut = cmd.output();

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

        AgentRequest::ReconfigureNetwork(req) => match apply_network_reconfigure(&req).await {
            Ok(()) => AgentResponse::ReconfigureNetwork(ReconfigureNetworkResponse {
                interface: req.interface,
                ipv4: req.ipv4,
            }),
            Err(e) => AgentResponse::Error(ErrorResponse {
                message: format!("reconfigure-network failed: {e}"),
            }),
        },

        // ShellStart is handled in handle_connection before reaching here.
        // ShellData and ShellResize are only valid during an active shell session.
        AgentRequest::ShellStart(_) | AgentRequest::ShellData(_) | AgentRequest::ShellResize(_) => {
            AgentResponse::Error(ErrorResponse {
                message: "shell messages are not valid outside a shell session".into(),
            })
        }
    }
}

/// Build `/etc/resolv.conf` contents for `dns`, or `None` to leave it untouched
/// when no servers are supplied. Used by the Linux-only network reconfigure.
#[cfg(target_os = "linux")]
fn resolv_conf_contents(dns: &[String]) -> Option<String> {
    if dns.is_empty() {
        return None;
    }
    Some(dns.iter().map(|s| format!("nameserver {s}\n")).collect())
}

/// Parse a `AA:BB:CC:DD:EE:FF` MAC string into six bytes.
#[cfg(target_os = "linux")]
fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for slot in out.iter_mut() {
        let part = parts
            .next()
            .ok_or_else(|| format!("mac {s} has too few octets"))?;
        *slot = u8::from_str_radix(part, 16).map_err(|e| format!("mac {s}: {e}"))?;
    }
    if parts.next().is_some() {
        return Err(format!("mac {s} has too many octets"));
    }
    Ok(out)
}

/// Apply a new network identity to the live guest via netlink (no `ip`
/// dependency, so it works on a distroless guest after a snapshot restore or
/// fork), then rewrite `/etc/resolv.conf`. Guest-only (it mutates real
/// interfaces), so it is never exercised by host-side tests.
#[cfg(target_os = "linux")]
async fn apply_network_reconfigure(req: &ReconfigureNetworkRequest) -> Result<(), String> {
    let iface = req.interface.clone();
    let mac = match req.mac.as_deref() {
        Some(s) => Some(parse_mac(s)?),
        None => None,
    };
    let addr: std::net::Ipv4Addr = req
        .ipv4
        .parse()
        .map_err(|e| format!("invalid ipv4 {}: {e}", req.ipv4))?;
    let prefix = req.prefix_len;
    let gateway = if req.gateway.is_empty() {
        None
    } else {
        Some(
            req.gateway
                .parse::<std::net::Ipv4Addr>()
                .map_err(|e| format!("invalid gateway {}: {e}", req.gateway))?,
        )
    };
    // netlink syscalls are blocking; keep them off the async reactor.
    tokio::task::spawn_blocking(move || {
        crate::netlink::reconfigure(&iface, mac, addr, prefix, gateway)
    })
    .await
    .map_err(|e| format!("netlink task panicked: {e}"))?
    .map_err(|e| format!("netlink reconfigure: {e}"))?;
    if let Some(contents) = resolv_conf_contents(&req.dns) {
        tokio::fs::write("/etc/resolv.conf", contents)
            .await
            .map_err(|e| format!("write /etc/resolv.conf: {e}"))?;
    }
    Ok(())
}

/// Network reconfigure targets real guest interfaces via netlink, so it is only
/// available on Linux; the macOS dev build returns a clear error.
#[cfg(not(target_os = "linux"))]
async fn apply_network_reconfigure(req: &ReconfigureNetworkRequest) -> Result<(), String> {
    let _ = req;
    Err("network reconfigure is only supported on Linux guests".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oci_cfg(env: &[&str], working_dir: Option<&str>) -> OciRuntimeConfig {
        OciRuntimeConfig {
            env: env.iter().map(|s| s.to_string()).collect(),
            working_dir: working_dir.map(|s| s.to_string()),
            entrypoint: vec![],
            cmd: vec![],
        }
    }

    #[test]
    fn merge_exec_env_overrides_and_appends_and_defaults_path() {
        let image = [
            "PATH=/usr/local/bin:/usr/bin".to_string(),
            "LANG=C".to_string(),
        ];
        let req = [
            ("PATH".to_string(), "/opt/bin".to_string()), // request overrides image PATH
            ("EXTRA".to_string(), "1".to_string()),       // request-only key appended
        ];
        let merged = merge_exec_env(&image, &req);
        // Image key order preserved; PATH overridden in place; new key appended.
        assert_eq!(
            merged,
            vec![
                ("PATH".to_string(), "/opt/bin".to_string()),
                ("LANG".to_string(), "C".to_string()),
                ("EXTRA".to_string(), "1".to_string()),
            ]
        );

        // No PATH anywhere -> a default PATH is injected so bare names resolve.
        let merged = merge_exec_env(&["FOO=bar".to_string()], &[]);
        assert!(merged.iter().any(|(k, v)| k == "PATH" && v == DEFAULT_PATH));

        // Malformed image entries (no '=') are skipped, not panicked on.
        let merged = merge_exec_env(&["NOTANENTRY".to_string()], &[]);
        assert!(merged.iter().all(|(k, _)| k != "NOTANENTRY"));
    }

    #[test]
    fn resolve_working_dir_prefers_request_then_image_then_root() {
        assert_eq!(resolve_working_dir(Some("/req"), Some("/img")), "/req");
        assert_eq!(resolve_working_dir(None, Some("/img")), "/img");
        assert_eq!(resolve_working_dir(None, None), "/");
        // Empty strings are treated as unset.
        assert_eq!(resolve_working_dir(Some(""), Some("/img")), "/img");
        assert_eq!(resolve_working_dir(Some(""), Some("")), "/");
    }

    #[test]
    fn resolve_program_finds_executable_on_path() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("toolx");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let path = dir.path().to_string_lossy().into_owned();
        assert_eq!(resolve_program("toolx", Some(&path)), bin.to_string_lossy());
        // A path with a slash is returned unchanged (no PATH search).
        assert_eq!(resolve_program("/abs/python3", Some(&path)), "/abs/python3");
        // Unresolved bare name is returned as-is (exec then fails as not-found).
        assert_eq!(resolve_program("nope", Some(&path)), "nope");
        // A non-executable file is not matched.
        let noexec = dir.path().join("data");
        std::fs::write(&noexec, b"x").unwrap();
        assert_eq!(resolve_program("data", Some(&path)), "data");
    }

    #[test]
    fn plan_exec_oci_image_uses_image_env_and_workdir() {
        let cfg = oci_cfg(&["PATH=/usr/local/bin", "LANG=C"], Some("/app"));
        // Use an absolute command so resolve_program does not touch the FS.
        let req = ExecRequest {
            command: "/usr/local/bin/python3".into(),
            args: vec!["-V".into()],
            working_dir: None,
            env: vec![("LANG".into(), "en_US".into())],
        };
        let plan = plan_exec(&req, Some(&cfg));
        assert!(plan.clear_env, "OCI exec runs with container-clean env");
        assert_eq!(plan.program, "/usr/local/bin/python3");
        assert_eq!(plan.current_dir, "/app", "falls back to image WorkingDir");
        // Request env overrides the image's LANG; image PATH retained.
        assert!(plan.env.contains(&("PATH".into(), "/usr/local/bin".into())));
        assert!(plan.env.contains(&("LANG".into(), "en_US".into())));
    }

    #[test]
    fn plan_exec_non_oci_keeps_inherited_env() {
        let req = ExecRequest {
            command: "echo".into(),
            args: vec!["hi".into()],
            working_dir: Some("/tmp".into()),
            env: vec![("FOO".into(), "bar".into())],
        };
        let plan = plan_exec(&req, None);
        assert!(!plan.clear_env, "non-OCI exec inherits the agent env");
        assert_eq!(plan.program, "echo", "no PATH resolution without an image");
        assert_eq!(plan.current_dir, "/tmp");
        assert_eq!(plan.env, vec![("FOO".to_string(), "bar".to_string())]);
    }

    #[test]
    fn supervisor_mode_requires_pid1_and_marker() {
        // PID 1 with the explicit marker -> supervisor.
        assert!(is_supervisor_mode(
            true,
            "ro init=/usr/local/bin/husker-agent husker.init=1"
        ));
        // PID 1 without the marker -> not supervisor (avoid accidental init).
        assert!(!is_supervisor_mode(true, "ro console=ttyS0 quiet"));
        // The marker without being PID 1 -> not supervisor.
        assert!(!is_supervisor_mode(false, "husker.init=1"));
        // A substring must not match a whole token.
        assert!(!is_supervisor_mode(true, "husker.init=10"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_mac_parses_and_rejects_malformed() {
        assert_eq!(
            parse_mac("AA:FC:00:00:00:09").unwrap(),
            [0xAA, 0xFC, 0x00, 0x00, 0x00, 0x09]
        );
        assert!(parse_mac("AA:FC:00:00:00").is_err(), "too few octets");
        assert!(
            parse_mac("AA:FC:00:00:00:09:11").is_err(),
            "too many octets"
        );
        assert!(parse_mac("ZZ:FC:00:00:00:09").is_err(), "non-hex");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolv_conf_contents_one_line_per_server_or_none() {
        assert_eq!(resolv_conf_contents(&[]), None);
        assert_eq!(
            resolv_conf_contents(&["192.0.2.1".into(), "1.1.1.1".into()]),
            Some("nameserver 192.0.2.1\nnameserver 1.1.1.1\n".to_string())
        );
    }
}
