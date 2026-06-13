use std::path::Path;
use std::time::Duration;

use husker_agent_proto::{
    AgentRequest, AgentResponse, ExecRequest, ReadFileRequest, ReconfigureNetworkRequest,
    ShellDataRequest, ShellResizeRequest, ShellStartRequest, WriteFileRequest, base64_decode,
    base64_encode, read_message, write_message,
};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("connection failed: {0}")]
    Connection(std::io::Error),
    #[error("vsock CONNECT rejected by Firecracker (port {0})")]
    VsockConnectRejected(u32),
    #[error("protocol error: {0}")]
    Protocol(#[from] husker_agent_proto::ProtocolError),
    #[error("unexpected response from agent")]
    UnexpectedResponse,
    #[error("agent returned error: {0}")]
    Agent(String),
    #[error("agent not ready after {0:?}")]
    NotReady(Duration),
}

/// Factory for creating agent connections.
pub struct AgentClient;

impl AgentClient {
    /// Connect to the agent via Firecracker's vsock UDS proxy.
    ///
    /// Firecracker exposes guest vsock as a Unix domain socket. To connect to a
    /// specific guest port, the host must:
    /// 1. Connect to the UDS at `vsock_uds_path`
    /// 2. Send `CONNECT {port}\n`
    /// 3. Read the response — `OK {local_port}\n` on success
    ///
    /// After the handshake, the stream is transparently bridged to the guest.
    pub async fn connect(
        vsock_uds_path: &Path,
        port: u32,
    ) -> Result<AgentConnection<tokio::net::UnixStream>, AgentError> {
        let stream = husker_vmm::vsock::connect_firecracker_vsock(vsock_uds_path, port)
            .await
            .map_err(|e| match e {
                husker_vmm::vsock::VsockConnectError::Rejected(port) => {
                    AgentError::VsockConnectRejected(port)
                }
                husker_vmm::vsock::VsockConnectError::Connect(e)
                | husker_vmm::vsock::VsockConnectError::HandshakeWrite(e)
                | husker_vmm::vsock::VsockConnectError::HandshakeRead(e) => {
                    AgentError::Connection(e)
                }
            })?;
        Ok(AgentConnection { stream })
    }

    /// Connect to the agent via a Unix socket path directly.
    pub async fn connect_unix(
        path: &Path,
    ) -> Result<AgentConnection<tokio::net::UnixStream>, AgentError> {
        let stream = tokio::net::UnixStream::connect(path)
            .await
            .map_err(AgentError::Connection)?;
        Ok(AgentConnection { stream })
    }

    /// Wait for the agent to become ready, retrying ping with backoff.
    pub async fn wait_ready(
        vsock_uds_path: &Path,
        port: u32,
        timeout: Duration,
    ) -> Result<AgentConnection<tokio::net::UnixStream>, AgentError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut interval = Duration::from_millis(100);

        loop {
            match Self::connect(vsock_uds_path, port).await {
                Ok(mut conn) => match conn.ping().await {
                    Ok(()) => return Ok(conn),
                    Err(_) if tokio::time::Instant::now() < deadline => {}
                    Err(e) => return Err(e),
                },
                Err(_) if tokio::time::Instant::now() < deadline => {}
                Err(e) => return Err(e),
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(AgentError::NotReady(timeout));
            }

            tokio::time::sleep(interval).await;
            interval = (interval * 2).min(Duration::from_secs(2));
        }
    }
}

/// A typed connection to a guest agent.
pub struct AgentConnection<S> {
    stream: S,
}

impl<S> AgentConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Wrap an existing stream as an agent connection.
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Check if the agent is alive.
    pub async fn ping(&mut self) -> Result<(), AgentError> {
        write_message(&mut self.stream, &AgentRequest::Ping).await?;
        let response: AgentResponse = read_message(&mut self.stream)
            .await?
            .ok_or(AgentError::UnexpectedResponse)?;
        match response {
            AgentResponse::Pong => Ok(()),
            AgentResponse::Error(e) => Err(AgentError::Agent(e.message)),
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Query the guest's network addresses.
    pub async fn guest_info(
        &mut self,
    ) -> Result<husker_agent_proto::GuestInfoResponse, AgentError> {
        write_message(&mut self.stream, &AgentRequest::GuestInfo).await?;
        let response: AgentResponse = read_message(&mut self.stream)
            .await?
            .ok_or(AgentError::UnexpectedResponse)?;
        match response {
            AgentResponse::GuestInfo(info) => Ok(info),
            AgentResponse::Error(e) => Err(AgentError::Agent(e.message)),
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Reconfigure the guest's primary interface in place: apply a new IPv4
    /// address, gateway, optional MAC, and DNS without rebooting. Used after a
    /// fork restore re-homes the guest onto a fresh host identity.
    pub async fn reconfigure_network(
        &mut self,
        interface: &str,
        ipv4: &str,
        prefix_len: u8,
        gateway: &str,
        mac: Option<&str>,
        dns: &[String],
    ) -> Result<(), AgentError> {
        let request = AgentRequest::ReconfigureNetwork(ReconfigureNetworkRequest {
            interface: interface.into(),
            ipv4: ipv4.into(),
            prefix_len,
            gateway: gateway.into(),
            mac: mac.map(Into::into),
            dns: dns.to_vec(),
        });
        write_message(&mut self.stream, &request).await?;
        let response: AgentResponse = read_message(&mut self.stream)
            .await?
            .ok_or(AgentError::UnexpectedResponse)?;
        match response {
            AgentResponse::ReconfigureNetwork(_) => Ok(()),
            AgentResponse::Error(e) => Err(AgentError::Agent(e.message)),
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Execute a command inside the VM.
    pub async fn exec(
        &mut self,
        command: &str,
        args: &[&str],
        working_dir: Option<&str>,
        env: &[(&str, &str)],
    ) -> Result<ExecResult, AgentError> {
        let request = AgentRequest::Exec(ExecRequest {
            command: command.into(),
            args: args.iter().map(|s| (*s).into()).collect(),
            working_dir: working_dir.map(Into::into),
            env: env
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
        });
        write_message(&mut self.stream, &request).await?;

        let response: AgentResponse = read_message(&mut self.stream)
            .await?
            .ok_or(AgentError::UnexpectedResponse)?;
        match response {
            AgentResponse::Exec(r) => Ok(ExecResult {
                exit_code: r.exit_code,
                stdout: r.stdout,
                stderr: r.stderr,
            }),
            AgentResponse::Error(e) => Err(AgentError::Agent(e.message)),
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Read a file from the guest filesystem.
    pub async fn read_file(&mut self, path: &str) -> Result<Vec<u8>, AgentError> {
        let request = AgentRequest::ReadFile(ReadFileRequest { path: path.into() });
        write_message(&mut self.stream, &request).await?;

        let response: AgentResponse = read_message(&mut self.stream)
            .await?
            .ok_or(AgentError::UnexpectedResponse)?;
        match response {
            AgentResponse::ReadFile(r) => base64_decode(&r.data)
                .map_err(|e| AgentError::Agent(format!("base64 decode failed: {e}"))),
            AgentResponse::Error(e) => Err(AgentError::Agent(e.message)),
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Write a file to the guest filesystem.
    pub async fn write_file(
        &mut self,
        path: &str,
        data: &[u8],
        mode: Option<u32>,
    ) -> Result<u64, AgentError> {
        let request = AgentRequest::WriteFile(WriteFileRequest {
            path: path.into(),
            data: base64_encode(data),
            mode,
        });
        write_message(&mut self.stream, &request).await?;

        let response: AgentResponse = read_message(&mut self.stream)
            .await?
            .ok_or(AgentError::UnexpectedResponse)?;
        match response {
            AgentResponse::WriteFile(r) => Ok(r.bytes_written),
            AgentResponse::Error(e) => Err(AgentError::Agent(e.message)),
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Start an interactive shell session.
    ///
    /// After calling this, use `shell_send`, `shell_recv`, and `shell_resize`
    /// to interact with the shell. The connection is no longer usable for
    /// regular requests after starting a shell.
    pub async fn shell_start(
        &mut self,
        command: Option<&str>,
        cols: u16,
        rows: u16,
    ) -> Result<(), AgentError> {
        let request = AgentRequest::ShellStart(ShellStartRequest {
            command: command.map(Into::into),
            env: vec![("TERM".into(), "xterm".into())],
            cols,
            rows,
        });
        write_message(&mut self.stream, &request).await?;
        let response: AgentResponse = read_message(&mut self.stream)
            .await?
            .ok_or(AgentError::UnexpectedResponse)?;
        match response {
            AgentResponse::ShellStarted => Ok(()),
            AgentResponse::Error(e) => Err(AgentError::Agent(e.message)),
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Send stdin data to the shell.
    pub async fn shell_send(&mut self, data: &[u8]) -> Result<(), AgentError> {
        let request = AgentRequest::ShellData(ShellDataRequest {
            data: base64_encode(data),
        });
        write_message(&mut self.stream, &request).await?;
        Ok(())
    }

    /// Receive output or exit event from the shell.
    pub async fn shell_recv(&mut self) -> Result<ShellEvent, AgentError> {
        let response: AgentResponse = read_message(&mut self.stream)
            .await?
            .ok_or(AgentError::UnexpectedResponse)?;
        match response {
            AgentResponse::ShellData(r) => {
                let data = base64_decode(&r.data)
                    .map_err(|e| AgentError::Agent(format!("base64 decode failed: {e}")))?;
                Ok(ShellEvent::Data(data))
            }
            AgentResponse::ShellExit(r) => Ok(ShellEvent::Exit(r.exit_code)),
            AgentResponse::Error(e) => Err(AgentError::Agent(e.message)),
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Resize the shell terminal.
    pub async fn shell_resize(&mut self, cols: u16, rows: u16) -> Result<(), AgentError> {
        let request = AgentRequest::ShellResize(ShellResizeRequest { cols, rows });
        write_message(&mut self.stream, &request).await?;
        Ok(())
    }
}

/// Result of executing a command inside a VM.
#[derive(Debug)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Events received during a shell session.
#[derive(Debug)]
pub enum ShellEvent {
    /// Output data from the shell.
    Data(Vec<u8>),
    /// Shell process exited.
    Exit(i32),
}
