//! Shared host/guest protocol messages and framing helpers for husker agent communication.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Messages sent from the host to the guest agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AgentRequest {
    /// Execute a command inside the VM.
    Exec(ExecRequest),

    /// Read a file from the guest filesystem.
    ReadFile(ReadFileRequest),

    /// Write a file to the guest filesystem.
    WriteFile(WriteFileRequest),

    /// Check if the agent is alive.
    Ping,

    /// Report guest network info (non-loopback IPv4 addresses).
    GuestInfo,

    /// Start an interactive shell session.
    ShellStart(ShellStartRequest),

    /// Send stdin data to the shell.
    ShellData(ShellDataRequest),

    /// Resize the shell terminal.
    ShellResize(ShellResizeRequest),

    /// Reconfigure the guest's primary network interface in place, without
    /// rebooting. Sent after a snapshot restore or fork gives the VM a new
    /// host-side identity (TAP/IP), so the live guest picks up the new address,
    /// gateway, and DNS.
    ReconfigureNetwork(ReconfigureNetworkRequest),

    /// Flush all dirty pages to disk and unmount the data volume, then signal
    /// readiness to be destroyed. Sent by the host as the first step of
    /// `destroy_vm` so that writes to a named volume (`--volume`) are durable
    /// even when the guest process is killed immediately after.
    Shutdown,
}

/// Messages sent from the guest agent back to the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AgentResponse {
    /// Result of a command execution.
    Exec(ExecResponse),

    /// Contents of a file read from the guest.
    ReadFile(ReadFileResponse),

    /// Acknowledgement of a file write.
    WriteFile(WriteFileResponse),

    /// Response to a ping.
    Pong,

    /// An error occurred processing the request.
    Error(ErrorResponse),

    /// Guest network information.
    GuestInfo(GuestInfoResponse),

    /// Shell session started successfully.
    ShellStarted,

    /// Output data from the shell.
    ShellData(ShellDataResponse),

    /// Shell process exited.
    ShellExit(ShellExitResponse),

    /// Acknowledgement that the guest network was reconfigured.
    ReconfigureNetwork(ReconfigureNetworkResponse),

    /// Acknowledgement that the guest has synced dirty pages and unmounted the
    /// data volume; the host may now kill the VM process.
    ShuttingDown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    /// The program to run. An empty string means "use the imported OCI image's
    /// default" ([`OciRuntimeConfig::argv`] = Entrypoint + Cmd), like
    /// `docker run <image>` with no command; the agent errors if there is no
    /// OCI config or it declares no default.
    pub command: String,
    pub args: Vec<String>,
    pub working_dir: Option<String>,
    pub env: Vec<(String, String)>,
    /// Max seconds the command may run before the agent kills it and returns the
    /// partial output (with exit code 124). `None` uses the agent default.
    /// `#[serde(default)]` so an older agent tolerates the field and a newer one
    /// tolerates its absence.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// Canonical in-guest path of the imported OCI runtime config. `import-oci`
/// writes [`OciRuntimeConfig`] here inside the rootfs; the guest agent reads it
/// to apply the image's environment and working directory when exec'ing.
pub const OCI_CONFIG_PATH: &str = "/etc/husker/oci-config.json";

/// Runtime configuration captured from an imported OCI/Docker image and written
/// into its rootfs at [`OCI_CONFIG_PATH`]. The guest agent applies it so that
/// commands run with the image's `PATH`/environment and working directory,
/// matching container semantics (a bare `python3` resolves, `$PWD` is the
/// image's `WorkingDir`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciRuntimeConfig {
    /// `Env` entries as `KEY=VALUE` strings (e.g. `PATH=/usr/local/bin:...`).
    #[serde(default)]
    pub env: Vec<String>,
    /// `WorkingDir`, if the image set one.
    #[serde(default)]
    pub working_dir: Option<String>,
    /// `Entrypoint` from the image (default command prefix).
    #[serde(default)]
    pub entrypoint: Vec<String>,
    /// `Cmd` from the image (default command / args).
    #[serde(default)]
    pub cmd: Vec<String>,
}

impl OciRuntimeConfig {
    /// The image's default argv: `Entrypoint` followed by `Cmd`. Used when an
    /// exec request carries no command (run the image's default, like
    /// `docker run <image>`). Empty when the image declares neither.
    pub fn argv(&self) -> Vec<String> {
        let mut argv = self.entrypoint.clone();
        argv.extend(self.cmd.iter().cloned());
        argv
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadFileRequest {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadFileResponse {
    /// Base64-encoded file contents.
    pub data: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteFileRequest {
    pub path: String,
    /// Base64-encoded file contents.
    pub data: String,
    pub mode: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteFileResponse {
    pub bytes_written: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub message: String,
}

/// Guest network information reported by the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestInfoResponse {
    /// Non-loopback IPv4 addresses, primary first.
    pub ipv4: Vec<String>,
}

/// New network identity to apply to a guest interface after restore/fork.
///
/// A forked VM shares its source's snapshot, so it boots with the source's MAC
/// and IP. husker puts every guest on one shared L2 bridge, and Firecracker's
/// snapshot `network_overrides` only rebinds the host TAP (not the guest MAC),
/// so the guest itself must take a fresh MAC and IP to avoid colliding with the
/// source on the bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconfigureNetworkRequest {
    /// Interface to reconfigure (e.g. `"eth0"`).
    pub interface: String,
    /// New IPv4 address (dotted quad, no prefix).
    pub ipv4: String,
    /// Prefix length for the address (e.g. `24`).
    pub prefix_len: u8,
    /// Default gateway IPv4 address.
    pub gateway: String,
    /// New link-layer (MAC) address. `None` leaves the current MAC unchanged
    /// (e.g. a plain restore that keeps the source's identity).
    #[serde(default)]
    pub mac: Option<String>,
    /// DNS servers to write to `/etc/resolv.conf`. Empty leaves it unchanged.
    pub dns: Vec<String>,
}

/// Result of applying a [`ReconfigureNetworkRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconfigureNetworkResponse {
    /// The interface that was reconfigured.
    pub interface: String,
    /// The IPv4 address now assigned to it.
    pub ipv4: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellStartRequest {
    /// Shell command to run (default: /bin/sh if None).
    pub command: Option<String>,
    pub env: Vec<(String, String)>,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellDataRequest {
    /// Base64-encoded stdin data.
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellResizeRequest {
    pub cols: u16,
    pub rows: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellDataResponse {
    /// Base64-encoded stdout/stderr data.
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellExitResponse {
    pub exit_code: i32,
}

/// Encode a message as a length-prefixed JSON frame.
///
/// Wire format: 4-byte big-endian length prefix followed by JSON bytes.
pub fn encode_message<T: Serialize>(msg: &T) -> Result<Vec<u8>, ProtocolError> {
    let json = serde_json::to_vec(msg)?;
    if json.len() > MAX_MESSAGE_SIZE {
        return Err(ProtocolError::MessageTooLarge { size: json.len() });
    }
    let len = (json.len() as u32).to_be_bytes();
    let mut buf = Vec::with_capacity(4 + json.len());
    buf.extend_from_slice(&len);
    buf.extend_from_slice(&json);
    Ok(buf)
}

/// Decode a length-prefixed JSON frame from a byte buffer.
///
/// Returns the decoded message and the number of bytes consumed,
/// or `None` if the buffer doesn't contain a complete frame.
pub fn decode_message<T: for<'de> Deserialize<'de>>(
    buf: &[u8],
) -> Result<Option<(T, usize)>, ProtocolError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(ProtocolError::MessageTooLarge { size: len });
    }
    if buf.len() < 4 + len {
        return Ok(None);
    }
    let msg = serde_json::from_slice(&buf[4..4 + len])?;
    Ok(Some((msg, 4 + len)))
}

/// Maximum allowed message size (16 MiB) to prevent unbounded allocations.
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Default vsock port the guest agent listens on.
pub const AGENT_VSOCK_PORT: u32 = 52;

/// Default wall-clock deadline for receiving a single framed payload once
/// the length prefix has been read. Callers who need a different bound can
/// use [`read_message_with_timeout`]. Operators can override the default
/// via the `HUSKER_PROTO_READ_TIMEOUT_SECS` environment variable.
pub const DEFAULT_READ_TIMEOUT_SECS: u64 = 30;

/// Upper bound on a single chunk read while receiving a payload. Growing
/// the buffer one chunk at a time keeps per-connection memory proportional
/// to bytes actually received rather than to the length the peer declared.
const PAYLOAD_READ_CHUNK: usize = 64 * 1024;

/// Resolve the payload read timeout, honouring `HUSKER_PROTO_READ_TIMEOUT_SECS`.
pub fn default_read_timeout() -> Duration {
    let secs = std::env::var("HUSKER_PROTO_READ_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_READ_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// Read a single length-prefixed JSON message from an async stream.
///
/// Returns `None` on clean EOF (stream closed with no partial data).
/// Returns an error on truncated messages or protocol violations.
///
/// Applies the default payload read timeout (see [`default_read_timeout`])
/// once the length prefix has been received. No timeout applies while
/// waiting for the next message to begin.
pub async fn read_message<T, S>(stream: &mut S) -> Result<Option<T>, ProtocolError>
where
    T: for<'de> Deserialize<'de>,
    S: tokio::io::AsyncRead + Unpin,
{
    read_message_with_timeout(stream, default_read_timeout()).await
}

/// Variant of [`read_message`] that takes an explicit payload read timeout.
pub async fn read_message_with_timeout<T, S>(
    stream: &mut S,
    payload_timeout: Duration,
) -> Result<Option<T>, ProtocolError>
where
    T: for<'de> Deserialize<'de>,
    S: tokio::io::AsyncRead + Unpin,
{
    // Length prefix: no timeout. An idle connection waiting for the next
    // request is legitimate; bounding that belongs at the connection layer.
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(ProtocolError::MessageTooLarge { size: len });
    }

    // Payload: bounded deadline + chunked allocation. Growing the buffer as
    // bytes arrive means a peer cannot force MAX_MESSAGE_SIZE of RAM to be
    // reserved up front by claiming a large length it never delivers.
    let payload_fut = async {
        let mut payload: Vec<u8> = Vec::with_capacity(len.min(PAYLOAD_READ_CHUNK));
        let mut remaining = len;
        while remaining > 0 {
            let this_chunk = remaining.min(PAYLOAD_READ_CHUNK);
            let start = payload.len();
            payload.resize(start + this_chunk, 0);
            stream.read_exact(&mut payload[start..]).await?;
            remaining -= this_chunk;
        }
        Ok::<_, std::io::Error>(payload)
    };

    let payload = match tokio::time::timeout(payload_timeout, payload_fut).await {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => {
            return Err(ProtocolError::ReadTimeout {
                declared: len,
                timeout_secs: payload_timeout.as_secs(),
            });
        }
    };

    let msg = serde_json::from_slice(&payload)?;
    Ok(Some(msg))
}

/// Write a single length-prefixed JSON message to an async stream.
pub async fn write_message<T, S>(stream: &mut S, msg: &T) -> Result<(), ProtocolError>
where
    T: Serialize,
    S: tokio::io::AsyncWrite + Unpin,
{
    let json = serde_json::to_vec(msg)?;
    if json.len() > MAX_MESSAGE_SIZE {
        return Err(ProtocolError::MessageTooLarge { size: json.len() });
    }
    let len = (json.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&json).await?;
    stream.flush().await?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("message too large: {size} bytes (max {MAX_MESSAGE_SIZE})")]
    MessageTooLarge { size: usize },
    #[error("payload read timed out after {timeout_secs}s (declared {declared} bytes)")]
    ReadTimeout { declared: usize, timeout_secs: u64 },
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// --- Base64 encoding/decoding ---
// Both the guest agent and host-side client need base64 for file transfer.

const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(data: &[u8]) -> String {
    let mut output = Vec::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;

    while i + 2 < data.len() {
        output.push(B64_CHARS[(data[i] >> 2) as usize]);
        output.push(B64_CHARS[(((data[i] & 0x03) << 4) | (data[i + 1] >> 4)) as usize]);
        output.push(B64_CHARS[(((data[i + 1] & 0x0f) << 2) | (data[i + 2] >> 6)) as usize]);
        output.push(B64_CHARS[(data[i + 2] & 0x3f) as usize]);
        i += 3;
    }

    let remaining = data.len() - i;
    match remaining {
        1 => {
            output.push(B64_CHARS[(data[i] >> 2) as usize]);
            output.push(B64_CHARS[((data[i] & 0x03) << 4) as usize]);
            output.push(b'=');
            output.push(b'=');
        }
        2 => {
            output.push(B64_CHARS[(data[i] >> 2) as usize]);
            output.push(B64_CHARS[(((data[i] & 0x03) << 4) | (data[i + 1] >> 4)) as usize]);
            output.push(B64_CHARS[((data[i + 1] & 0x0f) << 2) as usize]);
            output.push(b'=');
        }
        _ => {}
    }

    // B64_CHARS only contains ASCII bytes, so this is always valid UTF-8
    String::from_utf8(output).expect("base64 output is always valid UTF-8")
}

pub fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let input = input.as_bytes();
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    let decode_char = |c: u8| -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0),
            _ => Err(format!("invalid base64 character: {c}")),
        }
    };

    let mut i = 0;
    while i < input.len() {
        if i + 4 > input.len() {
            return Err("invalid base64 length".into());
        }
        let a = decode_char(input[i])?;
        let b = decode_char(input[i + 1])?;
        let c = decode_char(input[i + 2])?;
        let d = decode_char(input[i + 3])?;

        output.push((a << 2) | (b >> 4));
        if input[i + 2] != b'=' {
            output.push((b << 4) | (c >> 2));
        }
        if input[i + 3] != b'=' {
            output.push((c << 6) | d);
        }

        i += 4;
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn reconfigure_network_round_trip() {
        let req = AgentRequest::ReconfigureNetwork(ReconfigureNetworkRequest {
            interface: "eth0".into(),
            ipv4: "192.0.2.10".into(),
            prefix_len: 24,
            gateway: "192.0.2.1".into(),
            mac: Some("AA:FC:00:00:00:09".into()),
            dns: vec!["192.0.2.1".into(), "1.1.1.1".into()],
        });
        let encoded = encode_message(&req).unwrap();
        let (decoded, consumed): (AgentRequest, usize) = decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            AgentRequest::ReconfigureNetwork(r) => {
                assert_eq!(r.interface, "eth0");
                assert_eq!(r.ipv4, "192.0.2.10");
                assert_eq!(r.prefix_len, 24);
                assert_eq!(r.gateway, "192.0.2.1");
                assert_eq!(r.mac.as_deref(), Some("AA:FC:00:00:00:09"));
                assert_eq!(r.dns, vec!["192.0.2.1".to_string(), "1.1.1.1".to_string()]);
            }
            other => panic!("expected ReconfigureNetwork, got {other:?}"),
        }

        let resp = AgentResponse::ReconfigureNetwork(ReconfigureNetworkResponse {
            interface: "eth0".into(),
            ipv4: "192.0.2.10".into(),
        });
        let encoded = encode_message(&resp).unwrap();
        let (decoded, _): (AgentResponse, usize) = decode_message(&encoded).unwrap().unwrap();
        assert!(matches!(decoded, AgentResponse::ReconfigureNetwork(_)));
    }

    #[test]
    fn guest_info_round_trip() {
        let req = AgentRequest::GuestInfo;
        let bytes = serde_json::to_vec(&req).unwrap();
        let back: AgentRequest = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(back, AgentRequest::GuestInfo));

        let resp = AgentResponse::GuestInfo(GuestInfoResponse {
            ipv4: vec!["192.0.2.7".into()],
        });
        let bytes = serde_json::to_vec(&resp).unwrap();
        let back: AgentResponse = serde_json::from_slice(&bytes).unwrap();
        match back {
            AgentResponse::GuestInfo(g) => assert_eq!(g.ipv4, vec!["192.0.2.7".to_string()]),
            other => panic!("expected GuestInfo, got {other:?}"),
        }
    }

    #[test]
    fn oci_runtime_config_round_trips_and_defaults() {
        let cfg = OciRuntimeConfig {
            env: vec![
                "PATH=/usr/local/bin:/usr/bin".into(),
                "PYTHON_VERSION=3.12".into(),
            ],
            working_dir: Some("/app".into()),
            entrypoint: vec!["python3".into()],
            cmd: vec!["app.py".into()],
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: OciRuntimeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);

        // Missing fields default (forward/backward compatibility of the file).
        let minimal: OciRuntimeConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(minimal, OciRuntimeConfig::default());
        assert!(minimal.env.is_empty());
        assert!(minimal.working_dir.is_none());
    }

    #[test]
    fn roundtrip_exec_request() {
        let req = AgentRequest::Exec(ExecRequest {
            command: "ls".into(),
            args: vec!["-la".into()],
            working_dir: Some("/tmp".into()),
            env: vec![("FOO".into(), "bar".into())],
            timeout_secs: None,
        });
        let encoded = encode_message(&req).unwrap();
        let (decoded, consumed): (AgentRequest, usize) = decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            AgentRequest::Exec(e) => {
                assert_eq!(e.command, "ls");
                assert_eq!(e.args, vec!["-la"]);
            }
            _ => panic!("expected Exec"),
        }
    }

    #[test]
    fn roundtrip_ping_pong() {
        let ping = AgentRequest::Ping;
        let encoded = encode_message(&ping).unwrap();
        let (decoded, _): (AgentRequest, usize) = decode_message(&encoded).unwrap().unwrap();
        assert!(matches!(decoded, AgentRequest::Ping));

        let pong = AgentResponse::Pong;
        let encoded = encode_message(&pong).unwrap();
        let (decoded, _): (AgentResponse, usize) = decode_message(&encoded).unwrap().unwrap();
        assert!(matches!(decoded, AgentResponse::Pong));
    }

    #[test]
    fn roundtrip_shutdown() {
        let req = AgentRequest::Shutdown;
        let encoded = encode_message(&req).unwrap();
        let (decoded, consumed): (AgentRequest, usize) = decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        assert!(matches!(decoded, AgentRequest::Shutdown));

        let resp = AgentResponse::ShuttingDown;
        let encoded = encode_message(&resp).unwrap();
        let (decoded, consumed): (AgentResponse, usize) =
            decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        assert!(matches!(decoded, AgentResponse::ShuttingDown));
    }

    #[test]
    fn incomplete_buffer_returns_none() {
        let req = AgentRequest::Ping;
        let encoded = encode_message(&req).unwrap();
        // Truncate the buffer
        let partial = &encoded[..encoded.len() - 1];
        let result: Result<Option<(AgentRequest, usize)>, _> = decode_message(partial);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn empty_buffer_returns_none() {
        let result: Result<Option<(AgentRequest, usize)>, _> = decode_message(&[]);
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn read_message_times_out_on_slow_payload() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        // Advertise 1000 payload bytes but never send any of them. The length
        // prefix is accepted; the payload read must hit the deadline.
        tokio::spawn(async move {
            writer.write_all(&1000u32.to_be_bytes()).await.unwrap();
            // Hold the stream open well past the reader's deadline.
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let err =
            read_message_with_timeout::<AgentRequest, _>(&mut reader, Duration::from_millis(150))
                .await
                .expect_err("slow payload must time out");

        match err {
            ProtocolError::ReadTimeout {
                declared,
                timeout_secs: _,
            } => {
                assert_eq!(declared, 1000);
            }
            other => panic!("expected ReadTimeout, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_message_reads_chunked_payload() {
        // A payload larger than PAYLOAD_READ_CHUNK exercises the growth loop.
        let msg = AgentRequest::Exec(ExecRequest {
            command: "x".repeat(200_000),
            args: vec![],
            working_dir: None,
            env: vec![],
            timeout_secs: None,
        });
        let bytes = encode_message(&msg).unwrap();

        let (mut writer, mut reader) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            writer.write_all(&bytes).await.unwrap();
        });

        let got: AgentRequest = read_message_with_timeout(&mut reader, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();

        match got {
            AgentRequest::Exec(exec) => assert_eq!(exec.command.len(), 200_000),
            _ => panic!("expected Exec"),
        }
    }

    #[test]
    fn oversized_message_rejected() {
        let mut buf = vec![0u8; 8];
        let bogus_len = (MAX_MESSAGE_SIZE as u32 + 1).to_be_bytes();
        buf[..4].copy_from_slice(&bogus_len);
        let result: Result<Option<(AgentRequest, usize)>, _> = decode_message(&buf);
        assert!(matches!(result, Err(ProtocolError::MessageTooLarge { .. })));
    }

    #[test]
    fn base64_roundtrip_empty() {
        let data = b"";
        let encoded = base64_encode(data);
        assert_eq!(encoded, "");
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_roundtrip_one_byte() {
        let data = b"A";
        let encoded = base64_encode(data);
        assert_eq!(encoded, "QQ==");
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_roundtrip_two_bytes() {
        let data = b"AB";
        let encoded = base64_encode(data);
        assert_eq!(encoded, "QUI=");
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_roundtrip_three_bytes() {
        let data = b"ABC";
        let encoded = base64_encode(data);
        assert_eq!(encoded, "QUJD");
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_roundtrip_hello_world() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        assert_eq!(encoded, "SGVsbG8sIFdvcmxkIQ==");
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_roundtrip_binary_data() {
        let data: Vec<u8> = (0..=255).collect();
        let encoded = base64_encode(&data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_decode_invalid_length() {
        assert!(base64_decode("QQ=").is_err());
    }

    #[test]
    fn base64_decode_invalid_char() {
        assert!(base64_decode("QQ!=").is_err());
    }

    #[test]
    fn roundtrip_shell_start() {
        let req = AgentRequest::ShellStart(ShellStartRequest {
            command: Some("/bin/bash".into()),
            env: vec![("TERM".into(), "xterm-256color".into())],
            cols: 80,
            rows: 24,
        });
        let encoded = encode_message(&req).unwrap();
        let (decoded, consumed): (AgentRequest, usize) = decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            AgentRequest::ShellStart(s) => {
                assert_eq!(s.command.as_deref(), Some("/bin/bash"));
                assert_eq!(s.cols, 80);
                assert_eq!(s.rows, 24);
                assert_eq!(s.env, vec![("TERM".into(), "xterm-256color".into())]);
            }
            _ => panic!("expected ShellStart"),
        }
    }

    #[test]
    fn roundtrip_shell_start_default_command() {
        let req = AgentRequest::ShellStart(ShellStartRequest {
            command: None,
            env: vec![],
            cols: 120,
            rows: 40,
        });
        let encoded = encode_message(&req).unwrap();
        let (decoded, _): (AgentRequest, usize) = decode_message(&encoded).unwrap().unwrap();
        match decoded {
            AgentRequest::ShellStart(s) => {
                assert!(s.command.is_none());
                assert_eq!(s.cols, 120);
                assert_eq!(s.rows, 40);
            }
            _ => panic!("expected ShellStart"),
        }
    }

    #[test]
    fn roundtrip_shell_data_request() {
        let req = AgentRequest::ShellData(ShellDataRequest {
            data: base64_encode(b"ls -la\n"),
        });
        let encoded = encode_message(&req).unwrap();
        let (decoded, _): (AgentRequest, usize) = decode_message(&encoded).unwrap().unwrap();
        match decoded {
            AgentRequest::ShellData(s) => {
                let bytes = base64_decode(&s.data).unwrap();
                assert_eq!(bytes, b"ls -la\n");
            }
            _ => panic!("expected ShellData"),
        }
    }

    #[test]
    fn roundtrip_shell_resize() {
        let req = AgentRequest::ShellResize(ShellResizeRequest {
            cols: 200,
            rows: 50,
        });
        let encoded = encode_message(&req).unwrap();
        let (decoded, _): (AgentRequest, usize) = decode_message(&encoded).unwrap().unwrap();
        match decoded {
            AgentRequest::ShellResize(s) => {
                assert_eq!(s.cols, 200);
                assert_eq!(s.rows, 50);
            }
            _ => panic!("expected ShellResize"),
        }
    }

    #[test]
    fn roundtrip_shell_started() {
        let resp = AgentResponse::ShellStarted;
        let encoded = encode_message(&resp).unwrap();
        let (decoded, _): (AgentResponse, usize) = decode_message(&encoded).unwrap().unwrap();
        assert!(matches!(decoded, AgentResponse::ShellStarted));
    }

    #[test]
    fn roundtrip_shell_data_response() {
        let resp = AgentResponse::ShellData(ShellDataResponse {
            data: base64_encode(b"total 42\ndrwxr-xr-x"),
        });
        let encoded = encode_message(&resp).unwrap();
        let (decoded, _): (AgentResponse, usize) = decode_message(&encoded).unwrap().unwrap();
        match decoded {
            AgentResponse::ShellData(s) => {
                let bytes = base64_decode(&s.data).unwrap();
                assert_eq!(bytes, b"total 42\ndrwxr-xr-x");
            }
            _ => panic!("expected ShellData response"),
        }
    }

    #[test]
    fn roundtrip_shell_exit() {
        let resp = AgentResponse::ShellExit(ShellExitResponse { exit_code: 42 });
        let encoded = encode_message(&resp).unwrap();
        let (decoded, _): (AgentResponse, usize) = decode_message(&encoded).unwrap().unwrap();
        match decoded {
            AgentResponse::ShellExit(s) => {
                assert_eq!(s.exit_code, 42);
            }
            _ => panic!("expected ShellExit response"),
        }
    }

    #[test]
    fn roundtrip_shell_exit_zero() {
        let resp = AgentResponse::ShellExit(ShellExitResponse { exit_code: 0 });
        let encoded = encode_message(&resp).unwrap();
        let (decoded, _): (AgentResponse, usize) = decode_message(&encoded).unwrap().unwrap();
        match decoded {
            AgentResponse::ShellExit(s) => {
                assert_eq!(s.exit_code, 0);
            }
            _ => panic!("expected ShellExit response"),
        }
    }

    // --- Framing/argv hardening (kills mutants surfaced by `make mutation-gate`) --
    //
    // These pin the length-prefix size guards, the framing constants, the OCI
    // argv helper, and the read/write round trip. Each targets a specific
    // cargo-mutants survivor on husker-agent-proto's safety-critical code.

    #[test]
    fn argv_is_entrypoint_followed_by_cmd() {
        let cfg = OciRuntimeConfig {
            entrypoint: vec!["python3".into()],
            cmd: vec!["app.py".into(), "--verbose".into()],
            ..Default::default()
        };
        assert_eq!(cfg.argv(), vec!["python3", "app.py", "--verbose"]);
        // Empty when the image declares neither entrypoint nor cmd.
        assert!(OciRuntimeConfig::default().argv().is_empty());
        // Entrypoint-only and cmd-only preserve order and content.
        let ep_only = OciRuntimeConfig {
            entrypoint: vec!["/bin/sh".into()],
            ..Default::default()
        };
        assert_eq!(ep_only.argv(), vec!["/bin/sh"]);
        let cmd_only = OciRuntimeConfig {
            cmd: vec!["echo".into(), "hi".into()],
            ..Default::default()
        };
        assert_eq!(cmd_only.argv(), vec!["echo", "hi"]);
    }

    #[test]
    fn framing_size_constants_are_exact() {
        assert_eq!(MAX_MESSAGE_SIZE, 16_777_216);
        assert_eq!(PAYLOAD_READ_CHUNK, 65_536);
    }

    #[test]
    fn decode_rejects_prefix_over_max_at_four_bytes() {
        // Buffer holds only the 4-byte length prefix, declaring MAX+1. The size
        // guard must reject before the completeness check (`buf.len() < 4` is
        // false at exactly four bytes).
        let buf = ((MAX_MESSAGE_SIZE as u32) + 1).to_be_bytes();
        let result: Result<Option<(AgentRequest, usize)>, _> = decode_message(&buf);
        assert!(matches!(
            result,
            Err(ProtocolError::MessageTooLarge { size }) if size == MAX_MESSAGE_SIZE + 1
        ));
    }

    #[test]
    fn decode_allows_prefix_at_exactly_max_and_waits() {
        // A prefix of exactly MAX is within bounds; with no payload the frame is
        // incomplete, so decode returns None rather than rejecting it.
        let buf = (MAX_MESSAGE_SIZE as u32).to_be_bytes();
        let result: Result<Option<(AgentRequest, usize)>, _> = decode_message(&buf);
        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn write_message_emits_a_decodable_frame() {
        let mut sink = Vec::new();
        write_message(&mut sink, &AgentRequest::Ping).await.unwrap();
        assert!(!sink.is_empty(), "writer must emit the framed bytes");
        let (decoded, consumed): (AgentRequest, usize) = decode_message(&sink).unwrap().unwrap();
        assert_eq!(consumed, sink.len());
        assert!(matches!(decoded, AgentRequest::Ping));
    }

    #[tokio::test]
    async fn encode_and_write_reject_payload_larger_than_max() {
        // A payload strictly larger than MAX must be rejected by both the sync
        // encoder and the async writer, not only when it is exactly MAX.
        let oversize = AgentRequest::Exec(ExecRequest {
            command: "x".repeat(MAX_MESSAGE_SIZE + 1024),
            args: vec![],
            working_dir: None,
            env: vec![],
            timeout_secs: None,
        });
        assert!(matches!(
            encode_message(&oversize),
            Err(ProtocolError::MessageTooLarge { .. })
        ));
        let mut sink = Vec::new();
        let err = write_message(&mut sink, &oversize)
            .await
            .expect_err("writer must reject an oversize payload");
        assert!(matches!(err, ProtocolError::MessageTooLarge { .. }));
    }

    #[tokio::test]
    async fn read_message_rejects_prefix_over_max_without_reading_payload() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        tokio::spawn(async move {
            writer
                .write_all(&((MAX_MESSAGE_SIZE as u32) + 1).to_be_bytes())
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let err =
            read_message_with_timeout::<AgentRequest, _>(&mut reader, Duration::from_millis(250))
                .await
                .expect_err("oversize prefix must be rejected");
        assert!(matches!(
            err,
            ProtocolError::MessageTooLarge { size } if size == MAX_MESSAGE_SIZE + 1
        ));
    }

    #[tokio::test]
    async fn read_message_accepts_max_prefix_then_times_out_awaiting_payload() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        tokio::spawn(async move {
            writer
                .write_all(&(MAX_MESSAGE_SIZE as u32).to_be_bytes())
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let err =
            read_message_with_timeout::<AgentRequest, _>(&mut reader, Duration::from_millis(150))
                .await
                .expect_err("missing payload must hit the deadline");
        assert!(matches!(
            err,
            ProtocolError::ReadTimeout { declared, .. } if declared == MAX_MESSAGE_SIZE
        ));
    }

    #[tokio::test]
    async fn read_message_surfaces_non_eof_errors() {
        // A clean EOF on the length prefix means "no message" (Ok(None)); any
        // other read error must propagate rather than be swallowed as EOF.
        struct ErroringReader(std::io::ErrorKind);
        impl tokio::io::AsyncRead for ErroringReader {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Err(std::io::Error::new(self.0, "boom")))
            }
        }

        let mut reader = ErroringReader(std::io::ErrorKind::ConnectionReset);
        let result =
            read_message_with_timeout::<AgentRequest, _>(&mut reader, Duration::from_secs(1)).await;
        assert!(matches!(result, Err(ProtocolError::Io(_))));
    }

    #[test]
    fn default_read_timeout_resolves_env_then_default() {
        // Directly asserting the resolved Duration catches a resolver that
        // collapses to Duration::ZERO (which would make every payload read time
        // out instantly) - the round-trip tests miss it because a pre-buffered
        // payload completes before even a zero deadline fires.
        //
        // SAFETY: no other test in this binary reads the timeout env var (the
        // rest pass explicit timeouts), so mutating it here is race-free.
        unsafe {
            std::env::set_var("HUSKER_PROTO_READ_TIMEOUT_SECS", "5");
        }
        assert_eq!(default_read_timeout(), Duration::from_secs(5));
        unsafe {
            std::env::remove_var("HUSKER_PROTO_READ_TIMEOUT_SECS");
        }
        assert_eq!(default_read_timeout(), Duration::from_secs(30));
        assert_eq!(
            default_read_timeout(),
            Duration::from_secs(DEFAULT_READ_TIMEOUT_SECS)
        );
    }

    proptest! {
        #[test]
        fn prop_base64_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let encoded = base64_encode(&data);
            let decoded = base64_decode(&encoded).unwrap();
            prop_assert_eq!(decoded, data);
        }

        #[test]
        fn prop_frame_roundtrip_random_exec(
            cmd in ".*",
            args in proptest::collection::vec(".*", 0..8),
            wd in proptest::option::of(".*")
        ) {
            let req = AgentRequest::Exec(ExecRequest {
                command: cmd.clone(),
                args: args.clone(),
                working_dir: wd.clone(),
                env: Vec::new(),
                timeout_secs: None,
            });
            let encoded = encode_message(&req).unwrap();
            let decoded: Option<(AgentRequest, usize)> = decode_message(&encoded).unwrap();
            let (decoded, consumed) = decoded.unwrap();
            prop_assert_eq!(consumed, encoded.len());
            match decoded {
                AgentRequest::Exec(exec) => {
                    prop_assert_eq!(exec.command, cmd);
                    prop_assert_eq!(exec.args, args);
                    prop_assert_eq!(exec.working_dir, wd);
                }
                other => prop_assert!(false, "unexpected decoded variant: {other:?}"),
            }
        }
    }
}
