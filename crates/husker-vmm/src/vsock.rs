//! Shared Firecracker vsock UDS CONNECT handshake helpers.

use std::path::Path;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Debug, thiserror::Error)]
pub enum VsockConnectError {
    #[error("connect failed: {0}")]
    Connect(std::io::Error),
    #[error("vsock handshake write failed: {0}")]
    HandshakeWrite(std::io::Error),
    #[error("vsock handshake read failed: {0}")]
    HandshakeRead(std::io::Error),
    #[error("vsock CONNECT rejected (port {0})")]
    Rejected(u32),
}

/// Connect to Firecracker's vsock UDS and perform the CONNECT handshake.
pub async fn connect_firecracker_vsock(
    vsock_uds_path: &Path,
    port: u32,
) -> Result<tokio::net::UnixStream, VsockConnectError> {
    let stream = tokio::net::UnixStream::connect(vsock_uds_path)
        .await
        .map_err(VsockConnectError::Connect)?;

    let mut buf_stream = BufReader::new(stream);
    buf_stream
        .get_mut()
        .write_all(format!("CONNECT {port}\n").as_bytes())
        .await
        .map_err(VsockConnectError::HandshakeWrite)?;

    let mut response = String::new();
    buf_stream
        .read_line(&mut response)
        .await
        .map_err(VsockConnectError::HandshakeRead)?;

    if !response.starts_with("OK ") {
        return Err(VsockConnectError::Rejected(port));
    }

    Ok(buf_stream.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_firecracker_vsock_success() {
        let tmp = tempfile::tempdir().unwrap();
        let sock_path = tmp.path().join("vsock.sock");
        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 64];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, b"OK 123\n")
                .await
                .unwrap();
        });

        let _stream = connect_firecracker_vsock(&sock_path, 52).await.unwrap();
    }

    #[tokio::test]
    async fn connect_firecracker_vsock_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let sock_path = tmp.path().join("vsock.sock");
        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 64];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, b"ERR bad\n")
                .await
                .unwrap();
        });

        let err = connect_firecracker_vsock(&sock_path, 52).await.unwrap_err();
        assert!(matches!(err, VsockConnectError::Rejected(52)));
    }
}
