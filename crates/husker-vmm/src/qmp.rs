//! QEMU Monitor Protocol (QMP) client over a Unix domain socket.
//!
//! Session: connect -> read `{"QMP": ...}` greeting -> send `qmp_capabilities`
//! -> commands return `{"return": ...}` or `{"error": ...}`; async `{"event": ...}`
//! lines are skipped.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::VmmError;

const QMP_TIMEOUT: Duration = Duration::from_secs(10);

pub struct QmpClient {
    stream: BufReader<UnixStream>,
}

#[derive(Debug, Deserialize)]
struct QmpResponse {
    #[serde(rename = "return")]
    return_val: Option<Value>,
    error: Option<QmpError>,
    event: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct QmpError {
    class: String,
    desc: String,
}

#[derive(Debug, Serialize)]
struct QmpCommand<'a> {
    execute: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    arguments: Option<Value>,
}

impl QmpClient {
    /// Connect to a QMP socket and complete the capabilities handshake.
    pub async fn connect(socket_path: &std::path::Path) -> Result<Self, VmmError> {
        let stream = UnixStream::connect(socket_path).await.map_err(|e| {
            VmmError::ApiError(format!("QMP connect {}: {e}", socket_path.display()))
        })?;
        let mut client = Self {
            stream: BufReader::new(stream),
        };

        let greeting = client.read_line().await?;
        if !greeting.contains("QMP") {
            return Err(VmmError::ApiError(format!(
                "unexpected QMP greeting: {greeting}"
            )));
        }
        client.execute("qmp_capabilities", None).await?;
        Ok(client)
    }

    /// Send a command, skipping async events, returning its `return` value.
    pub async fn execute(&mut self, cmd: &str, args: Option<Value>) -> Result<Value, VmmError> {
        let msg = serde_json::to_string(&QmpCommand {
            execute: cmd,
            arguments: args,
        })
        .map_err(|e| VmmError::ApiError(format!("QMP serialize: {e}")))?;
        self.write_line(&msg).await?;
        loop {
            let line = self.read_line().await?;
            let resp: QmpResponse = serde_json::from_str(&line)
                .map_err(|e| VmmError::ApiError(format!("QMP parse: {e}: {line}")))?;
            if resp.event.is_some() {
                continue;
            }
            if let Some(err) = resp.error {
                return Err(VmmError::ApiError(format!(
                    "QMP {}: {}",
                    err.class, err.desc
                )));
            }
            return Ok(resp.return_val.unwrap_or(json!({})));
        }
    }

    pub async fn system_powerdown(&mut self) -> Result<(), VmmError> {
        self.execute("system_powerdown", None).await.map(|_| ())
    }

    /// Pause CPU execution (`stop`).
    pub async fn pause(&mut self) -> Result<(), VmmError> {
        self.execute("stop", None).await.map(|_| ())
    }

    /// Resume CPU execution (`cont`).
    pub async fn resume(&mut self) -> Result<(), VmmError> {
        self.execute("cont", None).await.map(|_| ())
    }

    async fn read_line(&mut self) -> Result<String, VmmError> {
        let mut line = String::new();
        let n = tokio::time::timeout(QMP_TIMEOUT, self.stream.read_line(&mut line))
            .await
            .map_err(|_| VmmError::ApiError("QMP read timed out".into()))?
            .map_err(|e| VmmError::ApiError(format!("QMP read: {e}")))?;
        if n == 0 {
            return Err(VmmError::ApiError("QMP connection closed (EOF)".into()));
        }
        Ok(line.trim_end().to_string())
    }

    async fn write_line(&mut self, msg: &str) -> Result<(), VmmError> {
        self.stream
            .get_mut()
            .write_all(format!("{msg}\n").as_bytes())
            .await
            .map_err(|e| VmmError::ApiError(format!("QMP write: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_return_value() {
        let resp: QmpResponse = serde_json::from_str(r#"{"return":{"status":"running"}}"#).unwrap();
        assert!(resp.error.is_none());
        assert!(resp.event.is_none());
        assert_eq!(resp.return_val.unwrap()["status"], "running");
    }

    #[test]
    fn parse_error_value() {
        let resp: QmpResponse =
            serde_json::from_str(r#"{"error":{"class":"GenericError","desc":"boom"}}"#).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.class, "GenericError");
        assert_eq!(err.desc, "boom");
    }

    #[test]
    fn parse_event_is_skippable() {
        let resp: QmpResponse = serde_json::from_str(r#"{"event":"SHUTDOWN","data":{}}"#).unwrap();
        assert!(resp.event.is_some());
        assert!(resp.return_val.is_none());
    }

    #[tokio::test]
    async fn connect_completes_capabilities_handshake() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("qmp.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();

        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut s, b"{\"QMP\":{\"version\":{}}}\n")
                .await
                .unwrap();
            let mut buf = vec![0u8; 128];
            let _ = tokio::io::AsyncReadExt::read(&mut s, &mut buf)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut s, b"{\"return\":{}}\n")
                .await
                .unwrap();
        });

        let client = QmpClient::connect(&sock).await;
        assert!(client.is_ok(), "handshake failed: {:?}", client.err());
    }
}
