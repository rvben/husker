//! QEMU Monitor Protocol (QMP) client over a Unix domain socket.
//!
//! Session: connect -> read `{"QMP": ...}` greeting -> send `qmp_capabilities`
//! -> commands return `{"return": ...}` or `{"error": ...}`; async `{"event": ...}`
//! lines are skipped.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::VmmError;

const QMP_TIMEOUT: Duration = Duration::from_secs(10);
const QMP_MAX_LINE_BYTES: usize = 64 * 1024;

pub struct QmpClient {
    stream: BufReader<UnixStream>,
    failed: bool,
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
        tokio::time::timeout(QMP_TIMEOUT, Self::connect_inner(socket_path))
            .await
            .map_err(|_| VmmError::ApiError("QMP handshake timed out".into()))?
    }

    async fn connect_inner(socket_path: &std::path::Path) -> Result<Self, VmmError> {
        let stream = UnixStream::connect(socket_path).await.map_err(|e| {
            VmmError::ApiError(format!("QMP connect {}: {e}", socket_path.display()))
        })?;
        let mut client = Self {
            stream: BufReader::new(stream),
            failed: false,
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
        if self.failed {
            return Err(VmmError::ApiError(
                "QMP connection unusable after failed or cancelled command".into(),
            ));
        }
        // Set before awaiting: cancellation cannot permit a late reply to be
        // mistaken for a subsequent command's result.
        self.failed = true;
        let result = tokio::time::timeout(QMP_TIMEOUT, self.execute_inner(cmd, args))
            .await
            .map_err(|_| VmmError::ApiError(format!("QMP {cmd} timed out")))?;
        if result.is_ok() {
            self.failed = false;
        }
        result
    }

    async fn execute_inner(&mut self, cmd: &str, args: Option<Value>) -> Result<Value, VmmError> {
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
        let n = tokio::time::timeout(
            QMP_TIMEOUT,
            (&mut self.stream)
                .take((QMP_MAX_LINE_BYTES + 1) as u64)
                .read_line(&mut line),
        )
        .await
        .map_err(|_| VmmError::ApiError("QMP read timed out".into()))?
        .map_err(|e| VmmError::ApiError(format!("QMP read: {e}")))?;
        if n > QMP_MAX_LINE_BYTES {
            return Err(VmmError::ApiError(
                "QMP response line exceeds 64 KiB".into(),
            ));
        }
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

    #[tokio::test]
    async fn cancelled_command_rejects_reuse_before_a_late_reply_can_be_consumed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("cancel.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, finish) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            stream.get_mut().write_all(b"{\"QMP\":{}}\n").await.unwrap();
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            stream
                .get_mut()
                .write_all(b"{\"return\":{}}\n")
                .await
                .unwrap();
            line.clear();
            stream.read_line(&mut line).await.unwrap();
            assert!(line.contains("stop"));
            started.send(()).unwrap();
            finish.await.unwrap();
            stream
                .get_mut()
                .write_all(b"{\"return\":{\"late\":true}}\n")
                .await
                .unwrap();
        });
        let mut client = QmpClient::connect(&path).await.unwrap();
        let mut command = Box::pin(client.execute("stop", None));
        tokio::select! {
            _ = ready => (),
            result = &mut command => panic!("silent command completed: {result:?}"),
        }
        drop(command);
        release.send(()).unwrap();
        server.await.unwrap();
        assert!(
            client
                .execute("cont", None)
                .await
                .unwrap_err()
                .to_string()
                .contains("cancelled command")
        );
    }

    #[tokio::test]
    async fn endless_events_cannot_extend_a_command_deadline_or_reuse_its_connection() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("events.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let events = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = events.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            stream.get_mut().write_all(b"{\"QMP\":{}}\n").await.unwrap();
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            stream
                .get_mut()
                .write_all(b"{\"return\":{}}\n")
                .await
                .unwrap();
            line.clear();
            stream.read_line(&mut line).await.unwrap();
            loop {
                if stream
                    .get_mut()
                    .write_all(b"{\"event\":\"STATUS\"}\n")
                    .await
                    .is_err()
                {
                    break;
                }
                observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        let mut client = QmpClient::connect(&path).await.unwrap();
        tokio::time::pause();
        let error = client.execute("stop", None).await.unwrap_err();
        assert!(error.to_string().contains("QMP stop timed out"));
        assert!(events.load(std::sync::atomic::Ordering::Relaxed) > 1);
        assert!(
            client
                .execute("cont", None)
                .await
                .unwrap_err()
                .to_string()
                .contains("unusable")
        );
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn oversized_unterminated_greeting_is_rejected_without_waiting_for_eof() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("oversized.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = stream.write_all(&vec![b'x'; QMP_MAX_LINE_BYTES + 1]).await;
            std::future::pending::<()>().await;
        });
        let error = QmpClient::connect(&path).await.err().unwrap();
        assert!(error.to_string().contains("response line exceeds 64 KiB"));
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

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
