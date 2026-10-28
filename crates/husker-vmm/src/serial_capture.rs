//! Bounded diagnostic output, independent of the guest command evidence stream.
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::Instrument;

use crate::VmmError;

#[cfg(target_os = "macos")]
pub(crate) const SERIAL_LOG_BYTES: usize = husker_types::factory_limits::SERIAL_BYTES as usize;
const TRUNCATION: &[u8] = b"\n[husker: serial diagnostic output truncated]\n";

async fn drain_serial<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    read: &mut R,
    file: &mut W,
    stopping: &mut tokio::sync::watch::Receiver<bool>,
    limit: usize,
) -> io::Result<()> {
    let mut retained = 0usize;
    let mut truncated = false;
    let mut storage_error = None;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let count = tokio::select! {
            biased;
            _ = stopping.changed() => break,
            result = read.read(&mut buffer) => match result {
                Ok(count) => count,
                Err(error) => return Err(storage_error.unwrap_or(error)),
            },
        };
        if count == 0 {
            break;
        }
        if storage_error.is_some() {
            continue; // Keep the guest's output endpoint open and draining.
        }
        let keep = count.min((limit - TRUNCATION.len()).saturating_sub(retained));
        let result = async {
            file.write_all(&buffer[..keep]).await?;
            retained += keep;
            if keep < count && !truncated {
                file.write_all(TRUNCATION).await?;
                truncated = true;
            }
            Ok::<_, io::Error>(())
        }
        .await;
        if let Err(error) = result {
            tracing::warn!(%error, "serial diagnostic storage failed; continuing to drain discarded output");
            storage_error = Some(error);
        }
    }
    if let Some(error) = storage_error {
        return Err(error);
    }
    file.flush().await
}

/// The instance owns this drain until confirmed shutdown. Excess output is
/// discarded while the socket continues to drain, keeping storage bounded.
pub(crate) struct SerialCapture {
    stop: tokio::sync::watch::Sender<bool>,
    worker: Option<tokio::task::JoinHandle<io::Result<()>>>,
}

impl SerialCapture {
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn pending_shutdown_fixture(
        entered: tokio::sync::oneshot::Sender<()>,
        release: tokio::sync::oneshot::Receiver<()>,
    ) -> Self {
        let (stop, mut stopping) = tokio::sync::watch::channel(false);
        let worker = tokio::spawn(async move {
            let _ = stopping.changed().await;
            let _ = entered.send(());
            let _ = release.await;
            Ok(())
        });
        Self {
            stop,
            worker: Some(worker),
        }
    }

    pub(crate) fn new(path: &Path, limit: usize) -> io::Result<(Arc<std::fs::File>, Self)> {
        use std::os::unix::fs::OpenOptionsExt;
        if limit < TRUNCATION.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "serial log cap too small",
            ));
        }
        let (write, read) = std::os::unix::net::UnixStream::pair()?;
        read.set_nonblocking(true)?;
        let mut read = tokio::net::UnixStream::from_std(read)?;
        let write: OwnedFd = write.into();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let mut file = tokio::fs::File::from_std(file);
        let (stop, mut stopping) = tokio::sync::watch::channel(false);
        let span = tracing::info_span!("serial_capture", log = %path.display());
        let worker = tokio::spawn(
            async move {
                let result = async {
                    drain_serial(&mut read, &mut file, &mut stopping, limit).await?;
                    file.sync_all().await
                }
                .await;
                if let Err(error) = &result {
                    tracing::warn!(%error, "serial diagnostic capture ended with lost output");
                }
                result
            }
            .instrument(span),
        );
        Ok((
            Arc::new(std::fs::File::from(write)),
            Self {
                stop,
                worker: Some(worker),
            },
        ))
    }

    /// Only after the machine is confirmed stopped (or never constructed).
    /// Timeout or cancellation leaves the join handle owned for retry. Serial
    /// diagnostics are a prefix: shutdown may omit unread final socket bytes.
    pub(crate) async fn finish(&mut self) -> Result<(), VmmError> {
        self.stop.send_replace(true);
        let Some(worker) = &mut self.worker else {
            return Ok(());
        };
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), worker)
            .await
            .map_err(|_| {
                VmmError::ProcessError("serial capture shutdown remains pending".into())
            })?;
        self.worker.take(); // Never poll a completed handle again.
        if !matches!(result, Ok(Ok(()))) {
            // Diagnostic loss is separate from confirmed VMM termination.
            tracing::warn!(?result, "serial diagnostic capture failed");
        }
        Ok(())
    }
}

impl Drop for SerialCapture {
    fn drop(&mut self) {
        if let Some(worker) = &self.worker {
            worker.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::IntoRawFd;

    struct FailingStorage {
        prefix: Vec<u8>,
        fail_after: usize,
        fail_flush: bool,
        writes: usize,
    }
    impl AsyncWrite for FailingStorage {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            self.writes += 1;
            if self.prefix.len() >= self.fail_after {
                return std::task::Poll::Ready(Err(io::Error::from_raw_os_error(libc::ENOSPC)));
            }
            let count = bytes.len().min(self.fail_after - self.prefix.len());
            self.prefix.extend_from_slice(&bytes[..count]);
            std::task::Poll::Ready(Ok(count))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(if self.fail_flush {
                Err(io::Error::from_raw_os_error(libc::ENOSPC))
            } else {
                Ok(())
            })
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    #[tokio::test]
    async fn storage_failure_drains_the_producer_and_reports_the_original_loss() {
        for (fail_after, fail_flush) in [
            (0, false),
            (32, false),
            (1024 - TRUNCATION.len(), false), // Failure writing the marker.
            (usize::MAX, true),
        ] {
            let (mut output, mut input) = tokio::io::duplex(4096);
            let (_stop, mut stopping) = tokio::sync::watch::channel(false);
            let reader = tokio::spawn(async move {
                let mut storage = FailingStorage {
                    prefix: Vec::new(),
                    fail_after,
                    fail_flush,
                    writes: 0,
                };
                let result = drain_serial(&mut input, &mut storage, &mut stopping, 1024).await;
                (result, storage)
            });
            // This producer cannot finish if the drain closes or stalls on ENOSPC.
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                output.write_all(&vec![b'x'; 256 * 1024]),
            )
            .await
            .unwrap()
            .unwrap();
            drop(output);
            let (result, storage) = reader.await.unwrap();
            assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::ENOSPC));
            assert!(storage.prefix.len() <= 1024);
            if !fail_flush {
                assert_eq!(storage.prefix.len(), fail_after);
                assert!(
                    storage.writes <= 2,
                    "failed storage must not be retried per chunk"
                );
            }
        }
    }

    #[tokio::test]
    async fn excess_serial_output_is_drained_with_bounded_truncated_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("serial.log");
        let (write, mut capture) = SerialCapture::new(&path, 1024).unwrap();
        let raw = write.try_clone().unwrap().into_raw_fd();
        let mut stream = unsafe { crate::fd_stream::FdStream::from_owned_raw_fd(raw).unwrap() };
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.write_all(&vec![b'x'; 1024 * 1024]),
        )
        .await
        .unwrap()
        .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if std::fs::metadata(&path).unwrap().len() == 1024 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // More than a kernel socket buffer drained even after the disk cap.
        capture.finish().await.unwrap();
        capture.finish().await.unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 1024);
        assert!(bytes[..1024 - TRUNCATION.len()].iter().all(|b| *b == b'x'));
        assert!(bytes.ends_with(TRUNCATION));
    }

    #[tokio::test]
    async fn eof_flushes_an_untruncated_short_prefix_and_replaced_paths_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("serial.log");
        let (write, mut capture) = SerialCapture::new(&path, 1024).unwrap();
        let raw = write.try_clone().unwrap().into_raw_fd();
        let mut stream = unsafe { crate::fd_stream::FdStream::from_owned_raw_fd(raw).unwrap() };
        stream.write_all(b"diagnostic prefix").await.unwrap();
        drop(stream);
        drop(write);
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while !capture.worker.as_ref().unwrap().is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        capture.finish().await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"diagnostic prefix");
        assert!(SerialCapture::new(&path, 1024).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(SerialCapture::new(&link, 1024).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"diagnostic prefix");
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_or_timed_out_shutdown_retains_the_worker_for_retry() {
        let (stop, _) = tokio::sync::watch::channel(false);
        let (release, waiting) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(async move {
            waiting.await.unwrap();
            Ok(())
        });
        let mut capture = SerialCapture {
            stop,
            worker: Some(worker),
        };
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), capture.finish())
                .await
                .is_err()
        );
        assert!(!capture.worker.as_ref().unwrap().is_finished());
        assert!(capture.finish().await.is_err());
        assert!(!capture.worker.as_ref().unwrap().is_finished());
        release.send(()).unwrap();
        capture.finish().await.unwrap();
        assert!(capture.worker.is_none());
    }
}
