//! Bounded diagnostic output, independent of the guest command evidence stream.
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tracing::Instrument;

use crate::VmmError;
use crate::serial_log::{DISCARD_MARKER_MAX, compaction_staging_path, discard_marker};

pub(crate) const SERIAL_LOG_BYTES: usize = husker_types::factory_limits::SERIAL_BYTES as usize;
/// The default `/proc/sys/fs/pipe-max-size`, the most an unprivileged
/// process may request.
#[cfg(target_os = "linux")]
const SERIAL_PIPE_BYTES: libc::c_int = 1 << 20;

/// Durable destination of a bounded serial log.
trait SerialStore {
    async fn append(&mut self, bytes: &[u8]) -> io::Result<()>;
    /// Replace the content with `marker` followed by its last `keep` bytes.
    async fn retain_tail(&mut self, length: usize, keep: usize, marker: &[u8]) -> io::Result<()>;
    async fn flush(&mut self) -> io::Result<()>;
}

/// The log file and the path readers open it by.
struct SerialFile {
    path: PathBuf,
    file: tokio::fs::File,
}

impl SerialFile {
    fn create(path: &Path) -> io::Result<tokio::fs::File> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        Ok(tokio::fs::File::from_std(file))
    }

    async fn replace(&mut self, marker: &[u8], tail: &[u8]) -> io::Result<()> {
        // The compaction is written beside the log and renamed over it, so a
        // reader opening the log sees either the old file or the complete new one.
        let staging = compaction_staging_path(&self.path);
        // Only a crash mid-compaction leaves one behind; it holds no output
        // the log lacks.
        match tokio::fs::remove_file(&staging).await {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
        let mut next = Self::create(&staging)?;
        let written = async {
            next.write_all(marker).await?;
            next.write_all(tail).await?;
            // A tokio write returns before its last chunk reaches the file, so
            // the rename waits for it, and for the disk, lest a reader or a
            // host crash find a short log in place of the old one.
            next.flush().await?;
            next.sync_data().await?;
            tokio::fs::rename(&staging, &self.path).await
        }
        .await;
        if written.is_err() {
            let _ = tokio::fs::remove_file(&staging).await;
        }
        written?;
        self.file = next;
        Ok(())
    }
}

impl SerialStore for SerialFile {
    async fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.file.write_all(bytes).await
    }

    async fn retain_tail(&mut self, length: usize, keep: usize, marker: &[u8]) -> io::Result<()> {
        use tokio::io::AsyncSeekExt;
        let mut tail = vec![0; keep];
        self.file
            .seek(io::SeekFrom::Start((length - keep) as u64))
            .await?;
        self.file.read_exact(&mut tail).await?;
        self.replace(marker, &tail).await
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.file.flush().await
    }
}

/// Remove a bounded serial log together with any staging file an interrupted
/// compaction left beside it.
pub(crate) async fn remove_serial_log(path: &Path) -> Result<(), VmmError> {
    crate::termination::remove_runtime_file(&compaction_staging_path(path)).await?;
    crate::termination::remove_runtime_file(path).await
}

/// Keeps the newest output within `limit` bytes: on overflow the older half is
/// discarded behind a marker counting every dropped byte, so long-running VMs
/// stay diagnosable without unbounded growth and followers keep their place.
async fn drain_serial<R: AsyncRead + Unpin, S: SerialStore>(
    read: &mut R,
    store: &mut S,
    stopping: &mut tokio::sync::watch::Receiver<bool>,
    limit: usize,
) -> io::Result<()> {
    // File bytes, of which the first `marker_len` are the discard marker.
    let mut length = 0usize;
    let mut marker_len = 0usize;
    let mut discarded = 0u64;
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
        let mut chunk = &buffer[..count];
        let result = async {
            if length + count > limit {
                // Reserving the longest marker keeps any count within the cap.
                let room = limit - DISCARD_MARKER_MAX;
                chunk = &chunk[count.saturating_sub(room)..];
                let content = length - marker_len;
                let keep = (room - chunk.len()).min(limit / 2).min(content);
                let dropped = (content - keep) + (count - chunk.len());
                let marker = discard_marker(discarded + dropped as u64);
                store.retain_tail(length, keep, &marker).await?;
                discarded += dropped as u64;
                marker_len = marker.len();
                length = marker_len + keep;
            }
            store.append(chunk).await?;
            length += chunk.len();
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
    store.flush().await
}

/// The instance owns this drain until confirmed shutdown. The VMM writes guest
/// serial output into a socket, never the log file, so the cap holds whatever
/// the guest emits.
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
        if limit <= 2 * DISCARD_MARKER_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "serial log cap too small",
            ));
        }
        // A pipe, not a socketpair: Firecracker writes the UART one byte at a
        // time to a non-blocking stdout and drops whatever does not fit, and
        // a socketpair charges each write a whole buffer, so it fills after a
        // few hundred bytes. A pipe holds bytes, and on Linux is grown to give
        // the drain minutes of slack at UART speed.
        let (read, write) = std::io::pipe()?;
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: F_SETPIPE_SZ on a pipe descriptor this function owns.
            if unsafe { libc::fcntl(write.as_raw_fd(), libc::F_SETPIPE_SZ, SERIAL_PIPE_BYTES) } < 0
            {
                tracing::debug!(
                    error = %io::Error::last_os_error(),
                    "serial pipe keeps its default size"
                );
            }
        }
        let mut read = tokio::net::unix::pipe::Receiver::from_owned_fd(read.into())?;
        let write: OwnedFd = write.into();
        let mut file = SerialFile {
            path: path.to_owned(),
            file: SerialFile::create(path)?,
        };
        let (stop, mut stopping) = tokio::sync::watch::channel(false);
        let span = tracing::info_span!("serial_capture", log = %path.display());
        let worker = tokio::spawn(
            async move {
                let result = async {
                    drain_serial(&mut read, &mut file, &mut stopping, limit).await?;
                    file.file.sync_all().await
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

    /// Guest serial output a child VMM writes to stdout reaches the log only
    /// through this capture, so the guest cannot grow it past the charged
    /// size. The child holds the only write end, making its exit the EOF.
    pub(crate) fn for_child(path: &Path) -> Result<(std::process::Stdio, Self), VmmError> {
        // A previous boot's log has no live writer: the instance owning it was
        // removed before this UUID could be created again.
        match std::fs::remove_file(path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                return Err(VmmError::ProcessError(format!(
                    "remove previous serial log: {error}"
                )));
            }
            _ => {}
        }
        let (write, capture) = Self::new(path, SERIAL_LOG_BYTES)
            .map_err(|e| VmmError::ProcessError(format!("create serial capture: {e}")))?;
        let write = Arc::into_inner(write).expect("a fresh capture writer is unshared");
        Ok((write.into(), capture))
    }

    /// For a capture whose only writer was a VMM process confirmed exited: the
    /// drain ends at EOF, so its final output (a panic, a shutdown trace) is
    /// kept. A writer still open past the grace falls back to `finish`.
    pub(crate) async fn finish_at_eof(&mut self) -> Result<(), VmmError> {
        if let Some(worker) = &mut self.worker
            && let Ok(result) =
                tokio::time::timeout(std::time::Duration::from_secs(2), worker).await
        {
            self.worker.take(); // Never poll a completed handle again.
            if !matches!(result, Ok(Ok(()))) {
                tracing::warn!(?result, "serial diagnostic capture failed");
            }
            return Ok(());
        }
        self.finish().await
    }

    /// Only after the machine is confirmed stopped (or never constructed).
    /// Timeout or cancellation leaves the join handle owned for retry. Shutdown
    /// may omit final socket bytes not yet read.
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

/// Join a child-fed capture once its VMM is confirmed exited. One still
/// pending stays owned (and aborted on drop) rather than awaited unboundedly.
pub(crate) async fn finish_child_capture(slot: &mut Option<SerialCapture>) {
    if let Some(capture) = slot
        && capture.finish_at_eof().await.is_ok()
    {
        *slot = None;
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
    use crate::serial_log::SerialLogOrigin;
    use std::os::fd::IntoRawFd;

    /// In-memory store that fails once `fail_after` bytes have been accepted.
    struct FailingStorage {
        content: Vec<u8>,
        fail_after: usize,
        fail_flush: bool,
        writes: usize,
        /// Most bytes stored at once: a compaction holds the old log and its
        /// replacement together until the rename.
        peak: usize,
    }
    impl SerialStore for FailingStorage {
        async fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.writes += 1;
            if self.content.len() + bytes.len() > self.fail_after {
                return Err(io::Error::from_raw_os_error(libc::ENOSPC));
            }
            self.content.extend_from_slice(bytes);
            Ok(())
        }
        async fn retain_tail(
            &mut self,
            length: usize,
            keep: usize,
            marker: &[u8],
        ) -> io::Result<()> {
            assert_eq!(length, self.content.len());
            self.writes += 1;
            if marker.len() + keep > self.fail_after {
                return Err(io::Error::from_raw_os_error(libc::ENOSPC));
            }
            self.peak = self.peak.max(length + marker.len() + keep);
            let tail = self.content.split_off(length - keep);
            self.content = [marker, &tail].concat();
            Ok(())
        }
        async fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                return Err(io::Error::from_raw_os_error(libc::ENOSPC));
            }
            Ok(())
        }
    }

    async fn drain_into(
        storage: FailingStorage,
        output: Vec<u8>,
        limit: usize,
    ) -> (io::Result<()>, FailingStorage) {
        let (mut writer, mut input) = tokio::io::duplex(4096);
        let (_stop, mut stopping) = tokio::sync::watch::channel(false);
        let reader = tokio::spawn(async move {
            let mut storage = storage;
            let result = drain_serial(&mut input, &mut storage, &mut stopping, limit).await;
            (result, storage)
        });
        // This producer cannot finish if the drain closes or stalls on ENOSPC.
        tokio::time::timeout(std::time::Duration::from_secs(3), writer.write_all(&output))
            .await
            .unwrap()
            .unwrap();
        drop(writer);
        reader.await.unwrap()
    }

    #[tokio::test]
    async fn storage_failure_drains_the_producer_and_reports_the_original_loss() {
        for (fail_after, fail_flush) in [(0, false), (100, false), (usize::MAX, true)] {
            let storage = FailingStorage {
                content: Vec::new(),
                fail_after,
                fail_flush,
                writes: 0,
                peak: 0,
            };
            let (result, storage) = drain_into(storage, vec![b'x'; 256 * 1024], 1024).await;
            assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::ENOSPC));
            assert!(storage.content.len() <= 1024);
            if !fail_flush {
                assert!(storage.content.len() <= fail_after);
                assert!(
                    storage.writes <= 2,
                    "failed storage must not be retried per chunk"
                );
            }
        }
    }

    #[tokio::test]
    async fn overflow_keeps_the_newest_output_within_the_cap() {
        // Numbered lines expose both order and which output survived.
        let output: Vec<u8> = (0..20_000)
            .flat_map(|n| format!("{n:05}\n").into_bytes())
            .collect();
        for limit in [1024, 4096, 64 * 1024] {
            let storage = FailingStorage {
                content: Vec::new(),
                fail_after: usize::MAX,
                fail_flush: false,
                writes: 0,
                peak: 0,
            };
            let (result, storage) = drain_into(storage, output.clone(), limit).await;
            result.unwrap();
            let content = storage.content;
            assert!(content.len() <= limit, "{} > {limit}", content.len());
            assert!(content.len() > limit / 2, "a compaction kept too little");
            use husker_types::factory_limits::{SERIAL_BYTES, SERIAL_STORAGE_BYTES};
            let charged = limit * (SERIAL_STORAGE_BYTES / SERIAL_BYTES) as usize;
            assert!(
                storage.peak > limit && storage.peak <= charged,
                "compaction peak {} outside ({limit}, {charged}]",
                storage.peak
            );
            let origin = SerialLogOrigin::parse(&content).unwrap();
            assert!(origin.discarded > 0, "discard is marked");
            let tail = &content[origin.content_offset as usize..];
            assert!(
                output.ends_with(tail),
                "kept bytes are not the newest output"
            );
            assert_eq!(
                origin.discarded + tail.len() as u64,
                output.len() as u64,
                "the marker counts exactly the dropped output"
            );
        }
    }

    #[tokio::test]
    async fn output_within_the_cap_is_kept_unmarked() {
        let storage = FailingStorage {
            content: Vec::new(),
            fail_after: usize::MAX,
            fail_flush: false,
            writes: 0,
            peak: 0,
        };
        let (result, storage) = drain_into(storage, vec![b'x'; 1024], 1024).await;
        result.unwrap();
        assert_eq!(storage.content, vec![b'x'; 1024]);
    }

    #[tokio::test]
    async fn excess_serial_output_is_drained_into_a_bounded_file_ending_with_the_newest_bytes() {
        // A staging file left by a crash mid-compaction must not block the next one.
        for stale_staging in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("serial.log");
            if stale_staging {
                std::fs::write(compaction_staging_path(&path), b"stale").unwrap();
            }
            let (write, mut capture) = SerialCapture::new(&path, 1024).unwrap();
            let raw = write.try_clone().unwrap().into_raw_fd();
            let mut stream = unsafe { crate::fd_stream::FdStream::from_owned_raw_fd(raw).unwrap() };
            let mut output = vec![b'x'; 1024 * 1024];
            output.extend_from_slice(b"final line\n");
            // Every read past a cap this small compacts and syncs the log, so
            // a busy disk needs seconds; the bound only has to catch a stall.
            let stall = std::time::Duration::from_secs(30);
            tokio::time::timeout(stall, stream.write_all(&output))
                .await
                .unwrap()
                .unwrap();
            drop(stream);
            drop(write);
            tokio::time::timeout(stall, async {
                while !capture.worker.as_ref().unwrap().is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            // More than a kernel socket buffer drained even after the disk cap.
            capture.finish().await.unwrap();
            capture.finish().await.unwrap();
            let bytes = std::fs::read(&path).unwrap();
            assert!(bytes.len() <= 1024 && bytes.len() > 512);
            let origin = SerialLogOrigin::parse(&bytes).unwrap();
            let content = &bytes[origin.content_offset as usize..];
            assert_eq!(origin.discarded + content.len() as u64, output.len() as u64);
            assert!(content.ends_with(b"xfinal line\n"));
            assert!(content[..content.len() - 11].iter().all(|b| *b == b'x'));
            assert!(!compaction_staging_path(&path).exists());
        }
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

    #[tokio::test]
    async fn a_vmm_writing_one_byte_at_a_time_loses_nothing_while_the_drain_is_busy() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("serial.log");
        let (write, capture) = SerialCapture::new(&path, 1 << 20).unwrap();
        use std::os::fd::AsRawFd;
        let mut uart = write.try_clone().unwrap();
        drop(write);
        // As Firecracker's UART does: a non-blocking stdout written a byte at
        // a time, dropping what does not fit. The test body never yields, so
        // the drain cannot run until every byte has been offered.
        let fd = uart.as_raw_fd();
        assert!(
            unsafe {
                libc::fcntl(
                    fd,
                    libc::F_SETFL,
                    libc::fcntl(fd, libc::F_GETFL) | libc::O_NONBLOCK,
                )
            } >= 0
        );
        let output = numbered_lines(0..5462);
        assert!(output.len() >= 32 << 10);
        for (offset, byte) in output.iter().enumerate() {
            if let Err(error) = uart.write_all(std::slice::from_ref(byte)) {
                panic!("byte {offset} of {} dropped: {error}", output.len());
            }
        }
        drop(uart);
        let mut capture = capture;
        tokio::time::timeout(std::time::Duration::from_secs(3), capture.finish_at_eof())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), output);
    }

    /// A capture of `limit` bytes at `path` and the stream feeding it.
    fn capture_at(path: &Path, limit: usize) -> (crate::fd_stream::FdStream, SerialCapture) {
        let (write, capture) = SerialCapture::new(path, limit).unwrap();
        let raw = write.try_clone().unwrap().into_raw_fd();
        let stream = unsafe { crate::fd_stream::FdStream::from_owned_raw_fd(raw).unwrap() };
        (stream, capture)
    }

    /// Close the stream and wait until the capture stored all of it.
    async fn close(stream: crate::fd_stream::FdStream, mut capture: SerialCapture) {
        drop(stream);
        tokio::time::timeout(std::time::Duration::from_secs(3), capture.finish_at_eof())
            .await
            .unwrap()
            .unwrap();
    }

    fn numbered_lines(lines: std::ops::Range<u32>) -> Vec<u8> {
        lines
            .flat_map(|n| format!("{n:05}\n").into_bytes())
            .collect()
    }

    #[tokio::test]
    async fn a_follower_keeping_up_sees_every_byte_once_across_compactions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("serial.log");
        let (mut stream, capture) = capture_at(&path, 1024);
        let (mut follower, preload, truncated) =
            crate::serial_log::SerialFollower::start(&path, 1 << 20)
                .await
                .unwrap();
        assert!(preload.is_empty() && !truncated);
        let output = numbered_lines(0..3000);
        let mut shown = Vec::new();
        for batch in output.chunks(300) {
            stream.write_all(batch).await.unwrap();
            let expected = shown.len() + batch.len();
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                while shown.len() < expected {
                    shown.extend(follower.poll(&path).await.unwrap().unwrap());
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            })
            .await
            .unwrap();
        }
        close(stream, capture).await;
        shown.extend(follower.poll(&path).await.unwrap().unwrap());
        assert!(
            SerialLogOrigin::parse(&std::fs::read(&path).unwrap())
                .unwrap()
                .discarded
                > 8 * 1024,
            "the log must have compacted many times"
        );
        assert!(shown == output, "followed output differs from guest output");
    }

    #[tokio::test]
    async fn a_follower_that_fell_behind_is_told_exactly_how_much_it_missed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("serial.log");
        let (mut stream, capture) = capture_at(&path, 1024);
        let shown_before = numbered_lines(0..10);
        stream.write_all(&shown_before).await.unwrap();
        let (mut follower, preload) =
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                loop {
                    let (follower, preload, _) =
                        crate::serial_log::SerialFollower::start(&path, 1 << 20)
                            .await
                            .unwrap();
                    if preload.len() == shown_before.len() {
                        return (follower, preload);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            })
            .await
            .unwrap();
        assert_eq!(preload, shown_before);
        let unseen = numbered_lines(10..2000);
        stream.write_all(&unseen).await.unwrap();
        close(stream, capture).await;
        let polled = follower.poll(&path).await.unwrap().unwrap();
        let origin = SerialLogOrigin::parse(&std::fs::read(&path).unwrap()).unwrap();
        let missed = origin.discarded - shown_before.len() as u64;
        let notice =
            format!("\n[... {missed} serial bytes discarded before they were shown ...]\n");
        let rest = polled
            .strip_prefix(notice.as_bytes())
            .expect("missed output is announced");
        assert_eq!(rest, &unseen[missed as usize..]);
        assert_eq!(follower.poll(&path).await.unwrap().unwrap(), b"");
    }

    #[tokio::test]
    async fn a_follower_announces_a_new_boot_log_shorter_or_longer_than_the_last() {
        let boots = [
            &b"short\n"[..],
            b"a second boot printing more than the first did\n",
        ];
        for (next_boot, reused_inode) in boots
            .into_iter()
            .flat_map(|boot| [(boot, false), (boot, true)])
        {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("serial.log");
            let (mut stream, capture) = capture_at(&path, 1024);
            stream.write_all(b"first boot\n").await.unwrap();
            close(stream, capture).await;
            let (mut follower, _, _) = crate::serial_log::SerialFollower::start(&path, 1 << 20)
                .await
                .unwrap();
            // As `for_child` does: the new boot's log replaces the old file.
            // Linux can hand the new file the old one's inode number, which
            // rewriting the same file in place reproduces.
            let next_path = dir.path().join("next-serial.log");
            let (mut stream, capture) = capture_at(&next_path, 1024);
            stream.write_all(next_boot).await.unwrap();
            close(stream, capture).await;
            if reused_inode {
                std::fs::write(&path, std::fs::read(&next_path).unwrap()).unwrap();
            } else {
                std::fs::rename(&next_path, &path).unwrap();
            }
            let polled = follower.poll(&path).await.unwrap().unwrap();
            assert_eq!(
                polled,
                [&b"\n[... serial log restarted ...]\n"[..], next_boot].concat(),
                "reused inode {reused_inode}: {}",
                String::from_utf8_lossy(&polled)
            );
            std::fs::remove_file(&path).unwrap();
            assert!(follower.poll(&path).await.unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn a_follower_announces_a_new_boot_that_repeats_the_last_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("serial.log");
        let (mut stream, capture) = capture_at(&path, 1024);
        stream.write_all(b"identical boot banner\n").await.unwrap();
        close(stream, capture).await;
        let (mut follower, _, _) = crate::serial_log::SerialFollower::start(&path, 1 << 20)
            .await
            .unwrap();
        // A new file whose bytes up to the follower's position match what it
        // already showed: only the file's identity reveals the restart. It is
        // created before the old one goes, so the two inodes differ.
        let next_path = dir.path().join("next-serial.log");
        let (mut stream, capture) = capture_at(&next_path, 1024);
        stream
            .write_all(b"identical boot banner\nthen it diverges\n")
            .await
            .unwrap();
        close(stream, capture).await;
        std::fs::rename(&next_path, &path).unwrap();
        let polled = follower.poll(&path).await.unwrap().unwrap();
        assert_eq!(
            polled,
            b"\n[... serial log restarted ...]\nidentical boot banner\nthen it diverges\n",
            "{}",
            String::from_utf8_lossy(&polled)
        );
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
