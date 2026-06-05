//! Async stream over an owned file descriptor.
//!
//! Wraps an `OwnedFd` with tokio's `AsyncFd` for non-blocking I/O.
//! This is pure Unix fd I/O with no platform-specific VMM code, so it
//! compiles and is testable on any Unix target (Linux CI included).

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Async stream wrapping an owned file descriptor.
///
/// The fd is set to non-blocking mode and registered with the tokio reactor
/// via `AsyncFd`. Reads and writes use `libc::read`/`libc::write` directly.
pub struct FdStream {
    fd: AsyncFd<OwnedFd>,
}

impl FdStream {
    /// Create from a raw file descriptor by duplicating it.
    ///
    /// The original fd remains owned by the caller. The duplicate is set to
    /// non-blocking mode and wrapped for async I/O.
    ///
    /// # Errors
    ///
    /// Returns an error if `dup(2)`, `fcntl(2)`, or tokio registration fails.
    pub fn from_dup_raw_fd(raw_fd: RawFd) -> io::Result<Self> {
        // Safety: dup(2) returns a new fd or -1 on error. We check the return
        // value before using it.
        let dup_fd = unsafe { libc::dup(raw_fd) };
        if dup_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safety: dup_fd is a valid, open fd that we own (from dup above).
        unsafe { Self::from_owned_raw_fd(dup_fd) }
    }

    /// Create from a raw file descriptor, taking ownership.
    ///
    /// The fd is set to non-blocking mode and registered with the tokio reactor.
    /// On error the fd is closed to avoid leaking it.
    ///
    /// # Safety
    ///
    /// The caller must ensure `raw_fd` is a valid, open file descriptor that
    /// they own exclusively. The fd must not be used or closed by the caller
    /// after this call.
    pub unsafe fn from_owned_raw_fd(raw_fd: RawFd) -> io::Result<Self> {
        // Safety: fcntl(2) with F_GETFL/F_SETFL to enable O_NONBLOCK.
        // On error we close the fd to avoid leaking it.
        unsafe {
            let flags = libc::fcntl(raw_fd, libc::F_GETFL);
            if flags < 0 {
                libc::close(raw_fd);
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                libc::close(raw_fd);
                return Err(io::Error::last_os_error());
            }

            // raw_fd is a valid, open fd that we own (caller's contract).
            let owned = OwnedFd::from_raw_fd(raw_fd);
            let async_fd = AsyncFd::new(owned)?;
            Ok(Self { fd: async_fd })
        }
    }
}

impl AsyncRead for FdStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.fd.poll_read_ready(cx))?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let b = buf.initialize_unfilled();
                // Safety: fd is a valid open descriptor (owned by AsyncFd).
                // b is a valid, writable buffer. read(2) returns bytes read or -1.
                let n = unsafe { libc::read(fd, b.as_mut_ptr().cast::<libc::c_void>(), b.len()) };
                if n >= 0 {
                    Ok(n as usize)
                } else {
                    Err(io::Error::last_os_error())
                }
            }) {
                Ok(result) => {
                    let n = result?;
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for FdStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.fd.poll_write_ready(cx))?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                // Safety: fd is a valid open descriptor. buf is a valid readable
                // slice. write(2) returns bytes written or -1.
                let n = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
                if n >= 0 {
                    Ok(n as usize)
                } else {
                    Err(io::Error::last_os_error())
                }
            }) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let fd = self.fd.get_ref().as_raw_fd();
        // Safety: fd is valid. shutdown(2) with SHUT_WR signals write-end close.
        let result = unsafe { libc::shutdown(fd, libc::SHUT_WR) };
        if result == 0 {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(io::Error::last_os_error()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Create a Unix socket pair and return both ends as OwnedFds.
    ///
    /// Uses `socketpair(2)` rather than `pipe(2)` because `FdStream::poll_shutdown`
    /// calls `shutdown(2)`, which is only valid on sockets.
    fn make_socket_pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [0i32; 2];
        // Safety: socketpair(2) writes two valid socket fds on success.
        let ret =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "socketpair(2) failed");
        // Safety: fds are valid open socket descriptors from socketpair(2).
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    #[tokio::test]
    async fn read_write_roundtrip() {
        let (fd_a, fd_b) = make_socket_pair();
        let mut stream_a = FdStream::from_dup_raw_fd(fd_a.as_raw_fd()).unwrap();
        let mut stream_b = FdStream::from_dup_raw_fd(fd_b.as_raw_fd()).unwrap();
        drop(fd_a);
        drop(fd_b);

        stream_a.write_all(b"hello").await.unwrap();
        stream_a.shutdown().await.unwrap();

        let mut buf = vec![0u8; 16];
        let n = stream_b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[tokio::test]
    async fn dup_independence() {
        let (fd_a, fd_b) = make_socket_pair();
        let mut stream_a = FdStream::from_dup_raw_fd(fd_a.as_raw_fd()).unwrap();
        let mut stream_b = FdStream::from_dup_raw_fd(fd_b.as_raw_fd()).unwrap();

        // Close the originals — streams should still work via their dup'd fds
        drop(fd_a);
        drop(fd_b);

        stream_a.write_all(b"after-close").await.unwrap();
        stream_a.shutdown().await.unwrap();

        let mut buf = String::new();
        stream_b.read_to_string(&mut buf).await.unwrap();
        assert_eq!(buf, "after-close");
    }

    #[test]
    fn invalid_fd_returns_error() {
        let result = FdStream::from_dup_raw_fd(-1);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn from_owned_raw_fd_roundtrip() {
        let (fd_a, fd_b) = make_socket_pair();
        // Dup manually, then pass the dup'd fd as owned
        let dup_a = unsafe { libc::dup(fd_a.as_raw_fd()) };
        let dup_b = unsafe { libc::dup(fd_b.as_raw_fd()) };
        assert!(dup_a >= 0);
        assert!(dup_b >= 0);
        drop(fd_a);
        drop(fd_b);

        let mut stream_a = unsafe { FdStream::from_owned_raw_fd(dup_a).unwrap() };
        let mut stream_b = unsafe { FdStream::from_owned_raw_fd(dup_b).unwrap() };

        stream_a.write_all(b"owned-fd-test").await.unwrap();
        stream_a.shutdown().await.unwrap();

        let mut buf = String::new();
        stream_b.read_to_string(&mut buf).await.unwrap();
        assert_eq!(buf, "owned-fd-test");
    }

    #[test]
    fn from_owned_raw_fd_invalid_returns_error() {
        let result = unsafe { FdStream::from_owned_raw_fd(-1) };
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn large_transfer() {
        let (fd_a, fd_b) = make_socket_pair();
        let mut writer = FdStream::from_dup_raw_fd(fd_a.as_raw_fd()).unwrap();
        let mut reader = FdStream::from_dup_raw_fd(fd_b.as_raw_fd()).unwrap();
        drop(fd_a);
        drop(fd_b);

        let data: Vec<u8> = (0..65536).map(|i| (i % 251) as u8).collect();
        let expected = data.clone();

        // Write in a separate task to avoid deadlock (socket buffer is limited)
        let write_handle = tokio::spawn(async move {
            writer.write_all(&data).await.unwrap();
            writer.shutdown().await.unwrap();
        });

        let mut received = Vec::new();
        reader.read_to_end(&mut received).await.unwrap();
        write_handle.await.unwrap();

        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn shutdown_signals_eof() {
        let (fd_a, fd_b) = make_socket_pair();
        let mut writer = FdStream::from_dup_raw_fd(fd_a.as_raw_fd()).unwrap();
        let mut reader = FdStream::from_dup_raw_fd(fd_b.as_raw_fd()).unwrap();
        drop(fd_a);
        drop(fd_b);

        writer.write_all(b"data").await.unwrap();
        writer.shutdown().await.unwrap();

        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"data");
    }

    #[tokio::test]
    async fn concurrent_sequential_writes() {
        let (fd_a, fd_b) = make_socket_pair();
        let mut writer = FdStream::from_dup_raw_fd(fd_a.as_raw_fd()).unwrap();
        let mut reader = FdStream::from_dup_raw_fd(fd_b.as_raw_fd()).unwrap();
        drop(fd_a);
        drop(fd_b);

        let write_handle = tokio::spawn(async move {
            for i in 0u8..100 {
                writer.write_all(&[i]).await.unwrap();
            }
            writer.shutdown().await.unwrap();
        });

        let mut received = Vec::new();
        reader.read_to_end(&mut received).await.unwrap();
        write_handle.await.unwrap();

        let expected: Vec<u8> = (0u8..100).collect();
        assert_eq!(received, expected);
    }
}
