//! Async PTY (pseudo-terminal) support.
//!
//! Opens a PTY master/slave pair via `openpty(3)`. The master is wrapped with
//! tokio's `AsyncFd` for non-blocking I/O. The slave `OwnedFd` is passed to
//! the child process as its controlling terminal.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Async wrapper around a PTY master file descriptor.
pub struct Pty {
    fd: AsyncFd<OwnedFd>,
}

impl Pty {
    /// Open a PTY pair with the given initial window size.
    ///
    /// Returns `(master, slave)` where:
    /// - `master` is the async PTY for reading output and writing input
    /// - `slave` is the raw fd to pass to the child process as stdin/stdout/stderr
    pub fn open(cols: u16, rows: u16) -> io::Result<(Self, OwnedFd)> {
        let mut master_fd: libc::c_int = 0;
        let mut slave_fd: libc::c_int = 0;
        let mut ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        // Safety: openpty writes two valid fds on success. We pass null for
        // name and termp since we don't need the slave path or custom termios.
        // The winsize pointer uses `addr_of_mut!` because the libc signature is
        // `*mut winsize` on BSD/macOS and `*const winsize` on Linux (`*mut`
        // coerces to `*const`).
        let ret = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::addr_of_mut!(ws),
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        // Set master to non-blocking for async I/O.
        // Safety: fcntl on a valid fd returned by openpty.
        unsafe {
            let flags = libc::fcntl(master_fd, libc::F_GETFL);
            if flags < 0 {
                libc::close(master_fd);
                libc::close(slave_fd);
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(master_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                libc::close(master_fd);
                libc::close(slave_fd);
                return Err(io::Error::last_os_error());
            }
        }

        // Safety: both fds are valid, open descriptors from openpty.
        let master = unsafe { OwnedFd::from_raw_fd(master_fd) };
        let slave = unsafe { OwnedFd::from_raw_fd(slave_fd) };

        let async_master = AsyncFd::new(master)?;
        Ok((Self { fd: async_master }, slave))
    }

    /// Resize the PTY window.
    pub fn resize(&self, cols: u16, rows: u16) -> io::Result<()> {
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // Safety: TIOCSWINSZ on the master fd sets the window size for the
        // terminal, which the shell can observe via SIGWINCH.
        let ret = unsafe { libc::ioctl(self.fd.get_ref().as_raw_fd(), libc::TIOCSWINSZ, &ws) };
        if ret != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn raw_fd(&self) -> RawFd {
        self.fd.get_ref().as_raw_fd()
    }
}

impl AsRawFd for Pty {
    fn as_raw_fd(&self) -> RawFd {
        self.raw_fd()
    }
}

impl AsyncRead for Pty {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.fd.poll_read_ready(cx))?;
            match guard.try_io(|_| {
                let b = buf.initialize_unfilled();
                // Safety: valid fd, valid buffer.
                let n = unsafe {
                    libc::read(
                        self.raw_fd(),
                        b.as_mut_ptr().cast::<libc::c_void>(),
                        b.len(),
                    )
                };
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

impl AsyncWrite for Pty {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.fd.poll_write_ready(cx))?;
            match guard.try_io(|_| {
                // Safety: valid fd, valid buffer.
                let n = unsafe {
                    libc::write(
                        self.raw_fd(),
                        buf.as_ptr().cast::<libc::c_void>(),
                        buf.len(),
                    )
                };
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
        Poll::Ready(Ok(()))
    }
}
