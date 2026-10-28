//! Conservative VMM matching; a UUID appearing in unrelated argv is insufficient.
//!
//! Identity is the exact VMM flag followed by an absolute path named for the
//! VM's UUID, as separate argv entries. The executable name is deliberately not
//! part of it: operators configure arbitrary VMM paths, and a binary replaced
//! while its VM runs reports `<path> (deleted)`. Missing either would leave a
//! live VMM unmanaged once startup marks its record stopped.
use std::path::Path;
use uuid::Uuid;

pub(crate) fn matches_vmm(id: Uuid, cmdline: &[u8]) -> bool {
    if id.is_nil() || cmdline.len() > 65536 {
        return false;
    }
    let file_matches = |bytes: &[u8], suffix: &str| {
        std::str::from_utf8(bytes).ok().is_some_and(|path| {
            Path::new(path).is_absolute()
                && Path::new(path)
                    .file_name()
                    .is_some_and(|name| name == format!("{id}.{suffix}").as_str())
        })
    };
    cmdline
        .split(|byte| *byte == 0)
        .collect::<Vec<_>>()
        .windows(2)
        .any(|args| {
            (args[0] == b"--api-sock" && file_matches(args[1], "sock"))
                || (args[0] == b"-pidfile" && file_matches(args[1], "pid"))
        })
}

#[cfg(target_os = "linux")]
pub(crate) fn pending_match(pid: u32, ids: &std::collections::HashSet<Uuid>) -> Option<Uuid> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let directory = format!("/proc/{pid}");
    if std::fs::metadata(&directory).ok()?.uid() != unsafe { libc::geteuid() } {
        return None;
    }
    let mut cmdline = Vec::new();
    std::fs::File::open(format!("{directory}/cmdline"))
        .ok()?
        .take(65537)
        .read_to_end(&mut cmdline)
        .ok()?;
    ids.iter().copied().find(|id| matches_vmm(*id, &cmdline))
}

#[cfg(target_os = "linux")]
pub(crate) fn reap(id: Uuid, pid: u32) -> bool {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::MetadataExt;
    if pid == 0 || pid > i32::MAX as u32 || pid == std::process::id() {
        return false;
    }
    // Open the process handle BEFORE inspecting /proc. Signalling this handle
    // cannot target a replacement PID; unavailable pidfds fail closed.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0u32) };
    if raw < 0 {
        return false;
    }
    let process = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    let directory = format!("/proc/{pid}");
    let Ok(metadata) = std::fs::metadata(&directory) else {
        return false;
    };
    if metadata.uid() != unsafe { libc::geteuid() } {
        return false;
    }
    // Read bounded proc bytes, never a potentially huge argv allocation.
    use std::io::Read;
    let Ok(file) = std::fs::File::open(format!("{directory}/cmdline")) else {
        return false;
    };
    let mut cmdline = Vec::new();
    if file.take(65537).read_to_end(&mut cmdline).is_err() || !matches_vmm(id, &cmdline) {
        return false;
    }
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            process.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0u32,
        )
    } != 0
    {
        return false;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let mut poll = libc::pollfd {
            fd: process.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        let result = unsafe { libc::poll(&mut poll, 1, remaining.as_millis().min(2000) as i32) };
        if result > 0 {
            return poll.revents & (libc::POLLIN | libc::POLLHUP) != 0;
        }
        if result == 0 {
            return false;
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_uuid_named_flag_arguments_match_under_any_executable() {
        let id = Uuid::new_v4();
        for argv in [
            format!("firecracker\0--api-sock\0/run/{id}.sock\0"),
            format!("/opt/bin/fc\0--api-sock\0/run/{id}.sock\0"),
            format!("qemu-system-aarch64\0-pidfile\0/run/{id}.pid\0"),
        ] {
            assert!(matches_vmm(id, argv.as_bytes()), "{argv:?}");
        }
        for argv in [
            format!("firecracker\0--log-path\0/run/{id}.sock\0"),
            format!("firecracker\0--api-sock\0{id}.sock\0"),
            format!("firecracker\0--api-sock\0/run/{id}.sock.backup\0"),
            format!("firecracker\0--api-sock\0/run/prefix-{id}.sock\0"),
            format!("firecracker\0--api-sock\0/run/{id}.pid\0"),
            format!("qemu-system-aarch64\0-pidfile\0/run/{id}.sock\0"),
            // A shell holding the whole command line as one argument.
            format!("sh\0-c\0firecracker --api-sock /run/{id}.sock\0"),
        ] {
            assert!(!matches_vmm(id, argv.as_bytes()), "{argv:?}");
        }
        let qemu = format!("qemu-system-aarch64\0-pidfile\0/run/{id}.pid\0");
        assert!(!matches_vmm(Uuid::new_v4(), qemu.as_bytes()));
        assert!(!matches_vmm(Uuid::nil(), qemu.as_bytes()));
    }
}
