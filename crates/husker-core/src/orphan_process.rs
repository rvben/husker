//! Conservative VMM matching; a UUID appearing in unrelated argv is insufficient.
use std::path::Path;
use uuid::Uuid;

pub(crate) fn matches_vmm(id: Uuid, executable: &Path, cmdline: &[u8]) -> bool {
    if id.is_nil() || cmdline.len() > 65536 {
        return false;
    }
    let Some(name) = executable.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let args = cmdline.split(|byte| *byte == 0).collect::<Vec<_>>();
    let file_matches = |bytes: &[u8], suffix: &str| {
        std::str::from_utf8(bytes).ok().is_some_and(|path| {
            Path::new(path).is_absolute()
                && Path::new(path)
                    .file_name()
                    .is_some_and(|name| name == format!("{id}.{suffix}").as_str())
        })
    };
    if name == "firecracker" || name.starts_with("firecracker-v") {
        return args
            .windows(2)
            .any(|args| args[0] == b"--api-sock" && file_matches(args[1], "sock"));
    }
    if name.starts_with("qemu-system-") {
        return args
            .windows(2)
            .any(|args| args[0] == b"-pidfile" && file_matches(args[1], "pid"));
    }
    false
}

#[cfg(target_os = "linux")]
pub(crate) fn pending_match(pid: u32, ids: &std::collections::HashSet<Uuid>) -> Option<Uuid> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let directory = format!("/proc/{pid}");
    if std::fs::metadata(&directory).ok()?.uid() != unsafe { libc::geteuid() } {
        return None;
    }
    let executable = std::fs::read_link(format!("{directory}/exe")).ok()?;
    let name = executable.file_name()?.to_str()?;
    if name != "firecracker"
        && !name.starts_with("firecracker-v")
        && !name.starts_with("qemu-system-")
    {
        return None;
    }
    let mut cmdline = Vec::new();
    std::fs::File::open(format!("{directory}/cmdline"))
        .ok()?
        .take(65537)
        .read_to_end(&mut cmdline)
        .ok()?;
    ids.iter()
        .copied()
        .find(|id| matches_vmm(*id, &executable, &cmdline))
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
    let Ok(executable) = std::fs::read_link(format!("{directory}/exe")) else {
        return false;
    };
    // Read bounded proc bytes, never a potentially huge argv allocation.
    use std::io::Read;
    let Ok(file) = std::fs::File::open(format!("{directory}/cmdline")) else {
        return false;
    };
    let mut cmdline = Vec::new();
    if file.take(65537).read_to_end(&mut cmdline).is_err()
        || !matches_vmm(id, &executable, &cmdline)
    {
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
    fn uuid_mentions_wrong_executables_flags_relative_paths_and_filename_suffixes_cannot_match() {
        let id = Uuid::new_v4();
        let correct = format!("firecracker\0--api-sock\0/run/{id}.sock\0");
        assert!(matches_vmm(
            id,
            Path::new("/usr/bin/firecracker"),
            correct.as_bytes()
        ));
        assert!(!matches_vmm(id, Path::new("/bin/sh"), correct.as_bytes()));
        for args in [
            format!("firecracker\0--log-path\0/run/{id}.sock\0"),
            format!("firecracker\0--api-sock\0{id}.sock\0"),
            format!("firecracker\0--api-sock\0/run/{id}.sock.backup\0"),
            format!("firecracker\0--api-sock\0/run/prefix-{id}.sock\0"),
        ] {
            assert!(!matches_vmm(
                id,
                Path::new("/usr/bin/firecracker"),
                args.as_bytes()
            ));
        }
        let qemu = format!("qemu-system-aarch64\0-pidfile\0/run/{id}.pid\0");
        assert!(matches_vmm(
            id,
            Path::new("/usr/bin/qemu-system-aarch64"),
            qemu.as_bytes()
        ));
        assert!(!matches_vmm(
            Uuid::new_v4(),
            Path::new("/usr/bin/qemu-system-aarch64"),
            qemu.as_bytes()
        ));
    }
}
