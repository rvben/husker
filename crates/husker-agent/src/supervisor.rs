//! Guest init/supervisor: the minimal PID-1 duties that let an arbitrary OCI
//! rootfs boot in a husker microVM. This module covers the filesystem and device
//! setup; networking and child supervision are layered on top.
//!
//! These functions are only meaningful when the agent is PID 1 (see
//! [`crate::is_supervisor_mode`]) and use raw `libc` syscalls (matching the rest
//! of the codebase) because the rootfs may be distroless (no shell, no `mount`).

use std::ffi::CString;
use std::io;
use std::path::Path;

use tracing::{info, warn};

/// A pseudo-filesystem the supervisor mounts during init.
pub struct MountSpec {
    pub source: &'static str,
    pub target: &'static str,
    pub fstype: &'static str,
    /// A critical mount failing aborts init (the supervisor reboots the guest);
    /// a best-effort mount failing is logged and skipped.
    pub critical: bool,
}

/// The pseudo-filesystems to mount, in order. `/proc` and `/dev` are critical
/// (cmdline parsing and device nodes depend on them); the rest are best-effort.
pub fn mount_plan() -> Vec<MountSpec> {
    vec![
        MountSpec { source: "proc", target: "/proc", fstype: "proc", critical: true },
        MountSpec { source: "devtmpfs", target: "/dev", fstype: "devtmpfs", critical: true },
        MountSpec { source: "sysfs", target: "/sys", fstype: "sysfs", critical: false },
        MountSpec { source: "devpts", target: "/dev/pts", fstype: "devpts", critical: false },
        MountSpec { source: "tmpfs", target: "/tmp", fstype: "tmpfs", critical: false },
        MountSpec { source: "tmpfs", target: "/run", fstype: "tmpfs", critical: false },
        MountSpec { source: "cgroup2", target: "/sys/fs/cgroup", fstype: "cgroup2", critical: false },
    ]
}

fn mount_one(spec: &MountSpec) -> io::Result<()> {
    // Create the mount point (a distroless rootfs may lack /proc, /sys, ...).
    let _ = std::fs::create_dir_all(spec.target);
    let source = CString::new(spec.source).expect("static source has no NUL");
    let target = CString::new(spec.target).expect("static target has no NUL");
    let fstype = CString::new(spec.fstype).expect("static fstype has no NUL");
    // SAFETY: all three pointers are valid CStrings held for the call; flags are
    // none and the data pointer is null (no fs-specific options).
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Mount the pseudo-filesystems. Returns `Err` only when a *critical* mount fails
/// (other than "already mounted") so the caller can reboot; best-effort failures
/// are logged and skipped.
pub fn mount_all() -> io::Result<()> {
    for spec in mount_plan() {
        match mount_one(&spec) {
            Ok(()) => info!("mounted {} on {}", spec.fstype, spec.target),
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {
                // Already mounted (e.g. the kernel mounted /proc) - fine.
            }
            Err(e) if spec.critical => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("critical mount {} on {} failed: {e}", spec.fstype, spec.target),
                ));
            }
            Err(e) => warn!(
                "skipping best-effort mount {} on {}: {e}",
                spec.fstype, spec.target
            ),
        }
    }
    Ok(())
}

/// Core character device nodes as `(path, major, minor)`. devtmpfs normally
/// creates these; we backfill any missing so workloads and PTYs work even on a
/// rootfs that shipped a bare `/dev`.
const DEVICE_NODES: &[(&str, u32, u32)] = &[
    ("/dev/null", 1, 3),
    ("/dev/zero", 1, 5),
    ("/dev/full", 1, 7),
    ("/dev/random", 1, 8),
    ("/dev/urandom", 1, 9),
    ("/dev/tty", 5, 0),
    ("/dev/console", 5, 1),
];

/// Create any missing core character device nodes.
pub fn ensure_device_nodes() {
    for (path, major, minor) in DEVICE_NODES {
        if Path::new(path).exists() {
            continue;
        }
        let cpath = CString::new(*path).expect("static path has no NUL");
        let dev = libc::makedev(*major, *minor);
        let mode = libc::S_IFCHR | 0o666;
        // SAFETY: cpath is a valid CString held for the call; mode encodes a
        // character device with 0666 perms; dev is a valid device number.
        let rc = unsafe { libc::mknod(cpath.as_ptr(), mode, dev) };
        if rc != 0 {
            warn!("could not create {path}: {}", io::Error::last_os_error());
        }
    }
}

/// Reboot the guest immediately. Used when a critical init step fails: the host
/// observes the VM exit and reports it, rather than the guest half-booting and
/// accepting vsock while workloads mysteriously fail. Never returns.
pub fn reboot_now() -> ! {
    // SAFETY: sync() and reboot(RB_AUTOBOOT) take no pointers; reboot only
    // returns on error.
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_AUTOBOOT);
    }
    // If reboot somehow returns, PID 1 must never exit - spin instead.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_plan_marks_proc_and_dev_critical() {
        let plan = mount_plan();
        let critical: Vec<&str> = plan.iter().filter(|m| m.critical).map(|m| m.target).collect();
        assert_eq!(critical, vec!["/proc", "/dev"]);
        assert!(
            plan.iter()
                .any(|m| m.target == "/run" && m.fstype == "tmpfs" && !m.critical),
            "/run is a best-effort tmpfs"
        );
        assert!(
            plan.iter()
                .any(|m| m.target == "/sys/fs/cgroup" && m.fstype == "cgroup2"),
            "cgroup2 is mounted"
        );
        assert!(
            plan.iter().all(|m| m.target.starts_with('/')),
            "mount targets are absolute"
        );
    }
}
