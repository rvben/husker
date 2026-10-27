//! Guest power control behind the host's `Shutdown` request.
//!
//! The host names the power action its VMM exits on (Firecracker exits when
//! the guest reboots, QEMU and Apple VZ when it powers off). The connection
//! loop answers with the action the agent will actually take and applies it
//! once the host has read the acknowledgement. The kernel is reachable only
//! through the vsock listeners, which serve a real guest; the Unix-socket
//! listener, the embedder entry point and every test run with
//! [`NoPowerControl`], so no code path a host test can reach ever flushes,
//! unmounts, remounts or reboots the machine the test runs on.

use husker_agent_proto::GuestPowerAction;

/// What the agent does with guest storage and guest power on `Shutdown`.
pub trait PowerControl: Send + Sync {
    /// Make everything the guest has written durable and decide what happens
    /// to guest power once the host has read the acknowledgement: `requested`
    /// when this control can carry it out, [`GuestPowerAction::Flush`] when it
    /// cannot. Runs before the acknowledgement is sent, so the host never sees
    /// `ShuttingDown` for a guest whose pages are still dirty.
    fn prepare(&self, requested: GuestPowerAction) -> GuestPowerAction;

    /// Carry out an action `prepare` returned other than `Flush`. On success
    /// the guest ends and this never returns; it returns only on failure, after
    /// which the host ends the VM itself when its exit wait runs out.
    fn apply(&self, action: GuestPowerAction);
}

/// No access to guest storage or power: every `Shutdown` is answered with
/// `Flush` and nothing is applied. Used wherever the agent serves on a host,
/// which is every path a test can reach.
pub struct NoPowerControl;

impl PowerControl for NoPowerControl {
    fn prepare(&self, _requested: GuestPowerAction) -> GuestPowerAction {
        GuestPowerAction::Flush
    }

    fn apply(&self, _action: GuestPowerAction) {}
}

/// The kernel of a real guest: `sync(2)`, `umount2(2)`, `mount(2)` and
/// `reboot(2)` on Linux, `sync(2)` and the system `shutdown` utility on macOS.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub struct KernelPowerControl;

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl PowerControl for KernelPowerControl {
    fn prepare(&self, requested: GuestPowerAction) -> GuestPowerAction {
        flush_guest_storage();
        requested
    }

    fn apply(&self, action: GuestPowerAction) {
        if let Err(error) = end_guest(action) {
            tracing::error!(?action, "guest power action failed: {error}");
        }
    }
}

/// Flush all dirty pages to disk, then best-effort-unmount `/data` (the
/// auto-mounted volume) and any virtiofs shares mounted by the supervisor.
///
/// Runs on `Shutdown` so that writes to named volumes are durable whatever
/// ends the VM afterwards. All unmount errors are ignored: a `sync()` before
/// any `umount2()` is the durability guarantee, and a lazy detach
/// (`MNT_DETACH`) is sufficient even when the umount itself fails.
#[cfg(target_os = "linux")]
fn flush_guest_storage() {
    // SAFETY: sync() takes no pointers and has no preconditions; it queues
    // all dirty page-cache and buffer-cache writes to their respective block
    // devices and waits for completion.
    unsafe { libc::sync() };

    // Best-effort lazy unmount of the auto-mounted data volume.
    let data = std::ffi::CString::new("/data").expect("no NUL in /data");
    // SAFETY: data is a valid CString held for the call; MNT_DETACH detaches
    // the mount from the name-space immediately and waits for all in-flight
    // I/O (already flushed by sync) to drain before freeing the superblock.
    unsafe { libc::umount2(data.as_ptr(), libc::MNT_DETACH) };

    // Best-effort lazy unmount of virtiofs shares the supervisor mounted.
    // Errors are ignored: the sync above is the durability guarantee.
    if let Ok(cmdline) = std::fs::read_to_string("/proc/cmdline") {
        for (_tag, path, _ro) in crate::supervisor::parse_shares(&cmdline) {
            if let Ok(cpath) = std::ffi::CString::new(path.as_str()) {
                // SAFETY: cpath is a valid CString held for the call.
                unsafe { libc::umount2(cpath.as_ptr(), libc::MNT_DETACH) };
            }
        }
    }
}

/// Flush all dirty pages to disk. A macOS guest mounts no husker volume, so
/// there is nothing to detach.
#[cfg(target_os = "macos")]
fn flush_guest_storage() {
    // SAFETY: sync() takes no pointers and has no preconditions.
    unsafe { libc::sync() };
}

/// Ask the kernel to end the guest. `reboot(2)` with `RB_AUTOBOOT` or
/// `RB_POWER_OFF` acts immediately and without unmounting, which is why the
/// pages were flushed first; it returns only on failure, with errno set.
///
/// Between the flush and the reboot the root filesystem is remounted
/// read-only. Ending the kernel without that leaves ext4's `needs_recovery`
/// flag set on the rootfs clone, so every later reader (the next boot, or the
/// host's e2fsprogs before it edits or commits the clone) first replays a
/// journal that holds nothing. The remount commits the journal and clears the
/// flag, leaving the clone clean. It is best effort: a guest with files still
/// open for writing (a systemd guest's journald, a running session) answers
/// `EBUSY`, and the stop proceeds exactly as before. A guest whose `reboot(2)`
/// fails (an agent without `CAP_SYS_BOOT`) lives on until the host ends it,
/// so it gets its writable root back before the failure is reported.
#[cfg(target_os = "linux")]
fn end_guest(action: GuestPowerAction) -> std::io::Result<()> {
    let command = match action {
        GuestPowerAction::Flush => return Ok(()),
        GuestPowerAction::Reboot => libc::RB_AUTOBOOT,
        GuestPowerAction::PowerOff => libc::RB_POWER_OFF,
    };
    // SAFETY: sync() takes no pointers and has no preconditions.
    unsafe { libc::sync() };
    let read_only = remount_root(libc::MS_RDONLY);
    if let Err(error) = &read_only {
        tracing::debug!("root filesystem stays writable until the kernel ends: {error}");
    }
    // SAFETY: reboot() takes no pointers and does not return on success.
    if unsafe { libc::reboot(command) } < 0 {
        let error = std::io::Error::last_os_error();
        if read_only.is_ok()
            && let Err(undo) = remount_root(0)
        {
            tracing::warn!("root filesystem stays read-only after the failed power action: {undo}");
        }
        return Err(error);
    }
    Ok(())
}

/// Remount the root filesystem in place with `flags` on top of `MS_REMOUNT`:
/// `MS_RDONLY` makes it read-only, no flag makes it writable again. The
/// kernel keeps the source, type and options of the existing mount.
#[cfg(target_os = "linux")]
fn remount_root(flags: libc::c_ulong) -> std::io::Result<()> {
    let root = c"/";
    // SAFETY: `mount` with `MS_REMOUNT` reads only the target path, held for
    // the call; the source, filesystem type and data pointers may be null.
    let status = unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            libc::MS_REMOUNT | flags,
            std::ptr::null(),
        )
    };
    if status < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Ask the system to end the guest through `shutdown`, which runs macOS's own
/// orderly shutdown (its unmounts included). The agent runs as root under its
/// LaunchDaemon, which is the privilege `shutdown` needs. The child is not
/// awaited: it ends this process along with everything else.
#[cfg(target_os = "macos")]
fn end_guest(action: GuestPowerAction) -> std::io::Result<()> {
    let flag = match action {
        GuestPowerAction::Flush => return Ok(()),
        GuestPowerAction::Reboot => "-r",
        GuestPowerAction::PowerOff => "-h",
    };
    std::process::Command::new("/sbin/shutdown")
        .args([flag, "now"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_power_control_plans_a_flush_whatever_the_host_asks() {
        for requested in [
            GuestPowerAction::Flush,
            GuestPowerAction::Reboot,
            GuestPowerAction::PowerOff,
        ] {
            assert_eq!(NoPowerControl.prepare(requested), GuestPowerAction::Flush);
        }
    }
}
