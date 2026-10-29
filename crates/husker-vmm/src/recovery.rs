//! Durable identity for supervised, offline Firecracker factory generations.
//! Old allocations without a receipt stay pending. PID reuse proves the old
//! process ended; it never authorizes signalling the replacement process.
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{VmInfo, VmmError};

fn failure(message: impl std::fmt::Display) -> VmmError {
    VmmError::ProcessError(format!("factory recovery: {message}"))
}

fn boot_id() -> Result<String, VmmError> {
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    Uuid::parse_str(value.trim()).map_err(failure)?;
    Ok(value.trim().to_owned())
}

fn start_time(stat: &str) -> Result<u64, VmmError> {
    // comm may contain spaces and ')'. Field 22 follows the final ')'.
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| failure("invalid process birth time"))
}

fn process_start(pid: u32) -> Result<Option<u64>, VmmError> {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => start_time(&stat).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Receipt {
    version: u32,
    id: Uuid,
    name: String,
    cid: u32,
    boot: String,
    pid: u32,
    start: u64,
    uid: u32,
    pid_namespace: u64,
    cgroup: PathBuf,
    cgroup_inode: u64,
}

impl Receipt {
    pub(crate) fn capture(info: &VmInfo, cgroup: &Path) -> Result<Self, VmmError> {
        let pid = info
            .pid
            .ok_or_else(|| failure("missing process identity"))?;
        let start = process_start(pid)?.ok_or_else(|| failure("process already exited"))?;
        let metadata = std::fs::symlink_metadata(cgroup)?;
        if !metadata.is_dir() {
            return Err(failure("invalid cgroup"));
        }
        Ok(Self {
            version: 1,
            id: info.id,
            name: info.name.clone(),
            cid: info.vsock_cid,
            boot: boot_id()?,
            pid,
            start,
            uid: std::fs::metadata(format!("/proc/{pid}"))?.uid(),
            pid_namespace: std::fs::metadata("/proc/self/ns/pid")?.ino(),
            cgroup: cgroup.to_owned(),
            cgroup_inode: metadata.ino(),
        })
    }

    pub(crate) fn persist(&self, runtime: &Path) -> Result<(), VmmError> {
        let path = runtime.join(format!("{}.recovery.json", self.id));
        // No replacement: a repeated generation must never overwrite its proof.
        // A partial write after a crash fails parsing and retains ownership.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(&serde_json::to_vec(self).map_err(failure)?)?;
        file.sync_all()?;
        std::fs::File::open(runtime)?.sync_all()?;
        Ok(())
    }

    pub(crate) fn load(runtime: &Path, id: Uuid) -> Result<Self, VmmError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(runtime.join(format!("{id}.recovery.json")))?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(failure("receipt is not private and owned"));
        }
        let mut bytes = Vec::new();
        file.take(8193).read_to_end(&mut bytes)?;
        if bytes.len() > 8192 {
            return Err(failure("oversized receipt"));
        }
        serde_json::from_slice(&bytes).map_err(failure)
    }

    pub(crate) async fn confirm(
        &self,
        id: Uuid,
        name: &str,
        cid: u32,
        runtime: &Path,
        cgroup: &Path,
    ) -> Result<(), VmmError> {
        if self.version != 1
            || self.id != id
            || id.is_nil()
            || self.name != name
            || name
                .strip_prefix("job-")
                .and_then(|s| Uuid::parse_str(s).ok())
                .is_none()
            || self.cid != cid
            || self.cgroup != cgroup
            || !cgroup.is_absolute()
            || self.uid != unsafe { libc::geteuid() }
            || self.pid == 0
            || self.pid > i32::MAX as u32
            || self.pid == std::process::id()
            || self.start == 0
            || Uuid::parse_str(&self.boot).is_err()
        {
            return Err(failure("receipt ownership mismatch"));
        }
        let same_boot = self.boot == boot_id()?;
        if same_boot {
            if self.pid_namespace != std::fs::metadata("/proc/self/ns/pid")?.ino() {
                return Err(failure("PID namespace changed"));
            }
            self.end_original_process(runtime).await?;
        }
        // The recorded process has ended, but descendants/device owners may
        // remain. Never kill a replacement cgroup or accept a failed read.
        match std::fs::symlink_metadata(cgroup) {
            Ok(metadata) => {
                if !same_boot || !metadata.is_dir() || metadata.ino() != self.cgroup_inode {
                    return Err(failure("cgroup generation changed"));
                }
                let events = std::fs::read_to_string(cgroup.join("cgroup.events"))?;
                if !events.lines().any(|line| line == "populated 0")
                    || events
                        .lines()
                        .any(|line| line.starts_with("populated ") && line != "populated 0")
                {
                    return Err(failure("cgroup is still populated"));
                }
                // rmdir itself confirms that no tasks or descendant cgroups
                // remain, including a task racing the preceding read.
                std::fs::remove_dir(cgroup)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    async fn end_original_process(&self, runtime: &Path) -> Result<(), VmmError> {
        // Pin before reading /proc. A later PID reuse cannot redirect a signal.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, self.pid as libc::pid_t, 0u32) };
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(())
            } else {
                Err(error.into())
            };
        }
        let process = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        let mut exited = libc::pollfd {
            fd: process.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut exited, 1, 0) } > 0 && exited.revents & libc::POLLIN != 0 {
            return Ok(());
        }
        if process_start(self.pid)? != Some(self.start) {
            // Original birth identity is gone. Leave the new process alone.
            return Ok(());
        }
        let metadata = std::fs::metadata(format!("/proc/{}", self.pid))?;
        let mut argv = Vec::new();
        std::fs::File::open(format!("/proc/{}/cmdline", self.pid))?
            .take(65537)
            .read_to_end(&mut argv)?;
        let socket = runtime.join(format!("{}.sock", self.id));
        use std::os::unix::ffi::OsStrExt;
        if metadata.uid() != self.uid
            || argv.len() > 65536
            || !argv
                .split(|b| *b == 0)
                .collect::<Vec<_>>()
                .windows(2)
                .any(|args| args[0] == b"--api-sock" && args[1] == socket.as_os_str().as_bytes())
        {
            return Err(failure("original process argv or uid mismatch"));
        }
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                process.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        if result != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
            return Err(std::io::Error::last_os_error().into());
        }
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let mut poll = libc::pollfd {
                fd: process.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut poll, 1, 0) };
            if ready > 0 && poll.revents & libc::POLLIN != 0 {
                return Ok(());
            }
            if ready < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(failure("process exit unconfirmed"));
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command, Stdio};

    struct Fixture {
        dir: tempfile::TempDir,
        receipt: Receipt,
        child: Child,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let id = Uuid::new_v4();
            let socket = dir.path().join(format!("{id}.sock"));
            let child = Command::new("/bin/bash")
                .args(["-c", "read -t 60", "--api-sock"])
                .arg(&socket)
                .stdin(Stdio::piped())
                .spawn()
                .unwrap();
            let cgroup = dir.path().join(format!("vm-{id}"));
            std::fs::create_dir(&cgroup).unwrap();
            let info = VmInfo {
                id,
                name: format!("job-{}", Uuid::new_v4()),
                state: crate::VmState::Running,
                pid: Some(child.id()),
                vcpu_count: 1,
                mem_size_mib: 128,
                vsock_cid: 31000,
            };
            let receipt = Receipt::capture(&info, &cgroup).unwrap();
            Self {
                dir,
                receipt,
                child,
            }
        }
        async fn confirm(&self) -> Result<(), VmmError> {
            self.receipt
                .confirm(
                    self.receipt.id,
                    &self.receipt.name,
                    self.receipt.cid,
                    self.dir.path(),
                    &self.receipt.cgroup,
                )
                .await
        }
        fn no_cgroup(&self) {
            std::fs::remove_dir(&self.receipt.cgroup).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[tokio::test]
    async fn durable_receipt_reaps_exact_process_and_survives_repeated_recovery() {
        let mut f = Fixture::new();
        f.receipt.persist(f.dir.path()).unwrap();
        assert!(f.receipt.persist(f.dir.path()).is_err());
        let loaded = Receipt::load(f.dir.path(), f.receipt.id).unwrap();
        f.no_cgroup();
        loaded
            .confirm(
                loaded.id,
                &loaded.name,
                loaded.cid,
                f.dir.path(),
                &loaded.cgroup,
            )
            .await
            .unwrap();
        assert!(!f.child.wait().unwrap().success());
        f.confirm().await.unwrap();
        assert!(Receipt::load(f.dir.path(), f.receipt.id).is_ok());
    }

    #[tokio::test]
    async fn reused_pid_and_already_dead_process_are_not_signalled() {
        let mut f = Fixture::new();
        f.no_cgroup();
        f.receipt.start += 1; // original birth identity differs from this live PID
        f.confirm().await.unwrap();
        assert!(f.child.try_wait().unwrap().is_none());
        f.child.kill().unwrap();
        // Unreaped zombies have empty argv; a readable pidfd proves exit.
        f.confirm().await.unwrap();
        f.child.wait().unwrap();
        f.confirm().await.unwrap();
    }

    #[tokio::test]
    async fn wrong_ownership_never_signals_live_process() {
        let mut f = Fixture::new();
        for (id, name, cid) in [
            (Uuid::new_v4(), f.receipt.name.clone(), f.receipt.cid),
            (
                f.receipt.id,
                format!("job-{}", Uuid::new_v4()),
                f.receipt.cid,
            ),
            (f.receipt.id, f.receipt.name.clone(), f.receipt.cid + 1),
        ] {
            assert!(
                f.receipt
                    .confirm(id, &name, cid, f.dir.path(), &f.receipt.cgroup)
                    .await
                    .is_err()
            );
            assert!(f.child.try_wait().unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn wrong_socket_and_pid_namespace_do_not_signal_original_process() {
        let mut f = Fixture::new();
        let runtime = tempfile::tempdir().unwrap();
        assert!(
            f.receipt
                .confirm(
                    f.receipt.id,
                    &f.receipt.name,
                    f.receipt.cid,
                    runtime.path(),
                    &f.receipt.cgroup
                )
                .await
                .is_err()
        );
        assert!(f.child.try_wait().unwrap().is_none());
        f.receipt.pid_namespace += 1;
        assert!(f.confirm().await.is_err());
        assert!(f.child.try_wait().unwrap().is_none());
    }

    #[tokio::test]
    async fn populated_replaced_and_unreadable_cgroups_retain_ownership() {
        let mut f = Fixture::new();
        // Prove the recorded process gone without killing the live bystander.
        f.receipt.start += 1;
        std::fs::write(f.receipt.cgroup.join("cgroup.events"), "populated 1\n").unwrap();
        assert!(f.confirm().await.is_err());
        assert!(f.receipt.cgroup.exists());
        std::fs::remove_file(f.receipt.cgroup.join("cgroup.events")).unwrap();
        assert!(f.confirm().await.is_err());
        let saved = f.receipt.cgroup.with_extension("old");
        std::fs::rename(&f.receipt.cgroup, &saved).unwrap();
        std::fs::create_dir(&f.receipt.cgroup).unwrap();
        assert!(f.confirm().await.is_err());
        assert!(f.receipt.cgroup.exists());
        assert!(f.child.try_wait().unwrap().is_none());
    }

    #[tokio::test]
    async fn foreign_boot_requires_absent_cgroup_and_does_not_signal_current_pid() {
        let mut f = Fixture::new();
        f.receipt.boot = Uuid::new_v4().to_string();
        assert!(f.confirm().await.is_err());
        f.no_cgroup();
        f.confirm().await.unwrap();
        assert!(f.child.try_wait().unwrap().is_none());
    }

    #[test]
    fn missing_partial_public_or_symlinked_receipts_are_not_proof() {
        let f = Fixture::new();
        assert!(Receipt::load(f.dir.path(), f.receipt.id).is_err());
        let path = f.dir.path().join(format!("{}.recovery.json", f.receipt.id));
        std::fs::write(&path, b"{").unwrap();
        assert!(Receipt::load(f.dir.path(), f.receipt.id).is_err());
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("/dev/null", &path).unwrap();
        assert!(Receipt::load(f.dir.path(), f.receipt.id).is_err());
    }

    #[test]
    fn process_stat_handles_parentheses_in_comm_and_rejects_invalid_birth() {
        let fields = std::iter::repeat_n("0", 19)
            .chain(["123"])
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(start_time(&format!("1 (a ) b) {fields}")).unwrap(), 123);
        assert!(start_time("1 (bad) S 1").is_err());
    }
}

#[cfg(test)]
mod privileged_tests {
    use super::*;

    /// Runs only in a private delegated unit, never in an installed daemon's
    /// subtree. Exercises the real cgroup.events/rmdir success path and pidfd.
    #[tokio::test]
    #[ignore = "requires HUSKER_RUN_RECOVERY_CGROUP_TEST=1 in husker-recovery-test-*.service with Delegate=yes"]
    async fn real_delegated_cgroup_is_empty_and_removed_after_exact_process_exit() {
        assert_eq!(
            std::env::var("HUSKER_RUN_RECOVERY_CGROUP_TEST").as_deref(),
            Ok("1")
        );
        assert!(
            std::fs::read_to_string("/proc/self/cgroup")
                .unwrap()
                .contains("/husker-recovery-test-")
        );
        let supervisor = crate::cgroup::CgroupSupervisor::init(crate::cgroup::CgroupConfig {
            enabled: true,
            memory_overhead_mib: 128,
            cpu_limit: true,
        })
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4();
        let mut child = std::process::Command::new("/bin/bash")
            .args(["-c", "read -t 60", "--api-sock"])
            .arg(dir.path().join(format!("{id}.sock")))
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let group = supervisor.create_vm_cgroup(id, 1, 128).unwrap();
        group.place(child.id()).unwrap();
        let cgroup = supervisor.recovery_path(id).unwrap();
        let info = VmInfo {
            id,
            name: format!("job-{}", Uuid::new_v4()),
            state: crate::VmState::Running,
            pid: Some(child.id()),
            vcpu_count: 1,
            mem_size_mib: 128,
            vsock_cid: 31000,
        };
        let receipt = Receipt::capture(&info, &cgroup).unwrap();
        receipt.persist(dir.path()).unwrap();
        let result = receipt
            .confirm(id, &info.name, info.vsock_cid, dir.path(), &cgroup)
            .await;
        let _ = child.kill();
        child.wait().unwrap();
        result.unwrap();
        assert!(!cgroup.exists());
        // A journal failure/restart must be able to repeat the persisted proof.
        Receipt::load(dir.path(), id)
            .unwrap()
            .confirm(id, &info.name, info.vsock_cid, dir.path(), &cgroup)
            .await
            .unwrap();
    }
}
