//! Factory-only Linux process policy. Ordinary development exec keeps its own
//! compatibility semantics; jobs never fall back to that execution path.
use std::time::Duration;

use anyhow::Result;
use husker_agent_proto::job_spec::JobSpec;

pub struct JobProcess {
    pub command: tokio::process::Command,
    pub timeout: Duration,
    pub containment: JobContainment,
}

pub struct JobContainment {
    #[cfg(target_os = "linux")]
    directory: std::path::PathBuf,
}

#[cfg(not(target_os = "linux"))]
pub fn build_job_process(_spec: &JobSpec, _index: usize, _job_id: &str) -> Result<JobProcess> {
    anyhow::bail!(
        "factory commands require a Linux guest with cgroup v2; no host execution fallback"
    )
}

#[cfg(not(target_os = "linux"))]
impl JobContainment {
    pub async fn terminate_and_confirm(&self) -> Result<()> {
        anyhow::bail!("factory process containment requires Linux")
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use anyhow::ensure;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;

    fn control(path: &Path, write: bool) -> Result<File> {
        Ok(OpenOptions::new()
            .read(!write)
            .write(write)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?)
    }
    fn read_control(path: &Path) -> Result<String> {
        let mut value = String::new();
        control(path, false)?
            .take(4097)
            .read_to_string(&mut value)?;
        ensure!(value.len() <= 4096, "cgroup control response exceeds limit");
        Ok(value)
    }

    pub fn build(spec: &JobSpec, index: usize, job_id: &str) -> Result<JobProcess> {
        spec.validate()?;
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "trusted factory runner must start as guest root"
        );
        ensure!(
            job_id.len() == 36 && job_id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
            "invalid stable job identity"
        );
        let command_spec = spec
            .commands
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("command index out of range"))?;
        let remaining = Duration::from_secs(u64::try_from(spec.deadline.timestamp())?)
            .checked_sub(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?)
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| anyhow::anyhow!("job deadline expired"))?;
        let root = Path::new("/sys/fs/cgroup");
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root)?;
        let metadata = directory.metadata()?;
        ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "cgroup root must be root-owned and protected"
        );
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { libc::fstatfs(directory.as_raw_fd(), &mut fs) } == 0,
            "cannot inspect cgroup filesystem"
        );
        ensure!(fs.f_type == 0x63677270, "cgroup v2 is required");
        ensure!(
            read_control(&root.join("cgroup.controllers"))?
                .split_whitespace()
                .any(|c| c == "pids"),
            "pids controller unavailable"
        );
        control(&root.join("cgroup.subtree_control"), true)?.write_all(b"+pids")?;
        let path = root.join(format!("husker-check-{job_id}-{index}"));
        std::fs::create_dir(&path)?; // Refuse an existing/stale ownership receipt.
        let containment = JobContainment { directory: path };
        let configured = (|| -> Result<File> {
            control(&containment.directory.join("pids.max"), true)?
                .write_all(spec.resources.pids_limit.to_string().as_bytes())?;
            ensure!(
                read_control(&containment.directory.join("pids.max"))?.trim()
                    == spec.resources.pids_limit.to_string(),
                "pids limit was not applied"
            );
            // Presence is required before source executes; kernels lacking
            // cgroup.kill cannot guarantee termination of escaped descendants.
            let _kill = control(&containment.directory.join("cgroup.kill"), true)?;
            let _events = control(&containment.directory.join("cgroup.events"), false)?;
            control(&containment.directory.join("cgroup.procs"), true)
        })();
        let membership = configured?;
        let mut command = tokio::process::Command::new(&command_spec.argv[0]);
        command
            .args(&command_spec.argv[1..])
            .current_dir(&spec.working_directory)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", "/workspace")
            .env("TMPDIR", "/tmp")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("WERKT_ACCEPTANCE_DIR", "/acceptance")
            .envs(&spec.environment)
            .kill_on_drop(true)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        ensure!(
            spec.environment
                .get("WERKT_ACCEPTANCE_DIR")
                .is_none_or(|p| p == "/acceptance"),
            "acceptance directory override forbidden"
        );
        let uid = spec.uid;
        let gid = spec.gid;
        // SAFETY: only async-signal-safe syscalls run in the forked child. All
        // files, arguments and numeric values are prepared in the parent.
        unsafe {
            command.pre_exec(move || {
                if libc::write(membership.as_raw_fd(), b"0".as_ptr().cast(), 1) != 1 {
                    return Err(std::io::Error::last_os_error());
                }
                let core = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                let descriptors = libc::rlimit {
                    rlim_cur: 256,
                    rlim_max: 256,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0
                    || libc::setrlimit(libc::RLIMIT_NOFILE, &descriptors) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) != 0
                    || libc::prctl(
                        libc::PR_CAP_AMBIENT,
                        libc::PR_CAP_AMBIENT_CLEAR_ALL,
                        0,
                        0,
                        0,
                    ) != 0
                    || libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setresgid(gid, gid, gid) != 0
                    || libc::setresuid(uid, uid, uid) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(JobProcess {
            command,
            timeout: Duration::from_secs(command_spec.timeout_secs).min(remaining),
            containment,
        })
    }

    impl JobContainment {
        pub async fn terminate_and_confirm(&self) -> Result<()> {
            control(&self.directory.join("cgroup.kill"), true)?.write_all(b"1")?;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            loop {
                let events = read_control(&self.directory.join("cgroup.events"))?;
                if events.lines().any(|line| line == "populated 0") {
                    return Ok(());
                }
                ensure!(
                    tokio::time::Instant::now() < deadline,
                    "process termination pending: cgroup remains populated; destroy the job VM"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }

    impl Drop for JobContainment {
        fn drop(&mut self) {
            // Last best effort; callers must observe terminate_and_confirm and
            // use host VM destruction when cancellation cannot be confirmed.
            if let Ok(mut kill) = control(&self.directory.join("cgroup.kill"), true) {
                let _ = kill.write_all(b"1");
            }
            let _ = std::fs::remove_dir(&self.directory);
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::build as build_job_process;
