//! Parent-side ownership for one VZ worker generation. Register the owner before
//! launch/RPC. Keep it registered after any uncertain observation or cancellation.
//! This module never removes runtime files and never interprets RPC as VM death.
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use tokio::net::UnixStream;
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::Mutex;

use crate::vz_worker::{self, WorkerOperation, WorkerReply, WorkerRequest};
use crate::{VmConfig, VmInfo, VmmError};

const MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;

fn error(message: impl std::fmt::Display) -> VmmError {
    VmmError::ProcessError(format!("VZ worker owner: {message}"))
}

/// An operator-reviewed worker executable pin. This checks bytes and file type,
/// not code-signing identity, entitlement or compatibility with the parent.
#[derive(Clone)]
pub struct WorkerExecutable {
    path: PathBuf,
    sha256: [u8; 32],
}

impl WorkerExecutable {
    pub fn new(path: PathBuf, sha256: [u8; 32]) -> Result<Self, VmmError> {
        let value = Self { path, sha256 };
        value.verify()?;
        Ok(value)
    }

    /// Read-only preflight, before any VM or child allocation. The immutable
    /// digest is checked on both sides of native static-code inspection, and
    /// launch rechecks the same digest. This does not attest publisher identity.
    pub fn verify_virtualization_entitlement(&self) -> Result<(), VmmError> {
        self.verify()?;
        crate::vz_worker_signing::verify(&self.path)?;
        self.verify()
    }

    fn verify(&self) -> Result<(), VmmError> {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        if !self.path.is_absolute() {
            return Err(error("absolute worker executable required"));
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.path)
            .map_err(error)?;
        let before = file.metadata().map_err(error)?;
        if !before.is_file()
            || before.nlink() != 1
            || before.uid() != unsafe { libc::geteuid() }
            || before.mode() & 0o022 != 0
            || before.mode() & 0o111 == 0
            || before.len() == 0
            || before.len() > MAX_EXECUTABLE_BYTES
        {
            return Err(error(
                "owned nonlinked protected executable bounded to 64 MiB required",
            ));
        }
        let mut file = file;
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        let mut buffer = [0; 64 * 1024];
        loop {
            let count = file.read(&mut buffer).map_err(error)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or_else(|| error("worker size overflow"))?;
            if total > MAX_EXECUTABLE_BYTES {
                return Err(error("worker executable grew beyond bound"));
            }
            hasher.update(&buffer[..count]);
        }
        let after = file.metadata().map_err(error)?;
        if total != before.len()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
            || <[u8; 32]>::from(hasher.finalize()) != self.sha256
        {
            return Err(error(
                "worker executable changed or differs from reviewed digest",
            ));
        }
        Ok(())
    }
}

#[derive(Default)]
struct ProcessState {
    attempted: bool,
    child: Option<Child>,
    keepalive: Option<ChildStdin>,
    pid: Option<u32>,
    death_confirmed: bool,
    launch_fenced: bool,
}

pub struct WorkerOwner {
    config: VmConfig,
    runtime_dir: PathBuf,
    deadline_epoch: u64,
    deadline: tokio::time::Instant,
    executable: WorkerExecutable,
    process: Mutex<ProcessState>,
    creation_attempted: AtomicBool,
    creation_frame_started: AtomicBool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerDeathProof {
    ChildReaped,
    /// Only this owner never spawned a child; not proof about prior/foreign VMs.
    NoChildLaunched,
}

#[derive(Debug)]
pub struct WorkerConnection {
    pub reply: WorkerReply,
    pub stream: UnixStream,
}

impl WorkerOwner {
    /// Pure ownership planning; this launches nothing and creates no files.
    pub fn new(
        config: VmConfig,
        runtime_dir: PathBuf,
        deadline_epoch: u64,
        executable: WorkerExecutable,
    ) -> Result<Self, VmmError> {
        let id = config
            .requested_id
            .ok_or_else(|| error("assigned VM generation required"))?;
        vz_worker::validate_request(
            &WorkerRequest {
                version: 1,
                vm_id: id,
                operation: WorkerOperation::Create(Box::new(config.clone())),
            },
            id,
        )?;
        if !runtime_dir.is_absolute() {
            return Err(error("absolute private runtime directory required"));
        }
        if env!("HUSKER_WORKSPACE_RUST_SOURCE_SHA256") == "unavailable" {
            return Err(error(
                "VZ worker requires paired workspace builds with source identity",
            ));
        }
        vz_worker::validate_control_path(&runtime_dir)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(error)?
            .as_secs();
        let lifetime = vz_worker::lifetime_remaining(deadline_epoch, now)?;
        Ok(Self {
            config,
            runtime_dir,
            deadline_epoch,
            deadline: tokio::time::Instant::now() + lifetime,
            executable,
            process: Mutex::new(ProcessState::default()),
            creation_attempted: AtomicBool::new(false),
            creation_frame_started: AtomicBool::new(false),
        })
    }

    /// Caller must have published this owner before awaiting launch. There is no
    /// await between spawn and retaining the child, PID and parent pipe.
    pub async fn launch(&self) -> Result<(), VmmError> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let mut state = self.process.lock().await;
        if state.attempted || state.launch_fenced {
            return Err(error("launch fenced; inspect or destroy only"));
        }
        state.attempted = true;
        if tokio::time::Instant::now() >= self.deadline {
            return Err(error("worker lifetime expired before launch"));
        }
        self.executable.verify()?;
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&self.runtime_dir)
            .map_err(error)?;
        let metadata = directory.metadata().map_err(error)?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o700 {
            return Err(error("owned private 0700 runtime directory required"));
        }
        match self
            .runtime_dir
            .join(vz_worker::CONTROL_SOCKET)
            .symlink_metadata()
        {
            Ok(_) => {
                return Err(error(
                    "worker endpoint already exists; ownership is uncertain",
                ));
            }
            Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => {}
            Err(failure) => return Err(error(failure)),
        }
        let mut command = Command::new(&self.executable.path);
        command
            .arg(&self.runtime_dir)
            .arg(self.config.requested_id.unwrap().to_string())
            .arg(self.deadline_epoch.to_string())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(error)?;
        state.pid = child.id();
        state.keepalive = child.stdin.take();
        state.child = Some(child);
        if state.keepalive.is_none() {
            return Err(error(
                "spawned worker has no parent pipe; child ownership retained",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn install_sleeper_fixture(&self) {
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .env_clear()
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut state = self.process.lock().await;
        state.attempted = true;
        state.pid = child.id();
        state.keepalive = child.stdin.take();
        state.child = Some(child);
    }

    #[cfg(test)]
    pub(crate) fn mark_creation_frame_fixture(&self) {
        self.creation_frame_started.store(true, Ordering::SeqCst);
    }

    pub async fn pid(&self) -> Option<u32> {
        self.process.lock().await.pid
    }

    pub async fn death_confirmed(&self) -> bool {
        self.process.lock().await.death_confirmed
    }

    /// Closing the pipe requests worker exit; it is deliberately not a receipt.
    pub async fn request_parent_exit(&self) {
        self.process.lock().await.keepalive.take();
    }

    /// Positive termination (or a fenced, never-spawned owner). Future
    /// cancellation/error retains the exact child handle for another attempt.
    pub async fn destroy(&self) -> Result<WorkerDeathProof, VmmError> {
        let mut state = self.process.lock().await;
        state.launch_fenced = true;
        let proof = if let Some(child) = state.child.as_mut() {
            crate::termination::terminate_child(child, "owned VZ worker").await?;
            state.death_confirmed = true;
            WorkerDeathProof::ChildReaped
        } else {
            WorkerDeathProof::NoChildLaunched
        };
        state.keepalive.take();
        Ok(proof)
    }

    pub fn creation_frame_started(&self) -> bool {
        self.creation_frame_started.load(Ordering::SeqCst)
    }

    pub async fn create(&self) -> Result<WorkerConnection, VmmError> {
        if self.creation_attempted.swap(true, Ordering::SeqCst) {
            return Err(error("VM creation already attempted; inspect only"));
        }
        tokio::time::timeout(Duration::from_secs(120), async {
            let identity = self
                .exchange(WorkerOperation::Describe, Duration::from_secs(5))
                .await?;
            if !matches!(identity.reply, WorkerReply::Identity(_)) {
                return Err(error("worker compatibility handshake was not accepted"));
            }
            self.exchange(
                WorkerOperation::Create(Box::new(self.config.clone())),
                Duration::from_secs(120),
            )
            .await
        })
        .await
        .map_err(|_| error("creation observation expired; child ownership retained"))?
    }

    /// Fresh connection per operation. Only connection establishment retries;
    /// once a frame is sent, a lost reply is uncertain and never resent.
    pub async fn rpc(
        &self,
        operation: WorkerOperation,
        observation: Duration,
    ) -> Result<WorkerConnection, VmmError> {
        if matches!(operation, WorkerOperation::Create(_)) {
            // Creation has a separate single-use entry point.
            return Err(error("use the single-use create entry point"));
        }
        self.exchange(operation, observation).await
    }

    async fn exchange(
        &self,
        operation: WorkerOperation,
        observation: Duration,
    ) -> Result<WorkerConnection, VmmError> {
        if observation.is_zero() || observation > Duration::from_secs(120) {
            return Err(error("RPC observation must be within 120s"));
        }
        let remaining = self
            .deadline
            .saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(error("worker lifetime expired; confirm destruction"));
        }
        let id = self.config.requested_id.unwrap();
        let request = WorkerRequest {
            version: 1,
            vm_id: id,
            operation,
        };
        vz_worker::validate_request(&request, id)?;
        let connection = async {
            let mut stream = loop {
                {
                    let mut state = self.process.lock().await;
                    if state.death_confirmed {
                        return Err(error("worker destruction already confirmed"));
                    }
                    let child = state
                        .child
                        .as_mut()
                        .ok_or_else(|| error("worker not spawned"))?;
                    if child.try_wait().map_err(error)?.is_some() {
                        return Err(error("worker exited; destruction receipt still required"));
                    }
                }
                match UnixStream::connect(self.runtime_dir.join(vz_worker::CONTROL_SOCKET)).await {
                    Ok(stream) => break stream,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                        ) =>
                    {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    Err(failure) => return Err(error(failure)),
                }
            };
            if matches!(request.operation, WorkerOperation::Create(_)) {
                self.creation_frame_started.store(true, Ordering::SeqCst);
            }
            vz_worker::write_frame(&mut stream, &request).await?;
            let reply: WorkerReply = vz_worker::read_frame(&mut stream).await?;
            if let WorkerReply::Info(info) = &reply {
                self.validate_info(info)?;
            }
            match (&request.operation, &reply) {
                (_, WorkerReply::Error(message)) if message.len() <= 2048 => {}
                (WorkerOperation::Describe, WorkerReply::Identity(identity))
                    if *identity == vz_worker::WorkerIdentity::current() => {}
                (WorkerOperation::Create(_), WorkerReply::Info(info))
                    if info.state == crate::VmState::Running => {}
                (WorkerOperation::Inspect, WorkerReply::Info(_)) => {}
                (WorkerOperation::Destroy, WorkerReply::Destroyed) => {}
                (WorkerOperation::Connect { .. }, WorkerReply::Stream) => {}
                _ => return Err(error("reply does not match requested operation")),
            }
            Ok(WorkerConnection { reply, stream })
        };
        tokio::time::timeout(observation.min(remaining), connection)
            .await
            .map_err(|_| error("RPC observation expired; child ownership retained"))?
    }

    fn validate_info(&self, info: &VmInfo) -> Result<(), VmmError> {
        if Some(info.id) != self.config.requested_id
            || info.name != self.config.name
            || info.pid.is_some()
            || info.vsock_cid != self.config.vsock_cid
            || info.vcpu_count != self.config.vcpu_count
            || info.mem_size_mib != self.config.mem_size_mib
        {
            return Err(error("worker reply changed VM identity or resources"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BootMode;
    use std::os::unix::fs::PermissionsExt;

    fn planned_owner(directory: &std::path::Path) -> WorkerOwner {
        let executable = directory.join("reviewed-fixture");
        let bytes = b"#!/bin/sh\nexit 0\n";
        std::fs::write(&executable, bytes).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let pin = WorkerExecutable::new(executable, Sha256::digest(bytes).into()).unwrap();
        let config = VmConfig {
            requested_id: Some(uuid::Uuid::new_v4()),
            name: "fixture".into(),
            vcpu_count: 1,
            mem_size_mib: 512,
            kernel_path: "/never-booted/kernel".into(),
            rootfs_path: "/never-booted/rootfs".into(),
            kernel_args: None,
            initrd_path: None,
            vsock_cid: 3,
            tap_device: None,
            guest_mac: None,
            vmm: None,
            boot: BootMode::DirectKernel,
            seed_path: None,
            balloon: false,
            volume_path: None,
            network_disabled: true,
            factory_recovery: false,
            host_shares: vec![],
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        WorkerOwner::new(config, directory.to_path_buf(), now + 60, pin).unwrap()
    }

    #[tokio::test]
    async fn incompatible_or_rejected_handshake_never_sends_creation() {
        let current = vz_worker::WorkerIdentity::current();
        let mut wrong_version = current.clone();
        wrong_version.protocol_version += 1;
        let mut wrong_package = current.clone();
        wrong_package.package_version.push_str("-foreign");
        let mut wrong_source = current.clone();
        wrong_source.workspace_rust_source_sha256 = "0".repeat(64);
        let mut wrong_target = current.clone();
        wrong_target.build_target = "foreign-target".into();
        let mut wrong_profile = current;
        wrong_profile.execution_profile = "nat".into();
        for reply in [
            WorkerReply::Identity(wrong_version),
            WorkerReply::Identity(wrong_package),
            WorkerReply::Identity(wrong_profile),
            WorkerReply::Identity(wrong_source),
            WorkerReply::Identity(wrong_target),
            WorkerReply::Error("unsupported operation".into()),
        ] {
            let dir = tempfile::tempdir_in("/private/tmp").unwrap();
            let owner = planned_owner(dir.path());
            owner.install_sleeper_fixture().await;
            let listener =
                tokio::net::UnixListener::bind(dir.path().join(vz_worker::CONTROL_SOCKET)).unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request: WorkerRequest = vz_worker::read_frame(&mut stream).await.unwrap();
                assert!(matches!(request.operation, WorkerOperation::Describe));
                vz_worker::write_frame(&mut stream, &reply).await.unwrap();
                listener
            });
            assert!(owner.create().await.is_err());
            let listener = server.await.unwrap();
            assert!(!owner.creation_frame_started());
            assert!(!owner.death_confirmed().await);
            assert!(owner.pid().await.is_some());
            assert!(owner.create().await.is_err());
            assert!(
                tokio::time::timeout(Duration::from_millis(20), listener.accept())
                    .await
                    .is_err()
            );
            assert_eq!(
                owner.destroy().await.unwrap(),
                WorkerDeathProof::ChildReaped
            );
        }
    }

    #[tokio::test]
    async fn matching_handshake_precedes_single_generation_creation_frame() {
        let dir = tempfile::tempdir_in("/private/tmp").unwrap();
        let owner = planned_owner(dir.path());
        owner.install_sleeper_fixture().await;
        let config = owner.config.clone();
        let listener =
            tokio::net::UnixListener::bind(dir.path().join(vz_worker::CONTROL_SOCKET)).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request: WorkerRequest = vz_worker::read_frame(&mut stream).await.unwrap();
            assert_eq!(Some(request.vm_id), config.requested_id);
            assert!(matches!(request.operation, WorkerOperation::Describe));
            vz_worker::write_frame(
                &mut stream,
                &WorkerReply::Identity(vz_worker::WorkerIdentity::current()),
            )
            .await
            .unwrap();
            drop(stream);
            let (mut stream, _) = listener.accept().await.unwrap();
            let request: WorkerRequest = vz_worker::read_frame(&mut stream).await.unwrap();
            assert_eq!(Some(request.vm_id), config.requested_id);
            let WorkerOperation::Create(received) = request.operation else {
                panic!("creation must follow handshake");
            };
            assert_eq!(
                serde_json::to_value(received).unwrap(),
                serde_json::to_value(&config).unwrap()
            );
            vz_worker::write_frame(
                &mut stream,
                &WorkerReply::Info(VmInfo {
                    id: config.requested_id.unwrap(),
                    name: config.name,
                    state: crate::VmState::Running,
                    pid: None,
                    vcpu_count: config.vcpu_count,
                    mem_size_mib: config.mem_size_mib,
                    vsock_cid: config.vsock_cid,
                }),
            )
            .await
            .unwrap();
        });
        assert!(matches!(
            owner.create().await.unwrap().reply,
            WorkerReply::Info(_)
        ));
        server.await.unwrap();
        assert!(owner.creation_frame_started());
        assert!(!owner.death_confirmed().await);
        assert!(owner.create().await.is_err());
        owner.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn closed_pipe_and_rpc_timeout_preserve_child_until_positive_reap() {
        let dir = tempfile::tempdir().unwrap();
        let owner = planned_owner(dir.path());
        owner.install_sleeper_fixture().await;
        let pid = owner.pid().await.unwrap();
        owner.request_parent_exit().await;
        assert!(!owner.death_confirmed().await);
        assert!(
            owner
                .process
                .lock()
                .await
                .child
                .as_mut()
                .unwrap()
                .try_wait()
                .unwrap()
                .is_none()
        );
        assert!(
            owner
                .rpc(WorkerOperation::Inspect, Duration::from_millis(25))
                .await
                .unwrap_err()
                .to_string()
                .contains("observation expired")
        );
        assert_eq!(owner.pid().await, Some(pid));
        assert!(!owner.death_confirmed().await);
        assert_eq!(
            owner.destroy().await.unwrap(),
            WorkerDeathProof::ChildReaped
        );
        assert!(owner.death_confirmed().await);
        assert!(
            owner
                .process
                .lock()
                .await
                .child
                .as_mut()
                .unwrap()
                .try_wait()
                .unwrap()
                .is_some()
        );
        assert_eq!(
            owner.destroy().await.unwrap(),
            WorkerDeathProof::ChildReaped
        );
    }

    #[tokio::test]
    async fn cancelled_rpc_does_not_block_independent_destruction_or_forget_owner() {
        let dir = tempfile::tempdir().unwrap();
        let owner = std::sync::Arc::new(planned_owner(dir.path()));
        owner.install_sleeper_fixture().await;
        let rpc_owner = owner.clone();
        let rpc = tokio::spawn(async move {
            rpc_owner
                .rpc(WorkerOperation::Inspect, Duration::from_secs(30))
                .await
        });
        tokio::task::yield_now().await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), owner.destroy())
                .await
                .unwrap()
                .unwrap(),
            WorkerDeathProof::ChildReaped
        );
        rpc.abort();
        let _ = rpc.await;
        assert!(owner.death_confirmed().await);
    }

    #[tokio::test]
    async fn never_spawned_owner_is_fenced_without_inventing_death() {
        let dir = tempfile::tempdir().unwrap();
        let owner = planned_owner(dir.path());
        assert_eq!(
            owner.destroy().await.unwrap(),
            WorkerDeathProof::NoChildLaunched
        );
        assert!(!owner.death_confirmed().await);
        assert!(owner.pid().await.is_none());
        assert!(owner.launch().await.is_err());
        assert!(owner.create().await.is_err());
        assert!(
            owner
                .create()
                .await
                .unwrap_err()
                .to_string()
                .contains("already attempted")
        );
    }

    #[test]
    fn reply_identity_must_match_the_owned_config() {
        let dir = tempfile::tempdir().unwrap();
        let owner = planned_owner(dir.path());
        let info = VmInfo {
            id: owner.config.requested_id.unwrap(),
            name: owner.config.name.clone(),
            state: crate::VmState::Running,
            pid: None,
            vcpu_count: owner.config.vcpu_count,
            mem_size_mib: owner.config.mem_size_mib,
            vsock_cid: owner.config.vsock_cid,
        };
        owner.validate_info(&info).unwrap();
        let mut changed = info.clone();
        changed.id = uuid::Uuid::new_v4();
        assert!(owner.validate_info(&changed).is_err());
        let mut changed = info.clone();
        changed.name = "foreign".into();
        assert!(owner.validate_info(&changed).is_err());
        let mut changed = info.clone();
        changed.pid = Some(1);
        assert!(owner.validate_info(&changed).is_err());
        let mut changed = info.clone();
        changed.vsock_cid += 1;
        assert!(owner.validate_info(&changed).is_err());
        let mut changed = info.clone();
        changed.vcpu_count += 1;
        assert!(owner.validate_info(&changed).is_err());
        let mut changed = info;
        changed.mem_size_mib += 1;
        assert!(owner.validate_info(&changed).is_err());
    }

    #[tokio::test]
    async fn changed_executable_fails_before_spawn_and_keeps_no_child_proof() {
        let dir = tempfile::tempdir().unwrap();
        let owner = planned_owner(dir.path());
        std::fs::write(&owner.executable.path, b"#!/bin/sh\nexit 1\n").unwrap();
        assert!(owner.launch().await.is_err());
        assert!(owner.pid().await.is_none());
        assert_eq!(
            owner.destroy().await.unwrap(),
            WorkerDeathProof::NoChildLaunched
        );
        assert!(!owner.death_confirmed().await);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&owner.executable.path, &link).unwrap();
        assert!(WorkerExecutable::new(link, owner.executable.sha256).is_err());
    }
}
