//! Private, single-generation VZ worker protocol. The parent must retain and
//! positively reap the child before releasing its VM lease or runtime files.
//! A worker reply or a disconnected socket is never a child-death receipt.
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

use crate::{
    BackendKind, BackendRequirements, BackendSelection, VmConfig, VmInfo, VmmBackend, VmmError,
};

pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const CONTROL_SOCKET: &str = "control.sock";
pub const STOP_RECEIPT: &str = "framework-stopped.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerIdentity {
    pub protocol_version: u32,
    pub package_version: String,
    pub execution_profile: String,
    pub workspace_rust_source_sha256: String,
    pub build_target: String,
}

impl WorkerIdentity {
    pub fn current() -> Self {
        Self {
            protocol_version: 1,
            package_version: env!("CARGO_PKG_VERSION").into(),
            execution_profile: "offline-direct-kernel-stop-receipt-v1".into(),
            workspace_rust_source_sha256: env!("HUSKER_WORKSPACE_RUST_SOURCE_SHA256").into(),
            build_target: env!("HUSKER_BUILD_TARGET").into(),
        }
    }
}

pub(crate) fn validate_control_path(runtime_dir: &Path) -> Result<(), VmmError> {
    use std::os::unix::ffi::OsStrExt;
    let path = runtime_dir.join(CONTROL_SOCKET);
    let bytes = path.as_os_str().as_bytes();
    let socket: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= socket.sun_path.len() || bytes.contains(&0) {
        return Err(protocol_error(
            "control socket path exceeds native limit or contains NUL",
        ));
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrameworkStopReceipt {
    pub version: u32,
    pub vm_id: Uuid,
}

#[derive(Default)]
struct FrameworkStopState {
    confirmed: bool,
    receipt: Option<std::fs::File>,
}

impl FrameworkStopState {
    async fn destroy_with_receipt<F, Fut>(
        &mut self,
        runtime_dir: &Path,
        vm_id: Uuid,
        destroy: F,
    ) -> Result<(), VmmError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), VmmError>>,
    {
        if !self.confirmed {
            destroy().await?;
            // No await between successful destruction and retaining proof.
            // Receipt publication may fail after the backend forgets the VM.
            self.confirmed = true;
        }
        self.persist(runtime_dir, vm_id)
    }

    fn persist(&mut self, runtime_dir: &Path, vm_id: Uuid) -> Result<(), VmmError> {
        use std::io::{Seek, SeekFrom, Write};
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        if !self.confirmed {
            return Err(protocol_error("framework stop remains unconfirmed"));
        }
        let path = runtime_dir.join(STOP_RECEIPT);
        if self.receipt.is_none() {
            // Never adopt a file from a prior or foreign owner. Retain the exact
            // descriptor immediately, including across later write/sync errors.
            self.receipt = Some(
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&path)
                    .map_err(protocol_error)?,
            );
        }
        let file = self.receipt.as_mut().expect("receipt retained above");
        let metadata = file.metadata().map_err(protocol_error)?;
        let current = path.symlink_metadata().map_err(protocol_error)?;
        if !metadata.is_file()
            || !current.is_file()
            || (metadata.dev(), metadata.ino()) != (current.dev(), current.ino())
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(protocol_error("framework receipt ownership changed"));
        }
        let receipt = serde_json::to_vec(&FrameworkStopReceipt { version: 1, vm_id })
            .map_err(protocol_error)?;
        file.set_len(0).map_err(protocol_error)?;
        file.seek(SeekFrom::Start(0)).map_err(protocol_error)?;
        file.write_all(&receipt).map_err(protocol_error)?;
        file.sync_all().map_err(protocol_error)?;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(runtime_dir)
            .map_err(protocol_error)?
            .sync_all()
            .map_err(protocol_error)?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRequest {
    pub version: u32,
    pub vm_id: Uuid,
    pub operation: WorkerOperation,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", content = "parameters", deny_unknown_fields)]
pub enum WorkerOperation {
    Describe,
    Create(Box<VmConfig>),
    Inspect,
    Destroy,
    Connect { port: u32 },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", content = "value", deny_unknown_fields)]
pub enum WorkerReply {
    Identity(WorkerIdentity),
    Info(VmInfo),
    Destroyed,
    Stream,
    Error(String),
}

fn protocol_error(message: impl std::fmt::Display) -> VmmError {
    VmmError::ProcessError(format!("VZ worker protocol: {message}"))
}

pub async fn read_frame<R: AsyncRead + Unpin, T: serde::de::DeserializeOwned>(
    read: &mut R,
) -> Result<T, VmmError> {
    let length = read.read_u32().await.map_err(protocol_error)? as usize;
    if !(1..=MAX_FRAME_BYTES).contains(&length) {
        return Err(protocol_error("frame outside 1..=64 KiB bound"));
    }
    let mut data = vec![0; length];
    read.read_exact(&mut data).await.map_err(protocol_error)?;
    serde_json::from_slice(&data).map_err(protocol_error)
}

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    write: &mut W,
    value: &T,
) -> Result<(), VmmError> {
    let data = serde_json::to_vec(value).map_err(protocol_error)?;
    if !(1..=MAX_FRAME_BYTES).contains(&data.len()) {
        return Err(protocol_error("frame outside 1..=64 KiB bound"));
    }
    write
        .write_u32(data.len() as u32)
        .await
        .map_err(protocol_error)?;
    write.write_all(&data).await.map_err(protocol_error)?;
    write.flush().await.map_err(protocol_error)
}

pub fn validate_request(request: &WorkerRequest, assigned_id: Uuid) -> Result<(), VmmError> {
    if request.version != 1 || assigned_id.is_nil() || request.vm_id != assigned_id {
        return Err(protocol_error(
            "unsupported version or changed VM generation",
        ));
    }
    match &request.operation {
        WorkerOperation::Create(config) => {
            if config.requested_id != Some(assigned_id)
                || !config.network_disabled
                || config.tap_device.is_some()
                || config.guest_mac.is_some()
                || !config.host_shares.is_empty()
                || config.volume_path.is_some()
                || config.seed_path.is_some()
                || config.balloon
                || config.vmm.is_some()
                || !matches!(config.boot, crate::BootMode::DirectKernel)
                || !(1..=32).contains(&config.vcpu_count)
                || !(128..=65536).contains(&config.mem_size_mib)
                || config.vsock_cid < 3
                || config.name.is_empty()
                || config.name.len() > 128
            {
                return Err(VmmError::InvalidConfig("VZ worker requires pinned-generation offline direct-kernel devices without shares, volumes, seeds or balloon".into()));
            }
        }
        // The daemon only ever dials the guest agent; no other guest port is
        // reachable through a worker.
        WorkerOperation::Connect { port } if *port != husker_agent_proto::AGENT_VSOCK_PORT => {
            return Err(protocol_error("guest port is not the agent port"));
        }
        _ => {}
    }
    Ok(())
}

pub fn lifetime_remaining(deadline_epoch: u64, now_epoch: u64) -> Result<Duration, VmmError> {
    let remaining = deadline_epoch
        .checked_sub(now_epoch)
        .filter(|seconds| (1..=3600).contains(seconds))
        .ok_or_else(|| protocol_error("worker lifetime must be within the next hour"))?;
    Ok(Duration::from_secs(remaining))
}

/// Entry point for the separately signed worker binary. Never called by an
/// ordinary daemon constructor. Its stdin must be an inherited parent pipe.
/// No VM is constructed until a valid, single-use Create request is received.
pub async fn serve(
    runtime_dir: &Path,
    assigned_id: Uuid,
    deadline_epoch: u64,
) -> Result<(), VmmError> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::net::UnixListener;

    validate_control_path(runtime_dir)?;
    if assigned_id.is_nil() {
        return Err(protocol_error("nonnil assigned generation required"));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(protocol_error)?
        .as_secs();
    let lifetime = lifetime_remaining(deadline_epoch, now)?;
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(runtime_dir)
        .map_err(protocol_error)?;
    let metadata = directory.metadata().map_err(protocol_error)?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o700 {
        return Err(protocol_error(
            "owned private 0700 runtime directory required",
        ));
    }
    let mut input_metadata: libc::stat = unsafe { std::mem::zeroed() };
    // A terminal or /dev/null is not a parent-liveness channel.
    if unsafe { libc::fstat(libc::STDIN_FILENO, &mut input_metadata) } != 0
        || input_metadata.st_mode & libc::S_IFMT != libc::S_IFIFO
    {
        return Err(protocol_error("inherited parent pipe required on stdin"));
    }
    let path = runtime_dir.join(CONTROL_SOCKET);
    let listener = UnixListener::bind(&path).map_err(protocol_error)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(protocol_error)?;
    // These watchdogs do not depend on the Tokio or VZ dispatch queues. _exit
    // deliberately avoids native destructors that might themselves be blocked.
    // The parent still must confirm child exit with its retained process handle.
    std::thread::Builder::new()
        .name("vz-parent-watch".into())
        .spawn(|| {
            let mut byte = [0; 1];
            loop {
                match std::io::stdin().read(&mut byte) {
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    _ => unsafe { libc::_exit(0) },
                }
            }
        })
        .map_err(protocol_error)?;
    std::thread::Builder::new()
        .name("vz-lifetime-watch".into())
        .spawn(move || {
            std::thread::sleep(lifetime);
            unsafe { libc::_exit(124) };
        })
        .map_err(protocol_error)?;
    let backend = Arc::new(crate::apple_vz::AppleVzBackend::new(runtime_dir));
    let attempted = Arc::new(AtomicBool::new(false));
    let framework_stop = Arc::new(tokio::sync::Mutex::new(FrameworkStopState::default()));
    let slots = Arc::new(tokio::sync::Semaphore::new(16));
    let stream_slots = Arc::new(tokio::sync::Semaphore::new(8));
    // Keep the validated directory descriptor open for the whole worker lifetime.
    let _directory_descriptor = directory.as_raw_fd();
    loop {
        let (mut stream, _) = listener.accept().await.map_err(protocol_error)?;
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let backend = backend.clone();
        let attempted = attempted.clone();
        let framework_stop = framework_stop.clone();
        let stream_slots = stream_slots.clone();
        let receipt_directory = runtime_dir.to_path_buf();
        tokio::spawn(async move {
            let _slot = slot;
            let request = match tokio::time::timeout(
                Duration::from_secs(5),
                read_frame::<_, WorkerRequest>(&mut stream),
            )
            .await
            {
                Ok(Ok(request)) => request,
                _ => return,
            };
            let reply = match validate_request(&request, assigned_id) {
                Err(error) => WorkerReply::Error(error.to_string().chars().take(512).collect()),
                Ok(()) => match request.operation {
                    WorkerOperation::Describe => WorkerReply::Identity(WorkerIdentity::current()),
                    WorkerOperation::Create(config) => {
                        if attempted.swap(true, Ordering::SeqCst) {
                            WorkerReply::Error("creation already attempted; inspect only".into())
                        } else {
                            let selection = BackendSelection::new(
                                BackendRequirements::from_config(&config),
                                BackendKind::AppleVz,
                            );
                            match backend.create_vm(selection, *config).await {
                                Ok(created) => WorkerReply::Info(created.info),
                                Err(error) => WorkerReply::Error(
                                    error.to_string().chars().take(512).collect(),
                                ),
                            }
                        }
                    }
                    WorkerOperation::Inspect => match backend.vm_info(assigned_id).await {
                        Ok(info) => WorkerReply::Info(info),
                        Err(error) => {
                            WorkerReply::Error(error.to_string().chars().take(512).collect())
                        }
                    },
                    WorkerOperation::Destroy => match framework_stop
                        .lock()
                        .await
                        .destroy_with_receipt(&receipt_directory, assigned_id, || {
                            backend.destroy_vm(assigned_id)
                        })
                        .await
                    {
                        Ok(()) => WorkerReply::Destroyed,
                        Err(error) => {
                            WorkerReply::Error(error.to_string().chars().take(512).collect())
                        }
                    },
                    WorkerOperation::Connect { port } => {
                        let Ok(_stream_slot) = stream_slots.try_acquire_owned() else {
                            let _ = tokio::time::timeout(
                                Duration::from_secs(5),
                                write_frame(
                                    &mut stream,
                                    &WorkerReply::Error("guest stream capacity exhausted".into()),
                                ),
                            )
                            .await;
                            return;
                        };
                        match backend.vsock_connect(assigned_id, port).await {
                            Ok(mut guest) => {
                                if matches!(
                                    tokio::time::timeout(
                                        Duration::from_secs(5),
                                        write_frame(&mut stream, &WorkerReply::Stream)
                                    )
                                    .await,
                                    Ok(Ok(()))
                                ) {
                                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut guest)
                                        .await;
                                }
                                return;
                            }
                            Err(error) => {
                                WorkerReply::Error(error.to_string().chars().take(512).collect())
                            }
                        }
                    }
                },
            };
            let _ = tokio::time::timeout(Duration::from_secs(5), write_frame(&mut stream, &reply))
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn control_socket_path_limit_is_checked_before_launch() {
        let socket: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        let max_runtime_bytes = socket.sun_path.len() - CONTROL_SOCKET.len() - 2;
        let valid = format!("/{}", "x".repeat(max_runtime_bytes - 1));
        validate_control_path(Path::new(&valid)).unwrap();
        assert!(validate_control_path(Path::new(&(valid + "x"))).is_err());
        assert!(validate_control_path(Path::new("/tmp/invalid\0path")).is_err());
    }
    #[tokio::test]
    async fn failed_stop_and_cancelled_observation_never_publish_stop_proof() {
        let dir = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4();
        let mut state = FrameworkStopState::default();
        assert!(state.persist(dir.path(), id).is_err());
        assert!(
            state
                .destroy_with_receipt(dir.path(), id, || async { Err(VmmError::VmNotFound(id)) })
                .await
                .is_err()
        );
        assert!(!state.confirmed);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                state.destroy_with_receipt(dir.path(), id, std::future::pending)
            )
            .await
            .is_err()
        );
        assert!(!state.confirmed);
        assert!(state.receipt.is_none());
        assert!(!dir.path().join(STOP_RECEIPT).exists());
    }

    #[tokio::test]
    async fn stop_receipt_creation_failure_retries_without_destroying_again() {
        let dir = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4();
        let path = dir.path().join(STOP_RECEIPT);
        std::fs::create_dir(&path).unwrap();
        let mut state = FrameworkStopState::default();
        assert!(
            state
                .destroy_with_receipt(dir.path(), id, || async { Ok(()) })
                .await
                .is_err()
        );
        assert!(state.confirmed);
        assert!(state.receipt.is_none());
        assert!(path.is_dir());
        std::fs::remove_dir(&path).unwrap();
        state
            .destroy_with_receipt(dir.path(), id, || async {
                panic!("confirmed stop must not enter backend again")
            })
            .await
            .unwrap();
        let receipt: FrameworkStopReceipt =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(receipt.vm_id, id);
        assert_eq!(receipt.version, 1);
        state
            .destroy_with_receipt(dir.path(), id, || async {
                panic!("replayed destruction must only reconcile receipt")
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn stop_receipt_repairs_only_retained_inode_and_refuses_foreign_files() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4();
        let path = dir.path().join(STOP_RECEIPT);
        let moved = dir.path().join("retained-receipt");
        let mut state = FrameworkStopState::default();
        state
            .destroy_with_receipt(dir.path(), id, || async { Ok(()) })
            .await
            .unwrap();
        let file = state.receipt.as_mut().unwrap();
        file.set_len(0).unwrap();
        file.write_all(b"partial").unwrap();
        state.persist(dir.path(), id).unwrap();
        let receipt: FrameworkStopReceipt =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(receipt.vm_id, id);

        std::fs::rename(&path, &moved).unwrap();
        std::fs::write(&path, b"foreign file remains untouched").unwrap();
        assert!(state.persist(dir.path(), id).is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"foreign file remains untouched"
        );
        let mut foreign = FrameworkStopState {
            confirmed: true,
            ..Default::default()
        };
        assert!(foreign.persist(dir.path(), id).is_err());
        assert!(foreign.receipt.is_none());
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(&moved, &path).unwrap();
        state.persist(dir.path(), id).unwrap();
    }

    #[tokio::test]
    async fn framed_protocol_preserves_following_stream_bytes_and_rejects_excessive_frame() {
        let (mut write, mut read) = tokio::io::duplex(1024);
        write_frame(&mut write, &WorkerReply::Stream).await.unwrap();
        write.write_all(b"guest bytes").await.unwrap();
        assert!(matches!(
            read_frame::<_, WorkerReply>(&mut read).await.unwrap(),
            WorkerReply::Stream
        ));
        let mut raw = [0; 11];
        read.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"guest bytes");
        write.write_u32(MAX_FRAME_BYTES as u32 + 1).await.unwrap();
        assert!(
            read_frame::<_, WorkerReply>(&mut read)
                .await
                .unwrap_err()
                .to_string()
                .contains("64 KiB")
        );
    }
    #[tokio::test]
    async fn malformed_and_oversized_messages_never_enter_native_operations() {
        let (mut write, mut read) = tokio::io::duplex(1024);
        write.write_u32(0).await.unwrap();
        assert!(read_frame::<_, WorkerRequest>(&mut read).await.is_err());
        let malformed = br#"{"version":1,"vm_id":"00000000-0000-0000-0000-000000000001","operation":{"operation":"Inspect"},"extra":true}"#;
        write.write_u32(malformed.len() as u32).await.unwrap();
        write.write_all(malformed).await.unwrap();
        assert!(read_frame::<_, WorkerRequest>(&mut read).await.is_err());
        let error = WorkerReply::Error("x".repeat(MAX_FRAME_BYTES));
        assert!(write_frame(&mut write, &error).await.is_err());
        drop(write);
        // The oversized encoder must not have emitted even a partial frame header.
        let mut tail = vec![];
        read.read_to_end(&mut tail).await.unwrap();
        assert!(tail.is_empty());
    }

    #[test]
    fn create_refuses_network_and_extra_devices_before_native_execution() {
        let id = Uuid::new_v4();
        let config = VmConfig {
            requested_id: Some(id),
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
            boot: crate::BootMode::DirectKernel,
            seed_path: None,
            balloon: false,
            volume_path: None,
            network_disabled: true,
            host_shares: vec![],
        };
        let request = |config| WorkerRequest {
            version: 1,
            vm_id: id,
            operation: WorkerOperation::Create(Box::new(config)),
        };
        validate_request(&request(config.clone()), id).unwrap();
        let mut invalid = vec![];
        let mut changed = config.clone();
        changed.network_disabled = false;
        invalid.push(changed);
        let mut changed = config.clone();
        changed.requested_id = None;
        invalid.push(changed);
        let mut changed = config.clone();
        changed.tap_device = Some("tap0".into());
        invalid.push(changed);
        let mut changed = config.clone();
        changed.volume_path = Some("/extra-disk".into());
        invalid.push(changed);
        let mut changed = config.clone();
        changed.seed_path = Some("/seed".into());
        invalid.push(changed);
        let mut changed = config.clone();
        changed.balloon = true;
        invalid.push(changed);
        let mut changed = config.clone();
        changed.mem_size_mib = 0;
        invalid.push(changed);
        let mut changed = config.clone();
        changed.vcpu_count = 0;
        invalid.push(changed);
        let mut changed = config.clone();
        changed.vsock_cid = 2;
        invalid.push(changed);
        let mut changed = config;
        changed.host_shares.push(crate::HostShare {
            host: "/host-share".into(),
            guest: "/guest-share".into(),
            read_only: true,
            tag: "fs0".into(),
        });
        invalid.push(changed);
        for config in invalid {
            assert!(validate_request(&request(config), id).is_err());
        }
    }

    #[test]
    fn protocol_generation_version_port_and_lifetime_are_bounded() {
        let id = Uuid::new_v4();
        let mut request = WorkerRequest {
            version: 1,
            vm_id: id,
            operation: WorkerOperation::Inspect,
        };
        validate_request(&request, id).unwrap();
        request.vm_id = Uuid::new_v4();
        assert!(validate_request(&request, id).is_err());
        request.vm_id = id;
        request.version = 2;
        assert!(validate_request(&request, id).is_err());
        request.version = 1;
        request.operation = WorkerOperation::Connect {
            port: husker_agent_proto::AGENT_VSOCK_PORT,
        };
        validate_request(&request, id).unwrap();
        for port in [0, 80, 1024, 65535] {
            request.operation = WorkerOperation::Connect { port };
            assert!(validate_request(&request, id).is_err());
        }
        assert_eq!(
            lifetime_remaining(3601, 1).unwrap(),
            Duration::from_secs(3600)
        );
        for deadline in [0, 1, 3602, u64::MAX] {
            assert!(lifetime_remaining(deadline, 1).is_err());
        }
    }
}
