//! Opt-in offline VZ backend with one supervised child per VM generation.
//! Native construction happens only in that child. Registry ownership precedes
//! filesystem setup and launch; failures/cancellation keep a destroyable owner.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;
use uuid::Uuid;

use crate::vz_worker::{CONTROL_SOCKET, WorkerOperation, WorkerReply};
use crate::vz_worker_owner::{WorkerDeathProof, WorkerExecutable, WorkerOwner};
use crate::{
    BackendKind, BackendRequirements, BackendSelection, CreatedVm, VmConfig, VmInfo, VmState,
    VmmBackend, VmmError,
};

fn error(message: impl std::fmt::Display) -> VmmError {
    VmmError::ProcessError(format!("VZ child backend: {message}"))
}

#[derive(Default)]
struct RuntimeOwnership {
    identity: Option<(u64, u64)>,
    collision: bool,
    directory: Option<std::fs::File>,
    removed: bool,
    framework_confirmed: bool,
}

struct Entry {
    name: String,
    owner: WorkerOwner,
    info: Mutex<VmInfo>,
    runtime: PathBuf,
    files: Mutex<RuntimeOwnership>,
}

pub struct AppleVzWorkerBackend {
    runtime_dir: PathBuf,
    executable: WorkerExecutable,
    lifetime_secs: u64,
    instances: Mutex<HashMap<Uuid, Arc<Entry>>>,
    creation_locks: crate::creation::CreationLocks,
}

impl AppleVzWorkerBackend {
    pub fn new(
        runtime_dir: PathBuf,
        executable: WorkerExecutable,
        lifetime_secs: u64,
    ) -> Result<Self, VmmError> {
        if !runtime_dir.is_absolute() || !(1..=3600).contains(&lifetime_secs) {
            return Err(error(
                "absolute runtime root and lifetime in 1..=3600s required",
            ));
        }
        crate::vz_worker::validate_control_path(&runtime_dir.join(generation_dir(Uuid::nil())))?;
        Ok(Self {
            runtime_dir,
            executable,
            lifetime_secs,
            instances: Mutex::new(HashMap::new()),
            creation_locks: Default::default(),
        })
    }

    async fn entry(&self, id: Uuid) -> Result<Arc<Entry>, VmmError> {
        self.instances
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or(VmmError::VmNotFound(id))
    }

    fn prepare_runtime(&self, entry: &Entry, files: &mut RuntimeOwnership) -> Result<(), VmmError> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
        let root = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&self.runtime_dir)
            .map_err(error)?;
        let metadata = root.metadata().map_err(error)?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            return Err(error("protected owned runtime root required"));
        }
        match std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&entry.runtime)
        {
            Ok(()) => {}
            Err(failure) => {
                files.collision = failure.kind() == std::io::ErrorKind::AlreadyExists;
                return Err(error(failure));
            }
        }
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&entry.runtime)
            .map_err(error)?;
        let metadata = directory.metadata().map_err(error)?;
        files.identity = Some((metadata.dev(), metadata.ino()));
        files.directory = Some(directory);
        Ok(())
    }

    fn validate_framework_stop(entry: &Entry) -> Result<(), VmmError> {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(entry.runtime.join(crate::vz_worker::STOP_RECEIPT))
            .map_err(|_| error("child reaped but framework stop unconfirmed; retain resources"))?;
        let metadata = file.metadata().map_err(error)?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() > 512
        {
            return Err(error("invalid framework stop receipt; resources retained"));
        }
        let mut bytes = vec![];
        file.take(513).read_to_end(&mut bytes).map_err(error)?;
        let receipt: crate::vz_worker::FrameworkStopReceipt =
            serde_json::from_slice(&bytes).map_err(error)?;
        if bytes.len() as u64 != metadata.len()
            || receipt.version != 1
            || entry.runtime.file_name().and_then(|name| name.to_str())
                != Some(generation_dir(receipt.vm_id).as_str())
        {
            return Err(error("framework receipt generation changed"));
        }
        Ok(())
    }

    async fn cleanup_runtime(
        entry: &Entry,
        files: &mut RuntimeOwnership,
        proof: WorkerDeathProof,
    ) -> Result<(), VmmError> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        if files.removed {
            return match entry.runtime.symlink_metadata() {
                Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => Ok(()),
                _ => Err(error("replacement path exists after confirmed cleanup")),
            };
        }
        if files.collision {
            return Err(error("preexisting runtime ownership remains uncertain"));
        }
        let metadata = match entry.runtime.symlink_metadata() {
            Ok(metadata) => metadata,
            Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => {
                // A retained directory FD distinguishes completed unlink from a
                // rename. A dropped filesystem observer cannot strand cleanup.
                if files.identity.is_none()
                    || files.directory.as_ref().is_some_and(|directory| {
                        directory
                            .metadata()
                            .is_ok_and(|metadata| metadata.nlink() == 0)
                    })
                {
                    return Ok(());
                }
                return Err(error(
                    "owned directory disappeared without confirmed unlink",
                ));
            }
            Err(failure) => return Err(error(failure)),
        };
        if !metadata.is_dir()
            || files.identity != Some((metadata.dev(), metadata.ino()))
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(error("runtime generation identity changed; files retained"));
        }
        let id = entry.info.lock().await.id;
        let serial = format!("{id}.serial.log");
        let mut paths = vec![];
        for item in std::fs::read_dir(&entry.runtime).map_err(error)? {
            let item = item.map_err(error)?;
            let name = item.file_name();
            let metadata = item.path().symlink_metadata().map_err(error)?;
            if proof != WorkerDeathProof::ChildReaped
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.nlink() != 1
                || metadata.mode() & 0o077 != 0
                || !((name == CONTROL_SOCKET && metadata.file_type().is_socket())
                    || (name == serial.as_str()
                        && metadata.is_file()
                        && metadata.len() <= crate::serial_capture::SERIAL_LOG_BYTES as u64)
                    || (name == crate::vz_worker::STOP_RECEIPT
                        && metadata.is_file()
                        && metadata.len() <= 512))
            {
                return Err(error(
                    "unexpected runtime entry; no recursive or unowned cleanup",
                ));
            }
            paths.push(item.path());
        }
        // Validate the entire inventory before removing anything. A later failure
        // keeps the owner and its positive process receipt for an exact retry.
        for path in paths {
            crate::termination::remove_runtime_file(&path).await?;
        }
        // No await between successful unlink and recording the receipt.
        std::fs::remove_dir(&entry.runtime).map_err(error)?;
        files.removed = true;
        Ok(())
    }
}

/// Per-VM runtime directory, relative to the backend runtime root, that the
/// child worker owns for one creation generation.
fn generation_dir(id: Uuid) -> String {
    format!("vz-worker-{id}")
}

impl VmmBackend for AppleVzWorkerBackend {
    type VsockStream = crate::fd_stream::FdStream;
    fn backend_kind(&self) -> &'static str {
        "apple_vz"
    }
    fn serial_log_file(&self, id: Uuid) -> PathBuf {
        // The child runs an in-process VZ backend rooted at its generation
        // directory, which names the log exactly as the native backend does.
        PathBuf::from(generation_dir(id)).join(format!("{id}.serial.log"))
    }
    fn select_backend(
        &self,
        requirements: BackendRequirements,
    ) -> Result<BackendSelection, VmmError> {
        if requirements.requested.is_some()
            || requirements.has_host_shares
            || requirements.boot != crate::BootKind::DirectKernel
        {
            return Err(VmmError::Unsupported(
                "VZ child backend supports offline direct-kernel jobs without host shares".into(),
            ));
        }
        Ok(BackendSelection::new(requirements, BackendKind::AppleVz))
    }
    async fn create_vm(
        &self,
        selection: BackendSelection,
        mut config: VmConfig,
    ) -> Result<CreatedVm, VmmError> {
        selection.validate_for_backend(&config, BackendKind::AppleVz)?;
        let id = crate::creation_id(&config)?;
        config.requested_id = Some(id);
        let guard = self.creation_locks.lock(id).await;
        let deadline = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(error)?
            .as_secs()
            .checked_add(self.lifetime_secs)
            .ok_or_else(|| error("lifetime overflow"))?;
        let runtime = self.runtime_dir.join(generation_dir(id));
        let owner = WorkerOwner::new(
            config.clone(),
            runtime.clone(),
            deadline,
            self.executable.clone(),
        )?;
        let entry = Arc::new(Entry {
            name: config.name.clone(),
            owner,
            runtime,
            files: Mutex::new(RuntimeOwnership::default()),
            info: Mutex::new(VmInfo {
                id,
                name: config.name.clone(),
                state: VmState::Creating,
                pid: None,
                vcpu_count: config.vcpu_count,
                mem_size_mib: config.mem_size_mib,
                vsock_cid: config.vsock_cid,
            }),
        });
        {
            let mut instances = self.instances.lock().await;
            if instances.contains_key(&id) {
                return Err(VmmError::InvalidConfig(
                    "requested UUID already owned".into(),
                ));
            }
            if instances
                .values()
                .any(|previous| previous.runtime == entry.runtime)
            {
                return Err(error("runtime already owned"));
            }
            // Immutable names are checked in the insertion critical section.
            if instances
                .values()
                .any(|previous| previous.name == config.name)
            {
                return Err(VmmError::VmAlreadyExists(config.name));
            }
            if instances.len() >= 16 {
                return Err(error("VZ child ownership capacity exhausted"));
            }
            instances.insert(id, entry.clone());
        }
        {
            let mut files = entry.files.lock().await;
            self.prepare_runtime(&entry, &mut files)?;
            entry.owner.launch().await?;
            entry.info.lock().await.pid = entry.owner.pid().await;
        }
        // Native/RPC observation never holds the creation lock. Destroy can
        // kill/reap the child while construction or a vsock callback is hung.
        drop(guard);
        let result = entry.owner.create().await;
        let _publication = self.creation_locks.lock(id).await;
        if !self
            .instances
            .lock()
            .await
            .get(&id)
            .is_some_and(|current| Arc::ptr_eq(current, &entry))
            || entry.owner.death_confirmed().await
        {
            return Err(error(
                "creation completed after owned destruction; no running VM publication",
            ));
        }
        match result {
            Ok(connection) => match connection.reply {
                WorkerReply::Info(mut info) => {
                    info.pid = entry.owner.pid().await;
                    *entry.info.lock().await = info.clone();
                    Ok(CreatedVm::new(info, selection))
                }
                WorkerReply::Error(message) => {
                    entry.info.lock().await.state = VmState::Failed;
                    Err(error(message))
                }
                _ => Err(error("invalid create reply")),
            },
            Err(failure) => {
                entry.info.lock().await.state = VmState::Failed;
                Err(failure)
            }
        }
    }
    async fn abort_create(&self, id: Uuid) -> Result<(), VmmError> {
        crate::abort_registered_create(self.destroy_vm(id).await)
    }

    async fn destroy_vm(&self, id: Uuid) -> Result<(), VmmError> {
        let _guard = self.creation_locks.lock(id).await;
        let entry = self.entry(id).await?;
        let mut files = entry.files.lock().await;
        if entry.owner.creation_frame_started() && !entry.owner.death_confirmed().await {
            // Destruction is generation-bound and retryable; creation is not.
            // Give transient receipt publication failure an opportunity to
            // recover, without extending the independent kill/reap deadline.
            let _ = tokio::time::timeout(Duration::from_secs(7), async {
                for attempt in 0..3 {
                    if entry
                        .owner
                        .rpc(WorkerOperation::Destroy, Duration::from_secs(7))
                        .await
                        .is_ok_and(|connection| matches!(connection.reply, WorkerReply::Destroyed))
                    {
                        break;
                    }
                    if attempt < 2 {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            })
            .await;
        }
        let proof = entry.owner.destroy().await?;
        if entry.owner.creation_frame_started() && !files.framework_confirmed {
            Self::validate_framework_stop(&entry)?;
            // Retain positive proof before any cancellable file removal. The
            // receipt itself may already be gone on the next cleanup attempt.
            files.framework_confirmed = true;
        }
        entry.info.lock().await.state = VmState::Stopped;
        Self::cleanup_runtime(&entry, &mut files, proof).await?;
        let mut instances = self.instances.lock().await;
        if !instances
            .get(&id)
            .is_some_and(|current| Arc::ptr_eq(current, &entry))
        {
            return Err(error("replacement generation ownership retained"));
        }
        instances.remove(&id);
        Ok(())
    }
    async fn vm_info(&self, id: Uuid) -> Result<VmInfo, VmmError> {
        let entry = self.entry(id).await?;
        match entry
            .owner
            .rpc(WorkerOperation::Inspect, Duration::from_secs(1))
            .await
        {
            Ok(connection) => {
                if let WorkerReply::Info(mut info) = connection.reply {
                    info.pid = entry.owner.pid().await;
                    *entry.info.lock().await = info;
                } else {
                    entry.info.lock().await.state = VmState::Failed;
                }
            }
            Err(_) => entry.info.lock().await.state = VmState::Failed,
        }
        // One-second observation keeps the core's 15s cleanup pass able to
        // reach independent kill/reap even when a native state query is hung.
        // Cached Failed is ownership metadata, never a destruction receipt.
        Ok(entry.info.lock().await.clone())
    }
    async fn vsock_connect(&self, id: Uuid, port: u32) -> Result<Self::VsockStream, VmmError> {
        use std::os::fd::IntoRawFd;
        let entry = self.entry(id).await?;
        let connection = entry
            .owner
            .rpc(WorkerOperation::Connect { port }, Duration::from_secs(30))
            .await?;
        if !matches!(connection.reply, WorkerReply::Stream) {
            return Err(error("guest stream was not accepted"));
        }
        let descriptor = connection.stream.into_std().map_err(error)?.into_raw_fd();
        // Ownership of this descriptor is transferred; the constructor closes it
        // if registration fails. Child destruction closes the other endpoint.
        unsafe { crate::fd_stream::FdStream::from_owned_raw_fd(descriptor).map_err(error) }
    }
    async fn set_balloon(&self, _id: Uuid, _amount_mib: u32) -> Result<(), VmmError> {
        Err(VmmError::Unsupported("VZ child balloon".into()))
    }
    async fn stop_vm(&self, _id: Uuid) -> Result<(), VmmError> {
        Err(VmmError::Unsupported(
            "VZ child graceful stop; use confirmed destroy".into(),
        ))
    }
    async fn pause_vm(&self, _id: Uuid) -> Result<(), VmmError> {
        Err(VmmError::Unsupported("VZ child pause".into()))
    }
    async fn resume_vm(&self, _id: Uuid) -> Result<(), VmmError> {
        Err(VmmError::Unsupported("VZ child resume".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;

    fn backend(directory: &std::path::Path) -> AppleVzWorkerBackend {
        let executable = directory.join("reviewed-never-launched-fixture");
        let bytes = b"#!/bin/sh\nexit 0\n";
        std::fs::write(&executable, bytes).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        AppleVzWorkerBackend::new(
            directory.to_path_buf(),
            WorkerExecutable::new(executable, Sha256::digest(bytes).into()).unwrap(),
            60,
        )
        .unwrap()
    }
    #[test]
    fn serial_log_file_names_the_log_inside_the_child_generation_directory() {
        let directory = tempfile::tempdir_in("/private/tmp").unwrap();
        let backend = backend(directory.path());
        let id = Uuid::new_v4();
        // The child roots its VZ backend at the generation directory, which
        // names the serial log `<id>.serial.log` like any native VZ VM.
        assert_eq!(
            backend.runtime_dir.join(backend.serial_log_file(id)),
            directory
                .path()
                .join(format!("vz-worker-{id}"))
                .join(format!("{id}.serial.log"))
        );
    }

    async fn tracked(backend: &AppleVzWorkerBackend) -> (Uuid, Arc<Entry>) {
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
        let runtime = backend.runtime_dir.join(generation_dir(id));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let entry = Arc::new(Entry {
            name: config.name.clone(),
            owner: WorkerOwner::new(
                config.clone(),
                runtime.clone(),
                now + 60,
                backend.executable.clone(),
            )
            .unwrap(),
            runtime,
            files: Mutex::new(Default::default()),
            info: Mutex::new(VmInfo {
                id,
                name: config.name,
                state: VmState::Creating,
                pid: None,
                vcpu_count: 1,
                mem_size_mib: 512,
                vsock_cid: 3,
            }),
        });
        backend.instances.lock().await.insert(id, entry.clone());
        (id, entry)
    }
    #[tokio::test]
    async fn cleanup_failure_retains_reaped_child_and_retries_exact_owned_directory() {
        let dir = tempfile::tempdir_in("/private/tmp").unwrap();
        let backend = backend(dir.path());
        let (id, entry) = tracked(&backend).await;
        backend
            .prepare_runtime(&entry, &mut *entry.files.lock().await)
            .unwrap();
        entry.owner.install_sleeper_fixture().await;
        let obstruction = entry.runtime.join("unexpected");
        std::fs::write(&obstruction, b"retain for operator").unwrap();
        assert!(backend.destroy_vm(id).await.is_err());
        assert!(entry.owner.death_confirmed().await);
        assert!(obstruction.exists());
        assert!(Arc::ptr_eq(&backend.entry(id).await.unwrap(), &entry));
        std::fs::remove_file(obstruction).unwrap();
        backend.destroy_vm(id).await.unwrap();
        assert!(!entry.runtime.exists());
        assert!(matches!(
            backend.destroy_vm(id).await,
            Err(VmmError::VmNotFound(_))
        ));
    }
    #[tokio::test]
    async fn reaped_child_rejects_directory_rename_until_exact_path_restored() {
        let dir = tempfile::tempdir_in("/private/tmp").unwrap();
        let backend = backend(dir.path());
        let (id, entry) = tracked(&backend).await;
        backend
            .prepare_runtime(&entry, &mut *entry.files.lock().await)
            .unwrap();
        entry.owner.install_sleeper_fixture().await;
        entry.owner.destroy().await.unwrap();
        let moved = entry.runtime.with_extension("moved");
        std::fs::rename(&entry.runtime, &moved).unwrap();
        assert!(backend.destroy_vm(id).await.is_err());
        assert!(moved.exists());
        assert!(backend.entry(id).await.is_ok());
        std::fs::rename(&moved, &entry.runtime).unwrap();
        backend.destroy_vm(id).await.unwrap();
        assert!(backend.entry(id).await.is_err());
    }
    #[tokio::test]
    async fn creation_requires_stop_receipt_and_retains_validated_proof_during_cleanup() {
        let dir = tempfile::tempdir_in("/private/tmp").unwrap();
        let backend = backend(dir.path());
        let (id, entry) = tracked(&backend).await;
        backend
            .prepare_runtime(&entry, &mut *entry.files.lock().await)
            .unwrap();
        entry.owner.install_sleeper_fixture().await;
        entry.owner.mark_creation_frame_fixture();
        entry.owner.destroy().await.unwrap();
        assert!(backend.destroy_vm(id).await.is_err());
        assert!(entry.runtime.exists());
        assert!(!entry.files.lock().await.framework_confirmed);

        let receipt_path = entry.runtime.join(crate::vz_worker::STOP_RECEIPT);
        let write_receipt = |bytes: &[u8]| {
            std::fs::write(&receipt_path, bytes).unwrap();
            std::fs::set_permissions(&receipt_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        };
        for bytes in [
            b"not JSON".to_vec(),
            serde_json::to_vec(&crate::vz_worker::FrameworkStopReceipt {
                version: 1,
                vm_id: Uuid::new_v4(),
            })
            .unwrap(),
            serde_json::to_vec(&crate::vz_worker::FrameworkStopReceipt {
                version: 2,
                vm_id: id,
            })
            .unwrap(),
        ] {
            write_receipt(&bytes);
            assert!(backend.destroy_vm(id).await.is_err());
            assert!(!entry.files.lock().await.framework_confirmed);
        }
        write_receipt(
            &serde_json::to_vec(&crate::vz_worker::FrameworkStopReceipt {
                version: 1,
                vm_id: id,
            })
            .unwrap(),
        );
        let obstruction = entry.runtime.join("unexpected");
        std::fs::write(&obstruction, b"retain").unwrap();
        assert!(backend.destroy_vm(id).await.is_err());
        assert!(entry.files.lock().await.framework_confirmed);
        // Model interruption after removing the receipt but before removing
        // the directory. The retained proof must survive that retry boundary.
        std::fs::remove_file(receipt_path).unwrap();
        std::fs::remove_file(obstruction).unwrap();
        backend.destroy_vm(id).await.unwrap();
        assert!(!entry.runtime.exists());
        assert!(backend.entry(id).await.is_err());
    }
    #[tokio::test]
    async fn preexisting_directory_is_not_adopted_or_removed_after_no_child_launch() {
        let dir = tempfile::tempdir_in("/private/tmp").unwrap();
        let backend = backend(dir.path());
        let (id, entry) = tracked(&backend).await;
        std::fs::create_dir(&entry.runtime).unwrap();
        assert!(
            backend
                .prepare_runtime(&entry, &mut *entry.files.lock().await)
                .is_err()
        );
        assert!(backend.destroy_vm(id).await.is_err());
        assert!(!entry.owner.death_confirmed().await);
        assert!(entry.runtime.exists());
        assert!(backend.entry(id).await.is_ok());
    }
    #[tokio::test]
    async fn stalled_inspection_preserves_identity_and_leaves_time_for_core_cleanup() {
        let dir = tempfile::tempdir_in("/private/tmp").unwrap();
        let backend = backend(dir.path());
        let (id, entry) = tracked(&backend).await;
        backend
            .prepare_runtime(&entry, &mut *entry.files.lock().await)
            .unwrap();
        entry.owner.install_sleeper_fixture().await;
        let pid = entry.owner.pid().await;
        entry.info.lock().await.pid = pid;
        let info = tokio::time::timeout(Duration::from_secs(2), backend.vm_info(id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(info.id, id);
        assert_eq!(info.vsock_cid, 3);
        assert_eq!(info.pid, pid);
        assert_eq!(info.state, VmState::Failed);
        assert!(!entry.owner.death_confirmed().await);
        tokio::time::timeout(Duration::from_secs(2), backend.destroy_vm(id))
            .await
            .unwrap()
            .unwrap();
        assert!(entry.owner.death_confirmed().await);
    }

    #[tokio::test]
    async fn transient_stop_receipt_failure_retries_within_same_destruction_pass() {
        let dir = tempfile::tempdir_in("/private/tmp").unwrap();
        let backend = backend(dir.path());
        let (id, entry) = tracked(&backend).await;
        backend
            .prepare_runtime(&entry, &mut *entry.files.lock().await)
            .unwrap();
        entry.owner.install_sleeper_fixture().await;
        entry.owner.mark_creation_frame_fixture();
        let socket = entry.runtime.join(CONTROL_SOCKET);
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let runtime = entry.runtime.clone();
        let server = tokio::spawn(async move {
            for attempt in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request: crate::vz_worker::WorkerRequest =
                    crate::vz_worker::read_frame(&mut stream).await.unwrap();
                assert_eq!(request.vm_id, id);
                assert!(matches!(request.operation, WorkerOperation::Destroy));
                let reply = if attempt == 2 {
                    let path = runtime.join(crate::vz_worker::STOP_RECEIPT);
                    std::fs::write(
                        &path,
                        serde_json::to_vec(&crate::vz_worker::FrameworkStopReceipt {
                            version: 1,
                            vm_id: id,
                        })
                        .unwrap(),
                    )
                    .unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                    WorkerReply::Destroyed
                } else {
                    WorkerReply::Error("fixture receipt storage temporarily unavailable".into())
                };
                crate::vz_worker::write_frame(&mut stream, &reply)
                    .await
                    .unwrap();
            }
        });
        tokio::time::timeout(Duration::from_secs(2), backend.destroy_vm(id))
            .await
            .unwrap()
            .unwrap();
        server.await.unwrap();
        assert!(entry.owner.death_confirmed().await);
        assert!(!entry.runtime.exists());
        assert!(backend.entry(id).await.is_err());
    }

    #[tokio::test]
    async fn stalled_rpc_does_not_prevent_confirmed_backend_destruction() {
        let dir = tempfile::tempdir_in("/private/tmp").unwrap();
        let backend = backend(dir.path());
        let (id, entry) = tracked(&backend).await;
        backend
            .prepare_runtime(&entry, &mut *entry.files.lock().await)
            .unwrap();
        entry.owner.install_sleeper_fixture().await;
        let rpc_entry = entry.clone();
        let observer = tokio::spawn(async move { rpc_entry.owner.create().await });
        tokio::task::yield_now().await;
        tokio::time::timeout(Duration::from_secs(2), backend.destroy_vm(id))
            .await
            .unwrap()
            .unwrap();
        assert!(entry.owner.death_confirmed().await);
        assert!(observer.await.unwrap().is_err());
        assert!(!entry.runtime.exists());
    }
}
