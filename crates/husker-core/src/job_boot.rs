//! Prepared factory boot inputs. No mutable image resolution or agent refresh.
use super::*;
use husker_state::jobs::JobState;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

pub(crate) struct PreparedBoot {
    pub vm_id: Uuid,
}

fn invalid(message: impl Into<String>) -> CoreError {
    CoreError::InvalidArgument(message.into())
}

#[cfg(unix)]
fn private_directory(path: &std::path::Path) -> Result<(), CoreError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(invalid(format!("create prepared input directory: {error}"))),
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| invalid(format!("inspect prepared input directory: {error}")))?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(invalid(
            "prepared input directory must be private, owned and not a symlink",
        ));
    }
    Ok(())
}

#[cfg(unix)]
async fn copy_verified(
    source: &std::path::Path,
    destination: &std::path::Path,
    expected: &str,
    limit: u64,
) -> Result<(), CoreError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let input = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source)
        .map_err(|error| invalid(format!("open pinned boot input: {error}")))?;
    let metadata = input
        .metadata()
        .map_err(|error| invalid(error.to_string()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > limit {
        return Err(invalid(
            "pinned boot input is not a bounded nonempty regular file",
        ));
    }
    let output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(destination)
        .map_err(|error| invalid(format!("create private boot input: {error}")))?;
    let mut input = tokio::fs::File::from_std(input);
    let mut output = tokio::fs::File::from_std(output);
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 1024 * 1024];
    let zeroes = vec![0; buffer.len()];
    let mut copied = 0u64;
    loop {
        let count = input
            .read(&mut buffer)
            .await
            .map_err(|error| invalid(error.to_string()))?;
        if count == 0 {
            break;
        }
        copied += count as u64;
        if copied > limit {
            return Err(invalid("pinned boot input grew beyond limit"));
        }
        hash.update(&buffer[..count]);
        // Hash every logical byte, including holes, but avoid materializing
        // zero-filled extents in a multi-GiB sparse image. The new private inode
        // cannot contain stale data; seeks therefore represent authentic zeros.
        if buffer[..count] == zeroes[..count] {
            output
                .seek(std::io::SeekFrom::Current(count as i64))
                .await
                .map_err(|error| invalid(error.to_string()))?;
        } else {
            output
                .write_all(&buffer[..count])
                .await
                .map_err(|error| invalid(error.to_string()))?;
        }
    }
    if copied != metadata.len() || format!("sha256:{}", hex::encode(hash.finalize())) != expected {
        return Err(invalid("pinned boot input size or digest mismatch"));
    }
    output
        .flush()
        .await
        .map_err(|error| invalid(error.to_string()))?;
    // A final zero extent advances the offset without extending the inode.
    output
        .set_len(copied)
        .await
        .map_err(|error| invalid(error.to_string()))?;
    output
        .sync_all()
        .await
        .map_err(|error| invalid(error.to_string()))?;
    output
        .set_permissions(std::fs::Permissions::from_mode(0o400))
        .await
        .map_err(|error| invalid(error.to_string()))?;
    output
        .sync_all()
        .await
        .map_err(|error| invalid(error.to_string()))?;
    Ok(())
}

#[cfg(unix)]
async fn remove_directory(path: &std::path::Path) -> Result<(), CoreError> {
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(invalid(format!("remove factory directory: {error}"))),
    }
}

impl<B: VmmBackend> HuskerCore<B> {
    /// Caller holds the reserved-name lock, serializing against allocation.
    /// Factory cleanup also holds its job lifecycle lock. Match the exact
    /// entered lease and backend owner before destruction; retain positive
    /// completion synchronously before any fallible journal operation.
    pub(crate) async fn destroy_factory_allocation(
        &self,
        job_id: Uuid,
        vm_id: Uuid,
        lease_id: Option<Uuid>,
    ) -> Result<(), CoreError> {
        let job = self
            .state
            .get_job(job_id)
            .map_err(|error| invalid(error.to_string()))?;
        let name = format!("job-{job_id}");
        if job.vm_id != Some(vm_id)
            || job.vm_name.as_deref() != Some(&name)
            || !job.cleanup_pending
            || job.vm_allocation_aborted
        {
            return Err(invalid("factory backend destruction ownership mismatch"));
        }
        let related: Vec<_> = self
            .state
            .list_host_resource_leases()?
            .into_iter()
            .filter(|lease| lease.vm_id == Some(vm_id) || lease.vm_name == name)
            .collect();
        let lease = if let Some(lease_id) = lease_id {
            if related.len() != 1 || related[0].id != lease_id {
                return Err(invalid(
                    "factory backend destruction has conflicting lease owners",
                ));
            }
            let lease = &related[0];
            if lease.vm_id != Some(vm_id)
                || lease.vm_name != name
                || !lease.backend_entered
                || lease.allocation_aborted
                || lease.tap_device.is_some()
                || lease.guest_ip.is_some()
            {
                return Err(invalid("factory backend destruction ownership mismatch"));
            }
            Some(lease)
        } else {
            if !related.is_empty() {
                return Err(invalid(
                    "factory VM row has conflicting creation lease owners",
                ));
            }
            None
        };
        let record = match self.state.get_vm(vm_id) {
            Ok(vm) if vm.name == name => Some(vm),
            Ok(_) => {
                return Err(invalid(
                    "factory backend UUID belongs to a different VM name",
                ));
            }
            Err(husker_state::StateError::VmNotFound(_)) => None,
            Err(error) => return Err(error.into()),
        };
        match self.state.get_vm_by_name(&name) {
            Ok(vm) if vm.id == vm_id => (),
            Ok(_) => return Err(invalid("factory reserved name belongs to another VM UUID")),
            Err(husker_state::StateError::VmNotFoundByName(_)) => (),
            Err(error) => return Err(error.into()),
        }
        let cid = if let Some(lease) = lease {
            if record
                .as_ref()
                .is_some_and(|vm| vm.vsock_cid != lease.vsock_cid)
            {
                return Err(invalid("factory VM row differs from its creation lease"));
            }
            lease.vsock_cid
        } else {
            let vm = record.as_ref().ok_or_else(|| {
                invalid("factory destruction requires an exact VM row or entered lease")
            })?;
            if vm.network != NetworkMode::Isolated
                || vm.tap_device.is_some()
                || vm.guest_ip.is_some()
            {
                return Err(invalid(
                    "factory VM row has an incompatible offline profile",
                ));
            }
            vm.vsock_cid
        };
        let retained = self
            .factory_destroyed_allocations
            .lock()
            .get(&vm_id)
            .copied();
        if retained.is_some_and(|owner| owner != (job_id, lease_id)) {
            return Err(invalid("factory destruction confirmation owner mismatch"));
        }
        if !lease.is_some_and(|lease| lease.vm_destroyed) && retained.is_none() {
            match self.vmm.vm_info(vm_id).await {
                Ok(info) if info.id == vm_id && info.name == name && info.vsock_cid == cid => {}
                Ok(_) => {
                    return Err(invalid(
                        "factory backend identity differs from its creation lease",
                    ));
                }
                // An owned preflight process can precede VmInfo registration.
                // Only destroy's positive result can confirm its termination;
                // neither this error nor a later destroy NotFound suffices.
                Err(husker_vmm::VmmError::VmNotFound(missing)) if missing == vm_id => (),
                Err(error) => return Err(error.into()),
            }
            self.vmm.destroy_vm(vm_id).await?;
            // No await or fallible operation between positive destruction and
            // retained proof. Later retries do not infer death from VmNotFound.
            self.factory_destroyed_allocations
                .lock()
                .insert(vm_id, (job_id, lease_id));
        }
        if let Some(lease_id) = lease_id {
            self.state
                .record_host_resource_lease_destruction(lease_id, vm_id)?;
        }
        self.state
            .record_job_vm_destruction(vm_id)
            .map_err(|error| invalid(error.to_string()))?;
        self.factory_destroyed_allocations.lock().remove(&vm_id);
        Ok(())
    }

    /// Cleanup a terminal factory job without releasing ownership on failure.
    /// The lifecycle lock waits for allocation to finish; callers must keep the
    /// owning allocation task alive/joined even if the original request closes.
    /// Unknown allocations without a bound UUID remain pending, never guessed
    /// absent. Confirmed destruction and explicit pre-allocation abort receipts
    /// are durable across restart; absence alone is never a receipt.
    #[cfg(unix)]
    pub async fn cleanup_job_vm(&self, id: Uuid) -> Result<(), CoreError> {
        let _lifecycle = self.job_lifecycle_lock(id).lock_owned().await;
        let mut job = self
            .state
            .get_job(id)
            .map_err(|error| invalid(error.to_string()))?;
        if !job.state.terminal() {
            return Err(invalid("job must be terminal before cleanup"));
        }
        if !job.cleanup_pending {
            return Ok(());
        }
        let name = job
            .vm_name
            .as_deref()
            .ok_or_else(|| invalid("missing allocation ownership"))?;
        if name != format!("job-{id}") {
            return Err(invalid("factory allocation name mismatch"));
        }
        let vm_id = job
            .vm_id
            .ok_or_else(|| invalid("allocation UUID unknown; absence cannot be confirmed"))?;
        let _name = self.vm_name_lock(name).lock_owned().await;
        let leases: Vec<_> = self
            .state
            .list_host_resource_leases()?
            .into_iter()
            .filter(|lease| lease.vm_name == name || lease.vm_id == Some(vm_id))
            .collect();
        if leases.len() > 1 {
            return Err(invalid(
                "factory cleanup has conflicting creation lease owners",
            ));
        }
        for lease in &leases {
            if lease.vm_name != name
                || lease.tap_device.is_some()
                || lease.guest_ip.is_some()
                || lease.vm_id != Some(vm_id)
                || (job.vm_allocation_aborted && lease.backend_entered)
            {
                return Err(invalid(
                    "factory creation lease ownership or offline profile mismatch",
                ));
            }
            if lease.backend_entered && lease.vm_destroyed {
                self.state
                    .record_job_vm_destruction(vm_id)
                    .map_err(|error| invalid(error.to_string()))?;
                job.vm_destroyed = true;
            }
        }
        match self.state.get_vm_by_name(name) {
            Ok(vm) if vm.id == vm_id && !job.vm_allocation_aborted => {
                self.destroy_vm_locked(&vm).await?;
            }
            Ok(vm) if vm.id == vm_id => {
                return Err(invalid(
                    "VM exists despite a confirmed pre-allocation abort",
                ));
            }
            Ok(_) => {
                return Err(invalid(
                    "reserved name now belongs to a different VM generation",
                ));
            }
            Err(husker_state::StateError::VmNotFoundByName(_))
                if job.vm_destroyed || job.vm_allocation_aborted => {}
            Err(husker_state::StateError::VmNotFoundByName(_)) => {
                if leases.len() != 1 || !leases[0].backend_entered {
                    return Err(invalid(
                        "VM row absent without exact entered backend ownership",
                    ));
                }
                self.destroy_factory_allocation(id, vm_id, Some(leases[0].id))
                    .await?;
            }
            Err(error) => return Err(error.into()),
        }
        let confirmed = self
            .state
            .get_job(id)
            .map_err(|error| invalid(error.to_string()))?;
        if !confirmed.vm_destroyed && !confirmed.vm_allocation_aborted {
            return Err(invalid("VM destruction remains unconfirmed"));
        }
        self.factory_destroyed_allocations.lock().remove(&vm_id);
        // Generic destruction may previously have retired the VM row. Retry its
        // remaining generation-specific files without ever touching a replacement.
        let vm_directory = self.storage.vm_dir(name);
        remove_directory(&vm_directory).await?;
        for suffix in ["serial.log", "boot.log"] {
            let path = self.runtime_dir.join(format!("{vm_id}.{suffix}"));
            match tokio::fs::remove_file(&path).await {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(invalid(format!("remove factory runtime file: {error}"))),
            }
        }
        remove_directory(&self.suspend_slot_dir(vm_id)).await?;
        let parent = self.storage.data_dir.join("job-inputs");
        match std::fs::symlink_metadata(&parent) {
            Ok(_) => {
                private_directory(&parent)?;
                let inputs = parent.join(id.to_string());
                match std::fs::symlink_metadata(&inputs) {
                    Ok(metadata) if metadata.is_dir() => remove_directory(&inputs).await?,
                    Ok(_) => return Err(invalid("private job input directory was replaced")),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                    Err(error) => return Err(invalid(format!("inspect job inputs: {error}"))),
                }
                std::fs::File::open(&parent)
                    .and_then(|file| file.sync_all())
                    .map_err(|error| invalid(format!("sync private input removal: {error}")))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(invalid(format!("inspect private input parent: {error}"))),
        }
        for lease in &leases {
            if lease.backend_entered {
                self.state
                    .record_host_resource_lease_destruction(lease.id, vm_id)?;
            }
            self.state.release_host_resource_lease(lease.id)?;
        }
        self.state
            .confirm_job_cleanup(id, vm_id)
            .map_err(|error| invalid(error.to_string()))?;
        Ok(())
    }

    /// Allocate the VM for a newly accepted job, using authenticated private
    /// copies of catalog/rootfs and operator kernel/initrd inputs. This is an
    /// allocation primitive, not submission or execution. The owning worker must
    /// retain/join this future through cancellation; dropping creation mid-flight
    /// is not confirmed cleanup. Replayed Preparing jobs are never re-executed.
    /// Private boot inputs stay owned until VM destruction and worker cleanup.
    #[cfg(unix)]
    pub async fn create_reserved_job_vm(&self, id: Uuid) -> Result<VmRecord, CoreError> {
        let _lifecycle = self.job_lifecycle_lock(id).lock_owned().await;
        let job = self
            .state
            .get_job(id)
            .map_err(|error| invalid(error.to_string()))?;
        if job.state != JobState::Accepted {
            return Err(invalid("only a newly accepted job may allocate a VM"));
        }
        let spec: crate::job_spec::JobSpec = serde_json::from_str(&job.specification)
            .map_err(|error| invalid(format!("decode frozen job specification: {error}")))?;
        let canonical = spec
            .canonical_json()
            .map_err(|error| invalid(error.to_string()))?;
        if canonical != job.specification || spec.deadline.timestamp() != job.deadline {
            return Err(invalid("job specification is not canonical"));
        }
        // Filtered egress stays unsupported here until its pinned policy and
        // backend enforcement are integrated into the factory worker.
        if !matches!(spec.network, crate::job_spec::JobNetwork::None {}) {
            return Err(invalid(
                "prepared job allocation currently requires network none",
            ));
        }
        let image = self.state.get_image(spec.image.catalog_id)?;
        if image.kind != ImageKind::Rootfs
            || image.format != "ext4"
            || image.boot_init.is_some()
            || image.content_digest.as_deref() != Some(&spec.image.rootfs_digest)
        {
            return Err(invalid(
                "prepared image must be a pinned direct-kernel rootfs using /sbin/init",
            ));
        }
        let kernel = self
            .default_kernel
            .as_ref()
            .ok_or_else(|| invalid("prepared jobs require an operator kernel path"))?;
        let initrd = match &spec.image.initrd_digest {
            Some(_) => Some(
                self.default_initrd
                    .as_ref()
                    .ok_or_else(|| invalid("pinned initrd has no operator path"))?,
            ),
            None => None,
        };
        let reserved = self
            .state
            .claim_job_vm(id)
            .map_err(|error| invalid(error.to_string()))?;
        // Persist the intended UUID before filesystem or VMM allocation. A
        // crash after allocation begins leaves a generation even without a VM row.
        let vm_id = Uuid::new_v4();
        self.state
            .bind_job_vm(
                id,
                vm_id,
                reserved
                    .vm_name
                    .as_deref()
                    .ok_or_else(|| invalid("missing VM reservation"))?,
            )
            .map_err(|error| invalid(error.to_string()))?;
        // The journal reservation precedes the first filesystem allocation.
        let mut allocation_entered = false;
        let result = async {
            let parent = self.storage.data_dir.join("job-inputs");
            private_directory(&parent)?;
            let directory = parent.join(id.to_string());
            // An existing input directory is evidence of an earlier attempt,
            // never permission to retry creation or overwrite its files.
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .map_err(|error| invalid(format!("create new job input directory: {error}")))?;
            let rootfs_path = directory.join("rootfs.ext4");
            let kernel_path = directory.join("kernel");
            copy_verified(
                std::path::Path::new(&image.file_path),
                &rootfs_path,
                &spec.image.rootfs_digest,
                spec.resources.disk_size_bytes,
            )
            .await?;
            copy_verified(
                kernel,
                &kernel_path,
                &spec.image.kernel_digest,
                husker_types::factory_limits::KERNEL_BYTES,
            )
            .await?;
            let initrd_path =
                if let (Some(source), Some(digest)) = (initrd, &spec.image.initrd_digest) {
                    let destination = directory.join("initrd");
                    copy_verified(
                        source,
                        &destination,
                        digest,
                        husker_types::factory_limits::INITRD_BYTES,
                    )
                    .await?;
                    Some(destination)
                } else {
                    None
                };
            std::fs::File::open(&directory)
                .and_then(|file| file.sync_all())
                .map_err(|error| invalid(error.to_string()))?;
            std::fs::File::open(&parent)
                .and_then(|file| file.sync_all())
                .map_err(|error| invalid(error.to_string()))?;
            if chrono::Utc::now().timestamp() >= job.deadline {
                return Err(invalid("job deadline elapsed during boot preparation"));
            }
            // This fence is deliberately before the entire allocation routine,
            // including storage work. Any error after entry remains uncertain.
            allocation_entered = true;
            let record = self
                .create_vm_record_inner(
                    CreateVmRequest {
                        name: reserved
                            .vm_name
                            .clone()
                            .ok_or_else(|| invalid("missing VM reservation"))?,
                        kernel_path: Some(kernel_path),
                        rootfs_path: Some(rootfs_path),
                        initrd_path,
                        vcpu_count: Some(spec.resources.vcpu_count),
                        mem_size_mib: Some(spec.resources.mem_size_mib),
                        disk_size: Some(spec.resources.disk_size_bytes),
                        network: Some("none".into()),
                        ..Default::default()
                    },
                    None,
                    false,
                    Some(PendingVmExpiration {
                        owner: Some(format!("factory-job/{id}")),
                        expires_at: spec.deadline,
                    }),
                    Some(&PreparedBoot { vm_id }),
                )
                .await?;
            let bound = self
                .state
                .bind_job_vm(id, record.id, &record.name)
                .map_err(|error| invalid(error.to_string()))?;
            if bound.state != JobState::Preparing || chrono::Utc::now().timestamp() >= job.deadline
            {
                return Err(invalid(
                    "job stopped or deadline elapsed during VM allocation; cleanup remains pending",
                ));
            }
            Ok(record)
        }
        .await;
        if let Err(error) = &result {
            if !allocation_entered {
                self.state
                    .record_job_vm_allocation_abort(id, vm_id)
                    .map_err(|journal| {
                        invalid(format!("record pre-allocation abort: {journal}"))
                    })?;
            }
            let state = if chrono::Utc::now().timestamp() >= job.deadline {
                JobState::TimedOut
            } else {
                JobState::InfrastructureFailed
            };
            let manifest = serde_json::json!({"version":1,"job_id":id,"preparation_error":error.to_string().chars().take(512).collect::<String>()}).to_string();
            self.state
                .finish_job_failure(id, state, &manifest)
                .map_err(|journal| {
                    invalid(format!(
                        "preparation failed ({error}); journal failure: {journal}"
                    ))
                })?;
        }
        result
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn private_boot_copy_authenticates_actual_bytes_and_rejects_reuse_links_and_oversize() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let copy = temp.path().join("copy");
        std::fs::write(&source, b"pinned input").unwrap();
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(b"pinned input")));
        copy_verified(&source, &copy, &digest, 12).await.unwrap();
        std::fs::write(&source, b"new contents").unwrap();
        assert_eq!(std::fs::read(&copy).unwrap(), b"pinned input");
        assert!(copy_verified(&source, &copy, &digest, 12).await.is_err());
        assert!(
            copy_verified(&source, &temp.path().join("bad-hash"), &digest, 12)
                .await
                .is_err()
        );
        assert!(
            copy_verified(&source, &temp.path().join("oversize"), &digest, 1)
                .await
                .is_err()
        );
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&source, &link).unwrap();
        assert!(
            copy_verified(&link, &temp.path().join("link-copy"), &digest, 12)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn private_boot_copy_preserves_sparse_zeros_and_independent_authenticated_bytes() {
        use std::io::{Read, Seek, Write};
        use std::os::unix::fs::MetadataExt;
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("sparse-source");
        let destination = temp.path().join("private-copy");
        let size = 64 * 1024 * 1024;
        let mut file = std::fs::File::create(&source).unwrap();
        file.set_len(size).unwrap();
        file.write_all(b"header").unwrap();
        file.seek(std::io::SeekFrom::Start(size / 2)).unwrap();
        file.write_all(b"middle").unwrap();
        file.sync_all().unwrap();
        let mut bytes = Vec::new();
        std::fs::File::open(&source)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        copy_verified(&source, &destination, &digest, size)
            .await
            .unwrap();
        let metadata = std::fs::metadata(&destination).unwrap();
        assert_eq!(metadata.len(), size);
        assert_eq!(metadata.mode() & 0o777, 0o400);
        assert_ne!(metadata.ino(), std::fs::metadata(&source).unwrap().ino());
        assert_eq!(std::fs::read(&destination).unwrap(), bytes);
        assert!(
            metadata.blocks() * 512 < size / 4,
            "zero extents were materialized"
        );
        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        file.write_all(b"mutate").unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), bytes);
    }

    /// Host filesystem proof only: never allocates or boots a VM. The caller
    /// supplies an already prepared, immutable image and its reviewed digest.
    #[tokio::test]
    #[ignore = "requires explicit HUSKER_FACTORY_PREPARED_ROOTFS and digest; scans the full image"]
    async fn real_prepared_image_staging_and_writable_disk_are_independent() {
        use husker_storage::StorageDriver;
        use std::io::{Read, Seek, Write};
        use std::os::unix::fs::MetadataExt;
        let source =
            std::path::PathBuf::from(std::env::var("HUSKER_FACTORY_PREPARED_ROOTFS").unwrap());
        let digest = std::env::var("HUSKER_FACTORY_PREPARED_ROOTFS_DIGEST").unwrap();
        let source_metadata = std::fs::symlink_metadata(&source).unwrap();
        assert!(source_metadata.is_file());
        assert_eq!(source_metadata.mode() & 0o777, 0o400);
        let temp = tempfile::tempdir().unwrap();
        let staged = temp.path().join("sealed.ext4");
        let disk = temp.path().join("vm/rootfs.ext4");
        let start = std::time::Instant::now();
        copy_verified(&source, &staged, &digest, source_metadata.len())
            .await
            .unwrap();
        let elapsed_ms = start.elapsed().as_millis();
        let staged_metadata = std::fs::metadata(&staged).unwrap();
        assert_eq!(staged_metadata.mode() & 0o777, 0o400);
        assert!(staged_metadata.blocks() * 512 < staged_metadata.len());
        husker_storage::LocalStorageDriver
            .prepare_root_disk(husker_storage::RootDiskRequest {
                source: &staged,
                destination: &disk,
                size_bytes: Some(source_metadata.len()),
                guest_agent: &[],
            })
            .await
            .unwrap();
        assert_eq!(std::fs::metadata(&disk).unwrap().mode() & 0o777, 0o600);
        assert_ne!(
            std::fs::metadata(&disk).unwrap().ino(),
            staged_metadata.ino()
        );
        let mut before = [0u8; 32];
        std::fs::File::open(&staged)
            .unwrap()
            .read_exact(&mut before)
            .unwrap();
        let mut writer = std::fs::OpenOptions::new().write(true).open(&disk).unwrap();
        writer.seek(std::io::SeekFrom::Start(0)).unwrap();
        writer.write_all(&[0xA5; 32]).unwrap();
        writer.sync_all().unwrap();
        for path in [&source, &staged] {
            let mut after = [0u8; 32];
            std::fs::File::open(path)
                .unwrap()
                .read_exact(&mut after)
                .unwrap();
            assert_eq!(after, before);
            assert_eq!(std::fs::metadata(path).unwrap().mode() & 0o777, 0o400);
        }
        println!(
            "{}",
            serde_json::json!({"scope":"host-prepared-image-copy-only",
            "logical_bytes":staged_metadata.len(),"allocated_bytes":staged_metadata.blocks()*512,
            "staging_duration_ms":elapsed_ms,"vm_booted":false})
        );
    }
}

#[cfg(test)]
mod allocation_recovery_tests {
    use super::*;
    use husker_state::jobs::CollectionState;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    // Pure ownership fixture: no child, VM, guest, socket or network operation.
    struct OwnedAllocation {
        id: Uuid,
        info: parking_lot::Mutex<Option<husker_vmm::VmInfo>>,
        owned: AtomicBool,
        fail_destroy: AtomicBool,
        destroys: AtomicUsize,
        observations: AtomicUsize,
    }

    impl VmmBackend for OwnedAllocation {
        type VsockStream = tokio::io::DuplexStream;

        async fn create_vm(
            &self,
            _: husker_vmm::BackendSelection,
            _: husker_vmm::VmConfig,
        ) -> Result<husker_vmm::CreatedVm, husker_vmm::VmmError> {
            Err(husker_vmm::VmmError::Unsupported("fixture only".into()))
        }
        fn backend_kind(&self) -> &'static str {
            "firecracker"
        }
        async fn stop_vm(&self, _: Uuid) -> Result<(), husker_vmm::VmmError> {
            Err(husker_vmm::VmmError::Unsupported("fixture only".into()))
        }
        async fn destroy_vm(&self, id: Uuid) -> Result<(), husker_vmm::VmmError> {
            self.destroys.fetch_add(1, Ordering::SeqCst);
            if id != self.id || !self.owned.load(Ordering::SeqCst) {
                return Err(husker_vmm::VmmError::VmNotFound(id));
            }
            if self.fail_destroy.load(Ordering::SeqCst) {
                return Err(husker_vmm::VmmError::ProcessError(
                    "injected pending death".into(),
                ));
            }
            self.owned.store(false, Ordering::SeqCst);
            *self.info.lock() = None;
            Ok(())
        }
        async fn vm_info(&self, id: Uuid) -> Result<husker_vmm::VmInfo, husker_vmm::VmmError> {
            self.observations.fetch_add(1, Ordering::SeqCst);
            if id != self.id {
                return Err(husker_vmm::VmmError::VmNotFound(id));
            }
            self.info
                .lock()
                .clone()
                .ok_or(husker_vmm::VmmError::VmNotFound(id))
        }
        async fn pause_vm(&self, _: Uuid) -> Result<(), husker_vmm::VmmError> {
            Err(husker_vmm::VmmError::Unsupported("fixture only".into()))
        }
        async fn resume_vm(&self, _: Uuid) -> Result<(), husker_vmm::VmmError> {
            Err(husker_vmm::VmmError::Unsupported("fixture only".into()))
        }
        async fn set_balloon(&self, _: Uuid, _: u32) -> Result<(), husker_vmm::VmmError> {
            Err(husker_vmm::VmmError::Unsupported("fixture only".into()))
        }
        async fn vsock_connect(
            &self,
            _: Uuid,
            _: u32,
        ) -> Result<Self::VsockStream, husker_vmm::VmmError> {
            Err(husker_vmm::VmmError::Unsupported("fixture only".into()))
        }
    }

    fn fixture(
        path: &std::path::Path,
        profile: &str,
    ) -> (
        HuskerCore<OwnedAllocation>,
        husker_state::jobs::JobRecord,
        husker_state::HostResourceLease,
    ) {
        let state = husker_state::StateStore::open(&path.join("journal.sqlite")).unwrap();
        let deadline = chrono::Utc::now() + chrono::Duration::hours(1);
        let job = state
            .accept_job(
                "entered-recovery",
                "{}",
                deadline,
                deadline + chrono::Duration::hours(1),
            )
            .unwrap()
            .0;
        let name = state.claim_job_vm(job.id).unwrap().vm_name.unwrap();
        let id = Uuid::new_v4();
        state.bind_job_vm(job.id, id, &name).unwrap();
        let lease = state.begin_host_resource_lease_for_vm(&name, id).unwrap();
        if profile == "network" {
            state
                .set_host_resource_lease_network(lease.id, Some("fixture-tap"), None)
                .unwrap();
        }
        state
            .enter_host_resource_lease_backend(lease.id, id)
            .unwrap();
        let mut info = husker_vmm::VmInfo {
            id,
            name: name.clone(),
            state: husker_vmm::VmState::Failed,
            pid: None,
            vcpu_count: 1,
            mem_size_mib: 512,
            vsock_cid: lease.vsock_cid,
        };
        match profile {
            "foreign-id" => info.id = Uuid::new_v4(),
            "foreign-name" => info.name = "replacement".into(),
            "foreign-cid" => info.vsock_cid += 1,
            _ => (),
        }
        let backend = OwnedAllocation {
            id,
            info: parking_lot::Mutex::new(if matches!(profile, "preflight" | "missing") {
                None
            } else {
                Some(info)
            }),
            owned: AtomicBool::new(profile != "missing"),
            fail_destroy: AtomicBool::new(profile == "destroy-fails"),
            destroys: AtomicUsize::new(0),
            observations: AtomicUsize::new(0),
        };
        let storage = husker_storage::StorageConfig {
            data_dir: path.to_path_buf(),
            state_dir: path.to_path_buf(),
        };
        let directory = storage.vm_dir(&name);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("rootfs.ext4"), b"owned fixture disk").unwrap();
        #[cfg(feature = "linux-net")]
        let core = HuskerCore::new(
            backend,
            state,
            husker_net::IpAllocator::new("172.20.0.0".parse().unwrap(), 24),
            storage,
            "fixture-unused".into(),
            vec![],
            path.join("run"),
        );
        #[cfg(not(feature = "linux-net"))]
        let core = HuskerCore::new(backend, state, storage, path.join("run"));
        (core, job, lease)
    }

    fn terminal(core: &HuskerCore<OwnedAllocation>, job: Uuid) {
        core.state
            .finish_job(job, JobState::Unknown, CollectionState::Failed, "{}")
            .unwrap();
    }

    #[tokio::test]
    async fn factory_entered_allocation_without_vm_row_retries_positive_destruction() {
        let tmp = tempfile::tempdir().unwrap();
        let (core, job, lease) = fixture(tmp.path(), "destroy-fails");
        terminal(&core, job.id);
        let first = core.factory_cleanup_tick().await.unwrap();
        assert_eq!(first.pending, 1);
        assert_eq!(first.confirmed, 0);
        assert!(core.vmm.owned.load(Ordering::SeqCst));
        assert!(core.storage.vm_dir(&lease.vm_name).exists());
        assert!(!core.state.get_job(job.id).unwrap().vm_destroyed);
        assert!(
            !core
                .state
                .get_host_resource_lease(lease.id)
                .unwrap()
                .vm_destroyed
        );
        assert!(core.factory_destroyed_allocations.lock().is_empty());
        assert_ne!(core.state.allocate_cid().unwrap(), lease.vsock_cid);
        core.vmm.fail_destroy.store(false, Ordering::SeqCst);
        let second = core.factory_cleanup_tick().await.unwrap();
        assert_eq!(second.confirmed, 1);
        assert_eq!(second.pending, 0);
        let receipt = core.state.get_job(job.id).unwrap();
        assert!(receipt.vm_destroyed && !receipt.cleanup_pending && !receipt.vm_allocation_aborted);
        assert_eq!(receipt.state, JobState::Unknown);
        assert!(!core.storage.vm_dir(&lease.vm_name).exists());
        assert!(core.state.list_host_resource_leases().unwrap().is_empty());
        assert_eq!(core.state.allocate_cid().unwrap(), lease.vsock_cid);
        assert_eq!(core.vmm.destroys.load(Ordering::SeqCst), 2);
        let replay = core
            .state
            .accept_job(
                "entered-recovery",
                "{}",
                chrono::DateTime::from_timestamp(job.deadline, 0).unwrap(),
                chrono::DateTime::from_timestamp(job.retention_until, 0).unwrap(),
            )
            .unwrap();
        assert!(!replay.1);
        assert_eq!(replay.0.id, job.id);
        assert_eq!(replay.0.state, JobState::Unknown);
    }

    #[tokio::test]
    async fn factory_rollback_retains_positive_destruction_when_either_journal_write_fails() {
        for journal in ["lease", "job"] {
            let tmp = tempfile::tempdir().unwrap();
            let (core, job, lease) = fixture(tmp.path(), "owned");
            let connection = rusqlite::Connection::open(tmp.path().join("journal.sqlite")).unwrap();
            connection.execute_batch(if journal == "lease" {
                "CREATE TRIGGER block_death BEFORE UPDATE OF vm_destroyed ON host_resource_leases BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END;"
            } else {
                "CREATE TRIGGER block_death BEFORE UPDATE OF vm_destroyed ON execution_jobs BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END;"
            }).unwrap();
            assert!(
                core.rollback_create(AllocatedResources {
                    vm_id: lease.vm_id,
                    backend_allocation_entered: true,
                    host_resource_lease_id: Some(lease.id),
                    cid: Some(lease.vsock_cid),
                    vm_dir: Some(core.storage.vm_dir(&lease.vm_name)),
                    #[cfg(feature = "linux-net")]
                    guest_ip: None,
                    #[cfg(feature = "linux-net")]
                    tap_name: None,
                })
                .await
                .is_err()
            );
            assert!(!core.vmm.owned.load(Ordering::SeqCst));
            assert_eq!(core.vmm.destroys.load(Ordering::SeqCst), 1);
            assert_eq!(
                core.factory_destroyed_allocations
                    .lock()
                    .get(&lease.vm_id.unwrap()),
                Some(&(job.id, Some(lease.id)))
            );
            assert!(core.storage.vm_dir(&lease.vm_name).exists());
            terminal(&core, job.id);
            assert!(core.cleanup_job_vm(job.id).await.is_err());
            assert!(!core.state.get_job(job.id).unwrap().vm_destroyed);
            assert!(core.storage.vm_dir(&lease.vm_name).exists());
            assert_ne!(core.state.allocate_cid().unwrap(), lease.vsock_cid);
            connection
                .execute_batch("DROP TRIGGER block_death;")
                .unwrap();
            core.cleanup_job_vm(job.id).await.unwrap();
            assert!(core.factory_destroyed_allocations.lock().is_empty());
            assert_eq!(core.vmm.destroys.load(Ordering::SeqCst), 1);
            assert_eq!(core.vmm.observations.load(Ordering::SeqCst), 1);
            let receipt = core.state.get_job(job.id).unwrap();
            assert!(receipt.vm_destroyed && !receipt.cleanup_pending);
            assert!(!core.storage.vm_dir(&lease.vm_name).exists());
            assert_eq!(core.state.allocate_cid().unwrap(), lease.vsock_cid);
        }
    }

    #[tokio::test]
    async fn factory_existing_vm_retains_death_confirmation_through_journal_failure() {
        for transferred in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let (core, job, lease) = fixture(tmp.path(), "owned");
            let now = chrono::Utc::now();
            let record = husker_state::VmRecord {
                id: lease.vm_id.unwrap(),
                name: lease.vm_name.clone(),
                state: VmLifecycleState::Running,
                pid: None,
                vcpu_count: 1,
                mem_size_mib: 512,
                vsock_cid: lease.vsock_cid,
                tap_device: None,
                host_ip: None,
                guest_ip: None,
                kernel_path: "fixture-kernel".into(),
                rootfs_path: "fixture-rootfs".into(),
                created_at: now,
                updated_at: now,
                userdata: None,
                userdata_status: None,
                userdata_env: None,
                service_id: None,
                service_ordinal: None,
                vmm: BackendKind::Firecracker,
                boot_mode: BootKind::DirectKernel,
                balloon: false,
                volume: None,
                network: NetworkMode::Isolated,
                egress_policy: None,
                last_activity_at: now,
                suspended_at: None,
                idle_timeout_secs: None,
                suspend_ttl_secs: None,
                auto_resume: false,
                forked_from: None,
            };
            if transferred {
                core.state
                    .commit_vm_from_host_resource_lease(&record, lease.id)
                    .unwrap();
                assert!(core.state.list_host_resource_leases().unwrap().is_empty());
            } else {
                core.state.insert_vm(&record).unwrap();
            }
            terminal(&core, job.id);
            let connection = rusqlite::Connection::open(tmp.path().join("journal.sqlite")).unwrap();
            connection.execute_batch(if transferred {
            "CREATE TRIGGER block_death BEFORE UPDATE OF vm_destroyed ON execution_jobs BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END;"
        } else {
            "CREATE TRIGGER block_death BEFORE UPDATE OF vm_destroyed ON host_resource_leases BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END;"
        }).unwrap();
            assert!(core.cleanup_job_vm(job.id).await.is_err());
            assert!(!core.vmm.owned.load(Ordering::SeqCst));
            assert!(core.state.get_vm(lease.vm_id.unwrap()).is_ok());
            assert!(core.storage.vm_dir(&lease.vm_name).exists());
            assert!(!core.factory_destroyed_allocations.lock().is_empty());
            connection
                .execute_batch("DROP TRIGGER block_death;")
                .unwrap();
            core.cleanup_job_vm(job.id).await.unwrap();
            assert_eq!(core.vmm.destroys.load(Ordering::SeqCst), 1);
            assert_eq!(core.vmm.observations.load(Ordering::SeqCst), 1);
            assert!(core.factory_destroyed_allocations.lock().is_empty());
            assert!(core.state.get_vm(lease.vm_id.unwrap()).is_err());
            assert!(!core.storage.vm_dir(&lease.vm_name).exists());
            let receipt = core.state.get_job(job.id).unwrap();
            assert!(receipt.vm_destroyed && !receipt.cleanup_pending);
        }
    }

    #[tokio::test]
    async fn factory_entered_recovery_rejects_missing_foreign_and_conflicting_owners() {
        for profile in [
            "missing",
            "foreign-id",
            "foreign-name",
            "foreign-cid",
            "duplicate",
            "duplicate-confirmed",
            "network",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let (core, job, lease) = fixture(tmp.path(), profile);
            if profile.starts_with("duplicate") {
                core.state
                    .begin_host_resource_lease_for_vm("another-owner", lease.vm_id.unwrap())
                    .unwrap();
            }
            if profile == "duplicate-confirmed" {
                core.state
                    .record_host_resource_lease_destruction(lease.id, lease.vm_id.unwrap())
                    .unwrap();
            }
            terminal(&core, job.id);
            assert!(core.cleanup_job_vm(job.id).await.is_err(), "{profile}");
            assert_eq!(
                core.vmm.destroys.load(Ordering::SeqCst),
                usize::from(profile == "missing")
            );
            assert!(!core.state.get_job(job.id).unwrap().vm_destroyed);
            assert!(core.state.get_job(job.id).unwrap().cleanup_pending);
            assert_eq!(
                core.state
                    .get_host_resource_lease(lease.id)
                    .unwrap()
                    .vm_destroyed,
                profile == "duplicate-confirmed"
            );
            assert!(core.storage.vm_dir(&lease.vm_name).exists());
            assert!(core.factory_destroyed_allocations.lock().is_empty());
            assert_ne!(core.state.allocate_cid().unwrap(), lease.vsock_cid);
        }
    }

    #[tokio::test]
    async fn factory_restart_never_reconstructs_volatile_death_confirmation_from_absence() {
        let tmp = tempfile::tempdir().unwrap();
        let (core, job, lease) = fixture(tmp.path(), "owned");
        terminal(&core, job.id);
        let connection = rusqlite::Connection::open(tmp.path().join("journal.sqlite")).unwrap();
        connection.execute_batch("CREATE TRIGGER block_death BEFORE UPDATE OF vm_destroyed ON host_resource_leases BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END;").unwrap();
        assert!(core.cleanup_job_vm(job.id).await.is_err());
        assert!(!core.factory_destroyed_allocations.lock().is_empty());
        assert!(!core.state.get_job(job.id).unwrap().vm_destroyed);
        assert!(
            !core
                .state
                .get_host_resource_lease(lease.id)
                .unwrap()
                .vm_destroyed
        );
        drop(core);
        connection
            .execute_batch("DROP TRIGGER block_death;")
            .unwrap();
        let state = husker_state::StateStore::open(&tmp.path().join("journal.sqlite")).unwrap();
        let backend = OwnedAllocation {
            id: lease.vm_id.unwrap(),
            info: parking_lot::Mutex::new(None),
            owned: AtomicBool::new(false),
            fail_destroy: AtomicBool::new(false),
            destroys: AtomicUsize::new(0),
            observations: AtomicUsize::new(0),
        };
        let storage = husker_storage::StorageConfig {
            data_dir: tmp.path().to_path_buf(),
            state_dir: tmp.path().to_path_buf(),
        };
        #[cfg(feature = "linux-net")]
        let restarted = HuskerCore::new(
            backend,
            state,
            husker_net::IpAllocator::new("172.20.0.0".parse().unwrap(), 24),
            storage,
            "fixture-unused".into(),
            vec![],
            tmp.path().join("run"),
        );
        #[cfg(not(feature = "linux-net"))]
        let restarted = HuskerCore::new(backend, state, storage, tmp.path().join("run"));
        assert!(restarted.cleanup_job_vm(job.id).await.is_err());
        let receipt = restarted.state.get_job(job.id).unwrap();
        assert_eq!(receipt.state, JobState::Unknown);
        assert!(receipt.cleanup_pending && !receipt.vm_destroyed);
        assert!(
            !restarted
                .state
                .get_host_resource_lease(lease.id)
                .unwrap()
                .vm_destroyed
        );
        assert!(restarted.storage.vm_dir(&lease.vm_name).exists());
        assert_ne!(restarted.state.allocate_cid().unwrap(), lease.vsock_cid);
        assert!(restarted.factory_destroyed_allocations.lock().is_empty());
    }

    #[tokio::test]
    async fn factory_owned_preflight_without_vm_info_requires_positive_destroy() {
        let tmp = tempfile::tempdir().unwrap();
        let (core, job, lease) = fixture(tmp.path(), "preflight");
        terminal(&core, job.id);
        core.cleanup_job_vm(job.id).await.unwrap();
        assert_eq!(core.vmm.destroys.load(Ordering::SeqCst), 1);
        assert_eq!(core.vmm.observations.load(Ordering::SeqCst), 1);
        let receipt = core.state.get_job(job.id).unwrap();
        assert!(receipt.vm_destroyed && !receipt.cleanup_pending);
        assert!(!core.storage.vm_dir(&lease.vm_name).exists());
    }
}
