use super::*;

impl<B: VmmBackend> HuskerCore<B> {
    /// Create a snapshot from a stopped VM.
    pub async fn create_snapshot(
        &self,
        req: CreateSnapshotRequest,
    ) -> Result<SnapshotRecord, CoreError> {
        validate_resource_name("snapshot", &req.name)?;
        let vm = self.lookup_vm(&req.vm)?;
        if vm.state != "stopped" {
            return Err(CoreError::InvalidState {
                name: vm.name,
                actual: vm.state,
                expected: "stopped".into(),
            });
        }

        let source_rootfs = self.storage.vm_dir(&req.vm).join("rootfs.ext4");
        let snapshots_dir = self.storage.images_dir().join("snapshots");
        tokio::fs::create_dir_all(&snapshots_dir)
            .await
            .map_err(husker_storage::StorageError::Io)?;

        let snapshot_path = snapshots_dir.join(format!("{}.ext4", req.name));
        self.storage_driver
            .clone_rootfs(&source_rootfs, &snapshot_path)
            .await?;

        let record = SnapshotRecord {
            id: Uuid::new_v4(),
            name: req.name.clone(),
            source_vm_name: req.vm,
            file_path: snapshot_path.to_string_lossy().into_owned(),
            created_at: chrono::Utc::now(),
        };

        if let Err(err) = self.state.insert_snapshot(&record).map_err(|e| match e {
            husker_state::StateError::SnapshotAlreadyExists(name) => {
                CoreError::SnapshotAlreadyExists(name)
            }
            other => CoreError::State(other),
        }) {
            let _ = tokio::fs::remove_file(&snapshot_path).await;
            return Err(err);
        }

        Ok(record)
    }

    /// List all snapshots.
    pub fn list_snapshots(&self) -> Result<Vec<SnapshotRecord>, CoreError> {
        Ok(self.state.list_snapshots()?)
    }

    /// Get a snapshot by name.
    pub fn get_snapshot(&self, name: &str) -> Result<SnapshotRecord, CoreError> {
        self.state.get_snapshot_by_name(name).map_err(|e| match e {
            husker_state::StateError::SnapshotNotFoundByName(_) => {
                CoreError::SnapshotNotFound(name.into())
            }
            other => CoreError::State(other),
        })
    }

    /// Delete a snapshot by name.
    pub async fn delete_snapshot(&self, name: &str) -> Result<(), CoreError> {
        let snapshot = self.get_snapshot(name)?;
        match tokio::fs::remove_file(&snapshot.file_path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(CoreError::Storage(husker_storage::StorageError::Io(e))),
        }

        self.state
            .delete_snapshot(snapshot.id)
            .map_err(|e| match e {
                husker_state::StateError::SnapshotNotFound(_) => {
                    CoreError::SnapshotNotFound(name.into())
                }
                other => CoreError::State(other),
            })
    }

    /// Restore a snapshot into a new VM.
    pub async fn restore_snapshot(
        &self,
        snapshot_name: &str,
        req: RestoreSnapshotRequest,
    ) -> Result<VmRecord, CoreError> {
        validate_resource_name("vm", &req.name)?;
        let snapshot = self.get_snapshot(snapshot_name)?;
        self.create_vm(CreateVmRequest {
            name: req.name,
            kernel_path: Some(req.kernel_path),
            rootfs_path: Some(PathBuf::from(snapshot.file_path)),
            vcpu_count: req.vcpu_count,
            mem_size_mib: req.mem_size_mib,
            initrd_path: req.initrd_path,
            userdata: req.userdata,
            env: req.env,
            vmm: None,
            cloud_image: None,
            disk_size: None,
            ssh_authorized_keys: Vec::new(),
            balloon: false,
            volume: None,
            network: None,
            mounts: Vec::new(),
            ..Default::default()
        })
        .await
    }
}
