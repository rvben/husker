use super::*;

impl<B: VmmBackend> HuskerCore<B> {
    /// Resize a running VM's memory balloon (amount = MiB reclaimed from the guest).
    ///
    /// Fails immediately when the VM was not created with `--balloon` (the
    /// device is absent in the guest) or when the VM is not currently running.
    pub async fn set_balloon(&self, name: &str, amount_mib: u32) -> Result<(), CoreError> {
        let record = self.lookup_vm(name)?;
        if !record.balloon {
            return Err(CoreError::InvalidArgument(format!(
                "VM '{name}' was created without --balloon"
            )));
        }
        if record.state != VmLifecycleState::Running {
            return Err(CoreError::InvalidState {
                name: name.into(),
                actual: record.state.to_string(),
                expected: "running".into(),
            });
        }
        self.vmm
            .set_balloon(record.id, amount_mib)
            .await
            .map_err(CoreError::Vmm)
    }

    /// Resolve a volume name to its record and image path for attachment.
    ///
    /// Returns `(volume_name, image_path)` when a name is provided. Returns
    /// `None` when no volume is requested (name is None).
    pub(crate) fn resolve_volume_attachment(
        &self,
        name: &Option<String>,
    ) -> Result<Option<(String, PathBuf)>, CoreError> {
        let Some(vol_name) = name else {
            return Ok(None);
        };
        let record = self
            .state
            .get_volume_by_name(vol_name)
            .map_err(|e| match e {
                husker_state::StateError::VolumeNotFoundByName(_) => {
                    CoreError::InvalidArgument(format!("volume '{vol_name}' not found"))
                }
                other => CoreError::State(other),
            })?;
        husker_storage::validate_volume(std::path::Path::new(&record.file_path))
            .map_err(CoreError::Storage)?;
        if let Some(holder) = self.state.find_vm_by_volume(vol_name)? {
            return Err(CoreError::VolumeAttached {
                volume: vol_name.clone(),
                vm: holder.name,
            });
        }
        Ok(Some((record.name, PathBuf::from(record.file_path))))
    }

    /// Create a named persistent volume.
    ///
    /// Validates the name, rejects duplicates, creates a sparse ext4 image
    /// under `{data_dir}/volumes/`, and inserts the catalog record. On insert
    /// failure the image file is removed (mirror of `import_image`'s
    /// compensation pattern).
    pub async fn create_volume(&self, req: CreateVolumeRequest) -> Result<VolumeRecord, CoreError> {
        validate_resource_name("volume", &req.name)?;
        let _volume_guard = self.volume_lock(&req.name).lock_owned().await;
        match self.state.get_volume_by_name(&req.name) {
            Ok(_) => return Err(CoreError::VolumeAlreadyExists(req.name)),
            Err(husker_state::StateError::VolumeNotFoundByName(_)) => {}
            Err(other) => return Err(CoreError::State(other)),
        }

        let volumes_dir = self.storage.volumes_dir();
        let image_path = volumes_dir.join(format!("{}.img", req.name));

        husker_storage::create_volume_image(&image_path, req.size_bytes).await?;

        let record = VolumeRecord {
            id: uuid::Uuid::new_v4(),
            name: req.name.clone(),
            file_path: image_path.to_string_lossy().into_owned(),
            size_bytes: req.size_bytes,
            created_at: chrono::Utc::now(),
        };

        if let Err(err) = self.state.insert_volume(&record).map_err(|e| match e {
            husker_state::StateError::VolumeAlreadyExists(name) => {
                CoreError::VolumeAlreadyExists(name)
            }
            other => CoreError::State(other),
        }) {
            let _ = tokio::fs::remove_file(&image_path).await;
            return Err(err);
        }

        Ok(record)
    }

    /// List all catalog volumes.
    pub fn list_volumes(&self) -> Result<Vec<VolumeRecord>, CoreError> {
        Ok(self.state.list_volumes()?)
    }

    /// Get a catalog volume by name.
    pub fn get_volume(&self, name: &str) -> Result<VolumeRecord, CoreError> {
        self.state.get_volume_by_name(name).map_err(|e| match e {
            husker_state::StateError::VolumeNotFoundByName(_) => {
                CoreError::VolumeNotFound(name.into())
            }
            other => CoreError::State(other),
        })
    }

    /// Delete a catalog volume by name.
    ///
    /// Refuses deletion while any VM record holds the volume. After the record
    /// is deleted the image file is removed on a best-effort basis.
    pub async fn delete_volume(&self, name: &str) -> Result<(), CoreError> {
        let _volume_guard = self.volume_lock(name).lock_owned().await;
        let record =
            self.state
                .delete_unattached_volume_by_name(name)
                .map_err(|error| match error {
                    husker_state::StateError::VolumeNotFoundByName(_) => {
                        CoreError::VolumeNotFound(name.into())
                    }
                    husker_state::StateError::VolumeAttached { volume, vm } => {
                        CoreError::VolumeAttached { volume, vm }
                    }
                    other => CoreError::State(other),
                })?;

        // Best-effort: log but do not fail if the file is already gone.
        match tokio::fs::remove_file(&record.file_path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                warn!(
                    volume = %name,
                    path = %record.file_path,
                    error = %e,
                    "failed to remove volume image file during delete"
                );
            }
        }

        Ok(())
    }
}
