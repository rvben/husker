use super::*;

impl<B: VmmBackend> HuskerCore<B> {
    /// Import an image into the managed image catalog.
    pub async fn import_image(&self, req: ImportImageRequest) -> Result<ImageRecord, CoreError> {
        validate_resource_name("image", &req.name)?;
        validate_host_path("import source", &req.source_path)?;
        let kind = validate_image_kind(req.kind.as_deref())?;
        match self.state.get_image_by_name(&req.name) {
            Ok(_) => return Err(CoreError::ImageAlreadyExists(req.name)),
            Err(husker_state::StateError::ImageNotFoundByName(_)) => {}
            Err(other) => return Err(CoreError::State(other)),
        }

        if kind == "cloud-image" {
            husker_storage::validate_cloud_image(&req.source_path)?;
        } else {
            husker_storage::validate_rootfs(&req.source_path)?;
        }

        let catalog_dir = self.storage.images_dir().join("catalog");
        tokio::fs::create_dir_all(&catalog_dir)
            .await
            .map_err(husker_storage::StorageError::Io)?;

        let extension = req
            .source_path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("ext4");
        let image_path = catalog_dir.join(format!("{}.{}", req.name, extension));
        self.storage_driver
            .clone_rootfs(&req.source_path, &image_path)
            .await?;

        let metadata = tokio::fs::metadata(&image_path)
            .await
            .map_err(husker_storage::StorageError::Io)?;
        let format = if kind == "cloud-image" && req.format.is_none() {
            "qcow2".to_string()
        } else {
            req.format
                .unwrap_or_else(|| infer_image_format(&req.source_path))
        };
        let record = ImageRecord {
            id: Uuid::new_v4(),
            name: req.name.clone(),
            source_path: req.source_path.to_string_lossy().into_owned(),
            file_path: image_path.to_string_lossy().into_owned(),
            format,
            kind,
            boot_init: None,
            size_bytes: metadata.len(),
            created_at: chrono::Utc::now(),
        };

        if let Err(err) = self.state.insert_image(&record).map_err(|e| match e {
            husker_state::StateError::ImageAlreadyExists(name) => {
                CoreError::ImageAlreadyExists(name)
            }
            other => CoreError::State(other),
        }) {
            let _ = tokio::fs::remove_file(&image_path).await;
            return Err(err);
        }

        Ok(record)
    }

    /// Build a husker rootfs image from an OCI/Docker image and register it.
    ///
    /// Pulls the image, flattens its layers, injects the husker agent + guest
    /// runtime so the rootfs boots into the agent, builds an ext4 image, and
    /// registers it in the catalog as a `rootfs` image runnable with `husker run`.
    /// v1 targets busybox-init images (e.g. alpine); the host must have
    /// `mkfs.ext4` and the daemon must embed the guest agent.
    #[cfg(feature = "linux-net")]
    pub async fn import_oci_image(
        &self,
        name: &str,
        reference: &str,
    ) -> Result<ImageRecord, CoreError> {
        validate_resource_name("image", name)?;
        if self.embedded_agent.is_empty() {
            return Err(CoreError::InvalidArgument(
                "OCI import needs the embedded guest agent; build the daemon with \
                 `make build-agent` (or set HUSKER_EMBED_AGENT_BIN) first"
                    .into(),
            ));
        }
        match self.state.get_image_by_name(name) {
            Ok(_) => return Err(CoreError::ImageAlreadyExists(name.into())),
            Err(husker_state::StateError::ImageNotFoundByName(_)) => {}
            Err(other) => return Err(CoreError::State(other)),
        }

        let arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => {
                return Err(CoreError::InvalidArgument(format!(
                    "unsupported host architecture for OCI import: {other}"
                )));
            }
        };

        // Pull + flatten into a temp dir, then inject the guest runtime. The
        // image's runtime config (env/PATH/WorkingDir) is captured and written
        // into the rootfs so the agent applies it on exec.
        let work = tempfile::tempdir().map_err(|e| CoreError::Io(format!("oci work dir: {e}")))?;
        let rootfs_dir = work.path().join("rootfs");
        let image_config = husker_oci::pull_and_flatten(reference, arch, &rootfs_dir)
            .await
            .map_err(|e| CoreError::InvalidArgument(format!("pull {reference}: {e}")))?;
        let oci_runtime = husker_agent_proto::OciRuntimeConfig {
            env: image_config.env,
            working_dir: image_config.working_dir,
            entrypoint: image_config.entrypoint,
            cmd: image_config.cmd,
        };
        inject_guest_runtime(&rootfs_dir, self.embedded_agent, &oci_runtime)?;

        // Build the ext4 image sized to the tree plus generous overhead.
        let catalog_dir = self.storage.images_dir().join("catalog");
        tokio::fs::create_dir_all(&catalog_dir)
            .await
            .map_err(husker_storage::StorageError::Io)?;
        let image_path = catalog_dir.join(format!("{name}.ext4"));
        let tree_size = {
            let d = rootfs_dir.clone();
            tokio::task::spawn_blocking(move || husker_storage::dir_apparent_size(&d))
                .await
                .map_err(|e| CoreError::Io(format!("size join: {e}")))?
        };
        // Bound disk use: refuse images whose extracted tree is implausibly large
        // (a decompression-bomb guard on top of the compressed-download cap).
        const MAX_ROOTFS_BYTES: u64 = 8 * 1024 * 1024 * 1024;
        if tree_size > MAX_ROOTFS_BYTES {
            return Err(CoreError::InvalidArgument(format!(
                "imported rootfs is {tree_size} bytes, over the {MAX_ROOTFS_BYTES}-byte limit"
            )));
        }
        let size_bytes = (tree_size * 2).max(128 * 1024 * 1024) + 64 * 1024 * 1024;
        husker_storage::build_ext4_from_dir(&rootfs_dir, &image_path, size_bytes).await?;

        let metadata = tokio::fs::metadata(&image_path)
            .await
            .map_err(husker_storage::StorageError::Io)?;
        let record = ImageRecord {
            id: Uuid::new_v4(),
            name: name.into(),
            source_path: format!("oci://{reference}"),
            file_path: image_path.to_string_lossy().into_owned(),
            format: "ext4".into(),
            kind: "rootfs".into(),
            // Boot imported OCI images via the guest agent as PID 1 (the agent
            // supervisor does mounts/network/reaping), since they carry no
            // busybox init. The injected agent lives at this path.
            boot_init: Some("/usr/local/bin/husker-agent".to_string()),
            size_bytes: metadata.len(),
            created_at: chrono::Utc::now(),
        };
        if let Err(err) = self.state.insert_image(&record).map_err(|e| match e {
            husker_state::StateError::ImageAlreadyExists(n) => CoreError::ImageAlreadyExists(n),
            other => CoreError::State(other),
        }) {
            let _ = tokio::fs::remove_file(&image_path).await;
            return Err(err);
        }
        Ok(record)
    }

    /// OCI import is Linux-only (needs `mkfs.ext4`); the macOS build rejects it.
    #[cfg(not(feature = "linux-net"))]
    pub async fn import_oci_image(
        &self,
        _name: &str,
        _reference: &str,
    ) -> Result<ImageRecord, CoreError> {
        Err(CoreError::Vmm(husker_vmm::VmmError::Unsupported(
            "OCI image import is only supported on Linux".into(),
        )))
    }

    /// List all catalog images.
    pub fn list_images(&self) -> Result<Vec<ImageRecord>, CoreError> {
        Ok(self.state.list_images()?)
    }

    /// Get a catalog image by name.
    pub fn get_image(&self, name: &str) -> Result<ImageRecord, CoreError> {
        self.state.get_image_by_name(name).map_err(|e| match e {
            husker_state::StateError::ImageNotFoundByName(_) => {
                CoreError::ImageNotFound(name.into())
            }
            other => CoreError::State(other),
        })
    }

    /// Export a catalog image to a destination path.
    pub async fn export_image(
        &self,
        name: &str,
        req: ExportImageRequest,
    ) -> Result<ExportImageResult, CoreError> {
        validate_host_path("export destination", &req.destination_path)?;
        let image = self.get_image(name)?;
        self.storage_driver
            .clone_rootfs(Path::new(&image.file_path), &req.destination_path)
            .await?;
        let metadata = tokio::fs::metadata(&req.destination_path)
            .await
            .map_err(husker_storage::StorageError::Io)?;

        Ok(ExportImageResult {
            name: image.name,
            destination_path: req.destination_path,
            size_bytes: metadata.len(),
        })
    }

    /// Delete a catalog image by name.
    pub async fn delete_image(&self, name: &str) -> Result<(), CoreError> {
        let image = self.get_image(name)?;
        match tokio::fs::remove_file(&image.file_path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(CoreError::Storage(husker_storage::StorageError::Io(e))),
        }

        self.state.delete_image(image.id).map_err(|e| match e {
            husker_state::StateError::ImageNotFound(_) => CoreError::ImageNotFound(name.into()),
            other => CoreError::State(other),
        })
    }
}
