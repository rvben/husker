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
        // Canonicalise before anything records or reports it: an image's
        // `source_path` is `oci://<reference>`, and re-importing that value must
        // not stack a second scheme onto the one already there.
        let reference = husker_oci::strip_oci_scheme(reference);
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

        let catalog_dir = self.storage.images_dir().join("catalog");
        tokio::fs::create_dir_all(&catalog_dir)
            .await
            .map_err(husker_storage::StorageError::Io)?;
        let image_path = catalog_dir.join(format!("{name}.ext4"));
        let artifact = self
            .oci_materializer
            .materialize(OciMaterializationRequest {
                reference,
                destination: &image_path,
                guest_agent: self.embedded_agent,
            })
            .await
            .map_err(map_oci_materialization_error)?;
        let record = ImageRecord {
            id: Uuid::new_v4(),
            name: name.into(),
            source_path: oci_source_path(reference),
            file_path: image_path.to_string_lossy().into_owned(),
            format: "ext4".into(),
            kind: "rootfs".into(),
            // Boot imported OCI images via the guest agent as PID 1 (the agent
            // supervisor does mounts/network/reaping), since they carry no
            // busybox init. The injected agent lives at this path.
            boot_init: Some("/usr/local/bin/husker-agent".to_string()),
            size_bytes: artifact.size_bytes,
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

#[cfg(feature = "linux-net")]
fn map_oci_materialization_error(error: OciMaterializationError) -> CoreError {
    match error {
        error @ (OciMaterializationError::Pull { .. }
        | OciMaterializationError::RootfsTooLarge { .. }
        | OciMaterializationError::MissingGuestAgent
        | OciMaterializationError::UnsupportedArchitecture(_)) => {
            CoreError::InvalidArgument(error.to_string())
        }
        error @ (OciMaterializationError::WorkDirectory(_)
        | OciMaterializationError::Runtime(_)
        | OciMaterializationError::SizeTask(_)) => CoreError::Io(error.to_string()),
        OciMaterializationError::Storage(error) => CoreError::Storage(error),
    }
}

/// The `source_path` recorded for an OCI-imported image, and the value
/// `image list` reports. Carries exactly one `oci://` scheme whatever form the
/// caller used, so the reported value can be fed straight back to `import-oci`.
///
/// The only caller is `import_oci_image`, which needs `linux-net`. The function
/// itself is pure string handling, so it stays compiled everywhere and its test
/// runs on macOS too; without that feature it simply has no caller outside the
/// test.
#[cfg_attr(not(feature = "linux-net"), allow(dead_code))]
fn oci_source_path(reference: &str) -> String {
    format!("oci://{}", husker_oci::strip_oci_scheme(reference))
}

#[cfg(test)]
mod tests {
    use super::oci_source_path;

    #[test]
    fn reported_source_path_carries_exactly_one_scheme() {
        // The bug this guards: `image list` prints `oci://alpine:3.20`, and
        // re-importing that value used to record `oci://oci://alpine:3.20`, whose
        // scheme then parses as a registry host called `oci`.
        for reference in ["alpine:3.20", "ghcr.io/rvben/husker:v1"] {
            let reported = oci_source_path(reference);
            assert_eq!(reported, format!("oci://{reference}"));
            assert_eq!(
                oci_source_path(&reported),
                reported,
                "re-importing the reported source_path must not stack a second scheme"
            );
            let parsed = husker_oci::ImageReference::parse(&reported)
                .expect("the reported source_path must parse as a reference");
            assert_ne!(
                parsed.registry, "oci",
                "the scheme must not be read as a registry host"
            );
        }
    }
}
