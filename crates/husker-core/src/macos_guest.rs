//! macOS guest VMs (Apple Virtualization.framework on Apple Silicon).
//!
//! A macOS guest boots from a bundle produced by `husker macos install`
//! (see [`husker_vmm::macos_bundle`]). Each VM gets copy-on-write clones of
//! the bundle's disk and auxiliary storage plus its own machine identifier, so
//! the bundle stays a pristine template and VMs never share mutable state.

use super::*;
use husker_vmm::macos_bundle::MacOsBundle;
#[cfg(not(feature = "linux-net"))]
use husker_vmm::macos_bundle::{MacOsBundleManifest, vm_shape};

/// Directory under the data dir that holds named macOS bundles.
pub const MACOS_IMAGES_DIR: &str = "macos";

/// Where named macOS bundles live.
pub fn macos_images_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(MACOS_IMAGES_DIR)
}

/// Check that `name` can name a bundle under `<data_dir>/macos/`. A bundle
/// name follows the rules of every other resource name (at most 64 ASCII
/// alphanumerics plus `-`, `_` and `.`, not starting with `.`), which keeps
/// `..` and the install staging directories out of the namespace.
pub fn validate_macos_image_name(name: &str) -> Result<(), CoreError> {
    validate_resource_name("macOS image", name)
}

/// A `macos_image` reference as the user wrote it. A value containing `/` is
/// a bundle directory path; anything else names an installed bundle under
/// `<data_dir>/macos/`, so a bare name can never escape that directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacOsImageRef {
    Path(PathBuf),
    Name(String),
}

impl MacOsImageRef {
    /// Classify `image`, refusing a bare name outside the resource name rules
    /// before anything looks at the filesystem.
    pub fn parse(image: &str) -> Result<Self, CoreError> {
        if image.contains('/') {
            return Ok(Self::Path(PathBuf::from(image)));
        }
        validate_macos_image_name(image)?;
        Ok(Self::Name(image.to_string()))
    }

    /// The bundle this reference names, which must exist.
    pub fn resolve(&self, data_dir: &Path) -> Result<MacOsBundle, CoreError> {
        match self {
            Self::Path(path) if path.is_dir() => Ok(MacOsBundle::new(path)),
            Self::Path(path) => Err(CoreError::InvalidArgument(format!(
                "macOS image path {} is not a directory",
                path.display()
            ))),
            Self::Name(name) => {
                let named = macos_images_dir(data_dir).join(name);
                if named.is_dir() {
                    return Ok(MacOsBundle::new(named));
                }
                Err(CoreError::InvalidArgument(format!(
                    "macOS image '{name}' is not installed (install one with `husker macos install <name>`)"
                )))
            }
        }
    }
}

/// Resolve a `macos_image` reference to an existing bundle.
pub fn resolve_macos_bundle(data_dir: &Path, image: &str) -> Result<MacOsBundle, CoreError> {
    MacOsImageRef::parse(image)?.resolve(data_dir)
}

/// Reject request fields a macOS guest cannot honour, before any resource
/// is allocated.
pub(crate) fn validate_macos_request(req: &CreateVmRequest) -> Result<(), CoreError> {
    let unsupported = [
        (req.cloud_image.is_some(), "--cloud-image"),
        (req.kernel_path.is_some(), "a kernel"),
        (req.rootfs_path.is_some(), "a rootfs"),
        (req.initrd_path.is_some(), "an initrd"),
        (req.volume.is_some(), "--volume"),
        (!req.mounts.is_empty(), "--mount"),
        (req.disk_size.is_some(), "--disk-size"),
        (!req.ssh_authorized_keys.is_empty(), "SSH keys"),
    ];
    if let Some((_, what)) = unsupported.iter().find(|(set, _)| *set) {
        return Err(CoreError::InvalidArgument(format!(
            "{what} cannot be combined with a macOS image"
        )));
    }
    Ok(())
}

/// Pick the VM shape: explicit values are checked against the bundle's
/// minimums, missing ones default to a usable desktop-class size.
#[cfg(not(feature = "linux-net"))]
pub(crate) fn macos_vm_shape(
    manifest: &MacOsBundleManifest,
    vcpu_count: Option<u32>,
    mem_size_mib: Option<u32>,
) -> Result<(u32, u32), CoreError> {
    // A shape below the image's minimum is the caller's request at fault, so it
    // surfaces as an invalid argument rather than a VMM failure.
    vm_shape(manifest, vcpu_count, mem_size_mib).map_err(|e| match e {
        husker_vmm::VmmError::InvalidConfig(msg) => CoreError::InvalidArgument(msg),
        other => other.into(),
    })
}

/// Readiness-failure hint for a macOS guest. It has no serial console, so
/// the useful pointers are the conditions the agent needs to come up and the
/// guest-side log the provisioned launch daemon writes.
pub(crate) fn macos_boot_failure_hint() -> String {
    "\nhint: macOS guests have no serial console; the agent starts only once macOS \
     has finished booting from an image installed with `husker macos install` and \
     provisioned with `sudo husker macos provision`. Inside the guest, the agent \
     logs to /var/log/husker-guest-agent.log"
        .to_string()
}

/// Validate a bundle for booting: complete, and carrying the guest agent
/// (without it husker has no way to reach the guest).
#[cfg(not(feature = "linux-net"))]
pub(crate) fn bootable_manifest(bundle: &MacOsBundle) -> Result<MacOsBundleManifest, CoreError> {
    let manifest = bundle.validate()?;
    if !manifest.agent_provisioned {
        return Err(CoreError::InvalidArgument(format!(
            "macOS image {} has no guest agent; run `sudo husker macos provision {}` first",
            bundle.dir().display(),
            bundle.dir().display()
        )));
    }
    Ok(manifest)
}

#[cfg(not(feature = "linux-net"))]
impl<B: VmmBackend> HuskerCore<B> {
    /// Create and boot a macOS guest from a bundle. Called from the
    /// host-networking-free create path after the CID is allocated; `vm_dir`
    /// does not exist yet.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn create_macos_vm(
        &self,
        req: CreateVmRequest,
        bundle: MacOsBundle,
        backend_selection: husker_vmm::BackendSelection,
        network_mode: NetworkMode,
        cid: u32,
        vm_dir: PathBuf,
        tags: Option<ServiceTag>,
        expiration: Option<&PendingVmExpiration>,
        resources: &mut AllocatedResources,
    ) -> Result<VmRecord, CoreError> {
        // Held from validation through both clones, so a provision cannot
        // start between them: it would mark the image unprovisioned and
        // rewrite the disk the clone is about to copy.
        let bundle_lock = bundle
            .try_lock(false)?
            .ok_or_else(|| CoreError::ImageBusy(bundle.dir().display().to_string()))?;
        let manifest = bootable_manifest(&bundle)?;
        let (vcpu_count, mem_size_mib) =
            macos_vm_shape(&manifest, req.vcpu_count, req.mem_size_mib)?;

        tokio::fs::create_dir_all(&vm_dir)
            .await
            .map_err(|e| CoreError::Storage(husker_storage::StorageError::Io(e)))?;
        resources.vm_dir = Some(vm_dir.clone());

        let disk = vm_dir.join(husker_vmm::macos_bundle::DISK_FILE);
        let aux = vm_dir.join(husker_vmm::macos_bundle::AUX_FILE);
        let machine_identifier = vm_dir.join(husker_vmm::macos_bundle::MACHINE_IDENTIFIER_FILE);
        husker_storage::clone_rootfs(&bundle.disk_path(), &disk).await?;
        husker_storage::clone_rootfs(&bundle.aux_path(), &aux).await?;
        drop(bundle_lock);
        write_machine_identifier(&machine_identifier)?;

        let boot = husker_vmm::BootMode::MacOs {
            auxiliary_storage: aux,
            hardware_model: bundle.hardware_model_path(),
            machine_identifier,
        };
        let boot_kind = boot.kind();
        let vm_config = husker_vmm::VmConfig {
            requested_id: None,
            name: req.name.clone(),
            vcpu_count,
            mem_size_mib,
            kernel_path: PathBuf::new(),
            rootfs_path: disk,
            kernel_args: None,
            initrd_path: None,
            vsock_cid: cid,
            tap_device: None,
            guest_mac: None,
            vmm: backend_selection.requirements().requested,
            boot,
            seed_path: None,
            balloon: req.balloon,
            volume_path: None,
            network_disabled: network_mode == NetworkMode::Isolated,
            factory_recovery: false,
            host_shares: vec![],
        };

        let created = self
            .create_leased_vm(backend_selection, vm_config, resources)
            .await?;
        let backend = created.backend();
        let info = created.info;

        let userdata_status = req.userdata.as_ref().map(|_| UserdataStatus::Pending);
        let now = chrono::Utc::now();
        let record = VmRecord {
            id: info.id,
            name: req.name,
            state: durable_lifecycle_state(info.state),
            pid: info.pid,
            vcpu_count: info.vcpu_count,
            mem_size_mib: info.mem_size_mib,
            vsock_cid: cid,
            tap_device: None,
            host_ip: None,
            guest_ip: None,
            kernel_path: String::new(),
            // Provenance: the bundle this VM was cloned from.
            rootfs_path: bundle.dir().to_string_lossy().into_owned(),
            created_at: now,
            updated_at: now,
            userdata: req.userdata,
            userdata_status,
            userdata_env: if req.env.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&req.env).expect("env serializes to JSON"))
            },
            service_id: tags.map(|t| t.service_id),
            service_ordinal: tags.map(|t| t.ordinal),
            vmm: backend,
            boot_mode: boot_kind,
            balloon: req.balloon,
            volume: None,
            network: network_mode,
            egress_policy: None,
            last_activity_at: now,
            suspended_at: None,
            idle_timeout_secs: None,
            suspend_ttl_secs: None,
            auto_resume: true,
            forked_from: None,
        };

        let expiration = expiration.map(|value| VmExpirationRecord {
            vm_id: record.id,
            owner: value.owner.clone(),
            expires_at: value.expires_at,
        });
        let lease = resources
            .host_resource_lease_id
            .ok_or_else(|| CoreError::Io("VM creation has no durable resource lease".into()))?;
        self.state
            .commit_vm_from_host_resource_lease_with_expiration(&record, lease, expiration.as_ref())
            .map_err(crate::vm_lifecycle::map_vm_insert_error)?;
        Ok(record)
    }
}

/// A fresh, VZ-generated machine identifier for one VM.
#[cfg(all(not(feature = "linux-net"), target_os = "macos"))]
fn write_machine_identifier(path: &Path) -> Result<(), CoreError> {
    Ok(husker_vmm::apple_vz_macos::write_new_machine_identifier(
        path,
    )?)
}

#[cfg(all(not(feature = "linux-net"), not(target_os = "macos")))]
fn write_machine_identifier(_path: &Path) -> Result<(), CoreError> {
    Err(CoreError::InvalidArgument(
        "macOS guests require an Apple Silicon Mac host".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use husker_vmm::macos_bundle::{MACOS_BUNDLE_FORMAT, MacOsBundleManifest};

    fn manifest(min_cpus: u32, min_memory_mib: u32) -> MacOsBundleManifest {
        MacOsBundleManifest {
            format: MACOS_BUNDLE_FORMAT,
            build: "25A354".into(),
            os_version: "26.0.1".into(),
            disk_size_bytes: 64 << 30,
            min_cpus,
            min_memory_mib,
            agent_provisioned: true,
        }
    }

    fn write_bundle(dir: &Path, m: &MacOsBundleManifest) -> MacOsBundle {
        std::fs::create_dir_all(dir).unwrap();
        let bundle = MacOsBundle::new(dir);
        bundle.write_manifest(m).unwrap();
        for p in [
            bundle.disk_path(),
            bundle.aux_path(),
            bundle.hardware_model_path(),
        ] {
            std::fs::write(p, b"x").unwrap();
        }
        bundle
    }

    #[cfg(not(feature = "linux-net"))]
    #[test]
    fn shape_defaults_to_desktop_size_but_never_below_the_bundle_minimum() {
        assert_eq!(
            macos_vm_shape(&manifest(2, 4096), None, None).unwrap(),
            (4, 8192)
        );
        assert_eq!(
            macos_vm_shape(&manifest(6, 12288), None, None).unwrap(),
            (6, 12288)
        );
        assert_eq!(
            macos_vm_shape(&manifest(2, 4096), Some(2), Some(4096)).unwrap(),
            (2, 4096)
        );
    }

    #[test]
    fn the_boot_failure_hint_does_not_point_at_a_serial_console() {
        let hint = macos_boot_failure_hint();
        assert!(!hint.contains("logs --source serial"), "{hint}");
        assert!(hint.contains("husker macos provision"), "{hint}");
    }

    #[cfg(not(feature = "linux-net"))]
    #[test]
    fn an_explicit_shape_below_the_minimum_is_rejected_not_raised() {
        let err = macos_vm_shape(&manifest(2, 4096), Some(1), None).unwrap_err();
        assert!(
            matches!(&err, CoreError::InvalidArgument(m) if m.contains("at least 2 vCPUs")),
            "{err:?}"
        );
        let err = macos_vm_shape(&manifest(2, 4096), None, Some(2048)).unwrap_err();
        assert!(
            matches!(&err, CoreError::InvalidArgument(m) if m.contains("at least 4096 MiB")),
            "{err:?}"
        );
    }

    #[test]
    fn resolves_a_bundle_by_path_or_by_installed_name() {
        let data = tempfile::tempdir().unwrap();
        let named = macos_images_dir(data.path()).join("sequoia");
        write_bundle(&named, &manifest(2, 4096));
        assert_eq!(
            resolve_macos_bundle(data.path(), "sequoia").unwrap().dir(),
            named
        );
        let elsewhere = tempfile::tempdir().unwrap();
        let path = elsewhere.path().to_str().unwrap();
        assert_eq!(
            resolve_macos_bundle(data.path(), path).unwrap().dir(),
            elsewhere.path()
        );
    }

    #[test]
    fn unknown_and_traversing_names_are_rejected() {
        let data = tempfile::tempdir().unwrap();
        // `..` from the macos dir is the data dir itself, which exists.
        std::fs::create_dir_all(macos_images_dir(data.path())).unwrap();
        let err = resolve_macos_bundle(data.path(), "missing").unwrap_err();
        assert!(err.to_string().contains("husker macos install"), "{err}");
        for name in [".", "..", ""] {
            let err = resolve_macos_bundle(data.path(), name).unwrap_err();
            assert!(
                err.to_string().contains("macOS image name"),
                "a name outside the rules is refused as such, not reported as uninstalled: {name}: {err}"
            );
        }
        let err = resolve_macos_bundle(data.path(), "/nonexistent/bundle").unwrap_err();
        assert!(err.to_string().contains("not a directory"), "{err}");
    }

    #[test]
    fn a_reference_is_a_path_when_it_contains_a_slash_and_a_checked_name_otherwise() {
        assert_eq!(
            MacOsImageRef::parse("/bundles/sequoia").unwrap(),
            MacOsImageRef::Path(PathBuf::from("/bundles/sequoia"))
        );
        assert_eq!(
            MacOsImageRef::parse("./sequoia").unwrap(),
            MacOsImageRef::Path(PathBuf::from("./sequoia"))
        );
        assert_eq!(
            MacOsImageRef::parse("sequoia").unwrap(),
            MacOsImageRef::Name("sequoia".into())
        );
        let err = MacOsImageRef::parse(&"c".repeat(65)).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum length"),
            "a bare name is checked before resolution: {err}"
        );
    }

    #[test]
    fn bundle_names_follow_the_resource_name_rules() {
        let longest = "a".repeat(64);
        validate_macos_image_name(&longest).unwrap();
        validate_macos_image_name("sequoia-15.1_beta").unwrap();
        for (name, reason) in [
            ("a".repeat(65), "exceeds maximum length"),
            (".hidden".into(), "cannot start with"),
            ("se quoia".into(), "invalid character"),
            (String::new(), "cannot be empty"),
        ] {
            let err = validate_macos_image_name(&name).unwrap_err();
            assert!(
                matches!(&err, CoreError::InvalidArgument(m) if m.contains(reason)),
                "{name:?}: {err}"
            );
        }
    }

    #[test]
    fn an_installed_bundle_with_a_name_outside_the_rules_does_not_resolve() {
        // The cap applies to resolution as well as to install, so a directory
        // that appeared under the images dir by other means is not a bundle.
        let data = tempfile::tempdir().unwrap();
        let too_long = "b".repeat(65);
        write_bundle(
            &macos_images_dir(data.path()).join(&too_long),
            &manifest(2, 4096),
        );
        let err = resolve_macos_bundle(data.path(), &too_long).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum length"), "{err}");
    }

    #[cfg(not(feature = "linux-net"))]
    #[test]
    fn a_bundle_without_the_agent_cannot_boot() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = write_bundle(
            dir.path(),
            &MacOsBundleManifest {
                agent_provisioned: false,
                ..manifest(2, 4096)
            },
        );
        let err = bootable_manifest(&bundle).unwrap_err();
        assert!(err.to_string().contains("husker macos provision"), "{err}");
        let dir = tempfile::tempdir().unwrap();
        let bundle = write_bundle(dir.path(), &manifest(2, 4096));
        assert!(bootable_manifest(&bundle).is_ok());
    }

    #[test]
    fn linux_only_inputs_are_rejected_with_a_macos_image() {
        let base = CreateVmRequest {
            name: "m".into(),
            macos_image: Some("sequoia".into()),
            ..Default::default()
        };
        assert!(validate_macos_request(&base).is_ok());
        let cases = [
            (
                CreateVmRequest {
                    cloud_image: Some("u".into()),
                    ..base.clone()
                },
                "--cloud-image",
            ),
            (
                CreateVmRequest {
                    volume: Some("v".into()),
                    ..base.clone()
                },
                "--volume",
            ),
            (
                CreateVmRequest {
                    mounts: vec!["/a:/b".into()],
                    ..base.clone()
                },
                "--mount",
            ),
            (
                CreateVmRequest {
                    disk_size: Some(1),
                    ..base.clone()
                },
                "--disk-size",
            ),
            (
                CreateVmRequest {
                    kernel_path: Some("/k".into()),
                    ..base.clone()
                },
                "kernel",
            ),
            (
                CreateVmRequest {
                    rootfs_path: Some("/r".into()),
                    ..base.clone()
                },
                "rootfs",
            ),
            (
                CreateVmRequest {
                    initrd_path: Some("/i".into()),
                    ..base.clone()
                },
                "initrd",
            ),
            (
                CreateVmRequest {
                    ssh_authorized_keys: vec!["ssh-ed25519 AAAA".into()],
                    ..base.clone()
                },
                "SSH keys",
            ),
        ];
        for (req, what) in cases {
            let err = validate_macos_request(&req).unwrap_err().to_string();
            assert!(err.contains(what), "{what}: {err}");
        }
    }
}
