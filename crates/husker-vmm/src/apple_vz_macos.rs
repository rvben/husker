//! macOS guests on Apple Virtualization.framework (Apple Silicon only).
//!
//! Covers the parts of a macOS guest's life that Linux guests do not have:
//! locating a restore image (IPSW), creating the hardware-model-specific
//! artifacts a bundle needs, running `VZMacOSInstaller`, and building the Mac
//! platform and device set that both installation and every later boot use.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use block2::RcBlock;
use dispatch2::DispatchQueue;
use objc2::AnyThread;
use objc2::rc::Retained;
use objc2_foundation::{NSArray, NSData, NSError, NSString, NSURL};
use objc2_virtualization::{
    VZDiskImageCachingMode, VZDiskImageStorageDeviceAttachment, VZDiskImageSynchronizationMode,
    VZMacAuxiliaryStorage, VZMacAuxiliaryStorageInitializationOptions,
    VZMacGraphicsDeviceConfiguration, VZMacGraphicsDisplayConfiguration, VZMacHardwareModel,
    VZMacMachineIdentifier, VZMacOSBootLoader, VZMacOSInstaller, VZMacOSRestoreImage,
    VZMacPlatformConfiguration, VZNATNetworkDeviceAttachment, VZUSBKeyboardConfiguration,
    VZUSBScreenCoordinatePointingDeviceConfiguration, VZVirtioBlockDeviceConfiguration,
    VZVirtioEntropyDeviceConfiguration, VZVirtioNetworkDeviceConfiguration, VZVirtualMachine,
    VZVirtualMachineConfiguration,
};

use crate::VmmError;
use crate::apple_vz::{QueueConfined, dispatch_sync_fallible, dispatch_sync_result};
use crate::macos_bundle::{MACOS_BUNDLE_FORMAT, MacOsBundle, MacOsBundleManifest};

/// Display the guest renders to. VZ requires a graphics device for macOS
/// guests; husker runs them headless, so the size only matters to whatever
/// later attaches a view or screen-sharing session.
const DISPLAY_WIDTH: isize = 1920;
const DISPLAY_HEIGHT: isize = 1200;
const DISPLAY_PPI: isize = 80;

/// A macOS restore image as reported by Virtualization.framework, reduced to
/// plain data so it can cross threads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreImageInfo {
    /// A file URL for a local IPSW, or the download URL for a fetched one.
    pub url: String,
    pub build: String,
    pub os_version: String,
    /// The most featureful configuration this host supports for the image.
    /// `None` when no hardware model in the image runs on this host.
    pub supported: Option<SupportedConfiguration>,
}

/// Requirements of the best hardware model a restore image offers this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedConfiguration {
    /// `VZMacHardwareModel.dataRepresentation`.
    pub hardware_model: Vec<u8>,
    pub min_cpus: u32,
    pub min_memory_bytes: u64,
}

impl SupportedConfiguration {
    /// The minimum memory rounded up to whole MiB.
    pub fn min_memory_mib(&self) -> u32 {
        u32::try_from(self.min_memory_bytes.div_ceil(1 << 20)).unwrap_or(u32::MAX)
    }
}

impl RestoreImageInfo {
    /// The supported configuration, or an error naming why the host cannot
    /// install this image.
    pub fn require_supported(&self) -> Result<&SupportedConfiguration, VmmError> {
        self.supported.as_ref().ok_or_else(|| {
            VmmError::InvalidConfig(format!(
                "macOS {} ({}) has no hardware model this host can virtualize; \
                 macOS guests need an Apple Silicon host running the same or a newer macOS",
                self.os_version, self.build
            ))
        })
    }

    /// The supported configuration and the installer VM's vCPUs and memory
    /// (see [`crate::macos_bundle::resolve_shape`]), or an error when the
    /// host cannot run the image or an explicit shape is below the image's
    /// minimum. Checked before downloading so a bad `--cpus`/`--memory`
    /// fails up front.
    pub fn require_shape(
        &self,
        vcpu_count: Option<u32>,
        mem_size_mib: Option<u32>,
    ) -> Result<(&SupportedConfiguration, u32, u32), VmmError> {
        let supported = self.require_supported()?;
        let (vcpus, mem) = crate::macos_bundle::resolve_shape(
            &self.os_version,
            supported.min_cpus,
            supported.min_memory_mib(),
            vcpu_count,
            mem_size_mib,
        )?;
        Ok((supported, vcpus, mem))
    }
}

/// Snapshot a `VZMacOSRestoreImage` into plain data.
///
/// # Safety
///
/// `image` must point to a live `VZMacOSRestoreImage`.
unsafe fn restore_image_info(image: &VZMacOSRestoreImage) -> RestoreImageInfo {
    unsafe {
        let version = image.operatingSystemVersion();
        let url = image.URL();
        let url = url
            .absoluteString()
            .map(|s| s.to_string())
            .unwrap_or_default();
        let supported = image
            .mostFeaturefulSupportedConfiguration()
            .and_then(|req| {
                let model = req.hardwareModel();
                model.isSupported().then(|| SupportedConfiguration {
                    hardware_model: model.dataRepresentation().to_vec(),
                    min_cpus: u32::try_from(req.minimumSupportedCPUCount()).unwrap_or(u32::MAX),
                    min_memory_bytes: req.minimumSupportedMemorySize(),
                })
            });
        RestoreImageInfo {
            url,
            build: image.buildVersion().to_string(),
            os_version: format_os_version(
                version.majorVersion,
                version.minorVersion,
                version.patchVersion,
            ),
            supported,
        }
    }
}

fn format_os_version(major: isize, minor: isize, patch: isize) -> String {
    if patch == 0 {
        format!("{major}.{minor}")
    } else {
        format!("{major}.{minor}.{patch}")
    }
}

type RestoreImageSender =
    Arc<StdMutex<Option<tokio::sync::oneshot::Sender<Result<RestoreImageInfo, VmmError>>>>>;

/// Completion block shared by the fetch and load class methods. VZ invokes it
/// on an arbitrary thread; the image is snapshotted there.
fn restore_image_handler(
    tx: RestoreImageSender,
    context: &'static str,
) -> RcBlock<dyn Fn(*mut VZMacOSRestoreImage, *mut NSError)> {
    RcBlock::new(
        move |image: *mut VZMacOSRestoreImage, error: *mut NSError| {
            let result = if !error.is_null() {
                // Safety: non-null NSError from the VZ completion handler, valid for
                // the duration of the callback.
                let desc = unsafe { (*error).localizedDescription() };
                Err(VmmError::ApiError(format!("{context}: {desc}")))
            } else if image.is_null() {
                Err(VmmError::ApiError(format!(
                    "{context}: no restore image returned"
                )))
            } else {
                // Safety: non-null restore image from the completion handler.
                Ok(unsafe { restore_image_info(&*image) })
            };
            if let Some(tx) = tx.lock().ok().and_then(|mut g| g.take()) {
                let _ = tx.send(result);
            }
        },
    )
    .copy()
}

/// Fail unless this process runs natively on Apple Silicon. The Mac guest
/// classes (`VZMacOSRestoreImage`, `VZMacHardwareModel`, ...) do not exist on
/// Intel, nor for an x86_64 binary under Rosetta, and messaging a missing
/// class aborts the process instead of returning an error.
fn require_apple_silicon() -> Result<(), VmmError> {
    if cfg!(target_arch = "aarch64") {
        Ok(())
    } else {
        Err(VmmError::InvalidConfig(
            crate::MACOS_GUEST_UNSUPPORTED.into(),
        ))
    }
}

/// Ask Apple which restore image is the newest this host can install.
///
/// Only metadata is fetched; the IPSW itself must be downloaded from
/// [`RestoreImageInfo::url`] before installation.
pub async fn fetch_latest_restore_image() -> Result<RestoreImageInfo, VmmError> {
    require_apple_silicon()?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let handler = restore_image_handler(
        Arc::new(StdMutex::new(Some(tx))),
        "fetch latest restore image",
    );
    // Safety: class method; VZ copies the handler block and calls it once.
    unsafe { VZMacOSRestoreImage::fetchLatestSupportedWithCompletionHandler(&handler) };
    rx.await
        .map_err(|_| VmmError::ProcessError("restore image fetch produced no result".into()))?
        .map_err(|e| match e {
            // Without the entitlement the catalog fetch fails with an opaque
            // "Installation service returned an unexpected error".
            VmmError::ApiError(message) => VmmError::ApiError(format!(
                "{message}; this needs network access to Apple and a husker binary signed with \
                 the com.apple.security.virtualization entitlement (`make install` signs it)"
            )),
            other => other,
        })
}

/// Load a local IPSW and report what it contains.
pub async fn load_restore_image(ipsw: &Path) -> Result<RestoreImageInfo, VmmError> {
    require_apple_silicon()?;
    if !ipsw.is_file() {
        // VZ raises an Objective-C exception for a URL that is not a local file.
        return Err(VmmError::InvalidConfig(format!(
            "restore image {} is not a file",
            ipsw.display()
        )));
    }
    let url = file_url(ipsw, "restore image")?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let handler = restore_image_handler(Arc::new(StdMutex::new(Some(tx))), "load restore image");
    // Safety: class method with a local file URL (checked above); VZ copies the
    // handler block and calls it once.
    unsafe { VZMacOSRestoreImage::loadFileURL_completionHandler(&url, &handler) };
    rx.await
        .map_err(|_| VmmError::ProcessError("restore image load produced no result".into()))?
}

fn file_url(path: &Path, what: &str) -> Result<Retained<NSURL>, VmmError> {
    let s = path
        .to_str()
        .ok_or_else(|| VmmError::InvalidConfig(format!("{what} path not valid UTF-8")))?;
    Ok(NSURL::fileURLWithPath(&NSString::from_str(s)))
}

fn read_bytes(path: &Path, what: &str) -> Result<Vec<u8>, VmmError> {
    std::fs::read(path)
        .map_err(|e| VmmError::InvalidConfig(format!("read {what} {}: {e}", path.display())))
}

/// Decode a stored hardware model and check this host can run it.
pub fn hardware_model_from_bytes(bytes: &[u8]) -> Result<Retained<VZMacHardwareModel>, VmmError> {
    require_apple_silicon()?;
    let data = NSData::with_bytes(bytes);
    // Safety: initWithDataRepresentation returns nil (None) for invalid data.
    let model = unsafe {
        VZMacHardwareModel::initWithDataRepresentation(VZMacHardwareModel::alloc(), &data)
    }
    .ok_or_else(|| VmmError::InvalidConfig("invalid macOS hardware model data".into()))?;
    // Safety: plain property read on a live object.
    if !unsafe { model.isSupported() } {
        return Err(VmmError::InvalidConfig(
            "this host cannot virtualize the bundle's macOS hardware model".into(),
        ));
    }
    Ok(model)
}

fn machine_identifier_from_bytes(
    bytes: &[u8],
) -> Result<Retained<VZMacMachineIdentifier>, VmmError> {
    require_apple_silicon()?;
    let data = NSData::with_bytes(bytes);
    // Safety: initWithDataRepresentation returns nil (None) for invalid data.
    unsafe {
        VZMacMachineIdentifier::initWithDataRepresentation(VZMacMachineIdentifier::alloc(), &data)
    }
    .ok_or_else(|| VmmError::InvalidConfig("invalid macOS machine identifier data".into()))
}

/// Write a new, unique machine identifier to `path`.
///
/// Apple VZ requires concurrently running macOS VMs to have distinct
/// identifiers, so every VM cloned from a bundle gets its own.
pub fn write_new_machine_identifier(path: &Path) -> Result<(), VmmError> {
    require_apple_silicon()?;
    // Safety: plain constructor.
    let id = unsafe { VZMacMachineIdentifier::new() };
    // Safety: plain property read on a live object.
    let bytes = unsafe { id.dataRepresentation() }.to_vec();
    std::fs::write(path, bytes).map_err(|e| {
        VmmError::ProcessError(format!("write machine identifier {}: {e}", path.display()))
    })
}

/// Create an empty auxiliary storage for `hardware_model` at `path`,
/// replacing any existing file.
pub fn create_auxiliary_storage(path: &Path, hardware_model: &[u8]) -> Result<(), VmmError> {
    let model = hardware_model_from_bytes(hardware_model)?;
    let url = file_url(path, "auxiliary storage")?;
    // Safety: initializer with a valid file URL and a live hardware model.
    unsafe {
        VZMacAuxiliaryStorage::initCreatingStorageAtURL_hardwareModel_options_error(
            VZMacAuxiliaryStorage::alloc(),
            &url,
            &model,
            VZMacAuxiliaryStorageInitializationOptions::AllowOverwrite,
        )
    }
    .map(|_| ())
    .map_err(|e| VmmError::ApiError(format!("create auxiliary storage {}: {e}", path.display())))
}

/// Mac platform for a guest: hardware model, machine identifier, and its
/// auxiliary storage.
pub(crate) fn mac_platform(
    hardware_model: &Path,
    machine_identifier: &Path,
    auxiliary_storage: &Path,
) -> Result<Retained<VZMacPlatformConfiguration>, VmmError> {
    let model = hardware_model_from_bytes(&read_bytes(hardware_model, "hardware model")?)?;
    let identifier =
        machine_identifier_from_bytes(&read_bytes(machine_identifier, "machine identifier")?)?;
    if !auxiliary_storage.is_file() {
        return Err(VmmError::InvalidConfig(format!(
            "auxiliary storage {} does not exist",
            auxiliary_storage.display()
        )));
    }
    let aux_url = file_url(auxiliary_storage, "auxiliary storage")?;
    // Safety: plain VZ configuration objects; nothing here touches a VM yet.
    unsafe {
        let aux = VZMacAuxiliaryStorage::initWithURL(VZMacAuxiliaryStorage::alloc(), &aux_url);
        let platform = VZMacPlatformConfiguration::new();
        platform.setHardwareModel(&model);
        platform.setMachineIdentifier(&identifier);
        platform.setAuxiliaryStorage(Some(&aux));
        Ok(platform)
    }
}

/// The macOS boot loader.
pub(crate) fn macos_boot_loader() -> Result<Retained<objc2_virtualization::VZBootLoader>, VmmError>
{
    require_apple_silicon()?;
    // Safety: plain constructor.
    Ok(Retained::into_super(unsafe { VZMacOSBootLoader::new() }))
}

/// Devices every macOS guest gets on top of storage, network, and vsock:
/// a Mac graphics device (VZ will not boot macOS without one), a USB
/// keyboard and screen-coordinate pointer for any attached view, and an
/// entropy source.
///
/// # Safety
///
/// `config` must not yet be in use by a `VZVirtualMachine`.
pub(crate) unsafe fn add_macos_devices(config: &VZVirtualMachineConfiguration) {
    unsafe {
        let display =
            VZMacGraphicsDisplayConfiguration::initWithWidthInPixels_heightInPixels_pixelsPerInch(
                VZMacGraphicsDisplayConfiguration::alloc(),
                DISPLAY_WIDTH,
                DISPLAY_HEIGHT,
                DISPLAY_PPI,
            );
        let graphics = VZMacGraphicsDeviceConfiguration::new();
        graphics.setDisplays(&NSArray::from_retained_slice(&[display]));
        config.setGraphicsDevices(&NSArray::from_retained_slice(&[graphics.into_super()]));

        let keyboard = VZUSBKeyboardConfiguration::new();
        config.setKeyboards(&NSArray::from_retained_slice(&[keyboard.into_super()]));

        let pointer = VZUSBScreenCoordinatePointingDeviceConfiguration::new();
        config.setPointingDevices(&NSArray::from_retained_slice(&[pointer.into_super()]));

        let entropy = VZVirtioEntropyDeviceConfiguration::new();
        config.setEntropyDevices(&NSArray::from_retained_slice(&[entropy.into_super()]));
    }
}

/// Virtio block device for a raw disk image, with the explicit cached + fsync
/// modes every husker VZ disk uses (the defaults corrupt sparse images on APFS).
pub(crate) fn virtio_disk(
    path: &Path,
    read_only: bool,
    what: &str,
) -> Result<Retained<objc2_virtualization::VZStorageDeviceConfiguration>, VmmError> {
    let url = file_url(path, what)?;
    // Safety: attachment + device configuration objects, not yet attached to a VM.
    unsafe {
        let attachment =
            VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
                VZDiskImageStorageDeviceAttachment::alloc(),
                &url,
                read_only,
                VZDiskImageCachingMode::Cached,
                VZDiskImageSynchronizationMode::Fsync,
            )
            .map_err(|e| VmmError::InvalidConfig(format!("{what} attachment: {e}")))?;
        Ok(VZVirtioBlockDeviceConfiguration::initWithAttachment(
            VZVirtioBlockDeviceConfiguration::alloc(),
            &attachment,
        )
        .into_super())
    }
}

/// Paths for [`install`].
#[derive(Debug, Clone)]
pub struct InstallRequest {
    pub bundle: PathBuf,
    pub ipsw: PathBuf,
    pub disk_size_bytes: u64,
    /// Unset takes the default, raised to the image's minimum.
    pub vcpu_count: Option<u32>,
    /// Unset takes the default, raised to the image's minimum.
    pub mem_size_mib: Option<u32>,
}

/// Smallest boot disk husker will create for a macOS install.
pub const MIN_DISK_SIZE_BYTES: u64 = 32 << 30;

/// Create a new bundle at `req.bundle` and install macOS from `req.ipsw` onto it.
///
/// `progress` receives the installer's fraction completed (0.0..=1.0) about
/// once a second. On failure the partially written bundle is removed, so a
/// bundle directory with a manifest is always a completed install.
pub async fn install(
    req: InstallRequest,
    progress: impl Fn(f64) + Send + 'static,
) -> Result<MacOsBundleManifest, VmmError> {
    if req.disk_size_bytes < MIN_DISK_SIZE_BYTES {
        return Err(VmmError::InvalidConfig(format!(
            "macOS needs a disk of at least {} GiB",
            MIN_DISK_SIZE_BYTES >> 30
        )));
    }
    if req.bundle.exists() {
        return Err(VmmError::VmAlreadyExists(format!(
            "macOS bundle {} already exists",
            req.bundle.display()
        )));
    }
    let image = load_restore_image(&req.ipsw).await?;
    let (supported, vcpus, mem_size_mib) = image.require_shape(req.vcpu_count, req.mem_size_mib)?;
    let supported = supported.clone();

    std::fs::create_dir_all(&req.bundle).map_err(|e| {
        VmmError::ProcessError(format!("create bundle {}: {e}", req.bundle.display()))
    })?;
    let bundle = MacOsBundle::new(&req.bundle);
    let result = install_into(
        &bundle,
        &req,
        &image,
        &supported,
        (vcpus, mem_size_mib),
        progress,
    )
    .await;
    if result.is_err() {
        let _ = std::fs::remove_dir_all(bundle.dir());
    }
    result
}

async fn install_into(
    bundle: &MacOsBundle,
    req: &InstallRequest,
    image: &RestoreImageInfo,
    supported: &SupportedConfiguration,
    (vcpus, mem_size_mib): (u32, u32),
    progress: impl Fn(f64) + Send + 'static,
) -> Result<MacOsBundleManifest, VmmError> {
    let min_memory_mib = supported.min_memory_mib();
    let io = |what: &str, e: std::io::Error| VmmError::ProcessError(format!("{what}: {e}"));
    std::fs::write(bundle.hardware_model_path(), &supported.hardware_model)
        .map_err(|e| io("write hardware model", e))?;
    write_new_machine_identifier(&bundle.machine_identifier_path())?;
    create_auxiliary_storage(&bundle.aux_path(), &supported.hardware_model)?;
    // Sparse: only blocks the installer writes consume host space.
    std::fs::File::create(bundle.disk_path())
        .and_then(|f| f.set_len(req.disk_size_bytes))
        .map_err(|e| io("create disk image", e))?;

    let queue = DispatchQueue::new("com.husker.macos-install", None);
    let ipsw_url = req.ipsw.clone();
    let paths = bundle.clone();
    let mem_bytes = u64::from(mem_size_mib) << 20;
    let (tx, rx) = tokio::sync::oneshot::channel::<Result<(), VmmError>>();
    let tx = Arc::new(StdMutex::new(Some(tx)));

    let queue_for_vm = queue.clone();
    let installer = dispatch_sync_fallible(queue.clone(), move || {
        let config = installer_configuration(&paths, vcpus, mem_bytes)?;
        let ipsw = file_url(&ipsw_url, "restore image")?;
        // Safety: VM and installer are created and started on `queue`, the
        // VM's own serial queue, as VZ requires.
        unsafe {
            let vm = VZVirtualMachine::initWithConfiguration_queue(
                VZVirtualMachine::alloc(),
                &config,
                &queue_for_vm,
            );
            let installer = VZMacOSInstaller::initWithVirtualMachine_restoreImageURL(
                VZMacOSInstaller::alloc(),
                &vm,
                &ipsw,
            );
            let handler = RcBlock::new(move |error: *mut NSError| {
                let result = if error.is_null() {
                    Ok(())
                } else {
                    // Safety: non-null NSError from the completion handler.
                    let desc = (*error).localizedDescription();
                    Err(VmmError::ApiError(format!(
                        "macOS installation failed: {desc}"
                    )))
                };
                if let Some(tx) = tx.lock().ok().and_then(|mut g| g.take()) {
                    let _ = tx.send(result);
                }
            });
            installer.installWithCompletionHandler(&handler);
            Ok(QueueConfined(installer))
        }
    })
    .await?;

    let installer = Arc::new(installer);
    let mut rx = rx;
    let outcome = loop {
        tokio::select! {
            done = &mut rx => {
                break done.map_err(|_| {
                    VmmError::ProcessError("installer completion channel closed".into())
                })?;
            }
            () = tokio::time::sleep(Duration::from_secs(1)) => {
                let installer = installer.clone();
                let fraction = dispatch_sync_result(queue.clone(), move || {
                    let _capture_whole = &installer;
                    // Safety: progress is read on the VM's queue.
                    unsafe { installer.0.progress().fractionCompleted() }
                })
                .await?;
                progress(fraction);
            }
        }
    };
    outcome?;
    progress(1.0);

    let manifest = MacOsBundleManifest {
        format: MACOS_BUNDLE_FORMAT,
        build: image.build.clone(),
        os_version: image.os_version.clone(),
        disk_size_bytes: req.disk_size_bytes,
        min_cpus: supported.min_cpus,
        min_memory_mib,
        agent_provisioned: false,
    };
    bundle.write_manifest(&manifest)?;
    Ok(manifest)
}

/// The VM configuration the installer runs against: the same Mac platform
/// and devices a later boot uses, so the installed system matches.
fn installer_configuration(
    bundle: &MacOsBundle,
    vcpu_count: u32,
    mem_bytes: u64,
) -> Result<Retained<VZVirtualMachineConfiguration>, VmmError> {
    let platform = mac_platform(
        &bundle.hardware_model_path(),
        &bundle.machine_identifier_path(),
        &bundle.aux_path(),
    )?;
    let disk = virtio_disk(&bundle.disk_path(), false, "macOS disk")?;
    let boot_loader = macos_boot_loader()?;
    // Safety: configuration object is built and validated before any VM uses it.
    unsafe {
        let config = VZVirtualMachineConfiguration::new();
        config.setCPUCount(vcpu_count as usize);
        config.setMemorySize(mem_bytes);
        config.setBootLoader(Some(&boot_loader));
        config.setPlatform(&platform);
        config.setStorageDevices(&NSArray::from_retained_slice(&[disk]));
        let net = VZVirtioNetworkDeviceConfiguration::new();
        net.setAttachment(Some(&VZNATNetworkDeviceAttachment::new()));
        config.setNetworkDevices(&NSArray::from_retained_slice(&[net.into_super()]));
        add_macos_devices(&config);
        config
            .validateWithError()
            .map_err(|e| VmmError::InvalidConfig(format!("installer configuration: {e}")))?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_version_omits_a_zero_patch() {
        assert_eq!(format_os_version(26, 0, 0), "26.0");
        assert_eq!(format_os_version(26, 0, 1), "26.0.1");
        assert_eq!(format_os_version(15, 7, 2), "15.7.2");
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn invalid_hardware_model_bytes_are_rejected() {
        let err = hardware_model_from_bytes(b"not a hardware model").unwrap_err();
        assert!(err.to_string().contains("hardware model"), "{err}");
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn invalid_machine_identifier_bytes_are_rejected() {
        let err = machine_identifier_from_bytes(b"nope").unwrap_err();
        assert!(err.to_string().contains("machine identifier"), "{err}");
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn new_machine_identifiers_are_distinct_and_decodable() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        write_new_machine_identifier(&a).unwrap();
        write_new_machine_identifier(&b).unwrap();
        let (a, b) = (std::fs::read(a).unwrap(), std::fs::read(b).unwrap());
        assert_ne!(a, b, "each VM needs its own identifier");
        machine_identifier_from_bytes(&a).unwrap();
    }

    #[cfg(target_arch = "aarch64")]
    #[tokio::test]
    async fn loading_a_missing_ipsw_is_an_error_not_an_exception() {
        let err = load_restore_image(Path::new("/nonexistent/restore.ipsw"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("is not a file"), "{err}");
    }

    #[cfg(target_arch = "aarch64")]
    #[tokio::test]
    async fn loading_a_non_ipsw_file_reports_the_framework_error() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("fake.ipsw");
        std::fs::write(&fake, b"definitely not an ipsw").unwrap();
        let err = load_restore_image(&fake).await.unwrap_err();
        assert!(err.to_string().contains("load restore image"), "{err}");
    }

    #[tokio::test]
    async fn install_rejects_a_disk_too_small_for_macos() {
        let dir = tempfile::tempdir().unwrap();
        let err = install(
            InstallRequest {
                bundle: dir.path().join("b"),
                ipsw: dir.path().join("x.ipsw"),
                disk_size_bytes: 8 << 30,
                vcpu_count: None,
                mem_size_mib: None,
            },
            |_| {},
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("at least 32 GiB"), "{err}");
        assert!(!dir.path().join("b").exists());
    }

    #[tokio::test]
    async fn install_refuses_to_overwrite_an_existing_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let err = install(
            InstallRequest {
                bundle: dir.path().to_path_buf(),
                ipsw: dir.path().join("x.ipsw"),
                disk_size_bytes: 64 << 30,
                vcpu_count: None,
                mem_size_mib: None,
            },
            |_| {},
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
        assert!(dir.path().exists(), "the existing directory is untouched");
    }

    /// The pre-install half of [`install_into`] against the real framework:
    /// the latest restore image's hardware model must produce auxiliary
    /// storage and a Mac VM configuration that Virtualization.framework
    /// validates. Contacts Apple's restore image catalog once.
    #[cfg(not(target_arch = "aarch64"))]
    #[tokio::test]
    async fn every_mac_guest_entry_point_refuses_off_apple_silicon() {
        let dir = tempfile::tempdir().unwrap();
        let unsupported = |e: VmmError| {
            assert!(
                e.to_string().contains(crate::MACOS_GUEST_UNSUPPORTED),
                "{e}"
            )
        };
        unsupported(fetch_latest_restore_image().await.unwrap_err());
        unsupported(load_restore_image(dir.path()).await.unwrap_err());
        unsupported(hardware_model_from_bytes(b"x").unwrap_err());
        unsupported(machine_identifier_from_bytes(b"x").unwrap_err());
        unsupported(write_new_machine_identifier(&dir.path().join("id")).unwrap_err());
        unsupported(macos_boot_loader().unwrap_err());
    }

    #[cfg(target_arch = "aarch64")]
    #[tokio::test]
    #[ignore = "needs Apple Silicon and network access to Apple's restore image catalog"]
    async fn the_latest_restore_image_yields_a_valid_mac_configuration() {
        let image = fetch_latest_restore_image().await.unwrap();
        assert!(image.url.starts_with("https://"), "{}", image.url);
        assert!(image.url.ends_with(".ipsw"), "{}", image.url);
        let supported = image.require_supported().unwrap();
        assert!(supported.min_cpus >= 1);
        assert!(supported.min_memory_bytes >= 1 << 30);

        let dir = tempfile::tempdir().unwrap();
        let bundle = MacOsBundle::new(dir.path());
        std::fs::write(bundle.hardware_model_path(), &supported.hardware_model).unwrap();
        write_new_machine_identifier(&bundle.machine_identifier_path()).unwrap();
        create_auxiliary_storage(&bundle.aux_path(), &supported.hardware_model).unwrap();
        assert!(std::fs::metadata(bundle.aux_path()).unwrap().len() > 0);
        std::fs::File::create(bundle.disk_path())
            .and_then(|f| f.set_len(MIN_DISK_SIZE_BYTES))
            .unwrap();

        let memory = supported.min_memory_bytes.max(4 << 30);
        let cpus = supported.min_cpus.max(2);
        installer_configuration(&bundle, cpus, memory).unwrap();
        // Below the hardware model's minimum the framework refuses to validate.
        assert!(installer_configuration(&bundle, cpus, 1 << 20).is_err());
    }
}
