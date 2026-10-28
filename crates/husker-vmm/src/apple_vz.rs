//! Apple Virtualization.framework backend for macOS.
//!
//! Each VM runs on a dedicated serial dispatch queue to satisfy
//! VZVirtualMachine's queue-affinity requirement.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};

use block2::RcBlock;
use dispatch2::{DispatchQueue, DispatchRetained};
use libc;
use objc2::AnyThread;
use objc2::rc::Retained;
use objc2_foundation::{NSArray, NSError, NSFileHandle, NSString, NSURL};
use objc2_virtualization::{
    VZDiskImageStorageDeviceAttachment, VZEFIBootLoader, VZEFIVariableStore,
    VZEFIVariableStoreInitializationOptions, VZFileHandleSerialPortAttachment,
    VZGenericPlatformConfiguration, VZLinuxBootLoader, VZNATNetworkDeviceAttachment,
    VZNetworkDeviceConfiguration, VZVirtioBlockDeviceConfiguration,
    VZVirtioConsoleDeviceSerialPortConfiguration, VZVirtioNetworkDeviceConfiguration,
    VZVirtioSocketConnection, VZVirtioSocketDevice, VZVirtioSocketDeviceConfiguration,
    VZVirtioTraditionalMemoryBalloonDevice, VZVirtioTraditionalMemoryBalloonDeviceConfiguration,
    VZVirtualMachine, VZVirtualMachineConfiguration, VZVirtualMachineState,
};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::fd_stream::FdStream;
use crate::guest_stop::{GUEST_SHUTDOWN_GRACE, GuestExit, wait_for_guest_exit};
use crate::{BackendKind, CreatedVm, VmConfig, VmInfo, VmState, VmmBackend, VmmError};

fn network_devices(disabled: bool) -> Vec<Retained<VZNetworkDeviceConfiguration>> {
    if disabled {
        return Vec::new();
    }
    let nat = unsafe { VZNATNetworkDeviceAttachment::new() };
    let device = unsafe { VZVirtioNetworkDeviceConfiguration::new() };
    unsafe { device.setAttachment(Some(&*nat)) };
    vec![device.into_super()]
}

// ── Send/Sync wrappers ──────────────────────────────────────────────────

/// Wrapper that marks an ObjC type as Send + Sync.
///
/// # Invariants
///
/// The wrapped value must only be accessed from a single serial dispatch queue.
/// `VZVirtualMachine` requires that all method calls happen on the queue it was
/// created on. By confining access to that queue (via `dispatch_sync_result` and
/// `dispatch_vz_op`), the `Send + Sync` impl is sound: the value is moved
/// between threads only inside closures dispatched to the correct queue.
pub(crate) struct QueueConfined<T>(pub(crate) T);

// Safety: Values are only accessed from their associated serial dispatch queue,
// satisfying VZVirtualMachine's queue-affinity requirement. Cross-thread moves
// happen only via dispatch queue submission, not direct access.
unsafe impl<T> Send for QueueConfined<T> {}
unsafe impl<T> Sync for QueueConfined<T> {}

/// Vsock stream type alias for Apple VZ.
///
/// The completion callback creates an independent fd via `dup(2)` and hands it
/// off as an `OwnedFd`, which closes it if the waiting caller has gone away.
/// The dup'd fd survives `VZVirtioSocketConnection` deallocation because
/// `dup()` creates a separate file description reference — the kernel keeps
/// the underlying socket alive as long as any fd references it. This is the
/// same pattern used by the Go VZ bindings (`Code-Hex/vz`), which extract
/// the fd via `net.FileConn` (which calls `dup`) and let the ObjC connection
/// object be deallocated.
pub type VzVsockStream = FdStream;

// ── Instance tracking ───────────────────────────────────────────────────

/// Instance tracking for a running VZ virtual machine.
struct VzInstance {
    info: VmInfo,
    /// Serial dispatch queue — all VZ operations for this VM go through here.
    queue: DispatchRetained<DispatchQueue>,
    /// The VZ virtual machine object. Only accessed from `queue`.
    vm: Option<QueueConfined<Retained<VZVirtualMachine>>>,
    configuration_inflight: bool,
    serial_log_path: PathBuf,
    /// Kept alive so the bounded capture socket remains valid for the attachment.
    _serial_file: Arc<std::fs::File>,
    serial_capture: Option<crate::serial_capture::SerialCapture>,
    /// Whether a virtio memory balloon device was attached at create time.
    balloon: bool,
    /// Guest memory size in bytes, used to compute the absolute balloon target.
    mem_size_bytes: u64,
}

impl VzInstance {
    fn machine(&self) -> Result<QueueConfined<Retained<VZVirtualMachine>>, VmmError> {
        self.vm
            .as_ref()
            .map(|vm| QueueConfined(vm.0.clone()))
            .ok_or_else(|| {
                VmmError::ProcessError("VZ configuration has no machine handle yet".into())
            })
    }
}

type VzOwner = Arc<Mutex<VzInstance>>;

struct RegisteredVzInstance {
    name: String,
    owner: VzOwner,
}

/// VZ operations that use completion handlers.
enum VzOp {
    Start,
    Stop,
    Pause,
    Resume,
}

/// Apple Virtualization.framework VMM backend.
pub struct AppleVzBackend {
    runtime_dir: PathBuf,
    creation_locks: crate::creation::CreationLocks,
    instances: Arc<Mutex<HashMap<Uuid, RegisteredVzInstance>>>,
}

impl AppleVzBackend {
    pub fn new(runtime_dir: impl Into<PathBuf>) -> Self {
        Self {
            runtime_dir: runtime_dir.into(),
            instances: Arc::new(Mutex::new(HashMap::new())),
            creation_locks: crate::creation::CreationLocks::default(),
        }
    }

    async fn instance(&self, id: Uuid) -> Result<VzOwner, VmmError> {
        self.instances
            .lock()
            .await
            .get(&id)
            .map(|registered| registered.owner.clone())
            .ok_or(VmmError::VmNotFound(id))
    }

    async fn forget_stopped_instance(&self, id: Uuid, owner: &VzOwner) -> Result<(), VmmError> {
        let mut instances = self.instances.lock().await;
        let registered = instances.get(&id).ok_or(VmmError::VmNotFound(id))?;
        if !Arc::ptr_eq(&registered.owner, owner) {
            return Err(VmmError::ProcessError(
                "VZ generation changed; replacement ownership retained".into(),
            ));
        }
        instances.remove(&id);
        Ok(())
    }

    /// Configure and publish an unstarted VM on its queue. The queued closure
    /// retains the serial file and publishes directly to its instance generation,
    /// even if its async observer is cancelled or times out.
    async fn configure_vm(
        id: Uuid,
        config: VmConfig,
        queue: DispatchRetained<DispatchQueue>,
        serial_file: Arc<std::fs::File>,
        owner: VzOwner,
    ) -> Result<(), VmmError> {
        let mem_size_bytes = u64::from(config.mem_size_mib) * 1024 * 1024;
        dispatch_sync_fallible(queue.clone(), {
            let config = config.clone();
            let queue_for_vm = queue.clone();
            // Safety: All VZ API calls in this closure execute on the VM's dedicated
            // serial dispatch queue via `dispatch_sync_fallible`. The objc2 bindings
            // are `unsafe` because they call into Objective-C; the VZ framework
            // guarantees thread-safety when called from the correct queue.
            move || -> Result<(), VmmError> {
                use std::os::fd::AsRawFd;
                let serial_write_fd = serial_file.as_raw_fd();
                let result = (|| -> Result<QueueConfined<Retained<VZVirtualMachine>>, VmmError> {
                // Boot loader — varies by boot mode.
                let boot_loader: objc2::rc::Retained<objc2_virtualization::VZBootLoader> =
                    match &config.boot {
                        crate::BootMode::DirectKernel => {
                            let kernel_path = config.kernel_path.to_str().ok_or_else(|| {
                                VmmError::InvalidConfig("kernel path not valid UTF-8".into())
                            })?;
                            let kernel_url =
                                NSURL::fileURLWithPath(&NSString::from_str(kernel_path));
                            let loader = unsafe {
                                VZLinuxBootLoader::initWithKernelURL(
                                    VZLinuxBootLoader::alloc(),
                                    &kernel_url,
                                )
                            };
                            if let Some(ref args) = config.kernel_args {
                                unsafe { loader.setCommandLine(&NSString::from_str(args)) };
                            }
                            if let Some(ref initrd) = config.initrd_path {
                                let initrd_str = initrd.to_str().ok_or_else(|| {
                                    VmmError::InvalidConfig("initrd path not valid UTF-8".into())
                                })?;
                                let initrd_url =
                                    NSURL::fileURLWithPath(&NSString::from_str(initrd_str));
                                unsafe { loader.setInitialRamdiskURL(Some(&initrd_url)) };
                            }
                            objc2::rc::Retained::into_super(loader)
                        }
                        crate::BootMode::Efi { variable_store } => {
                            let vs_str = variable_store.to_str().ok_or_else(|| {
                                VmmError::InvalidConfig(
                                    "EFI variable store path not valid UTF-8".into(),
                                )
                            })?;
                            let vs_url = NSURL::fileURLWithPath(&NSString::from_str(vs_str));
                            let store = if variable_store.exists() {
                                unsafe {
                                    VZEFIVariableStore::initWithURL(
                                        VZEFIVariableStore::alloc(),
                                        &vs_url,
                                    )
                                }
                            } else {
                                unsafe {
                                    VZEFIVariableStore::initCreatingVariableStoreAtURL_options_error(
                                        VZEFIVariableStore::alloc(),
                                        &vs_url,
                                        VZEFIVariableStoreInitializationOptions::empty(),
                                    )
                                    .map_err(|e| {
                                        VmmError::InvalidConfig(format!(
                                            "EFI variable store creation failed: {e}"
                                        ))
                                    })?
                                }
                            };
                            let efi_loader = unsafe { VZEFIBootLoader::new() };
                            unsafe { efi_loader.setVariableStore(Some(&store)) };
                            objc2::rc::Retained::into_super(efi_loader)
                        }
                        crate::BootMode::MacOs { .. } => {
                            crate::apple_vz_macos::macos_boot_loader()?
                        }
                        crate::BootMode::Uefi { .. } => {
                            // Filtered out before entering the dispatch closure; this
                            // arm is unreachable but required for exhaustive matching.
                            return Err(VmmError::InvalidConfig(
                                "OVMF boot is a Linux/QEMU mode; macOS uses EFI boot".into(),
                            ));
                        }
                    };

                let vz_config = unsafe { VZVirtualMachineConfiguration::new() };
                unsafe {
                    vz_config.setCPUCount(config.vcpu_count as usize);
                    vz_config.setMemorySize(mem_size_bytes);
                    vz_config.setBootLoader(Some(&*boot_loader));
                }

                // Block storage devices. The rootfs is always first (/dev/vda);
                // the optional volume is second (/dev/vdb) — same order the QEMU
                // backend enforces, keeping the guest device assignment stable.
                let rootfs_path = config
                    .rootfs_path
                    .to_str()
                    .ok_or_else(|| {
                        VmmError::InvalidConfig("rootfs path not valid UTF-8".into())
                    })?;
                let rootfs_url = NSURL::fileURLWithPath(&NSString::from_str(rootfs_path));
                // Explicit cached + fsync modes: the default attachment modes
                // corrupt re-reads of sparse raw images on APFS (pages read
                // back as zeros once evicted), progressively breaking the
                // guest. Cached I/O goes through the host's unified buffer
                // cache and stays coherent.
                let disk_attachment = unsafe {
                    VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
                        VZDiskImageStorageDeviceAttachment::alloc(),
                        &rootfs_url,
                        false,
                        objc2_virtualization::VZDiskImageCachingMode::Cached,
                        objc2_virtualization::VZDiskImageSynchronizationMode::Fsync,
                    )
                    .map_err(|e| VmmError::InvalidConfig(format!("disk attachment: {e}")))?
                };
                let rootfs_block = unsafe {
                    VZVirtioBlockDeviceConfiguration::initWithAttachment(
                        VZVirtioBlockDeviceConfiguration::alloc(),
                        &disk_attachment,
                    )
                };
                // Block storage device order matches QEMU: vda=boot disk, vdb=volume, vdc=seed.
                // husker-cloudinit automounts /dev/vdb as /data, so the volume must come
                // before the seed when both are present.
                let mut storage_devices = vec![rootfs_block.into_super()];

                if let Some(ref vol_path) = config.volume_path {
                    let vol_str = vol_path.to_str().ok_or_else(|| {
                        VmmError::InvalidConfig("volume path not valid UTF-8".into())
                    })?;
                    let vol_url = NSURL::fileURLWithPath(&NSString::from_str(vol_str));
                    let vol_attachment = unsafe {
                        VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
                            VZDiskImageStorageDeviceAttachment::alloc(),
                            &vol_url,
                            false,
                            objc2_virtualization::VZDiskImageCachingMode::Cached,
                            objc2_virtualization::VZDiskImageSynchronizationMode::Fsync,
                        )
                        .map_err(|e| VmmError::InvalidConfig(format!("volume attachment: {e}")))?
                    };
                    let vol_block = unsafe {
                        VZVirtioBlockDeviceConfiguration::initWithAttachment(
                            VZVirtioBlockDeviceConfiguration::alloc(),
                            &vol_attachment,
                        )
                    };
                    storage_devices.push(vol_block.into_super());
                }

                if let Some(ref seed) = config.seed_path {
                    let seed_str = seed.to_str().ok_or_else(|| {
                        VmmError::InvalidConfig("seed path not valid UTF-8".into())
                    })?;
                    let seed_url = NSURL::fileURLWithPath(&NSString::from_str(seed_str));
                    let seed_attachment = unsafe {
                        VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
                            VZDiskImageStorageDeviceAttachment::alloc(),
                            &seed_url,
                            true,
                            objc2_virtualization::VZDiskImageCachingMode::Cached,
                            objc2_virtualization::VZDiskImageSynchronizationMode::Fsync,
                        )
                        .map_err(|e| VmmError::InvalidConfig(format!("seed attachment: {e}")))?
                    };
                    let seed_block = unsafe {
                        VZVirtioBlockDeviceConfiguration::initWithAttachment(
                            VZVirtioBlockDeviceConfiguration::alloc(),
                            &seed_attachment,
                        )
                    };
                    storage_devices.push(seed_block.into_super());
                }

                unsafe {
                    vz_config
                        .setStorageDevices(&NSArray::from_retained_slice(&storage_devices));
                }

                // Offline enforcement is device omission at the VMM boundary,
                // independent of guest firewall, DNS, IPv4 or IPv6 settings.
                let networks = network_devices(config.network_disabled);
                unsafe {
                    vz_config.setNetworkDevices(&NSArray::from_retained_slice(&networks));
                }

                // Vsock
                let socket_device = unsafe { VZVirtioSocketDeviceConfiguration::new() };
                let socket_config = socket_device.into_super();
                unsafe {
                    vz_config
                        .setSocketDevices(&NSArray::from_retained_slice(&[socket_config]));
                }

                // Memory balloon (opt-in via VmConfig.balloon)
                if config.balloon {
                    let balloon_cfg =
                        unsafe { VZVirtioTraditionalMemoryBalloonDeviceConfiguration::new() };
                    let balloon_cfg = balloon_cfg.into_super();
                    unsafe {
                        vz_config.setMemoryBalloonDevices(&NSArray::from_retained_slice(&[
                            balloon_cfg,
                        ]));
                    }
                }

                // Platform: a macOS guest needs the Mac platform it was
                // installed for plus the Mac input/graphics devices; Linux on
                // ARM64 uses the generic platform.
                if let crate::BootMode::MacOs {
                    auxiliary_storage,
                    hardware_model,
                    machine_identifier,
                } = &config.boot
                {
                    let platform = crate::apple_vz_macos::mac_platform(
                        hardware_model,
                        machine_identifier,
                        auxiliary_storage,
                    )?;
                    unsafe {
                        vz_config.setPlatform(&platform);
                        crate::apple_vz_macos::add_macos_devices(&vz_config);
                    }
                } else {
                    let platform = unsafe { VZGenericPlatformConfiguration::new() };
                    unsafe {
                        vz_config.setPlatform(&platform);
                    }
                }

                // Serial console (hvc0 — virtio console)
                // Attach output to the bounded diagnostic drain. No input needed.
                let write_handle = NSFileHandle::initWithFileDescriptor(
                    NSFileHandle::alloc(),
                    serial_write_fd,
                );
                let attachment = unsafe {
                    VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                        VZFileHandleSerialPortAttachment::alloc(),
                        None,
                        Some(&*write_handle),
                    )
                };
                let serial_port =
                    unsafe { VZVirtioConsoleDeviceSerialPortConfiguration::new() };
                unsafe { serial_port.setAttachment(Some(&*attachment)) };
                let serial_config = serial_port.into_super();
                unsafe {
                    vz_config
                        .setSerialPorts(&NSArray::from_retained_slice(&[serial_config]));
                }

                // Validate
                unsafe {
                    vz_config
                        .validateWithError()
                        .map_err(|e| VmmError::InvalidConfig(format!("validation: {e}")))?;
                }

                // Create VM bound to its serial dispatch queue
                let vm = unsafe {
                    VZVirtualMachine::initWithConfiguration_queue(
                        VZVirtualMachine::alloc(),
                        &vz_config,
                        &queue_for_vm,
                    )
                };
                Ok(QueueConfined(vm))
                })();
                publish_configuration(&owner, id, result)
            }
        }).await
    }
}

impl Drop for AppleVzBackend {
    fn drop(&mut self) {
        // Best-effort cleanup: request each VM to stop.
        // Uses try_lock to avoid blocking if the mutex is held elsewhere during
        // teardown. The actual VZVirtualMachine deallocation is handled by ObjC
        // ARC when the Retained<VZVirtualMachine> refcount drops to zero.
        if let Ok(mut instances) = self.instances.try_lock() {
            for (_, registered) in instances.drain() {
                let Ok(instance) = registered.owner.try_lock() else {
                    continue;
                };
                let Ok(vm) = instance.machine() else { continue };
                instance.queue.exec_async(move || {
                    let _capture_whole = &vm;
                    // Safety: requestStopWithError is called on the VM's serial
                    // dispatch queue. Errors are ignored (best-effort cleanup).
                    unsafe {
                        let _ = vm.0.requestStopWithError();
                    }
                });
            }
        }
    }
}

fn publish_configuration(
    owner: &Mutex<VzInstance>,
    id: Uuid,
    result: Result<QueueConfined<Retained<VZVirtualMachine>>, VmmError>,
) -> Result<(), VmmError> {
    let mut instance = owner.blocking_lock();
    if instance.info.id != id {
        return Err(VmmError::VmNotFound(id));
    }
    instance.configuration_inflight = false;
    match result {
        Ok(vm) => {
            instance.vm = Some(vm);
            Ok(())
        }
        Err(error) => {
            instance.info.state = VmState::Failed;
            Err(error)
        }
    }
}

async fn await_vz_operation<T>(
    operation: impl std::future::Future<Output = Result<T, VmmError>>,
    label: &str,
) -> Result<T, VmmError> {
    tokio::time::timeout(std::time::Duration::from_secs(30), operation)
        .await
        .map_err(|_| VmmError::ProcessError(format!("VZ {label} not confirmed within 30s")))?
}

type VsockCompletion = tokio::sync::oneshot::Sender<Result<std::os::fd::OwnedFd, VmmError>>;

fn publish_vsock_result(
    sender: &StdMutex<Option<VsockCompletion>>,
    result: Result<std::os::fd::OwnedFd, VmmError>,
) {
    if let Some(sender) = sender.lock().ok().and_then(|mut guard| guard.take()) {
        // Failed delivery drops OwnedFd, including a late callback after timeout.
        let _ = sender.send(result);
    }
}

// ── Dispatch helpers ────────────────────────────────────────────────────

/// Run a closure on a dispatch queue from async context and return its result.
///
/// Uses a oneshot channel to transfer the result from the dispatch queue thread
/// back to the async caller, avoiding any mutex unwrap.
pub(crate) async fn dispatch_sync_result<T: Send + 'static>(
    queue: DispatchRetained<DispatchQueue>,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, VmmError> {
    await_vz_operation(dispatch_sync_result_inner(queue, f), "dispatch result").await
}

async fn dispatch_sync_result_inner<T: Send + 'static>(
    queue: DispatchRetained<DispatchQueue>,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, VmmError> {
    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::task::spawn_blocking(move || {
        queue.exec_sync(|| {
            let _ = tx.send(f());
        });
    })
    .await
    .map_err(|e| VmmError::ProcessError(format!("dispatch join: {e}")))?;

    rx.await
        .map_err(|_| VmmError::ProcessError("dispatch produced no result".into()))
}

/// Run a fallible closure on a dispatch queue and flatten the nested Result.
///
/// Convenience wrapper over `dispatch_sync_result` for closures that return
/// `Result<T, VmmError>`, avoiding the `??` pattern at call sites.
pub(crate) async fn dispatch_sync_fallible<T: Send + 'static>(
    queue: DispatchRetained<DispatchQueue>,
    f: impl FnOnce() -> Result<T, VmmError> + Send + 'static,
) -> Result<T, VmmError> {
    dispatch_sync_result(queue, f).await?
}

/// Read the live state of `vm` on its serial dispatch queue.
async fn live_vz_state(
    queue: &DispatchRetained<DispatchQueue>,
    vm: &QueueConfined<Retained<VZVirtualMachine>>,
) -> Result<VZVirtualMachineState, VmmError> {
    let vm = QueueConfined(vm.0.clone());
    dispatch_sync_result(queue.clone(), move || -> VZVirtualMachineState {
        let _capture_whole = &vm;
        // Safety: Called on the VM's serial dispatch queue.
        unsafe { vm.0.state() }
    })
    .await
}

/// Whether a VZ state means the guest no longer executes: it stopped, or the
/// framework hit an internal error and abandoned it.
fn vz_has_ended(state: VZVirtualMachineState) -> bool {
    matches!(
        state,
        VZVirtualMachineState::Stopped | VZVirtualMachineState::Error
    )
}

/// Dispatch a VZ completion-handler operation on a queue and await the result.
///
/// The closure calling the VZ method executes synchronously on the dispatch queue.
/// The completion handler fires asynchronously on the same queue after the VZ
/// operation completes, sending the result through a oneshot channel.
async fn dispatch_vz_op(
    queue: DispatchRetained<DispatchQueue>,
    vm: QueueConfined<Retained<VZVirtualMachine>>,
    op: VzOp,
) -> Result<(), VmmError> {
    let operation = match &op {
        VzOp::Start => "start",
        VzOp::Stop => "force-stop",
        VzOp::Pause => "pause",
        VzOp::Resume => "resume",
    };
    await_vz_operation(dispatch_vz_op_inner(queue, vm, op), operation).await
}

async fn dispatch_vz_op_inner(
    queue: DispatchRetained<DispatchQueue>,
    vm: QueueConfined<Retained<VZVirtualMachine>>,
    op: VzOp,
) -> Result<(), VmmError> {
    let (tx, rx) = tokio::sync::oneshot::channel::<Result<(), VmmError>>();
    let tx = Arc::new(StdMutex::new(Some(tx)));

    tokio::task::spawn_blocking(move || {
        queue.exec_sync(move || {
            // Force capture of entire `vm` (QueueConfined, which is Send) rather
            // than just `vm.0` (Retained<VZVirtualMachine>, which is !Send).
            // Rust 2021+ precise field captures would otherwise capture only vm.0.
            let _capture_whole = &vm;

            let tx_inner = tx.clone();
            let handler = RcBlock::new(move |error: *mut NSError| {
                let result = if error.is_null() {
                    Ok(())
                } else {
                    // Safety: non-null NSError pointer from VZ completion handler;
                    // valid for the duration of the callback under ObjC ARC.
                    let desc = unsafe { (*error).localizedDescription() };
                    Err(VmmError::ProcessError(desc.to_string()))
                };
                if let Some(tx) = tx_inner.lock().ok().and_then(|mut guard| guard.take()) {
                    let _ = tx.send(result);
                }
            });
            // Safety: VZ methods called on the VM's dedicated serial dispatch queue.
            // The handler block is retained by VZ until the operation completes.
            unsafe {
                match op {
                    VzOp::Start => vm.0.startWithCompletionHandler(&handler),
                    VzOp::Stop => vm.0.stopWithCompletionHandler(&handler),
                    VzOp::Pause => vm.0.pauseWithCompletionHandler(&handler),
                    VzOp::Resume => vm.0.resumeWithCompletionHandler(&handler),
                }
            }
        });
    })
    .await
    .map_err(|e| VmmError::ProcessError(format!("dispatch join: {e}")))?;

    rx.await
        .map_err(|_| VmmError::ProcessError("completion channel closed".into()))?
}

// ── VmmBackend impl ─────────────────────────────────────────────────────

impl VmmBackend for AppleVzBackend {
    type VsockStream = VzVsockStream;

    fn backend_kind(&self) -> &'static str {
        "apple_vz"
    }

    async fn create_vm(
        &self,
        selection: crate::BackendSelection,
        config: VmConfig,
    ) -> Result<CreatedVm, VmmError> {
        selection.validate_for_backend(&config, BackendKind::AppleVz)?;
        if !config.host_shares.is_empty() {
            return Err(VmmError::Unsupported(
                "host bind-mounts (--mount) are not supported on Apple VZ".into(),
            ));
        }
        let id = crate::creation_id(&config)?;
        let _creation = self.creation_locks.lock(id).await;
        if self.instances.lock().await.contains_key(&id) {
            return Err(VmmError::InvalidConfig(
                "requested VM UUID is already allocated".into(),
            ));
        }
        let mut instances = self.instances.lock().await;
        // Check name and UUID in the same registry critical section as insertion.
        // Different UUID creation locks do not serialize a shared VM name.
        if instances
            .values()
            .any(|registered| registered.name == config.name)
        {
            return Err(VmmError::VmAlreadyExists(config.name));
        }
        if instances.contains_key(&id) {
            return Err(VmmError::InvalidConfig(
                "requested VM UUID is already allocated".into(),
            ));
        }
        let queue = DispatchQueue::new(&format!("com.husker.vm.{id}"), None);
        let serial_log_path = self.runtime_dir.join(self.serial_log_file(id));
        let (serial_file, serial_capture) = crate::serial_capture::SerialCapture::new(
            &serial_log_path,
            crate::serial_capture::SERIAL_LOG_BYTES,
        )
        .map_err(|e| VmmError::ProcessError(format!("create serial capture: {e}")))?;
        let info = VmInfo {
            id,
            name: config.name.clone(),
            state: VmState::Creating,
            pid: None,
            vcpu_count: config.vcpu_count,
            mem_size_mib: config.mem_size_mib,
            vsock_cid: config.vsock_cid,
        };
        let owner = Arc::new(Mutex::new(VzInstance {
            info,
            queue: queue.clone(),
            vm: None,
            configuration_inflight: true,
            serial_log_path,
            _serial_file: serial_file.clone(),
            serial_capture: Some(serial_capture),
            balloon: config.balloon,
            mem_size_bytes: u64::from(config.mem_size_mib) * 1024 * 1024,
        }));
        instances.insert(
            id,
            RegisteredVzInstance {
                name: config.name.clone(),
                owner: owner.clone(),
            },
        );
        drop(instances);
        let configured = await_vz_operation(
            Self::configure_vm(id, config, queue.clone(), serial_file, owner.clone()),
            "configuration",
        )
        .await;
        let result = match configured {
            Ok(()) => {
                let vm = owner.lock().await.machine()?;
                dispatch_vz_op(queue, vm, VzOp::Start).await
            }
            Err(error) => Err(error),
        };
        let mut instance = owner.lock().await;
        match result {
            Ok(()) => {
                instance.info.state = VmState::Running;
                Ok(CreatedVm::new(instance.info.clone(), selection))
            }
            Err(error) => {
                instance.info.state = VmState::Failed;
                Err(error)
            }
        }
    }

    /// Stop the VM: send the guest an ACPI power-button request, wait up to the
    /// shared grace period for the VZVirtualMachine to stop, and force it off
    /// otherwise. On return the Virtualization.framework helper no longer holds
    /// the rootfs or serves the vsock device, so the caller may release them at
    /// once. A guest that already ended itself (the agent powered it off on the
    /// host's request) is recorded as stopped without a request.
    async fn stop_vm(&self, id: Uuid) -> Result<(), VmmError> {
        let owner = self.instance(id).await?;
        let (vm, queue) = {
            let inst = owner.lock().await;
            (inst.machine()?, inst.queue.clone())
        };

        let request_vm = QueueConfined(vm.0.clone());
        let requested = dispatch_sync_fallible(queue.clone(), move || -> Result<(), VmmError> {
            let _capture_whole = &request_vm;
            // Safety: Called on the VM's serial dispatch queue via dispatch_sync_fallible.
            unsafe {
                request_vm
                    .0
                    .requestStopWithError()
                    .map_err(|e| VmmError::ApiError(format!("requestStop: {e}")))
            }
        })
        .await;
        if let Err(error) = requested {
            // VZ refuses the request for a VM that is not running. When the
            // guest ended itself between the state check above and the request,
            // that refusal is the outcome the stop wanted; the wait below then
            // observes the stopped state at once.
            if !matches!(
                live_vz_state(&queue, &vm).await?,
                VZVirtualMachineState::Stopped | VZVirtualMachineState::Stopping
            ) {
                return Err(error);
            }
        }

        let exit = wait_for_guest_exit(
            GUEST_SHUTDOWN_GRACE,
            || async {
                let ended = vz_has_ended(live_vz_state(&queue, &vm).await?);
                Ok(ended.then_some(GuestExit::Clean))
            },
            || async {
                match dispatch_vz_op(queue.clone(), QueueConfined(vm.0.clone()), VzOp::Stop).await {
                    Ok(()) => Ok(GuestExit::Forced),
                    // The force stop is refused for a VM that ended meanwhile.
                    Err(_) if vz_has_ended(live_vz_state(&queue, &vm).await?) => {
                        Ok(GuestExit::Clean)
                    }
                    Err(error) => Err(error),
                }
            },
        )
        .await?;
        if exit == GuestExit::Forced {
            tracing::warn!(%id, "guest did not stop within the grace period; force-stopped the virtual machine");
        }

        // A VM that hit an internal VZ error while stopping is failed, not
        // stopped; everything else that ended is stopped.
        let settled = match live_vz_state(&queue, &vm).await? {
            VZVirtualMachineState::Error => VmState::Failed,
            _ => VmState::Stopped,
        };
        owner.lock().await.info.state = settled;
        Ok(())
    }

    async fn abort_create(&self, id: Uuid) -> Result<(), VmmError> {
        crate::abort_registered_create(self.destroy_vm(id).await)
    }

    async fn destroy_vm(&self, id: Uuid) -> Result<(), VmmError> {
        let _creation = self.creation_locks.lock(id).await;
        // Keep ownership until the force-stop callback AND actual VZ state
        // establish shutdown. Cancellation/error must leave a retryable handle.
        let owner = self.instance(id).await?;
        let mut instance = owner.lock().await;
        if instance.configuration_inflight {
            return Err(VmmError::ProcessError(
                "VZ configuration remains in flight; ownership retained".into(),
            ));
        }
        if instance.vm.is_none() {
            if let Some(capture) = &mut instance.serial_capture {
                capture.finish().await?;
            }
            crate::serial_capture::remove_serial_log(&instance.serial_log_path).await?;
            drop(instance);
            return self.forget_stopped_instance(id, &owner).await;
        }
        let stop = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            dispatch_vz_op(instance.queue.clone(), instance.machine()?, VzOp::Stop),
        )
        .await
        .map_err(|_| VmmError::ProcessError("VZ force-stop not confirmed within 5s".into()))?;
        let vm = instance.machine()?;
        let state = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            dispatch_sync_result(instance.queue.clone(), move || {
                let _capture_whole = &vm;
                unsafe { vm.0.state() }
            }),
        )
        .await
        .map_err(|_| VmmError::ProcessError("VZ stopped-state query timed out".into()))??;
        if state != VZVirtualMachineState::Stopped {
            return Err(stop.err().unwrap_or_else(|| {
                VmmError::ProcessError(format!("VZ remains in state {state:?} after force-stop"))
            }));
        }
        if let Some(capture) = &mut instance.serial_capture {
            capture.finish().await?;
        }
        crate::serial_capture::remove_serial_log(&instance.serial_log_path).await?;
        instance.info.state = VmState::Stopped;
        drop(instance);
        self.forget_stopped_instance(id, &owner).await
    }

    async fn vm_info(&self, id: Uuid) -> Result<VmInfo, VmmError> {
        // For Running/Paused VMs, query the live VZVirtualMachine state on the
        // VM's dispatch queue to detect guest-initiated shutdown (poweroff,
        // reboot, kernel panic). For Stopped/Failed/other states, the stored
        // info is already final and no live query is needed.
        let owner = self.instance(id).await?;
        let (info, maybe_live) = {
            let inst = owner.lock().await;
            let needs_check = matches!(inst.info.state, VmState::Running | VmState::Paused);
            let live = if needs_check {
                Some((inst.machine()?, inst.queue.clone()))
            } else {
                None
            };
            (inst.info.clone(), live)
        };

        let Some((vm, queue)) = maybe_live else {
            return Ok(info);
        };

        let live_state = live_vz_state(&queue, &vm).await?;

        // Map the live VZ state to our VmState. Only act when the live state
        // indicates the guest has stopped; all other transitions (Starting,
        // Pausing, Resuming, Saving, Restoring) are transient and the stored
        // state is the right thing to return.
        let updated_state = match live_state {
            VZVirtualMachineState::Stopped | VZVirtualMachineState::Stopping => {
                Some(VmState::Stopped)
            }
            VZVirtualMachineState::Error => Some(VmState::Failed),
            _ => None,
        };

        let Some(new_state) = updated_state else {
            return Ok(info);
        };

        // Guest has stopped or errored. Update the stored VmInfo so subsequent
        // calls reflect the actual state without re-querying the dispatch queue.
        let mut updated = info;
        updated.state = new_state;
        updated.pid = None;
        {
            let mut inst = owner.lock().await;
            inst.info.state = new_state;
            inst.info.pid = None;
        }
        Ok(updated)
    }

    async fn pause_vm(&self, id: Uuid) -> Result<(), VmmError> {
        let owner = self.instance(id).await?;
        let (vm, queue) = {
            let inst = owner.lock().await;
            (inst.machine()?, inst.queue.clone())
        };

        dispatch_vz_op(queue, vm, VzOp::Pause).await?;

        owner.lock().await.info.state = VmState::Paused;
        Ok(())
    }

    async fn resume_vm(&self, id: Uuid) -> Result<(), VmmError> {
        let owner = self.instance(id).await?;
        let (vm, queue) = {
            let inst = owner.lock().await;
            (inst.machine()?, inst.queue.clone())
        };

        dispatch_vz_op(queue, vm, VzOp::Resume).await?;

        owner.lock().await.info.state = VmState::Running;
        Ok(())
    }

    async fn set_balloon(&self, id: Uuid, amount_mib: u32) -> Result<(), VmmError> {
        let owner = self.instance(id).await?;
        let (vm, queue, balloon_enabled, mem_size_bytes) = {
            let inst = owner.lock().await;
            (
                inst.machine()?,
                inst.queue.clone(),
                inst.balloon,
                inst.mem_size_bytes,
            )
        };
        if !balloon_enabled {
            return Err(VmmError::InvalidConfig(
                "VM was created without a balloon device; rebuild with VmConfig.balloon = true"
                    .into(),
            ));
        }
        let target = balloon_target_bytes(mem_size_bytes, amount_mib)?;
        dispatch_sync_fallible(queue, move || -> Result<(), VmmError> {
            let _capture_whole = &vm;
            // Safety: Called on the VM's serial dispatch queue. memoryBalloonDevices
            // returns a live NSArray valid for the duration of this closure.
            let devices = unsafe { vm.0.memoryBalloonDevices() };
            let device = devices
                .firstObject()
                .ok_or_else(|| VmmError::ProcessError("no balloon device found on VM".into()))?;
            let device = device
                .downcast::<VZVirtioTraditionalMemoryBalloonDevice>()
                .map_err(|_| {
                    VmmError::ProcessError(
                        "balloon device is not a VZVirtioTraditionalMemoryBalloonDevice".into(),
                    )
                })?;
            // Safety: Called on the VM's serial dispatch queue.
            unsafe { device.setTargetVirtualMachineMemorySize(target) };
            Ok(())
        })
        .await
    }

    // snapshot_vm / restore_vm use the VmmBackend trait's default `Unsupported`
    // bodies; Apple VZ has no snapshot support.

    async fn vsock_connect(&self, id: Uuid, port: u32) -> Result<Self::VsockStream, VmmError> {
        use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
        await_vz_operation(
            async {
                let owner = self.instance(id).await?;
                let (vm, queue) = {
                    let inst = owner.lock().await;
                    (inst.machine()?, inst.queue.clone())
                };

                // Connect to the guest vsock port via the VZ socket device.
                // This must execute on the VM's dispatch queue.
                let (tx, rx) = tokio::sync::oneshot::channel::<Result<OwnedFd, VmmError>>();
                let tx = Arc::new(StdMutex::new(Some(tx)));

                tokio::task::spawn_blocking(move || {
                    queue.exec_sync(move || {
                        let _capture_whole = &vm;

                        // Safety: Called on the VM's serial dispatch queue.
                        let socket_devices = unsafe { vm.0.socketDevices() };
                        let socket_device = match socket_devices.firstObject() {
                            Some(dev) => match Retained::downcast::<VZVirtioSocketDevice>(dev) {
                                Ok(dev) => dev,
                                Err(_) => {
                                    if let Some(tx) = tx.lock().ok().and_then(|mut g| g.take()) {
                                        let _ = tx.send(Err(VmmError::ProcessError(
                                            "socket device is not a VZVirtioSocketDevice".into(),
                                        )));
                                    }
                                    return;
                                }
                            },
                            None => {
                                if let Some(tx) = tx.lock().ok().and_then(|mut g| g.take()) {
                                    let _ = tx.send(Err(VmmError::ProcessError(
                                        "no socket devices configured".into(),
                                    )));
                                }
                                return;
                            }
                        };
                        let tx_inner = tx.clone();
                        let handler = RcBlock::new(
                            move |conn: *mut VZVirtioSocketConnection, error: *mut NSError| {
                                let result = if error.is_null() && !conn.is_null() {
                                    // Safety: conn is non-null and points to a valid ObjC object
                                    // from the VZ completion handler.
                                    let raw_fd = unsafe { (*conn).fileDescriptor() };
                                    // Dup the fd NOW while the connection is still alive.
                                    // After this handler returns, VZ may deallocate the
                                    // connection and close raw_fd. The dup'd fd is an
                                    // independent kernel reference that survives deallocation.
                                    let dup_fd = unsafe { libc::dup(raw_fd) };
                                    if dup_fd < 0 {
                                        Err(VmmError::ProcessError(format!(
                                            "failed to dup vsock fd: {}",
                                            std::io::Error::last_os_error()
                                        )))
                                    } else {
                                        Ok(unsafe { OwnedFd::from_raw_fd(dup_fd) })
                                    }
                                } else if !error.is_null() {
                                    // Safety: non-null NSError pointer from VZ completion handler;
                                    // valid for the duration of the callback under ObjC ARC.
                                    let desc = unsafe { (*error).localizedDescription() };
                                    Err(VmmError::ProcessError(format!("vsock connect: {desc}")))
                                } else {
                                    Err(VmmError::ProcessError(
                                        "vsock connect returned null connection".into(),
                                    ))
                                };
                                publish_vsock_result(&tx_inner, result);
                            },
                        );

                        // Safety: Called on the VM's serial dispatch queue. The handler
                        // block is retained by VZ until the connection completes or fails.
                        unsafe {
                            socket_device.connectToPort_completionHandler(port, &handler);
                        }
                    });
                })
                .await
                .map_err(|e| VmmError::ProcessError(format!("dispatch join: {e}")))?;

                let dup_fd = rx.await.map_err(|_| {
                    VmmError::ProcessError("vsock completion channel closed".into())
                })??;

                // Safety: dup_fd is a valid fd that we own — it was dup'd inside the
                // completion handler while the VZ connection was still alive.
                unsafe {
                    FdStream::from_owned_raw_fd(dup_fd.into_raw_fd()).map_err(|e| {
                        VmmError::ProcessError(format!("failed to create async vsock stream: {e}"))
                    })
                }
            },
            "vsock connection",
        )
        .await
    }
}

/// Converts a reclaim amount in MiB into the absolute guest memory target
/// VZVirtioTraditionalMemoryBalloonDevice expects. Matches the QEMU backend's
/// semantics: amount_mib is taken FROM the guest.
fn balloon_target_bytes(mem_size_bytes: u64, amount_mib: u32) -> Result<u64, VmmError> {
    let reclaim = u64::from(amount_mib) * 1024 * 1024;
    if reclaim >= mem_size_bytes {
        return Err(VmmError::InvalidConfig(format!(
            "balloon amount {amount_mib} MiB must be less than VM memory {} MiB",
            mem_size_bytes / (1024 * 1024)
        )));
    }
    Ok(mem_size_bytes - reclaim)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn tracked_fixture(backend: &AppleVzBackend, id: Uuid, name: &str) -> VzOwner {
        let path = backend.runtime_dir.join(format!("{id}-{name}.serial.log"));
        let owner = Arc::new(Mutex::new(VzInstance {
            info: VmInfo {
                id,
                name: name.into(),
                state: VmState::Creating,
                pid: None,
                vcpu_count: 1,
                mem_size_mib: 128,
                vsock_cid: 3,
            },
            queue: DispatchQueue::new(&format!("test.owner.{id}.{name}"), None),
            vm: None,
            configuration_inflight: false,
            serial_log_path: path.clone(),
            _serial_file: Arc::new(std::fs::File::create(path).unwrap()),
            serial_capture: None,
            balloon: false,
            mem_size_bytes: 128 * 1024 * 1024,
        }));
        backend.instances.lock().await.insert(
            id,
            RegisteredVzInstance {
                name: name.into(),
                owner: owner.clone(),
            },
        );
        owner
    }

    #[tokio::test]
    async fn pending_serial_teardown_does_not_block_other_vm_and_cancel_retains_owner() {
        let dir = tempfile::tempdir().unwrap();
        let backend = Arc::new(AppleVzBackend::new(dir.path()));
        let blocked_id = Uuid::new_v4();
        let healthy_id = Uuid::new_v4();
        let blocked = tracked_fixture(&backend, blocked_id, "blocked").await;
        let healthy = tracked_fixture(&backend, healthy_id, "healthy").await;
        let path = blocked.lock().await.serial_log_path.clone();
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (release, gate) = tokio::sync::oneshot::channel();
        blocked.lock().await.serial_capture =
            Some(crate::serial_capture::SerialCapture::pending_shutdown_fixture(entered, gate));
        let cleanup_backend = backend.clone();
        let cleanup = tokio::spawn(async move { cleanup_backend.destroy_vm(blocked_id).await });
        tokio::time::timeout(std::time::Duration::from_secs(2), ready)
            .await
            .unwrap()
            .unwrap();
        // The real destroy path is awaiting its owned serial worker. No VM is created.
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            assert_eq!(
                backend.vm_info(healthy_id).await.unwrap().state,
                VmState::Creating
            );
            let publication = tokio::task::spawn_blocking(move || {
                publish_configuration(
                    &healthy,
                    healthy_id,
                    Err(VmmError::InvalidConfig(
                        "fixture construction failure".into(),
                    )),
                )
            });
            assert!(publication.await.unwrap().is_err());
            assert_eq!(
                backend.vm_info(healthy_id).await.unwrap().state,
                VmState::Failed
            );
            backend.destroy_vm(healthy_id).await.unwrap();
        })
        .await
        .unwrap();
        assert!(path.exists());
        assert!(Arc::ptr_eq(
            &backend.instance(blocked_id).await.unwrap(),
            &blocked
        ));
        cleanup.abort();
        assert!(cleanup.await.unwrap_err().is_cancelled());
        assert!(path.exists());
        assert!(Arc::ptr_eq(
            &backend.instance(blocked_id).await.unwrap(),
            &blocked
        ));
        release.send(()).unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            backend.destroy_vm(blocked_id),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!path.exists());
        assert!(matches!(
            backend.vm_info(blocked_id).await,
            Err(VmmError::VmNotFound(_))
        ));
    }

    #[tokio::test]
    async fn late_publication_and_forget_cannot_mutate_replacement_generation() {
        let dir = tempfile::tempdir().unwrap();
        let backend = AppleVzBackend::new(dir.path());
        let id = Uuid::new_v4();
        let old = tracked_fixture(&backend, id, "old").await;
        let replacement = tracked_fixture(&backend, id, "replacement").await;
        replacement.lock().await.configuration_inflight = true;
        let publication_owner = old.clone();
        assert!(
            tokio::task::spawn_blocking(move || publish_configuration(
                &publication_owner,
                id,
                Err(VmmError::InvalidConfig(
                    "late old-generation failure".into()
                ))
            ))
            .await
            .unwrap()
            .is_err()
        );
        assert_eq!(old.lock().await.info.state, VmState::Failed);
        assert_eq!(backend.vm_info(id).await.unwrap().state, VmState::Creating);
        assert!(replacement.lock().await.configuration_inflight);
        assert!(
            backend
                .forget_stopped_instance(id, &old)
                .await
                .unwrap_err()
                .to_string()
                .contains("generation changed")
        );
        assert!(Arc::ptr_eq(
            &backend.instance(id).await.unwrap(),
            &replacement
        ));
        assert!(replacement.lock().await.serial_log_path.exists());
    }

    #[tokio::test]
    async fn lost_configuration_observer_preserves_owner_and_fd_until_late_completion() {
        use std::os::fd::AsRawFd;
        for cancel in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let backend = AppleVzBackend::new(dir.path());
            let id = Uuid::new_v4();
            let path = dir.path().join(format!("{id}.serial.log"));
            let file = Arc::new(std::fs::File::create(&path).unwrap());
            let queue = DispatchQueue::new("test.pending.configuration", None);
            let owner = Arc::new(Mutex::new(VzInstance {
                info: VmInfo {
                    id,
                    name: "pending".into(),
                    state: VmState::Creating,
                    pid: None,
                    vcpu_count: 1,
                    mem_size_mib: 128,
                    vsock_cid: 3,
                },
                queue: queue.clone(),
                vm: None,
                configuration_inflight: true,
                serial_log_path: path.clone(),
                _serial_file: file.clone(),
                serial_capture: None,
                balloon: false,
                mem_size_bytes: 128 * 1024 * 1024,
            }));
            backend.instances.lock().await.insert(
                id,
                RegisteredVzInstance {
                    name: "pending".into(),
                    owner: owner.clone(),
                },
            );
            let publication_owner = owner.clone();
            let (entered, ready) = tokio::sync::oneshot::channel();
            let (release, gate) = std::sync::mpsc::channel();
            let (completed, completion) = tokio::sync::oneshot::channel();
            let observer = tokio::spawn(async move {
                await_vz_operation(
                    dispatch_sync_fallible(queue, move || {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            entered.send(()).unwrap();
                            gate.recv_timeout(std::time::Duration::from_secs(5))
                                .unwrap();
                            assert_ne!(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) }, -1);
                            publish_configuration(
                                &publication_owner,
                                id,
                                Err(VmmError::InvalidConfig(
                                    "injected native configuration failure".into(),
                                )),
                            )
                        }));
                        let _ = completed.send(result.map_err(|panic| {
                            panic
                                .downcast_ref::<String>()
                                .cloned()
                                .or_else(|| {
                                    panic.downcast_ref::<&str>().map(|text| text.to_string())
                                })
                                .unwrap_or_else(|| "native fixture panic".into())
                        }));
                        Ok(())
                    }),
                    "configuration",
                )
                .await
            });
            ready.await.unwrap();
            if cancel {
                observer.abort();
                assert!(observer.await.unwrap_err().is_cancelled());
            } else {
                tokio::time::pause();
                // Cross the timer wheel's rounding boundary while the native
                // worker is deliberately blocked (auto-advance is inhibited).
                tokio::time::advance(std::time::Duration::from_secs(31)).await;
                assert!(
                    observer
                        .await
                        .unwrap()
                        .unwrap_err()
                        .to_string()
                        .contains("not confirmed within 30s")
                );
                tokio::time::resume();
            }
            assert!(
                backend
                    .destroy_vm(id)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("in flight")
            );
            assert!(path.exists());
            release.send(()).unwrap();
            assert!(
                completion.await.unwrap().is_ok(),
                "native publication panicked"
            );
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                loop {
                    if !owner.lock().await.configuration_inflight {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert_eq!(backend.vm_info(id).await.unwrap().state, VmState::Failed);
            std::fs::remove_file(&path).unwrap();
            std::fs::create_dir(&path).unwrap();
            assert!(backend.destroy_vm(id).await.is_err());
            assert!(backend.instances.lock().await.contains_key(&id));
            std::fs::remove_dir(&path).unwrap();
            // Left by a compaction a crash interrupted.
            let staging = crate::serial_log::compaction_staging_path(&path);
            std::fs::write(&staging, b"").unwrap();
            backend.destroy_vm(id).await.unwrap();
            assert!(!backend.instances.lock().await.contains_key(&id));
            assert!(!staging.exists());
        }
    }

    #[test]
    fn cancelled_vsock_delivery_closes_descriptors_before_and_after_channel_delivery() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;
        for cancelled_before_delivery in [false, true] {
            let (mut peer, connection) = UnixStream::pair().unwrap();
            peer.set_nonblocking(true).unwrap();
            let (sender, receiver) = tokio::sync::oneshot::channel();
            let sender = StdMutex::new(Some(sender));
            let mut receiver = Some(receiver);
            if cancelled_before_delivery {
                drop(receiver.take());
            }
            publish_vsock_result(&sender, Ok(connection.into()));
            drop(receiver);
            assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
        }
    }

    #[test]
    fn new_has_no_instances() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let backend = AppleVzBackend::new(dir.path());
        rt.block_on(async {
            let instances = backend.instances.lock().await;
            assert!(instances.is_empty());
        });
    }

    /// No `--vmm` name maps to Apple VZ, so every explicit backend request is
    /// refused here rather than answered with an Apple VZ VM.
    #[test]
    fn every_vmm_request_is_refused_by_the_apple_backend() {
        use crate::{BackendKind, BackendRequirements, BootKind, VmmKind};

        let dir = tempfile::tempdir().unwrap();
        let backend = AppleVzBackend::new(dir.path());
        let requirements = |requested| BackendRequirements {
            requested,
            boot: BootKind::DirectKernel,
            has_host_shares: false,
        };

        let unrequested = backend.select_backend(requirements(None)).unwrap();
        assert_eq!(unrequested.backend(), BackendKind::AppleVz);
        for requested in VmmKind::ALL {
            let error = backend
                .select_backend(requirements(Some(requested)))
                .unwrap_err();
            let VmmError::InvalidConfig(message) = error else {
                panic!("expected InvalidConfig for {requested}, got {error:?}");
            };
            assert!(
                message.contains(&format!("\"{requested}\"")) && message.contains("apple_vz only"),
                "message must name the request and the running backend: {message}"
            );
        }
    }

    #[tokio::test]
    async fn vm_not_found_errors() {
        let dir = tempfile::tempdir().unwrap();
        let backend = AppleVzBackend::new(dir.path());
        let id = Uuid::new_v4();

        assert!(matches!(
            backend.vm_info(id).await,
            Err(VmmError::VmNotFound(_))
        ));
        assert!(matches!(
            backend.stop_vm(id).await,
            Err(VmmError::VmNotFound(_))
        ));
        assert!(matches!(
            backend.destroy_vm(id).await,
            Err(VmmError::VmNotFound(_))
        ));
        assert!(matches!(
            backend.pause_vm(id).await,
            Err(VmmError::VmNotFound(_))
        ));
        assert!(matches!(
            backend.resume_vm(id).await,
            Err(VmmError::VmNotFound(_))
        ));
        assert!(matches!(
            backend.vsock_connect(id, 52).await,
            Err(VmmError::VmNotFound(_))
        ));
    }

    #[test]
    fn offline_topology_has_no_network_devices_and_nat_keeps_one() {
        assert!(network_devices(true).is_empty());
        assert_eq!(network_devices(false).len(), 1);
    }

    #[tokio::test]
    async fn dispatch_sync_result_returns_value() {
        let queue = DispatchQueue::new("com.husker.test.dispatch", None);
        let result = dispatch_sync_result(queue, || 42).await.unwrap();
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn dispatch_sync_fallible_propagates_error() {
        let queue = DispatchQueue::new("com.husker.test.fallible", None);
        let result: Result<(), VmmError> =
            dispatch_sync_fallible(queue, || Err(VmmError::ProcessError("test error".into())))
                .await;
        assert!(matches!(result, Err(VmmError::ProcessError(ref msg)) if msg == "test error"));
    }

    #[tokio::test]
    async fn dispatch_sync_fallible_returns_ok() {
        let queue = DispatchQueue::new("com.husker.test.fallible-ok", None);
        let result: Result<String, VmmError> =
            dispatch_sync_fallible(queue, || Ok("hello".to_string())).await;
        assert_eq!(result.unwrap(), "hello");
    }

    #[tokio::test]
    async fn dispatch_sync_fallible_propagates_api_error() {
        let queue = DispatchQueue::new("com.husker.test.fallible-api-err", None);
        let result: Result<(), VmmError> =
            dispatch_sync_fallible(queue, || Err(VmmError::ApiError("api failed".into()))).await;
        assert!(matches!(result, Err(VmmError::ApiError(ref msg)) if msg == "api failed"));
    }

    #[test]
    fn new_sets_runtime_dir() {
        let dir = tempfile::tempdir().unwrap();
        let backend = AppleVzBackend::new(dir.path());
        assert_eq!(backend.runtime_dir, dir.path().to_path_buf());
    }

    #[test]
    fn drop_on_empty_backend_is_safe() {
        let dir = tempfile::tempdir().unwrap();
        let backend = AppleVzBackend::new(dir.path());
        drop(backend);
        // No panic = pass
    }

    /// Minimal VmConfig for boot-mode rejection tests. VZ object construction is
    /// not reached when the boot mode is rejected before the dispatch closure.
    fn minimal_config_with_boot(boot: crate::BootMode) -> crate::VmConfig {
        crate::VmConfig {
            requested_id: None,
            name: "test-vm".into(),
            vcpu_count: 1,
            mem_size_mib: 128,
            kernel_path: "/nonexistent/kernel".into(),
            rootfs_path: "/nonexistent/rootfs.img".into(),
            kernel_args: None,
            initrd_path: None,
            vsock_cid: 3,
            tap_device: None,
            guest_mac: None,
            vmm: None,
            boot,
            seed_path: None,
            balloon: false,
            volume_path: None,
            network_disabled: false,
            host_shares: Vec::new(),
        }
    }

    // ── set_balloon ──────────────────────────────────────────────────────
    // The `balloon: false -> InvalidConfig` branch has no dedicated unit test
    // because constructing a VzInstance requires a live VZVirtualMachine, which
    // requires the com.apple.security.virtualization entitlement. Coverage for
    // that branch comes from real-hardware verification.

    #[tokio::test]
    async fn set_balloon_unknown_id_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let backend = AppleVzBackend::new(dir.path());
        let id = Uuid::new_v4();
        let err = backend.set_balloon(id, 64).await.unwrap_err();
        assert!(
            matches!(err, VmmError::VmNotFound(_)),
            "expected VmNotFound, got: {err:?}"
        );
    }

    // ── balloon_target_bytes ─────────────────────────────────────────────

    #[test]
    fn balloon_target_bytes_normal_case() {
        let target = balloon_target_bytes(1024 * 1024 * 1024, 256).unwrap();
        assert_eq!(target, 768 * 1024 * 1024);
    }

    #[test]
    fn balloon_target_bytes_zero_reclaim_is_full_memory() {
        let target = balloon_target_bytes(1024 * 1024 * 1024, 0).unwrap();
        assert_eq!(target, 1024 * 1024 * 1024);
    }

    #[test]
    fn balloon_target_bytes_equal_to_mem_is_invalid() {
        assert!(balloon_target_bytes(1024 * 1024 * 1024, 1024).is_err());
    }

    #[test]
    fn balloon_target_bytes_exceeding_mem_is_invalid() {
        assert!(balloon_target_bytes(1024 * 1024 * 1024, 2048).is_err());
    }

    /// `BootMode::Uefi` is rejected before any VZ framework call is made.
    /// The check happens in `create_vm` before entering the dispatch
    /// closure, so no Virtualization entitlement is required to run this test.
    #[tokio::test]
    async fn uefi_boot_mode_is_rejected_with_invalid_config() {
        let dir = tempfile::tempdir().unwrap();
        let backend = AppleVzBackend::new(dir.path());
        let config = minimal_config_with_boot(crate::BootMode::Uefi {
            ovmf_code: "/nonexistent/OVMF_CODE.fd".into(),
            ovmf_vars_template: "/nonexistent/OVMF_VARS.fd".into(),
        });
        let result = backend
            .create_vm(backend.select_backend_for_config(&config).unwrap(), config)
            .await;
        assert!(
            matches!(&result, Err(VmmError::InvalidConfig(msg)) if msg.contains("OVMF boot")),
            "expected InvalidConfig with OVMF hint, got {result:?}"
        );
    }

    /// A host share is refused before the serial log or any VZ object exists:
    /// the backend has no virtiofs device, and a VM without the share the
    /// caller asked for must not come up.
    #[tokio::test]
    async fn host_shares_are_rejected_before_any_vz_call() {
        let dir = tempfile::tempdir().unwrap();
        let backend = AppleVzBackend::new(dir.path());
        let mut config = minimal_config_with_boot(crate::BootMode::DirectKernel);
        config.host_shares = vec![crate::HostShare {
            host: "/srv/work".into(),
            guest: "/work".into(),
            read_only: false,
            tag: "fs0".into(),
        }];
        let result = backend
            .create_vm(backend.select_backend_for_config(&config).unwrap(), config)
            .await;
        assert!(
            matches!(&result, Err(VmmError::Unsupported(msg)) if msg.contains("--mount")),
            "expected Unsupported naming --mount, got {result:?}"
        );
        assert!(
            std::fs::read_dir(dir.path()).unwrap().next().is_none(),
            "a refused VM must leave no runtime file behind"
        );
    }
}
