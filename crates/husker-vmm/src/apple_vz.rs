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
    VZVirtioBlockDeviceConfiguration, VZVirtioConsoleDeviceSerialPortConfiguration,
    VZVirtioNetworkDeviceConfiguration, VZVirtioSocketConnection, VZVirtioSocketDevice,
    VZVirtioSocketDeviceConfiguration, VZVirtioTraditionalMemoryBalloonDevice,
    VZVirtioTraditionalMemoryBalloonDeviceConfiguration, VZVirtualMachine,
    VZVirtualMachineConfiguration, VZVirtualMachineState,
};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::fd_stream::FdStream;
use crate::{
    RestoreTarget, SnapshotMeta, SnapshotPaths, VmConfig, VmInfo, VmState, VmmBackend, VmmError,
};

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
struct QueueConfined<T>(T);

// Safety: Values are only accessed from their associated serial dispatch queue,
// satisfying VZVirtualMachine's queue-affinity requirement. Cross-thread moves
// happen only via dispatch queue submission, not direct access.
unsafe impl<T> Send for QueueConfined<T> {}
unsafe impl<T> Sync for QueueConfined<T> {}

/// Vsock stream type alias for Apple VZ.
///
/// `FdStream::from_dup_raw_fd()` creates an independent fd via `dup(2)`.
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
    vm: QueueConfined<Retained<VZVirtualMachine>>,
    serial_log_path: PathBuf,
    /// Kept alive so the file descriptor remains valid for the VZ serial attachment.
    _serial_file: std::fs::File,
    /// Whether a virtio memory balloon device was attached at create time.
    balloon: bool,
    /// Guest memory size in bytes, used to compute the absolute balloon target.
    mem_size_bytes: u64,
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
    instances: Arc<Mutex<HashMap<Uuid, VzInstance>>>,
}

impl AppleVzBackend {
    pub fn new(runtime_dir: impl Into<PathBuf>) -> Self {
        Self {
            runtime_dir: runtime_dir.into(),
            instances: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Configure, validate, and start a VZ virtual machine.
    ///
    /// Separated from `create_vm` so the caller can clean up the serial log
    /// file on any failure (config, validation, or start).
    async fn create_and_start_vm(
        &self,
        config: VmConfig,
        queue: DispatchRetained<DispatchQueue>,
        serial_write_fd: i32,
    ) -> Result<
        (
            QueueConfined<Retained<VZVirtualMachine>>,
            DispatchRetained<DispatchQueue>,
        ),
        VmmError,
    > {
        if matches!(config.boot, crate::BootMode::Uefi { .. }) {
            return Err(VmmError::InvalidConfig(
                "OVMF boot is a Linux/QEMU mode; macOS uses EFI boot".into(),
            ));
        }
        let mem_size_bytes = u64::from(config.mem_size_mib) * 1024 * 1024;
        let vm = dispatch_sync_fallible(queue.clone(), {
            let config = config.clone();
            let queue_for_vm = queue.clone();
            // Safety: All VZ API calls in this closure execute on the VM's dedicated
            // serial dispatch queue via `dispatch_sync_fallible`. The objc2 bindings
            // are `unsafe` because they call into Objective-C; the VZ framework
            // guarantees thread-safety when called from the correct queue.
            move || -> Result<QueueConfined<Retained<VZVirtualMachine>>, VmmError> {
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

                // Network (NAT — VZ handles it internally)
                let nat = unsafe { VZNATNetworkDeviceAttachment::new() };
                let net_device = unsafe { VZVirtioNetworkDeviceConfiguration::new() };
                unsafe { net_device.setAttachment(Some(&*nat)) };
                let net_config = net_device.into_super();
                unsafe {
                    vz_config
                        .setNetworkDevices(&NSArray::from_retained_slice(&[net_config]));
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

                // Platform (required for Linux on ARM64)
                let platform = unsafe { VZGenericPlatformConfiguration::new() };
                unsafe {
                    vz_config.setPlatform(&platform);
                }

                // Serial console (hvc0 — virtio console)
                // Attach output to a log file for `husker logs`. No input needed (None).
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
            }
        })
        .await?;

        // Start the VM
        let vm_inner = vm.0.clone();
        dispatch_vz_op(queue.clone(), QueueConfined(vm_inner), VzOp::Start).await?;

        Ok((vm, queue))
    }
}

impl Drop for AppleVzBackend {
    fn drop(&mut self) {
        // Best-effort cleanup: request each VM to stop.
        // Uses try_lock to avoid blocking if the mutex is held elsewhere during
        // teardown. The actual VZVirtualMachine deallocation is handled by ObjC
        // ARC when the Retained<VZVirtualMachine> refcount drops to zero.
        if let Ok(mut instances) = self.instances.try_lock() {
            for (_, instance) in instances.drain() {
                let vm = instance.vm;
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

// ── Dispatch helpers ────────────────────────────────────────────────────

/// Run a closure on a dispatch queue from async context and return its result.
///
/// Uses a oneshot channel to transfer the result from the dispatch queue thread
/// back to the async caller, avoiding any mutex unwrap.
async fn dispatch_sync_result<T: Send + 'static>(
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
async fn dispatch_sync_fallible<T: Send + 'static>(
    queue: DispatchRetained<DispatchQueue>,
    f: impl FnOnce() -> Result<T, VmmError> + Send + 'static,
) -> Result<T, VmmError> {
    dispatch_sync_result(queue, f).await?
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
                if let Some(tx) = tx_inner.lock().ok().and_then(|mut g| g.take()) {
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

    async fn create_vm(&self, config: VmConfig) -> Result<VmInfo, VmmError> {
        {
            let instances = self.instances.lock().await;
            if instances.values().any(|i| i.info.name == config.name) {
                return Err(VmmError::VmAlreadyExists(config.name));
            }
        }

        let id = Uuid::new_v4();
        let queue = DispatchQueue::new(&format!("com.husker.vm.{id}"), None);

        // Capture serial console output to a file for `husker logs`.
        let serial_log_path = self.runtime_dir.join(format!("{id}.serial.log"));
        let serial_file = std::fs::File::create(&serial_log_path)
            .map_err(|e| VmmError::ProcessError(format!("create serial log: {e}")))?;
        let serial_write_fd = {
            use std::os::unix::io::AsRawFd;
            serial_file.as_raw_fd()
        };

        // Create and start the VM, cleaning up the serial log on any failure.
        let (vm, queue) = match self
            .create_and_start_vm(config.clone(), queue, serial_write_fd)
            .await
        {
            Ok(pair) => pair,
            Err(e) => {
                let _ = std::fs::remove_file(&serial_log_path);
                return Err(e);
            }
        };

        let mem_size_bytes = u64::from(config.mem_size_mib) * 1024 * 1024;
        let info = VmInfo {
            id,
            name: config.name,
            state: VmState::Running,
            pid: None,
            vcpu_count: config.vcpu_count,
            mem_size_mib: config.mem_size_mib,
            vsock_cid: config.vsock_cid,
        };

        self.instances.lock().await.insert(
            id,
            VzInstance {
                info: info.clone(),
                queue,
                vm,
                serial_log_path,
                _serial_file: serial_file,
                balloon: config.balloon,
                mem_size_bytes,
            },
        );

        Ok(info)
    }

    /// Best-effort, asynchronous shutdown: requests a guest stop and marks the VM
    /// `Stopped`, but the VZVirtualMachine may still be winding down. Callers must
    /// not assume it has exited (mirrors the QEMU and Firecracker backends;
    /// `destroy_vm` force-stops).
    async fn stop_vm(&self, id: Uuid) -> Result<(), VmmError> {
        let (vm, queue) = {
            let instances = self.instances.lock().await;
            let inst = instances.get(&id).ok_or(VmmError::VmNotFound(id))?;
            (QueueConfined(inst.vm.0.clone()), inst.queue.clone())
        };

        // Send ACPI power button (graceful shutdown)
        dispatch_sync_fallible(queue, move || -> Result<(), VmmError> {
            let _capture_whole = &vm;
            // Safety: Called on the VM's serial dispatch queue via dispatch_sync_fallible.
            unsafe {
                vm.0.requestStopWithError()
                    .map_err(|e| VmmError::ApiError(format!("requestStop: {e}")))
            }
        })
        .await?;

        let mut instances = self.instances.lock().await;
        if let Some(inst) = instances.get_mut(&id) {
            inst.info.state = VmState::Stopped;
        }
        Ok(())
    }

    async fn destroy_vm(&self, id: Uuid) -> Result<(), VmmError> {
        let instance = {
            let mut instances = self.instances.lock().await;
            instances.remove(&id).ok_or(VmmError::VmNotFound(id))?
        };

        // Force stop — best-effort, ignore errors (VM may already be stopped)
        let _ = dispatch_vz_op(instance.queue, instance.vm, VzOp::Stop).await;
        let _ = tokio::fs::remove_file(&instance.serial_log_path).await;
        Ok(())
    }

    async fn vm_info(&self, id: Uuid) -> Result<VmInfo, VmmError> {
        // For Running/Paused VMs, query the live VZVirtualMachine state on the
        // VM's dispatch queue to detect guest-initiated shutdown (poweroff,
        // reboot, kernel panic). For Stopped/Failed/other states, the stored
        // info is already final and no live query is needed.
        let (info, maybe_live) = {
            let instances = self.instances.lock().await;
            let inst = instances.get(&id).ok_or(VmmError::VmNotFound(id))?;
            let needs_check = matches!(inst.info.state, VmState::Running | VmState::Paused);
            let live = if needs_check {
                Some((QueueConfined(inst.vm.0.clone()), inst.queue.clone()))
            } else {
                None
            };
            (inst.info.clone(), live)
        };

        let Some((vm, queue)) = maybe_live else {
            return Ok(info);
        };

        let live_state = dispatch_sync_result(queue, move || -> VZVirtualMachineState {
            let _capture_whole = &vm;
            // Safety: Called on the VM's serial dispatch queue.
            unsafe { vm.0.state() }
        })
        .await?;

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
            let mut instances = self.instances.lock().await;
            if let Some(inst) = instances.get_mut(&id) {
                inst.info.state = new_state;
                inst.info.pid = None;
            }
        }
        Ok(updated)
    }

    async fn pause_vm(&self, id: Uuid) -> Result<(), VmmError> {
        let (vm, queue) = {
            let instances = self.instances.lock().await;
            let inst = instances.get(&id).ok_or(VmmError::VmNotFound(id))?;
            (QueueConfined(inst.vm.0.clone()), inst.queue.clone())
        };

        dispatch_vz_op(queue, vm, VzOp::Pause).await?;

        let mut instances = self.instances.lock().await;
        if let Some(inst) = instances.get_mut(&id) {
            inst.info.state = VmState::Paused;
        }
        Ok(())
    }

    async fn resume_vm(&self, id: Uuid) -> Result<(), VmmError> {
        let (vm, queue) = {
            let instances = self.instances.lock().await;
            let inst = instances.get(&id).ok_or(VmmError::VmNotFound(id))?;
            (QueueConfined(inst.vm.0.clone()), inst.queue.clone())
        };

        dispatch_vz_op(queue, vm, VzOp::Resume).await?;

        let mut instances = self.instances.lock().await;
        if let Some(inst) = instances.get_mut(&id) {
            inst.info.state = VmState::Running;
        }
        Ok(())
    }

    async fn set_balloon(&self, id: Uuid, amount_mib: u32) -> Result<(), VmmError> {
        let (vm, queue, balloon_enabled, mem_size_bytes) = {
            let instances = self.instances.lock().await;
            let inst = instances.get(&id).ok_or(VmmError::VmNotFound(id))?;
            (
                QueueConfined(inst.vm.0.clone()),
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

    async fn snapshot_vm(&self, _id: Uuid, _dst: &SnapshotPaths) -> Result<SnapshotMeta, VmmError> {
        Err(VmmError::Unsupported(
            "snapshot_vm not supported by this backend".into(),
        ))
    }

    async fn restore_vm(
        &self,
        _src: &SnapshotPaths,
        _target: RestoreTarget,
    ) -> Result<VmInfo, VmmError> {
        Err(VmmError::Unsupported(
            "restore_vm not supported by this backend".into(),
        ))
    }

    async fn vsock_connect(&self, id: Uuid, port: u32) -> Result<Self::VsockStream, VmmError> {
        let (vm, queue) = {
            let instances = self.instances.lock().await;
            let inst = instances.get(&id).ok_or(VmmError::VmNotFound(id))?;
            (QueueConfined(inst.vm.0.clone()), inst.queue.clone())
        };

        // Connect to the guest vsock port via the VZ socket device.
        // This must execute on the VM's dispatch queue.
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<i32, VmmError>>();
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
                                Ok(dup_fd)
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
                        if let Some(tx) = tx_inner.lock().ok().and_then(|mut g| g.take()) {
                            let _ = tx.send(result);
                        }
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

        let dup_fd = rx
            .await
            .map_err(|_| VmmError::ProcessError("vsock completion channel closed".into()))??;

        // Safety: dup_fd is a valid fd that we own — it was dup'd inside the
        // completion handler while the VZ connection was still alive.
        unsafe {
            FdStream::from_owned_raw_fd(dup_fd).map_err(|e| {
                VmmError::ProcessError(format!("failed to create async vsock stream: {e}"))
            })
        }
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
    /// The check happens in `create_and_start_vm` before entering the dispatch
    /// closure, so no Virtualization entitlement is required to run this test.
    #[tokio::test]
    async fn uefi_boot_mode_is_rejected_with_invalid_config() {
        let dir = tempfile::tempdir().unwrap();
        let backend = AppleVzBackend::new(dir.path());
        let config = minimal_config_with_boot(crate::BootMode::Uefi {
            ovmf_code: "/nonexistent/OVMF_CODE.fd".into(),
            ovmf_vars_template: "/nonexistent/OVMF_VARS.fd".into(),
        });
        let result = backend.create_vm(config).await;
        assert!(
            matches!(&result, Err(VmmError::InvalidConfig(msg)) if msg.contains("OVMF boot")),
            "expected InvalidConfig with OVMF hint, got {result:?}"
        );
    }
}
