//! VMM abstraction and backend-neutral types for Firecracker and Apple VZ.

pub mod firecracker;
pub mod vsock;

#[cfg(unix)]
pub mod fd_stream;

#[cfg(target_os = "macos")]
pub mod apple_vz;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

/// Configuration for creating a new VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    pub name: String,
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub kernel_args: Option<String>,
    pub initrd_path: Option<PathBuf>,
    pub vsock_cid: u32,
    pub tap_device: Option<String>,
    pub guest_mac: Option<String>,
}

/// Runtime information about a VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmInfo {
    pub id: Uuid,
    pub name: String,
    pub state: VmState,
    pub pid: Option<u32>,
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    pub vsock_cid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VmState {
    Creating,
    Running,
    Paused,
    Stopped,
    Failed,
}

impl std::fmt::Display for VmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmState::Creating => write!(f, "creating"),
            VmState::Running => write!(f, "running"),
            VmState::Paused => write!(f, "paused"),
            VmState::Stopped => write!(f, "stopped"),
            VmState::Failed => write!(f, "failed"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VmmError {
    #[error("VM not found: {0}")]
    VmNotFound(Uuid),
    #[error("VM already exists: {0}")]
    VmAlreadyExists(String),
    #[error("VMM process error: {0}")]
    ProcessError(String),
    #[error("API error: {0}")]
    ApiError(String),
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Trait abstracting over different VMM implementations.
///
/// Each backend (Firecracker, Apple VZ) implements this trait.
/// Uses desugared async methods with `Send` bounds for compatibility with
/// multi-threaded runtimes. Implementations can use `async fn` syntax.
pub trait VmmBackend: Send + Sync {
    /// The stream type returned by vsock connections.
    type VsockStream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Create and boot a new VM with the given configuration.
    fn create_vm(
        &self,
        config: VmConfig,
    ) -> impl std::future::Future<Output = Result<VmInfo, VmmError>> + Send;

    /// Stop a running VM gracefully.
    fn stop_vm(&self, id: Uuid) -> impl std::future::Future<Output = Result<(), VmmError>> + Send;

    /// Force-kill a VM.
    fn destroy_vm(
        &self,
        id: Uuid,
    ) -> impl std::future::Future<Output = Result<(), VmmError>> + Send;

    /// Get information about a VM.
    fn vm_info(
        &self,
        id: Uuid,
    ) -> impl std::future::Future<Output = Result<VmInfo, VmmError>> + Send;

    /// Pause a running VM (if supported).
    fn pause_vm(&self, id: Uuid) -> impl std::future::Future<Output = Result<(), VmmError>> + Send;

    /// Resume a paused VM (if supported).
    fn resume_vm(&self, id: Uuid)
    -> impl std::future::Future<Output = Result<(), VmmError>> + Send;

    /// Connect to a VM's vsock at the given port.
    ///
    /// Returns an async stream that can be used for bidirectional communication
    /// with the guest. The connection method is backend-specific:
    /// - Firecracker: UDS proxy with CONNECT handshake
    /// - Apple VZ: VZVirtioSocketDevice connectToPort
    fn vsock_connect(
        &self,
        id: Uuid,
        port: u32,
    ) -> impl std::future::Future<Output = Result<Self::VsockStream, VmmError>> + Send;
}
