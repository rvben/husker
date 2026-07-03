//! Error envelope and `CoreError` -> HTTP status/code mapping for the husker HTTP API.

use axum::Json;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use husker_core::CoreError;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    /// Stable snake_case error identifier consumers branch on. Named `kind` to
    /// match the clispec CLI contract (`husker schema`) and the CLI's error
    /// envelope, so every husker surface uses the same identifier field.
    pub kind: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    // Backward-compatible alias kept for existing clients/tests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub(crate) fn error_response(kind: &str, message: impl Into<String>) -> Json<ErrorResponse> {
    let message = message.into();
    Json(ErrorResponse {
        kind: kind.to_string(),
        message: message.clone(),
        hint: None,
        details: None,
        error: Some(message),
    })
}

pub(crate) fn error_response_with_hint(
    kind: &str,
    message: impl Into<String>,
    hint: impl Into<String>,
) -> Json<ErrorResponse> {
    let message = message.into();
    Json(ErrorResponse {
        kind: kind.to_string(),
        message: message.clone(),
        hint: Some(hint.into()),
        details: None,
        error: Some(message),
    })
}

pub(crate) fn map_error(err: CoreError) -> (StatusCode, Json<ErrorResponse>) {
    let (status, kind, message) = match &err {
        CoreError::VmNotFound(_) => (StatusCode::NOT_FOUND, "vm_not_found", err.to_string()),
        CoreError::HostGroupNotFound(_) => (
            StatusCode::NOT_FOUND,
            "host_group_not_found",
            err.to_string(),
        ),
        CoreError::ServiceNotFound(_) => {
            (StatusCode::NOT_FOUND, "service_not_found", err.to_string())
        }
        CoreError::PoolNotFound(_) => (StatusCode::NOT_FOUND, "pool_not_found", err.to_string()),
        CoreError::ImageNotFound(_) => (StatusCode::NOT_FOUND, "image_not_found", err.to_string()),
        CoreError::SecretNotFound(_) => {
            (StatusCode::NOT_FOUND, "secret_not_found", err.to_string())
        }
        CoreError::SnapshotNotFound(_) => {
            (StatusCode::NOT_FOUND, "snapshot_not_found", err.to_string())
        }
        CoreError::InvalidState { .. } => (StatusCode::CONFLICT, "invalid_state", err.to_string()),
        CoreError::InvalidArgument(_) => {
            (StatusCode::BAD_REQUEST, "invalid_argument", err.to_string())
        }
        CoreError::PortForwardConflict(_) => (StatusCode::CONFLICT, "port_in_use", err.to_string()),
        CoreError::PortForwardDenied(_) => (StatusCode::FORBIDDEN, "denied", err.to_string()),
        CoreError::ServiceOperationFailed(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "service_operation_failed",
            err.to_string(),
        ),
        CoreError::VmAlreadyExists(_) => {
            (StatusCode::CONFLICT, "vm_already_exists", err.to_string())
        }
        CoreError::HostGroupAlreadyExists(_) => (
            StatusCode::CONFLICT,
            "host_group_already_exists",
            err.to_string(),
        ),
        CoreError::ServiceAlreadyExists(_) => (
            StatusCode::CONFLICT,
            "service_already_exists",
            err.to_string(),
        ),
        CoreError::PoolAlreadyExists(_) => {
            (StatusCode::CONFLICT, "pool_already_exists", err.to_string())
        }
        CoreError::ImageAlreadyExists(_) => (
            StatusCode::CONFLICT,
            "image_already_exists",
            err.to_string(),
        ),
        CoreError::VolumeNotFound(_) => {
            (StatusCode::NOT_FOUND, "volume_not_found", err.to_string())
        }
        CoreError::VolumeAlreadyExists(_) => (
            StatusCode::CONFLICT,
            "volume_already_exists",
            err.to_string(),
        ),
        CoreError::VolumeAttached { .. } => {
            (StatusCode::CONFLICT, "volume_attached", err.to_string())
        }
        CoreError::SecretAlreadyExists(_) => (
            StatusCode::CONFLICT,
            "secret_already_exists",
            err.to_string(),
        ),
        CoreError::SnapshotAlreadyExists(_) => (
            StatusCode::CONFLICT,
            "snapshot_already_exists",
            err.to_string(),
        ),
        CoreError::SecretCrypto(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "secret_crypto_error",
            err.to_string(),
        ),
        CoreError::Agent(husker_core::AgentError::NotReady { .. }) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "agent_not_ready",
            err.to_string(),
        ),
        CoreError::Io(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "io_error",
            err.to_string(),
        ),
        CoreError::Storage(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            err.to_string(),
        ),
        CoreError::State(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "state_error",
            err.to_string(),
        ),
        CoreError::Vmm(husker_vmm::VmmError::Unsupported(_)) => {
            (StatusCode::NOT_IMPLEMENTED, "unsupported", err.to_string())
        }
        CoreError::Vmm(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "vmm_error",
            err.to_string(),
        ),
        #[cfg(feature = "linux-net")]
        CoreError::Network(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "network_error",
            err.to_string(),
        ),
        CoreError::CloudInit(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "cloud_init_error",
            err.to_string(),
        ),
        CoreError::Agent(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "agent_error",
            err.to_string(),
        ),
    };
    (status, error_response(kind, message))
}

pub(crate) fn map_agent_connect_error(err: CoreError) -> (StatusCode, Json<ErrorResponse>) {
    match err {
        CoreError::Vmm(husker_vmm::VmmError::VmNotFound(_))
        | CoreError::Vmm(husker_vmm::VmmError::ProcessError(_))
        | CoreError::Vmm(husker_vmm::VmmError::ApiError(_))
        | CoreError::Agent(husker_core::AgentError::Connection(_))
        | CoreError::Agent(husker_core::AgentError::VsockConnectRejected(_))
        | CoreError::Agent(husker_core::AgentError::NotReady { .. }) => (
            StatusCode::SERVICE_UNAVAILABLE,
            error_response_with_hint(
                "agent_not_ready",
                format!("agent not ready: {err}"),
                "retry after the VM boot sequence has completed",
            ),
        ),
        other => map_error(other),
    }
}
