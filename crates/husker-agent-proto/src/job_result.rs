//! Bounded guest evidence contract. A successful runner process is insufficient:
//! hosts must authenticate inputs, validate this manifest, and export artifacts.
use crate::job_spec::{JobBundle, JobSpec, JobSpecError, PreparedJobImage};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_JOB_MANIFEST_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobOutcome {
    Completed,
    CommandFailed,
    InfrastructureFailed,
    Cancelled,
    TimedOut,
    Interrupted,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobCollectionStatus {
    Complete,
    Truncated,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobCommandResult {
    pub command_index: usize,
    pub exit_code: Option<i32>,
    pub outcome: JobOutcome,
    pub duration_ms: u64,
    pub output: String,
    pub output_truncated: bool,
    pub logs_truncated: bool,
    pub termination_confirmed: bool,
    pub termination_error: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobArtifactResult {
    pub path: String,
    pub stored_name: Option<String>,
    pub digest: Option<String>,
    pub size_bytes: Option<u64>,
    pub error: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestJobManifest {
    pub version: u32,
    pub job_id: Uuid,
    pub execution_specification_digest: String,
    pub image: PreparedJobImage,
    pub source: JobBundle,
    pub acceptance: JobBundle,
    pub commands: Vec<JobCommandResult>,
    pub artifacts: Vec<JobArtifactResult>,
    pub source_changed: Option<bool>,
    pub source_verification_error: Option<String>,
    pub collection_status: JobCollectionStatus,
    pub outcome: JobOutcome,
}
impl GuestJobManifest {
    pub fn decode_for(bytes: &[u8], spec: &JobSpec, job_id: Uuid) -> Result<Self, JobSpecError> {
        if bytes.len() > MAX_JOB_MANIFEST_BYTES {
            return Err(JobSpecError("manifest exceeds 64 KiB"));
        }
        let result: Self =
            serde_json::from_slice(bytes).map_err(|_| JobSpecError("invalid guest manifest"))?;
        if result.version != 1
            || result.job_id != job_id
            || result.execution_specification_digest != spec.digest()?
            || result.image != spec.image
            || result.source != spec.source
            || result.acceptance != spec.acceptance
        {
            return Err(JobSpecError("guest result identity mismatch"));
        }
        if result.commands.is_empty() || result.commands.len() > spec.commands.len() {
            return Err(JobSpecError("invalid command result count"));
        }
        for (index, command) in result.commands.iter().enumerate() {
            if command.command_index != index || command.output.len() > 2048 {
                return Err(JobSpecError("invalid command result index or output bound"));
            }
            if command
                .termination_error
                .as_ref()
                .is_some_and(|error| error.len() > 2048)
                || (command.termination_confirmed && command.termination_error.is_some())
            {
                return Err(JobSpecError("inconsistent termination evidence"));
            }
            if command.outcome == JobOutcome::Completed
                && (command.exit_code != Some(0) || !command.termination_confirmed)
            {
                return Err(JobSpecError(
                    "completed command lacks successful confirmed termination",
                ));
            }
            if command.outcome == JobOutcome::CommandFailed
                && (command.exit_code.is_none_or(|code| code == 0)
                    || !command.termination_confirmed)
            {
                return Err(JobSpecError("command failure lacks confirmed nonzero exit"));
            }
        }
        if result.artifacts.len() != spec.artifacts.len() {
            return Err(JobSpecError("artifact declarations missing from result"));
        }
        for (index, (artifact, declaration)) in
            result.artifacts.iter().zip(&spec.artifacts).enumerate()
        {
            if artifact.path != declaration.path
                || artifact
                    .error
                    .as_ref()
                    .is_some_and(|error| error.len() > 2048)
            {
                return Err(JobSpecError("invalid artifact declaration or error bound"));
            }
            match &artifact.error {
                Some(_)
                    if artifact.digest.is_none()
                        && artifact.stored_name.is_none()
                        && artifact.size_bytes.is_none() => {}
                None if artifact.stored_name.as_deref()
                    == Some(format!("{index}.bin").as_str())
                    && artifact
                        .size_bytes
                        .is_some_and(|size| size <= declaration.max_bytes)
                    && artifact
                        .digest
                        .as_deref()
                        .is_some_and(super::job_spec::digest_valid) => {}
                _ => return Err(JobSpecError("inconsistent artifact receipt")),
            }
        }
        if result
            .source_verification_error
            .as_ref()
            .is_some_and(|error| error.len() > 2048)
        {
            return Err(JobSpecError("source verification error exceeds bound"));
        }
        if result.outcome == JobOutcome::Completed
            && (result.commands.len() != spec.commands.len()
                || result
                    .commands
                    .iter()
                    .any(|command| command.outcome != JobOutcome::Completed)
                || result.source_changed != Some(false)
                || result.source_verification_error.is_some()
                || result.collection_status == JobCollectionStatus::Failed
                || result
                    .artifacts
                    .iter()
                    .any(|artifact| artifact.error.is_some()))
        {
            return Err(JobSpecError(
                "completed result lacks successful execution and collection evidence",
            ));
        }
        // This validates receipts only. The host must still retrieve each file,
        // enforce total limits, compare its hash/size, and persist before cleanup.
        Ok(result)
    }
}
