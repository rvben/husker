//! Bounded staging and one-time guest submission. Running reconnects only query.
use crate::agent_client::{AgentConnection, AgentError};
use husker_agent_proto::frozen_bundle::FrozenBundle;
use husker_agent_proto::job_spec::JobSpec;
use husker_agent_proto::{ExecRequest, SessionInfo, SessionStartRequest};
use husker_state::StateStore;
use husker_state::jobs::{JobRecord, JobState, JournalError};
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

const RUNNER: &str = "/usr/local/bin/husker-job-runner";
const CHUNK: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum JobLaunchError {
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Agent(#[from] AgentError),
    #[error("job launch refused: {0}")]
    Invalid(String),
    #[error("job deadline expired during staging or submission")]
    Deadline,
}
pub(crate) fn remaining_deadline(deadline: i64) -> std::time::Duration {
    chrono::DateTime::from_timestamp(deadline, 0)
        .and_then(|deadline| (deadline - chrono::Utc::now()).to_std().ok())
        .unwrap_or_default()
}

fn invalid(message: impl Into<String>) -> JobLaunchError {
    JobLaunchError::Invalid(message.into())
}

fn validated_spec(
    job: &JobRecord,
    source: &FrozenBundle,
    acceptance: &FrozenBundle,
) -> Result<JobSpec, JobLaunchError> {
    let spec: JobSpec =
        serde_json::from_str(&job.specification).map_err(|error| invalid(error.to_string()))?;
    if spec
        .canonical_json()
        .map_err(|error| invalid(error.to_string()))?
        != job.specification
        || spec.deadline.timestamp() != job.deadline
        || spec.digest().map_err(|error| invalid(error.to_string()))? != job.specification_digest
        || source.digest() != spec.source.digest
        || source.bytes().len() as u64 != spec.source.size_bytes
        || acceptance.digest() != spec.acceptance.digest
        || acceptance.bytes().len() as u64 != spec.acceptance.size_bytes
    {
        return Err(invalid("frozen specification or bundle identity mismatch"));
    }
    for directory in &spec.writable_directories {
        if source.files().keys().any(|path| {
            path == directory
                || path.starts_with(&format!("{directory}/"))
                || directory.starts_with(&format!("{path}/"))
        }) {
            return Err(invalid("build/output directory overlaps frozen source"));
        }
    }
    Ok(spec)
}

fn session_request(job: &JobRecord) -> Result<SessionStartRequest, JobLaunchError> {
    let timeout = u64::try_from(job.deadline - job.created_at)
        .map_err(|_| invalid("invalid job lifetime"))?;
    Ok(SessionStartRequest {
        id: job.session_id.to_string(),
        exec: ExecRequest {
            command: RUNNER.into(),
            args: vec![job.id.to_string(), job.specification_digest.clone()],
            working_dir: Some("/".into()),
            env: vec![],
            timeout_secs: Some(timeout),
        },
    })
}

async fn upload<S: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut AgentConnection<S>,
    path: &str,
    bytes: &[u8],
) -> Result<(), JobLaunchError> {
    for (index, chunk) in bytes.chunks(CHUNK).enumerate() {
        let written = connection
            .write_file(path, chunk, Some(0o600), index > 0)
            .await?;
        if written != chunk.len() as u64 {
            return Err(invalid("guest acknowledged an incomplete input chunk"));
        }
    }
    Ok(())
}

/// The caller must fence the connected VM's immutable UUID and serialize this
/// operation with allocation/cleanup. The core wrapper below does both. After
/// Running is persisted, errors leave it pending/unknown for session observation,
/// continuous capture and VM fallback; they never authorize a fresh start.
pub async fn stage_and_launch_job<S: AsyncRead + AsyncWrite + Unpin>(
    store: &StateStore,
    id: Uuid,
    connection: &mut AgentConnection<S>,
    source: &FrozenBundle,
    acceptance: &FrozenBundle,
) -> Result<SessionInfo, JobLaunchError> {
    let job = store.get_job(id)?;
    validated_spec(&job, source, acceptance)?;
    if job.vm_id.is_none()
        || job.vm_destroyed
        || !matches!(job.state, JobState::Preparing | JobState::Running)
    {
        return Err(invalid(
            "job is not attached to an executable VM generation",
        ));
    }
    let remaining = remaining_deadline(job.deadline);
    if remaining.is_zero() {
        return Err(JobLaunchError::Deadline);
    }
    let result = tokio::time::timeout(remaining, async {
        if job.state == JobState::Running {
            // A crash may have occurred before or after acceptance. Never start
            // on reconnect: only observe the exact journaled identity.
            let info = connection.session_get(&job.session_id.to_string()).await?;
            if info.id != job.session_id.to_string() || info.command != RUNNER {
                return Err(invalid("guest session identity changed"));
            }
            return Ok(info);
        }
        let version = connection.guest_info().await?.protocol_version;
        if version < husker_agent_proto::MIN_PROTOCOL_VERSION_FOR_SESSION_REPLAY {
            return Err(invalid(
                "guest agent does not support durable session replay",
            ));
        }
        let job_id = job.id.to_string();
        let prepared = connection
            .exec_with_timeout(
                RUNNER,
                &["--prepare", &job_id, &job.specification_digest],
                Some("/"),
                &[],
                Some(10),
            )
            .await?;
        if prepared.exit_code != 0 {
            return Err(invalid(format!(
                "trusted guest preparation failed: {}",
                prepared.stderr.chars().take(512).collect::<String>()
            )));
        }
        upload(
            connection,
            "/run/husker-job/spec.json",
            job.specification.as_bytes(),
        )
        .await?;
        upload(connection, "/run/husker-job/source.tar", source.bytes()).await?;
        upload(
            connection,
            "/run/husker-job/acceptance.tar",
            acceptance.bytes(),
        )
        .await?;
        // Durable host identity before the request can reach the guest. Even a
        // lost response leaves a stable session to query; no re-upload on retry.
        store.mark_job_running(id)?;
        let info = connection
            .session_start_replay(session_request(&job)?)
            .await?;
        if info.id != job.session_id.to_string() || info.command != RUNNER {
            return Err(invalid("guest submission identity changed"));
        }
        Ok(info)
    })
    .await
    .unwrap_or(Err(JobLaunchError::Deadline));
    if let Err(error) = &result {
        let current = store.get_job(id)?;
        if current.state == JobState::Preparing {
            let outcome = if matches!(error, JobLaunchError::Deadline) {
                JobState::TimedOut
            } else {
                JobState::InfrastructureFailed
            };
            let manifest = serde_json::json!({"version":1,"job_id":id,"staging_error":error.to_string().chars().take(512).collect::<String>()}).to_string();
            store.finish_job_failure(id, outcome, &manifest)?;
        }
    }
    result
}

impl<B: husker_vmm::VmmBackend> crate::HuskerCore<B> {
    pub async fn launch_prepared_job(
        &self,
        id: Uuid,
        source: &FrozenBundle,
        acceptance: &FrozenBundle,
    ) -> Result<SessionInfo, JobLaunchError> {
        let _lifecycle = self.job_lifecycle_lock(id).lock_owned().await;
        let job = self.state.get_job(id)?;
        let vm_id = job
            .vm_id
            .ok_or_else(|| invalid("job has no VM generation"))?;
        let name = job
            .vm_name
            .as_deref()
            .ok_or_else(|| invalid("job has no VM name"))?;
        let _name = self.vm_name_lock(name).lock_owned().await;
        let vm = self
            .state
            .get_vm_by_name(name)
            .map_err(|error| invalid(error.to_string()))?;
        if vm.id != vm_id {
            return Err(invalid("VM generation changed before launch"));
        }
        let remaining = remaining_deadline(job.deadline);
        if remaining.is_zero() {
            return Err(JobLaunchError::Deadline);
        }
        // VMM creation acknowledges a running hypervisor before guest PID 1
        // has bound the management socket. Only retry connection/ping here;
        // staging and the durable session submission must still happen once.
        let readiness = remaining.min(std::time::Duration::from_secs(30));
        let mut connection =
            tokio::time::timeout(remaining, self.agent_connect_ready(name, readiness))
                .await
                .map_err(|_| JobLaunchError::Deadline)?
                .map_err(|error| invalid(error.to_string()))?;
        if self
            .state
            .get_vm_by_name(name)
            .map_err(|error| invalid(error.to_string()))?
            .id
            != vm_id
        {
            return Err(invalid("VM generation changed while connecting"));
        }
        stage_and_launch_job(&self.state, id, &mut connection, source, acceptance).await
    }
}
