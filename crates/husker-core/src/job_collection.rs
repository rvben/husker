//! Host-side evidence collection. Never infer check success from the helper's
//! exit code; retain validated manifests, logs and artifact bytes before cleanup.
use crate::agent_client::{AgentConnection, AgentError};
use husker_agent_proto::SessionState;
use husker_agent_proto::job_result::{
    GuestJobManifest, JobCollectionStatus, JobOutcome, MAX_JOB_MANIFEST_BYTES,
};
use husker_agent_proto::job_spec::JobSpec;
use husker_state::StateStore;
use husker_state::jobs::{CollectionState, JobEvent, JobRecord, JobState, JournalError};
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum JobCollectionError {
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Core(#[from] crate::CoreError),
    #[error(transparent)]
    Agent(#[from] AgentError),
    #[error("execution evidence collection failed: {0}")]
    Invalid(String),
    #[error("execution hard deadline expired during evidence collection")]
    Deadline,
}

fn failure_manifest(id: Uuid, error: &JobCollectionError) -> String {
    serde_json::json!({"version": 1, "job_id": id,
        "collection_error": error.to_string().chars().take(512).collect::<String>()})
    .to_string()
}

async fn read_bounded<S: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut AgentConnection<S>,
    path: &str,
    max: usize,
    expected: Option<u64>,
) -> Result<Vec<u8>, JobCollectionError> {
    let mut bytes = Vec::new();
    let mut identity = None;
    loop {
        let read = connection
            .read_file_range(path, bytes.len() as u64, Some(64 * 1024))
            .await?;
        let size = read.total_size.ok_or_else(|| {
            JobCollectionError::Invalid("guest ranged read omitted total size".into())
        })?;
        let modified = read.modified_nanos.ok_or_else(|| {
            JobCollectionError::Invalid("guest ranged read omitted modification identity".into())
        })?;
        if size > max as u64
            || expected.is_some_and(|expected| expected != size)
            || identity.is_some_and(|identity| identity != (size, modified))
            || read.data.len() > 64 * 1024
            || bytes.len() as u64 + read.data.len() as u64 > size
        {
            return Err(JobCollectionError::Invalid(
                "export size or file identity changed".into(),
            ));
        }
        identity = Some((size, modified));
        let empty = read.data.is_empty();
        bytes.extend_from_slice(&read.data);
        if bytes.len() as u64 == size {
            return Ok(bytes);
        }
        if empty {
            return Err(JobCollectionError::Invalid(
                "export ended before declared size".into(),
            ));
        }
    }
}

/// The caller must bind the actual connection to the journal's exact VM
/// generation before calling this collector. HuskerCore does that below.
pub async fn collect_finished_job<S: AsyncRead + AsyncWrite + Unpin>(
    store: &StateStore,
    id: Uuid,
    connection: &mut AgentConnection<S>,
) -> Result<JobRecord, JobCollectionError> {
    let job = store.get_job(id)?;
    if job.state.terminal() {
        return Ok(job);
    }
    if job.state != JobState::Running {
        return Err(JobCollectionError::Invalid("job is not running".into()));
    }
    let remaining = crate::job_launch::remaining_deadline(job.deadline);
    let result = if remaining.is_zero() {
        Err(JobCollectionError::Deadline)
    } else {
        tokio::time::timeout(remaining, collect_inner(store, &job, connection))
            .await
            .map_err(|_| JobCollectionError::Deadline)
            .and_then(|result| result)
    };
    match result {
        Ok(result) => Ok(result),
        Err(error) => {
            let state = if matches!(error, JobCollectionError::Deadline) {
                JobState::TimedOut
            } else {
                JobState::InfrastructureFailed
            };
            let manifest = failure_manifest(id, &error);
            // A concurrent cancellation/completion remains the terminal winner.
            match store.finish_job_failure(id, state, &manifest) {
                Ok(_) | Err(JournalError::Conflict(_)) => {}
                Err(error) => return Err(error.into()),
            }
            Err(error)
        }
    }
}

/// Persist a bounded output observation while checks may still be running.
/// Errors leave prior committed output intact and do not authorize re-execution
/// or seal a passing result. The owner must reconcile/cancel on repeated failure.
/// Callers must fence the actual connected VM generation (core wrapper does).
pub async fn capture_job_output<S: AsyncRead + AsyncWrite + Unpin>(
    store: &StateStore,
    id: Uuid,
    connection: &mut AgentConnection<S>,
) -> Result<husker_agent_proto::SessionInfo, JobCollectionError> {
    let job = store.get_job(id)?;
    if job.state != JobState::Running
        || job.vm_id.is_none()
        || job.vm_destroyed
        || job.collection != CollectionState::Pending
    {
        return Err(JobCollectionError::Invalid(
            "job is not accepting output observations".into(),
        ));
    }
    let remaining = crate::job_launch::remaining_deadline(job.deadline);
    if remaining.is_zero() {
        return Err(JobCollectionError::Deadline);
    }
    tokio::time::timeout(
        remaining.min(std::time::Duration::from_secs(5)),
        capture_inner(store, &job, connection),
    )
    .await
    .map_err(|_| {
        JobCollectionError::Invalid(
            "output observation timed out; retained cursor remains resumable".into(),
        )
    })?
}

async fn capture_inner<S: AsyncRead + AsyncWrite + Unpin>(
    store: &StateStore,
    job: &JobRecord,
    connection: &mut AgentConnection<S>,
) -> Result<husker_agent_proto::SessionInfo, JobCollectionError> {
    let session_id = job.session_id.to_string();
    let mut status = connection.session_get(&session_id).await?;
    if status.id != session_id || status.command != "/usr/local/bin/husker-job-runner" {
        return Err(JobCollectionError::Invalid(
            "runner session identity changed".into(),
        ));
    }
    let mut cursor = job.capture_cursor;
    // Even a peer sending arbitrarily small pages cannot keep an observation
    // alive forever or drive cursors beyond the durable event quota.
    for _ in 0..=husker_state::jobs::MAX_EVENTS {
        let page = connection.session_events(&session_id, cursor).await?;
        if page.session.id != session_id
            || page.session.command != status.command
            || page.session.created_at != status.created_at
            || (status.state != SessionState::Running
                && (page.session.state != status.state
                    || page.session.exit_code != status.exit_code
                    || page.session.finished_at != status.finished_at))
            || (status.output_truncated && !page.session.output_truncated)
            || page.events.len() > husker_state::jobs::EVENT_PAGE_SIZE
            || page.next_cursor != page.events.last().map_or(cursor, |event| event.sequence)
            || (page.has_more && page.events.is_empty())
        {
            return Err(JobCollectionError::Invalid(
                "invalid session output receipt".into(),
            ));
        }
        let events = page
            .events
            .iter()
            .map(|event| {
                if event.data.len() > husker_state::jobs::MAX_EVENT_BYTES.div_ceil(3) * 4 {
                    return Err(JobCollectionError::Invalid(
                        "output event exceeds encoded limit".into(),
                    ));
                }
                let data = husker_agent_proto::base64_decode(&event.data)
                    .map_err(|error| JobCollectionError::Invalid(error.to_string()))?;
                Ok(JobEvent {
                    sequence: event.sequence,
                    stream: event.stream.clone(),
                    data,
                })
            })
            .collect::<Result<Vec<_>, JobCollectionError>>()?;
        store.append_job_events(job.id, &events, page.session.output_truncated)?;
        cursor = page.next_cursor;
        status = page.session;
        if !page.has_more {
            return Ok(status);
        }
    }
    Err(JobCollectionError::Invalid(
        "output page quota exceeded".into(),
    ))
}

async fn collect_inner<S: AsyncRead + AsyncWrite + Unpin>(
    store: &StateStore,
    job: &JobRecord,
    connection: &mut AgentConnection<S>,
) -> Result<JobRecord, JobCollectionError> {
    let spec: JobSpec = serde_json::from_str(&job.specification)
        .map_err(|error| JobCollectionError::Invalid(error.to_string()))?;
    if spec
        .digest()
        .map_err(|error| JobCollectionError::Invalid(error.to_string()))?
        != job.specification_digest
    {
        return Err(JobCollectionError::Invalid(
            "journal specification digest changed".into(),
        ));
    }
    let status = capture_inner(store, job, connection).await?;
    if status.state != SessionState::Completed || status.exit_code != Some(0) {
        return Err(JobCollectionError::Invalid(
            "runner has no confirmed successful terminal receipt".into(),
        ));
    }
    let bytes = read_bounded(
        connection,
        "/run/husker-job/result.json",
        MAX_JOB_MANIFEST_BYTES,
        None,
    )
    .await?;
    let manifest = GuestJobManifest::decode_for(&bytes, &spec, job.id)
        .map_err(|error| JobCollectionError::Invalid(error.to_string()))?;
    let json = std::str::from_utf8(&bytes)
        .map_err(|_| JobCollectionError::Invalid("manifest is not UTF-8".into()))?;
    store.stage_job_manifest(job.id, json)?;
    for (index, artifact) in manifest.artifacts.iter().enumerate() {
        if artifact.error.is_some() {
            continue;
        }
        let bytes = read_bounded(
            connection,
            &format!("/run/husker-job/artifacts/{index}.bin"),
            spec.artifacts[index].max_bytes as usize,
            artifact.size_bytes,
        )
        .await?;
        store.retain_job_artifact(
            job.id,
            index,
            &artifact.path,
            artifact
                .digest
                .as_deref()
                .ok_or_else(|| JobCollectionError::Invalid("artifact digest missing".into()))?,
            &bytes,
        )?;
    }
    let state = match manifest.outcome {
        JobOutcome::Completed => JobState::Completed,
        JobOutcome::CommandFailed => JobState::CommandFailed,
        JobOutcome::InfrastructureFailed => JobState::InfrastructureFailed,
        JobOutcome::Cancelled => JobState::Cancelled,
        JobOutcome::TimedOut => JobState::TimedOut,
        JobOutcome::Interrupted => JobState::Interrupted,
        JobOutcome::Unknown => JobState::Unknown,
    };
    let collection = match manifest.collection_status {
        JobCollectionStatus::Complete if store.get_job(job.id)?.output_truncated => {
            CollectionState::Truncated
        }
        JobCollectionStatus::Complete => CollectionState::Complete,
        JobCollectionStatus::Truncated => CollectionState::Truncated,
        JobCollectionStatus::Failed => CollectionState::Failed,
    };
    let json = String::from_utf8(bytes)
        .map_err(|_| JobCollectionError::Invalid("manifest is not UTF-8".into()))?;
    Ok(store.finish_job(job.id, state, collection, &json)?)
}

impl<B: husker_vmm::VmmBackend> crate::HuskerCore<B> {
    /// Capture live logs under the VM-name lock, bounded to a short observation.
    /// The absolute deadline remains independent of observed activity.
    pub async fn capture_job_output(
        &self,
        id: Uuid,
    ) -> Result<husker_agent_proto::SessionInfo, JobCollectionError> {
        let job = self.state.get_job(id)?;
        if job.state != JobState::Running || job.vm_destroyed {
            return Err(JobCollectionError::Invalid(
                "job is not accepting output observations".into(),
            ));
        }
        let remaining = crate::job_launch::remaining_deadline(job.deadline);
        if remaining.is_zero() {
            return Err(JobCollectionError::Deadline);
        }
        tokio::time::timeout(remaining.min(std::time::Duration::from_secs(5)), async {
            let name = job
                .vm_name
                .as_deref()
                .ok_or_else(|| JobCollectionError::Invalid("job has no VM ownership".into()))?;
            let _name = self.vm_name_lock(name).lock_owned().await;
            let vm = self.lookup_vm(name)?;
            if Some(vm.id) != job.vm_id {
                return Err(JobCollectionError::Invalid(
                    "VM generation changed before output observation".into(),
                ));
            }
            let mut connection = self.agent_connect(name).await?;
            if self.lookup_vm(name)?.id != vm.id {
                return Err(JobCollectionError::Invalid(
                    "VM generation changed during output connection".into(),
                ));
            }
            capture_job_output(&self.state, id, &mut connection).await
        })
        .await
        .map_err(|_| {
            JobCollectionError::Invalid(
                "output observation timed out; retained cursor remains resumable".into(),
            )
        })?
    }

    pub async fn collect_job_evidence(&self, id: Uuid) -> Result<JobRecord, JobCollectionError> {
        let job = self.state.get_job(id)?;
        if job.state.terminal() {
            return Ok(job);
        }
        if job.state != JobState::Running {
            return Err(JobCollectionError::Invalid("job is not running".into()));
        }
        let result = async {
            let name = job
                .vm_name
                .as_deref()
                .ok_or_else(|| JobCollectionError::Invalid("job has no VM ownership".into()))?;
            let vm = self.lookup_vm(name)?;
            if Some(vm.id) != job.vm_id {
                return Err(JobCollectionError::Invalid(
                    "execution VM generation changed".into(),
                ));
            }
            let remaining = crate::job_launch::remaining_deadline(job.deadline);
            if remaining.is_zero() {
                return Err(JobCollectionError::Deadline);
            }
            let mut connection = tokio::time::timeout(remaining, self.agent_connect(name))
                .await
                .map_err(|_| JobCollectionError::Deadline)??;
            if self.lookup_vm(name)?.id != vm.id {
                return Err(JobCollectionError::Invalid(
                    "execution VM changed during connection".into(),
                ));
            }
            collect_finished_job(&self.state, id, &mut connection).await
        }
        .await;
        if let Err(error) = &result {
            let terminal = self.state.get_job(id)?;
            if !terminal.state.terminal() {
                let state = if matches!(error, JobCollectionError::Deadline) {
                    JobState::TimedOut
                } else {
                    JobState::Unknown
                };
                let manifest = failure_manifest(id, error);
                match self.state.finish_job_failure(id, state, &manifest) {
                    Ok(_) | Err(JournalError::Conflict(_)) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        result
    }
}
