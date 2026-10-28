//! Version-one factory jobs and retained host evidence in one admin trust domain.
use crate::extract::{Json, Path, Query};
use crate::{ErrorResponse, errors::error_response_with_hint};
use axum::{extract::State, http::StatusCode};
use chrono::{DateTime, Utc};
use husker_agent_proto::{
    base64_decode, base64_encode,
    frozen_bundle::{FrozenBundle, MAX_BUNDLE_BYTES},
    job_spec::{JobNetwork, JobSubmission},
};
use husker_core::job_worker::{JobArtifactRecord, JobRecord, JournalError};
use husker_vmm::VmmBackend;
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

type Failure = (StatusCode, Json<ErrorResponse>);
fn failure(status: StatusCode, kind: &str, message: impl Into<String>) -> Failure {
    (
        status,
        error_response_with_hint(
            kind,
            message,
            "inspect the retained job; retry an identical submission key only",
        ),
    )
}
fn journal_error(error: JournalError) -> Failure {
    let (status, kind) = match &error {
        JournalError::NotFound(_) | JournalError::SubmissionNotFound => {
            (StatusCode::NOT_FOUND, "job_not_found")
        }
        JournalError::Conflict(_) => (StatusCode::CONFLICT, "job_conflict"),
        JournalError::Capacity(_) => (StatusCode::TOO_MANY_REQUESTS, "job_capacity_exhausted"),
        JournalError::Invalid(_) => (StatusCode::BAD_REQUEST, "invalid_job"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "job_journal_failed"),
    };
    failure(status, kind, error.to_string())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SubmissionLookup {
    idempotency_key: String,
    execution_specification_digest: String,
}
#[utoipa::path(get, path = "/v1/job-submissions", tag = "jobs", security(("factoryBearer" = [])),
    params(("idempotency_key" = String, Query), ("execution_specification_digest" = String, Query)),
    responses((status = 200, body = JobInspection, description = "Read-only accepted identity lookup"),
    (status = 404, body = ErrorResponse, description = "Submission absent from this journal; lookup never starts execution"),
    (status = 409, body = ErrorResponse, description = "Changed specification or deleted evidence")))]
pub(crate) async fn lookup<B: VmmBackend + 'static>(
    State(core): State<crate::SharedCore<B>>,

    Query(query): Query<SubmissionLookup>,
) -> Result<Json<JobInspection>, Failure> {
    let job = core
        .find_factory_job_submission(
            &query.idempotency_key,
            &query.execution_specification_digest,
        )
        .map_err(journal_error)?;
    Ok(Json(inspection(&core, job)?))
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactorySubmission {
    submission: JobSubmission,
    /// Canonical frozen tar bytes in standard padded base64, up to 32 MiB decoded.
    source_bundle: String,
    acceptance_bundle: String,
    retention_until: DateTime<Utc>,
}
#[derive(Serialize, ToSchema)]
pub(crate) struct JobReferences {
    job: String,
    events: String,
    artifacts: String,
}
#[derive(Serialize, ToSchema)]
pub(crate) struct JobInspection {
    contract_version: u32,
    job: JobRecord,
    artifacts: Vec<JobArtifactRecord>,
    references: JobReferences,
}
#[derive(Serialize, ToSchema)]
pub(crate) struct JobReceipt {
    #[serde(flatten)]
    inspection: JobInspection,
    replayed: bool,
}
fn inspection<B: VmmBackend + 'static>(
    core: &husker_core::HuskerCore<B>,
    job: JobRecord,
) -> Result<JobInspection, Failure> {
    let id = job.id;
    Ok(JobInspection {
        contract_version: 1,
        artifacts: core.factory_job_artifacts(id).map_err(journal_error)?,
        job,
        references: JobReferences {
            job: format!("/v1/jobs/{id}"),
            events: format!("/v1/jobs/{id}/events"),
            artifacts: format!("/v1/jobs/{id}/artifacts"),
        },
    })
}
fn decode_bundle(encoded: String, digest: &str, size: u64) -> Result<FrozenBundle, Failure> {
    if encoded.len() > MAX_BUNDLE_BYTES.div_ceil(3) * 4 {
        return Err(failure(
            StatusCode::PAYLOAD_TOO_LARGE,
            "bundle_too_large",
            "encoded bundle exceeds 32 MiB decoded",
        ));
    }
    let bytes = base64_decode(&encoded).map_err(|_| {
        failure(
            StatusCode::BAD_REQUEST,
            "invalid_bundle",
            "invalid base64 bundle",
        )
    })?;
    FrozenBundle::decode(bytes, digest, size)
        .map_err(|error| failure(StatusCode::BAD_REQUEST, "invalid_bundle", error.to_string()))
}

#[utoipa::path(post, path = "/v1/jobs", tag = "jobs", security(("factoryBearer" = [])), request_body = FactorySubmission,
    responses((status = 202, body = JobReceipt, description = "Durably accepted before worker launch"),
    (status = 200, body = JobReceipt, description = "Identical submission replay"),
    (status = 409, body = ErrorResponse, description = "Changed immutable submission"),
    (status = 429, body = ErrorResponse, description = "Factory allocation or journal capacity exhausted; no fresh receipt created"),
    (status = 403, body = ErrorResponse, description = "Factory execution disabled or policy denied")))]
pub(crate) async fn submit<B: VmmBackend + 'static>(
    State(core): State<crate::SharedCore<B>>,
    State(policy): State<std::sync::Arc<crate::ApiPolicy>>,
    Json(request): Json<FactorySubmission>,
) -> Result<(StatusCode, Json<JobReceipt>), Failure> {
    if !policy.factory_jobs_enabled {
        return Err(failure(
            StatusCode::FORBIDDEN,
            "factory_jobs_disabled",
            "factory execution requires explicit operator enablement",
        ));
    }
    request
        .submission
        .canonical_specification()
        .map_err(|error| failure(StatusCode::BAD_REQUEST, "invalid_job", error.to_string()))?;
    let spec = &request.submission.specification;
    if !matches!(spec.network, JobNetwork::None {}) {
        return Err(failure(
            StatusCode::NOT_IMPLEMENTED,
            "job_policy_unsupported",
            "factory jobs currently require offline network policy",
        ));
    }
    if policy.exec_allowlist.is_empty()
        || spec.commands.iter().any(|command| {
            !crate::handlers::exec_command_allowed(&command.argv[0], &policy)
                || command.timeout_secs > policy.exec_timeout_max_secs
        })
        || spec
            .environment
            .keys()
            .any(|key| !policy.exec_env_allowlist.contains(key))
    {
        return Err(failure(
            StatusCode::FORBIDDEN,
            "job_policy_denied",
            "factory commands, command deadlines and environment require operator allowlisting",
        ));
    }
    let source = decode_bundle(
        request.source_bundle,
        &spec.source.digest,
        spec.source.size_bytes,
    )?;
    let acceptance = decode_bundle(
        request.acceptance_bundle,
        &spec.acceptance.digest,
        spec.acceptance.size_bytes,
    )?;
    let (job, fresh) = core
        .submit_factory_job(
            &request.submission,
            source,
            acceptance,
            request.retention_until,
        )
        .map_err(journal_error)?;
    Ok((
        if fresh {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        },
        Json(JobReceipt {
            inspection: inspection(&core, job)?,
            replayed: !fresh,
        }),
    ))
}
#[utoipa::path(get, path = "/v1/jobs/{id}", tag = "jobs", security(("factoryBearer" = [])), params(("id" = Uuid, Path)), responses((status = 200, body = JobInspection)))]
pub(crate) async fn get<B: VmmBackend + 'static>(
    State(core): State<crate::SharedCore<B>>,

    Path(id): Path<Uuid>,
) -> Result<Json<JobInspection>, Failure> {
    let job = core.inspect_factory_job(id).map_err(journal_error)?;
    Ok(Json(inspection(&core, job)?))
}
#[derive(Deserialize)]
pub(crate) struct EventQuery {
    #[serde(default)]
    after: u64,
}
#[derive(Serialize, ToSchema)]
pub(crate) struct JobEvent {
    sequence: u64,
    stream: String,
    data: String,
}
#[derive(Serialize, ToSchema)]
pub(crate) struct JobEvents {
    job_id: Uuid,
    events: Vec<JobEvent>,
    next_cursor: u64,
    has_more: bool,
    output_truncated: bool,
}
#[utoipa::path(get, path = "/v1/jobs/{id}/events", tag = "jobs", security(("factoryBearer" = [])), params(("id" = Uuid, Path), ("after" = Option<u64>, Query)), responses((status = 200, body = JobEvents)))]
pub(crate) async fn events<B: VmmBackend + 'static>(
    State(core): State<crate::SharedCore<B>>,

    Path(id): Path<Uuid>,
    Query(query): Query<EventQuery>,
) -> Result<Json<JobEvents>, Failure> {
    let page = core
        .factory_job_events(id, query.after)
        .map_err(journal_error)?;
    Ok(Json(JobEvents {
        job_id: id,
        next_cursor: page.next_cursor,
        has_more: page.has_more,
        output_truncated: page.job.output_truncated,
        events: page
            .events
            .into_iter()
            .map(|event| JobEvent {
                sequence: event.sequence,
                stream: event.stream,
                data: base64_encode(&event.data),
            })
            .collect(),
    }))
}
#[utoipa::path(get, path = "/v1/jobs/{id}/artifacts", tag = "jobs", security(("factoryBearer" = [])), params(("id" = Uuid, Path)), responses((status = 200, body = Vec<JobArtifactRecord>)))]
pub(crate) async fn artifacts<B: VmmBackend + 'static>(
    State(core): State<crate::SharedCore<B>>,

    Path(id): Path<Uuid>,
) -> Result<Json<Vec<JobArtifactRecord>>, Failure> {
    core.inspect_factory_job(id).map_err(journal_error)?;
    Ok(Json(core.factory_job_artifacts(id).map_err(journal_error)?))
}
#[derive(Serialize, ToSchema)]
pub(crate) struct JobArtifact {
    descriptor: JobArtifactRecord,
    data: String,
}
#[utoipa::path(get, path = "/v1/jobs/{id}/artifacts/{index}", tag = "jobs", security(("factoryBearer" = [])), params(("id" = Uuid, Path), ("index" = usize, Path)), responses((status = 200, body = JobArtifact)))]
pub(crate) async fn artifact<B: VmmBackend + 'static>(
    State(core): State<crate::SharedCore<B>>,

    Path((id, index)): Path<(Uuid, usize)>,
) -> Result<Json<JobArtifact>, Failure> {
    core.inspect_factory_job(id).map_err(journal_error)?;
    let descriptor = core
        .factory_job_artifacts(id)
        .map_err(journal_error)?
        .into_iter()
        .find(|artifact| artifact.index == index)
        .ok_or_else(|| {
            failure(
                StatusCode::NOT_FOUND,
                "artifact_not_found",
                "declared artifact has no retained bytes",
            )
        })?;
    let data = core
        .factory_job_artifact(id, index)
        .map_err(journal_error)?;
    Ok(Json(JobArtifact {
        descriptor,
        data: base64_encode(&data),
    }))
}
#[utoipa::path(post, path = "/v1/jobs/{id}/cancel", tag = "jobs", security(("factoryBearer" = [])), params(("id" = Uuid, Path)), responses((status = 202, body = JobInspection, description = "Durable cancellation; destruction still pending"), (status = 200, body = JobInspection, description = "Terminal receipt")))]
pub(crate) async fn cancel<B: VmmBackend + 'static>(
    State(core): State<crate::SharedCore<B>>,

    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<JobInspection>), Failure> {
    let job = core.cancel_factory_job(id).map_err(journal_error)?;
    let status = if job.cleanup_pending {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(inspection(&core, job)?)))
}
#[utoipa::path(delete, path = "/v1/jobs/{id}", tag = "jobs", security(("factoryBearer" = [])), params(("id" = Uuid, Path)), responses((status = 204, description = "Evidence deleted; submission tombstone retained"), (status = 409, body = ErrorResponse, description = "Active execution or unconfirmed cleanup")))]
pub(crate) async fn remove<B: VmmBackend + 'static>(
    State(core): State<crate::SharedCore<B>>,

    Path(id): Path<Uuid>,
) -> Result<StatusCode, Failure> {
    core.delete_factory_job_evidence(id)
        .map_err(journal_error)?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(OpenApi)]
#[openapi(modifiers(&FactorySecurity), paths(submit, lookup, get, events, artifacts, artifact, cancel, remove), tags((name = "jobs", description = "Version-one factory execution and retained host evidence")))]
pub(crate) struct JobApiDoc;

struct FactorySecurity;
impl utoipa::Modify for FactorySecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityScheme};
        openapi
            .components
            .get_or_insert_with(Default::default)
            .add_security_scheme(
                "factoryBearer",
                SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
            );
    }
}
