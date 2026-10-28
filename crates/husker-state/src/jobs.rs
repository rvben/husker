//! Host-side execution journal. VM deletion never cascades into this evidence.
//!
//! This is persistence, not a scheduler: orchestration must verify/freeze the
//! specification, enforce policy, and fence VM/session identity before execution.
use chrono::{DateTime, Utc};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{StateError, StateStore};

pub const MAX_RETAINED_JOBS: usize = 64;
/// Execution reservations include terminal jobs until cleanup is confirmed.
pub const MAX_ACTIVE_JOBS: usize = 16;

/// Operator allocation budget, not a measurement of available host resources.
/// Boot storage includes two independent root disks, bounded kernel/initrd
/// inputs and serial diagnostics. Catalog caches and journal storage are separate.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryResourceBudget {
    pub max_jobs: usize,
    pub max_vcpus: u64,
    pub max_memory_mib: u64,
    pub memory_overhead_mib: u32,
    pub max_root_disk_bytes: u64,
    pub max_boot_storage_bytes: u64,
    pub min_free_storage_bytes: u64,
}

pub struct FactoryAvailableStorage {
    pub shared_filesystem: bool,
    pub boot_bytes: u64,
    pub journal_bytes: u64,
}
type StorageObservation<'a> =
    Box<dyn FnOnce() -> Result<FactoryAvailableStorage, JournalError> + 'a>;
const JOURNAL_HEADROOM_PER_RECEIPT: u64 = 64 * 1024 * 1024;

impl FactoryResourceBudget {
    pub fn validate(&self) -> Result<(), JournalError> {
        if !(1..=MAX_ACTIVE_JOBS).contains(&self.max_jobs)
            || self.max_vcpus == 0
            || self.max_memory_mib <= u64::from(self.memory_overhead_mib)
            || self.max_root_disk_bytes == 0
            || self.max_boot_storage_bytes == 0
            || self.min_free_storage_bytes == 0
        {
            return Err(JournalError::Invalid("invalid factory resource budget"));
        }
        Ok(())
    }

    fn check<'a>(
        &self,
        specifications: impl Iterator<Item = &'a str>,
    ) -> Result<u64, JournalError> {
        let mut cpus = 0u64;
        let mut memory = 0u64;
        let mut disks = 0u64;
        let mut boot_storage = 0u64;
        for specification in specifications {
            let value: serde_json::Value = serde_json::from_str(specification)
                .map_err(|_| JournalError::Capacity("unaccounted execution reservation"))?;
            let resources = &value["resources"];
            let resource = |name: &str| {
                resources[name]
                    .as_u64()
                    .filter(|n| *n > 0)
                    .ok_or(JournalError::Capacity("unaccounted execution reservation"))
            };
            cpus = cpus
                .checked_add(resource("vcpu_count")?)
                .ok_or(JournalError::Capacity("factory vCPU budget"))?;
            memory = memory
                .checked_add(resource("mem_size_mib")?)
                .and_then(|n| n.checked_add(u64::from(self.memory_overhead_mib)))
                .ok_or(JournalError::Capacity("factory memory budget"))?;
            let disk = resource("disk_size_bytes")?;
            disks = disks
                .checked_add(disk)
                .ok_or(JournalError::Capacity("factory root disk budget"))?;
            // The prepared immutable job copy and writable VM disk may allocate
            // independently even when initially sparse or reflinked. Charge the
            // optional initrd bound even when absent, including legacy receipts.
            use husker_types::factory_limits::{INITRD_BYTES, KERNEL_BYTES, SERIAL_BYTES};
            boot_storage = disk
                .checked_mul(2)
                .and_then(|n| n.checked_add(KERNEL_BYTES + INITRD_BYTES + SERIAL_BYTES))
                .and_then(|n| boot_storage.checked_add(n))
                .ok_or(JournalError::Capacity("factory boot storage budget"))?;
            if cpus > self.max_vcpus {
                return Err(JournalError::Capacity("factory vCPU budget"));
            }
            if memory > self.max_memory_mib {
                return Err(JournalError::Capacity("factory memory budget"));
            }
            if disks > self.max_root_disk_bytes {
                return Err(JournalError::Capacity("factory root disk budget"));
            }
            if boot_storage > self.max_boot_storage_bytes {
                return Err(JournalError::Capacity("factory boot storage budget"));
            }
        }
        Ok(boot_storage)
    }
}
pub const MAX_SUBMISSION_RECEIPTS: usize = 4096;
pub const MAX_SPEC_BYTES: usize = 64 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EVENTS: u64 = 4096;
pub const MAX_EVENT_BYTES: usize = 8192;
pub const EVENT_PAGE_SIZE: usize = 128;
pub const MAX_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_ARTIFACT_TOTAL_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ARTIFACTS: usize = 16;

pub(crate) const ARTIFACT_SCHEMA: &str = "
CREATE TABLE execution_job_artifacts (
    job_id TEXT NOT NULL REFERENCES execution_jobs(id) ON DELETE CASCADE,
    artifact_index INTEGER NOT NULL CHECK(artifact_index BETWEEN 0 AND 15),
    path TEXT NOT NULL CHECK(length(CAST(path AS BLOB)) BETWEEN 1 AND 255),
    digest TEXT NOT NULL,
    data BLOB NOT NULL CHECK(length(data)<=4194304),
    PRIMARY KEY(job_id,artifact_index), UNIQUE(job_id,path)
);
CREATE TRIGGER execution_job_artifact_is_immutable BEFORE UPDATE ON execution_job_artifacts
BEGIN SELECT RAISE(ABORT, 'execution artifact is immutable'); END;
";

// Reserve names before VMM allocation; never release ownership on an uncertain
// creation outcome. Existing conflicting ownership makes migration fail closed.
pub(crate) const OWNERSHIP_SCHEMA: &str = "
CREATE UNIQUE INDEX execution_job_pending_vm_name ON execution_jobs(vm_name)
WHERE cleanup_pending=1 AND vm_name IS NOT NULL;
CREATE TRIGGER execution_job_vm_name_is_immutable
BEFORE UPDATE OF vm_name ON execution_jobs
WHEN OLD.vm_name IS NOT NULL AND NEW.vm_name IS NOT OLD.vm_name
BEGIN SELECT RAISE(ABORT, 'execution VM name is immutable'); END;
";

pub(crate) const DESTRUCTION_SCHEMA: &str = "
ALTER TABLE execution_jobs ADD COLUMN vm_destroyed INTEGER NOT NULL DEFAULT 0 CHECK(vm_destroyed IN (0,1));
CREATE TRIGGER execution_job_vm_destruction_is_monotonic BEFORE UPDATE OF vm_destroyed ON execution_jobs
WHEN OLD.vm_destroyed=1 AND NEW.vm_destroyed<>1
BEGIN SELECT RAISE(ABORT, 'confirmed VM destruction is immutable'); END;
";

pub(crate) const ALLOCATION_ABORT_SCHEMA: &str = "
ALTER TABLE execution_jobs ADD COLUMN vm_allocation_aborted INTEGER NOT NULL DEFAULT 0
CHECK(vm_allocation_aborted IN (0,1) AND (vm_allocation_aborted=0 OR
    (vm_destroyed=0 AND vm_id IS NOT NULL AND state NOT IN ('accepted','running','completed','command_failed'))));
CREATE TRIGGER execution_job_allocation_abort_is_monotonic
BEFORE UPDATE OF vm_allocation_aborted ON execution_jobs
WHEN OLD.vm_allocation_aborted=1 AND NEW.vm_allocation_aborted<>1
BEGIN SELECT RAISE(ABORT, 'confirmed allocation abort is immutable'); END;
";

// There is deliberately no foreign key from jobs to vms. Deleting a VM must
// preserve its ownership record, status, manifest and logs for reconciliation.
pub(crate) const SCHEMA: &str = "
CREATE TABLE execution_jobs (
    id TEXT PRIMARY KEY,
    submission_key TEXT NOT NULL UNIQUE,
    spec_digest TEXT NOT NULL,
    specification TEXT CHECK(specification IS NULL OR length(CAST(specification AS BLOB))<=65536),
    state TEXT NOT NULL CHECK(state IN ('accepted','preparing','running',
        'completed','command_failed','infrastructure_failed','interrupted',
        'cancelled','timed_out','unknown','deleted')),
    created_at INTEGER NOT NULL,
    deadline INTEGER NOT NULL,
    retention_until INTEGER NOT NULL,
    vm_id TEXT UNIQUE,
    vm_name TEXT,
    session_id TEXT NOT NULL UNIQUE,
    capture_cursor INTEGER NOT NULL DEFAULT 0 CHECK(capture_cursor BETWEEN 0 AND 4096),
    retained_bytes INTEGER NOT NULL DEFAULT 0 CHECK(retained_bytes BETWEEN 0 AND 4194304),
    output_truncated INTEGER NOT NULL DEFAULT 0,
    collection TEXT NOT NULL DEFAULT 'pending' CHECK(collection IN
        ('pending','complete','truncated','failed')),
    manifest TEXT CHECK(manifest IS NULL OR length(CAST(manifest AS BLOB))<=65536),
    cleanup_pending INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE execution_job_events (
    job_id TEXT NOT NULL REFERENCES execution_jobs(id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK(sequence BETWEEN 1 AND 4096),
    stream TEXT NOT NULL CHECK(stream IN ('stdout','stderr')),
    digest TEXT NOT NULL,
    data BLOB CHECK(data IS NULL OR length(data)<=8192),
    PRIMARY KEY(job_id, sequence)
);
CREATE INDEX execution_jobs_deadline ON execution_jobs(state, deadline);
CREATE INDEX execution_jobs_retention ON execution_jobs(retention_until);
CREATE TRIGGER execution_job_identity_is_immutable
BEFORE UPDATE OF id, submission_key, spec_digest, deadline, session_id ON execution_jobs
BEGIN SELECT RAISE(ABORT, 'execution job identity is immutable'); END;
CREATE TRIGGER execution_job_vm_generation_is_immutable
BEFORE UPDATE OF vm_id,vm_name ON execution_jobs
WHEN OLD.vm_id IS NOT NULL AND (NEW.vm_id IS NOT OLD.vm_id OR NEW.vm_name IS NOT OLD.vm_name)
BEGIN SELECT RAISE(ABORT, 'execution VM generation is immutable'); END;
CREATE TRIGGER execution_job_spec_is_immutable
BEFORE UPDATE OF specification ON execution_jobs
WHEN NEW.specification IS NOT OLD.specification AND
     NOT (NEW.specification IS NULL AND NEW.state = 'deleted')
BEGIN SELECT RAISE(ABORT, 'execution job specification is immutable'); END;
";

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
    #[error("execution job not found: {0}")]
    NotFound(Uuid),
    #[error("execution submission not found")]
    SubmissionNotFound,
    #[error("execution submission conflict: {0}")]
    Conflict(&'static str),
    #[error("execution journal capacity exhausted: {0}")]
    Capacity(&'static str),
    #[error("invalid execution evidence: {0}")]
    Invalid(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum JobState {
    Accepted,
    Preparing,
    Running,
    Completed,
    CommandFailed,
    InfrastructureFailed,
    Interrupted,
    Cancelled,
    TimedOut,
    Unknown,
}
impl JobState {
    pub fn terminal(self) -> bool {
        !matches!(self, Self::Accepted | Self::Preparing | Self::Running)
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Preparing => "preparing",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::CommandFailed => "command_failed",
            Self::InfrastructureFailed => "infrastructure_failed",
            Self::Interrupted => "interrupted",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
            Self::Unknown => "unknown",
        }
    }
    fn parse(value: &str) -> rusqlite::Result<Self> {
        match value {
            "accepted" => Ok(Self::Accepted),
            "preparing" => Ok(Self::Preparing),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "command_failed" => Ok(Self::CommandFailed),
            "infrastructure_failed" => Ok(Self::InfrastructureFailed),
            "interrupted" => Ok(Self::Interrupted),
            "cancelled" => Ok(Self::Cancelled),
            "timed_out" => Ok(Self::TimedOut),
            "unknown" => Ok(Self::Unknown),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum CollectionState {
    Pending,
    Complete,
    Truncated,
    Failed,
}
impl CollectionState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Complete => "complete",
            Self::Truncated => "truncated",
            Self::Failed => "failed",
        }
    }
    fn parse(value: &str) -> rusqlite::Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "complete" => Ok(Self::Complete),
            "truncated" => Ok(Self::Truncated),
            "failed" => Ok(Self::Failed),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct JobRecord {
    pub id: Uuid,
    pub specification_digest: String,
    pub specification: String,
    pub state: JobState,
    pub created_at: i64,
    pub deadline: i64,
    pub retention_until: i64,
    pub vm_id: Option<Uuid>,
    pub vm_name: Option<String>,
    pub session_id: Uuid,
    pub capture_cursor: u64,
    pub retained_bytes: usize,
    pub output_truncated: bool,
    pub collection: CollectionState,
    pub manifest: Option<String>,
    pub cleanup_pending: bool,
    pub vm_destroyed: bool,
    /// The owning preparation future ended before entering VM allocation.
    /// This is a positive nonallocation receipt, never inferred from absence.
    pub vm_allocation_aborted: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobEvent {
    pub sequence: u64,
    pub stream: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct JobArtifactRecord {
    pub index: usize,
    pub path: String,
    pub digest: String,
    pub size_bytes: usize,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct JobEventPage {
    pub job: JobRecord,
    pub events: Vec<JobEvent>,
    pub next_cursor: u64,
    pub has_more: bool,
}

const COLUMNS: &str = "id,spec_digest,specification,state,created_at,deadline,retention_until,
    vm_id,vm_name,session_id,capture_cursor,retained_bytes,output_truncated,collection,manifest,cleanup_pending,vm_destroyed,vm_allocation_aborted";
fn uuid(value: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery)
}
fn read_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobRecord> {
    Ok(JobRecord {
        id: uuid(row.get(0)?)?,
        specification_digest: row.get(1)?,
        specification: row.get(2)?,
        state: JobState::parse(&row.get::<_, String>(3)?)?,
        created_at: row.get(4)?,
        deadline: row.get(5)?,
        retention_until: row.get(6)?,
        vm_id: row.get::<_, Option<String>>(7)?.map(uuid).transpose()?,
        vm_name: row.get(8)?,
        session_id: uuid(row.get(9)?)?,
        capture_cursor: u64::from(row.get::<_, u32>(10)?),
        retained_bytes: row.get::<_, u32>(11)? as usize,
        output_truncated: row.get(12)?,
        collection: CollectionState::parse(&row.get::<_, String>(13)?)?,
        manifest: row.get(14)?,
        cleanup_pending: row.get(15)?,
        vm_destroyed: row.get(16)?,
        vm_allocation_aborted: row.get(17)?,
    })
}
fn get_on(conn: &rusqlite::Connection, id: Uuid) -> Result<JobRecord, JournalError> {
    conn.query_row(
        &format!("SELECT {COLUMNS} FROM execution_jobs WHERE id=?1 AND state!='deleted'"),
        [id.to_string()],
        read_record,
    )
    .optional()?
    .ok_or(JournalError::NotFound(id))
}
fn bounded_json(value: &str, limit: usize) -> Result<(), JournalError> {
    if value.len() > limit
        || !serde_json::from_str::<serde_json::Value>(value).is_ok_and(|v| v.is_object())
    {
        return Err(JournalError::Invalid("expected a bounded JSON object"));
    }
    Ok(())
}

impl StateStore {
    /// Persist the validated guest receipt before artifact export. A timeout or
    /// transport failure during subsequent transfers must not erase it.
    pub fn stage_job_manifest(&self, id: Uuid, manifest: &str) -> Result<(), JournalError> {
        bounded_json(manifest, MAX_MANIFEST_BYTES)?;
        let mut conn = self.lock_durable()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let job = get_on(&tx, id)?;
        if job.state != JobState::Running || job.collection != CollectionState::Pending {
            return Err(JournalError::Conflict("manifest collection is not active"));
        }
        if job.manifest.as_deref().is_some_and(|old| old != manifest) {
            return Err(JournalError::Conflict("staged guest manifest changed"));
        }
        tx.execute(
            "UPDATE execution_jobs SET manifest=?1 WHERE id=?2",
            params![manifest, id.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Commit verified artifact bytes before terminal publication or VM cleanup.
    /// Byte-identical replay is harmless; altered receipts or bytes conflict.
    pub fn retain_job_artifact(
        &self,
        id: Uuid,
        index: usize,
        path: &str,
        expected_digest: &str,
        data: &[u8],
    ) -> Result<JobArtifactRecord, JournalError> {
        if index >= MAX_ARTIFACTS
            || data.len() > MAX_ARTIFACT_BYTES
            || path.is_empty()
            || path.len() > 255
            || path.contains('\\')
            || path.chars().any(char::is_control)
            || path.split('/').any(|part| matches!(part, "" | "." | ".."))
        {
            return Err(JournalError::Invalid(
                "invalid artifact path, index or size",
            ));
        }
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(data)));
        if digest != expected_digest {
            return Err(JournalError::Invalid("artifact digest mismatch"));
        }
        let mut conn = self.lock_durable()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let job = get_on(&tx, id)?;
        let old = tx.query_row("SELECT path,digest,data FROM execution_job_artifacts WHERE job_id=?1 AND artifact_index=?2",
            params![id.to_string(), index as u32], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?))).optional()?;
        if let Some(old) = old {
            if old != (path.to_owned(), digest.clone(), data.to_vec()) {
                return Err(JournalError::Conflict("retained artifact replay changed"));
            }
        } else {
            if job.state != JobState::Running || job.collection != CollectionState::Pending {
                return Err(JournalError::Conflict("artifact collection is not active"));
            }
            let total: u32 = tx.query_row(
                "SELECT COALESCE(SUM(length(data)),0) FROM execution_job_artifacts WHERE job_id=?1",
                [id.to_string()],
                |row| row.get(0),
            )?;
            if total as usize + data.len() > MAX_ARTIFACT_TOTAL_BYTES {
                return Err(JournalError::Capacity("artifact total exceeds 16 MiB"));
            }
            let path_exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM execution_job_artifacts WHERE job_id=?1 AND path=?2)",
                params![id.to_string(), path],
                |row| row.get(0),
            )?;
            if path_exists {
                return Err(JournalError::Conflict("artifact path already retained"));
            }
            tx.execute("INSERT INTO execution_job_artifacts(job_id,artifact_index,path,digest,data) VALUES (?1,?2,?3,?4,?5)", params![id.to_string(),index as u32,path,digest,data])?;
        }
        tx.commit()?;
        Ok(JobArtifactRecord {
            index,
            path: path.into(),
            digest,
            size_bytes: data.len(),
        })
    }

    pub fn job_artifacts(&self, id: Uuid) -> Result<Vec<JobArtifactRecord>, JournalError> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        get_on(&tx, id)?;
        let records = {
            let mut statement = tx.prepare("SELECT artifact_index,path,digest,length(data) FROM execution_job_artifacts WHERE job_id=?1 ORDER BY artifact_index")?;
            statement
                .query_map([id.to_string()], |row| {
                    Ok(JobArtifactRecord {
                        index: row.get::<_, u32>(0)? as usize,
                        path: row.get(1)?,
                        digest: row.get(2)?,
                        size_bytes: row.get::<_, u32>(3)? as usize,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        tx.commit()?;
        Ok(records)
    }

    pub fn job_artifact(&self, id: Uuid, index: usize) -> Result<Vec<u8>, JournalError> {
        if index >= MAX_ARTIFACTS {
            return Err(JournalError::Invalid("artifact index exceeds limit"));
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        get_on(&tx, id)?;
        let data = tx
            .query_row(
                "SELECT data FROM execution_job_artifacts WHERE job_id=?1 AND artifact_index=?2",
                params![id.to_string(), index as u32],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(JournalError::Invalid("artifact not retained"))?;
        tx.commit()?;
        Ok(data)
    }
    /// Atomically persist acceptance before an orchestrator acknowledges/executes.
    /// Callers pass canonical JSON including every immutable execution input.
    /// Keys belong to this database's single administrative trust domain.
    pub fn accept_job(
        &self,
        key: &str,
        specification: &str,
        deadline: DateTime<Utc>,
        retention_until: DateTime<Utc>,
    ) -> Result<(JobRecord, bool), JournalError> {
        self.accept_job_inner(key, specification, deadline, retention_until, None)
    }

    /// Reserve resources atomically with acceptance. Replay never reserves twice.
    pub fn accept_job_with_budget(
        &self,
        key: &str,
        specification: &str,
        deadline: DateTime<Utc>,
        retention_until: DateTime<Utc>,
        budget: &FactoryResourceBudget,
        observe_storage: impl FnOnce() -> Result<FactoryAvailableStorage, JournalError>,
    ) -> Result<(JobRecord, bool), JournalError> {
        budget.validate()?;
        self.accept_job_inner(
            key,
            specification,
            deadline,
            retention_until,
            Some((budget, Box::new(observe_storage))),
        )
    }

    fn accept_job_inner(
        &self,
        key: &str,
        specification: &str,
        deadline: DateTime<Utc>,
        retention_until: DateTime<Utc>,
        budget: Option<(&FactoryResourceBudget, StorageObservation<'_>)>,
    ) -> Result<(JobRecord, bool), JournalError> {
        if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
            return Err(JournalError::Invalid(
                "submission key must be 1–128 printable UTF-8 bytes",
            ));
        }
        bounded_json(specification, MAX_SPEC_BYTES)?;
        let digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(specification.as_bytes()))
        );
        let mut conn = self.lock_durable()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = tx
            .query_row(
                "SELECT id,spec_digest,deadline,state FROM execution_jobs WHERE submission_key=?1",
                [key],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        if let Some((id, old_digest, old_deadline, state)) = old {
            if state == "deleted" {
                return Err(JournalError::Conflict(
                    "evidence explicitly deleted; use a new key",
                ));
            }
            if old_digest != digest || old_deadline != deadline.timestamp() {
                return Err(JournalError::Conflict(
                    "immutable specification or deadline changed",
                ));
            }
            let record = get_on(&tx, uuid(id)?)?;
            tx.commit()?;
            return Ok((record, false));
        }
        let now = Utc::now();
        if deadline.timestamp() <= now.timestamp()
            || retention_until <= deadline
            || retention_until > now + chrono::Duration::days(30)
        {
            return Err(JournalError::Invalid(
                "deadline must be future; retention must exceed deadline and be at most 30 days",
            ));
        }
        let (receipts, retained, active): (u32, u32, u32) = tx.query_row(
            "SELECT COUNT(*),COUNT(CASE WHEN state!='deleted' THEN 1 END),COUNT(CASE WHEN state IN ('accepted','preparing','running') OR cleanup_pending=1 THEN 1 END) FROM execution_jobs", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        if receipts >= MAX_SUBMISSION_RECEIPTS as u32 {
            return Err(JournalError::Capacity("submission receipts"));
        }
        if retained >= MAX_RETAINED_JOBS as u32 {
            return Err(JournalError::Capacity("retained jobs"));
        }
        if active >= MAX_ACTIVE_JOBS as u32 {
            return Err(JournalError::Capacity("active jobs"));
        }
        if let Some((budget, observe_storage)) = budget {
            if active as usize >= budget.max_jobs {
                return Err(JournalError::Capacity("factory job budget"));
            }
            let mut statement = tx.prepare(
                "SELECT specification FROM execution_jobs WHERE state IN ('accepted','preparing','running') OR cleanup_pending=1",
            )?;
            let specifications = statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            let boot_storage = budget.check(
                specifications
                    .iter()
                    .map(String::as_str)
                    .chain(std::iter::once(specification)),
            )?;
            let storage = observe_storage()?;
            let boot_required = boot_storage
                .checked_add(budget.min_free_storage_bytes)
                .ok_or(JournalError::Capacity("factory storage headroom overflow"))?;
            let journal_required = u64::from(retained)
                .checked_add(1)
                .and_then(|n| n.checked_mul(JOURNAL_HEADROOM_PER_RECEIPT))
                .and_then(|n| n.checked_add(budget.min_free_storage_bytes))
                .ok_or(JournalError::Capacity("factory journal headroom overflow"))?;
            let boot_required = if storage.shared_filesystem {
                boot_required
                    .checked_add(journal_required - budget.min_free_storage_bytes)
                    .ok_or(JournalError::Capacity("factory storage headroom overflow"))?
            } else {
                boot_required
            };
            let boot_available = if storage.shared_filesystem {
                storage.boot_bytes.min(storage.journal_bytes)
            } else {
                storage.boot_bytes
            };
            if boot_available < boot_required {
                return Err(JournalError::Capacity("factory boot filesystem pressure"));
            }
            if storage.journal_bytes < journal_required {
                return Err(JournalError::Capacity(
                    "factory journal filesystem pressure",
                ));
            }
        }
        let id = Uuid::new_v4();
        let session = Uuid::new_v4();
        tx.execute("INSERT INTO execution_jobs(id,submission_key,spec_digest,specification,state,created_at,deadline,retention_until,session_id) VALUES (?1,?2,?3,?4,'accepted',?5,?6,?7,?8)",
            params![id.to_string(), key, digest, specification, now.timestamp(), deadline.timestamp(), retention_until.timestamp(), session.to_string()])?;
        let record = get_on(&tx, id)?;
        tx.commit()?;
        Ok((record, true))
    }

    /// Read-only reconciliation after a lost response. Missing keys never accept
    /// work; tombstones and changed identities cannot be mistaken for fresh work.
    pub fn find_job_submission(
        &self,
        key: &str,
        expected_digest: &str,
    ) -> Result<JobRecord, JournalError> {
        if key.is_empty()
            || key.len() > 128
            || key.chars().any(char::is_control)
            || expected_digest.len() != 71
            || !expected_digest.starts_with("sha256:")
            || !expected_digest[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(JournalError::Invalid("invalid submission lookup identity"));
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let record = tx
            .query_row(
                "SELECT id,spec_digest,state FROM execution_jobs WHERE submission_key=?1",
                [key],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        let (id, digest, state) = record.ok_or(JournalError::SubmissionNotFound)?;
        if digest != expected_digest {
            return Err(JournalError::Conflict("immutable specification changed"));
        }
        if state == "deleted" {
            return Err(JournalError::Conflict(
                "evidence deleted; submission tombstone retained",
            ));
        }
        let job = get_on(&tx, uuid(id)?)?;
        tx.commit()?;
        Ok(job)
    }

    pub fn get_job(&self, id: Uuid) -> Result<JobRecord, JournalError> {
        get_on(&*self.lock()?, id)
    }

    /// Persist ownership before starting any allocation. The name is derived
    /// from the durable identity and must be used with create-without-replace.
    /// Replay never authorizes restarting an interrupted allocation.
    pub fn reserve_job_vm(&self, id: Uuid) -> Result<JobRecord, JournalError> {
        self.reserve_job_vm_inner(id, true)
    }

    /// Claim allocation exactly once. Reconciliation uses the replayable read
    /// above; an allocation worker must use this atomic non-replayable claim.
    pub fn claim_job_vm(&self, id: Uuid) -> Result<JobRecord, JournalError> {
        self.reserve_job_vm_inner(id, false)
    }

    fn reserve_job_vm_inner(&self, id: Uuid, replay: bool) -> Result<JobRecord, JournalError> {
        let mut conn = self.lock_durable()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let job = get_on(&tx, id)?;
        if job.vm_name.is_some() && !replay {
            return Err(JournalError::Conflict("allocation already claimed"));
        }
        if job.vm_name.is_none() {
            if job.state != JobState::Accepted || job.deadline <= Utc::now().timestamp() {
                return Err(JournalError::Conflict("job is no longer accepting a VM"));
            }
            tx.execute(
                "UPDATE execution_jobs SET vm_name=?1,state='preparing',cleanup_pending=1 WHERE id=?2",
                params![format!("job-{id}"), id.to_string()],
            )?;
        }
        let record = get_on(&tx, id)?;
        tx.commit()?;
        Ok(record)
    }

    /// Bind the actual allocation generation without changing a terminal winner.
    /// A late allocation must still be recorded for cleanup after cancellation.
    /// Retry cannot substitute a recreated VM, even when its name matches.
    pub fn bind_job_vm(
        &self,
        id: Uuid,
        vm_id: Uuid,
        name: &str,
    ) -> Result<JobRecord, JournalError> {
        if name.is_empty() || name.len() > 255 || name.chars().any(char::is_control) {
            return Err(JournalError::Invalid("invalid VM name"));
        }
        let mut conn = self.lock_durable()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let job = get_on(&tx, id)?;
        if job.vm_allocation_aborted {
            return Err(JournalError::Conflict(
                "VM allocation was permanently aborted",
            ));
        }
        if let Some(bound) = job.vm_id {
            if bound != vm_id || job.vm_name.as_deref() != Some(name) {
                return Err(JournalError::Conflict("VM generation changed"));
            }
        } else {
            let reserved = job.vm_name.is_some();
            if reserved {
                if job.vm_name.as_deref() != Some(name) || !job.cleanup_pending {
                    return Err(JournalError::Conflict("VM reservation changed or released"));
                }
            } else if job.state != JobState::Accepted || job.deadline <= Utc::now().timestamp() {
                return Err(JournalError::Conflict("job is no longer accepting a VM"));
            }
            let owned: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM execution_jobs WHERE vm_id=?1 OR (vm_name=?2 AND cleanup_pending=1 AND id<>?3))",
                params![vm_id.to_string(), name, id.to_string()],
                |r| r.get(0),
            )?;
            if owned {
                return Err(JournalError::Conflict("VM is already owned by another job"));
            }
            tx.execute("UPDATE execution_jobs SET vm_id=?1,vm_name=?2,state=CASE WHEN state='accepted' THEN 'preparing' ELSE state END,cleanup_pending=1 WHERE id=?3",
                params![vm_id.to_string(), name, id.to_string()])?;
        }
        let job = get_on(&tx, id)?;
        tx.commit()?;
        Ok(job)
    }

    pub fn mark_job_running(&self, id: Uuid) -> Result<(), JournalError> {
        let conn = self.lock_durable()?;
        let changed = conn.execute("UPDATE execution_jobs SET state='running' WHERE id=?1 AND state='preparing' AND vm_id IS NOT NULL AND vm_destroyed=0 AND vm_allocation_aborted=0 AND deadline>?2", params![id.to_string(), Utc::now().timestamp()])?;
        if changed == 0 {
            let job = get_on(&conn, id)?;
            if job.state != JobState::Running || job.vm_destroyed || job.vm_allocation_aborted {
                return Err(JournalError::Conflict("job cannot enter running state"));
            }
        }
        Ok(())
    }

    /// Append an atomic guest-event batch. Replayed bytes must match; cursor and
    /// retention changes commit together. Truncation preserves hashes, not data,
    /// so an altered replay cannot rewrite/forge previously collected evidence.
    pub fn append_job_events(
        &self,
        id: Uuid,
        events: &[JobEvent],
        guest_truncated: bool,
    ) -> Result<(), JournalError> {
        if events.len() > EVENT_PAGE_SIZE {
            return Err(JournalError::Invalid("event batch exceeds page limit"));
        }
        let mut conn = self.lock_durable()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let job = get_on(&tx, id)?;
        if job.collection != CollectionState::Pending {
            return Err(JournalError::Conflict("evidence collection is sealed"));
        }
        let mut cursor = job.capture_cursor;
        let mut bytes = job.retained_bytes;
        let mut truncated = job.output_truncated || guest_truncated;
        let mut host_dropped: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM execution_job_events WHERE job_id=?1 AND data IS NULL)",
            [id.to_string()],
            |r| r.get(0),
        )?;
        for event in events {
            if event.sequence == 0
                || event.sequence > MAX_EVENTS
                || event.data.is_empty()
                || event.data.len() > MAX_EVENT_BYTES
                || !matches!(event.stream.as_str(), "stdout" | "stderr")
            {
                return Err(JournalError::Invalid(
                    "invalid event sequence, stream or size",
                ));
            }
            let digest = hex::encode(Sha256::digest(&event.data));
            if event.sequence <= cursor {
                let old = tx.query_row("SELECT stream,digest FROM execution_job_events WHERE job_id=?1 AND sequence=?2",
                    params![id.to_string(), event.sequence as i64], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).optional()?;
                if old != Some((event.stream.clone(), digest)) {
                    return Err(JournalError::Conflict("guest event replay changed"));
                }
                continue;
            }
            if event.sequence != cursor + 1 {
                return Err(JournalError::Invalid("event cursor has a gap"));
            }
            // Prefix retention: after host truncation, never resume retaining.
            let data = if !host_dropped && bytes + event.data.len() <= MAX_OUTPUT_BYTES {
                bytes += event.data.len();
                Some(event.data.as_slice())
            } else {
                truncated = true;
                host_dropped = true;
                None
            };
            tx.execute("INSERT INTO execution_job_events(job_id,sequence,stream,digest,data) VALUES (?1,?2,?3,?4,?5)",
                params![id.to_string(), event.sequence as i64, event.stream, digest, data])?;
            cursor = event.sequence;
        }
        tx.execute("UPDATE execution_jobs SET capture_cursor=?1,retained_bytes=?2,output_truncated=?3 WHERE id=?4",
            params![cursor as i64, bytes as i64, truncated, id.to_string()])?;
        tx.commit()?;
        Ok(())
    }

    /// First terminal publication wins a completion/cancellation race. A
    /// repeated identical publication is idempotent; a changed result conflicts.
    /// Collection completeness is independent of the command's outcome.
    /// Host errors must use `finish_job_failure` to merge staged evidence atomically.
    pub fn finish_job(
        &self,
        id: Uuid,
        state: JobState,
        collection: CollectionState,
        manifest: &str,
    ) -> Result<JobRecord, JournalError> {
        self.finish_job_inner(id, state, collection, manifest, false)
    }

    /// Publish a host-side failure, preserving the latest staged guest receipt
    /// under the same immediate transaction as the first terminal decision.
    /// Callers supply only the bounded host envelope, never a prior guest read.
    /// This cannot publish command success/failure or change a terminal winner.
    pub fn finish_job_failure(
        &self,
        id: Uuid,
        state: JobState,
        envelope: &str,
    ) -> Result<JobRecord, JournalError> {
        if matches!(state, JobState::Completed | JobState::CommandFailed) {
            return Err(JournalError::Invalid(
                "host failure cannot publish a command result",
            ));
        }
        bounded_json(envelope, MAX_MANIFEST_BYTES)?;
        let value: serde_json::Value = serde_json::from_str(envelope)
            .map_err(|_| JournalError::Invalid("invalid failure envelope"))?;
        if [
            "guest_result",
            "guest_result_sha256",
            "guest_result_body_truncated",
        ]
        .iter()
        .any(|key| value.get(key).is_some())
        {
            return Err(JournalError::Invalid(
                "guest receipt fields are journal-owned",
            ));
        }
        self.finish_job_inner(id, state, CollectionState::Failed, envelope, true)
    }

    fn finish_job_inner(
        &self,
        id: Uuid,
        state: JobState,
        collection: CollectionState,
        manifest: &str,
        preserve_staged: bool,
    ) -> Result<JobRecord, JournalError> {
        if !state.terminal() || collection == CollectionState::Pending {
            return Err(JournalError::Invalid(
                "terminal result and explicit collection status required",
            ));
        }
        bounded_json(manifest, MAX_MANIFEST_BYTES)?;
        let mut conn = self.lock_durable()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = get_on(&tx, id)?;
        if old.state.terminal() {
            if preserve_staged {
                return Err(JournalError::Conflict("terminal evidence is immutable"));
            }
            if old.state != state
                || old.collection != collection
                || old.manifest.as_deref() != Some(manifest)
            {
                return Err(JournalError::Conflict("terminal evidence is immutable"));
            }
        } else {
            if matches!(state, JobState::Completed | JobState::CommandFailed)
                && old.state != JobState::Running
            {
                return Err(JournalError::Conflict(
                    "unexecuted job cannot publish command completion",
                ));
            }
            if old.output_truncated && collection == CollectionState::Complete {
                return Err(JournalError::Invalid(
                    "truncated logs cannot be marked complete",
                ));
            }
            let manifest = if preserve_staged {
                let mut envelope: serde_json::Value = serde_json::from_str(manifest)
                    .map_err(|_| JournalError::Invalid("invalid failure envelope"))?;
                if let Some(staged) = &old.manifest {
                    let guest: serde_json::Value = serde_json::from_str(staged)
                        .map_err(|_| JournalError::Invalid("staged guest receipt is unreadable"))?;
                    envelope["guest_result"] = guest;
                    if envelope.to_string().len() > MAX_MANIFEST_BYTES {
                        envelope.as_object_mut().unwrap().remove("guest_result");
                        envelope["guest_result_sha256"] = serde_json::json!(format!(
                            "sha256:{}",
                            hex::encode(Sha256::digest(staged.as_bytes()))
                        ));
                        envelope["guest_result_body_truncated"] = serde_json::json!(true);
                    }
                }
                envelope.to_string()
            } else {
                manifest.to_owned()
            };
            bounded_json(&manifest, MAX_MANIFEST_BYTES)?;
            tx.execute(
                "UPDATE execution_jobs SET state=?1,collection=?2,manifest=?3 WHERE id=?4",
                params![
                    state.as_str(),
                    collection.as_str(),
                    manifest,
                    id.to_string()
                ],
            )?;
        }
        let job = get_on(&tx, id)?;
        tx.commit()?;
        Ok(job)
    }

    pub fn job_events(&self, id: Uuid, after: u64) -> Result<JobEventPage, JournalError> {
        if after > MAX_EVENTS {
            return Err(JournalError::Invalid("event cursor exceeds limit"));
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let job = get_on(&tx, id)?;
        let mut events = {
            let mut stmt = tx.prepare("SELECT sequence,stream,data FROM execution_job_events WHERE job_id=?1 AND sequence>?2 AND data IS NOT NULL ORDER BY sequence LIMIT ?3")?;
            stmt.query_map(
                params![id.to_string(), after as i64, (EVENT_PAGE_SIZE + 1) as i64],
                |r| {
                    Ok(JobEvent {
                        sequence: u64::from(r.get::<_, u32>(0)?),
                        stream: r.get(1)?,
                        data: r.get(2)?,
                    })
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let has_more = events.len() > EVENT_PAGE_SIZE;
        events.truncate(EVENT_PAGE_SIZE);
        let next_cursor = if has_more {
            events.last().map_or(after, |e| e.sequence)
        } else {
            after.max(job.capture_cursor)
        };
        tx.commit()?;
        Ok(JobEventPage {
            job,
            events,
            next_cursor,
            has_more,
        })
    }

    /// Lookup immutable ownership independent of whether the VM row still exists.
    /// Find the unique job that still owns cleanup for this reserved VM name,
    /// including creations that never committed a VM row.
    pub fn job_for_pending_vm_name(&self, name: &str) -> Result<Option<JobRecord>, JournalError> {
        let conn = self.lock()?;
        Ok(conn
            .query_row(
                &format!(
                    "SELECT {COLUMNS} FROM execution_jobs WHERE vm_name=?1 AND cleanup_pending=1"
                ),
                params![name],
                read_record,
            )
            .optional()?)
    }

    pub fn job_for_vm(&self, vm_id: Uuid) -> Result<Option<JobRecord>, JournalError> {
        let conn = self.lock()?;
        Ok(conn
            .query_row(
                &format!(
                    "SELECT {COLUMNS} FROM execution_jobs WHERE vm_id=?1 AND state<>'deleted'"
                ),
                [vm_id.to_string()],
                read_record,
            )
            .optional()?)
    }

    /// Called only after the VMM positively confirms destruction. NotFound or
    /// absence of a VM row is not a destruction receipt. Persist before removing
    /// storage/state so crash recovery can finish cleanup without guessing.
    pub fn record_job_vm_destruction(&self, vm_id: Uuid) -> Result<(), JournalError> {
        let conn = self.lock_durable()?;
        conn.execute(
            "UPDATE execution_jobs SET vm_destroyed=1 WHERE vm_id=?1",
            [vm_id.to_string()],
        )?;
        Ok(())
    }

    /// Only the owner of a completed preparation future may issue this receipt,
    /// and only when it never entered the VM allocation routine. Restart, a
    /// missing row, timeout or a backend error cannot establish this fact.
    pub fn record_job_vm_allocation_abort(
        &self,
        id: Uuid,
        vm_id: Uuid,
    ) -> Result<(), JournalError> {
        let conn = self.lock_durable()?;
        let changed = conn.execute(
            "UPDATE execution_jobs SET vm_allocation_aborted=1 WHERE id=?1 AND vm_id=?2 AND vm_destroyed=0 AND cleanup_pending=1 AND state IN ('preparing','infrastructure_failed','interrupted','cancelled','timed_out','unknown')",
            params![id.to_string(), vm_id.to_string()],
        )?;
        if changed == 0 {
            get_on(&conn, id)?;
            return Err(JournalError::Conflict(
                "allocation abort ownership or state mismatch",
            ));
        }
        Ok(())
    }

    /// Called after the owning preparation future returns before backend entry,
    /// or during exclusive startup recovery when that future cannot still run.
    /// Fence the exact planned lease and journal the abort in one transaction
    /// before any cleanup. A missing VM record alone cannot supply this proof.
    pub fn record_job_leased_prebackend_abort(
        &self,
        id: Uuid,
        vm_id: Uuid,
        lease_id: Uuid,
    ) -> Result<(), JournalError> {
        let mut conn = self.lock_durable()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let job = get_on(&tx, id)?;
        let name = format!("job-{id}");
        if job.vm_id != Some(vm_id)
            || job.vm_name.as_deref() != Some(&name)
            || job.vm_destroyed
            || !job.cleanup_pending
            || !matches!(
                job.state,
                JobState::Preparing
                    | JobState::InfrastructureFailed
                    | JobState::Interrupted
                    | JobState::Cancelled
                    | JobState::TimedOut
                    | JobState::Unknown
            )
        {
            return Err(JournalError::Conflict(
                "pre-backend abort job ownership mismatch",
            ));
        }
        let has_conflict: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM vms WHERE id=?1 OR name=?2) OR EXISTS(SELECT 1 FROM host_resource_leases WHERE id<>?3 AND (vm_id=?1 OR vm_name=?2))",
            params![vm_id.to_string(), name, lease_id.to_string()],
            |row| row.get(0),
        )?;
        if has_conflict || tx.execute("UPDATE host_resource_leases SET allocation_aborted=1 WHERE id=?1 AND vm_name=?2 AND vm_id=?3 AND backend_entered=0 AND vm_destroyed=0",
            params![lease_id.to_string(), name, vm_id.to_string()])? != 1 {
            return Err(JournalError::Conflict("exact unentered creation lease required"));
        }
        tx.execute(
            "UPDATE execution_jobs SET vm_allocation_aborted=1 WHERE id=?1",
            [id.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Clear only after destruction or allocation abort was confirmed. This
    /// separate flag permits repeated cleanup attempts after terminal status.
    pub fn confirm_job_cleanup(&self, id: Uuid, vm_id: Uuid) -> Result<(), JournalError> {
        let conn = self.lock_durable()?;
        let changed = conn.execute("UPDATE execution_jobs SET cleanup_pending=0 WHERE id=?1 AND vm_id=?2 AND (vm_destroyed=1 OR vm_allocation_aborted=1) AND state NOT IN ('accepted','preparing','running','deleted')",
            params![id.to_string(), vm_id.to_string()])?;
        if changed == 0 {
            get_on(&conn, id)?;
            return Err(JournalError::Conflict(
                "cleanup generation or terminal state mismatch",
            ));
        }
        Ok(())
    }

    /// Release an allocation reservation only after the owning creation task
    /// has ended (or daemon restart), and the orchestrator has verified absence
    /// of the reserved VM, VMM processes and storage. A name lookup alone while
    /// creation is in flight is insufficient. Bound generations use UUID cleanup.
    pub fn confirm_unallocated_job_cleanup(
        &self,
        id: Uuid,
        name: &str,
    ) -> Result<(), JournalError> {
        let conn = self.lock_durable()?;
        let changed = conn.execute(
            "UPDATE execution_jobs SET cleanup_pending=0 WHERE id=?1 AND vm_id IS NULL AND vm_name=?2 AND state NOT IN ('accepted','preparing','running','deleted')",
            params![id.to_string(), name],
        )?;
        if changed == 0 {
            get_on(&conn, id)?;
            return Err(JournalError::Conflict(
                "unallocated cleanup ownership or terminal state mismatch",
            ));
        }
        Ok(())
    }

    /// Read all records needing reconciliation/cleanup, ordered and bounded by
    /// the retained-job capacity. Never infer execution success from absence.
    pub fn recoverable_jobs(&self) -> Result<Vec<JobRecord>, JournalError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(&format!("SELECT {COLUMNS} FROM execution_jobs WHERE state IN ('accepted','preparing','running') OR cleanup_pending=1 ORDER BY created_at,id"))?;
        Ok(stmt
            .query_map([], read_record)?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Explicit deletion or retention expiry removes evidence but keeps a
    /// bounded submission tombstone. Cleanup ownership must never be erased.
    pub fn delete_job_evidence(&self, id: Uuid) -> Result<(), JournalError> {
        let mut conn = self.lock_durable()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let job = get_on(&tx, id)?;
        if !job.state.terminal() || job.cleanup_pending {
            return Err(JournalError::Conflict(
                "active execution or unconfirmed VM cleanup",
            ));
        }
        tx.execute(
            "DELETE FROM execution_job_artifacts WHERE job_id=?1",
            [id.to_string()],
        )?;
        tx.execute(
            "DELETE FROM execution_job_events WHERE job_id=?1",
            [id.to_string()],
        )?;
        tx.execute("UPDATE execution_jobs SET state='deleted',specification=NULL,manifest=NULL,capture_cursor=0,retained_bytes=0 WHERE id=?1", [id.to_string()])?;
        tx.commit()?;
        Ok(())
    }

    pub fn expire_job_evidence(&self, now: DateTime<Utc>) -> Result<usize, JournalError> {
        let ids = {
            let conn = self.lock()?;
            let mut stmt = conn.prepare("SELECT id FROM execution_jobs WHERE state NOT IN ('accepted','preparing','running','deleted') AND cleanup_pending=0 AND retention_until<=?1")?;
            stmt.query_map([now.timestamp()], |r| uuid(r.get(0)?))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for id in &ids {
            self.delete_job_evidence(*id)?;
        }
        Ok(ids.len())
    }
}
