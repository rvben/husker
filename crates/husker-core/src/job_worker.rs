//! Client-independent factory execution. Replays never create another worker.
use std::{future::Future, sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use husker_agent_proto::{SessionState, frozen_bundle::FrozenBundle, job_spec::JobSubmission};
pub use husker_state::jobs::{
    CollectionState, JobArtifactRecord, JobEventPage, JobRecord, JobState, JournalError,
};
use husker_vmm::VmmBackend;
use uuid::Uuid;

use crate::HuskerCore;

fn try_seal(
    store: &husker_state::StateStore,
    id: Uuid,
    state: JobState,
    error: &str,
) -> Result<JobRecord, JournalError> {
    let manifest = serde_json::json!({
        "host_error": error.chars().take(512).collect::<String>(),
        "collection": "failed",
        "retained_output": "journaled prefix; final tail may be unavailable"
    });
    store.finish_job_failure(id, state, &manifest.to_string())
}

fn seal(store: &husker_state::StateStore, id: Uuid, state: JobState, error: &str) {
    // The first terminal decision wins, including concurrent collection/cancel.
    match try_seal(store, id, state, error) {
        Ok(_) => (),
        Err(JournalError::Conflict(reason)) => tracing::debug!(%id, reason,
            "factory terminal publication did not replace prior decision"),
        Err(error) => tracing::warn!(%id, %error,
            "factory terminal publication failed; durable outcome remains unresolved"),
    }
}

/// Dropping a staging/observation future is safe only because exact-generation
/// VM destruction follows. Allocation instead must be awaited after interruption.
async fn interruptible<F: Future>(
    future: F,
    stop: impl Future<Output = ()>,
    join: bool,
) -> Option<F::Output> {
    tokio::pin!(future);
    tokio::pin!(stop);
    tokio::select! {
        biased;
        _ = &mut stop => {
            if join { let _ = future.await; }
            None
        }
        result = &mut future => Some(result),
    }
}

async fn monitor_stop(store: &husker_state::StateStore, id: Uuid) {
    loop {
        let job = match store.get_job(id) {
            Ok(job) => job,
            Err(_) => return,
        };
        if job.state.terminal() {
            return;
        }
        let remaining = crate::job_launch::remaining_deadline(job.deadline);
        if remaining.is_zero() {
            seal(
                store,
                id,
                JobState::TimedOut,
                "absolute factory deadline expired",
            );
            return;
        }
        tokio::time::sleep(remaining.min(Duration::from_millis(100))).await;
    }
}

/// Safe recovery never resumes guest execution, even for Accepted receipts.
/// Call only under exclusive daemon ownership, before serving requests or
/// starting this incarnation's workers. The old allocator must no longer run.
fn recover_after_restart(store: &husker_state::StateStore) -> Result<usize, JournalError> {
    let mut interrupted = 0;
    for job in store.recoverable_jobs()? {
        if job.state.terminal() {
            continue;
        }
        let outcome = if crate::job_launch::remaining_deadline(job.deadline).is_zero() {
            JobState::TimedOut
        } else if job.state == JobState::Accepted {
            JobState::Interrupted
        } else {
            JobState::Unknown
        };
        seal(
            store,
            job.id,
            outcome,
            "daemon restarted; execution will not be resubmitted; confirmed VM cleanup required",
        );
        if !store.get_job(job.id)?.state.terminal() {
            return Err(JournalError::Conflict("restart outcome was not persisted"));
        }
        interrupted += 1;
    }
    // The daemon lock excludes an old storage future. Durable backend entry is
    // written before invoking the VMM, so this exact unentered lease can be
    // fenced without inferring destruction from a missing VM record or PID.
    for lease in store.list_host_resource_leases()? {
        if lease.backend_entered || lease.vm_destroyed || lease.vm_id.is_none() {
            continue;
        }
        let Some(job) = store.job_for_pending_vm_name(&lease.vm_name)? else {
            continue;
        };
        if !job.state.terminal() || job.vm_id != lease.vm_id {
            continue;
        }
        match store.record_job_leased_prebackend_abort(job.id, lease.vm_id.unwrap(), lease.id) {
            Ok(()) => tracing::info!(job = %job.id, lease = %lease.id,
                "fenced interrupted factory allocation before backend entry"),
            Err(JournalError::Conflict(reason)) => tracing::warn!(job = %job.id,
                lease = %lease.id, reason, "preserving conflicting interrupted factory lease"),
            Err(error) => return Err(error),
        }
    }
    Ok(interrupted)
}

#[derive(Debug, Default)]
pub struct FactoryCleanupReport {
    pub attempted: usize,
    pub confirmed: usize,
    pub pending: usize,
    pub expired_evidence: usize,
    pub outcomes_reconciled: usize,
    pub outcome_publication_pending: usize,
    pub allocation_aborts_confirmed: usize,
    pub allocation_aborts_pending: usize,
}

type OwnedWorker = (Uuid, tokio::task::JoinHandle<()>);

type WorkerRegistry =
    parking_lot::Mutex<std::collections::HashMap<Uuid, tokio::task::JoinHandle<()>>>;

struct JoiningWorkers<'a> {
    registry: &'a WorkerRegistry,
    workers: Vec<OwnedWorker>,
}
impl Drop for JoiningWorkers<'_> {
    fn drop(&mut self) {
        // Also restores handles when the joining future itself is cancelled.
        self.registry
            .lock()
            .extend(std::mem::take(&mut self.workers));
    }
}
async fn join_registered_workers(registry: &WorkerRegistry, grace: Duration) -> (usize, usize) {
    let mut batch = JoiningWorkers {
        registry,
        workers: registry.lock().drain().collect(),
    };
    let deadline = tokio::time::Instant::now() + grace;
    let mut joined = 0;
    let mut index = 0;
    while index < batch.workers.len() {
        match tokio::time::timeout_at(deadline, &mut batch.workers[index].1).await {
            Ok(result) => {
                let (id, handle) = batch.workers.remove(index);
                drop(handle); // A completed JoinHandle must never be polled twice.
                joined += 1;
                if let Err(error) = result {
                    tracing::warn!(%id, %error, "factory worker failed while joining shutdown");
                }
            }
            Err(_) => index += 1, // Never abort late allocation.
        }
    }
    (joined, batch.workers.len())
}

#[derive(Default)]
struct WorkerReconciliation {
    reconciled: usize,
    pending: usize,
    aborts_confirmed: usize,
    aborts_pending: usize,
}

fn worker_ownership_resolved(store: &husker_state::StateStore, id: Uuid) -> bool {
    store
        .get_job(id)
        .is_ok_and(|job| job.state.terminal() && !job.cleanup_pending)
}

/// Only a registered handle observed finished proves this daemon's worker has
/// stopped. Missing handles and live allocations never authorize reconciliation.
fn reconcile_finished_workers(
    store: &husker_state::StateStore,
    registry: &WorkerRegistry,
) -> WorkerReconciliation {
    let finished: Vec<_> = registry
        .lock()
        .iter()
        .filter(|(_, handle)| handle.is_finished())
        .map(|(id, _)| *id)
        .collect();
    let mut report = WorkerReconciliation::default();
    for id in finished {
        let job = match store.get_job(id) {
            Ok(job) => job,
            Err(error) => {
                report.pending += 1;
                tracing::warn!(%id, %error, "finished factory worker receipt unavailable; ownership retained");
                continue;
            }
        };
        if !job.state.terminal() {
            let outcome = if crate::job_launch::remaining_deadline(job.deadline).is_zero() {
                JobState::TimedOut
            } else if job.state == JobState::Accepted {
                JobState::Interrupted
            } else {
                JobState::Unknown
            };
            match try_seal(
                store,
                id,
                outcome,
                "owned worker finished without durable terminal publication; execution will not be resubmitted",
            ) {
                Ok(_) => report.reconciled += 1,
                Err(JournalError::Conflict(_))
                    if store.get_job(id).is_ok_and(|job| job.state.terminal()) => {}
                Err(error) => {
                    report.pending += 1;
                    tracing::warn!(%id, %error, "finished factory worker terminal publication pending; ownership retained");
                    continue;
                }
            }
        }
        let abort = (|| -> Result<usize, JournalError> {
            let job = store.get_job(id)?;
            if !job.cleanup_pending || job.vm_destroyed || job.vm_allocation_aborted {
                return Ok(0);
            }
            let Some(vm_id) = job.vm_id else {
                return Ok(0);
            };
            let name = format!("job-{id}");
            if job.vm_name.as_deref() != Some(&name) {
                return Ok(0);
            }
            for lease in store.list_host_resource_leases()? {
                if lease.vm_name != name
                    || lease.vm_id != Some(vm_id)
                    || lease.backend_entered
                    || lease.vm_destroyed
                {
                    continue;
                }
                // The registered allocator has positively finished. Fence only
                // this exact unentered generation, never an absent/foreign VM.
                store.record_job_leased_prebackend_abort(id, vm_id, lease.id)?;
                return Ok(1);
            }
            Ok(0)
        })();
        match abort {
            Ok(count) => report.aborts_confirmed += count,
            Err(error) => {
                report.aborts_pending += 1;
                tracing::warn!(%id, %error, "finished factory allocation abort remains pending; ownership retained");
            }
        }
    }
    // Retain completion proof through pending abort/destruction/file cleanup.
    registry
        .lock()
        .retain(|id, handle| !handle.is_finished() || !worker_ownership_resolved(store, *id));
    report
}

#[derive(Debug)]
pub struct FactoryShutdownReport {
    pub workers_joined: usize,
    pub workers_pending: usize,
    pub cleanup_pending: usize,
}

impl<B: VmmBackend + 'static> HuskerCore<B> {
    /// Called as soon as shutdown starts, including while HTTP connections drain.
    pub fn close_factory_admission(&self) {
        *self.factory_admission.lock() = false;
    }

    /// Close admission atomically with submission's accept/register handoff, seal
    /// active decisions, and join owned workers before generic VM drain. Timed-out
    /// workers remain registered, never aborted or reported as cleaned up.
    pub async fn shutdown_factory_jobs(
        &self,
        grace: Duration,
    ) -> Result<FactoryShutdownReport, JournalError> {
        let _shutdown = self.factory_shutdown_lock.lock().await;
        self.close_factory_admission();
        // A journal failure must not bypass joining already owned tasks.
        let decisions = (|| -> Result<(), JournalError> {
            for job in self.state.recoverable_jobs()? {
                if !job.state.terminal() {
                    let outcome = if crate::job_launch::remaining_deadline(job.deadline).is_zero() {
                        JobState::TimedOut
                    } else {
                        JobState::Interrupted
                    };
                    seal(
                        &self.state,
                        job.id,
                        outcome,
                        "daemon shutdown interrupted execution; final cleanup receipt required",
                    );
                    if !self.state.get_job(job.id)?.state.terminal() {
                        return Err(JournalError::Conflict("shutdown outcome was not persisted"));
                    }
                }
            }
            Ok(())
        })();
        let (joined, count) = join_registered_workers(&self.factory_workers, grace).await;
        if count > 0 {
            tracing::warn!(
                pending = count,
                "factory workers remain owned beyond shutdown grace"
            );
        }
        decisions?;
        Ok(FactoryShutdownReport {
            workers_joined: joined,
            workers_pending: count,
            cleanup_pending: self
                .state
                .recoverable_jobs()?
                .iter()
                .filter(|job| job.cleanup_pending)
                .count(),
        })
    }

    /// Startup-only, while holding the exclusive daemon lock, before API
    /// ingress. No session start, allocation or guest command is issued. Exact
    /// unentered leases are fenced; entered leases still require destruction.
    pub fn recover_factory_jobs_after_restart(&self) -> Result<usize, JournalError> {
        let _shutdown = self.factory_shutdown_lock.try_lock().map_err(|_| {
            JournalError::Conflict("restart recovery cannot race owned worker shutdown")
        })?;
        let _admission = self.factory_admission.lock();
        if !self.factory_workers.lock().is_empty() {
            return Err(JournalError::Conflict(
                "restart recovery requires no owned workers",
            ));
        }
        recover_after_restart(&self.state)
    }

    /// Retry at most four terminal owners per tick, with fair rotation and a
    /// bounded attempt. Cancellation of destruction leaves its durable receipt
    /// pending; backend handles/UUID ownership must survive that cancellation.
    pub async fn factory_cleanup_tick(&self) -> Result<FactoryCleanupReport, JournalError> {
        use futures_util::{StreamExt, stream};
        let outcomes = {
            // Submission holds this through accept/register. No async work under
            // the lock; late allocations remain registered and excluded above.
            let _admission = self.factory_admission.lock();
            reconcile_finished_workers(&self.state, &self.factory_workers)
        };
        let pending: Vec<_> = self
            .state
            .recoverable_jobs()?
            .into_iter()
            .filter(|job| job.state.terminal() && job.cleanup_pending)
            .collect();
        let mut report = FactoryCleanupReport {
            outcomes_reconciled: outcomes.reconciled,
            outcome_publication_pending: outcomes.pending,
            allocation_aborts_confirmed: outcomes.aborts_confirmed,
            allocation_aborts_pending: outcomes.aborts_pending,
            ..Default::default()
        };
        if !pending.is_empty() {
            let start = self
                .factory_cleanup_cursor
                .fetch_add(4, std::sync::atomic::Ordering::Relaxed)
                % pending.len();
            let ids: Vec<_> = pending
                .iter()
                .cycle()
                .skip(start)
                .take(pending.len().min(4))
                .map(|job| job.id)
                .collect();
            report.attempted = ids.len();
            let results = stream::iter(ids.into_iter().map(|id| async move {
                match tokio::time::timeout(Duration::from_secs(15), self.cleanup_job_vm(id)).await {
                    Ok(Ok(())) => true,
                    Ok(Err(error)) => {
                        tracing::warn!(%id, %error, "factory cleanup retry remains pending");
                        false
                    }
                    Err(_) => {
                        tracing::warn!(%id, "factory cleanup retry timed out; ownership retained");
                        false
                    }
                }
            }))
            .buffer_unordered(4)
            .collect::<Vec<_>>()
            .await;
            report.confirmed = results.into_iter().filter(|confirmed| *confirmed).count();
        }
        report.pending = self
            .state
            .recoverable_jobs()?
            .iter()
            .filter(|job| job.cleanup_pending)
            .count();
        // Only cleanup-confirmed terminal evidence is eligible for expiry.
        report.expired_evidence = self.state.expire_job_evidence(Utc::now())?;
        Ok(report)
    }

    pub fn find_factory_job_submission(
        &self,
        key: &str,
        digest: &str,
    ) -> Result<JobRecord, JournalError> {
        self.state.find_job_submission(key, digest)
    }

    pub fn inspect_factory_job(&self, id: Uuid) -> Result<JobRecord, JournalError> {
        self.state.get_job(id)
    }
    pub fn factory_job_events(&self, id: Uuid, after: u64) -> Result<JobEventPage, JournalError> {
        self.state.job_events(id, after)
    }
    pub fn factory_job_artifacts(&self, id: Uuid) -> Result<Vec<JobArtifactRecord>, JournalError> {
        self.state.job_artifacts(id)
    }
    pub fn factory_job_artifact(&self, id: Uuid, index: usize) -> Result<Vec<u8>, JournalError> {
        self.state.job_artifact(id, index)
    }
    pub fn delete_factory_job_evidence(&self, id: Uuid) -> Result<(), JournalError> {
        self.state.delete_job_evidence(id)
    }

    /// Validate frozen inputs, commit acceptance, and transfer execution ownership
    /// to Tokio before returning. Only newly accepted submissions may launch.
    /// The caller must enforce operator authorization/resource/image/env policy.
    /// No startup recovery path may resubmit retained Accepted/Preparing jobs.
    pub fn submit_factory_job(
        self: &Arc<Self>,
        submission: &JobSubmission,
        source: FrozenBundle,
        acceptance: FrozenBundle,
        retention_until: DateTime<Utc>,
    ) -> Result<(JobRecord, bool), JournalError> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| JournalError::Invalid("factory worker requires a daemon runtime"))?;
        let specification = submission
            .canonical_specification()
            .map_err(|_| JournalError::Invalid("invalid factory specification"))?;
        let spec = &submission.specification;
        if source.digest() != spec.source.digest
            || source.bytes().len() as u64 != spec.source.size_bytes
            || acceptance.digest() != spec.acceptance.digest
            || acceptance.bytes().len() as u64 != spec.acceptance.size_bytes
            || spec.writable_directories.iter().any(|directory| {
                source.files().keys().any(|path| {
                    path == directory
                        || path.starts_with(&format!("{directory}/"))
                        || directory.starts_with(&format!("{path}/"))
                })
            })
        {
            return Err(JournalError::Invalid(
                "frozen factory inputs do not match specification",
            ));
        }
        let admission = self.factory_admission.lock();
        if !*admission {
            return Err(JournalError::Capacity(
                "factory admission closed for daemon shutdown",
            ));
        }
        let budget = self
            .factory_resource_budget
            .as_ref()
            .ok_or(JournalError::Capacity(
                "factory resource budget must be configured",
            ))?;
        let (job, fresh) = self.state.accept_job_with_budget(
            &submission.idempotency_key,
            &specification,
            spec.deadline,
            retention_until,
            budget,
            || {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    let observe = |path: &std::path::Path| {
                        husker_storage::available_directory_bytes(path).map_err(|_| {
                            JournalError::Capacity("factory storage observation failed")
                        })
                    };
                    Ok(husker_state::jobs::FactoryAvailableStorage {
                        shared_filesystem: std::fs::metadata(&self.storage.data_dir)
                            .and_then(|boot| {
                                std::fs::metadata(&self.storage.state_dir)
                                    .map(|journal| boot.dev() == journal.dev())
                            })
                            .map_err(|_| {
                                JournalError::Capacity("factory storage observation failed")
                            })?,
                        boot_bytes: observe(&self.storage.data_dir)?,
                        journal_bytes: observe(&self.storage.state_dir)?,
                    })
                }
                #[cfg(not(unix))]
                Err(JournalError::Capacity(
                    "factory storage observation unsupported",
                ))
            },
        )?;
        if fresh {
            let slot = match Arc::clone(&self.factory_worker_slots).try_acquire_owned() {
                Ok(slot) => slot,
                Err(_) => {
                    // A terminal allocation may still be joining a backend call.
                    // Preserve the accepted identity without starting more work.
                    seal(
                        &self.state,
                        job.id,
                        JobState::InfrastructureFailed,
                        "factory worker capacity exhausted; execution never started",
                    );
                    return Ok((self.state.get_job(job.id)?, true));
                }
            };
            let core = Arc::clone(self);
            let id = job.id;
            // Registration is guarded with acceptance, independent of HTTP lifetime.
            let handle = runtime.spawn(async move {
                let _slot = slot;
                use futures_util::FutureExt;
                let result = std::panic::AssertUnwindSafe(core.run_factory_job(id, source, acceptance))
                    .catch_unwind().await;
                if result.is_err() {
                    seal(&core.state, id, JobState::Unknown, "factory worker panicked; execution unresolved");
                }
                if let Err(error) = core.cleanup_job_vm(id).await {
                    tracing::warn!(%id, %error, "factory cleanup remains pending for reconciliation");
                }
            });
            let mut workers = self.factory_workers.lock();
            workers.retain(|id, handle| {
                !handle.is_finished() || !worker_ownership_resolved(&self.state, *id)
            });
            workers.insert(id, handle);
        }
        Ok((job, fresh))
    }

    /// Acknowledgement is durable; cleanup completion is a separate receipt.
    /// Previously captured bytes survive. Cancellation seals an explicit failed
    /// collection rather than claiming that unobserved final output was retained.
    pub fn cancel_factory_job(&self, id: Uuid) -> Result<JobRecord, JournalError> {
        let old = self.state.get_job(id)?;
        if old.state.terminal() {
            return Ok(old);
        }
        seal(
            &self.state,
            id,
            JobState::Cancelled,
            "cancelled by client; VM destruction required",
        );
        let job = self.state.get_job(id)?;
        if !job.state.terminal() {
            return Err(JournalError::Conflict("cancellation was not persisted"));
        }
        Ok(job)
    }

    async fn factory_stop(&self, id: Uuid) {
        monitor_stop(&self.state, id).await;
    }

    async fn run_factory_job(&self, id: Uuid, source: FrozenBundle, acceptance: FrozenBundle) {
        let allocated =
            interruptible(self.create_reserved_job_vm(id), self.factory_stop(id), true).await;
        match allocated {
            Some(Ok(_)) => (),
            Some(Err(error)) => {
                seal(
                    &self.state,
                    id,
                    JobState::InfrastructureFailed,
                    &error.to_string(),
                );
                return;
            }
            None => return,
        }
        let launched = interruptible(
            self.launch_prepared_job(id, &source, &acceptance),
            self.factory_stop(id),
            false,
        )
        .await;
        if launched.is_none() {
            return;
        }
        let launch_error = launched
            .and_then(Result::err)
            .map(|error| error.to_string());
        // A lost start acknowledgement is observed through the durable session,
        // never by issuing another start. Pre-start failures are already sealed.
        loop {
            let job = match self.state.get_job(id) {
                Ok(job) => job,
                Err(_) => return,
            };
            if job.state.terminal() {
                return;
            }
            if job.state != JobState::Running {
                seal(
                    &self.state,
                    id,
                    JobState::InfrastructureFailed,
                    launch_error
                        .as_deref()
                        .unwrap_or("launch ended without a running receipt"),
                );
                return;
            }
            let observed =
                interruptible(self.capture_job_output(id), self.factory_stop(id), false).await;
            match observed {
                None => return,
                Some(Ok(session)) if session.state != SessionState::Running => {
                    let _ =
                        interruptible(self.collect_job_evidence(id), self.factory_stop(id), false)
                            .await;
                    if self
                        .state
                        .get_job(id)
                        .is_ok_and(|job| !job.state.terminal())
                    {
                        seal(
                            &self.state,
                            id,
                            JobState::Unknown,
                            "terminal helper evidence could not be published",
                        );
                    }
                    return;
                }
                _ => (), // Transient observation errors preserve the cursor.
            }
            if interruptible(
                tokio::time::sleep(Duration::from_millis(200)),
                self.factory_stop(id),
                false,
            )
            .await
            .is_none()
            {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn interrupted_allocation_is_joined_before_cleanup_can_follow() {
        let (finish, receiver) = tokio::sync::oneshot::channel();
        let (started, start) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(async move {
            interruptible(
                async {
                    started.send(()).unwrap();
                    receiver.await.unwrap()
                },
                async { tokio::time::sleep(Duration::from_millis(10)).await },
                true,
            )
            .await
        });
        start.await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !worker.is_finished(),
            "cancel must not abandon late allocation"
        );
        finish.send(42).unwrap();
        assert_eq!(worker.await.unwrap(), None);
    }
    #[tokio::test]
    async fn observation_is_dropped_on_interruption() {
        let result = interruptible(std::future::pending::<()>(), async {}, false).await;
        assert_eq!(result, None);
    }
    #[tokio::test]
    async fn deadline_is_persisted_without_client_or_guest_activity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jobs.db");
        let store = husker_state::StateStore::open(&path).unwrap();
        let deadline = chrono::DateTime::from_timestamp(Utc::now().timestamp() + 1, 0).unwrap();
        let (job, _) = store
            .accept_job(
                "deadline",
                "{}",
                deadline,
                deadline + chrono::Duration::hours(1),
            )
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), monitor_stop(&store, job.id))
            .await
            .unwrap();
        drop(store);
        let reopened = husker_state::StateStore::open(&path).unwrap();
        let result = reopened.get_job(job.id).unwrap();
        assert_eq!(result.state, JobState::TimedOut);
        assert_eq!(result.collection, CollectionState::Failed);
        assert!(
            result
                .manifest
                .unwrap()
                .contains("final tail may be unavailable")
        );
        seal(&reopened, job.id, JobState::Cancelled, "late cancellation");
        assert_eq!(reopened.get_job(job.id).unwrap().state, JobState::TimedOut);
    }
    #[test]
    fn restart_seals_receipts_preserves_prefix_and_staged_evidence_without_reexecution() {
        use husker_state::jobs::JobEvent;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("restart.db");
        let store = husker_state::StateStore::open(&path).unwrap();
        let deadline = chrono::DateTime::from_timestamp(Utc::now().timestamp() + 60, 0).unwrap();
        let accepted = store
            .accept_job(
                "accepted",
                "{}",
                deadline,
                deadline + chrono::Duration::hours(1),
            )
            .unwrap()
            .0;
        let preparing = store
            .accept_job(
                "preparing",
                "{}",
                deadline,
                deadline + chrono::Duration::hours(1),
            )
            .unwrap()
            .0;
        store.claim_job_vm(preparing.id).unwrap();
        let running = store
            .accept_job(
                "running",
                "{}",
                deadline,
                deadline + chrono::Duration::hours(1),
            )
            .unwrap()
            .0;
        store
            .bind_job_vm(running.id, Uuid::new_v4(), &format!("job-{}", running.id))
            .unwrap();
        store.mark_job_running(running.id).unwrap();
        store
            .append_job_events(
                running.id,
                &[JobEvent {
                    sequence: 1,
                    stream: "stdout".into(),
                    data: vec![0, 255],
                }],
                false,
            )
            .unwrap();
        store
            .stage_job_manifest(running.id, "{\"staged\":true}")
            .unwrap();
        let completed = store
            .accept_job(
                "completed",
                "{}",
                deadline,
                deadline + chrono::Duration::hours(1),
            )
            .unwrap()
            .0;
        store
            .bind_job_vm(
                completed.id,
                Uuid::new_v4(),
                &format!("job-{}", completed.id),
            )
            .unwrap();
        store.mark_job_running(completed.id).unwrap();
        store
            .finish_job(
                completed.id,
                JobState::Completed,
                CollectionState::Complete,
                "{\"completed\":true}",
            )
            .unwrap();
        drop(store);
        let reopened = husker_state::StateStore::open(&path).unwrap();
        assert_eq!(recover_after_restart(&reopened).unwrap(), 3);
        assert_eq!(recover_after_restart(&reopened).unwrap(), 0);
        assert_eq!(
            reopened.get_job(accepted.id).unwrap().state,
            JobState::Interrupted
        );
        let preparing = reopened.get_job(preparing.id).unwrap();
        assert_eq!(preparing.state, JobState::Unknown);
        assert!(preparing.cleanup_pending);
        assert_eq!(preparing.vm_id, None);
        let running = reopened.get_job(running.id).unwrap();
        assert_eq!(running.state, JobState::Unknown);
        assert_eq!(running.collection, CollectionState::Failed);
        assert!(running.cleanup_pending);
        assert!(!running.vm_destroyed);
        let manifest: serde_json::Value =
            serde_json::from_str(running.manifest.as_ref().unwrap()).unwrap();
        assert_eq!(manifest["guest_result"]["staged"], true);
        assert_eq!(
            reopened.job_events(running.id, 0).unwrap().events[0].data,
            vec![0, 255]
        );
        let completed = reopened.get_job(completed.id).unwrap();
        assert_eq!(completed.state, JobState::Completed);
        assert_eq!(completed.manifest.as_deref(), Some("{\"completed\":true}"));
        let (replay, fresh) = reopened
            .accept_job(
                "running",
                "{}",
                deadline,
                deadline + chrono::Duration::hours(1),
            )
            .unwrap();
        assert!(!fresh);
        assert_eq!(replay.id, running.id);
        assert_eq!(replay.state, JobState::Unknown);
        assert!(reopened.delete_job_evidence(running.id).is_err());
    }
    #[test]
    fn failure_envelope_explicitly_hashes_a_staged_manifest_that_exceeds_its_bound() {
        let store = husker_state::StateStore::open_memory().unwrap();
        let deadline = chrono::DateTime::from_timestamp(Utc::now().timestamp() + 60, 0).unwrap();
        let job = store
            .accept_job(
                "large-stage",
                "{}",
                deadline,
                deadline + chrono::Duration::hours(1),
            )
            .unwrap()
            .0;
        store
            .bind_job_vm(job.id, Uuid::new_v4(), &format!("job-{}", job.id))
            .unwrap();
        store.mark_job_running(job.id).unwrap();
        let staged = serde_json::json!({"payload": "x".repeat(65500)}).to_string();
        store.stage_job_manifest(job.id, &staged).unwrap();
        seal(
            &store,
            job.id,
            JobState::Unknown,
            "daemon restarted during evidence export",
        );
        let result = store.get_job(job.id).unwrap();
        assert_eq!(result.state, JobState::Unknown);
        let manifest = result.manifest.unwrap();
        assert!(manifest.len() <= 64 * 1024);
        let manifest: serde_json::Value = serde_json::from_str(&manifest).unwrap();
        assert_eq!(manifest["guest_result_body_truncated"], true);
        use sha2::Digest;
        assert_eq!(
            manifest["guest_result_sha256"],
            format!(
                "sha256:{}",
                hex::encode(sha2::Sha256::digest(staged.as_bytes()))
            )
        );
        assert!(manifest.get("guest_result").is_none());
        assert_eq!(result.collection, CollectionState::Failed);
    }
    #[tokio::test]
    async fn restart_after_deadline_records_timeout_without_claiming_destruction() {
        let store = husker_state::StateStore::open_memory().unwrap();
        let deadline = chrono::DateTime::from_timestamp(Utc::now().timestamp() + 1, 0).unwrap();
        let job = store
            .accept_job(
                "expired-restart",
                "{}",
                deadline,
                deadline + chrono::Duration::hours(1),
            )
            .unwrap()
            .0;
        let vm_id = Uuid::new_v4();
        store
            .bind_job_vm(job.id, vm_id, &format!("job-{}", job.id))
            .unwrap();
        tokio::time::sleep(
            crate::job_launch::remaining_deadline(job.deadline) + Duration::from_millis(10),
        )
        .await;
        assert_eq!(recover_after_restart(&store).unwrap(), 1);
        let result = store.get_job(job.id).unwrap();
        assert_eq!(result.state, JobState::TimedOut);
        assert_eq!(result.vm_id, Some(vm_id));
        assert_eq!(result.collection, CollectionState::Failed);
        assert!(result.cleanup_pending);
        assert!(!result.vm_destroyed);
    }
    #[tokio::test]
    async fn finished_worker_publication_retries_after_journal_failure_without_losing_evidence_or_vm_owner()
     {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("publication.sqlite");
        let store = husker_state::StateStore::open(&path).unwrap();
        let deadline = Utc::now() + chrono::Duration::hours(1);
        let job = store
            .accept_job(
                "publication",
                "{}",
                deadline,
                deadline + chrono::Duration::hours(1),
            )
            .unwrap()
            .0;
        let vm_id = Uuid::new_v4();
        store
            .bind_job_vm(job.id, vm_id, &format!("job-{}", job.id))
            .unwrap();
        store.mark_job_running(job.id).unwrap();
        store
            .append_job_events(
                job.id,
                &[husker_state::jobs::JobEvent {
                    sequence: 1,
                    stream: "stdout".into(),
                    data: b"committed prefix".to_vec(),
                }],
                false,
            )
            .unwrap();
        store
            .stage_job_manifest(job.id, "{\"guest\":\"staged receipt\"}")
            .unwrap();
        let independent = store
            .accept_job(
                "independent-publication",
                "{}",
                deadline,
                deadline + chrono::Duration::hours(1),
            )
            .unwrap()
            .0;
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection.execute_batch(&format!("CREATE TRIGGER fail_terminal_publication BEFORE UPDATE OF state ON execution_jobs WHEN OLD.id='{}' BEGIN SELECT RAISE(ABORT, 'synthetic publication write failure'); END;", job.id)).unwrap();
        let worker = tokio::spawn(async {});
        let registry = WorkerRegistry::new(std::collections::HashMap::from([
            (job.id, worker),
            (independent.id, tokio::spawn(async {})),
        ]));
        tokio::time::timeout(Duration::from_secs(1), async {
            while registry.lock().values().any(|handle| !handle.is_finished()) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let blocked = reconcile_finished_workers(&store, &registry);
        assert_eq!(blocked.pending, 1);
        assert_eq!(blocked.reconciled, 1);
        assert_eq!(
            store.get_job(independent.id).unwrap().state,
            JobState::Interrupted
        );
        assert!(!registry.lock().contains_key(&independent.id));
        assert!(registry.lock()[&job.id].is_finished());
        let unresolved = store.get_job(job.id).unwrap();
        assert_eq!(unresolved.state, JobState::Running);
        assert_eq!(unresolved.vm_id, Some(vm_id));
        assert!(unresolved.cleanup_pending);
        assert!(!unresolved.vm_destroyed);
        connection
            .execute_batch("DROP TRIGGER fail_terminal_publication;")
            .unwrap();
        assert_eq!(reconcile_finished_workers(&store, &registry).reconciled, 1);
        assert!(registry.lock()[&job.id].is_finished());
        assert_eq!(reconcile_finished_workers(&store, &registry).reconciled, 0);
        let sealed = store.get_job(job.id).unwrap();
        assert_eq!(sealed.state, JobState::Unknown);
        assert_eq!(sealed.collection, CollectionState::Failed);
        assert!(sealed.cleanup_pending);
        assert!(!sealed.vm_destroyed);
        assert_eq!(sealed.vm_id, Some(vm_id));
        let manifest: serde_json::Value =
            serde_json::from_str(sealed.manifest.as_ref().unwrap()).unwrap();
        assert_eq!(manifest["guest_result"]["guest"], "staged receipt");
        assert_eq!(
            store.job_events(job.id, 0).unwrap().events[0].data,
            b"committed prefix"
        );
        let (replay, fresh) = store
            .accept_job(
                "publication",
                "{}",
                deadline,
                deadline + chrono::Duration::hours(1),
            )
            .unwrap();
        assert!(!fresh);
        assert_eq!(replay.id, job.id);
        assert_eq!(replay.state, JobState::Unknown);
    }

    #[tokio::test]
    async fn worker_reconciliation_never_infers_stopped_from_missing_or_live_handles() {
        let store = husker_state::StateStore::open_memory().unwrap();
        let deadline = Utc::now() + chrono::Duration::hours(1);
        let missing = store
            .accept_job(
                "missing-handle",
                "{}",
                deadline,
                deadline + chrono::Duration::hours(1),
            )
            .unwrap()
            .0;
        let live = store
            .accept_job(
                "live-handle",
                "{}",
                deadline,
                deadline + chrono::Duration::hours(1),
            )
            .unwrap()
            .0;
        let (finish, receiver) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(async move {
            receiver.await.unwrap();
        });
        let registry = WorkerRegistry::new(std::collections::HashMap::from([(live.id, worker)]));
        assert_eq!(reconcile_finished_workers(&store, &registry).reconciled, 0);
        assert_eq!(store.get_job(missing.id).unwrap().state, JobState::Accepted);
        assert_eq!(store.get_job(live.id).unwrap().state, JobState::Accepted);
        finish.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !registry.lock()[&live.id].is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(reconcile_finished_workers(&store, &registry).reconciled, 1);
        assert_eq!(store.get_job(live.id).unwrap().state, JobState::Interrupted);
        assert_eq!(store.get_job(missing.id).unwrap().state, JobState::Accepted);
    }

    #[tokio::test]
    async fn finished_worker_reconciliation_after_deadline_records_timeout_without_death_proof() {
        let store = husker_state::StateStore::open_memory().unwrap();
        let deadline = chrono::DateTime::from_timestamp(Utc::now().timestamp() + 1, 0).unwrap();
        let job = store
            .accept_job(
                "late-publication",
                "{}",
                deadline,
                deadline + chrono::Duration::hours(1),
            )
            .unwrap()
            .0;
        let registry = WorkerRegistry::new(std::collections::HashMap::from([(
            job.id,
            tokio::spawn(async {}),
        )]));
        tokio::time::sleep(
            crate::job_launch::remaining_deadline(job.deadline) + Duration::from_millis(10),
        )
        .await;
        assert_eq!(reconcile_finished_workers(&store, &registry).reconciled, 1);
        let sealed = store.get_job(job.id).unwrap();
        assert_eq!(sealed.state, JobState::TimedOut);
        assert_eq!(sealed.collection, CollectionState::Failed);
        assert!(!sealed.vm_destroyed);
    }

    #[tokio::test]
    async fn finished_worker_retries_failed_prebackend_abort_and_fences_late_entry() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("finished-abort.sqlite");
        let store = husker_state::StateStore::open(&path).unwrap();
        let deadline = Utc::now() + chrono::Duration::hours(1);
        let job = store
            .accept_job(
                "abort-retry",
                "{}",
                deadline,
                deadline + chrono::Duration::hours(1),
            )
            .unwrap()
            .0;
        let name = store.claim_job_vm(job.id).unwrap().vm_name.unwrap();
        let vm_id = Uuid::new_v4();
        store.bind_job_vm(job.id, vm_id, &name).unwrap();
        let lease = store
            .begin_host_resource_lease_for_vm(&name, vm_id)
            .unwrap();
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection.execute_batch("CREATE TRIGGER fail_abort BEFORE UPDATE OF vm_allocation_aborted ON execution_jobs BEGIN SELECT RAISE(ABORT, 'synthetic abort write failure'); END;").unwrap();
        let registry = WorkerRegistry::new(std::collections::HashMap::from([(
            job.id,
            tokio::spawn(async {}),
        )]));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !registry.lock()[&job.id].is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let blocked = reconcile_finished_workers(&store, &registry);
        assert_eq!(blocked.reconciled, 1);
        assert_eq!(blocked.aborts_pending, 1);
        assert_eq!(blocked.aborts_confirmed, 0);
        assert!(!store.get_job(job.id).unwrap().vm_allocation_aborted);
        assert!(
            !store
                .get_host_resource_lease(lease.id)
                .unwrap()
                .allocation_aborted
        );
        assert!(registry.lock()[&job.id].is_finished());
        // Publishing a terminal outcome must not discard the allocator proof.
        assert_eq!(
            reconcile_finished_workers(&store, &registry).aborts_pending,
            1
        );
        connection
            .execute_batch("DROP TRIGGER fail_abort;")
            .unwrap();
        let repaired = reconcile_finished_workers(&store, &registry);
        assert_eq!(repaired.reconciled, 0);
        assert_eq!(repaired.aborts_confirmed, 1);
        assert_eq!(repaired.aborts_pending, 0);
        let receipt = store.get_job(job.id).unwrap();
        assert_eq!(receipt.state, JobState::Unknown);
        assert!(receipt.vm_allocation_aborted);
        assert!(!receipt.vm_destroyed);
        assert!(receipt.cleanup_pending);
        assert!(
            store
                .get_host_resource_lease(lease.id)
                .unwrap()
                .allocation_aborted
        );
        assert!(
            store
                .enter_host_resource_lease_backend(lease.id, vm_id)
                .is_err()
        );
        assert!(registry.lock()[&job.id].is_finished());
        assert_eq!(
            reconcile_finished_workers(&store, &registry).aborts_confirmed,
            0
        );
        store.confirm_job_cleanup(job.id, vm_id).unwrap();
        reconcile_finished_workers(&store, &registry);
        assert!(registry.lock().is_empty());
    }

    #[tokio::test]
    async fn finished_worker_abort_reconciliation_preserves_entered_foreign_and_live_allocations() {
        for profile in ["entered", "foreign", "unbound", "live"] {
            let store = husker_state::StateStore::open_memory().unwrap();
            let deadline = Utc::now() + chrono::Duration::hours(1);
            let job = store
                .accept_job(
                    profile,
                    "{}",
                    deadline,
                    deadline + chrono::Duration::hours(1),
                )
                .unwrap()
                .0;
            let name = store.claim_job_vm(job.id).unwrap().vm_name.unwrap();
            let vm_id = Uuid::new_v4();
            store.bind_job_vm(job.id, vm_id, &name).unwrap();
            let lease = if profile == "unbound" {
                store.begin_host_resource_lease(&name).unwrap()
            } else {
                store
                    .begin_host_resource_lease_for_vm(
                        &name,
                        if profile == "foreign" {
                            Uuid::new_v4()
                        } else {
                            vm_id
                        },
                    )
                    .unwrap()
            };
            if profile == "entered" {
                store
                    .enter_host_resource_lease_backend(lease.id, vm_id)
                    .unwrap();
            }
            let (finish, receiver) = tokio::sync::oneshot::channel();
            let worker = tokio::spawn(async move {
                let _ = receiver.await;
            });
            let registry = WorkerRegistry::new(std::collections::HashMap::from([(job.id, worker)]));
            if profile != "live" {
                finish.send(()).unwrap();
                tokio::time::timeout(Duration::from_secs(1), async {
                    while !registry.lock()[&job.id].is_finished() {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
            }
            let report = reconcile_finished_workers(&store, &registry);
            assert_eq!(report.aborts_confirmed, 0, "{profile}");
            assert!(
                !store.get_job(job.id).unwrap().vm_allocation_aborted,
                "{profile}"
            );
            assert!(
                !store
                    .get_host_resource_lease(lease.id)
                    .unwrap()
                    .allocation_aborted,
                "{profile}"
            );
            assert!(registry.lock().contains_key(&job.id), "{profile}");
            let handle = registry.lock().remove(&job.id).unwrap();
            handle.abort();
            let _ = handle.await;
        }
    }

    #[tokio::test]
    async fn shutdown_join_retains_a_late_worker_handle_and_then_joins_it() {
        let id = Uuid::new_v4();
        let (finish, receiver) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(async move {
            receiver.await.unwrap();
        });
        let registry = WorkerRegistry::new(std::collections::HashMap::from([(id, worker)]));
        let (joined, pending) = join_registered_workers(&registry, Duration::from_millis(5)).await;
        assert_eq!(joined, 0);
        assert_eq!(pending, 1);
        assert!(!registry.lock()[&id].is_finished());
        finish.send(()).unwrap(); // Would fail if shutdown had aborted the task.
        let (joined, pending) = join_registered_workers(&registry, Duration::from_secs(1)).await;
        assert_eq!(joined, 1);
        assert_eq!(pending, 0);
        assert!(registry.lock().is_empty());
    }
    #[tokio::test]
    async fn cancelling_the_join_future_restores_its_owned_handles() {
        let id = Uuid::new_v4();
        let (finish, receiver) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(async move {
            receiver.await.unwrap();
        });
        let registry = Arc::new(WorkerRegistry::new(std::collections::HashMap::from([(
            id, worker,
        )])));
        let joining = {
            let registry = Arc::clone(&registry);
            tokio::spawn(async move {
                join_registered_workers(&registry, Duration::from_secs(10)).await
            })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while !registry.lock().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        joining.abort();
        assert!(joining.await.unwrap_err().is_cancelled());
        assert!(registry.lock().contains_key(&id));
        finish.send(()).unwrap();
        assert_eq!(
            join_registered_workers(&registry, Duration::from_secs(1)).await,
            (1, 0)
        );
    }
}
