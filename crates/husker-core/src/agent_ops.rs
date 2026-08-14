use super::*;

struct UserdataJob {
    token: u64,
    handle: tokio::task::JoinHandle<()>,
}

struct UserdataJobState {
    accepting: bool,
    jobs: std::collections::HashMap<Uuid, UserdataJob>,
}

/// Ownership boundary for background userdata execution.
///
/// A job is inserted before it is allowed to begin, which closes the tiny
/// spawn-before-registration race that otherwise lets shutdown miss a task.
/// Tokens prevent an old task's completion from removing a newer job for the
/// same VM generation.
pub(crate) struct UserdataJobs {
    next_token: std::sync::atomic::AtomicU64,
    state: parking_lot::Mutex<UserdataJobState>,
}

impl Default for UserdataJobs {
    fn default() -> Self {
        Self {
            next_token: std::sync::atomic::AtomicU64::new(1),
            state: parking_lot::Mutex::new(UserdataJobState {
                accepting: true,
                jobs: std::collections::HashMap::new(),
            }),
        }
    }
}

impl UserdataJobs {
    fn next_token(&self) -> u64 {
        self.next_token
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    fn claim_and_insert(
        &self,
        store: &husker_state::StateStore,
        vm_id: Uuid,
        spawn: impl FnOnce(u64) -> tokio::task::JoinHandle<()>,
    ) -> Result<Option<u64>, CoreError> {
        let mut state = self.state.lock();
        if !state.accepting || state.jobs.contains_key(&vm_id) {
            return Ok(None);
        }

        // Keep the ownership mutex across the durable claim and registration.
        // Shutdown and per-VM cancellation can therefore never observe a
        // `running` status without also finding its owned task.
        if !store.transition_userdata_status(
            vm_id,
            UserdataStatus::Pending,
            UserdataStatus::Running,
        )? {
            return Ok(None);
        }

        let token = self.next_token();
        let handle = spawn(token);
        state.jobs.insert(vm_id, UserdataJob { token, handle });
        Ok(Some(token))
    }

    fn remove_if_current(&self, vm_id: Uuid, token: u64) -> Option<tokio::task::JoinHandle<()>> {
        let mut state = self.state.lock();
        if state.jobs.get(&vm_id).is_some_and(|job| job.token == token) {
            state.jobs.remove(&vm_id).map(|job| job.handle)
        } else {
            None
        }
    }

    fn take(&self, vm_id: Uuid) -> Option<tokio::task::JoinHandle<()>> {
        self.state.lock().jobs.remove(&vm_id).map(|job| job.handle)
    }

    fn close_and_take_all(&self) -> Vec<(Uuid, tokio::task::JoinHandle<()>)> {
        let mut state = self.state.lock();
        state.accepting = false;
        state
            .jobs
            .drain()
            .map(|(vm_id, job)| (vm_id, job.handle))
            .collect()
    }
}

struct UserdataRunGuard<'a> {
    state: &'a husker_state::StateStore,
    vm_id: Uuid,
    armed: bool,
}

impl<'a> UserdataRunGuard<'a> {
    fn new(state: &'a husker_state::StateStore, vm_id: Uuid) -> Self {
        Self {
            state,
            vm_id,
            armed: true,
        }
    }

    fn finish(&mut self, status: UserdataStatus) -> Result<(), CoreError> {
        match self
            .state
            .transition_userdata_status(self.vm_id, UserdataStatus::Running, status)?
        {
            true => {
                self.armed = false;
                Ok(())
            }
            false => {
                self.armed = false;
                Err(CoreError::Io(format!(
                    "userdata status for VM {} changed while execution was active",
                    self.vm_id
                )))
            }
        }
    }
}

impl Drop for UserdataRunGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Err(error) = self.state.transition_userdata_status(
            self.vm_id,
            UserdataStatus::Running,
            UserdataStatus::Pending,
        ) && !matches!(error, husker_state::StateError::VmNotFound(_))
        {
            warn!(vm_id = %self.vm_id, %error, "failed to restore interrupted userdata to pending");
        }
    }
}

impl<B: VmmBackend> HuskerCore<B> {
    /// Connect to the guest agent for a running VM.
    ///
    /// Delegates vsock connection to the VMM backend, which handles the
    /// platform-specific protocol (Firecracker UDS+CONNECT, Apple VZ socket).
    ///
    /// A `suspended` VM with `auto_resume` set is transparently resumed first
    /// (idempotent: resuming an already-running VM is a no-op, so a retrying
    /// caller like [`Self::agent_connect_ready`] never double-resumes). A
    /// `suspended` VM without `auto_resume` is left alone and reported as an
    /// `InvalidState`, same as any other non-`running` state.
    ///
    /// On success, records control-plane activity for the idle policy and
    /// returns a connection carrying an [`ActiveSessionGuard`] for its
    /// lifetime, so the VM stays pinned active for as long as the connection
    /// is held.
    pub async fn agent_connect(
        &self,
        name: &str,
    ) -> Result<AgentConnection<B::VsockStream>, CoreError> {
        let record = self.lookup_vm(name)?;
        if record.state == VmLifecycleState::Suspended {
            if record.auto_resume {
                if self.resume_vm(name).await? {
                    self.idle_metrics
                        .auto_resumed_control_plane_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            } else {
                return Err(CoreError::InvalidState {
                    name: name.into(),
                    actual: record.state.to_string(),
                    expected: "running".into(),
                });
            }
        }
        // Re-read after a possible resume: the state (and, on Linux, the
        // vsock CID) may have changed.
        let record = self.lookup_vm(name)?;
        if record.state != VmLifecycleState::Running {
            return Err(CoreError::InvalidState {
                name: name.into(),
                actual: record.state.to_string(),
                expected: "running".into(),
            });
        }
        // Pin the VM active and record the touch before dialing the guest,
        // so a connection attempt in progress can never be suspended out
        // from under itself.
        let now = chrono::Utc::now();
        self.note_activity(record.id);
        // Debounce the SQLite mirror: `note_activity`'s in-memory timestamp
        // is the authoritative signal the idle-policy poll reads, so only
        // flush to the DB when the persisted value has drifted more than
        // ~30s. This keeps a hot exec/shell loop from writing to the DB on
        // every call.
        if (now - record.last_activity_at).num_seconds() >= 30 {
            let _ = self.state.touch_last_activity(record.id, now);
        }
        let guard = self.begin_session(record.id);
        debug!(%name, id = %record.id, "connecting to agent via vsock");
        let stream = self
            .vmm
            .vsock_connect(record.id, husker_agent_proto::AGENT_VSOCK_PORT)
            .await?;
        Ok(AgentConnection::new(stream).with_session_guard(guard))
    }

    /// Connect to the guest agent, retrying transient failures with backoff.
    ///
    /// Callers that reach the agent immediately after VM boot (e.g. `exec`)
    /// race the agent bind. Use this helper instead of [`Self::agent_connect`]
    /// when the caller can tolerate a bounded wait.
    ///
    /// The wait is bounded to approximately `timeout` (the last attempt is
    /// allowed to finish). Retries only VMM/Agent connection errors (vsock
    /// CONNECT rejected, agent not responding). State errors (VM destroyed or
    /// stopped) fail immediately.
    pub async fn agent_connect_ready(
        &self,
        name: &str,
        timeout: std::time::Duration,
    ) -> Result<AgentConnection<B::VsockStream>, CoreError> {
        // Resolve the VM and mint a session guard up front, held for the
        // entire wait. `agent_connect` only attaches its own guard once a
        // connection actually succeeds, so without this the VM would
        // repeatedly flicker to zero active sessions between failed attempts
        // while the guest boots (or a suspend-resume triggered by the first
        // attempt is still in flight) - exactly the window the idle policy
        // must not act in. This guard and the one the returned connection
        // carries briefly overlap (count 2) once a connect succeeds; this one
        // drops when this function returns.
        let record = self.lookup_vm(name)?;
        self.note_activity(record.id);
        let _hold_guard = self.begin_session(record.id);

        let mut backoff = std::time::Duration::from_millis(200);
        let max_backoff = std::time::Duration::from_secs(2);
        // Shrink the deadline by one attempt window so a final attempt that
        // starts just under the deadline cannot push total wall-clock beyond
        // approximately `timeout`.
        let deadline =
            tokio::time::Instant::now() + timeout.saturating_sub(AGENT_PING_ATTEMPT_TIMEOUT);
        loop {
            // Each attempt (connect + ping) is bounded so a guest that accepts
            // the vsock but never replies cannot exceed the overall deadline.
            let attempt = tokio::time::timeout(AGENT_PING_ATTEMPT_TIMEOUT, async {
                let mut conn = self.agent_connect(name).await?;
                conn.ping().await?;
                Ok::<_, CoreError>(conn)
            })
            .await;
            match attempt {
                Ok(Ok(conn)) => return Ok(conn),
                // State errors (VM stopped/destroyed) fail fast.
                Ok(Err(e)) if !matches!(e, CoreError::Vmm(_) | CoreError::Agent(_)) => {
                    return Err(e);
                }
                // Connection/agent errors are transient.
                Ok(Err(e)) => debug!(%name, error = %e, "agent not ready, retrying"),
                // A timed-out attempt is transient.
                Err(_) => debug!(%name, "agent ping attempt timed out, retrying"),
            }
            if tokio::time::Instant::now() + backoff >= deadline {
                return Err(CoreError::Agent(
                    crate::agent_client::AgentError::NotReady {
                        timeout,
                        detail: self.boot_failure_detail(name),
                    },
                ));
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(max_backoff);
        }
    }

    /// Diagnostic suffix for a boot/agent-readiness failure: the tail of the
    /// guest serial console plus a pointer to the full log. Appended to
    /// readiness errors so a failed boot is diagnosable from the error alone,
    /// instead of leaving the user to discover `husker logs` on their own.
    /// Returns an empty string if the VM record is gone (nothing to point at).
    fn boot_failure_detail(&self, name: &str) -> String {
        let Ok(path) = self.serial_log_path(name) else {
            return String::new();
        };
        match tail_last_lines(&path, BOOT_FAILURE_SERIAL_TAIL_LINES) {
            Some(tail) => {
                let module_hint = kernel_module_mismatch_hint(&tail)
                    .map(|h| format!("\nhint: {h}"))
                    .unwrap_or_default();
                format!(
                    "\n--- guest serial console (last {BOOT_FAILURE_SERIAL_TAIL_LINES} lines) ---\n{tail}\n\
                     hint: run `husker logs --source serial {name}` for the full guest console{module_hint}",
                )
            }
            None => format!(
                "\nhint: the guest serial console has no output yet; \
                 run `husker logs --source serial {name}` to inspect it",
            ),
        }
    }

    /// Single-attempt readiness probe (for the `/ready` endpoint): connect and
    /// ping once with a short timeout. `Ok(true)` if the agent ponged, `Ok(false)`
    /// if not yet reachable (or timed out), and `Err` for state errors (VM
    /// stopped/destroyed) so callers can distinguish "not up yet" from "gone".
    pub async fn probe_ready(&self, name: &str) -> Result<bool, CoreError> {
        let attempt = tokio::time::timeout(AGENT_PING_ATTEMPT_TIMEOUT, async {
            let mut conn = self.agent_connect(name).await?;
            conn.ping().await?;
            Ok::<_, CoreError>(())
        })
        .await;
        match attempt {
            Ok(Ok(())) => Ok(true),
            Ok(Err(CoreError::Vmm(_) | CoreError::Agent(_))) => Ok(false),
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(false),
        }
    }

    /// Execute the userdata script inside a running VM.
    ///
    /// Retries agent connection with exponential backoff (bounded by the
    /// boot-mode-aware default readiness timeout), writes the script to
    /// `/tmp/husker-userdata.sh`, executes it via `sh`, and updates
    /// `userdata_status` to `completed` or `failed`.
    async fn execute_claimed_userdata(
        &self,
        record: VmRecord,
        script: String,
    ) -> Result<(), CoreError> {
        let name = record.name.as_str();
        let mut run_guard = UserdataRunGuard::new(&self.state, record.id);
        let result: Result<(), CoreError> = async {
            let mut conn = self
                .agent_connect_ready(name, default_ready_timeout(record.boot_mode))
                .await?;

            conn.write_file(
                "/tmp/husker-userdata.sh",
                script.as_bytes(),
                Some(0o755),
                false,
            )
            .await?;

            let env_pairs: Vec<(String, String)> = record
                .userdata_env
                .as_deref()
                .map(|s| serde_json::from_str(s).unwrap_or_default())
                .unwrap_or_default();
            let env_refs: Vec<(&str, &str)> = env_pairs
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();

            let exec_result = conn
                .exec("sh", &["/tmp/husker-userdata.sh"], None, &env_refs)
                .await?;

            // Persist the script's output so it is inspectable after the fact
            // via `husker logs <name> --userdata`, rather than being discarded.
            let log_path = self
                .runtime_dir
                .join(format!("{}.userdata.log", record.id));
            let mut log = exec_result.stdout.clone();
            if !exec_result.stderr.is_empty() {
                if !log.is_empty() && !log.ends_with('\n') {
                    log.push('\n');
                }
                log.push_str("[stderr]\n");
                log.push_str(&exec_result.stderr);
            }
            if let Err(e) = tokio::fs::write(&log_path, log).await {
                warn!(%name, path = %log_path.display(), error = %e, "failed to write userdata log");
            }

            if exec_result.exit_code == 0 {
                run_guard.finish(UserdataStatus::Completed)?;
            } else {
                warn!(
                    %name,
                    exit_code = exec_result.exit_code,
                    stderr = %exec_result.stderr,
                    "userdata script failed"
                );
                run_guard.finish(UserdataStatus::Failed)?;
            }
            Ok(())
        }
        .await;

        if let Err(ref e) = result {
            warn!(%name, error = %e, "userdata execution error");
            if let Err(status_err) = run_guard.finish(UserdataStatus::Failed) {
                warn!(%name, error = %status_err, "failed to update userdata status to failed");
            }
        }

        result
    }

    async fn start_userdata_job(
        self: &Arc<Self>,
        record: VmRecord,
        require_running: bool,
    ) -> Result<Option<tokio::sync::oneshot::Receiver<Result<(), CoreError>>>, CoreError>
    where
        B: 'static,
    {
        // Serialize registration with stop/pause/suspend/destroy and refresh
        // the record after taking the lock. A delayed spawn for an old VM
        // generation must not start against its same-name replacement.
        let _name_guard = self.vm_name_lock(&record.name).lock_owned().await;
        let current = self.lookup_vm(&record.name)?;
        if current.id != record.id {
            return Ok(None);
        }
        if require_running && current.state != VmLifecycleState::Running {
            return Ok(None);
        }
        let Some(script) = current.userdata.clone() else {
            return Ok(None);
        };

        let vm_id = current.id;
        let name = current.name.clone();
        let (start_tx, start_rx) = tokio::sync::oneshot::channel();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let core = Arc::clone(self);
        let jobs = Arc::clone(&self.userdata_jobs);
        let token = self
            .userdata_jobs
            .claim_and_insert(&self.state, vm_id, move |token| {
                tokio::spawn(async move {
                    if start_rx.await.is_err() {
                        return;
                    }
                    let result = core.execute_claimed_userdata(current, script).await;
                    if let Err(error) = &result {
                        warn!(%name, %error, "userdata execution failed");
                    }
                    let _ = result_tx.send(result);
                    jobs.remove_if_current(vm_id, token);
                })
            })?;
        let Some(token) = token else {
            return Ok(None);
        };

        if start_tx.send(()).is_err() {
            if let Some(handle) = self.userdata_jobs.remove_if_current(vm_id, token) {
                handle.abort();
            }
            let _ = self.state.transition_userdata_status(
                vm_id,
                UserdataStatus::Running,
                UserdataStatus::Pending,
            );
            return Ok(None);
        }

        Ok(Some(result_rx))
    }

    /// Execute userdata once, waiting for the tracked job's result.
    ///
    /// A concurrent caller that finds the script already claimed or terminal
    /// returns successfully without executing it again.
    pub async fn run_userdata(self: &Arc<Self>, name: &str) -> Result<(), CoreError>
    where
        B: 'static,
    {
        let record = self.lookup_vm(name)?;
        let Some(result) = self.start_userdata_job(record, false).await? else {
            return Ok(());
        };
        result
            .await
            .map_err(|_| CoreError::UserdataCancelled(name.to_string()))?
    }

    /// Start owned background userdata execution for a freshly created VM.
    ///
    /// Returns whether this call atomically claimed and registered a job. A
    /// duplicate call, a terminal status, or a shutting-down core returns
    /// `false` without executing the script.
    pub async fn spawn_userdata(self: &Arc<Self>, record: &VmRecord) -> bool
    where
        B: 'static,
    {
        match self.start_userdata_job(record.clone(), true).await {
            Ok(Some(result)) => {
                drop(result);
                true
            }
            Ok(None) => false,
            Err(error) => {
                warn!(name = %record.name, %error, "failed to start userdata execution");
                false
            }
        }
    }

    pub(crate) async fn cancel_userdata_job(&self, vm_id: Uuid) -> bool {
        let Some(handle) = self.userdata_jobs.take(vm_id) else {
            return false;
        };
        handle.abort();
        if let Err(error) = handle.await
            && !error.is_cancelled()
        {
            warn!(%vm_id, %error, "userdata job failed while cancelling");
        }
        let _ = self.state.transition_userdata_status(
            vm_id,
            UserdataStatus::Running,
            UserdataStatus::Pending,
        );
        true
    }

    pub(crate) async fn shutdown_userdata_jobs(&self) -> usize {
        let handles = self.userdata_jobs.close_and_take_all();
        let count = handles.len();
        for (_, handle) in &handles {
            handle.abort();
        }
        for (vm_id, handle) in handles {
            if let Err(error) = handle.await
                && !error.is_cancelled()
            {
                warn!(%vm_id, %error, "userdata job failed during shutdown");
            }
            let _ = self.state.transition_userdata_status(
                vm_id,
                UserdataStatus::Running,
                UserdataStatus::Pending,
            );
        }
        if count > 0 {
            info!(count, "cancelled userdata jobs for shutdown");
        }
        count
    }
}
