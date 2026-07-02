use super::*;

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
        if record.state == "suspended" {
            if record.auto_resume {
                if self.resume_vm(name).await? {
                    self.idle_metrics
                        .auto_resumed_control_plane_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            } else {
                return Err(CoreError::InvalidState {
                    name: name.into(),
                    actual: record.state,
                    expected: "running".into(),
                });
            }
        }
        // Re-read after a possible resume: the state (and, on Linux, the
        // vsock CID) may have changed.
        let record = self.lookup_vm(name)?;
        if record.state != "running" {
            return Err(CoreError::InvalidState {
                name: name.into(),
                actual: record.state,
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
    pub async fn run_userdata(&self, name: &str) -> Result<(), CoreError> {
        let record = self.lookup_vm(name)?;
        let script = match record.userdata {
            Some(ref s) => s.clone(),
            None => return Ok(()),
        };

        self.state.update_userdata_status(record.id, "running")?;

        let result: Result<(), CoreError> = async {
            let mut conn = self
                .agent_connect_ready(name, default_ready_timeout(&record.boot_mode))
                .await?;

            conn.write_file("/tmp/husker-userdata.sh", script.as_bytes(), Some(0o755))
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
                self.state.update_userdata_status(record.id, "completed")?;
            } else {
                warn!(
                    %name,
                    exit_code = exec_result.exit_code,
                    stderr = %exec_result.stderr,
                    "userdata script failed"
                );
                self.state.update_userdata_status(record.id, "failed")?;
            }
            Ok(())
        }
        .await;

        if let Err(ref e) = result {
            warn!(%name, error = %e, "userdata execution error");
            if let Err(status_err) = self.state.update_userdata_status(record.id, "failed") {
                warn!(%name, error = %status_err, "failed to update userdata status to failed");
            }
        }

        result
    }

    /// Spawn background userdata execution for a freshly created VM, if it has any.
    /// Fire-and-forget: returns immediately; `run_userdata` updates `userdata_status`.
    pub fn spawn_userdata(self: &Arc<Self>, record: &VmRecord)
    where
        B: 'static,
    {
        if record.userdata.is_none() {
            return;
        }
        let core = Arc::clone(self);
        let name = record.name.clone();
        tokio::spawn(async move {
            if let Err(e) = core.run_userdata(&name).await {
                warn!(%name, error = %e, "userdata execution failed");
            }
        });
    }
}
