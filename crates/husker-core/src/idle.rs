use super::*;

/// The idle policy a VM is created with, as persisted on its record. A VM that
/// did not opt in carries no timeout and no TTL and auto-resumes, so a later
/// connect never has to consult the daemon defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IdleSettings {
    pub(crate) idle_timeout_secs: Option<u64>,
    pub(crate) suspend_ttl_secs: Option<u64>,
    pub(crate) auto_resume: bool,
}

impl IdleSettings {
    const NOT_OPTED_IN: Self = Self {
        idle_timeout_secs: None,
        suspend_ttl_secs: None,
        auto_resume: true,
    };
}

/// Resolve a create request's idle policy against the daemon defaults and the
/// selected backend.
///
/// An explicit `idle_timeout_secs` wins; otherwise the bare `idle` flag opts in
/// with the default window. The window is resolved without a sentinel so an
/// explicit `--idle-timeout 0` (suspend as soon as idle) is not overwritten by
/// the default. A suspend TTL default of zero means no TTL.
///
/// Idle suspend relies on a full-state snapshot, so an opt-in on a backend
/// without one is rejected here, before any host resource is allocated.
pub(crate) fn resolve_idle_settings(
    req: &CreateVmRequest,
    defaults: &IdlePolicyConfig,
    backend: BackendKind,
) -> Result<IdleSettings, CoreError> {
    let Some(idle_timeout_secs) = req.idle_timeout_secs.or_else(|| {
        req.idle
            .unwrap_or(false)
            .then_some(defaults.default_idle_timeout_secs)
    }) else {
        return Ok(IdleSettings::NOT_OPTED_IN);
    };
    require_snapshot_backend(backend)?;
    Ok(IdleSettings {
        idle_timeout_secs: Some(idle_timeout_secs),
        suspend_ttl_secs: req.suspend_ttl_secs.or_else(|| {
            (defaults.default_suspend_ttl_secs > 0).then_some(defaults.default_suspend_ttl_secs)
        }),
        auto_resume: req.auto_resume.unwrap_or(defaults.default_auto_resume),
    })
}

/// Reject an idle opt-in on a backend that cannot take a full-state snapshot.
/// The message lists the backends that can, read from their capabilities, so
/// it stays true when a backend gains or loses snapshot support.
fn require_snapshot_backend(backend: BackendKind) -> Result<(), CoreError> {
    let can_snapshot =
        |kind: BackendKind| husker_vmm::Capabilities::for_backend_kind(kind).snapshot;
    if can_snapshot(backend) {
        return Ok(());
    }
    let capable = BackendKind::ALL
        .into_iter()
        .filter(|kind| can_snapshot(*kind))
        .map(BackendKind::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    Err(CoreError::InvalidArgument(format!(
        "idle policy requires a full-state snapshot backend ({capable}), not {backend}"
    )))
}

impl<B: VmmBackend> HuskerCore<B> {
    /// Record control-plane activity (an exec/shell/API touch) against a VM's
    /// idle clock.
    pub fn note_activity(&self, id: Uuid) {
        self.control_plane_last_active
            .lock()
            .insert(id, std::time::Instant::now());
    }

    /// Record network activity (a port-forward byte delta) against a VM's idle
    /// clock.
    pub fn mark_network_active(&self, id: Uuid) {
        self.network_last_active
            .lock()
            .insert(id, std::time::Instant::now());
    }

    /// Time elapsed since `id`'s last recorded network activity, or `None` if
    /// the VM has no entry (never seen, or seeding never ran).
    pub fn network_last_active_elapsed(&self, id: Uuid) -> Option<std::time::Duration> {
        self.network_last_active
            .lock()
            .get(&id)
            .map(|t| t.elapsed())
    }

    /// Number of open sessions (exec/shell streams) currently pinning `id` active.
    pub fn active_session_count(&self, id: Uuid) -> u64 {
        *self.active_sessions.lock().get(&id).unwrap_or(&0)
    }

    /// Increment the active-session refcount for `id` and return an RAII guard
    /// that decrements it on drop, including on cancellation or a panic, so a
    /// session can never leak the count and strand a VM pinned-active.
    pub fn begin_session(&self, id: Uuid) -> ActiveSessionGuard {
        *self.active_sessions.lock().entry(id).or_insert(0) += 1;
        ActiveSessionGuard::from_parts(Arc::clone(&self.active_sessions), id)
    }

    /// Seed both activity timers to now. Call on create/fork/first-sight so a
    /// never-touched VM has a real idle clock instead of a missing entry.
    pub fn seed_activity(&self, id: Uuid) {
        let now = std::time::Instant::now();
        self.control_plane_last_active.lock().insert(id, now);
        self.network_last_active.lock().insert(id, now);
    }

    /// Time `record` has been idle, or `None` if it is not eligible for idle
    /// evaluation right now (not running, or an open session pins it active).
    ///
    /// Pure read: never inserts into `control_plane_last_active` or
    /// `network_last_active`. `idle_policy_tick` calls this twice per
    /// candidate (once for the initial verdict, once for the in-lock
    /// re-check); if a missing entry were seeded here, the re-check would see
    /// a freshly-seeded ~0ms-old entry and the suspend would never go
    /// through. Map entries are populated only by explicit activity events
    /// (`note_activity`, `mark_network_active`, `seed_activity`).
    fn idle_for(&self, record: &VmRecord) -> Option<std::time::Duration> {
        if record.state != VmLifecycleState::Running || self.active_session_count(record.id) > 0 {
            return None;
        }
        // Fallback when a signal has no in-memory entry (never seen since the
        // daemon started, or seeding never ran): the DB mirror of the last
        // control-plane touch. `last_activity_at` is set to `created_at` at
        // creation, so an untouched-but-old VM is immediately eligible while a
        // freshly-created one waits out a full window.
        let db_elapsed = (chrono::Utc::now() - record.last_activity_at)
            .to_std()
            .unwrap_or(std::time::Duration::ZERO);
        let control_plane = self
            .control_plane_last_active
            .lock()
            .get(&record.id)
            .map(|t| t.elapsed())
            .unwrap_or(db_elapsed);
        let network = self
            .network_last_active
            .lock()
            .get(&record.id)
            .map(|t| t.elapsed())
            .unwrap_or(db_elapsed);
        Some(control_plane.min(network))
    }

    /// Read every husker-managed port-forward counter in one `nft` call,
    /// bounded to 500ms so a wedged or slow `nft` invocation cannot stall the
    /// idle-policy tick. Empty on timeout or error: the caller then treats
    /// this poll as "no network update this tick" rather than failing it.
    #[cfg(feature = "linux-net")]
    async fn snapshot_pf_counters(&self) -> std::collections::HashMap<String, (u64, u64)> {
        match tokio::time::timeout(
            std::time::Duration::from_millis(500),
            self.host_network
                .read_all_port_forward_counters(&self.bridge_name),
        )
        .await
        {
            Ok(Ok(counters)) => counters,
            Ok(Err(e)) => {
                warn!(error = %e, "idle tick: reading port-forward counters failed");
                std::collections::HashMap::new()
            }
            Err(_) => {
                warn!("idle tick: reading port-forward counters timed out");
                std::collections::HashMap::new()
            }
        }
    }

    /// Compare `vm`'s port-forward byte counters against the previous tick's
    /// baseline in `network_counters`; a growing packet count means the
    /// forward carried traffic since the last poll, so mark the VM network-
    /// active. Always writes the fresh tuple back, even when it did not grow,
    /// so a counter that resets after a resume (new < old, since the DNAT
    /// rule was recreated at 0) just re-baselines instead of raising a false
    /// positive on every subsequent tick.
    #[cfg(feature = "linux-net")]
    fn refresh_network_activity(
        &self,
        vm: &VmRecord,
        counters: &std::collections::HashMap<String, (u64, u64)>,
    ) {
        let Some(tap) = vm.tap_device.as_deref() else {
            return;
        };
        let forwards = self
            .state
            .list_port_forwards_for_vm(vm.id)
            .unwrap_or_default();
        if forwards.is_empty() {
            return;
        }
        let mut became_active = false;
        {
            let mut nc = self.network_counters.lock();
            for pf in &forwards {
                let key = format!("husker-pf:{tap}:{}", pf.host_port);
                let new_counts = counters.get(&key).copied().unwrap_or((0, 0));
                let old_counts = nc.get(&key).copied().unwrap_or((0, 0));
                if new_counts.0 > old_counts.0 {
                    became_active = true;
                }
                nc.insert(key, new_counts);
            }
        }
        if became_active {
            self.mark_network_active(vm.id);
        }
    }

    /// One pass of the idle-policy poll loop.
    ///
    /// For every VM opted in via `idle_timeout_secs`, refresh its network-
    /// activity signal (Linux), compute how long it has been idle, and act on
    /// `evaluate_policy`'s verdict. A `Suspend`/`Reap` verdict from the first
    /// pass is provisional: before acting on it, the VM's name lock is
    /// acquired and the record + policy inputs are re-read and re-evaluated
    /// under that lock. The lock is held across both the re-check and the
    /// action itself, so no session, connection, or resume can slip in
    /// between the final `evaluate_policy` call and the suspend/reap (no
    /// drop-then-reacquire TOCTOU gap).
    ///
    /// Calls the `*_locked` inner functions directly, never the public
    /// `suspend_vm`/`destroy_vm`: those acquire the same per-name lock this
    /// function already holds, and tokio's `Mutex` is not reentrant, so
    /// calling them here would deadlock.
    pub async fn idle_policy_tick(self: &Arc<Self>)
    where
        B: 'static,
    {
        let vms = match self.state.list_vms() {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "idle tick: list_vms");
                return;
            }
        };
        // One table dump per tick, indexed by comment (Linux). Best-effort.
        #[cfg(feature = "linux-net")]
        let counters = self.snapshot_pf_counters().await;
        for vm in vms {
            if vm.idle_timeout_secs.is_none() {
                continue;
            }
            #[cfg(feature = "linux-net")]
            self.refresh_network_activity(&vm, &counters);

            let idle_for = self.idle_for(&vm);
            let has_active = self.active_session_count(vm.id) > 0;
            let has_fork = self.state.count_live_forks_of(vm.id).unwrap_or(0) > 0;
            match evaluate_policy(&vm, chrono::Utc::now(), idle_for, has_active, has_fork) {
                PolicyAction::None => {}
                PolicyAction::Suspend => {
                    // In-lock re-check: see the doc comment above for why the
                    // lock spans both the re-check and the action.
                    let _guard = self.vm_name_lock(&vm.name).lock_owned().await;
                    if let Ok(fresh) = self.state.get_vm(vm.id) {
                        #[cfg(feature = "linux-net")]
                        {
                            let c = self.snapshot_pf_counters().await;
                            self.refresh_network_activity(&fresh, &c);
                        }
                        let re = evaluate_policy(
                            &fresh,
                            chrono::Utc::now(),
                            self.idle_for(&fresh),
                            self.active_session_count(fresh.id) > 0,
                            self.state.count_live_forks_of(fresh.id).unwrap_or(0) > 0,
                        );
                        if matches!(re, PolicyAction::Suspend) {
                            match self.suspend_vm_locked(&fresh).await {
                                Ok(_) => {
                                    self.idle_metrics
                                        .suspended_total
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                                Err(e) => {
                                    warn!(vm = %fresh.name, error = %e, "idle tick: suspend failed")
                                }
                            }
                        }
                    }
                }
                PolicyAction::Reap => {
                    let _guard = self.vm_name_lock(&vm.name).lock_owned().await;
                    if let Ok(fresh) = self.state.get_vm(vm.id) {
                        let re = evaluate_policy(
                            &fresh,
                            chrono::Utc::now(),
                            None,
                            self.active_session_count(fresh.id) > 0,
                            self.state.count_live_forks_of(fresh.id).unwrap_or(0) > 0,
                        );
                        if matches!(re, PolicyAction::Reap) {
                            match self.destroy_vm_recoverable_locked(&fresh).await {
                                Ok(_) => {
                                    self.idle_metrics
                                        .reaped_total
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                                Err(e) => {
                                    warn!(vm = %fresh.name, error = %e, "idle tick: reap failed")
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Test-only accessor to the underlying state store, for tests that need
    /// to reach setters (`set_idle_policy`, `set_suspended_at`, ...) not
    /// otherwise exposed on `HuskerCore`.
    #[cfg(all(test, feature = "linux-net"))]
    pub(crate) fn state(&self) -> &husker_state::StateStore {
        &self.state
    }

    /// Test-only: force both idle-activity timers to a specific `Instant`
    /// (e.g. in the past), bypassing `note_activity`/`mark_network_active`'s
    /// "now" semantics so a test can stage a VM as already idle.
    #[cfg(all(test, feature = "linux-net"))]
    pub(crate) fn set_last_active_for_test(&self, id: Uuid, at: std::time::Instant) {
        self.control_plane_last_active.lock().insert(id, at);
        self.network_last_active.lock().insert(id, at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> IdlePolicyConfig {
        IdlePolicyConfig {
            poll_interval_secs: 30,
            default_idle_timeout_secs: 1800,
            default_suspend_ttl_secs: 0,
            default_auto_resume: true,
        }
    }

    fn can_snapshot(backend: BackendKind) -> bool {
        husker_vmm::Capabilities::for_backend_kind(backend).snapshot
    }

    fn snapshot_backend() -> BackendKind {
        BackendKind::ALL
            .into_iter()
            .find(|backend| can_snapshot(*backend))
            .expect("at least one backend takes full-state snapshots")
    }

    #[test]
    fn a_request_without_an_opt_in_resolves_to_no_policy_on_every_backend() {
        let requests = [
            CreateVmRequest::default(),
            CreateVmRequest {
                idle: Some(false),
                ..Default::default()
            },
        ];
        for backend in BackendKind::ALL {
            for req in &requests {
                let settings = resolve_idle_settings(req, &defaults(), backend).unwrap();
                assert_eq!(settings, IdleSettings::NOT_OPTED_IN, "{backend}: {req:?}");
            }
        }
    }

    #[test]
    fn an_opt_in_is_accepted_exactly_on_the_backends_with_full_state_snapshots() {
        let req = CreateVmRequest {
            idle: Some(true),
            ..Default::default()
        };
        for backend in BackendKind::ALL {
            let result = resolve_idle_settings(&req, &defaults(), backend);
            assert_eq!(
                result.is_ok(),
                can_snapshot(backend),
                "{backend}: {result:?}"
            );
        }
    }

    #[test]
    fn a_rejection_names_the_rejected_backend_and_every_snapshot_backend() {
        let req = CreateVmRequest {
            idle_timeout_secs: Some(60),
            ..Default::default()
        };
        let capable: Vec<&str> = BackendKind::ALL
            .into_iter()
            .filter(|backend| can_snapshot(*backend))
            .map(BackendKind::as_str)
            .collect();
        assert!(!capable.is_empty());
        for backend in BackendKind::ALL
            .into_iter()
            .filter(|backend| !can_snapshot(*backend))
        {
            let err = resolve_idle_settings(&req, &defaults(), backend).unwrap_err();
            let CoreError::InvalidArgument(message) = err else {
                panic!("{backend}: expected InvalidArgument, got {err:?}");
            };
            assert!(message.contains(backend.as_str()), "{message}");
            for name in &capable {
                assert!(message.contains(name), "{message} does not name {name}");
            }
        }
    }

    #[test]
    fn an_explicit_timeout_wins_over_the_bare_flag_and_the_default_window() {
        let req = CreateVmRequest {
            idle: Some(true),
            idle_timeout_secs: Some(0),
            ..Default::default()
        };
        let settings = resolve_idle_settings(&req, &defaults(), snapshot_backend()).unwrap();
        assert_eq!(settings.idle_timeout_secs, Some(0));
    }

    #[test]
    fn the_bare_flag_opts_in_with_the_daemon_defaults() {
        let defaults = IdlePolicyConfig {
            default_idle_timeout_secs: 90,
            default_suspend_ttl_secs: 600,
            default_auto_resume: false,
            ..defaults()
        };
        let req = CreateVmRequest {
            idle: Some(true),
            ..Default::default()
        };
        let settings = resolve_idle_settings(&req, &defaults, snapshot_backend()).unwrap();
        assert_eq!(
            settings,
            IdleSettings {
                idle_timeout_secs: Some(90),
                suspend_ttl_secs: Some(600),
                auto_resume: false,
            }
        );
    }

    #[test]
    fn a_zero_default_ttl_means_no_ttl_and_explicit_values_win_over_the_defaults() {
        let bare = CreateVmRequest {
            idle: Some(true),
            ..Default::default()
        };
        let settings = resolve_idle_settings(&bare, &defaults(), snapshot_backend()).unwrap();
        assert_eq!(settings.suspend_ttl_secs, None);
        assert!(settings.auto_resume);

        let explicit = CreateVmRequest {
            idle: Some(true),
            suspend_ttl_secs: Some(5),
            auto_resume: Some(false),
            ..Default::default()
        };
        let settings = resolve_idle_settings(&explicit, &defaults(), snapshot_backend()).unwrap();
        assert_eq!(settings.suspend_ttl_secs, Some(5));
        assert!(!settings.auto_resume);
    }
}
