use super::*;

impl<B: VmmBackend> HuskerCore<B> {
    /// Durable per-VM suspend slot: `<data_dir>/suspend/<vm_id>/`.
    pub(crate) fn suspend_slot_dir(&self, id: Uuid) -> PathBuf {
        self.storage.data_dir.join("suspend").join(id.to_string())
    }

    /// Suspend a VM to disk: pause, capture full state, terminate the process.
    ///
    /// Networking (TAP/IP/CID) and the VM's rootfs are intentionally preserved so
    /// `resume_vm` can restore the same identity in place. Idempotent.
    ///
    /// Takes `Arc<Self>` (rather than `&self`) because a VM suspended with
    /// `auto_resume` and active port forwards needs `install_resume_listeners`
    /// to bind a resume hook that owns a clone of the core so it can call
    /// `resume_vm` on first connection, long after this call returns.
    pub async fn suspend_vm(self: &Arc<Self>, name: &str) -> Result<(), CoreError>
    where
        B: 'static,
    {
        info!(%name, "suspending VM");
        // Serialize against a concurrent resume/fork of this VM: fork moves the
        // source's rootfs aside during `/snapshot/load` and reuses its vsock path,
        // so suspend/resume/fork on one name must not interleave. `fork_vm` takes
        // this same lock on the source name.
        let _guard = self.vm_name_lock(name).lock_owned().await;
        let record = self.lookup_vm(name)?;
        match record.state {
            VmLifecycleState::Running | VmLifecycleState::Paused => {}
            VmLifecycleState::Suspended => {
                debug!(%name, "VM already suspended; suspend is a no-op");
                return Ok(());
            }
            _ => {
                return Err(CoreError::InvalidState {
                    name: name.into(),
                    actual: record.state.to_string(),
                    expected: "running or paused".into(),
                });
            }
        }
        self.suspend_vm_locked(&record).await
    }

    /// Suspend logic assuming the caller already holds `name`'s `vm_name_lock`
    /// and has validated `record.state` is `"running"` or `"paused"`. Captures
    /// full VM state to disk, then (Linux) transitions the network path from
    /// kernel DNAT to a userspace resume listener (if `auto_resume`) or tears
    /// the forward down entirely.
    pub(crate) async fn suspend_vm_locked(
        self: &Arc<Self>,
        record: &VmRecord,
    ) -> Result<(), CoreError>
    where
        B: 'static,
    {
        let name = &record.name;

        // Fail fast before pausing: only backends with full-state snapshot can be
        // suspended. Otherwise a QEMU/Apple VZ VM would be paused, hit
        // `Unsupported` at snapshot time, and have to be un-paused again.
        if !husker_vmm::Capabilities::for_backend_kind(record.vmm).snapshot {
            return Err(CoreError::Vmm(husker_vmm::VmmError::Unsupported(format!(
                "backend '{}' does not support suspend (full-state snapshot)",
                record.vmm
            ))));
        }

        // A manual suspend can race startup execution even though the idle
        // policy is shielded by the agent session. End that session before
        // snapshotting so no guest command straddles the suspend boundary.
        self.cancel_userdata_job(record.id).await;

        let paused_by_us = record.state == VmLifecycleState::Running;
        let original_state = record.state;

        // Persist the transient "suspending" state up front, BEFORE pausing or
        // capturing anything. A crash anywhere in the capture window then leaves a
        // "suspending" VM that startup `reconcile_suspended_vms` resolves from the
        // on-disk slot (a complete slot -> "suspended", an incomplete one ->
        // "stopped"), instead of a "running"/"paused" row that startup downgrades
        // to "stopped" even though a complete, resumable slot exists on disk.
        self.state
            .update_vm_state(record.id, VmLifecycleState::Suspending)?;

        let slot = self.suspend_slot_dir(record.id);
        let paths = SnapshotPaths::in_dir(&slot);

        // Capture the full state (pause -> snapshot -> manifest). On any failure,
        // roll the DB state back to what it was and resume the VMM if we paused it,
        // so a failed suspend is a no-op for the caller.
        let capture = async {
            if paused_by_us {
                self.vmm.pause_vm(record.id).await?;
            }
            tokio::fs::create_dir_all(&slot)
                .await
                .map_err(|e| CoreError::Io(format!("create suspend slot: {e}")))?;
            let meta = self.vmm.snapshot_vm(record.id, &paths).await?;
            let manifest = serde_json::json!({
                "kind": "full",
                "backend": meta.backend,
                "vmm_version": meta.vmm_version,
                "vcpu_count": record.vcpu_count,
                "mem_size_mib": record.mem_size_mib,
                "vsock_cid": record.vsock_cid,
                "rootfs_path": record.rootfs_path,
            });
            write_file_atomic(
                &paths.manifest,
                &serde_json::to_vec_pretty(&manifest).expect("manifest serializes"),
            )
            .await
            .map_err(|e| CoreError::Io(format!("write suspend manifest: {e}")))?;
            Ok::<(), CoreError>(())
        };
        if let Err(e) = capture.await {
            let _ = tokio::fs::remove_dir_all(&slot).await;
            if paused_by_us {
                let _ = self.vmm.resume_vm(record.id).await;
            }
            let _ = self.state.update_vm_state(record.id, original_state);
            return Err(e);
        }

        // The slot is complete and durable; freeing the memory and the final state
        // write are both covered by reconcile (state is already "suspending").
        // This is the backend process kill (`self.vmm.destroy_vm`), not core's
        // public `destroy_vm`, which also takes `vm_name_lock` and would deadlock
        // re-entering it here.
        self.vmm.destroy_vm(record.id).await?;
        self.state
            .update_vm_runtime(record.id, VmLifecycleState::Suspended, None)?;

        // Stamp the reap anchor before the network transition, so a crash mid
        // transition still leaves a suspended VM whose TTL clock is running.
        self.state
            .set_suspended_at(record.id, Some(chrono::Utc::now()))?;

        #[cfg(feature = "linux-net")]
        {
            let forwards = self
                .state
                .list_port_forwards_for_vm(record.id)
                .unwrap_or_default();
            if record.auto_resume && !forwards.is_empty() {
                // Bind the resume listeners FIRST, so there is no window where
                // neither the kernel DNAT nor a userspace listener is accepting
                // connections on the forwarded host ports.
                self.install_resume_listeners(record, &forwards).await;
            }
            for pf in &forwards {
                if let Some(tap) = record.tap_device.as_deref() {
                    let _ = self
                        .host_network
                        .remove_port_forward(pf.host_port, tap, &self.bridge_name)
                        .await;
                }
            }
        }

        info!(%name, "VM suspended");
        Ok(())
    }

    /// Bind a userspace `PortProxy` per forwarded port so a suspended,
    /// `auto_resume` VM keeps accepting connections on its host ports after
    /// the kernel DNAT rule is removed: the first connection resumes the VM
    /// (idempotently) via the captured `Arc<Self>`, then relays through once
    /// the guest is back up.
    #[cfg(feature = "linux-net")]
    pub(crate) async fn install_resume_listeners(
        self: &Arc<Self>,
        record: &VmRecord,
        forwards: &[husker_state::PortForwardRecord],
    ) where
        B: 'static,
    {
        if record.tap_device.is_none() {
            return;
        }
        let Some(guest_ip) = record.guest_ip.as_deref().and_then(|ip| ip.parse().ok()) else {
            return;
        };
        let core = Arc::clone(self);
        let vm_name = record.name.clone();
        let resume = move |name: String| {
            let core = Arc::clone(&core);
            async move {
                match core.resume_vm(&name).await {
                    // Only a real suspended->running transition counts as an
                    // auto-resume: concurrent connections racing the same
                    // suspended VM all land here, but only the first actually
                    // resumes it (the rest observe `false`, an already-running
                    // no-op), so gating on `true` keeps the counter from
                    // over-counting a single resume N times.
                    Ok(true) => {
                        core.idle_metrics
                            .auto_resumed_connect_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        Ok(())
                    }
                    Ok(false) => Ok(()),
                    Err(e) => Err(std::io::Error::other(e.to_string())),
                }
            }
        };
        let dialer = crate::port_proxy::ResumeDialer::new(
            crate::port_proxy::DirectIpDialer,
            vm_name,
            resume,
        );
        let proxy = crate::port_proxy::PortProxy::new(dialer);
        for pf in forwards {
            let bind_addr = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
            if let Err(e) = proxy
                .add_guarded(
                    record.id,
                    bind_addr,
                    pf.host_port,
                    guest_ip,
                    pf.guest_port,
                    Arc::clone(&self.active_sessions),
                )
                .await
            {
                warn!(
                    vm = %record.name,
                    host_port = pf.host_port,
                    error = %e,
                    "failed to bind resume listener; suspended VM will not auto-resume on this port"
                );
            }
        }
        self.resume_listeners
            .lock()
            .insert(record.id, Box::new(proxy));
    }

    /// Test-only: whether a resume listener is currently registered for `id`.
    #[cfg(all(test, feature = "linux-net"))]
    pub(crate) fn has_resume_listener_for_test(&self, id: Uuid) -> bool {
        self.resume_listeners.lock().contains_key(&id)
    }

    /// Recover VMs interrupted mid-suspend on a previous daemon run.
    ///
    /// A VM in the transient `"suspending"` state was past its snapshot + manifest
    /// write (so its guest memory may already be freed) when the daemon stopped.
    /// If a complete suspend slot is on disk the VM is resumable, so finish the
    /// transition to `"suspended"`; otherwise the capture never completed and the
    /// memory state is unrecoverable, so fall back to `"stopped"` (the rootfs is
    /// intact, so the VM can be re-run). Returns the number of VMs reconciled.
    /// Call at daemon startup, before serving requests.
    pub async fn reconcile_suspended_vms(&self) -> Result<usize, CoreError> {
        let mut reconciled = 0;
        for vm in self.state.list_vms()? {
            if vm.state != VmLifecycleState::Suspending {
                continue;
            }
            // A hard crash between the snapshot write and destroy_vm can leave the
            // pre-crash firecracker alive (reparented), still bound to this VM's
            // rootfs/vsock/CID/TAP. Reap it before trusting the slot, so a later
            // resume/fork cannot race a surviving VMM over the same resources.
            // (`reap_orphaned_vmms` does not: it targets running/paused, not
            // suspending.)
            if let Some(pid) = vm.pid
                && reap_vmm_if_orphaned(vm.id, pid)
            {
                warn!(pid, vm = %vm.name, "reaped firecracker orphaned by an interrupted suspend");
            }
            let paths = SnapshotPaths::in_dir(self.suspend_slot_dir(vm.id));
            let slot_complete = tokio::fs::try_exists(&paths.manifest)
                .await
                .unwrap_or(false)
                && tokio::fs::try_exists(&paths.memory).await.unwrap_or(false)
                && tokio::fs::try_exists(&paths.vmstate).await.unwrap_or(false);
            let recovered_to = if slot_complete {
                self.state
                    .update_vm_runtime(vm.id, VmLifecycleState::Suspended, None)?;
                "suspended"
            } else {
                let _ = tokio::fs::remove_dir_all(self.suspend_slot_dir(vm.id)).await;
                self.state.mark_vm_stopped(vm.id)?;
                "stopped"
            };
            warn!(vm = %vm.name, recovered_to, "reconciled interrupted suspend");
            reconciled += 1;
        }
        Ok(reconciled)
    }

    /// Recover source rootfs disks left stranded by a fork that crashed mid-load
    /// on a prior daemon run. Such a fork leaves the source's `rootfs.ext4` as a
    /// stale symlink to the fork clone, with the real disk in a
    /// `rootfs.ext4.fork-src-bak` backup. Restore each one before any resume can
    /// open the stale symlink and boot the source against the wrong disk. Run at
    /// daemon startup. Returns the number recovered.
    pub fn recover_stranded_fork_rootfs(&self) -> usize {
        let vms = match self.state.list_vms() {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "failed to list VMs for stranded-fork rootfs recovery");
                return 0;
            }
        };
        let mut recovered = 0;
        for vm in vms {
            let rootfs = self.storage.vm_dir(&vm.name).join("rootfs.ext4");
            match husker_vmm::firecracker::recover_aliased_rootfs(&rootfs) {
                Ok(true) => {
                    warn!(vm = %vm.name, "recovered source rootfs stranded by an interrupted fork");
                    recovered += 1;
                }
                Ok(false) => {}
                Err(e) => {
                    warn!(vm = %vm.name, error = %e, "failed to recover stranded fork source rootfs")
                }
            }
        }
        recovered
    }

    /// Restore a suspended VM in place (same id/IP/CID/MAC).
    async fn restore_from_suspend(&self, record: &VmRecord) -> Result<(), CoreError> {
        let slot = self.suspend_slot_dir(record.id);
        let paths = SnapshotPaths::in_dir(&slot);

        let manifest_bytes = tokio::fs::read(&paths.manifest)
            .await
            .map_err(|e| CoreError::Io(format!("suspend slot missing manifest: {e}")))?;
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| CoreError::InvalidArgument(format!("invalid suspend manifest: {e}")))?;
        let backend = manifest
            .get("backend")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if backend != record.vmm.as_str() {
            return Err(CoreError::InvalidArgument(format!(
                "suspend snapshot backend '{backend}' does not match VM backend '{}'",
                record.vmm
            )));
        }

        let target = RestoreTarget::Resume {
            id: record.id,
            name: record.name.clone(),
            vcpu_count: record.vcpu_count,
            mem_size_mib: record.mem_size_mib,
            vsock_cid: record.vsock_cid,
        };
        let restored = self.vmm.restore_vm(&paths, target).await?;
        self.state
            .update_vm_runtime(record.id, VmLifecycleState::Running, restored.pid)?;

        let _ = tokio::fs::remove_dir_all(&slot).await;
        Ok(())
    }

    /// Resume a paused or suspended VM.
    ///
    /// - `paused`: un-pauses the running VMM process. Pausing never removed
    ///   DNAT or installed a resume listener (see `suspend_vm_locked`), so
    ///   resuming from `paused` touches no networking and is not part of the
    ///   idle-suspend lifecycle: `suspended_at` and the idle timers are left
    ///   untouched.
    /// - `suspended`: restores full VM state from the suspend slot on disk,
    ///   re-adds DNAT, drains and closes any resume listener, and resets both
    ///   idle timers so the woken VM gets a fresh full window.
    /// - `running`: idempotent no-op.
    ///
    /// Returns `true` only for a real `suspended` -> `running` restore;
    /// `paused` -> `running` and the already-running no-op both return
    /// `false`. Callers that bump an "auto-resumed from idle-suspend" metric
    /// should gate on `true` so neither an already-running race nor an
    /// unrelated pause/unpause cycle is miscounted as an idle auto-resume.
    pub async fn resume_vm(&self, name: &str) -> Result<bool, CoreError> {
        info!(%name, "resuming VM");
        // Serialize against a concurrent fork/suspend of this VM (see `suspend_vm`):
        // restoring a suspended source must not interleave with a fork that has the
        // source's rootfs aliased to a clone during `/snapshot/load`.
        let _guard = self.vm_name_lock(name).lock_owned().await;
        let record = self.lookup_vm(name)?;
        self.ensure_vm_is_not_pool_template(&record)?;
        // Only a "suspended" restore removed DNAT and installed resume
        // listeners (see `suspend_vm_locked`); a "paused" VM never touched
        // networking, so its resume must not either, and it is not part of
        // the idle-suspend lifecycle (no `suspended_at` to clear, no idle
        // timers to reset).
        let restoring_from_suspend = record.state == VmLifecycleState::Suspended;
        match record.state {
            VmLifecycleState::Paused => {
                self.vmm.resume_vm(record.id).await?;
                self.state
                    .update_vm_state(record.id, VmLifecycleState::Running)?;
            }
            VmLifecycleState::Suspended => {
                self.restore_from_suspend(&record).await?;
            }
            VmLifecycleState::Running => {
                debug!(%name, "VM already running; resume is a no-op");
                return Ok(false);
            }
            _ => {
                return Err(CoreError::InvalidState {
                    name: name.into(),
                    actual: record.state.to_string(),
                    expected: "paused or suspended".into(),
                });
            }
        }

        if restoring_from_suspend {
            #[cfg(feature = "linux-net")]
            {
                let forwards = self
                    .state
                    .list_port_forwards_for_vm(record.id)
                    .unwrap_or_default();
                // Re-add DNAT before draining the resume listener, so new
                // connections use the kernel path while ones already queued on
                // the userspace listener are still relayed.
                for pf in &forwards {
                    if let (Some(tap), Some(gip)) =
                        (record.tap_device.as_deref(), record.guest_ip.as_deref())
                        && let Ok(gip) = gip.parse()
                    {
                        let _ = self
                            .host_network
                            .add_port_forward(
                                pf.host_port,
                                gip,
                                pf.guest_port,
                                tap,
                                &self.bridge_name,
                            )
                            .await;
                    }
                }
                if let Some(proxy) = self.resume_listeners.lock().remove(&record.id) {
                    proxy.drain_and_close(record.id);
                }
                // Drop stale counter baselines: the DNAT rules were just
                // recreated at 0, so any pre-suspend baseline is invalid.
                // Clear this VM's comment keys so the next tick re-baselines
                // instead of comparing new(small) against old(large) and
                // missing traffic.
                {
                    let mut nc = self.network_counters.lock();
                    for pf in &forwards {
                        if let Some(tap) = record.tap_device.as_deref() {
                            nc.remove(&format!("husker-pf:{tap}:{}", pf.host_port));
                        }
                    }
                }
            }

            // Reset idle timers so the woken VM gets a fresh full window
            // (in-memory + the DB mirror, so the fallback in idle_for is also
            // fresh if the maps are ever lost).
            let now = std::time::Instant::now();
            self.control_plane_last_active.lock().insert(record.id, now);
            self.network_last_active.lock().insert(record.id, now);
            let _ = self
                .state
                .touch_last_activity(record.id, chrono::Utc::now());
            self.state.set_suspended_at(record.id, None)?;
        }

        Ok(restoring_from_suspend)
    }
}
