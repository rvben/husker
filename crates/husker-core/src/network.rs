use super::*;

impl<B: VmmBackend> HuskerCore<B> {
    /// Fill guest_ip for a running EFI-boot VM that does not have one yet.
    ///
    /// Attempts vsock connect (1-second timeout) then a GuestInfo request
    /// (1-second timeout) - at most 2 seconds per call in the worst case.
    /// Persists on success. Never fails the read - any error or timeout is
    /// silently discarded (debug! at most).
    ///
    /// Boot modes "efi" (VZ cloud images) and "macos" (VZ macOS guests) get a
    /// DHCP-assigned guest IP that is not known at creation time. On Linux, boot
    /// mode is always direct or UEFI, so this function is a no-op.
    pub(crate) async fn discover_guest_ip(&self, vm: &mut VmRecord) {
        if vm.guest_ip.is_some()
            || vm.state != VmLifecycleState::Running
            || !vm.boot_mode.learns_guest_ip_from_agent()
        {
            return;
        }

        let connect_result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            self.vmm
                .vsock_connect(vm.id, husker_agent_proto::AGENT_VSOCK_PORT),
        )
        .await;

        let stream = match connect_result {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                debug!(name = %vm.name, error = %e, "discover_guest_ip: vsock connect failed");
                return;
            }
            Err(_) => {
                debug!(name = %vm.name, "discover_guest_ip: vsock connect timed out");
                return;
            }
        };

        let mut conn = crate::agent_client::AgentConnection::new(stream);
        let info_result =
            tokio::time::timeout(std::time::Duration::from_secs(1), conn.guest_info()).await;

        let info = match info_result {
            Ok(Ok(i)) => i,
            Ok(Err(e)) => {
                debug!(name = %vm.name, error = %e, "discover_guest_ip: GuestInfo request failed");
                return;
            }
            Err(_) => {
                debug!(name = %vm.name, "discover_guest_ip: GuestInfo request timed out");
                return;
            }
        };

        let Some(ip) = info.ipv4.into_iter().next() else {
            debug!(name = %vm.name, "discover_guest_ip: agent returned no IPv4 addresses");
            return;
        };

        // The agent's reported address is untrusted guest input. Check it against
        // the host's own interfaces before persisting, so a compromised guest
        // cannot point the VM's port forwards at the host's services or at an
        // address outside the links a VM can sit on. A report that cannot be
        // checked is dropped; the next read asks the agent again.
        let parsed = match ip.parse::<std::net::Ipv4Addr>() {
            Ok(addr) => {
                let host_links = match host_ipv4_links() {
                    Ok(links) => links,
                    Err(e) => {
                        warn!(name = %vm.name, reported = %addr, error = %e, "discover_guest_ip: cannot list the host's interfaces to check the reported guest IP; ignoring it");
                        return;
                    }
                };
                match check_guest_ip(&addr, &host_links) {
                    Ok(()) => addr,
                    Err(reason) => {
                        warn!(name = %vm.name, reported = %addr, %reason, "discover_guest_ip: agent reported an untrustworthy guest IP; ignoring");
                        return;
                    }
                }
            }
            Err(e) => {
                warn!(name = %vm.name, reported = %ip, error = %e, "discover_guest_ip: agent reported an unparseable IPv4; ignoring");
                return;
            }
        };

        let canonical = parsed.to_string();
        if let Err(e) = self.state.update_vm_guest_ip(vm.id, &canonical) {
            warn!(name = %vm.name, error = %e, "discover_guest_ip: failed to persist guest IP");
        }
        vm.guest_ip = Some(canonical);
    }

    /// Refresh a persisted VM record against the backend's live process view.
    ///
    /// The backend's `vm_info` performs the actual liveness check (`try_wait`,
    /// which also reaps a child that exited on its own, e.g. a guest-initiated
    /// `poweroff`/`reboot`). When the DB says running/paused but the process is
    /// gone - the backend reports Stopped/Failed, or no longer tracks the VM at
    /// all - the record is marked stopped in state and the updated record is
    /// returned. Errors persisting the state are logged, not fatal: the caller
    /// still sees the corrected in-memory record.
    ///
    /// Platform scope: Firecracker and QEMU backends detect process exit via
    /// `try_wait` on the child process. The Apple VZ backend queries the live
    /// `VZVirtualMachine.state()` on the VM's dispatch queue so guest-initiated
    /// shutdown (poweroff, kernel panic) is also detected on macOS.
    pub async fn refresh_vm_liveness(&self, vm: &VmRecord) -> VmRecord {
        if !vm.state.is_live() {
            return vm.clone();
        }
        let alive = match self.vmm.vm_info(vm.id).await {
            Ok(info) => matches!(info.state, VmState::Running | VmState::Paused),
            // Backend does not track this VM (e.g. process reaped or daemon
            // restarted): it is not running.
            Err(_) => false,
        };
        if alive {
            return vm.clone();
        }
        info!(name = %vm.name, "VM process is gone; marking stopped");
        if let Err(e) = self.state.mark_vm_stopped(vm.id) {
            warn!(name = %vm.name, error = %e, "failed to persist stopped state");
        }
        let mut updated = vm.clone();
        updated.state = VmLifecycleState::Stopped;
        updated.pid = None;
        updated
    }

    /// Add a port forward from a host port to a guest port on a VM.
    #[cfg(feature = "linux-net")]
    pub async fn add_port_forward(
        &self,
        name: &str,
        host_port: u16,
        guest_port: u16,
        bind_addr: Option<std::net::IpAddr>,
    ) -> Result<husker_state::PortForwardRecord, CoreError> {
        let record = self.lookup_vm(name)?;

        if record.network != NetworkMode::Nat {
            return Err(CoreError::InvalidArgument(format!(
                "VM '{name}' uses {} networking; port forwards apply to NAT VMs only",
                record.network
            )));
        }

        // The Linux nftables backend exposes forwards on all host interfaces; a
        // specific bind address is not supported here.
        if let Some(addr) = bind_addr
            && !addr.is_unspecified()
        {
            return Err(CoreError::InvalidArgument(format!(
                "--bind {addr} is not supported on the Linux nftables backend; \
                 forwards are reachable on all host interfaces"
            )));
        }

        let guest_ip: std::net::Ipv4Addr = record
            .guest_ip
            .as_deref()
            .ok_or_else(|| CoreError::VmNotFound(format!("{name}: no guest IP")))?
            .parse()
            .map_err(|_| CoreError::VmNotFound(format!("{name}: invalid guest IP")))?;
        let tap_name = record
            .tap_device
            .as_deref()
            .ok_or_else(|| CoreError::VmNotFound(format!("{name}: no TAP device")))?;

        // Idempotent behavior: if this exact forward already exists on this VM,
        // treat it as success.
        if let Ok(existing) = self.state.list_port_forwards_for_vm(record.id)
            && let Some(found) = existing
                .iter()
                .find(|pf| pf.host_port == host_port && pf.guest_port == guest_port)
        {
            info!(%name, host_port, guest_port, "port forward already present (no-op)");
            return Ok(found.clone());
        }

        self.host_network
            .add_port_forward(host_port, guest_ip, guest_port, tap_name, &self.bridge_name)
            .await?;

        let pf_record = husker_state::PortForwardRecord {
            id: 0,
            vm_id: record.id,
            host_port,
            guest_port,
            protocol: "tcp".into(),
            bind_addr: None,
            created_at: chrono::Utc::now(),
        };
        if let Err(e) = self
            .state
            .insert_port_forward(&pf_record)
            .map_err(|e| match e {
                husker_state::StateError::PortAlreadyForwarded(port) => {
                    CoreError::PortForwardConflict(port)
                }
                other => CoreError::State(other),
            })
        {
            if let Err(rollback_err) = self
                .host_network
                .remove_port_forward(host_port, tap_name, &self.bridge_name)
                .await
            {
                warn!(
                    %name,
                    host_port,
                    tap = tap_name,
                    error = %rollback_err,
                    "failed to rollback nftables rule after state insert error"
                );
            }
            return Err(e);
        }

        info!(%name, host_port, guest_port, "port forward added");
        Ok(pf_record)
    }

    /// Remove a port forward.
    #[cfg(feature = "linux-net")]
    pub async fn remove_port_forward(&self, name: &str, host_port: u16) -> Result<(), CoreError> {
        let record = self.lookup_vm(name)?;
        let tap_name = record
            .tap_device
            .as_deref()
            .ok_or_else(|| CoreError::VmNotFound(format!("{name}: no TAP device")))?;

        self.host_network
            .remove_port_forward(host_port, tap_name, &self.bridge_name)
            .await?;
        self.state.delete_port_forward(host_port)?;
        self.network_counters
            .lock()
            .remove(&format!("husker-pf:{tap_name}:{host_port}"));

        info!(%name, host_port, "port forward removed");
        Ok(())
    }

    /// Add a port forward via the userspace proxy (macOS).
    ///
    /// Binds a host TCP listener and relays accepted connections to the guest.
    /// The forward is bound to the running VM instance; it is torn down on stop
    /// or destroy and does not survive a daemon restart.
    #[cfg(not(feature = "linux-net"))]
    pub async fn add_port_forward(
        &self,
        name: &str,
        host_port: u16,
        guest_port: u16,
        bind_addr: Option<std::net::IpAddr>,
    ) -> Result<husker_state::PortForwardRecord, CoreError> {
        let _guard = self.vm_name_lock(name).lock_owned().await;
        let record = self.lookup_vm(name)?;
        if record.network != NetworkMode::Nat {
            return Err(CoreError::InvalidArgument(format!(
                "VM '{name}' uses {} networking; port forwards apply to NAT VMs only",
                record.network
            )));
        }
        if record.state != VmLifecycleState::Running {
            return Err(CoreError::InvalidState {
                name: name.into(),
                actual: record.state.to_string(),
                expected: "running".into(),
            });
        }
        let guest_ip: std::net::Ipv4Addr = record
            .guest_ip
            .as_deref()
            .ok_or_else(|| CoreError::InvalidState {
                name: name.into(),
                actual: "running without a discovered guest IP".into(),
                expected: "running with a guest IP".into(),
            })?
            .parse()
            .map_err(|_| CoreError::InvalidArgument(format!("{name}: invalid guest IP")))?;

        let bind = bind_addr.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let bind_str = bind.to_string();

        // Idempotent only when host port, guest port, AND bind address all match
        // an existing forward. A re-add with a different bind on the same host
        // port falls through and is rejected as a conflict by the bind below.
        if let Ok(existing) = self.state.list_port_forwards_for_vm(record.id)
            && let Some(found) = existing.iter().find(|pf| {
                pf.host_port == host_port
                    && pf.guest_port == guest_port
                    && pf.bind_addr.as_deref() == Some(bind_str.as_str())
            })
        {
            return Ok(found.clone());
        }

        let bound = self
            .port_proxy
            .add(record.id, bind, host_port, guest_ip, guest_port)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::AddrInUse => CoreError::PortForwardConflict(host_port),
                std::io::ErrorKind::PermissionDenied => CoreError::PortForwardDenied(host_port),
                _ => CoreError::Io(e.to_string()),
            })?;

        let pf_record = husker_state::PortForwardRecord {
            id: 0,
            vm_id: record.id,
            host_port: bound,
            guest_port,
            protocol: "tcp".into(),
            bind_addr: Some(bind_str),
            created_at: chrono::Utc::now(),
        };
        if let Err(e) = self
            .state
            .insert_port_forward(&pf_record)
            .map_err(|e| match e {
                husker_state::StateError::PortAlreadyForwarded(_) => {
                    CoreError::PortForwardConflict(bound)
                }
                other => CoreError::State(other),
            })
        {
            self.port_proxy.stop(record.id, bound);
            return Err(e);
        }
        info!(%name, host_port = bound, guest_port, "port forward added (userspace proxy)");
        Ok(pf_record)
    }

    /// Remove a port forward (macOS userspace proxy).
    #[cfg(not(feature = "linux-net"))]
    pub async fn remove_port_forward(&self, name: &str, host_port: u16) -> Result<(), CoreError> {
        let _guard = self.vm_name_lock(name).lock_owned().await;
        let record = self.lookup_vm(name)?;
        // Only remove a forward that belongs to this VM. `delete_port_forward`
        // keys on host_port globally, so an unscoped delete could drop another
        // VM's row and orphan its listener. No-op (idempotent) otherwise.
        let owned = self
            .state
            .list_port_forwards_for_vm(record.id)?
            .iter()
            .any(|pf| pf.host_port == host_port);
        if owned {
            self.port_proxy.stop(record.id, host_port);
            self.state.delete_port_forward(host_port)?;
            info!(%name, host_port, "port forward removed (userspace proxy)");
        }
        Ok(())
    }

    /// List port forwards for a VM.
    pub fn list_port_forwards(
        &self,
        name: &str,
    ) -> Result<Vec<husker_state::PortForwardRecord>, CoreError> {
        let record = self.lookup_vm(name)?;
        Ok(self.state.list_port_forwards_for_vm(record.id)?)
    }

    /// The IPv4 resolvers a pinned egress policy admits so the guest can still
    /// resolve names. The policy lives in the bridge-family IPv4 rules, so a
    /// configured resolver that is not an IPv4 address gets no carve-out and
    /// stays denied like any other unlisted destination.
    #[cfg(feature = "linux-net")]
    pub(crate) fn egress_resolvers(&self) -> Vec<Ipv4Addr> {
        self.dns_servers
            .iter()
            .filter_map(|value| value.parse().ok())
            .collect()
    }

    /// Re-install a VM's persisted egress policy on its TAP. Persisted rules
    /// are security state: a policy that no longer parses is an error, never
    /// an empty allow-list.
    #[cfg(feature = "linux-net")]
    pub(crate) async fn apply_persisted_egress_policy(
        &self,
        tap: &str,
        serialized: &str,
    ) -> Result<(), CoreError> {
        let persisted = crate::egress::parse_persisted_rules(serialized)?;
        let rules = crate::egress::net_rules(&persisted);
        self.host_network
            .apply_egress_policy(
                tap,
                &self.bridge_name,
                self.ip_allocator.gateway(),
                &self.egress_resolvers(),
                &rules,
            )
            .await?;
        Ok(())
    }

    /// The bridge a suspended VM's preserved TAP belongs to, or `None` for an
    /// isolated VM that never had one.
    #[cfg(feature = "linux-net")]
    fn suspended_vm_bridge(&self, vm: &VmRecord) -> Result<Option<&str>, CoreError> {
        match vm.network {
            NetworkMode::Isolated => Ok(None),
            NetworkMode::Nat => Ok(Some(self.bridge_name.as_str())),
            NetworkMode::Bridged => {
                self.lan_bridge
                    .as_deref()
                    .map(Some)
                    .ok_or_else(|| CoreError::InvalidState {
                        name: vm.name.clone(),
                        actual: "suspended with bridged networking but no LAN bridge configured"
                            .into(),
                        expected: "a configured LAN bridge".into(),
                    })
            }
        }
    }

    /// Put a suspended VM's host network back the way its snapshot expects it
    /// before the guest runs again: the persisted egress policy on the TAP,
    /// then the TAP enslaved to its bridge. Both steps are idempotent, so this
    /// is safe to run at every daemon start and again on every resume.
    ///
    /// Suspending keeps the TAP so the snapshot resumes with the same network
    /// identity, but deleting the managed bridge at daemon shutdown detaches
    /// it, and a host reboot removes it altogether while the snapshot on disk
    /// survives. A detached TAP is re-enslaved; a vanished one is recreated
    /// under its persisted name so the restore can open it.
    ///
    /// Returns whether the TAP had to be recreated (`false` for an isolated
    /// VM, which has no host network). An error means the guest must not run:
    /// the policy is applied before the attach, so a policy failure leaves the
    /// TAP disconnected instead of connected and unfiltered.
    #[cfg(feature = "linux-net")]
    pub(crate) async fn restore_suspended_vm_network(
        &self,
        vm: &VmRecord,
    ) -> Result<bool, CoreError> {
        let Some(bridge) = self.suspended_vm_bridge(vm)? else {
            return Ok(false);
        };
        let tap = vm
            .tap_device
            .as_deref()
            .ok_or_else(|| CoreError::InvalidState {
                name: vm.name.clone(),
                actual: "suspended without a preserved TAP device".into(),
                expected: "suspended with a preserved TAP device".into(),
            })?;
        if let Some(serialized) = vm.egress_policy.as_deref() {
            self.apply_persisted_egress_policy(tap, serialized).await?;
        }
        match self.host_network.attach_to_bridge(tap, bridge).await {
            Ok(()) => Ok(false),
            Err(error) if error.is_missing_interface(tap) => {
                info!(
                    name = %vm.name,
                    tap,
                    "preserved TAP of suspended VM is gone; recreating it for the snapshot"
                );
                self.host_network.create_tap(tap).await?;
                if let Err(error) = self.host_network.attach_to_bridge(tap, bridge).await {
                    // A masterless TAP carries no traffic, but it would still
                    // occupy the name on the next attempt.
                    if let Err(cleanup) = self.host_network.delete_tap(tap).await {
                        warn!(name = %vm.name, tap, error = %cleanup, "failed to remove the recreated TAP after its attach failed");
                    }
                    return Err(error.into());
                }
                Ok(true)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Restore the host network of every suspended VM during daemon startup.
    ///
    /// This must run after the managed bridge and nftables tables exist and
    /// before resume listeners or the API become reachable; otherwise a
    /// connect can resume a guest whose network is still disconnected. Each VM
    /// is handled on its own: one whose network cannot be restored is logged
    /// and counted, and its resume repeats the attempt and fails with the real
    /// error, while every other VM and the daemon itself keep going. Only a
    /// state-store failure is fatal, since nothing can be served without it.
    #[cfg(feature = "linux-net")]
    pub async fn restore_suspended_vm_networks(
        &self,
    ) -> Result<SuspendedNetworkRestore, CoreError> {
        let mut summary = SuspendedNetworkRestore::default();
        for vm in self.state.list_vms()? {
            if vm.state != VmLifecycleState::Suspended || vm.network == NetworkMode::Isolated {
                continue;
            }
            match self.restore_suspended_vm_network(&vm).await {
                Ok(recreated) => {
                    summary.restored += 1;
                    if recreated {
                        summary.recreated += 1;
                    }
                }
                Err(error) => {
                    summary.failed += 1;
                    warn!(
                        name = %vm.name,
                        tap = vm.tap_device.as_deref().unwrap_or("-"),
                        error = %error,
                        "failed to restore suspended VM network during startup; its resume will retry and report this error"
                    );
                }
            }
        }
        Ok(summary)
    }

    /// Rebuild nftables port-forward rules from persisted state on startup.
    ///
    /// This closes drift after daemon restarts because `init_nat` recreates the
    /// nftables table while port-forward records remain in SQLite.
    #[cfg(feature = "linux-net")]
    pub async fn reconcile_port_forwards_from_state(&self) -> PortForwardReconcile {
        let vms = match self.state.list_vms() {
            Ok(vms) => vms,
            Err(e) => {
                warn!(error = %e, "failed to list VMs for port-forward reconciliation");
                return PortForwardReconcile::default();
            }
        };

        let mut restored = 0usize;
        let mut skipped_suspended = 0usize;
        for vm in vms {
            if vm.network != NetworkMode::Nat {
                continue;
            }
            if vm.state == VmLifecycleState::Suspended {
                // A suspended VM has no live guest; DNAT would blackhole traffic to a
                // dead IP and bypass the resume listener. Skip; listeners are
                // re-installed separately by `reinstall_resume_listeners`.
                skipped_suspended += 1;
                continue;
            }
            let Some(guest_ip_str) = vm.guest_ip.as_deref() else {
                continue;
            };
            let Some(tap_name) = vm.tap_device.as_deref() else {
                continue;
            };
            let guest_ip: Ipv4Addr = match guest_ip_str.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    warn!(name = %vm.name, guest_ip = %guest_ip_str, "skipping invalid guest IP during reconciliation");
                    continue;
                }
            };

            let forwards = match self.state.list_port_forwards_for_vm(vm.id) {
                Ok(f) => f,
                Err(e) => {
                    warn!(name = %vm.name, error = %e, "failed to list port forwards during reconciliation");
                    continue;
                }
            };

            for pf in forwards {
                match self
                    .host_network
                    .add_port_forward(
                        pf.host_port,
                        guest_ip,
                        pf.guest_port,
                        tap_name,
                        &self.bridge_name,
                    )
                    .await
                {
                    Ok(()) => {
                        restored += 1;
                    }
                    Err(e) => {
                        warn!(
                            name = %vm.name,
                            tap = tap_name,
                            host_port = pf.host_port,
                            guest_port = pf.guest_port,
                            error = %e,
                            "failed to restore port-forward rule"
                        );
                    }
                }
            }
        }
        PortForwardReconcile {
            restored,
            skipped_suspended,
        }
    }

    /// Re-bind userspace resume listeners for `suspended` + `auto_resume` VMs
    /// after a daemon restart.
    ///
    /// `reconcile_port_forwards_from_state` intentionally skips DNAT restore
    /// for `suspended` VMs (see above); without this, a suspended VM that was
    /// relying on a resume listener before the restart would come back up
    /// with neither kernel DNAT nor a userspace listener on its forwarded
    /// ports, so nothing would ever auto-resume it on connect. Call after
    /// `reconcile_port_forwards_from_state` at startup.
    #[cfg(feature = "linux-net")]
    pub async fn reinstall_resume_listeners(self: &Arc<Self>)
    where
        B: 'static,
    {
        let vms = match self.state.list_vms() {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "failed to list VMs for resume-listener reinstall");
                return;
            }
        };
        for vm in vms {
            if vm.network != NetworkMode::Nat
                || vm.state != VmLifecycleState::Suspended
                || !vm.auto_resume
            {
                continue;
            }
            let forwards = self
                .state
                .list_port_forwards_for_vm(vm.id)
                .unwrap_or_default();
            if forwards.is_empty() {
                continue;
            }
            self.install_resume_listeners(&vm, &forwards).await;
        }
    }

    /// No-op on macOS: the userspace port-forward proxy there relays
    /// continuously regardless of VM state and has no separate DNAT/listener
    /// split, so there is nothing to reinstall after a restart.
    #[cfg(not(feature = "linux-net"))]
    pub async fn reinstall_resume_listeners(self: &Arc<Self>) {}
}
