use super::*;

impl<B: VmmBackend> HuskerCore<B> {
    #[cfg(feature = "linux-net")]
    pub(crate) async fn remove_tap_host_resources(&self, tap: &str) -> Result<(), CoreError> {
        let egress_result = self
            .host_network
            .remove_egress_policy(tap, &self.bridge_name)
            .await;
        let forward_result = self
            .host_network
            .remove_all_port_forwards(tap, &self.bridge_name)
            .await;
        let tap_result = self.host_network.delete_tap(tap).await;

        egress_result?;
        forward_result?;
        tap_result?;
        Ok(())
    }

    /// Remove the host resources owned by a persisted VM record. Both nftables
    /// and TAP cleanup are attempted; IP ownership is released only when the
    /// kernel resources are gone.
    #[cfg(feature = "linux-net")]
    pub(crate) async fn release_vm_host_network(&self, record: &VmRecord) -> Result<(), CoreError> {
        if let Some(tap) = record.tap_device.as_deref() {
            self.remove_tap_host_resources(tap).await?;
        }

        if let Some(guest_ip) = record.guest_ip.as_deref() {
            let guest_ip = guest_ip.parse::<Ipv4Addr>().map_err(|error| {
                CoreError::State(husker_state::StateError::CorruptData {
                    column: "vms.guest_ip",
                    message: error.to_string(),
                })
            })?;
            self.ip_allocator.release(guest_ip)?;
        }
        Ok(())
    }

    /// Reclaim resources owned by VM creations interrupted before their final
    /// VM record was committed. A lease is released only after every host
    /// resource it names is gone, so a lease whose cleanup fails is kept and
    /// retried at the next startup. Each lease is handled on its own: one
    /// stuck lease blocks neither the other leases nor the daemon. Only a
    /// state-store failure is fatal.
    ///
    /// A lease is reclaimed only with positive proof that nothing else owns
    /// what it names. It is kept, untouched, while:
    /// - the backend was entered and its destruction was never confirmed;
    /// - a factory job owns the lease without a terminal, cleaned-up VM;
    /// - a committed VM record holds its name (creation refuses a taken name
    ///   and commit inserts the record and deletes the lease in one
    ///   transaction, so this needs an operator: deleting the VM lets the
    ///   next startup reclaim);
    /// - another lease names the same VM UUID or guest address, or a VM
    ///   record holds that address.
    pub async fn recover_host_resource_leases(&self) -> Result<HostResourceRecovery, CoreError> {
        let mut summary = HostResourceRecovery::default();
        for lease in self.state.list_host_resource_leases()? {
            if lease.backend_entered && !lease.vm_destroyed {
                summary.failed += 1;
                warn!(vm = %lease.vm_name, lease = %lease.id,
                    "preserving creation lease without durable backend destruction proof");
                continue;
            }
            let job = self
                .state
                .job_for_pending_vm_name(&lease.vm_name)
                .map_err(|error| {
                    CoreError::Io(format!("inspect creation lease job owner: {error}"))
                })?;
            // Follow job -> name lock order used by the factory allocator.
            let _job_guard = if let Some(job) = &job {
                Some(self.job_lifecycle_lock(job.id).lock_owned().await)
            } else {
                None
            };
            let _name_guard = self.vm_name_lock(&lease.vm_name).lock_owned().await;
            // A creator may have committed and another attempt may now own the
            // name while recovery waited. A stale snapshot cannot delete it.
            let lease = match self.state.get_host_resource_lease(lease.id) {
                Ok(fresh) if fresh.vm_name == lease.vm_name => fresh,
                Ok(_) | Err(husker_state::StateError::HostResourceLeaseNotFound(_)) => continue,
                Err(error) => return Err(error.into()),
            };
            if lease.backend_entered && !lease.vm_destroyed {
                summary.failed += 1;
                warn!(vm = %lease.vm_name, lease = %lease.id,
                    "preserving creation lease without durable backend destruction proof");
                continue;
            }
            let fresh = self
                .state
                .job_for_pending_vm_name(&lease.vm_name)
                .map_err(|error| {
                    CoreError::Io(format!("recheck creation lease job owner: {error}"))
                })?;
            if let Some(fresh) = fresh
                && (job.as_ref().map(|job| job.id) != Some(fresh.id)
                    || lease.vm_id.is_none()
                    || lease.vm_id != fresh.vm_id
                    || !fresh.state.terminal()
                    || (!fresh.vm_destroyed && !fresh.vm_allocation_aborted))
            {
                summary.failed += 1;
                warn!(vm = %lease.vm_name, job = %fresh.id,
                    "preserving creation lease without positive factory VM cleanup proof");
                continue;
            }
            match self.state.get_vm_by_name(&lease.vm_name) {
                Ok(vm) => {
                    summary.failed += 1;
                    warn!(
                        vm = %lease.vm_name,
                        id = %vm.id,
                        cid = lease.vsock_cid,
                        "a creation lease names a committed VM; leaving its host resources untouched and keeping the lease"
                    );
                    continue;
                }
                Err(husker_state::StateError::VmNotFoundByName(_)) => {}
                Err(error) => return Err(error.into()),
            }
            if lease.vm_id.is_some()
                && self
                    .state
                    .list_host_resource_leases()?
                    .iter()
                    .any(|other| other.id != lease.id && other.vm_id == lease.vm_id)
            {
                summary.failed += 1;
                warn!(vm = %lease.vm_name, lease = %lease.id,
                    "preserving creation lease with another durable owner of its VM UUID");
                continue;
            }
            #[cfg(feature = "linux-net")]
            let guest_ip = match lease
                .guest_ip
                .as_deref()
                .map(str::parse::<Ipv4Addr>)
                .transpose()
            {
                Ok(address) => address,
                Err(error) => {
                    summary.failed += 1;
                    warn!(vm = %lease.vm_name, lease = %lease.id, %error,
                        "preserving creation lease with an unreadable guest address");
                    continue;
                }
            };
            #[cfg(feature = "linux-net")]
            if let Some(address) = guest_ip
                && self.guest_address_has_another_owner(&lease, address)?
            {
                summary.failed += 1;
                warn!(vm = %lease.vm_name, lease = %lease.id,
                    "preserving creation lease whose address has another durable owner");
                continue;
            }
            match self.reclaim_leased_host_resources(&lease).await {
                Ok(()) => {
                    self.state.release_host_resource_lease(lease.id)?;
                    // Return the in-memory address only after the durable owner
                    // has been released. A database failure must keep both
                    // reservations.
                    #[cfg(feature = "linux-net")]
                    if let Some(address) = guest_ip {
                        match self.ip_allocator.release(address) {
                            Ok(()) | Err(husker_net::NetError::NotAllocated(_)) => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                    summary.recovered += 1;
                    info!(vm = %lease.vm_name, cid = lease.vsock_cid, "recovered interrupted VM host resources");
                }
                Err(error) => {
                    summary.failed += 1;
                    warn!(
                        vm = %lease.vm_name,
                        cid = lease.vsock_cid,
                        error = %error,
                        "could not reclaim interrupted VM host resources; keeping the lease for the next startup"
                    );
                }
            }
        }
        Ok(summary)
    }

    /// Whether a VM record or another creation lease holds `address`.
    #[cfg(feature = "linux-net")]
    fn guest_address_has_another_owner(
        &self,
        lease: &husker_state::HostResourceLease,
        address: Ipv4Addr,
    ) -> Result<bool, CoreError> {
        let holds =
            |ip: Option<&str>| ip.and_then(|ip| ip.parse::<Ipv4Addr>().ok()) == Some(address);
        Ok(self
            .state
            .list_vms()?
            .iter()
            .any(|vm| holds(vm.guest_ip.as_deref()))
            || self
                .state
                .list_host_resource_leases()?
                .iter()
                .any(|other| other.id != lease.id && holds(other.guest_ip.as_deref())))
    }

    async fn reclaim_leased_host_resources(
        &self,
        lease: &husker_state::HostResourceLease,
    ) -> Result<(), CoreError> {
        #[cfg(not(feature = "linux-net"))]
        if lease.tap_device.is_some() || lease.guest_ip.is_some() {
            return Err(CoreError::InvalidArgument(
                "creation lease owns Linux network resources unsupported by this host".into(),
            ));
        }
        #[cfg(feature = "linux-net")]
        if let Some(tap) = lease.tap_device.as_deref() {
            self.remove_tap_host_resources(tap).await?;
        }
        let vm_dir = self.storage.vm_dir(&lease.vm_name);
        match tokio::fs::remove_dir_all(&vm_dir).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(CoreError::Io(format!(
                "remove interrupted VM directory {}: {error}",
                vm_dir.display()
            ))),
        }
    }
}
