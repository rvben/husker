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

    /// Recover only leases with confirmed ownership and backend destruction.
    /// One unresolved allocation must not prevent recovery of unrelated leases.
    pub async fn recover_host_resource_leases(&self) -> Result<HostResourceRecovery, CoreError> {
        let mut summary = HostResourceRecovery::default();
        for lease in self.state.list_host_resource_leases()? {
            match self.recover_one_host_resource_lease(lease).await {
                Ok(true) => summary.recovered += 1,
                Ok(false) => summary.failed += 1,
                Err(error @ (CoreError::State(_) | CoreError::InvalidArgument(_))) => {
                    return Err(error);
                }
                Err(error) => {
                    summary.failed += 1;
                    warn!(%error, "creation lease remains owned for recovery retry");
                }
            }
        }
        Ok(summary)
    }
    async fn recover_one_host_resource_lease(
        &self,
        lease: husker_state::HostResourceLease,
    ) -> Result<bool, CoreError> {
        let job = self
            .state
            .job_for_pending_vm_name(&lease.vm_name)
            .map_err(crate::job_boot::journal)?;
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
            Ok(_) | Err(husker_state::StateError::HostResourceLeaseNotFound(_)) => {
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        let fresh = self
            .state
            .job_for_pending_vm_name(&lease.vm_name)
            .map_err(crate::job_boot::journal)?;
        if let Some(fresh) = &fresh
            && (job.as_ref().map(|job| job.id) != Some(fresh.id)
                || lease.vm_id.is_none()
                || lease.vm_id != fresh.vm_id
                || !fresh.state.terminal())
        {
            warn!(vm = %lease.vm_name, job = %fresh.id,
                    "preserving creation lease without positive factory VM cleanup proof");
            return Ok(false);
        }
        match self.state.get_vm_by_name(&lease.vm_name) {
            Ok(_) => {
                warn!(vm = %lease.vm_name, "preserving creation lease while a VM record owns this name");
                return Ok(false);
            }
            Err(husker_state::StateError::VmNotFoundByName(_)) => {}
            Err(error) => return Err(error.into()),
        }
        if self.state.list_host_resource_leases()?.iter().any(|other| {
            other.id != lease.id && lease.vm_id.is_some() && other.vm_id == lease.vm_id
        }) {
            warn!(vm = %lease.vm_name, lease = %lease.id,
                    "preserving creation lease with another durable owner of its VM UUID");
            return Ok(false);
        }
        #[cfg(not(feature = "linux-net"))]
        if lease.tap_device.is_some() || lease.guest_ip.is_some() {
            warn!(lease = %lease.id, "creation lease owns Linux network resources unsupported by this host");
            return Ok(false);
        }
        #[cfg(feature = "linux-net")]
        let guest_ip = lease
            .guest_ip
            .as_deref()
            .map(|address| address.parse::<Ipv4Addr>())
            .transpose()
            .map_err(|error| CoreError::Io(format!("invalid creation lease IP: {error}")))?;
        #[cfg(feature = "linux-net")]
        if let Some(address) = guest_ip
            && (self.state.list_vms()?.iter().any(|vm| {
                vm.guest_ip
                    .as_deref()
                    .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                    == Some(address)
            }) || self.state.list_host_resource_leases()?.iter().any(|other| {
                other.id != lease.id
                    && other
                        .guest_ip
                        .as_deref()
                        .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                        == Some(address)
            }))
        {
            warn!(vm = %lease.vm_name, lease = %lease.id,
                    "preserving creation lease whose address has another durable owner");
            return Ok(false);
        }
        if let Some(vm_id) = lease.vm_id {
            match self.state.get_vm(vm_id) {
                Ok(_) => return Ok(false),
                Err(husker_state::StateError::VmNotFound(_)) => (),
                Err(error) => return Err(error.into()),
            }
        }
        if !self
            .confirm_creation_lease_termination(&lease, fresh.as_ref())
            .await?
        {
            return Ok(false);
        }
        if !lease.backend_entered
            && fresh
                .as_ref()
                .is_some_and(|job| !job.vm_destroyed && !job.vm_allocation_aborted)
        {
            return Ok(false);
        }
        #[cfg(feature = "linux-net")]
        if let Some(tap) = lease.tap_device.as_deref() {
            self.remove_tap_host_resources(tap).await?;
        }

        let vm_dir = self.storage.vm_dir(&lease.vm_name);
        if let Err(error) = tokio::fs::remove_dir_all(&vm_dir).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(CoreError::Io(format!(
                "remove interrupted VM directory {}: {error}",
                vm_dir.display()
            )));
        }

        self.state.release_host_resource_lease(lease.id)?;
        // Return the in-memory address only after the durable owner has
        // been released. A database failure must keep both reservations.
        #[cfg(feature = "linux-net")]
        if let Some(address) = guest_ip {
            match self.ip_allocator.release(address) {
                Ok(()) | Err(husker_net::NetError::NotAllocated(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        info!(vm = %lease.vm_name, cid = lease.vsock_cid, "recovered interrupted VM host resources");
        Ok(true)
    }
    /// Called under the allocation's name lock, after generation and owner
    /// checks. A missing backend handle is never a termination receipt.
    pub(crate) async fn confirm_creation_lease_termination(
        &self,
        lease: &husker_state::HostResourceLease,
        job: Option<&husker_state::jobs::JobRecord>,
    ) -> Result<bool, CoreError> {
        if !lease.backend_entered {
            return Ok(true);
        }
        if lease.vm_destroyed || job.is_some_and(|job| job.vm_destroyed) {
            if !lease.vm_destroyed {
                self.state.record_host_resource_lease_destruction(
                    lease.id,
                    lease.vm_id.ok_or_else(|| {
                        CoreError::Io("destroyed job has no lease generation".into())
                    })?,
                )?;
            }
            if let Some(job) = job {
                self.state
                    .record_job_vm_destruction(job.vm_id.ok_or_else(|| {
                        CoreError::Io("destroyed lease has no job generation".into())
                    })?)
                    .map_err(crate::job_boot::journal)?;
            }
            return Ok(true);
        }
        if self.state.confirm_host_resource_lease_reboot(lease.id)? {
            if let Some(job) = job {
                self.state
                    .record_job_vm_destruction(job.vm_id.ok_or_else(|| {
                        CoreError::Io("reboot recovery has no job generation".into())
                    })?)
                    .map_err(crate::job_boot::journal)?;
            }
            info!(lease = %lease.id, "confirmed allocation termination across a host reboot");
            return Ok(true);
        }
        let Some(vm_id) = lease.vm_id else {
            return Ok(false);
        };
        if let Some(job) = job {
            return match self
                .destroy_factory_allocation(
                    job.id,
                    vm_id,
                    Some(lease.id),
                    crate::job_boot::FactoryTeardown::Destroy,
                )
                .await
            {
                Ok(()) => Ok(true),
                Err(CoreError::Vmm(husker_vmm::VmmError::VmNotFound(_))) => Ok(false),
                // Factory teardown reports an ownership or identity mismatch
                // as InvalidArgument. That refutes cleanup of this lease only,
                // so it stays owned instead of stopping recovery of the rest.
                Err(CoreError::InvalidArgument(reason)) => {
                    warn!(lease = %lease.id, job = %job.id, %reason,
                        "preserving factory creation lease after failed ownership check");
                    Ok(false)
                }
                Err(error) => Err(error),
            };
        }
        let retained = self
            .destroyed_creation_leases
            .lock()
            .get(&lease.id)
            .copied();
        if retained.is_some_and(|owner| owner != vm_id) {
            return Err(CoreError::Io(
                "retained allocation destruction owner mismatch".into(),
            ));
        }
        if retained.is_none() {
            match self.vmm.vm_info(vm_id).await {
                Ok(info)
                    if info.id == vm_id
                        && info.name == lease.vm_name
                        && info.vsock_cid == lease.vsock_cid => {}
                Ok(_) => return Ok(false),
                Err(husker_vmm::VmmError::VmNotFound(_)) => (),
                Err(error) => return Err(error.into()),
            }
            match self.vmm.destroy_vm(vm_id).await {
                Ok(()) => (),
                Err(husker_vmm::VmmError::VmNotFound(_)) => return Ok(false),
                Err(error) => return Err(error.into()),
            }
            // Keep proof before any await or fallible persistence operation.
            self.destroyed_creation_leases
                .lock()
                .insert(lease.id, vm_id);
        }
        self.state
            .record_host_resource_lease_destruction(lease.id, vm_id)?;
        self.destroyed_creation_leases.lock().remove(&lease.id);
        Ok(true)
    }
}
