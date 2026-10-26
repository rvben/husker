use super::*;

impl<B: VmmBackend> HuskerCore<B> {
    async fn remove_tap_host_resources(&self, tap: &str) -> Result<(), CoreError> {
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
    /// A lease names a VM directory and TAP by VM name, so it must never be
    /// reclaimed while a committed record of that name exists: those
    /// resources would be the VM's. Creation refuses a taken name before
    /// leasing and commit inserts the record and deletes the lease in one
    /// transaction, so the two do not coexist; should they ever, the lease
    /// is kept, nothing is touched, and the conflict is logged for an
    /// operator to resolve (deleting the VM lets the next startup reclaim).
    pub async fn recover_host_resource_leases(&self) -> Result<HostResourceRecovery, CoreError> {
        let mut summary = HostResourceRecovery::default();
        for lease in self.state.list_host_resource_leases()? {
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
            match self.reclaim_leased_host_resources(&lease).await {
                Ok(()) => {
                    self.state.release_host_resource_lease(lease.id)?;
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

    async fn reclaim_leased_host_resources(
        &self,
        lease: &husker_state::HostResourceLease,
    ) -> Result<(), CoreError> {
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
