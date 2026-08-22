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
    /// VM record was committed. A lease is removed only after every recoverable
    /// host resource is gone, so a failed startup can safely retry later.
    pub async fn recover_host_resource_leases(&self) -> Result<usize, CoreError> {
        let leases = self.state.list_host_resource_leases()?;
        let mut recovered = 0;

        for lease in leases {
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
            recovered += 1;
            info!(vm = %lease.vm_name, cid = lease.vsock_cid, "recovered interrupted VM host resources");
        }

        Ok(recovered)
    }
}
