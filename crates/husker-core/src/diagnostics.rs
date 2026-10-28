use std::time::Duration;

use super::*;

/// Longest a single VM's backend stop may take during the shutdown drain.
/// A guest that ignores its shutdown signal, or a backend process that wedges
/// in its wait, must not keep the other VMs from being stopped or hold the
/// daemon past its own deadline.
pub const DRAIN_STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// Outcome of a shutdown drain across all live VMs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DrainReport {
    /// Live VMs that the drain marked stopped, whether or not the backend
    /// stop succeeded.
    pub stopped: usize,
    /// VMs whose backend stop failed or timed out. Their state is still
    /// marked stopped, so the next daemon start does not believe them live.
    pub unclean: usize,
}

impl<B: VmmBackend> HuskerCore<B> {
    /// Stop ingress that can transition VM state during daemon shutdown.
    ///
    /// Linux auto-resume listeners must be dropped without draining their
    /// socket backlog: draining deliberately services queued connections and
    /// could resume a suspended VM after the shutdown drain took its snapshot.
    pub fn quiesce_shutdown_ingress(&self) {
        #[cfg(feature = "linux-net")]
        {
            let mut listeners = self.resume_listeners.lock();
            let count = listeners.len();
            listeners.clear();
            drop(listeners);
            if count > 0 {
                info!(count, "closed auto-resume listeners for daemon shutdown");
            }
        }
    }

    /// Path to a VM's serial console log file.
    pub fn serial_log_path(&self, name: &str) -> Result<PathBuf, CoreError> {
        let record = self.lookup_vm(name)?;
        Ok(self.runtime_dir.join(self.vmm.serial_log_file(record.id)))
    }

    /// Path to the captured userdata stdout/stderr log for a VM. Written by
    /// `run_userdata` so the output of the userdata script is inspectable via
    /// `husker logs <name> --userdata` instead of being discarded.
    pub fn userdata_log_path(&self, name: &str) -> Result<PathBuf, CoreError> {
        let record = self.lookup_vm(name)?;
        Ok(self.runtime_dir.join(format!("{}.userdata.log", record.id)))
    }

    /// Path to a VM's backend process ("boot") log: QEMU's own stdout/stderr or
    /// Firecracker's process log, distinct from the guest serial console.
    pub fn boot_log_path(&self, name: &str) -> Result<PathBuf, CoreError> {
        let record = self.lookup_vm(name)?;
        Ok(self.runtime_dir.join(format!("{}.boot.log", record.id)))
    }

    /// Stop all running and paused VMs during daemon shutdown.
    ///
    /// Every live VM is stopped concurrently, each under
    /// [`DRAIN_STOP_TIMEOUT`], so the drain takes about as long as the
    /// slowest guest instead of the sum of all guests. A stop that fails or
    /// times out is logged and counted as unclean; the VM is still marked
    /// stopped so the persisted state matches a daemon that no longer owns it.
    pub async fn drain_vms(&self) -> DrainReport {
        // Close the job registry before taking the VM snapshot: this prevents
        // a late create/reconcile from registering new guest work while the
        // shutdown drain is already stopping VMMs.
        self.shutdown_userdata_jobs().await;

        let vms = match self.list_vms() {
            Ok(vms) => vms,
            Err(e) => {
                warn!(error = %e, "failed to list VMs for drain");
                return DrainReport::default();
            }
        };

        let live: Vec<VmRecord> = vms.into_iter().filter(|vm| vm.state.is_live()).collect();
        let outcomes =
            futures_util::future::join_all(live.iter().map(|vm| self.drain_one(vm))).await;

        let stopped = outcomes.len();
        let unclean = outcomes.iter().filter(|clean| !**clean).count();
        DrainReport { stopped, unclean }
    }

    /// Stop one live VM for the shutdown drain and reconcile its persisted
    /// state. Returns whether the backend stop completed cleanly.
    async fn drain_one(&self, vm: &VmRecord) -> bool {
        info!(name = %vm.name, state = %vm.state, "draining VM");
        // The guest's own shutdown shares the drain bound with the backend
        // stop, so a guest that stalls still cannot hold the daemon past it.
        let stop = async {
            self.shut_down_guest(vm).await;
            self.vmm.stop_vm(vm.id).await
        };
        let clean = match tokio::time::timeout(DRAIN_STOP_TIMEOUT, stop).await {
            Ok(Ok(())) => true,
            Ok(Err(e)) => {
                warn!(name = %vm.name, error = %e, "failed to stop VM during drain");
                false
            }
            Err(_) => {
                warn!(
                    name = %vm.name,
                    timeout_secs = DRAIN_STOP_TIMEOUT.as_secs(),
                    "VM stop did not finish within the drain timeout"
                );
                false
            }
        };
        if let Err(e) = self.state.mark_vm_stopped(vm.id) {
            warn!(name = %vm.name, error = %e, "failed to update state during drain");
        }
        self.finish_userdata_interruption(vm.id);
        clean
    }
}
