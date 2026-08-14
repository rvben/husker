use super::*;

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
        Ok(self.runtime_dir.join(format!("{}.serial.log", record.id)))
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
    /// Returns the number of VMs that were drained. Errors on individual VMs
    /// are logged but do not abort the drain.
    pub async fn drain_vms(&self) -> usize {
        // Close the job registry before taking the VM snapshot: this prevents
        // a late create/reconcile from registering new guest work while the
        // shutdown drain is already stopping VMMs.
        self.shutdown_userdata_jobs().await;

        let vms = match self.list_vms() {
            Ok(vms) => vms,
            Err(e) => {
                warn!(error = %e, "failed to list VMs for drain");
                return 0;
            }
        };

        let mut count = 0;
        for vm in vms {
            if !vm.state.is_live() {
                continue;
            }
            info!(name = %vm.name, state = %vm.state, "draining VM");
            if let Err(e) = self.vmm.stop_vm(vm.id).await {
                warn!(name = %vm.name, error = %e, "failed to stop VM during drain");
            }
            if let Err(e) = self.state.mark_vm_stopped(vm.id) {
                warn!(name = %vm.name, error = %e, "failed to update state during drain");
            }
            self.finish_userdata_interruption(vm.id);
            count += 1;
        }
        count
    }

    /// Rotate serial log files that exceed the size threshold.
    ///
    /// Scans `runtime_dir` for `*.serial.log` files larger than 10 MiB,
    /// keeps the last 5 MiB using the copy-truncate pattern (safe for
    /// Firecracker/VZ which hold the fd open).
    ///
    /// Returns the number of files rotated.
    pub async fn rotate_serial_logs(&self) -> usize {
        let entries = match std::fs::read_dir(&self.runtime_dir) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "failed to read runtime dir for log rotation");
                return 0;
            }
        };

        let mut rotated = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.ends_with(".serial.log") {
                continue;
            }

            let metadata = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };

            if metadata.len() <= LOG_ROTATE_THRESHOLD {
                continue;
            }

            match rotate_log_file(&path, LOG_ROTATE_KEEP).await {
                Ok(()) => {
                    info!(path = %path.display(), "rotated serial log");
                    rotated += 1;
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "failed to rotate serial log");
                }
            }
        }
        rotated
    }
}
