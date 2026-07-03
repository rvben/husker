//! Periodic reclamation of host resources leaked by crashed VMs.
//!
//! When a guest crashes, [`HuskerCore::refresh_vm_liveness`] marks the VM
//! `stopped` but does not release its TAP device, nftables port-forward rules,
//! or /30 IP - those are freed only by an explicit destroy. On a long-running
//! daemon these leak. This sweep releases them for genuinely-abandoned VMs while
//! keeping the stopped record (with its network fields cleared) visible in
//! `husker list`.
//!
//! Deliberately NOT run in the liveness read path: an earlier read-path attempt
//! cleared `guest_ip` on every liveness-detected stop, breaking the contract
//! that a just-stopped VM retains its network identity. The sweep runs only
//! against VMs abandoned past a grace period, in a dedicated task.

// The predicate is used by the linux-net sweep below and by the tests. On a
// macOS build (no linux-net) there are no host-network leaks to reclaim, so it
// is intentionally absent there rather than silenced with `allow(dead_code)`.
#[cfg(any(feature = "linux-net", test))]
use chrono::{DateTime, Duration, Utc};
#[cfg(any(feature = "linux-net", test))]
use husker_state::VmRecord;

/// Whether a VM is a reclaimable resource leak: a genuinely-abandoned stopped
/// VM still holding host network resources.
///
/// Excludes service instances (the reconciler owns those), suspended VMs (they
/// keep TAP/IP for resume), and VMs stopped more recently than `grace` (so a
/// user about to inspect or replace a just-crashed VM is not surprised).
/// `now - updated_at` approximates the stopped-for duration: `update_vm_state`
/// stamps `updated_at` on the stop and nothing mutates a stopped VM afterward.
#[cfg(any(feature = "linux-net", test))]
pub(crate) fn is_reclaimable_leak(vm: &VmRecord, now: DateTime<Utc>, grace: Duration) -> bool {
    let terminal = vm.state == "stopped" || vm.state == "failed";
    let standalone = vm.service_id.is_none();
    let not_suspended = vm.suspended_at.is_none();
    let holds_resources = vm.tap_device.is_some() || vm.guest_ip.is_some() || vm.host_ip.is_some();
    let stopped_long_enough = now.signed_duration_since(vm.updated_at) >= grace;
    terminal && standalone && not_suspended && holds_resources && stopped_long_enough
}

#[cfg(feature = "linux-net")]
impl<B: husker_vmm::VmmBackend> super::HuskerCore<B> {
    /// Release leaked host resources (TAP, nftables port forwards, /30 IP) for
    /// every abandoned crashed VM past `grace`, clearing the record's network
    /// fields but keeping the stopped record. Returns the number reclaimed.
    ///
    /// Mirrors the network-release half of `destroy_vm_locked` without removing
    /// the VMM/record/rootfs, so a subsequent same-name re-create still replaces
    /// the record cleanly (its cleared fields make the destroy-on-replace a
    /// no-op, so nothing is double-released).
    pub async fn reclaim_abandoned_vms(&self, grace_secs: u64) -> usize {
        use std::net::Ipv4Addr;
        use tracing::{info, warn};

        let grace = Duration::seconds(grace_secs as i64);
        let now = Utc::now();
        let vms = match self.state.list_vms() {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "reclaim sweep: failed to list VMs");
                return 0;
            }
        };

        let mut reclaimed = 0;
        for vm in vms {
            if !is_reclaimable_leak(&vm, now, grace) {
                continue;
            }
            // Hold the per-VM name lock so a concurrent create/destroy/replace of
            // the same name cannot race the resource release.
            let _guard = self.vm_name_lock(&vm.name).lock_owned().await;
            // Re-read under the lock: the VM may have been replaced (new id) or
            // resumed between listing and locking.
            let current = match self.state.get_vm(vm.id) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if !is_reclaimable_leak(&current, now, grace) {
                continue;
            }

            let forwards = self
                .state
                .list_port_forwards_for_vm(current.id)
                .unwrap_or_default();
            if let Some(ref tap) = current.tap_device {
                if let Err(e) = husker_net::remove_all_port_forwards(tap, &self.bridge_name).await {
                    warn!(name = %current.name, tap, error = %e, "reclaim: remove port forwards failed");
                }
                if let Err(e) = husker_net::delete_tap(tap).await {
                    warn!(name = %current.name, tap, error = %e, "reclaim: delete TAP failed");
                }
                let mut nc = self.network_counters.lock();
                for pf in &forwards {
                    nc.remove(&format!("husker-pf:{tap}:{}", pf.host_port));
                }
            }
            if let Some(ref guest_ip_str) = current.guest_ip
                && let Ok(guest_ip) = guest_ip_str.parse::<Ipv4Addr>()
                && let Err(e) = self.ip_allocator.release(guest_ip)
            {
                warn!(name = %current.name, %guest_ip, error = %e, "reclaim: release IP failed");
            }
            if let Err(e) = self.state.delete_port_forwards_for_vm(current.id) {
                warn!(name = %current.name, error = %e, "reclaim: delete port-forward rows failed");
            }
            if let Err(e) = self.state.clear_vm_network_resources(current.id) {
                warn!(name = %current.name, error = %e, "reclaim: clear network fields failed");
                continue;
            }
            info!(name = %current.name, "reclaimed host resources from abandoned crashed VM");
            reclaimed += 1;
        }
        reclaimed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use uuid::Uuid;

    /// A fully-populated running VM record; tests tweak only the fields under
    /// test. Mirrors the shape of the production record so field additions
    /// surface here.
    fn base_vm() -> VmRecord {
        let now = Utc::now();
        VmRecord {
            id: Uuid::new_v4(),
            name: "vm".into(),
            state: "stopped".into(),
            pid: None,
            vcpu_count: 1,
            mem_size_mib: 128,
            vsock_cid: 3,
            tap_device: Some("tap-vm".into()),
            host_ip: Some("192.0.2.1".into()),
            guest_ip: Some("192.0.2.2".into()),
            kernel_path: "/boot/vmlinux".into(),
            rootfs_path: "/images/rootfs.ext4".into(),
            created_at: now,
            updated_at: now,
            userdata: None,
            userdata_status: None,
            userdata_env: None,
            service_id: None,
            service_ordinal: None,
            vmm: "firecracker".into(),
            boot_mode: "direct".into(),
            balloon: false,
            volume: None,
            network: "nat".into(),
            last_activity_at: now,
            suspended_at: None,
            idle_timeout_secs: None,
            suspend_ttl_secs: None,
            auto_resume: true,
            forked_from: None,
        }
    }

    const GRACE: Duration = Duration::seconds(300);

    /// A stopped VM whose resources were leaked long ago is reclaimable.
    fn stopped_long_ago() -> VmRecord {
        let mut vm = base_vm();
        vm.updated_at = Utc::now() - Duration::seconds(600);
        vm
    }

    #[test]
    fn abandoned_stopped_vm_is_reclaimable() {
        assert!(is_reclaimable_leak(&stopped_long_ago(), Utc::now(), GRACE));
    }

    #[test]
    fn failed_state_is_also_reclaimable() {
        let mut vm = stopped_long_ago();
        vm.state = "failed".into();
        assert!(is_reclaimable_leak(&vm, Utc::now(), GRACE));
    }

    #[test]
    fn running_or_paused_vm_is_never_reclaimed() {
        for state in ["running", "paused", "creating", "suspended"] {
            let mut vm = stopped_long_ago();
            vm.state = state.into();
            assert!(
                !is_reclaimable_leak(&vm, Utc::now(), GRACE),
                "state {state} must not be reclaimed"
            );
        }
    }

    #[test]
    fn recently_stopped_vm_is_within_grace() {
        let mut vm = base_vm();
        vm.updated_at = Utc::now() - Duration::seconds(60); // < 300s grace
        assert!(!is_reclaimable_leak(&vm, Utc::now(), GRACE));
    }

    #[test]
    fn exactly_at_grace_boundary_is_reclaimable() {
        let now = Utc::now();
        let mut vm = base_vm();
        vm.updated_at = now - GRACE; // now - updated_at == grace, `>=` holds
        assert!(is_reclaimable_leak(&vm, now, GRACE));
    }

    #[test]
    fn service_instance_is_left_to_the_reconciler() {
        let mut vm = stopped_long_ago();
        vm.service_id = Some(Uuid::new_v4());
        assert!(!is_reclaimable_leak(&vm, Utc::now(), GRACE));
    }

    #[test]
    fn suspended_vm_keeps_its_resources_for_resume() {
        let mut vm = stopped_long_ago();
        vm.suspended_at = Some(Utc::now() - Duration::seconds(600));
        assert!(!is_reclaimable_leak(&vm, Utc::now(), GRACE));
    }

    #[test]
    fn vm_without_host_resources_has_nothing_to_reclaim() {
        let mut vm = stopped_long_ago();
        vm.tap_device = None;
        vm.host_ip = None;
        vm.guest_ip = None;
        assert!(!is_reclaimable_leak(&vm, Utc::now(), GRACE));
    }

    #[test]
    fn a_lingering_guest_ip_alone_is_still_reclaimable() {
        let mut vm = stopped_long_ago();
        vm.tap_device = None;
        vm.host_ip = None;
        // guest_ip still set -> the IP allocation is leaked.
        assert!(is_reclaimable_leak(&vm, Utc::now(), GRACE));
    }
}
