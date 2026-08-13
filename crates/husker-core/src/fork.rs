use super::*;

impl<B: VmmBackend> HuskerCore<B> {
    /// Fork a suspended VM into a new running VM with a fresh host identity.
    ///
    /// Clones the source's rootfs (reflink, copy-on-write), restores a new
    /// Firecracker VM from the source's snapshot (the memory file is mapped
    /// copy-on-write, so the source is untouched), binds it to a freshly
    /// allocated TAP/IP/MAC, and re-homes the guest's network in place via the
    /// agent. The source stays suspended.
    ///
    /// Limitations (v1): NAT-mode, Firecracker-backed, volume-free sources only.
    /// The fork reuses the source's vsock path, so (a) only one running fork per
    /// source at a time and the source must stay suspended while a fork of it
    /// runs, and (b) forks are ephemeral - destroy them rather than suspending
    /// them (a forked VM's snapshot still embeds the source's vsock path, which a
    /// plain resume cannot reconstruct). A volume-backed source is rejected
    /// because the snapshot embeds the source's writable volume disk, which the
    /// fork would otherwise share.
    #[cfg(feature = "linux-net")]
    pub async fn fork_vm(&self, source_name: &str, fork_name: &str) -> Result<VmRecord, CoreError> {
        info!(%source_name, %fork_name, "forking VM");
        // Validate the caller-supplied fork name before it is used to build any
        // filesystem path (the fork's vm_dir is `data_dir/vms/<fork_name>`, which is
        // deleted and recreated). Without this, an absolute or `..`-laden name escapes
        // the data dir. Every other resource-creation path validates its name; fork
        // must too.
        validate_resource_name("vm", fork_name)?;
        if source_name == fork_name {
            return Err(CoreError::InvalidArgument(
                "fork name must differ from the source name".into(),
            ));
        }
        // Serialize forks of the same source (the rootfs alias moves the source's
        // disk aside during load) and guard the new name against a racing create.
        // `src_guard` is released inside try_fork_vm as soon as the disk work is
        // done (see PERF-1 there); `_fork_guard` is held for the whole operation.
        let src_guard = self.vm_name_lock(source_name).lock_owned().await;
        let _fork_guard = self.vm_name_lock(fork_name).lock_owned().await;

        let source = self.lookup_vm(source_name)?;
        if source.state != VmLifecycleState::Suspended {
            return Err(CoreError::InvalidState {
                name: source_name.into(),
                actual: source.state.to_string(),
                expected: "suspended".into(),
            });
        }
        if !husker_vmm::Capabilities::for_backend_kind(source.vmm).fork {
            return Err(CoreError::Vmm(husker_vmm::VmmError::Unsupported(format!(
                "backend '{}' does not support fork",
                source.vmm
            ))));
        }
        if source.network != NetworkMode::Nat {
            return Err(CoreError::InvalidArgument(
                "fork is only supported for NAT-mode VMs".into(),
            ));
        }
        // The snapshot embeds the source's writable volume disk, and the fork only
        // clones the rootfs, so a fork would silently share (and corrupt) the
        // source's volume. Reject volume-backed sources.
        if source.volume.is_some() {
            return Err(CoreError::InvalidArgument(
                "cannot fork a VM with an attached volume (the fork would share the \
                 source's writable volume)"
                    .into(),
            ));
        }
        if self.lookup_vm(fork_name).is_ok() {
            return Err(CoreError::VmAlreadyExists(fork_name.into()));
        }

        let mut resources = AllocatedResources::default();
        match self
            .try_fork_vm(&source, fork_name, &mut resources, src_guard)
            .await
        {
            Ok(rec) => {
                info!(%source_name, %fork_name, "VM forked");
                self.seed_activity(rec.id);
                Ok(rec)
            }
            Err(e) => {
                // Log the reason server-side: fork failures previously surfaced
                // only in the HTTP 500 body, leaving the daemon journal silent.
                warn!(%source_name, %fork_name, error = %e, "fork failed; rolling back");
                self.rollback_create(resources).await;
                Err(e)
            }
        }
    }

    /// Inner fork logic that tracks allocated resources for rollback.
    #[cfg(feature = "linux-net")]
    async fn try_fork_vm(
        &self,
        source: &VmRecord,
        fork_name: &str,
        resources: &mut AllocatedResources,
        src_guard: tokio::sync::OwnedMutexGuard<()>,
    ) -> Result<VmRecord, CoreError> {
        // Fresh host identity for the fork. `cid` is the fork's host-side id: it
        // names the TAP (`husker{cid}`) and derives the MAC, and is what we
        // persist. The guest's internal vsock CID stays the source's (baked in
        // the snapshot), which is harmless because host->guest agent connections
        // are Unix-socket-path based, not CID-addressed.
        // PERF-1 measurement: split the source-lock-serialized disk work
        // (allocate/clone/restore) from the fork-only tail (reconfigure/attach).
        let t_start = std::time::Instant::now();
        let guest_ip = self.ip_allocator.allocate()?;
        resources.guest_ip = Some(guest_ip);
        let lease = self.state.begin_host_resource_lease(fork_name)?;
        let cid = lease.vsock_cid;
        resources.cid = Some(cid);
        resources.host_resource_lease_id = Some(lease.id);
        let tap_name = format!("husker{cid}");
        let mac = husker_net::generate_mac(cid);
        let gateway = self.ip_allocator.gateway();
        let prefix_len = self.ip_allocator.prefix_len();
        self.state.set_host_resource_lease_network(
            lease.id,
            Some(&tap_name),
            Some(&guest_ip.to_string()),
        )?;

        // Create the TAP (Firecracker binds it during restore) but do NOT attach it
        // to the bridge yet: the fork resumes with the source's IP and MAC, so
        // bridging it before the guest is re-homed would put a duplicate identity on
        // the shared L2. It joins the bridge only after ReconfigureNetwork below.
        resources.tap_name = Some(tap_name.clone());
        self.host_network.create_tap(&tap_name).await?;

        // Clone the source's live rootfs into the fork's dir (reflink CoW).
        let fork_dir = self.storage.vm_dir(fork_name);
        if fork_dir.exists() {
            let _ = tokio::fs::remove_dir_all(&fork_dir).await;
        }
        tokio::fs::create_dir_all(&fork_dir)
            .await
            .map_err(|e| CoreError::Io(format!("create fork dir: {e}")))?;
        resources.vm_dir = Some(fork_dir.clone());
        let source_rootfs = self.storage.vm_dir(&source.name).join("rootfs.ext4");
        let fork_rootfs = fork_dir.join("rootfs.ext4");
        self.storage_driver
            .clone_rootfs(&source_rootfs, &fork_rootfs)
            .await?;

        // Restore the fork from the source's snapshot, bound to its own TAP and
        // its own vsock UDS path (via FC `vsock_override`), so the source can be
        // forked many times concurrently without a host-socket collision.
        let fork_id = Uuid::new_v4();
        let src_snapshot = SnapshotPaths::in_dir(self.suspend_slot_dir(source.id));
        let info = self
            .vmm
            .restore_vm(
                &src_snapshot,
                RestoreTarget::Fork {
                    id: fork_id,
                    name: fork_name.into(),
                    vcpu_count: source.vcpu_count,
                    mem_size_mib: source.mem_size_mib,
                    vsock_cid: cid,
                    tap_device: tap_name.clone(),
                    source_rootfs,
                    fork_rootfs,
                },
            )
            .await?;
        resources.vm_id = Some(info.id);
        let disk_phase = t_start.elapsed();

        // PERF-1: the source name lock only needs to cover the disk work above.
        // The FC snapshot restore aliases the source rootfs aside and reverts it
        // before `restore_vm` returns, and everything below operates solely on
        // the fork (its own clone, VMM instance, and TAP). Release the source
        // lock now so a slow guest agent during the network re-home cannot stall
        // concurrent checkouts from the same pool. Measured ~240ms (28% of a
        // ~860ms fork) was held here needlessly on the happy path, and far more
        // as the reconfigure retries toward its 10s deadline. Rollback on a later
        // failure touches only the fork's resources, so it does not need this.
        drop(src_guard);

        // Re-home the guest's network identity (new MAC + IP + gateway + DNS) live.
        self.reconfigure_fork_network(info.id, &guest_ip, prefix_len, gateway, &mac)
            .await?;

        // Now that the guest carries its own MAC and IP, join it to the bridge.
        self.host_network
            .attach_to_bridge(&tap_name, &self.bridge_name)
            .await?;

        // Persist the fork as a running VM.
        let now = chrono::Utc::now();
        let record = VmRecord {
            id: fork_id,
            name: fork_name.into(),
            state: VmLifecycleState::Running,
            pid: info.pid,
            vcpu_count: source.vcpu_count,
            mem_size_mib: source.mem_size_mib,
            vsock_cid: cid,
            tap_device: Some(tap_name),
            host_ip: Some(gateway.to_string()),
            guest_ip: Some(guest_ip.to_string()),
            kernel_path: source.kernel_path.clone(),
            rootfs_path: source.rootfs_path.clone(),
            created_at: now,
            updated_at: now,
            userdata: None,
            userdata_status: None,
            userdata_env: None,
            service_id: None,
            service_ordinal: None,
            vmm: source.vmm,
            boot_mode: source.boot_mode.clone(),
            balloon: false,
            volume: None,
            network: NetworkMode::Nat,
            last_activity_at: now,
            suspended_at: None,
            idle_timeout_secs: None,
            suspend_ttl_secs: None,
            auto_resume: true,
            forked_from: Some(source.id),
        };
        self.state
            .commit_vm_from_host_resource_lease(&record, lease.id)
            .map_err(|e| match e {
                husker_state::StateError::VmAlreadyExists(name) => CoreError::VmAlreadyExists(name),
                other => CoreError::State(other),
            })?;
        let total = t_start.elapsed();
        info!(
            source = %source.name,
            fork = %fork_name,
            disk_phase_ms = disk_phase.as_millis() as u64,
            tail_ms = (total - disk_phase).as_millis() as u64,
            total_ms = total.as_millis() as u64,
            "fork phase timing (disk_phase holds the source lock; tail is fork-only)"
        );
        Ok(record)
    }

    /// Connect to a just-restored fork's agent and apply its new network identity.
    /// The agent was already running when the source was suspended, so it returns
    /// with the snapshot; retry briefly to race the vsock rebind.
    #[cfg(feature = "linux-net")]
    async fn reconfigure_fork_network(
        &self,
        fork_id: Uuid,
        guest_ip: &std::net::Ipv4Addr,
        prefix_len: u8,
        gateway: std::net::Ipv4Addr,
        mac: &str,
    ) -> Result<(), CoreError> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let attempt = async {
                let stream = self
                    .vmm
                    .vsock_connect(fork_id, husker_agent_proto::AGENT_VSOCK_PORT)
                    .await?;
                let mut conn = crate::agent_client::AgentConnection::new(stream);
                conn.reconfigure_network(
                    "eth0",
                    &guest_ip.to_string(),
                    prefix_len,
                    &gateway.to_string(),
                    Some(mac),
                    &self.dns_servers,
                )
                .await?;
                Ok::<(), CoreError>(())
            }
            .await;
            match attempt {
                Ok(()) => return Ok(()),
                // The agent connected but did not understand the reconfigure
                // request (EOF / wrong reply): it predates `ReconfigureNetwork`
                // and is too old for fork. Retrying for the full 10s deadline
                // cannot help, so fail fast with an actionable message instead of
                // an opaque "unexpected response from agent" after a long stall.
                Err(CoreError::Agent(AgentError::UnexpectedResponse)) => {
                    return Err(CoreError::InvalidArgument(
                        "fork requires live network reconfiguration, but the guest \
                         agent does not support it; rebuild the source VM's rootfs \
                         with a current husker-agent, then suspend it again before \
                         forking"
                            .into(),
                    ));
                }
                Err(e) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(e);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                }
            }
        }
    }

    /// Fork is only available on Linux (Firecracker); the macOS/Apple VZ build
    /// has no snapshot support, so this rejects rather than silently no-opping.
    #[cfg(not(feature = "linux-net"))]
    pub async fn fork_vm(
        &self,
        _source_name: &str,
        fork_name: &str,
    ) -> Result<VmRecord, CoreError> {
        // Reject unsafe fork names identically to the Linux path, so the
        // name-validation contract does not depend on the build feature set.
        validate_resource_name("vm", fork_name)?;
        Err(CoreError::Vmm(husker_vmm::VmmError::Unsupported(
            "fork is only supported on Linux (Firecracker)".into(),
        )))
    }
}
