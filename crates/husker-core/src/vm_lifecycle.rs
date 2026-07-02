use super::*;

impl<B: VmmBackend> HuskerCore<B> {
    /// Create and boot a new VM.
    ///
    /// Allocates network, storage, and VMM resources. On failure, all
    /// partially allocated resources are rolled back. A stopped or failed VM
    /// with the same name is automatically replaced.
    pub async fn create_vm(&self, req: CreateVmRequest) -> Result<VmRecord, CoreError> {
        self.create_vm_record(req, None, true).await
    }

    /// Resolve a `run`/`job` rootfs argument to a host path. Accepts a literal
    /// path (used as-is), a catalog image name (resolved to its file), or an
    /// OCI/Docker reference (auto-imported on first use, then cached). A bare
    /// unknown name is a clear error rather than a confusing missing-file one.
    pub(crate) async fn resolve_rootfs_arg(
        &self,
        arg: &std::path::Path,
    ) -> Result<std::path::PathBuf, CoreError> {
        // An existing file is a literal path.
        if arg.is_file() {
            return Ok(arg.to_path_buf());
        }
        let s = arg.to_string_lossy().to_string();
        // A path-shaped argument that does not exist: leave it for the rootfs
        // validator to report clearly (don't treat a mistyped path as an image).
        if looks_like_path(&s) {
            return Ok(arg.to_path_buf());
        }
        // A known catalog image name.
        if let Ok(img) = self.state.get_image_by_name(&s) {
            return Ok(std::path::PathBuf::from(img.file_path));
        }
        // An OCI/Docker reference (`repo:tag` or `host/path[:tag]`): import + cache.
        if s.contains(':') || s.contains('/') {
            let name = oci_ref_to_catalog_name(&s);
            if let Ok(img) = self.state.get_image_by_name(&name) {
                return Ok(std::path::PathBuf::from(img.file_path));
            }
            info!(reference = %s, name = %name, "auto-importing OCI image for run/job");
            let rec = self.import_oci_image(&name, &s).await?;
            return Ok(std::path::PathBuf::from(rec.file_path));
        }
        // A bare name that is not a path and not in the catalog.
        Err(CoreError::InvalidArgument(format!(
            "'{s}' is not a rootfs path, a catalog image, or an OCI reference; \
             pass a path, a catalog image name, or a reference like 'repo:tag'"
        )))
    }

    /// Internal/advanced: prefer `create_vm`. Used by the reconciler to stamp service ownership.
    ///
    /// `tags` stamps service ownership atomically onto the new VM record.
    /// `replace_existing_stopped` controls whether an existing stopped/failed
    /// same-named VM is auto-replaced (public API: true; reconciler: false to
    /// avoid clobbering a foreign stopped VM).
    pub async fn create_vm_record(
        &self,
        mut req: CreateVmRequest,
        tags: Option<ServiceTag>,
        replace_existing_stopped: bool,
    ) -> Result<VmRecord, CoreError> {
        validate_resource_name("vm", &req.name)?;
        info!(name = %req.name, "creating VM");

        let _name_guard = self.vm_name_lock(&req.name).lock_owned().await;

        // If a stopped VM with this name exists, replace it automatically when
        // the caller allows it. Running or paused VMs must be explicitly
        // destroyed first.
        if let Ok(existing) = self.state.get_vm_by_name(&req.name) {
            if replace_existing_stopped
                && (existing.state == "stopped" || existing.state == "failed")
            {
                info!(name = %req.name, "replacing stopped VM");
                self.destroy_vm_locked(&existing).await?;
            } else {
                return Err(CoreError::VmAlreadyExists(req.name));
            }
        }

        if req.cloud_image.is_none() {
            // Fill daemon defaults for any path the client omitted. A remote client
            // sends only the paths the user explicitly specified; the daemon fills the
            // rest from its own configured defaults so the paths are valid on the
            // daemon host, not the client host.
            if req.kernel_path.is_none() {
                req.kernel_path = self.default_kernel.clone();
            }
            if req.rootfs_path.is_none() {
                req.rootfs_path = self.default_rootfs.clone();
            }
            // Resolve a catalog image name or an OCI/Docker reference in the rootfs
            // argument to a real host path (auto-importing an OCI ref on first use),
            // so `husker run myimg` / `husker job python:3.12-alpine` work without
            // knowing the on-disk catalog layout.
            if let Some(rootfs) = req.rootfs_path.take() {
                req.rootfs_path = Some(self.resolve_rootfs_arg(&rootfs).await?);
            }
            let kernel = req.kernel_path.as_deref().ok_or_else(|| {
                CoreError::InvalidArgument(
                    "no kernel specified and the daemon has no default kernel; \
                     pass --kernel, or run `husker images pull` on the daemon host"
                        .into(),
                )
            })?;
            let rootfs = req.rootfs_path.as_deref().ok_or_else(|| {
                CoreError::InvalidArgument(
                    "no rootfs specified and the daemon has no default rootfs; \
                     pass a rootfs path, or run `husker images pull` on the daemon host"
                        .into(),
                )
            })?;
            husker_storage::validate_kernel(kernel)?;
            husker_storage::validate_rootfs(rootfs)?;
        }

        let mut resources = AllocatedResources::default();
        match self.try_create_vm(req, tags, &mut resources).await {
            Ok(record) => {
                info!(name = %record.name, id = %record.id, "VM created");
                self.seed_activity(record.id);
                Ok(record)
            }
            Err(e) => {
                warn!(error = %e, "VM creation failed, rolling back");
                self.rollback_create(resources).await;
                Err(e)
            }
        }
    }

    /// Inner create logic that tracks allocated resources for rollback.
    #[cfg(feature = "linux-net")]
    async fn try_create_vm(
        &self,
        req: CreateVmRequest,
        tags: Option<ServiceTag>,
        resources: &mut AllocatedResources,
    ) -> Result<VmRecord, CoreError> {
        // Validate + default the network mode before touching any host resources.
        let network_mode = validate_network_mode(req.network.as_deref())?;

        // Bridged mode preconditions: must have a cloud image and a configured LAN bridge.
        // These checks run before any resource allocation so tests can verify them in-memory.
        if network_mode == "bridged" {
            if req.cloud_image.is_none() {
                return Err(CoreError::InvalidArgument(
                    "bridged networking requires --cloud-image \
                     (microVM guests have no DHCP client)"
                        .into(),
                ));
            }
            if self.lan_bridge.is_none() {
                return Err(CoreError::InvalidArgument(
                    "bridged networking requires the lan_bridge config option".into(),
                ));
            }
        }

        // Resolve the backend kind once and persist it, so the record reflects the
        // backend the dispatcher actually runs (an omitted `--vmm` resolves to the
        // daemon default, not a hardcoded Firecracker). Resolved before any host
        // resource allocation so the idle-policy gate below fails fast.
        let resolved_vmm_kind = resolve_vmm_kind(
            req.vmm.as_deref(),
            req.cloud_image.is_some(),
            !req.mounts.is_empty(),
            self.default_vmm_kind,
        )?;

        // Resolve the idle policy: an explicit `idle_timeout_secs` wins; otherwise the
        // bare `--idle` flag opts in using the daemon default window. Resolved without
        // a sentinel so an explicit `--idle-timeout 0` (suspend as soon as idle) is not
        // silently overwritten by the default.
        let idle_timeout_secs = req.idle_timeout_secs.or_else(|| {
            req.idle
                .unwrap_or(false)
                .then_some(self.idle_policy.default_idle_timeout_secs)
        });
        let idle_opted_in = idle_timeout_secs.is_some();
        if idle_opted_in && resolved_vmm_kind != husker_vmm::VmmKind::Firecracker {
            return Err(CoreError::InvalidArgument(
                "idle policy requires a full-state snapshot backend (firecracker)".into(),
            ));
        }
        let suspend_ttl_secs = if idle_opted_in {
            req.suspend_ttl_secs.or_else(|| {
                (self.idle_policy.default_suspend_ttl_secs > 0)
                    .then_some(self.idle_policy.default_suspend_ttl_secs)
            })
        } else {
            None
        };
        let auto_resume = if idle_opted_in {
            req.auto_resume
                .unwrap_or(self.idle_policy.default_auto_resume)
        } else {
            true
        };

        // NAT mode: allocate a static IP. Bridged mode: skip allocation; the LAN DHCP
        // server assigns the address. The rollback field stays None so unwind skips it.
        let guest_ip = if network_mode == "nat" {
            let ip = self.ip_allocator.allocate()?;
            resources.guest_ip = Some(ip);
            Some(ip)
        } else {
            None
        };

        let cid = self.state.allocate_cid()?;
        resources.cid = Some(cid);

        let tap_name = format!("husker{cid}");
        let mac = husker_net::generate_mac(cid);

        // Computed for the NAT branches below; bridged mode never applies them.
        let gateway = self.ip_allocator.gateway();
        let netmask = husker_net::prefix_len_to_netmask(self.ip_allocator.prefix_len());

        if let Some(ip) = guest_ip {
            debug!(tap = %tap_name, %ip, %gateway, cid, "NAT resources allocated");
        } else {
            debug!(tap = %tap_name, cid, "bridged resources allocated (no IP)");
        }

        husker_net::create_tap(&tap_name).await?;
        resources.tap_name = Some(tap_name.clone());

        // Attach the TAP to the appropriate bridge: the LAN bridge for bridged mode,
        // or the husker NAT bridge for NAT mode.
        let attach_bridge = if network_mode == "bridged" {
            self.lan_bridge
                .as_deref()
                .expect("lan_bridge checked above")
        } else {
            &self.bridge_name
        };
        husker_net::attach_to_bridge(&tap_name, attach_bridge).await?;

        let vm_dir = self.storage.vm_dir(&req.name);
        if vm_dir.exists() {
            warn!(name = %req.name, "removing stale VM directory from incomplete cleanup");
            if let Err(e) = tokio::fs::remove_dir_all(&vm_dir).await {
                warn!(dir = %vm_dir.display(), error = %e, "failed to remove stale VM directory");
            }
        }
        // Register the VM directory for rollback before any disk is created, so a
        // partially-prepared disk (e.g. cloud clone succeeds but resize fails) is
        // still cleaned up on failure.
        resources.vm_dir = Some(vm_dir.clone());

        // Resolve the named volume before disk setup so the cloud-init seed can
        // reflect the correct mount_volume value in a single pass. The
        // exclusivity check (find_vm_by_volume) runs here right before the
        // VmRecord insert; there is a small TOCTOU window between this check
        // and the insert, but at homelab scale that race is acceptable.
        let volume_attachment = self.resolve_volume_attachment(&req.volume)?;
        if let Some((ref vol_name, _)) = volume_attachment
            && let Some(holder) = self.state.find_vm_by_volume(vol_name)?
        {
            return Err(CoreError::InvalidArgument(format!(
                "volume '{vol_name}' is already attached to VM '{}'",
                holder.name
            )));
        }
        let mount_volume = volume_attachment.is_some();

        // Choose the boot disk + mode. A cloud image boots via UEFI/OVMF from a cloned
        // qcow2; the default path boots a host kernel from a raw ext4 rootfs.
        // cloud_source_path: the resolved source image (catalog path or user path) used as
        // rootfs_path provenance in the VmRecord for cloud VMs; None for direct-kernel boot.
        let (disk_path, boot, is_cloud, seed_path, cloud_source_path) = if let Some(image) =
            req.cloud_image.as_ref()
        {
            // Resolve --cloud-image: an existing host path wins; otherwise it
            // names a catalog image of kind "cloud-image".
            let image_path = {
                let as_path = std::path::Path::new(image);
                if as_path.exists() {
                    as_path.to_path_buf()
                } else {
                    let rec = self.state.get_image_by_name(image).map_err(|e| match e {
                        husker_state::StateError::ImageNotFoundByName(_) => {
                            CoreError::InvalidArgument(format!(
                                "cloud image '{image}' is neither an existing file nor a \
                                 catalog image (register one with `husker image import \
                                 --kind cloud-image`)"
                            ))
                        }
                        other => CoreError::State(other),
                    })?;
                    if rec.kind != "cloud-image" {
                        return Err(CoreError::InvalidArgument(format!(
                            "catalog image '{image}' has kind '{}', not 'cloud-image'",
                            rec.kind
                        )));
                    }
                    PathBuf::from(rec.file_path)
                }
            };
            // Cloud-image boot is QEMU-only. Reject an explicit non-QEMU backend request.
            if let Some(v) = req.vmm.as_deref() {
                let kind = v.parse::<husker_vmm::VmmKind>().map_err(CoreError::Vmm)?;
                if kind != husker_vmm::VmmKind::Qemu {
                    return Err(CoreError::InvalidArgument(
                        "cloud-image boot requires the QEMU backend (--vmm qemu)".into(),
                    ));
                }
            }
            // The seed delivers the guest agent; fail fast (before cloning) if the
            // daemon was built without one.
            if self.embedded_agent.is_empty() {
                return Err(CoreError::InvalidArgument(
                    "cloud-image support needs the embedded guest agent; build the daemon with \
                     `make build-agent` (or set HUSKER_EMBED_AGENT_BIN) first"
                        .into(),
                ));
            }
            let disk = vm_dir.join("disk.qcow2");
            let boot = prepare_cloud_disk(
                self.storage_driver.as_ref(),
                &image_path,
                req.disk_size,
                &disk,
                &self.ovmf_code_path,
                &self.ovmf_vars_template_path,
            )
            .await?;
            // Build the NoCloud seed. For NAT mode, inject a static network config so
            // cloud-init does not stall waiting for DHCP before the agent comes up.
            // For bridged mode, omit network-config entirely: cloud-init falls back to
            // DHCP on all NICs, and the LAN DHCP server assigns the address.
            let seed_network = if network_mode == "nat" {
                Some(husker_cloudinit::NetworkConfig {
                    ip: guest_ip.expect("NAT mode always has a guest_ip"),
                    prefix_len: self.ip_allocator.prefix_len(),
                    gateway,
                    dns: self.dns_servers.clone(),
                })
            } else {
                None
            };
            let seed = husker_cloudinit::build_seed(&husker_cloudinit::SeedSpec {
                agent: self.embedded_agent,
                hostname: req.name.clone(),
                instance_id: req.name.clone(),
                ssh_authorized_keys: req.ssh_authorized_keys.clone(),
                network: seed_network,
                mount_volume,
            })
            .map_err(seed_error_to_core)?;
            let seed_path = vm_dir.join("seed.img");
            tokio::fs::write(&seed_path, &seed)
                .await
                .map_err(|e| CoreError::Storage(husker_storage::StorageError::Io(e)))?;
            (disk, boot, true, Some(seed_path), Some(image_path))
        } else {
            let rootfs = req.rootfs_path.as_deref().ok_or_else(|| {
                CoreError::InvalidArgument("rootfs_path is required for direct-kernel boot".into())
            })?;
            let vm_rootfs = vm_dir.join("rootfs.ext4");
            self.storage_driver.clone_rootfs(rootfs, &vm_rootfs).await?;
            (
                vm_rootfs,
                husker_vmm::BootMode::DirectKernel,
                false,
                None,
                None,
            )
        };

        // resolv.conf injection loop-mounts the ext4 rootfs; skip it for qcow2 cloud
        // images, which are not ext4. Cloud images configure DNS via cloud-init at boot.
        if !is_cloud && !self.dns_servers.is_empty() {
            inject_resolv_conf(&disk_path, &self.dns_servers).await?;
        }

        // For direct-kernel boot: resolve the kernel now (validation already ran in
        // create_vm_record; try_create_vm may also be called from tests that skip it).
        let (config_kernel_path, record_kernel_path, record_rootfs_path) = if is_cloud {
            // Cloud VMs boot via UEFI; kernel_path is unused in VmConfig for that path.
            // Persist an empty kernel_path and the resolved source image path as rootfs
            // provenance so callers can trace which catalog/host image backed this VM.
            let source = cloud_source_path
                .expect("cloud_source_path is Some when is_cloud")
                .to_string_lossy()
                .into_owned();
            (PathBuf::new(), String::new(), source)
        } else {
            let kernel = req.kernel_path.as_deref().ok_or_else(|| {
                CoreError::InvalidArgument("kernel_path is required for direct-kernel boot".into())
            })?;
            let rootfs = req.rootfs_path.as_deref().ok_or_else(|| {
                CoreError::InvalidArgument("rootfs_path is required for direct-kernel boot".into())
            })?;
            (
                kernel.to_path_buf(),
                kernel.to_string_lossy().into_owned(),
                rootfs.to_string_lossy().into_owned(),
            )
        };

        let volume_path = volume_attachment.as_ref().map(|(_, p)| p.clone());

        // If the booting rootfs is a catalog image with a boot_init (an OCI image
        // imported by `import-oci`), boot it via the agent supervisor. Looked up
        // by the source rootfs path so it works however the image was referenced.
        let boot_init = if is_cloud {
            None
        } else {
            self.state.list_images().ok().and_then(|imgs| {
                imgs.into_iter()
                    .find(|i| i.file_path == record_rootfs_path)
                    .and_then(|i| i.boot_init)
            })
        };

        // Resolve initrd: prefer explicit path, then daemon default (if it exists on
        // the daemon host), then the conventional data-dir location as a last resort.
        // Resolved before kernel_args so the root= flag reflects the actual initrd state.
        let initrd_path = req
            .initrd_path
            .clone()
            .or_else(|| self.default_initrd.clone().filter(|p| p.exists()))
            .or_else(|| {
                let conventional = self.storage.data_dir.join("kernels/initramfs-virt.gz");
                conventional.exists().then_some(conventional)
            });

        // Parse and validate host-mount specs. Each spec is validated for path
        // safety here; the API layer enforces the allowlist before forwarding.
        let mut host_shares: Vec<husker_vmm::HostShare> = Vec::new();
        for (i, spec) in req.mounts.iter().enumerate() {
            let share = parse_mount_spec(spec, i).map_err(CoreError::InvalidArgument)?;
            validate_host_path("mount", &share.host)?;
            host_shares.push(share);
        }

        // NAT direct-kernel VMs pass the static IP as a kernel boot parameter.
        // Cloud VMs (NAT and bridged) use cloud-init for network; kernel_args is None.
        let kernel_args = if is_cloud {
            None
        } else {
            // Direct-kernel boots are always NAT (bridged requires cloud image).
            // Without an initrd the kernel must mount root itself; append root=/dev/vda rw.
            let root = if initrd_path.is_none() {
                " root=/dev/vda rw"
            } else {
                ""
            };
            let base = format!(
                "console=ttyS0 reboot=k panic=1 pci=off{root} \
                 ip={ip}::{gateway}:{netmask}::eth0:off",
                ip = guest_ip.expect("direct-kernel boot is always NAT")
            );
            let mut args = apply_boot_init(&base, boot_init.as_deref());
            // Append one token per virtiofs share; the guest init reads these to
            // determine which tags to mount and where.
            for share in &host_shares {
                let ro_suffix = if share.read_only { ":ro" } else { "" };
                args.push_str(&format!(
                    " husker.share={}={}{}",
                    share.tag, share.guest, ro_suffix
                ));
            }
            Some(args)
        };

        let vm_config = husker_vmm::VmConfig {
            name: req.name.clone(),
            vcpu_count: req
                .vcpu_count
                .unwrap_or_else(|| self.default_cpus.unwrap_or(1)),
            mem_size_mib: req
                .mem_size_mib
                .unwrap_or_else(|| self.default_memory.unwrap_or(128)),
            kernel_path: config_kernel_path,
            rootfs_path: disk_path,
            kernel_args,
            initrd_path,
            vsock_cid: cid,
            tap_device: Some(tap_name.clone()),
            guest_mac: Some(mac),
            vmm: Some(resolved_vmm_kind),
            boot,
            seed_path,
            balloon: req.balloon,
            volume_path,
            host_shares,
        };

        let info = self.vmm.create_vm(vm_config).await?;
        resources.vm_id = Some(info.id);

        let userdata_status = req.userdata.as_ref().map(|_| "pending".to_string());
        let now = chrono::Utc::now();

        // NAT: persist the allocated IP and gateway; bridged: both stay None (DHCP-assigned).
        let (record_guest_ip, record_host_ip) = if network_mode == "nat" {
            (guest_ip.map(|ip| ip.to_string()), Some(gateway.to_string()))
        } else {
            (None, None)
        };

        let record = VmRecord {
            id: info.id,
            name: req.name,
            state: info.state.to_string(),
            pid: info.pid,
            vcpu_count: info.vcpu_count,
            mem_size_mib: info.mem_size_mib,
            vsock_cid: cid,
            tap_device: Some(tap_name),
            host_ip: record_host_ip,
            guest_ip: record_guest_ip,
            kernel_path: record_kernel_path,
            rootfs_path: record_rootfs_path,
            created_at: now,
            updated_at: now,
            userdata: req.userdata,
            userdata_status,
            userdata_env: if req.env.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&req.env).expect("env serializes to JSON"))
            },
            service_id: tags.map(|t| t.service_id),
            service_ordinal: tags.map(|t| t.ordinal),
            vmm: resolved_vmm_kind.to_string(),
            boot_mode: if is_cloud {
                "uefi".to_string()
            } else {
                "direct".to_string()
            },
            balloon: req.balloon,
            volume: volume_attachment.map(|(vol_name, _)| vol_name),
            network: network_mode.to_string(),
            last_activity_at: now,
            suspended_at: None,
            idle_timeout_secs,
            suspend_ttl_secs,
            auto_resume,
            forked_from: None,
        };

        self.state.insert_vm(&record).map_err(|e| match e {
            husker_state::StateError::VmAlreadyExists(name) => CoreError::VmAlreadyExists(name),
            other => CoreError::State(other),
        })?;

        Ok(record)
    }

    /// Inner create logic without host networking.
    ///
    /// Networking is handled by the VMM backend (e.g. VZ NAT). Supports both
    /// direct-kernel boot and cloud-image (qcow2-to-raw + EFI) boot.
    #[cfg(not(feature = "linux-net"))]
    async fn try_create_vm(
        &self,
        req: CreateVmRequest,
        tags: Option<ServiceTag>,
        resources: &mut AllocatedResources,
    ) -> Result<VmRecord, CoreError> {
        // Validate the network mode field even though only "nat" is meaningful here,
        // so callers get a clear error for unknown values.
        let network_mode = validate_network_mode(req.network.as_deref())?;

        // Bridged mode is a Linux-only feature (requires TAP + host bridge management).
        if network_mode == "bridged" {
            return Err(CoreError::InvalidArgument(
                "bridged networking is only supported on Linux".into(),
            ));
        }

        // Idle policy requires a full-state snapshot backend (Firecracker); Apple VZ
        // has no snapshot/restore support, so any opt-in is rejected before any host
        // resource is allocated. Opt-in is an explicit `idle_timeout_secs` or the
        // bare `--idle` flag.
        if req.idle_timeout_secs.is_some() || req.idle.unwrap_or(false) {
            return Err(CoreError::InvalidArgument(
                "idle policy requires a full-state snapshot backend (firecracker)".into(),
            ));
        }

        let cid = self.state.allocate_cid()?;
        resources.cid = Some(cid);

        debug!(cid, "resources allocated");

        let vm_dir = self.storage.vm_dir(&req.name);
        if vm_dir.exists() {
            warn!(name = %req.name, "removing stale VM directory from incomplete cleanup");
            if let Err(e) = tokio::fs::remove_dir_all(&vm_dir).await {
                warn!(dir = %vm_dir.display(), error = %e, "failed to remove stale VM directory");
            }
        }

        if let Some(image) = req.cloud_image.as_ref() {
            // --volume with --cloud-image is not yet supported on macOS.
            if req.volume.is_some() {
                return Err(CoreError::InvalidArgument(
                    "--volume with --cloud-image is not yet supported on macOS".into(),
                ));
            }

            // Resolve --cloud-image: an existing host path wins; otherwise it
            // names a catalog image of kind "cloud-image".
            let image_path = {
                let as_path = std::path::Path::new(image);
                if as_path.exists() {
                    as_path.to_path_buf()
                } else {
                    let rec = self.state.get_image_by_name(image).map_err(|e| match e {
                        husker_state::StateError::ImageNotFoundByName(_) => {
                            CoreError::InvalidArgument(format!(
                                "cloud image '{image}' is neither an existing file nor a \
                                 catalog image (register one with `husker image import \
                                 --kind cloud-image`)"
                            ))
                        }
                        other => CoreError::State(other),
                    })?;
                    if rec.kind != "cloud-image" {
                        return Err(CoreError::InvalidArgument(format!(
                            "catalog image '{image}' has kind '{}', not 'cloud-image'",
                            rec.kind
                        )));
                    }
                    PathBuf::from(rec.file_path)
                }
            };

            // Validate the qcow2 magic before any disk I/O.
            husker_storage::validate_cloud_image(&image_path)?;

            // The seed delivers the guest agent; fail fast (before disk conversion)
            // if this build has no embedded agent.
            if self.embedded_agent.is_empty() {
                return Err(CoreError::InvalidArgument(
                    "cloud-image VMs need the embedded guest agent; this build has none \
                     (Apple Silicon builds embed it; rebuild via make install)"
                        .into(),
                ));
            }

            // Guard against shrinking: if the caller requests a disk_size smaller
            // than the image's virtual size, reject before starting the conversion.
            if let Some(size) = req.disk_size {
                let virtual_size = husker_storage::qcow2_virtual_size(&image_path).await?;
                if size < virtual_size {
                    return Err(CoreError::InvalidArgument(format!(
                        "--disk-size {size} is smaller than the image's virtual size \
                         {virtual_size}"
                    )));
                }
            }

            // Register the VM directory for rollback before creating any disk files,
            // so a partial conversion is cleaned up on failure.
            tokio::fs::create_dir_all(&vm_dir)
                .await
                .map_err(|e| CoreError::Storage(husker_storage::StorageError::Io(e)))?;
            resources.vm_dir = Some(vm_dir.clone());

            // Convert the source qcow2 to a raw disk image. Apple Virtualization.framework
            // requires raw images; qemu-img convert is blocking (it reads GBs of data), so
            // it runs on the blocking thread pool.
            let disk = vm_dir.join("disk.raw");
            let src = image_path.clone();
            let dst = disk.clone();
            tokio::task::spawn_blocking(move || husker_storage::convert_qcow2_to_raw(&src, &dst))
                .await
                .map_err(|e| {
                    CoreError::Storage(husker_storage::StorageError::QemuImg(format!(
                        "spawn_blocking join error: {e}"
                    )))
                })??;

            if let Some(size) = req.disk_size {
                husker_storage::resize_disk(&disk, size).await?;
            }

            // Build the NoCloud seed. VZ NAT assigns addresses via DHCP, so omit
            // network-config and let cloud-init's fallback DHCP client handle it.
            let seed = husker_cloudinit::build_seed(&husker_cloudinit::SeedSpec {
                agent: self.embedded_agent,
                hostname: req.name.clone(),
                instance_id: req.name.clone(),
                ssh_authorized_keys: req.ssh_authorized_keys.clone(),
                network: None,
                mount_volume: false,
            })
            .map_err(seed_error_to_core)?;
            let seed_path = vm_dir.join("seed.img");
            tokio::fs::write(&seed_path, &seed)
                .await
                .map_err(|e| CoreError::Storage(husker_storage::StorageError::Io(e)))?;

            let boot = husker_vmm::BootMode::Efi {
                variable_store: vm_dir.join("nvram.bin"),
            };
            let boot_mode_str = boot.as_str().to_string();

            // For cloud VMs: kernel_path is unused by EFI boot; record it as empty
            // (mirrors the Linux cloud path). rootfs_path records the source image
            // for provenance (which catalog/host image backed this VM).
            let record_rootfs_path = image_path.to_string_lossy().into_owned();

            let vm_config = husker_vmm::VmConfig {
                name: req.name.clone(),
                vcpu_count: req
                    .vcpu_count
                    .unwrap_or_else(|| self.default_cpus.unwrap_or(1)),
                mem_size_mib: req
                    .mem_size_mib
                    .unwrap_or_else(|| self.default_memory.unwrap_or(128)),
                kernel_path: PathBuf::new(),
                rootfs_path: disk,
                kernel_args: None,
                initrd_path: None,
                vsock_cid: cid,
                tap_device: None,
                guest_mac: None,
                vmm: None,
                boot,
                seed_path: Some(seed_path),
                balloon: req.balloon,
                volume_path: None,
                host_shares: vec![],
            };

            let info = self.vmm.create_vm(vm_config).await?;
            resources.vm_id = Some(info.id);

            let userdata_status = req.userdata.as_ref().map(|_| "pending".to_string());
            let now = chrono::Utc::now();
            let record = VmRecord {
                id: info.id,
                name: req.name,
                state: info.state.to_string(),
                pid: info.pid,
                vcpu_count: info.vcpu_count,
                mem_size_mib: info.mem_size_mib,
                vsock_cid: cid,
                tap_device: None,
                host_ip: None,
                guest_ip: None,
                kernel_path: String::new(),
                rootfs_path: record_rootfs_path,
                created_at: now,
                updated_at: now,
                userdata: req.userdata,
                userdata_status,
                userdata_env: if req.env.is_empty() {
                    None
                } else {
                    Some(serde_json::to_string(&req.env).expect("env serializes to JSON"))
                },
                service_id: tags.map(|t| t.service_id),
                service_ordinal: tags.map(|t| t.ordinal),
                vmm: "apple_vz".to_string(),
                boot_mode: boot_mode_str,
                balloon: req.balloon,
                volume: None,
                network: network_mode.to_string(),
                last_activity_at: now,
                suspended_at: None,
                idle_timeout_secs: None,
                suspend_ttl_secs: None,
                auto_resume: true,
                forked_from: None,
            };

            self.state.insert_vm(&record).map_err(|e| match e {
                husker_state::StateError::VmAlreadyExists(name) => CoreError::VmAlreadyExists(name),
                other => CoreError::State(other),
            })?;

            return Ok(record);
        }

        // ── Direct-kernel boot ───────────────────────────────────────────────

        let kernel = req.kernel_path.as_deref().ok_or_else(|| {
            CoreError::InvalidArgument("kernel_path is required for direct-kernel boot".into())
        })?;
        let rootfs = req.rootfs_path.as_deref().ok_or_else(|| {
            CoreError::InvalidArgument("rootfs_path is required for direct-kernel boot".into())
        })?;
        let vm_rootfs = vm_dir.join("rootfs.ext4");
        self.storage_driver.clone_rootfs(rootfs, &vm_rootfs).await?;
        resources.vm_dir = Some(vm_dir);

        // Resolve the named volume to its image path. The exclusivity check runs
        // here, right before the VmRecord insert; there is a small TOCTOU window
        // between this check and the insert, but at homelab scale that race is
        // acceptable.
        let volume_attachment = self.resolve_volume_attachment(&req.volume)?;
        if let Some((ref vol_name, _)) = volume_attachment
            && let Some(holder) = self.state.find_vm_by_volume(vol_name)?
        {
            return Err(CoreError::InvalidArgument(format!(
                "volume '{vol_name}' is already attached to VM '{}'",
                holder.name
            )));
        }

        // Resolve initrd: prefer explicit path, then daemon default (if it exists on
        // the daemon host), then the conventional data-dir location as a last resort.
        let initrd_path = req
            .initrd_path
            .clone()
            .or_else(|| self.default_initrd.clone().filter(|p| p.exists()))
            .or_else(|| {
                let conventional = self.storage.data_dir.join("kernels/initramfs-virt.gz");
                conventional.exists().then_some(conventional)
            });

        let kernel_str = kernel.to_string_lossy().into_owned();
        let rootfs_str = rootfs.to_string_lossy().into_owned();
        let volume_path = volume_attachment.as_ref().map(|(_, p)| p.clone());
        let vm_config = husker_vmm::VmConfig {
            name: req.name.clone(),
            vcpu_count: req
                .vcpu_count
                .unwrap_or_else(|| self.default_cpus.unwrap_or(1)),
            mem_size_mib: req
                .mem_size_mib
                .unwrap_or_else(|| self.default_memory.unwrap_or(128)),
            kernel_path: kernel.to_path_buf(),
            rootfs_path: vm_rootfs,
            kernel_args: Some("console=hvc0 root=/dev/vda rw init=/sbin/init".into()),
            initrd_path,
            vsock_cid: cid,
            tap_device: None,
            guest_mac: None,
            vmm: None,
            boot: husker_vmm::BootMode::DirectKernel,
            seed_path: None,
            balloon: req.balloon,
            volume_path,
            host_shares: vec![],
        };

        let info = self.vmm.create_vm(vm_config).await?;
        resources.vm_id = Some(info.id);

        let userdata_status = req.userdata.as_ref().map(|_| "pending".to_string());
        let now = chrono::Utc::now();
        let record = VmRecord {
            id: info.id,
            name: req.name,
            state: info.state.to_string(),
            pid: info.pid,
            vcpu_count: info.vcpu_count,
            mem_size_mib: info.mem_size_mib,
            vsock_cid: cid,
            tap_device: None,
            host_ip: None,
            guest_ip: None,
            kernel_path: kernel_str,
            rootfs_path: rootfs_str,
            created_at: now,
            updated_at: now,
            userdata: req.userdata,
            userdata_status,
            userdata_env: if req.env.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&req.env).expect("env serializes to JSON"))
            },
            service_id: tags.map(|t| t.service_id),
            service_ordinal: tags.map(|t| t.ordinal),
            vmm: "apple_vz".to_string(),
            boot_mode: "direct".to_string(),
            balloon: req.balloon,
            volume: volume_attachment.map(|(vol_name, _)| vol_name),
            network: network_mode.to_string(),
            last_activity_at: now,
            suspended_at: None,
            idle_timeout_secs: None,
            suspend_ttl_secs: None,
            auto_resume: true,
            forked_from: None,
        };

        self.state.insert_vm(&record).map_err(|e| match e {
            husker_state::StateError::VmAlreadyExists(name) => CoreError::VmAlreadyExists(name),
            other => CoreError::State(other),
        })?;

        Ok(record)
    }

    /// Roll back partially allocated resources in reverse order.
    pub(crate) async fn rollback_create(&self, resources: AllocatedResources) {
        if let Some(vm_id) = resources.vm_id {
            debug!(%vm_id, "rolling back: destroying VM");
            if let Err(e) = self.vmm.destroy_vm(vm_id).await {
                warn!(%vm_id, error = %e, "rollback: failed to destroy VM");
            }
        }
        if let Some(ref dir) = resources.vm_dir {
            debug!(dir = %dir.display(), "rolling back: removing VM directory");
            if let Err(e) = tokio::fs::remove_dir_all(dir).await {
                warn!(dir = %dir.display(), error = %e, "rollback: failed to remove VM directory");
            }
        }
        #[cfg(feature = "linux-net")]
        if let Some(ref tap) = resources.tap_name {
            debug!(tap, "rolling back: removing TAP");
            if let Err(e) = husker_net::remove_all_port_forwards(tap, &self.bridge_name).await {
                warn!(tap, error = %e, "rollback: failed to remove port forwards");
            }
            if let Err(e) = husker_net::delete_tap(tap).await {
                warn!(tap, error = %e, "rollback: failed to delete TAP device");
            }
        }
        if let Some(cid) = resources.cid {
            debug!(cid, "rolling back: releasing CID");
            if let Err(e) = self.state.release_cid(cid) {
                warn!(cid, error = %e, "rollback: failed to release CID");
            }
        }
        #[cfg(feature = "linux-net")]
        if let Some(guest_ip) = resources.guest_ip {
            debug!(%guest_ip, "rolling back: releasing IP");
            if let Err(e) = self.ip_allocator.release(guest_ip) {
                warn!(%guest_ip, error = %e, "rollback: failed to release IP");
            }
        }
    }

    /// Stop a running or paused VM.
    ///
    /// Idempotent: stopping an already stopped VM is a no-op.
    pub async fn stop_vm(&self, name: &str) -> Result<(), CoreError> {
        info!(%name, "stopping VM");
        // Hold the per-VM name lock for the whole stop so a concurrent
        // add/remove of a userspace port forward cannot interleave with the
        // teardown below (macOS).
        #[cfg(not(feature = "linux-net"))]
        let _stop_guard = self.vm_name_lock(name).lock_owned().await;
        let record = self.lookup_vm(name)?;
        match record.state.as_str() {
            "running" | "paused" => {}
            "stopped" => {
                debug!(%name, "VM already stopped; stop is a no-op");
                return Ok(());
            }
            "suspended" => {
                // The process is already gone; discard the slot and mark stopped.
                let _ = tokio::fs::remove_dir_all(self.suspend_slot_dir(record.id)).await;
                self.state.update_vm_state(record.id, "stopped")?;
                return Ok(());
            }
            _ => {
                return Err(CoreError::InvalidState {
                    name: name.into(),
                    actual: record.state,
                    expected: "running or paused".into(),
                });
            }
        }
        self.vmm.stop_vm(record.id).await?;
        self.state.update_vm_state(record.id, "stopped")?;
        // macOS userspace forwards are bound to the running instance: tear them
        // down on stop. The name lock acquired above is still held.
        #[cfg(not(feature = "linux-net"))]
        {
            self.port_proxy.stop_all(record.id);
            self.state.delete_port_forwards_for_vm(record.id)?;
        }
        Ok(())
    }

    /// Pause a running VM.
    ///
    /// Idempotent: pausing an already paused VM is a no-op.
    pub async fn pause_vm(&self, name: &str) -> Result<(), CoreError> {
        info!(%name, "pausing VM");
        let record = self.lookup_vm(name)?;
        match record.state.as_str() {
            "running" => {}
            "paused" => {
                debug!(%name, "VM already paused; pause is a no-op");
                return Ok(());
            }
            _ => {
                return Err(CoreError::InvalidState {
                    name: name.into(),
                    actual: record.state,
                    expected: "running".into(),
                });
            }
        }
        self.vmm.pause_vm(record.id).await?;
        self.state.update_vm_state(record.id, "paused")?;
        Ok(())
    }

    /// Destroy a VM and clean up all associated resources.
    ///
    /// If the VM is already stopped or the VMM backend no longer tracks it
    /// (e.g. after a daemon restart), the VMM destroy step is skipped and
    /// only state/storage cleanup is performed.
    pub async fn destroy_vm(&self, name: &str) -> Result<(), CoreError> {
        let record = self.lookup_vm(name)?;
        let _name_guard = self.vm_name_lock(name).lock_owned().await;
        self.destroy_vm_locked(&record).await
    }

    /// Destroy a VM without acquiring the name lock.
    ///
    /// Callers MUST already hold the per-VM-name lock. Used internally by
    /// `create_vm_record` when replacing a stopped VM atomically within the
    /// same critical section, and by the idle-policy reap path (see
    /// `idle_policy_tick`), which holds the lock across its own re-check.
    pub(crate) async fn destroy_vm_locked(&self, record: &VmRecord) -> Result<(), CoreError> {
        let name = record.name.as_str();
        info!(%name, "destroying VM");

        match self.vmm.destroy_vm(record.id).await {
            Ok(()) => {}
            Err(husker_vmm::VmmError::VmNotFound(_)) => {
                debug!(%name, "VM not in VMM backend, cleaning up state only");
            }
            Err(e) => return Err(e.into()),
        }

        // Clean up network resources. Port forwards live in two places:
        // 1. nftables rules in the kernel (removed by remove_all_port_forwards)
        // 2. SQLite records in the state store (removed by delete_port_forwards_for_vm)
        // Both must be cleaned up. Deleting the TAP automatically detaches it
        // from the bridge.
        #[cfg(feature = "linux-net")]
        {
            // Read before the DB rows disappear below: needed to build each
            // forward's `husker-pf:<tap>:<host_port>` comment key so the idle
            // policy's counter baselines do not outlive the VM they belong to.
            let forwards = self
                .state
                .list_port_forwards_for_vm(record.id)
                .unwrap_or_default();

            if let Some(ref tap) = record.tap_device {
                if let Err(e) = husker_net::remove_all_port_forwards(tap, &self.bridge_name).await {
                    warn!(%name, tap, error = %e, "failed to remove port forwards during destroy");
                }
                if let Err(e) = husker_net::delete_tap(tap).await {
                    warn!(%name, tap, error = %e, "failed to delete TAP device during destroy");
                }
                let mut nc = self
                    .network_counters
                    .lock()
                    .expect("network_counters poisoned");
                for pf in &forwards {
                    nc.remove(&format!("husker-pf:{tap}:{}", pf.host_port));
                }
            }

            if let Some(ref guest_ip_str) = record.guest_ip
                && let Ok(guest_ip) = guest_ip_str.parse::<Ipv4Addr>()
                && let Err(e) = self.ip_allocator.release(guest_ip)
            {
                warn!(%name, %guest_ip, error = %e, "failed to release IP during destroy");
            }

            // A reaped *suspended* VM may still have a bound resume-listener
            // `PortProxy` (installed by `suspend_vm_locked`). Drop it here so
            // the host port it holds is freed instead of staying bound, which
            // would otherwise surface as EADDRINUSE the next time the port is
            // reused.
            if let Some(proxy) = self
                .resume_listeners
                .lock()
                .expect("resume_listeners poisoned")
                .remove(&record.id)
            {
                proxy.drain_and_close(record.id);
            }
        }

        self.state.release_cid(record.vsock_cid)?;
        // Abort any macOS userspace port-forward listeners before dropping the
        // rows. (`destroy_vm` already holds the per-VM name lock.)
        #[cfg(not(feature = "linux-net"))]
        self.port_proxy.stop_all(record.id);
        self.state.delete_port_forwards_for_vm(record.id)?;

        let vm_dir = self.storage.vm_dir(&record.name);
        if let Err(e) = tokio::fs::remove_dir_all(&vm_dir).await {
            warn!(%name, dir = %vm_dir.display(), error = %e, "failed to remove VM directory during destroy");
        }

        let serial_log = self.runtime_dir.join(format!("{}.serial.log", record.id));
        if let Err(e) = remove_file_best_effort(&serial_log).await {
            warn!(%name, path = %serial_log.display(), error = %e, "failed to remove serial log during destroy");
        }

        // The userdata log is optional (only VMs with userdata have one), so
        // its absence is not worth a warning.
        let userdata_log = self.runtime_dir.join(format!("{}.userdata.log", record.id));
        let _ = remove_file_best_effort(&userdata_log).await;

        let boot_log = self.runtime_dir.join(format!("{}.boot.log", record.id));
        if let Err(e) = remove_file_best_effort(&boot_log).await {
            warn!(%name, path = %boot_log.display(), error = %e, "failed to remove boot log during destroy");
        }

        let suspend_slot = self.suspend_slot_dir(record.id);
        if let Err(e) = tokio::fs::remove_dir_all(&suspend_slot).await
            && e.kind() != std::io::ErrorKind::NotFound
        {
            warn!(%name, dir = %suspend_slot.display(), error = %e, "failed to remove suspend slot during destroy");
        }

        // Drop this VM's idle-policy bookkeeping. Without this every destroyed
        // VM leaks a map entry forever (a slow but unbounded memory leak in a
        // long-running daemon that creates/destroys VMs continuously).
        self.control_plane_last_active
            .lock()
            .expect("control_plane_last_active poisoned")
            .remove(&record.id);
        self.network_last_active
            .lock()
            .expect("network_last_active poisoned")
            .remove(&record.id);
        self.active_sessions
            .lock()
            .expect("active_sessions poisoned")
            .remove(&record.id);

        self.state.delete_vm(record.id)?;
        info!(%name, "VM destroyed");
        Ok(())
    }

    /// List all VMs.
    pub fn list_vms(&self) -> Result<Vec<VmRecord>, CoreError> {
        Ok(self.state.list_vms()?)
    }

    /// The capability-defining backend kind of this daemon's VMM backend
    /// (e.g. `"firecracker"`, `"apple_vz"`). Used to advertise daemon
    /// capabilities over the API.
    pub fn backend_kind(&self) -> &'static str {
        self.vmm.backend_kind()
    }

    /// List all VMs with their state refreshed against the backend.
    ///
    /// Detects guest-initiated shutdowns (process exited without the daemon
    /// observing it). Prefer this for user-facing reads; use `list_vms` for
    /// internal callers that do not need a liveness check (e.g. the health
    /// endpoint, which is called on a tight monitoring loop and can tolerate
    /// VM counts lagging one reconcile interval).
    ///
    /// Note: guest-IP discovery runs serially per VM. In the worst case (N
    /// running EFI VMs all lacking IPs, all with slow or unresponsive agents)
    /// this adds up to N x 2 seconds of latency (two 1-second timeouts per VM).
    pub async fn list_vms_refreshed(&self) -> Result<Vec<VmRecord>, CoreError> {
        let vms = self.state.list_vms()?;
        let mut out = Vec::with_capacity(vms.len());
        for vm in &vms {
            let mut refreshed = self.refresh_vm_liveness(vm).await;
            self.discover_guest_ip(&mut refreshed).await;
            out.push(refreshed);
        }
        Ok(out)
    }

    /// Get info about a specific VM.
    pub fn get_vm(&self, name: &str) -> Result<VmRecord, CoreError> {
        self.lookup_vm(name)
    }

    /// Get a VM by name with its state refreshed against the backend.
    ///
    /// Detects guest-initiated shutdowns. Prefer this for user-facing reads.
    pub async fn get_vm_refreshed(&self, name: &str) -> Result<VmRecord, CoreError> {
        let record = self.get_vm(name)?;
        let mut refreshed = self.refresh_vm_liveness(&record).await;
        self.discover_guest_ip(&mut refreshed).await;
        Ok(refreshed)
    }

    pub(crate) fn lookup_vm(&self, name: &str) -> Result<VmRecord, CoreError> {
        self.state.get_vm_by_name(name).map_err(|e| match e {
            husker_state::StateError::VmNotFoundByName(_) => CoreError::VmNotFound(name.into()),
            other => CoreError::State(other),
        })
    }
}
