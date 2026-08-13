use super::*;

impl<B: VmmBackend> HuskerCore<B> {
    fn reconcile_lock(&self, id: Uuid) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self.reconcile_locks.lock();
        map.entry(id)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Create a host group.
    pub fn create_host_group(
        &self,
        req: CreateHostGroupRequest,
    ) -> Result<HostGroupRecord, CoreError> {
        validate_resource_name("host group", &req.name)?;
        let record = HostGroupRecord {
            id: Uuid::new_v4(),
            name: req.name,
            description: req.description,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        self.state.insert_host_group(&record).map_err(|e| match e {
            husker_state::StateError::HostGroupAlreadyExists(name) => {
                CoreError::HostGroupAlreadyExists(name)
            }
            other => CoreError::State(other),
        })?;
        Ok(record)
    }

    /// List all host groups.
    pub fn list_host_groups(&self) -> Result<Vec<HostGroupRecord>, CoreError> {
        Ok(self.state.list_host_groups()?)
    }

    /// Get a host group by name.
    pub fn get_host_group(&self, name: &str) -> Result<HostGroupRecord, CoreError> {
        self.state
            .get_host_group_by_name(name)
            .map_err(|e| match e {
                husker_state::StateError::HostGroupNotFoundByName(_) => {
                    CoreError::HostGroupNotFound(name.into())
                }
                other => CoreError::State(other),
            })
    }

    /// Delete a host group by name.
    pub fn delete_host_group(&self, name: &str) -> Result<(), CoreError> {
        let record = self.get_host_group(name)?;
        self.state
            .delete_host_group(record.id)
            .map_err(|e| match e {
                husker_state::StateError::HostGroupNotFound(_) => {
                    CoreError::HostGroupNotFound(name.into())
                }
                other => CoreError::State(other),
            })
    }

    /// Create a service and reconcile it to its desired instance count.
    pub async fn create_service(
        self: &std::sync::Arc<Self>,
        req: CreateServiceRequest,
    ) -> Result<(ServiceRecord, ReconcileOutcome), CoreError>
    where
        B: 'static,
    {
        validate_resource_name("service", &req.name)?;
        let desired_instances = req.desired_instances.unwrap_or(1);
        validate_service_instance_names(&req.name, desired_instances)?;
        if let Some(ref volume) = req.volume
            && desired_instances > 1
        {
            return Err(CoreError::InvalidArgument(format!(
                "service '{}' requests {desired_instances} instances with volume '{volume}': \
                 volumes are exclusive-attach, so a volume-backed service is limited to 1 instance",
                req.name,
            )));
        }

        // cloud-image services are not yet supported on macOS; reject before
        // persisting the ServiceRecord so the error surfaces immediately.
        #[cfg(not(feature = "linux-net"))]
        if req.cloud_image.is_some() {
            return Err(CoreError::InvalidArgument(
                "cloud-image services are not yet supported on macOS".into(),
            ));
        }

        let (rootfs, kernel) = if req.cloud_image.is_some() {
            (
                req.rootfs_path.unwrap_or_default(),
                req.kernel_path.unwrap_or_default(),
            )
        } else {
            // Fall back to the daemon's configured defaults when the client omits
            // them, mirroring create_vm_record. The client omits unspecified paths
            // (so a remote client does not send its own local paths), so the daemon
            // must resolve them here too or service create would reject valid input.
            (
                req.rootfs_path
                    .or_else(|| self.default_rootfs.clone())
                    .ok_or_else(|| {
                        CoreError::InvalidArgument(
                            "service requires a rootfs (--image or --rootfs) or --cloud-image, \
                             and the daemon has no default rootfs"
                                .into(),
                        )
                    })?,
                req.kernel_path
                    .or_else(|| self.default_kernel.clone())
                    .ok_or_else(|| {
                        CoreError::InvalidArgument(
                            "service requires a kernel, and the daemon has no default kernel"
                                .into(),
                        )
                    })?,
            )
        };

        let host_group_id = match req.host_group.as_deref() {
            Some(group_name) => Some(
                self.state
                    .get_host_group_by_name(group_name)
                    .map_err(|e| match e {
                        husker_state::StateError::HostGroupNotFoundByName(_) => {
                            CoreError::HostGroupNotFound(group_name.into())
                        }
                        other => CoreError::State(other),
                    })?
                    .id,
            ),
            None => None,
        };

        // Validate the volume name now so a typo'd volume fails service creation
        // immediately rather than at instance spawn time.
        self.resolve_volume_attachment(&req.volume)?;

        let now = chrono::Utc::now();
        let record = ServiceRecord {
            id: Uuid::new_v4(),
            name: req.name,
            host_group_id,
            desired_instances,
            image: req.image,
            kernel_path: kernel.to_string_lossy().into_owned(),
            rootfs_path: rootfs.to_string_lossy().into_owned(),
            initrd_path: req.initrd_path.map(|p| p.to_string_lossy().into_owned()),
            vcpu_count: req.vcpu_count,
            mem_size_mib: req.mem_size_mib,
            userdata: req.userdata,
            userdata_env: if req.env.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&req.env).expect("env serializes to JSON"))
            },
            created_at: now,
            updated_at: now,
            cloud_image: req.cloud_image,
            disk_size: req.disk_size,
            balloon: req.balloon,
            volume: req.volume,
        };
        self.state.insert_service(&record).map_err(|e| match e {
            husker_state::StateError::ServiceAlreadyExists(name) => {
                CoreError::ServiceAlreadyExists(name)
            }
            other => CoreError::State(other),
        })?;

        let outcome = self.reconcile_service(&record).await;
        Ok((record, outcome))
    }

    /// List all services.
    pub fn list_services(&self) -> Result<Vec<ServiceRecord>, CoreError> {
        Ok(self.state.list_services()?)
    }

    /// Get a service by name.
    pub fn get_service(&self, name: &str) -> Result<ServiceRecord, CoreError> {
        self.state.get_service_by_name(name).map_err(|e| match e {
            husker_state::StateError::ServiceNotFoundByName(_) => {
                CoreError::ServiceNotFound(name.into())
            }
            other => CoreError::State(other),
        })
    }

    /// Scale a service to the desired instance count and reconcile.
    pub async fn scale_service(
        self: &std::sync::Arc<Self>,
        name: &str,
        desired_instances: u32,
    ) -> Result<(ServiceRecord, ReconcileOutcome), CoreError>
    where
        B: 'static,
    {
        let record = self.get_service(name)?;
        validate_service_instance_names(name, desired_instances)?;
        if let Some(ref volume) = record.volume
            && desired_instances > 1
        {
            return Err(CoreError::InvalidArgument(format!(
                "cannot scale service '{name}' to {desired_instances} instances with volume \
                 '{volume}': volumes are exclusive-attach, so a volume-backed service is \
                 limited to 1 instance",
            )));
        }
        self.state
            .update_service_desired_instances(record.id, desired_instances)
            .map_err(|e| match e {
                husker_state::StateError::ServiceNotFound(_) => {
                    CoreError::ServiceNotFound(name.into())
                }
                other => CoreError::State(other),
            })?;
        let record = self.get_service(name)?;
        let outcome = self.reconcile_service(&record).await;
        Ok((record, outcome))
    }

    /// Destroy all instances, then delete the service row.
    ///
    /// If any instance fails to destroy, the row is retained and the error returned.
    pub async fn delete_service(
        self: &std::sync::Arc<Self>,
        name: &str,
    ) -> Result<ReconcileOutcome, CoreError>
    where
        B: 'static,
    {
        let mut record = self.get_service(name)?;
        record.desired_instances = 0;
        let outcome = self.reconcile_service(&record).await;
        if !outcome.failed.is_empty() {
            let (inst, err) = &outcome.failed[0];
            return Err(CoreError::ServiceOperationFailed(format!(
                "cannot delete service '{name}': instance {inst} cleanup failed: {err}"
            )));
        }
        self.state.delete_service(record.id).map_err(|e| match e {
            husker_state::StateError::ServiceNotFound(_) => CoreError::ServiceNotFound(name.into()),
            other => CoreError::State(other),
        })?;
        Ok(outcome)
    }

    /// List VMs owned by a service (core wrapper over state).
    pub fn list_vms_for_service(&self, service_id: Uuid) -> Result<Vec<VmRecord>, CoreError> {
        Ok(self.state.list_vms_for_service(service_id)?)
    }

    /// Create the partial unique index for service ordinals (core wrapper over state).
    pub fn create_service_ordinal_index(&self) -> Result<(), CoreError> {
        Ok(self.state.create_service_ordinal_index()?)
    }

    /// Converge a service's running instances to `desired_instances`.
    /// Target: ordinals 0..desired-1 each backed by exactly one `running` VM.
    pub async fn reconcile_service(self: &Arc<Self>, svc: &ServiceRecord) -> ReconcileOutcome
    where
        B: 'static,
    {
        let _guard = self.reconcile_lock(svc.id).lock_owned().await;
        let mut outcome = ReconcileOutcome::default();

        if svc.rootfs_path.is_empty() && svc.cloud_image.is_none() {
            outcome
                .failed
                .push((svc.name.clone(), "service has no rootfs template".into()));
            return outcome;
        }

        let instances = match self.state.list_vms_for_service(svc.id) {
            Ok(v) => v,
            Err(e) => {
                outcome.failed.push((svc.name.clone(), e.to_string()));
                return outcome;
            }
        };

        // Dedupe: one survivor per ordinal (BTreeMap = deterministic ascending order),
        // destroy the rest + any NULL-ordinal orphans.
        let mut by_ordinal: std::collections::BTreeMap<u32, VmRecord> =
            std::collections::BTreeMap::new();
        for vm in instances {
            let vm = self.refresh_vm_liveness(&vm).await;
            let Some(ord) = vm.service_ordinal else {
                let _ = self.destroy_instance(&vm, &mut outcome).await; // orphan
                continue;
            };
            match by_ordinal.get(&ord) {
                None => {
                    by_ordinal.insert(ord, vm);
                }
                Some(existing) => {
                    if better_survivor(&vm, existing) {
                        let loser = by_ordinal.insert(ord, vm).expect("ordinal present");
                        let _ = self.destroy_instance(&loser, &mut outcome).await;
                    } else {
                        let _ = self.destroy_instance(&vm, &mut outcome).await;
                    }
                }
            }
        }

        // Ordinals 0..desired-1: ensure each is a single running instance.
        for ordinal in 0..svc.desired_instances {
            match by_ordinal.get(&ordinal) {
                Some(vm) if vm.state == VmLifecycleState::Running => {}
                Some(vm) => {
                    let vm = vm.clone();
                    if self.destroy_instance(&vm, &mut outcome).await {
                        self.create_instance(svc, ordinal, &mut outcome).await;
                    }
                }
                None => self.create_instance(svc, ordinal, &mut outcome).await,
            }
        }

        // Scale-down: destroy survivors with ordinal >= desired (ascending, deterministic).
        let excess: Vec<VmRecord> = by_ordinal
            .into_iter()
            .filter(|(ord, _)| *ord >= svc.desired_instances)
            .map(|(_, vm)| vm)
            .collect();
        for vm in excess {
            let _ = self.destroy_instance(&vm, &mut outcome).await;
        }

        outcome
    }

    async fn create_instance(
        self: &Arc<Self>,
        svc: &ServiceRecord,
        ordinal: u32,
        outcome: &mut ReconcileOutcome,
    ) where
        B: 'static,
    {
        let name = instance_name(&svc.name, ordinal);

        // Ownership preflight: never clobber a VM not owned by this service.
        if let Ok(existing) = self.state.get_vm_by_name(&name)
            && existing.service_id != Some(svc.id)
        {
            outcome
                .failed
                .push((name, "name owned by a non-service VM".into()));
            return;
        }

        let req = instance_request(svc, &name);
        match self
            .create_vm_record(
                req,
                Some(ServiceTag {
                    service_id: svc.id,
                    ordinal,
                }),
                false,
            )
            .await
        {
            Ok(record) => {
                self.spawn_userdata(&record);
                outcome.created.push(name);
            }
            Err(e) => outcome.failed.push((name, e.to_string())),
        }
    }

    async fn destroy_instance(&self, vm: &VmRecord, outcome: &mut ReconcileOutcome) -> bool {
        let _name_guard = self.vm_name_lock(&vm.name).lock_owned().await;
        match self.destroy_vm_locked(vm).await {
            Ok(()) => {
                outcome.destroyed.push(vm.name.clone());
                true
            }
            Err(e) => {
                outcome.failed.push((vm.name.clone(), e.to_string()));
                false
            }
        }
    }
}
