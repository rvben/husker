use super::*;

impl<B: VmmBackend> HuskerCore<B> {
    /// Create a hot pool: boot a template VM from the base image, wait for its
    /// guest agent, suspend it to disk, and record the pool. `run`/`job --pool
    /// <name>` then fork this template into fresh, isolated VMs in sub-second.
    ///
    /// The template is a normal (suspended) VM named after the pool. Firecracker
    /// only (suspend needs full-state snapshot support). On any failure after the
    /// template is created it is destroyed, so the pool name is free again.
    pub async fn create_pool(
        self: &Arc<Self>,
        req: CreatePoolRequest,
    ) -> Result<PoolRecord, CoreError>
    where
        B: 'static,
    {
        validate_resource_name("pool", &req.name)?;
        if self.state.get_pool_by_name(&req.name).is_ok() {
            return Err(CoreError::PoolAlreadyExists(req.name.clone()));
        }

        let template = self
            .create_vm(CreateVmRequest {
                name: req.name.clone(),
                kernel_path: req.kernel_path.clone(),
                rootfs_path: req.rootfs_path.clone(),
                vcpu_count: req.vcpu_count,
                mem_size_mib: req.mem_size_mib,
                initrd_path: req.initrd_path.clone(),
                userdata: None,
                env: Vec::new(),
                vmm: None,
                cloud_image: None,
                disk_size: None,
                ssh_authorized_keys: Vec::new(),
                balloon: false,
                volume: None,
                network: None,
                mounts: Vec::new(),
                ..Default::default()
            })
            .await
            .map_err(|e| match e {
                CoreError::VmAlreadyExists(_) => CoreError::PoolAlreadyExists(req.name.clone()),
                other => other,
            })?;

        // Warm to agent-ready, then suspend = the pool template. Roll back the
        // half-built template on any failure so the pool name stays reusable.
        let warm_and_suspend = async {
            self.agent_connect_ready(&req.name, default_ready_timeout("direct"))
                .await?;
            self.suspend_vm(&req.name).await
        };
        if let Err(e) = warm_and_suspend.await {
            let _ = self.destroy_vm(&req.name).await;
            return Err(e);
        }

        let now = chrono::Utc::now();
        let record = PoolRecord {
            id: Uuid::new_v4(),
            name: req.name.clone(),
            template_vm_id: template.id,
            rootfs_path: template.rootfs_path.clone(),
            kernel_path: template.kernel_path.clone(),
            initrd_path: req
                .initrd_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            vcpu_count: req.vcpu_count,
            mem_size_mib: req.mem_size_mib,
            created_at: now,
            updated_at: now,
        };
        if let Err(e) = self.state.insert_pool(&record) {
            let _ = self.destroy_vm(&req.name).await;
            return Err(match e {
                husker_state::StateError::PoolAlreadyExists(_) => {
                    CoreError::PoolAlreadyExists(req.name.clone())
                }
                husker_state::StateError::PoolTemplateOwned { pool, .. } => {
                    CoreError::PoolTemplateOwned {
                        vm: template.name.clone(),
                        pool,
                    }
                }
                husker_state::StateError::PoolTemplateUnavailable { template, .. } => {
                    CoreError::PoolTemplateUnavailable {
                        pool: req.name.clone(),
                        template,
                    }
                }
                other => CoreError::State(other),
            });
        }
        info!(pool = %req.name, "hot pool created");
        Ok(record)
    }

    /// List all hot pools.
    pub fn list_pools(&self) -> Result<Vec<PoolRecord>, CoreError> {
        Ok(self.state.list_pools()?)
    }

    /// Get a hot pool by name.
    pub fn get_pool(&self, name: &str) -> Result<PoolRecord, CoreError> {
        self.state.get_pool_by_name(name).map_err(|e| match e {
            husker_state::StateError::PoolNotFoundByName(_) => CoreError::PoolNotFound(name.into()),
            other => CoreError::State(other),
        })
    }

    /// Check a fresh VM out of a pool: fork the suspended template into a new,
    /// isolated VM with its own identity (CoW rootfs, fresh IP/CID/MAC), in
    /// sub-second. The template stays suspended and reusable. Firecracker only.
    pub async fn checkout_pool(
        &self,
        pool_name: &str,
        vm_name: Option<&str>,
    ) -> Result<VmRecord, CoreError> {
        // Resolve the source by the durable identity stored in the pool. Pool
        // and template names may legitimately diverge across legacy state or a
        // future rename; the UUID is the aggregate ownership key.
        let (_pool, template) = self.resolve_pool_template(pool_name)?;
        // Default the member name to "<pool>-<short id>" when unspecified.
        let generated;
        let name = match vm_name {
            Some(n) => n,
            None => {
                let suffix = Uuid::new_v4().simple().to_string();
                generated = format!("{pool_name}-{}", &suffix[..8]);
                &generated
            }
        };
        self.fork_vm(&template.name, name).await
    }

    /// Delete a hot pool: destroy its template VM, then remove the record.
    pub async fn delete_pool(&self, name: &str) -> Result<(), CoreError> {
        let (pool, template) = self.resolve_pool_template(name)?;
        let _template_guard = self.vm_name_lock(&template.name).lock_owned().await;
        self.destroy_pool_template_locked(&template, &pool).await?;
        info!(pool = %name, "hot pool deleted");
        Ok(())
    }

    pub(crate) fn ensure_vm_is_not_pool_template(
        &self,
        record: &VmRecord,
    ) -> Result<(), CoreError> {
        if let Some(pool) = self.state.get_pool_by_template_vm_id(record.id)? {
            return Err(CoreError::PoolTemplateOwned {
                vm: record.name.clone(),
                pool: pool.name,
            });
        }
        Ok(())
    }

    fn resolve_pool_template(&self, name: &str) -> Result<(PoolRecord, VmRecord), CoreError> {
        let pool = self.get_pool(name)?;
        let template = self
            .state
            .get_vm(pool.template_vm_id)
            .map_err(|error| match error {
                husker_state::StateError::VmNotFound(_) => CoreError::PoolTemplateUnavailable {
                    pool: pool.name.clone(),
                    template: pool.template_vm_id,
                },
                other => CoreError::State(other),
            })?;
        Ok((pool, template))
    }
}
