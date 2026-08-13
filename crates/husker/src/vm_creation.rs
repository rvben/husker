//! VM acquisition planning shared by `husker run` and `husker job`.
//!
//! Parsing produces a [`VmCreationIntent`]. Planning resolves profiles, local
//! files, defaults, and source-specific conflicts into one executable
//! [`VmCreationPlan`]. Keeping those decisions here prevents the two commands
//! from quietly developing different VM creation semantics.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::cli::OutputFormat;
use crate::config::{Config, Profile, ProfileOrigin, merge_profiles};
use crate::daemon_client::DaemonClient;

/// The VM options supplied by a command before profile resolution.
#[derive(Debug, Default)]
pub(crate) struct VmRequestArgs {
    pub rootfs: Option<PathBuf>,
    pub kernel: Option<PathBuf>,
    pub initrd: Option<PathBuf>,
    pub cpus: Option<u32>,
    pub memory: Option<u32>,
    pub vmm: Option<String>,
    pub cloud_image: Option<PathBuf>,
    pub disk_size: Option<String>,
    pub ssh_key: Vec<PathBuf>,
    pub env: Vec<String>,
    pub balloon: bool,
    pub idle: bool,
    pub idle_timeout_secs: Option<u64>,
    pub suspend_ttl_secs: Option<u64>,
    pub auto_resume: Option<bool>,
    pub volume: Option<String>,
    pub mount: Vec<String>,
    pub network: Option<String>,
}

/// Everything needed to decide how a command obtains its VM.
#[derive(Debug)]
pub(crate) struct VmCreationIntent {
    pub name: String,
    pub pool: Option<String>,
    pub profile: Option<String>,
    pub args: VmRequestArgs,
    pub userdata: Option<PathBuf>,
    /// Command-specific flags that cannot be applied to a checked-out VM.
    pub extra_pool_conflicts: Vec<&'static str>,
}

/// A diagnostic produced while resolving an intent. Variants retain meaning;
/// rendering policy is kept out of the planning decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VmCreationDiagnostic {
    CloudImage(PathBuf),
    DirectBoot {
        kernel: Option<PathBuf>,
        rootfs: Option<PathBuf>,
        initrd: Option<PathBuf>,
    },
    MissingDefaultKernel(PathBuf),
    MissingDefaultRootfs(PathBuf),
}

impl VmCreationDiagnostic {
    pub(crate) fn report(&self, output: OutputFormat) {
        match self {
            Self::CloudImage(path) if output == OutputFormat::Text => {
                eprintln!("Using: cloud-image={}", path.display());
            }
            Self::DirectBoot {
                kernel,
                rootfs,
                initrd,
            } if output == OutputFormat::Text => {
                let display = |path: &Option<PathBuf>| {
                    path.as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "(daemon default)".to_string())
                };
                eprintln!(
                    "Using: kernel={} rootfs={} initrd={}",
                    display(kernel),
                    display(rootfs),
                    display(initrd)
                );
            }
            Self::MissingDefaultKernel(path) => eprintln!(
                "Default kernel not found at {}.\n\
                 Run `husker images pull` to fetch it, or pass --kernel explicitly.",
                path.display()
            ),
            Self::MissingDefaultRootfs(path) => eprintln!(
                "Default rootfs not found at {}.\n\
                 Run `husker images pull` to fetch it, or pass a rootfs path explicitly.",
                path.display()
            ),
            Self::CloudImage(_) | Self::DirectBoot { .. } => {}
        }
    }
}

/// The single acquisition request produced by planning.
#[derive(Debug)]
enum PlannedRequest {
    Create(Box<husker_core::CreateVmRequest>),
    PoolCheckout {
        pool: String,
        request: husker_api::CheckoutPoolRequest,
    },
}

/// A validated, fully resolved VM acquisition awaiting local prerequisites.
#[derive(Debug)]
pub(crate) struct VmCreationPlan {
    request: PlannedRequest,
    diagnostics: Vec<VmCreationDiagnostic>,
    local_firecracker_preflight: bool,
}

impl VmCreationPlan {
    pub(crate) fn report_diagnostics(&self, output: OutputFormat) {
        for diagnostic in &self.diagnostics {
            diagnostic.report(output);
        }
    }

    /// Perform local prerequisites and consume the unresolved plan. The
    /// resulting type is the only one that exposes daemon execution, making it
    /// impossible for a caller to accidentally skip preparation.
    pub(crate) async fn prepare(self, config: &Config) -> Result<PreparedVmCreationPlan> {
        #[cfg(all(target_os = "linux", feature = "linux-net"))]
        if self.local_firecracker_preflight {
            crate::daemon::ensure_firecracker(config).await?;
        }

        #[cfg(not(all(target_os = "linux", feature = "linux-net")))]
        let _ = (config, self.local_firecracker_preflight);

        Ok(PreparedVmCreationPlan {
            request: self.request,
        })
    }
}

/// A creation plan whose local prerequisites have succeeded.
#[derive(Debug)]
pub(crate) struct PreparedVmCreationPlan {
    request: PlannedRequest,
}

impl PreparedVmCreationPlan {
    pub(crate) async fn execute(&self, daemon: &DaemonClient) -> Result<reqwest::Response> {
        match &self.request {
            PlannedRequest::Create(body) => daemon.send(daemon.post("/v1/vms").json(body)).await,
            PlannedRequest::PoolCheckout { pool, request } => {
                daemon
                    .send(
                        daemon
                            .post(format!("/v1/pools/{pool}/checkout"))
                            .json(request),
                    )
                    .await
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn create_for_test(body: serde_json::Value) -> Self {
        let request = serde_json::from_value(body).expect("test VM request must match the API");
        Self {
            request: PlannedRequest::Create(Box::new(request)),
        }
    }
}

/// Resolve one CLI intent. Pool checkout deliberately skips profile and file
/// I/O because those inputs are invalid for a pool and should fail as a single,
/// deterministic conflict report.
pub(crate) async fn plan_vm_creation(
    daemon: &DaemonClient,
    config: &Config,
    intent: VmCreationIntent,
    local_target: bool,
) -> Result<VmCreationPlan> {
    if let Some(pool) = intent.pool {
        let conflicts = pool_conflicting_flags(
            &intent.args,
            intent.profile.is_some(),
            intent.userdata.is_some(),
            &intent.extra_pool_conflicts,
        );
        anyhow::ensure!(
            conflicts.is_empty(),
            "--pool cannot be combined with {} (pool '{pool}' defines the VM); pass only \
             --name and command-specific execution flags",
            conflicts.join(", ")
        );
        return Ok(VmCreationPlan {
            request: PlannedRequest::PoolCheckout {
                pool,
                request: husker_api::CheckoutPoolRequest {
                    vm_name: Some(intent.name),
                },
            },
            diagnostics: Vec::new(),
            local_firecracker_preflight: false,
        });
    }

    let daemon_profiles = fetch_daemon_profiles(daemon).await?.unwrap_or_default();
    let (profiles, origins) = merge_profiles(daemon_profiles, &config.profiles);
    let mut built = build_vm_request(
        &intent.name,
        intent.args,
        intent.profile.as_deref(),
        &profiles,
        &origins,
        config,
        local_target,
    )?;

    if let Some(userdata_path) = intent.userdata {
        let script = std::fs::read_to_string(&userdata_path)
            .with_context(|| format!("reading userdata script {}", userdata_path.display()))?;
        built.body.userdata = Some(script);
    }

    let local_firecracker_preflight = local_target && needs_firecracker_preflight(&built.body);
    Ok(VmCreationPlan {
        request: PlannedRequest::Create(Box::new(built.body)),
        diagnostics: built.diagnostics,
        local_firecracker_preflight,
    })
}

fn pool_conflicting_flags(
    args: &VmRequestArgs,
    profile: bool,
    userdata: bool,
    extra: &[&'static str],
) -> Vec<&'static str> {
    let mut conflicts = Vec::new();
    for (set, name) in [
        (args.rootfs.is_some(), "--rootfs"),
        (args.kernel.is_some(), "--kernel"),
        (args.initrd.is_some(), "--initrd"),
        (args.cpus.is_some(), "--cpus"),
        (args.memory.is_some(), "--memory"),
        (args.vmm.is_some(), "--vmm"),
        (args.cloud_image.is_some(), "--cloud-image"),
        (args.disk_size.is_some(), "--disk-size"),
        (args.volume.is_some(), "--volume"),
        (!args.mount.is_empty(), "--mount"),
        (args.network.is_some(), "--net"),
        (profile, "--profile"),
        (args.balloon, "--balloon"),
        (!args.ssh_key.is_empty(), "--ssh-key"),
        (!args.env.is_empty(), "--env/--env-file"),
        (userdata, "--userdata"),
        (args.idle, "--idle"),
        (args.idle_timeout_secs.is_some(), "--idle-timeout"),
        (args.suspend_ttl_secs.is_some(), "--suspend-ttl"),
        (args.auto_resume == Some(false), "--no-auto-resume"),
    ] {
        if set {
            conflicts.push(name);
        }
    }
    for flag in extra {
        if !conflicts.contains(flag) {
            conflicts.push(flag);
        }
    }
    conflicts
}

#[derive(Debug)]
pub(crate) struct BuiltVmRequest {
    pub body: husker_core::CreateVmRequest,
    pub diagnostics: Vec<VmCreationDiagnostic>,
}

/// Resolve profiles and local inputs into the daemon's create body without
/// printing or exiting. Exposed within the crate for focused compatibility
/// tests; production callers should use [`plan_vm_creation`].
pub(crate) fn build_vm_request(
    name: &str,
    mut args: VmRequestArgs,
    profile: Option<&str>,
    profiles: &HashMap<String, Profile>,
    origins: &HashMap<String, ProfileOrigin>,
    config: &Config,
    local_target: bool,
) -> Result<BuiltVmRequest> {
    let cli_had_rootfs = args.rootfs.is_some();

    if let Some(profile_name) = profile {
        let Some(profile_value) = profiles.get(profile_name) else {
            let mut names: Vec<&str> = profiles.keys().map(String::as_str).collect();
            names.sort_unstable();
            let available = if names.is_empty() {
                "none defined".to_string()
            } else {
                names.join(", ")
            };
            anyhow::bail!("unknown profile '{profile_name}' (available: {available})");
        };
        apply_profile(&mut args, profile_value);
    }

    anyhow::ensure!(
        args.ssh_key.is_empty() || args.cloud_image.is_some(),
        "--ssh-key requires --cloud-image"
    );

    let env_pairs: Vec<(String, String)> = args
        .env
        .iter()
        .filter_map(|value| {
            value
                .split_once('=')
                .map(|(key, value)| (key.to_string(), value.to_string()))
        })
        .collect();
    let mut diagnostics = Vec::new();

    let effective_disk_size_input = args.disk_size.clone().or_else(|| {
        args.cloud_image
            .is_some()
            .then(|| config.default_disk_size.clone())
            .flatten()
    });
    let effective_disk_size = if let Some(ref size) = effective_disk_size_input {
        let source = if args.disk_size.is_some() {
            "--disk-size"
        } else {
            "config default_disk_size"
        };
        let bytes =
            husker::parse_disk_size(size).map_err(|error| anyhow::anyhow!("{source}: {error}"))?;
        Some(bytes)
    } else {
        None
    };

    let mut body = husker_core::CreateVmRequest {
        name: name.to_string(),
        vcpu_count: args.cpus,
        mem_size_mib: args.memory,
        env: env_pairs,
        vmm: args.vmm,
        disk_size: effective_disk_size,
        balloon: args.balloon,
        volume: args.volume,
        network: args.network,
        mounts: args.mount,
        idle: args.idle.then_some(true),
        idle_timeout_secs: args.idle_timeout_secs,
        suspend_ttl_secs: args.suspend_ttl_secs,
        auto_resume: args.auto_resume,
        ..husker_core::CreateVmRequest::default()
    };

    if let Some(cloud_image) = args.cloud_image {
        body.cloud_image = Some(cloud_image.to_string_lossy().into_owned());
        if !args.ssh_key.is_empty() {
            let mut keys = Vec::new();
            for path in &args.ssh_key {
                let content = std::fs::read_to_string(path)
                    .with_context(|| format!("reading SSH public key {}", path.display()))?;
                let parsed = husker::parse_ssh_public_keys(&content)
                    .map_err(|error| anyhow::anyhow!("--ssh-key {}: {error}", path.display()))?;
                keys.extend(parsed);
            }
            body.ssh_authorized_keys = keys;
        }
        diagnostics.push(VmCreationDiagnostic::CloudImage(cloud_image));
    } else {
        let profile_rootfs_from_daemon = !cli_had_rootfs
            && profile
                .map(|name| origins.get(name) == Some(&ProfileOrigin::Daemon))
                .unwrap_or(false);
        let rootfs = args.rootfs.map(|path| {
            if profile_rootfs_from_daemon {
                path
            } else {
                husker::resolve_rootfs_arg(path, &config.data_dir)
            }
        });
        let kernel = args.kernel;
        let initrd = args.initrd;

        // A remote daemon owns its defaults. Inspecting the client's filesystem
        // in that case produces a false warning and leaks target resolution back
        // into request construction.
        if local_target {
            if kernel.is_none() && !config.default_kernel.exists() {
                diagnostics.push(VmCreationDiagnostic::MissingDefaultKernel(
                    config.default_kernel.clone(),
                ));
            }
            if rootfs.is_none() && !config.default_rootfs.exists() {
                diagnostics.push(VmCreationDiagnostic::MissingDefaultRootfs(
                    config.default_rootfs.clone(),
                ));
            }
        }
        diagnostics.push(VmCreationDiagnostic::DirectBoot {
            kernel: kernel.clone(),
            rootfs: rootfs.clone(),
            initrd: initrd.clone(),
        });
        if let Some(path) = rootfs {
            body.rootfs_path = Some(path);
        }
        if let Some(path) = kernel {
            body.kernel_path = Some(path);
        }
        if let Some(path) = initrd {
            body.initrd_path = Some(path);
        }
    }

    Ok(BuiltVmRequest { body, diagnostics })
}

/// Fill unset fields from a profile. Explicit command-line values win; list
/// fields use the profile only when the command line supplied none.
pub(crate) fn apply_profile(args: &mut VmRequestArgs, profile: &Profile) {
    args.cloud_image = args
        .cloud_image
        .take()
        .or_else(|| profile.cloud_image.clone());
    args.rootfs = args.rootfs.take().or_else(|| profile.rootfs.clone());
    args.kernel = args.kernel.take().or_else(|| profile.kernel.clone());
    args.initrd = args.initrd.take().or_else(|| profile.initrd.clone());
    args.cpus = args.cpus.or(profile.cpus);
    args.memory = args.memory.or(profile.memory);
    args.disk_size = args.disk_size.take().or_else(|| profile.disk_size.clone());
    args.vmm = args.vmm.take().or_else(|| profile.vmm.clone());
    if args.ssh_key.is_empty() {
        args.ssh_key = profile
            .ssh_keys
            .iter()
            .map(|key| crate::expand_tilde(key))
            .collect();
    }
    if args.env.is_empty() {
        args.env = profile.env.clone();
    }
    if !args.balloon {
        args.balloon = profile.balloon.unwrap_or(false);
    }
    args.idle_timeout_secs = args.idle_timeout_secs.or(profile.idle_timeout_secs);
    args.suspend_ttl_secs = args.suspend_ttl_secs.or(profile.suspend_ttl_secs);
    args.auto_resume = args.auto_resume.or(profile.auto_resume);
    args.volume = args.volume.take().or_else(|| profile.volume.clone());
    if args.mount.is_empty() {
        args.mount = profile.mounts.clone();
    }
    args.network = args.network.take().or_else(|| profile.network.clone());
}

pub(crate) fn profile_to_daemon(profile: &Profile) -> husker_core::DaemonProfile {
    husker_core::DaemonProfile {
        cloud_image: profile.cloud_image.as_deref().map(path_string),
        rootfs: profile.rootfs.as_deref().map(path_string),
        kernel: profile.kernel.as_deref().map(path_string),
        initrd: profile.initrd.as_deref().map(path_string),
        cpus: profile.cpus,
        memory: profile.memory,
        disk_size: profile.disk_size.clone(),
        vmm: profile.vmm.clone(),
        env: profile.env.clone(),
        balloon: profile.balloon,
        idle_timeout_secs: profile.idle_timeout_secs,
        suspend_ttl_secs: profile.suspend_ttl_secs,
        auto_resume: profile.auto_resume,
        volume: profile.volume.clone(),
        mounts: profile.mounts.clone(),
        network: profile.network.clone(),
    }
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

pub(crate) fn daemon_to_profile(profile: husker_core::DaemonProfile) -> Profile {
    Profile {
        cloud_image: profile.cloud_image.map(PathBuf::from),
        rootfs: profile.rootfs.map(PathBuf::from),
        kernel: profile.kernel.map(PathBuf::from),
        initrd: profile.initrd.map(PathBuf::from),
        cpus: profile.cpus,
        memory: profile.memory,
        disk_size: profile.disk_size,
        ssh_keys: Vec::new(),
        vmm: profile.vmm,
        env: profile.env,
        balloon: profile.balloon,
        idle_timeout_secs: profile.idle_timeout_secs,
        suspend_ttl_secs: profile.suspend_ttl_secs,
        auto_resume: profile.auto_resume,
        volume: profile.volume,
        mounts: profile.mounts,
        network: profile.network,
    }
}

/// Fetch daemon profiles, falling back only when the daemon/endpoint is absent.
/// Authentication and server failures are actionable and remain errors.
pub(crate) async fn fetch_daemon_profiles(
    daemon: &DaemonClient,
) -> Result<Option<HashMap<String, Profile>>> {
    let response = match daemon.try_send(daemon.get("/v1/profiles")).await {
        Ok(response) => response,
        Err(_) => return Ok(None),
    };
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED
        || status == reqwest::StatusCode::FORBIDDEN
        || status.is_server_error()
    {
        anyhow::bail!(
            "daemon rejected profiles request: {status} - check your api_token and daemon configuration"
        );
    }
    anyhow::ensure!(
        status.is_success(),
        "unexpected response from daemon profiles endpoint: {status}"
    );
    let Ok(body) = response.json::<serde_json::Value>().await else {
        return Ok(None);
    };
    let Some(profiles) = body.get("profiles") else {
        return Ok(None);
    };
    let Ok(profiles) =
        serde_json::from_value::<HashMap<String, husker_core::DaemonProfile>>(profiles.clone())
    else {
        return Ok(None);
    };
    Ok(Some(
        profiles
            .into_iter()
            .map(|(name, profile)| (name, daemon_to_profile(profile)))
            .collect(),
    ))
}

#[cfg(all(target_os = "linux", feature = "linux-net"))]
fn needs_firecracker_preflight(body: &husker_core::CreateVmRequest) -> bool {
    body.cloud_image.is_none() && body.vmm.as_deref() != Some("qemu")
}

#[cfg(not(all(target_os = "linux", feature = "linux-net")))]
fn needs_firecracker_preflight(_body: &husker_core::CreateVmRequest) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_conflicts_report_every_creation_input_in_stable_order() {
        let args = VmRequestArgs {
            rootfs: Some("rootfs".into()),
            memory: Some(512),
            mount: vec!["/host:/guest".into()],
            env: vec!["A=b".into()],
            ..VmRequestArgs::default()
        };
        assert_eq!(
            pool_conflicting_flags(&args, true, true, &["--dns", "--add-host"]),
            vec![
                "--rootfs",
                "--memory",
                "--mount",
                "--profile",
                "--env/--env-file",
                "--userdata",
                "--dns",
                "--add-host"
            ]
        );
    }

    #[test]
    fn remote_target_does_not_inspect_local_daemon_defaults() {
        let config = Config {
            default_kernel: "/definitely/missing/kernel".into(),
            default_rootfs: "/definitely/missing/rootfs".into(),
            ..Config::default()
        };
        let built = build_vm_request(
            "vm",
            VmRequestArgs::default(),
            None,
            &HashMap::new(),
            &HashMap::new(),
            &config,
            false,
        )
        .unwrap();
        assert_eq!(
            built.diagnostics,
            vec![VmCreationDiagnostic::DirectBoot {
                kernel: None,
                rootfs: None,
                initrd: None
            }]
        );
    }

    #[test]
    fn unknown_profile_is_a_recoverable_planning_error() {
        let error = build_vm_request(
            "vm",
            VmRequestArgs::default(),
            Some("missing"),
            &HashMap::new(),
            &HashMap::new(),
            &Config::default(),
            true,
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "unknown profile 'missing' (available: none defined)"
        );
    }

    #[tokio::test]
    async fn pool_intent_plans_checkout_without_contacting_daemon() {
        let daemon = DaemonClient::new("http://127.0.0.1:1", None);
        let plan = plan_vm_creation(
            &daemon,
            &Config::default(),
            VmCreationIntent {
                name: "job-x".into(),
                pool: Some("warm".into()),
                profile: None,
                args: VmRequestArgs::default(),
                userdata: None,
                extra_pool_conflicts: Vec::new(),
            },
            true,
        )
        .await
        .unwrap();

        let PlannedRequest::PoolCheckout { pool, request } = plan.request else {
            panic!("pool intent must produce a checkout request")
        };
        assert_eq!(pool, "warm");
        assert_eq!(request.vm_name.as_deref(), Some("job-x"));
    }

    #[tokio::test]
    async fn pool_conflicts_fail_before_contacting_daemon() {
        let daemon = DaemonClient::new("http://127.0.0.1:1", None);
        let error = plan_vm_creation(
            &daemon,
            &Config::default(),
            VmCreationIntent {
                name: "job-x".into(),
                pool: Some("warm".into()),
                profile: None,
                args: VmRequestArgs {
                    mount: vec!["/host:/guest".into()],
                    ..VmRequestArgs::default()
                },
                userdata: None,
                extra_pool_conflicts: Vec::new(),
            },
            true,
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("--mount"));
        assert!(error.to_string().contains("pool 'warm'"));
    }
}
