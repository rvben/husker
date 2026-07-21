use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "husker",
    about = "An open source microVM manager. Run `husker schema` for machine-readable API introspection.",
    version
)]
pub(crate) struct Cli {
    /// Path to config file
    #[arg(long)]
    pub(crate) config: Option<PathBuf>,

    /// Daemon API address (for client commands).
    ///
    /// Accepts http://host:port or ssh://[user@]host[:port] to reach a remote
    /// daemon over an SSH tunnel (reuses your ssh config/keys; no exposed port).
    /// Driving a Linux daemon this way unlocks Firecracker-only operations
    /// (fork, suspend, OCI import) from a macOS host. Overrides any selected
    /// context. Defaults to the current context, else http://127.0.0.1:7777.
    #[arg(long, env = "HUSKER_API_URL")]
    pub(crate) api_url: Option<String>,

    /// Use a saved context (see `husker context`) as the daemon target.
    /// Overridden by --api-url. Defaults to the current context.
    #[arg(long, short = 'c', env = "HUSKER_CONTEXT", global = true)]
    pub(crate) context: Option<String>,

    /// Bearer token for authenticated API access.
    #[arg(long)]
    pub(crate) api_token: Option<String>,

    /// Output format for command responses.
    #[arg(long, short = 'o', value_enum, default_value_t = OutputFormat::Auto, global = true)]
    pub(crate) output: OutputFormat,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum OutputFormat {
    /// Auto-detect: JSON when stdout is not a TTY, text when it is
    Auto,
    /// Human-readable text
    Text,
    /// Machine-readable JSON
    Json,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Start the husker daemon
    Daemon {
        /// Address to listen on
        #[arg(long, default_value = "127.0.0.1:7777")]
        listen: SocketAddr,
        /// Allow binding the daemon API to non-loopback addresses.
        ///
        /// By default husker refuses non-loopback binds to avoid accidental
        /// remote exposure of privileged VM control endpoints.
        #[arg(long)]
        allow_remote: bool,
    },

    /// Create and boot a new VM
    Run {
        /// Rootfs: a path, a catalog image name, or an OCI ref like
        /// `python:3.12-alpine` (auto-imported). Defaults to default_rootfs.
        rootfs: Option<PathBuf>,

        /// VM name
        #[arg(long)]
        name: Option<String>,

        /// Draw a fresh VM from a hot pool (fork its template) instead of booting
        /// from a rootfs. The pool's template defines the image and resources.
        #[arg(long)]
        pool: Option<String>,

        /// Path to kernel (vmlinux)
        #[arg(long)]
        kernel: Option<PathBuf>,

        /// Path to initrd/initramfs (auto-detected if not specified)
        #[arg(long)]
        initrd: Option<PathBuf>,

        /// Number of vCPUs (default: 1)
        #[arg(long, visible_alias = "vcpus")]
        cpus: Option<u32>,

        /// Memory in MiB (default: 128)
        #[arg(long)]
        memory: Option<u32>,

        /// Path to userdata script to execute after VM boots
        #[arg(long)]
        userdata: Option<PathBuf>,

        /// Environment variables for userdata script (KEY=VALUE)
        #[arg(long, short = 'e')]
        env: Vec<String>,

        /// Read environment variables from a KEY=VALUE file (repeatable). Keeps
        /// secrets out of the process table and shell history; explicit -e wins.
        #[arg(long = "env-file")]
        env_file: Vec<PathBuf>,

        /// DNS server for this VM's /etc/resolv.conf (repeatable). Scoped to this
        /// VM only, unlike the daemon-wide dns_servers config.
        #[arg(long = "dns")]
        dns: Vec<String>,

        /// Add a hostname-to-IP entry to this VM's /etc/hosts as name:ip
        /// (repeatable), e.g. --add-host registry.local:192.0.2.10.
        #[arg(long = "add-host")]
        add_host: Vec<String>,

        /// Backend to run this VM on
        #[arg(long, value_parser = ["firecracker", "qemu"])]
        vmm: Option<String>,

        /// Boot a cloud image: a catalog image name or a qcow2/img path. Uses QEMU/OVMF on
        /// Linux and Apple Virtualization.framework (EFI) on macOS (Apple Silicon).
        #[arg(long)]
        cloud_image: Option<PathBuf>,

        /// Resize the VM disk before boot, e.g. 10G. Cloud images grow on first boot (cloud-init); rootfs images are resized offline (needs e2fsprogs on the daemon host)
        #[arg(long)]
        disk_size: Option<String>,

        /// Authorize this SSH public key file in the cloud VM via cloud-init
        /// (repeatable; cloud-image only)
        #[arg(long = "ssh-key")]
        ssh_key: Vec<PathBuf>,

        /// Attach a virtio memory balloon (resize later with: husker balloon)
        ///
        /// macOS: explicit targets only, memory freed inside the guest is not
        /// automatically returned to the host
        #[arg(long)]
        balloon: bool,

        /// Enable idle auto-suspend using the daemon default window (Firecracker only).
        /// Conflicts with --idle-timeout.
        #[arg(long, conflicts_with = "idle_timeout")]
        idle: bool,

        /// Auto-suspend after this many seconds idle (Firecracker only, 0 = suspend as
        /// soon as idle).
        #[arg(long)]
        idle_timeout: Option<u64>,

        /// Destroy the VM after this many seconds suspended (0/unset = never).
        #[arg(long)]
        suspend_ttl: Option<u64>,

        /// Do not auto-resume on activity/connect; require explicit `husker resume`.
        #[arg(long)]
        no_auto_resume: bool,

        /// Attach a named persistent volume as the second disk (/dev/vdb)
        #[arg(long)]
        volume: Option<String>,

        /// Bind-mount a host directory into the guest over virtiofs as host:guest[:ro]
        /// (repeatable; QEMU only - pass --vmm qemu)
        #[arg(long)]
        mount: Vec<String>,

        /// Network mode: nat (default, husker-managed NAT), bridged (attach VM to the
        /// configured lan_bridge; cloud-image only, Linux only), or none (no interface
        /// at all; exec, file transfer and the agent still work over vsock)
        #[arg(long, value_parser = ["nat", "bridged", "none"])]
        net: Option<String>,

        /// Apply a named VM preset from config (explicit flags win)
        #[arg(long)]
        profile: Option<String>,
    },

    /// List running VMs
    #[command(alias = "ls")]
    List {
        /// Maximum number of VMs to return
        #[arg(long, default_value_t = 100)]
        limit: u32,
        /// Number of VMs to skip
        #[arg(long, default_value_t = 0)]
        offset: u32,
        /// Comma-separated list of fields to include in output
        #[arg(long)]
        fields: Option<String>,
    },

    /// Get info about a VM
    Info {
        /// VM name
        name: String,
    },

    /// Stop a running VM
    Stop {
        /// VM name
        name: String,
    },

    /// Pause a running VM
    Pause {
        /// VM name
        name: String,
    },

    /// Resume a paused VM
    Resume {
        /// VM name
        name: String,
    },

    /// Suspend a VM to disk (full-state snapshot, frees memory; resume to restore)
    Suspend {
        /// VM name
        name: String,
    },

    /// Fork a suspended VM into a new running VM with a fresh identity
    /// (Firecracker/NAT only; the source must be suspended and stays suspended)
    Fork {
        /// Source VM name (must be suspended)
        source: String,
        /// Name for the new forked VM
        fork_name: String,
    },

    /// Destroy a VM and clean up resources
    #[command(alias = "rm")]
    Destroy {
        /// VM name
        name: String,
        /// Skip confirmation prompt (required when stdin is not a TTY)
        #[arg(long)]
        yes: bool,
    },

    /// Resize a VM's memory balloon (MiB reclaimed from the guest)
    ///
    /// macOS: explicit targets only, memory freed inside the guest is not
    /// automatically returned to the host
    Balloon {
        /// VM name
        name: String,
        /// Target balloon size in MiB (memory reclaimed from the guest)
        amount_mib: u32,
    },

    /// Execute a command in a VM
    Exec {
        /// VM name
        name: String,

        /// Working directory inside the VM
        #[arg(long, short = 'w')]
        workdir: Option<String>,

        /// Environment variables for the command (KEY=VALUE), repeatable
        #[arg(long, short = 'e')]
        env: Vec<String>,

        /// Read environment variables from a KEY=VALUE file (repeatable). Keeps
        /// secrets out of the process table and shell history; explicit -e wins.
        #[arg(long = "env-file")]
        env_file: Vec<PathBuf>,

        /// Inject a stored secret as an env var: NAME (exposed as $NAME) or
        /// ENVVAR=secret-name (renamed), repeatable. The value is resolved inside
        /// the daemon and never appears in argv, `ps`, or shell history.
        #[arg(long = "secret")]
        secret: Vec<String>,

        /// Seconds to wait for the guest agent to become reachable before
        /// failing (server default: 30, or 180 for UEFI/cloud VMs)
        #[arg(long)]
        connect_timeout: Option<u64>,

        /// Maximum seconds the command may run (server default: 30, clamped
        /// to the daemon's exec_timeout_max_secs)
        #[arg(long)]
        timeout: Option<u64>,

        /// Command and arguments (after --)
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Boot a VM, run one command, destroy the VM, exit with its exit code
    Job {
        /// Rootfs: a path, a catalog image name, or an OCI ref like
        /// `python:3.12-alpine` (auto-imported). Defaults to default_rootfs.
        rootfs: Option<PathBuf>,

        /// VM name (default: job-<random>)
        #[arg(long)]
        name: Option<String>,

        /// Draw the job's VM from a hot pool (fork its template) for a
        /// sub-second start instead of a cold boot. The pool defines the image.
        #[arg(long)]
        pool: Option<String>,

        /// Path to kernel (vmlinux)
        #[arg(long)]
        kernel: Option<PathBuf>,

        /// Path to initrd/initramfs (auto-detected if not specified)
        #[arg(long)]
        initrd: Option<PathBuf>,

        /// Number of vCPUs (default: 1)
        #[arg(long, visible_alias = "vcpus")]
        cpus: Option<u32>,

        /// Memory in MiB (default: 128)
        #[arg(long)]
        memory: Option<u32>,

        /// Environment variables for the command (KEY=VALUE), repeatable
        #[arg(long, short = 'e')]
        env: Vec<String>,

        /// Read environment variables from a KEY=VALUE file (repeatable). Keeps
        /// secrets out of the process table and shell history; explicit -e wins.
        #[arg(long = "env-file")]
        env_file: Vec<PathBuf>,

        /// Inject a stored secret as an env var: NAME (exposed as $NAME) or
        /// ENVVAR=secret-name (renamed), repeatable. The value is resolved inside
        /// the daemon and never appears in argv, `ps`, or shell history.
        #[arg(long = "secret")]
        secret: Vec<String>,

        /// DNS server for this VM's /etc/resolv.conf (repeatable). Scoped to this
        /// VM only, unlike the daemon-wide dns_servers config.
        #[arg(long = "dns")]
        dns: Vec<String>,

        /// Add a hostname-to-IP entry to this VM's /etc/hosts as name:ip
        /// (repeatable), e.g. --add-host registry.local:192.0.2.10.
        #[arg(long = "add-host")]
        add_host: Vec<String>,

        /// Backend to run this VM on
        #[arg(long, value_parser = ["firecracker", "qemu"])]
        vmm: Option<String>,

        /// Boot a cloud image: a catalog image name or a qcow2/img path. Uses QEMU/OVMF on
        /// Linux and Apple Virtualization.framework (EFI) on macOS (Apple Silicon).
        #[arg(long)]
        cloud_image: Option<PathBuf>,

        /// Resize the VM disk before boot, e.g. 10G. Cloud images grow on first boot (cloud-init); rootfs images are resized offline (needs e2fsprogs on the daemon host)
        #[arg(long)]
        disk_size: Option<String>,

        /// Authorize this SSH public key file in the cloud VM via cloud-init
        /// (repeatable; cloud-image only)
        #[arg(long = "ssh-key")]
        ssh_key: Vec<PathBuf>,

        /// Attach a virtio memory balloon (resize later with: husker balloon)
        ///
        /// macOS: explicit targets only, memory freed inside the guest is not
        /// automatically returned to the host
        #[arg(long)]
        balloon: bool,

        /// Enable idle auto-suspend using the daemon default window (Firecracker only).
        /// Conflicts with --idle-timeout.
        #[arg(long, conflicts_with = "idle_timeout")]
        idle: bool,

        /// Auto-suspend after this many seconds idle (Firecracker only, 0 = suspend as
        /// soon as idle).
        #[arg(long)]
        idle_timeout: Option<u64>,

        /// Destroy the VM after this many seconds suspended (0/unset = never).
        #[arg(long)]
        suspend_ttl: Option<u64>,

        /// Do not auto-resume on activity/connect; require explicit `husker resume`.
        #[arg(long)]
        no_auto_resume: bool,

        /// Attach a named persistent volume as the second disk (/dev/vdb)
        #[arg(long)]
        volume: Option<String>,

        /// Bind-mount a host directory into the guest over virtiofs as host:guest[:ro]
        /// (repeatable; QEMU only - pass --vmm qemu)
        #[arg(long)]
        mount: Vec<String>,

        /// Network mode: nat (default, husker-managed NAT), bridged (attach VM to the
        /// configured lan_bridge; cloud-image only, Linux only), or none (no interface
        /// at all; exec, file transfer and the agent still work over vsock)
        #[arg(long, value_parser = ["nat", "bridged", "none"])]
        net: Option<String>,

        /// Apply a named VM preset from config (explicit flags win)
        #[arg(long)]
        profile: Option<String>,

        /// Maximum seconds the command may run (server-clamped)
        #[arg(long, default_value_t = 3600)]
        timeout: u64,

        /// Keep the VM after the job instead of destroying it
        #[arg(long)]
        keep: bool,

        /// Sync the current working directory into the VM (git-aware: tracked plus
        /// untracked-not-ignored files, gitignored build dirs excluded) and run the
        /// command there. The host filesystem is never modified (see --out /
        /// --write-back to pull results back). The command runs in the job's image,
        /// so pass a rootfs or --cloud-image that has your toolchain.
        #[arg(long = "sync-cwd")]
        sync_cwd: bool,

        /// Copy a path or glob (file or dir, relative to the synced tree) back to
        /// the host after the command, at the same relative location. Globs expand
        /// inside the guest after the command runs (quote them so your local shell
        /// does not), e.g. --out 'target/release/*'. Repeatable. Requires
        /// --sync-cwd. Build artifacts you do not name never come back.
        #[arg(long = "out", requires = "sync_cwd")]
        out: Vec<PathBuf>,

        /// Apply the command's changes to the synced files back onto the host
        /// working tree (e.g. `cargo fmt`). Only files that were synced in are
        /// written back; new build artifacts are not. Requires --sync-cwd.
        #[arg(long = "write-back", requires = "sync_cwd")]
        write_back: bool,

        /// Command and arguments (after --). Omit to run an imported OCI image's
        /// default (its Entrypoint + Cmd), like `docker run <image>`.
        #[arg(last = true)]
        command: Vec<String>,
    },

    /// Copy files between host and VM
    ///
    /// Use vmname:/path syntax for VM paths:
    ///   husker cp local.txt myvm:/tmp/local.txt
    ///   husker cp myvm:/var/log/syslog ./syslog
    Cp {
        /// Source (local path or vmname:/guest/path)
        source: String,

        /// Destination (local path or vmname:/guest/path)
        dest: String,

        /// File mode (octal, e.g. 755) when copying to VM
        #[arg(long, value_parser = crate::parse_octal_mode)]
        mode: Option<u32>,
    },

    /// Manage port forwards for a VM
    #[command(alias = "pf")]
    PortForward {
        /// VM name
        name: String,
        #[command(subcommand)]
        action: PortForwardAction,
    },

    /// Manage host groups
    #[command(alias = "hg")]
    HostGroup {
        #[command(subcommand)]
        action: HostGroupAction,
    },

    /// Manage service resources
    #[command(alias = "svc")]
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },

    /// Manage hot pools: pre-warmed VM templates that run/job fork sub-second
    Pool {
        #[command(subcommand)]
        action: PoolAction,
    },

    /// Manage VM snapshots
    #[command(alias = "snap")]
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },

    /// Manage image catalog resources
    #[command(visible_aliases = ["images", "img"])]
    Image {
        #[command(subcommand)]
        action: ImageAction,
    },

    /// Manage persistent volumes
    #[command(visible_aliases = ["volumes", "vol"])]
    Volume {
        #[command(subcommand)]
        action: VolumeAction,
    },

    /// Manage encrypted secrets
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },

    /// Open an interactive shell in a VM
    Shell {
        /// VM name
        name: String,
        /// Shell command (default: /bin/sh)
        #[arg(long)]
        command: Option<String>,
    },

    /// Show serial console output from a VM
    Logs {
        /// VM name
        name: String,
        /// Follow log output (like tail -f)
        #[arg(long, short = 'f')]
        follow: bool,
        /// Show last N lines
        #[arg(long, short = 'n')]
        tail: Option<u64>,
        /// Show the captured userdata script output instead of the serial console
        #[arg(long)]
        userdata: bool,
        /// Log source: serial (default), boot, or userdata. Overrides --userdata.
        #[arg(long, value_parser = ["serial", "boot", "userdata"])]
        source: Option<String>,
    },

    /// Wait until a VM's guest agent is ready (polls readiness)
    Wait {
        /// VM name
        name: String,
        /// Maximum seconds to wait (default: 120, or 180 for UEFI/cloud VMs)
        #[arg(long)]
        timeout: Option<u64>,
    },

    /// Print version information (client and daemon)
    Version,

    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Manage VM resource profiles (list effective profiles and their origin)
    #[command(visible_alias = "profiles")]
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },

    /// Manage saved daemon targets (named http:// or ssh:// URLs) and switch
    /// between them, e.g. a local Apple VZ daemon and a remote Linux daemon
    #[command(alias = "ctx")]
    Context {
        #[command(subcommand)]
        action: ContextAction,
    },

    /// Emit a machine-readable contract of the CLI (commands, args, output
    /// fields, exit codes) for agent introspection
    Schema,

    /// Generate a one-time migration to a reflink-capable storage volume
    Setup {
        #[command(subcommand)]
        action: SetupAction,
    },

    /// Diagnose host readiness (reflink, free space, backend) and print findings.
    /// Tries the daemon first; falls back to a local probe when the target is local
    /// and the daemon is unreachable.
    Doctor,

    /// Generate a shell completion script, e.g. `husker completions zsh`
    Completions {
        /// Target shell (bash, zsh, fish, powershell, elvish)
        shell: clap_complete::Shell,
    },
}

#[derive(clap::Subcommand)]
pub(crate) enum SetupAction {
    /// Generate the script + unit to migrate the data dir onto a reflink volume
    Storage {
        /// Where the DB + runtime relocate (default: <data_dir>-state)
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Loopback image path (default: <data_dir>.img)
        #[arg(long)]
        image_path: Option<PathBuf>,
        /// Loopback size, e.g. 50G (default: current bulk usage + 2G margin)
        #[arg(long)]
        size: Option<String>,
        /// Filesystem for the loopback
        #[arg(long, value_enum, default_value = "xfs")]
        fs: SetupFsArg,
        /// Reboot persistence mechanism
        #[arg(long, value_enum, default_value = "systemd")]
        persist: SetupPersistArg,
        /// Thin-provision the loopback (sparse; documents the ENOSPC risk)
        #[arg(long)]
        thin: bool,
        /// Write the script + unit into this directory instead of stdout
        #[arg(long)]
        out: Option<PathBuf>,
        /// Skip the overwrite confirmation when --out targets existing files
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub(crate) enum SetupFsArg {
    Xfs,
    Btrfs,
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub(crate) enum SetupPersistArg {
    Systemd,
    Fstab,
}

#[derive(Subcommand)]
pub(crate) enum ConfigAction {
    /// Validate the configuration file
    Check,
}

#[derive(Subcommand)]
pub(crate) enum ProfileAction {
    /// List effective profiles showing each one's origin (daemon or local config)
    #[command(visible_alias = "ls")]
    List,
}

#[derive(Subcommand)]
pub(crate) enum ContextAction {
    /// Add or update a named context
    Add {
        /// Context name
        name: String,
        /// API URL (http://host:port or ssh://[user@]host[:port])
        url: String,
    },
    /// List saved contexts (the current one is marked)
    #[command(alias = "ls")]
    List,
    /// Select the current context used when --api-url is not given
    Use {
        /// Context name
        name: String,
    },
    /// Remove a saved context
    #[command(alias = "rm")]
    Remove {
        /// Context name
        name: String,
    },
    /// Show the current context and its URL
    Show,
}

#[derive(Subcommand)]
pub(crate) enum PortForwardAction {
    /// Add a port forward
    Add {
        /// Host port
        host_port: u16,
        /// Guest port
        guest_port: u16,
        /// Host address to bind (macOS only; default 127.0.0.1). Use 0.0.0.0 to
        /// expose on all interfaces.
        #[arg(long)]
        bind: Option<String>,
    },
    /// Remove a port forward
    Remove {
        /// Host port
        host_port: u16,
    },
    /// List port forwards
    List,
}

#[derive(Subcommand)]
pub(crate) enum HostGroupAction {
    /// Create a host group
    Create {
        /// Host group name
        name: String,
        /// Optional description
        #[arg(long)]
        description: Option<String>,
    },
    /// List host groups
    List,
    /// Get a host group by name
    Get {
        /// Host group name
        name: String,
    },
    /// Delete a host group by name
    Delete {
        /// Host group name
        name: String,
        /// Skip confirmation prompt (required when stdin is not a TTY)
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum ServiceAction {
    /// Create a service
    Create {
        /// Service name
        name: String,
        /// Optional host group name
        #[arg(long)]
        host_group: Option<String>,
        /// Desired instance count
        #[arg(long, default_value_t = 1)]
        desired_instances: u32,
        /// Optional service image reference
        #[arg(long)]
        image: Option<String>,
        /// Rootfs image path or catalog reference (defaults to configured default_rootfs)
        #[arg(long)]
        rootfs: Option<PathBuf>,
        /// Kernel path (defaults to configured default_kernel)
        #[arg(long)]
        kernel: Option<PathBuf>,
        /// Initrd/initramfs path
        #[arg(long)]
        initrd: Option<PathBuf>,
        /// Number of vCPUs per instance
        #[arg(long, visible_alias = "cpus")]
        vcpus: Option<u32>,
        /// Memory per instance in MiB
        #[arg(long)]
        memory: Option<u32>,
        /// Path to a userdata script run on each instance
        #[arg(long)]
        userdata: Option<PathBuf>,
        /// Environment variable KEY=VALUE for the userdata script (repeatable)
        #[arg(long = "env")]
        env: Vec<String>,
        /// Boot instances from a stock cloud image (catalog name or qcow2 path);
        /// when set, --rootfs and --kernel become optional
        #[arg(long)]
        cloud_image: Option<String>,
        /// Resize the VM disk before boot, e.g. 10G. Cloud images grow on first boot (cloud-init); rootfs images are resized offline (needs e2fsprogs on the daemon host)
        #[arg(long)]
        disk_size: Option<String>,
        /// Attach a virtio memory balloon to each instance
        ///
        /// macOS: explicit targets only, memory freed inside the guest is not
        /// automatically returned to the host
        #[arg(long)]
        balloon: bool,
        /// Attach a named persistent volume to each instance as the second disk
        #[arg(long)]
        volume: Option<String>,
    },
    /// List services
    List,
    /// Get a service by name
    Get {
        /// Service name
        name: String,
    },
    /// Scale a service
    Scale {
        /// Service name
        name: String,
        /// Desired instance count
        desired_instances: u32,
    },
    /// Delete a service by name
    Delete {
        /// Service name
        name: String,
        /// Skip confirmation prompt (required when stdin is not a TTY)
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum PoolAction {
    /// Create a hot pool: boot a template from the base image, warm it, suspend it
    Create {
        /// Pool name
        name: String,
        /// Base rootfs (path, catalog name, or OCI ref); daemon default if omitted
        rootfs: Option<PathBuf>,
        #[arg(long)]
        kernel: Option<PathBuf>,
        #[arg(long)]
        initrd: Option<PathBuf>,
        #[arg(long, visible_alias = "cpus")]
        vcpus: Option<u32>,
        #[arg(long)]
        memory: Option<u32>,
    },
    /// List hot pools
    List,
    /// Show a hot pool
    Get {
        /// Pool name
        name: String,
    },
    /// Check a fresh VM out of a pool (fork the template into a new running VM)
    Checkout {
        /// Pool name
        name: String,
        /// Name for the new VM (generated from the pool name if omitted)
        #[arg(long = "name")]
        vm_name: Option<String>,
    },
    /// Delete a hot pool and its template
    Delete {
        /// Pool name
        name: String,
        /// Skip confirmation prompt (required when stdin is not a TTY)
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum SnapshotAction {
    /// Create a snapshot from a stopped VM
    Create {
        /// Snapshot name
        name: String,
        /// Source VM name
        #[arg(long)]
        vm: String,
    },
    /// List snapshots
    List,
    /// Get a snapshot by name
    Get {
        /// Snapshot name
        name: String,
    },
    /// Restore a snapshot into a new VM
    Restore {
        /// Snapshot name
        snapshot: String,
        /// New VM name
        #[arg(long)]
        name: String,
        /// Kernel path for the restored VM
        #[arg(long)]
        kernel: PathBuf,
        /// Optional initrd path
        #[arg(long)]
        initrd: Option<PathBuf>,
        /// Number of vCPUs (omit to use the daemon's configured default)
        #[arg(long, visible_alias = "vcpus")]
        cpus: Option<u32>,
        /// Memory in MiB (omit to use the daemon's configured default)
        #[arg(long)]
        memory: Option<u32>,
    },
    /// Delete a snapshot by name
    Delete {
        /// Snapshot name
        name: String,
        /// Skip confirmation prompt (required when stdin is not a TTY)
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum ImageAction {
    /// Import an image into the catalog
    Import {
        /// Image name
        name: String,
        /// Source image path
        #[arg(long)]
        source: PathBuf,
        /// Optional image format (default inferred from extension)
        #[arg(long)]
        format: Option<String>,
        /// Image kind: rootfs (default) or cloud-image (qcow2 for UEFI boot)
        #[arg(long, value_parser = ["rootfs", "cloud-image"])]
        kind: Option<String>,
    },
    /// Import an OCI/Docker image as a bootable rootfs (busybox-based, e.g. alpine)
    ImportOci {
        /// OCI/Docker reference, e.g. alpine:3.20 or ghcr.io/owner/image:tag
        reference: String,
        /// Catalog name for the image (defaults to a slug of the reference)
        #[arg(long)]
        name: Option<String>,
    },
    /// List imported images
    List,
    /// Get an image by name
    Get {
        /// Image name
        name: String,
    },
    /// Export an image to a destination path
    Export {
        /// Image name
        name: String,
        /// Destination path on host
        #[arg(long)]
        destination: PathBuf,
    },
    /// Delete an image by name
    Delete {
        /// Image name
        name: String,
        /// Skip confirmation prompt (required when stdin is not a TTY)
        #[arg(long)]
        yes: bool,
    },
    /// Fetch default kernel + initramfs + rootfs for this host into the data dir
    Pull {
        /// Override the configured base URL
        #[arg(long)]
        from: Option<String>,
        /// Re-download even if destination files already exist
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum VolumeAction {
    /// Create a named persistent volume
    Create {
        /// Volume name
        name: String,
        /// Volume size, e.g. 10G, 512M
        #[arg(long)]
        size: String,
    },
    /// List volumes
    List,
    /// Get volume details by name
    Get {
        /// Volume name
        name: String,
    },
    /// Delete a volume by name
    Delete {
        /// Volume name
        name: String,
        /// Skip confirmation prompt (required when stdin is not a TTY)
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum SecretAction {
    /// Create a secret
    Create {
        /// Secret name
        name: String,
        /// Secret plaintext value
        #[arg(long)]
        value: String,
    },
    /// List secret metadata
    List,
    /// Get secret metadata by name
    Get {
        /// Secret name
        name: String,
    },
    /// Reveal decrypted secret value
    Reveal {
        /// Secret name
        name: String,
    },
    /// Rotate secret to a new value
    Rotate {
        /// Secret name
        name: String,
        /// New plaintext value
        #[arg(long)]
        value: String,
    },
    /// Delete a secret by name
    Delete {
        /// Secret name
        name: String,
        /// Skip confirmation prompt (required when stdin is not a TTY)
        #[arg(long)]
        yes: bool,
    },
}
