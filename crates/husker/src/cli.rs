use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use husker_core::BootKind;

// Help for the timeout flags quotes the defaults the daemon applies, computed
// by the same functions the daemon runs, so a changed default or a new boot
// mode changes the help with it.

/// The per-boot-mode readiness defaults as a phrase. Firmware-booted guests
/// run a full OS first boot before the agent starts and wait longer.
fn ready_defaults(default_for: impl Fn(BootKind) -> u64) -> String {
    format!(
        "{}, or {} for UEFI/cloud VMs and {} for macOS guests",
        default_for(BootKind::DirectKernel),
        default_for(BootKind::Uefi),
        default_for(BootKind::MacOs)
    )
}

/// The `--vmm` values: every backend under its canonical name, taking the
/// aliases the daemon, `HUSKER_VMM` and profiles take as well, so a spelling
/// that works everywhere else is not refused by the parser. The aliases stay
/// out of the help and the schema; the canonical names are what the CLI
/// advertises, and the daemon canonicalizes whatever it receives.
fn vmm_value_parser() -> clap::builder::PossibleValuesParser {
    clap::builder::PossibleValuesParser::new(husker_vmm::VmmKind::ALL.map(|kind| {
        clap::builder::PossibleValue::new(kind.as_str()).aliases(kind.aliases().iter().copied())
    }))
}

/// Help for the `--connect-timeout` flag shared by every command that talks to
/// the guest agent (`exec`, `cp`, `shell`), so all three describe the same
/// daemon-side wait and clamp.
fn connect_timeout_help() -> String {
    format!(
        "Seconds to wait for the guest agent to become reachable before failing \
         (server default: {}; at most {})",
        ready_defaults(|kind| husker_api::resolve_exec_connect_timeout(None, kind).as_secs()),
        husker_api::MAX_EXEC_CONNECT_TIMEOUT_SECS
    )
}

fn exec_run_timeout_help() -> String {
    format!(
        "Maximum seconds the command may run (server default: {}, clamped to the \
         daemon's exec_timeout_max_secs, {} unless configured)",
        crate::config::default_exec_timeout_secs(),
        crate::config::default_exec_timeout_max_secs()
    )
}

fn wait_timeout_help() -> String {
    format!(
        "Maximum seconds to wait (default: {})",
        ready_defaults(|kind| husker_core::default_ready_timeout(kind).as_secs())
    )
}

#[derive(Parser)]
#[command(
    name = "husker",
    about = "An open source microVM manager. Run `husker schema` for machine-readable API introspection.",
    version
)]
pub(crate) struct Cli {
    /// Path to config file
    #[arg(long, global = true)]
    pub(crate) config: Option<PathBuf>,

    /// Daemon API address (for client commands).
    ///
    /// Accepts http://host:port or ssh://[user@]host[:port] to reach a remote
    /// daemon over an SSH tunnel (reuses your ssh config/keys; no exposed port).
    /// Driving a Linux daemon this way unlocks Firecracker-only operations
    /// (fork, suspend, OCI import) from a macOS host. Overrides any selected
    /// context. Defaults to the current context, else http://127.0.0.1:7777.
    #[arg(long, env = "HUSKER_API_URL", global = true)]
    pub(crate) api_url: Option<String>,

    /// Use a saved context (see `husker context`) as the daemon target.
    /// Overridden by --api-url. Defaults to the current context.
    #[arg(long, short = 'c', env = "HUSKER_CONTEXT", global = true)]
    pub(crate) context: Option<String>,

    /// Bearer token for authenticated API access. A blank value is refused:
    /// an empty token is a misconfiguration, not a request for no
    /// authentication.
    #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new(), global = true)]
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
    /// Freeze or verify a local factory input bundle without contacting a daemon
    Bundle {
        #[command(subcommand)]
        action: BundleAction,
    },
    /// Prepare and create development computers on the selected daemon
    Dev {
        #[command(subcommand)]
        action: DevAction,
    },
    /// Start a detached coding-agent session; inspect it with `session` and `events`
    Prompt {
        name: String,
        prompt: String,
        #[arg(long, value_parser = ["codex", "claude"], default_value = "codex")]
        agent: String,
        #[arg(long, default_value = "/workspace")]
        workdir: String,
        #[arg(long, default_value_t = 3600)]
        timeout: u64,
        /// Read credentials from KEY=VALUE files without exposing them in argv
        #[arg(long = "env-file")]
        env_file: Vec<PathBuf>,
        /// Inject a stored daemon secret as ENV_KEY=secret-name (repeatable)
        #[arg(long)]
        secret: Vec<String>,
    },
    /// Inspect, start, cancel, or remove detached guest sessions
    Session {
        name: String,
        #[command(subcommand)]
        action: SessionAction,
    },
    /// Read a page of session output, or reconnect and follow until completion
    Events {
        name: String,
        id: String,
        #[arg(long, default_value_t = 0)]
        after: u64,
        #[arg(long)]
        follow: bool,
    },
    /// Open a private loopback preview tunnel; keeps running until Ctrl-C
    Preview {
        name: String,
        /// TCP port of the application inside the guest (loopback is supported)
        #[arg(value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,
        /// Local loopback port; 0 asks the OS to choose a free port
        #[arg(long, default_value_t = 0)]
        local_port: u16,
    },
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
        #[arg(long, value_parser = vmm_value_parser())]
        vmm: Option<String>,

        /// Boot a cloud image: a catalog image name or a qcow2/img path. Uses QEMU/OVMF on
        /// Linux and Apple Virtualization.framework (EFI) on macOS (Apple Silicon).
        #[arg(long)]
        cloud_image: Option<PathBuf>,

        /// Boot a macOS guest from an installed image (see `husker macos install`):
        /// an image name or a bundle directory path. Apple Silicon hosts only.
        #[arg(
            long,
            value_name = "IMAGE",
            conflicts_with_all = [
                "rootfs", "kernel", "initrd", "cloud_image", "disk_size", "ssh_key",
                "volume", "mount", "dns", "add_host", "pool", "vmm"
            ]
        )]
        macos: Option<String>,

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
        /// (repeatable; Linux only, served by the QEMU backend)
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

    /// List VMs in creation order, one page at a time
    #[command(alias = "ls")]
    List {
        /// Maximum number of VMs to return
        #[arg(long, default_value_t = 100)]
        limit: u32,
        /// Number of VMs to skip
        #[arg(long, default_value_t = 0)]
        offset: u32,
        /// Comma-separated list of fields to include in JSON output
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

    /// Execute a command in a VM and exit with its exit code
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

        #[arg(long, help = connect_timeout_help())]
        connect_timeout: Option<u64>,

        #[arg(long, help = exec_run_timeout_help())]
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
        #[arg(long, value_parser = vmm_value_parser())]
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
        /// (repeatable; Linux only, served by the QEMU backend)
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

        #[arg(long, help = connect_timeout_help())]
        connect_timeout: Option<u64>,
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

    /// Install, list and provision macOS guest images (Apple Silicon hosts)
    Macos {
        #[command(subcommand)]
        action: MacosAction,
    },

    /// Serve the guest agent on vsock port 52. Runs inside macOS guests, where
    /// `husker macos provision` installs it as a LaunchDaemon.
    GuestAgent,

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

    /// Open an interactive shell in a VM and exit with the shell's exit code
    Shell {
        /// VM name
        name: String,
        /// Shell command (default: /bin/sh)
        #[arg(long)]
        command: Option<String>,

        #[arg(long, help = connect_timeout_help())]
        connect_timeout: Option<u64>,
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
        #[arg(long, help = wait_timeout_help())]
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

    /// Describe offline-safe CLI capabilities
    Capabilities,

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

#[derive(Subcommand)]
pub(crate) enum BundleAction {
    /// Copy a source tree into deterministic, credential-excluding frozen tar v1
    Freeze {
        source: PathBuf,
        /// New file outside the source tree; existing files are refused
        destination: PathBuf,
    },
    /// Authenticate bytes against the identity recorded in the execution spec
    Verify {
        bundle: PathBuf,
        #[arg(long)]
        digest: String,
        #[arg(long)]
        size: u64,
    },
}

#[derive(Subcommand)]
pub(crate) enum DevAction {
    /// Provision a credential-free Ubuntu dev image once on the daemon host
    Prepare {
        #[arg(long, default_value = "husker-dev")]
        image: String,
        /// Base OCI image; use a digest to pin the base exactly
        #[arg(long, default_value = "ubuntu:24.04")]
        base: String,
        #[arg(long, default_value_t = 2)]
        cpus: u32,
        #[arg(long, default_value_t = 4096)]
        memory: u32,
        #[arg(long, default_value = "20G")]
        disk_size: String,
        /// Rust toolchain installed by the provisioning recipe
        #[arg(long, default_value = "1.96.0")]
        rust: String,
        /// npm version/tag of @openai/codex; pin a version for repeatable builds
        #[arg(long, default_value = "latest")]
        codex: String,
        /// npm version/tag of @anthropic-ai/claude-code
        #[arg(long, default_value = "latest")]
        claude: String,
    },
    /// Create a ready development VM from a prepared catalog image
    New {
        name: String,
        #[arg(long, default_value = "husker-dev")]
        image: String,
        #[arg(long, default_value_t = 2)]
        cpus: u32,
        #[arg(long, default_value_t = 4096)]
        memory: u32,
        #[arg(long, default_value = "20G")]
        disk_size: String,
    },
    /// Check the guest agent, dev tools, and Docker daemon in an existing VM
    Check { name: String },
}

#[derive(Subcommand)]
pub(crate) enum SessionAction {
    /// Start any non-interactive command independently of the client connection
    Start {
        #[arg(long)]
        workdir: Option<String>,
        #[arg(long, default_value_t = 3600)]
        timeout: u64,
        #[arg(long = "env-file")]
        env_file: Vec<PathBuf>,
        #[arg(long)]
        secret: Vec<String>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// List retained sessions in the VM
    List,
    /// Inspect a session state and exit code
    Get { id: String },
    /// Cancel a running session and its child processes
    Cancel { id: String },
    /// Remove a finished session and its retained log
    Remove {
        id: String,
        #[arg(long)]
        yes: bool,
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
        /// Host address to bind. On macOS the default is 127.0.0.1 and 0.0.0.0
        /// exposes the forward on all interfaces. On Linux the nftables backend
        /// always exposes forwards on every host interface, so only 0.0.0.0 is
        /// accepted there and a specific address is rejected.
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
pub(crate) enum MacosAction {
    /// Install macOS from a restore image into a new named image. Without
    /// --ipsw, downloads the latest restore image this host supports.
    Install {
        /// Image name (up to 64 letters, digits, `-`, `_`, `.`; not starting
        /// with `.`)
        name: String,
        /// Local restore image (.ipsw) to install from. Read in place and
        /// never deleted
        #[arg(long, conflicts_with_all = ["download_dir", "keep_ipsw"])]
        ipsw: Option<PathBuf>,
        /// Directory to download the restore image into, e.g. on an external
        /// disk (default: <data_dir>/macos/.downloads)
        #[arg(long)]
        download_dir: Option<PathBuf>,
        /// Keep the downloaded restore image after a successful install
        /// instead of deleting it
        #[arg(long)]
        keep_ipsw: bool,
        /// Boot disk size, e.g. 64G (sparse; minimum 32G)
        #[arg(long, default_value = "64G")]
        disk_size: String,
        /// vCPUs for the installer VM
        #[arg(long)]
        cpus: Option<u32>,
        /// Memory in MiB for the installer VM
        #[arg(long)]
        memory: Option<u32>,
    },
    /// List installed macOS images
    List,
    /// Install the husker guest agent into an image so `husker exec` works.
    /// Writes root-owned files into the guest disk, so it must run as root.
    Provision {
        /// Image name or bundle directory path
        image: String,
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

// Semantic command metadata lives beside the clap definitions. Adding or
// removing a clap leaf without updating this registry fails the contract
// coverage test in `schema.rs`; there is deliberately no default policy.
use crate::cli_contract::{CommandContract, Effects, FieldContract as F, JsonType as T};

const VM_ACTION: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("vm", T::String),
];
const NAMED_ACTION: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("name", T::String),
];
const RUN_OUTPUT: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("vm", T::Object),
    F::required("userdata_queued", T::Boolean),
];
const VM_ITEM: &[F] = &[
    F::required("id", T::String),
    F::required("name", T::String),
    F::required("state", T::String),
    F::optional("pid", T::NullableInteger),
    F::required("vcpu_count", T::Integer),
    F::required("mem_size_mib", T::Integer),
    F::required("vsock_cid", T::Integer),
    F::optional("host_ip", T::NullableString),
    F::optional("guest_ip", T::NullableString),
    F::required("created_at", T::String),
    F::required("updated_at", T::String),
    F::optional("userdata_status", T::NullableString),
    F::required("vmm", T::String),
    F::required("boot_mode", T::String),
    F::required("rootfs_path", T::String),
    F::required("kernel_path", T::String),
    F::optional("volume", T::NullableString),
    F::required("network", T::String),
    F::optional("idle_timeout_secs", T::NullableInteger),
    F::optional("suspend_ttl_secs", T::NullableInteger),
    F::optional("auto_resume", T::NullableBoolean),
    F::optional("suspended_at", T::NullableString),
];
const VM_LIST: &[F] = &[
    F::required("items", T::Array),
    F::required("total", T::Integer),
    F::required("limit", T::Integer),
    F::required("offset", T::Integer),
    F::required("daemon_reachable", T::Boolean),
];
const INFO_OUTPUT: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("vm", T::Object),
];
const FORK_OUTPUT: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("source", T::String),
    F::required("vm", T::String),
    F::required("guest_ip", T::NullableString),
];
const BALLOON_OUTPUT: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("vm", T::String),
    F::required("amount_mib", T::Integer),
];
const EXEC_OUTPUT: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("vm", T::String),
    F::required("result", T::Object),
];
const SESSION_OUTPUT: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("vm", T::String),
    F::required("session", T::Object),
];
const SESSION_LIST_OUTPUT: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("vm", T::String),
    F::required("sessions", T::Array),
];
const EVENTS_OUTPUT: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("vm", T::String),
    F::required("page", T::Object),
];
const DEV_OUTPUT: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("vm", T::String),
    F::required("result", T::Object),
];
const JOB_OUTPUT: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("vm", T::String),
    F::required("exit_code", T::Integer),
    F::required("stdout", T::String),
    F::required("stderr", T::String),
    F::optional("retrieval", T::Object),
];
const BUNDLE_OUTPUT: &[F] = &[
    F::required("status", T::String),
    F::required("version", T::Integer),
    F::required("digest", T::String),
    F::required("size_bytes", T::Integer),
    F::required("file_count", T::Integer),
];
const CP_OUTPUT: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("direction", T::String),
    F::required("vm", T::String),
    F::required("path", T::String),
    F::required("bytes", T::Integer),
    F::optional("destination", T::String),
];
const LOGS_OUTPUT: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("vm", T::String),
    F::required("follow", T::Boolean),
    F::required("tail", T::NullableInteger),
    F::required("logs", T::String),
];
const WAIT_OUTPUT: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("vm", T::String),
    F::required("ready", T::Boolean),
];
const VERSION_OUTPUT: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("client_version", T::String),
    F::required("daemon", T::NullableObject),
];
const CONFIG_CHECK_OUTPUT: &[F] = &[
    F::required("status", T::String),
    F::required("config_file", T::NullableString),
    F::required("source", T::String),
    F::required("checks", T::Array),
];
const PROFILE_LIST: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("profiles", T::Object),
];
const CONTEXT_ITEM: &[F] = &[
    F::required("name", T::String),
    F::required("api_url", T::String),
    F::required("current", T::Boolean),
];
const CONTEXT_LIST: &[F] = &[F::required("contexts", T::Array)];
const CONTEXT_ADD: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("name", T::String),
    F::required("api_url", T::String),
];
const CONTEXT_SHOW: &[F] = &[
    F::required("current", T::NullableString),
    F::optional("api_url", T::String),
];
const DOCTOR_OUTPUT: &[F] = &[F::required("checks", T::Array)];
const CAPABILITIES_OUTPUT: &[F] = &[
    F::required("name", T::String),
    F::required("version", T::String),
    F::required("clispec", T::String),
    F::required("output", T::Array),
    F::required("features", T::Array),
    F::required("embedded_agent", T::Boolean),
];
const PF_ADD: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("vm", T::String),
    F::required("host_port", T::Integer),
    F::required("guest_port", T::Integer),
    F::required("bind_addr", T::NullableString),
];
const PF_REMOVE: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("vm", T::String),
    F::required("host_port", T::Integer),
];
const PF_LIST: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("vm", T::String),
    F::required("forwards", T::Array),
];
const PF_ITEM: &[F] = &[
    F::required("host_port", T::Integer),
    F::required("guest_port", T::Integer),
    F::required("protocol", T::String),
    F::required("bind_addr", T::NullableString),
    F::required("created_at", T::String),
];
const HOST_GROUP_ACTION: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("host_group", T::Object),
];
const HOST_GROUP_DELETE: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("host_group", T::String),
];
const HOST_GROUP_LIST: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("host_groups", T::Array),
];
const HOST_GROUP_ITEM: &[F] = &[
    F::required("id", T::String),
    F::required("name", T::String),
    F::required("description", T::NullableString),
    F::required("created_at", T::String),
    F::required("updated_at", T::String),
];
const SERVICE_ACTION: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("service", T::Object),
    F::optional("outcome", T::Object),
];
const SERVICE_LIST: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("services", T::Array),
];
const SERVICE_ITEM: &[F] = &[
    F::required("id", T::String),
    F::required("name", T::String),
    F::required("host_group_id", T::NullableString),
    F::required("desired_instances", T::Integer),
    F::required("current_instances", T::Integer),
    F::required("image", T::NullableString),
    F::required("rootfs_path", T::String),
    F::required("kernel_path", T::String),
    F::required("created_at", T::String),
    F::required("updated_at", T::String),
    F::optional("cloud_image", T::NullableString),
    F::optional("disk_size", T::NullableInteger),
    F::required("balloon", T::Boolean),
    F::optional("volume", T::NullableString),
];
const SERVICE_DELETE: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("name", T::String),
    F::required("outcome", T::Object),
];
const POOL_ACTION: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("pool", T::Object),
];
const POOL_LIST: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("pools", T::Array),
];
const POOL_ITEM: &[F] = &[
    F::required("id", T::String),
    F::required("name", T::String),
    F::required("template_vm_id", T::String),
    F::required("rootfs_path", T::String),
    F::required("kernel_path", T::String),
    F::optional("initrd_path", T::NullableString),
    F::optional("vcpu_count", T::NullableInteger),
    F::optional("mem_size_mib", T::NullableInteger),
    F::required("created_at", T::String),
    F::required("updated_at", T::String),
];
const POOL_CHECKOUT: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("vm", T::Object),
];
const SNAPSHOT_ACTION: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("snapshot", T::Object),
];
const SNAPSHOT_DELETE: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("snapshot", T::String),
];
const SNAPSHOT_LIST: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("snapshots", T::Array),
];
const SNAPSHOT_ITEM: &[F] = &[
    F::required("id", T::String),
    F::required("name", T::String),
    F::required("source_vm_name", T::String),
    F::required("file_path", T::String),
    F::required("created_at", T::String),
];
const SNAPSHOT_RESTORE: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("snapshot", T::String),
    F::required("vm", T::Object),
];
const IMAGE_ACTION: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("image", T::Object),
];
const IMAGE_DELETE: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("image", T::String),
];
const IMAGE_LIST: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("images", T::Array),
];
const IMAGE_ITEM: &[F] = &[
    F::required("id", T::String),
    F::required("name", T::String),
    F::required("source_path", T::String),
    F::required("file_path", T::String),
    F::required("format", T::String),
    F::required("kind", T::String),
    F::required("size_bytes", T::Integer),
    F::required("created_at", T::String),
];
const IMAGE_EXPORT: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("image", T::String),
    F::required("export", T::Object),
];
const IMAGE_PULL: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("source", T::String),
    F::required("kernel", T::String),
    F::required("rootfs", T::String),
    F::required("initrd", T::NullableString),
    F::required("assets", T::Array),
];
const MACOS_IMAGE_ACTION: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("image", T::Object),
];
const MACOS_LIST: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("images", T::Array),
];
const MACOS_IMAGE_ITEM: &[F] = &[
    F::required("name", T::String),
    F::required("path", T::String),
    F::required("build", T::String),
    F::required("os_version", T::String),
    F::required("disk_size_bytes", T::Integer),
    F::required("min_cpus", T::Integer),
    F::required("min_memory_mib", T::Integer),
    F::required("agent_provisioned", T::Boolean),
];
const VOLUME_ACTION: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("volume", T::Object),
];
const VOLUME_LIST: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("volumes", T::Array),
];
const VOLUME_ITEM: &[F] = &[
    F::required("id", T::String),
    F::required("name", T::String),
    F::required("file_path", T::String),
    F::required("size_bytes", T::Integer),
    F::required("created_at", T::String),
];
const SECRET_ACTION: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("secret", T::Object),
];
const SECRET_DELETE: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("secret", T::String),
];
const SECRET_LIST: &[F] = &[
    F::required("status", T::String),
    F::required("action", T::String),
    F::required("secrets", T::Array),
];
const SECRET_ITEM: &[F] = &[
    F::required("id", T::String),
    F::required("name", T::String),
    F::required("created_at", T::String),
    F::required("updated_at", T::String),
];

pub(crate) const COMMAND_CONTRACTS: &[CommandContract] = &[
    CommandContract::object("dev prepare", Effects::Idempotent, DEV_OUTPUT),
    CommandContract::object("dev new", Effects::NonIdempotent, DEV_OUTPUT),
    CommandContract::object("dev check", Effects::Idempotent, DEV_OUTPUT),
    CommandContract::object("prompt", Effects::NonIdempotent, SESSION_OUTPUT),
    CommandContract::object("session start", Effects::NonIdempotent, SESSION_OUTPUT),
    CommandContract::object("session list", Effects::ReadOnly, SESSION_LIST_OUTPUT),
    CommandContract::object("session get", Effects::ReadOnly, SESSION_OUTPUT),
    CommandContract::object("session cancel", Effects::Idempotent, SESSION_OUTPUT),
    CommandContract::object("session remove", Effects::Idempotent, VM_ACTION),
    CommandContract::object("events", Effects::ReadOnly, EVENTS_OUTPUT),
    CommandContract::unsupported("preview", Effects::Idempotent),
    CommandContract::unsupported("daemon", Effects::Idempotent),
    CommandContract::object("run", Effects::NonIdempotent, RUN_OUTPUT),
    CommandContract::list("list", Effects::ReadOnly, VM_LIST, "items", VM_ITEM),
    CommandContract::object("info", Effects::ReadOnly, INFO_OUTPUT),
    CommandContract::object("stop", Effects::Idempotent, VM_ACTION),
    CommandContract::object("pause", Effects::Idempotent, VM_ACTION),
    CommandContract::object("resume", Effects::Idempotent, VM_ACTION),
    CommandContract::object("suspend", Effects::Idempotent, VM_ACTION),
    CommandContract::object("fork", Effects::NonIdempotent, FORK_OUTPUT),
    CommandContract::object("destroy", Effects::Idempotent, VM_ACTION),
    CommandContract::object("balloon", Effects::Idempotent, BALLOON_OUTPUT),
    CommandContract::object("exec", Effects::NonIdempotent, EXEC_OUTPUT),
    CommandContract::object("job", Effects::NonIdempotent, JOB_OUTPUT),
    CommandContract::object("cp", Effects::Idempotent, CP_OUTPUT),
    CommandContract::object("port-forward add", Effects::NonIdempotent, PF_ADD),
    CommandContract::object("port-forward remove", Effects::Idempotent, PF_REMOVE),
    CommandContract::list(
        "port-forward list",
        Effects::ReadOnly,
        PF_LIST,
        "forwards",
        PF_ITEM,
    ),
    CommandContract::object(
        "host-group create",
        Effects::NonIdempotent,
        HOST_GROUP_ACTION,
    ),
    CommandContract::list(
        "host-group list",
        Effects::ReadOnly,
        HOST_GROUP_LIST,
        "host_groups",
        HOST_GROUP_ITEM,
    ),
    CommandContract::object("host-group get", Effects::ReadOnly, HOST_GROUP_ACTION),
    CommandContract::object("host-group delete", Effects::Idempotent, HOST_GROUP_DELETE),
    CommandContract::object("service create", Effects::NonIdempotent, SERVICE_ACTION),
    CommandContract::list(
        "service list",
        Effects::ReadOnly,
        SERVICE_LIST,
        "services",
        SERVICE_ITEM,
    ),
    CommandContract::object("service get", Effects::ReadOnly, SERVICE_ACTION),
    CommandContract::object("service scale", Effects::Idempotent, SERVICE_ACTION),
    CommandContract::object("service delete", Effects::Idempotent, SERVICE_DELETE),
    CommandContract::object("pool create", Effects::NonIdempotent, POOL_ACTION),
    CommandContract::list(
        "pool list",
        Effects::ReadOnly,
        POOL_LIST,
        "pools",
        POOL_ITEM,
    ),
    CommandContract::object("pool get", Effects::ReadOnly, POOL_ACTION),
    CommandContract::object("pool checkout", Effects::NonIdempotent, POOL_CHECKOUT),
    CommandContract::object("pool delete", Effects::Idempotent, NAMED_ACTION),
    CommandContract::object("snapshot create", Effects::NonIdempotent, SNAPSHOT_ACTION),
    CommandContract::list(
        "snapshot list",
        Effects::ReadOnly,
        SNAPSHOT_LIST,
        "snapshots",
        SNAPSHOT_ITEM,
    ),
    CommandContract::object("snapshot get", Effects::ReadOnly, SNAPSHOT_ACTION),
    CommandContract::object("snapshot restore", Effects::NonIdempotent, SNAPSHOT_RESTORE),
    CommandContract::object("snapshot delete", Effects::Idempotent, SNAPSHOT_DELETE),
    CommandContract::object("image import", Effects::NonIdempotent, IMAGE_ACTION),
    CommandContract::object("image import-oci", Effects::NonIdempotent, IMAGE_ACTION),
    CommandContract::list(
        "image list",
        Effects::ReadOnly,
        IMAGE_LIST,
        "images",
        IMAGE_ITEM,
    ),
    CommandContract::object("image get", Effects::ReadOnly, IMAGE_ACTION),
    CommandContract::object("image export", Effects::Idempotent, IMAGE_EXPORT),
    CommandContract::object("image delete", Effects::Idempotent, IMAGE_DELETE),
    CommandContract::object("image pull", Effects::Idempotent, IMAGE_PULL),
    CommandContract::object("macos install", Effects::NonIdempotent, MACOS_IMAGE_ACTION),
    CommandContract::list(
        "macos list",
        Effects::ReadOnly,
        MACOS_LIST,
        "images",
        MACOS_IMAGE_ITEM,
    ),
    CommandContract::object(
        "macos provision",
        Effects::NonIdempotent,
        MACOS_IMAGE_ACTION,
    ),
    CommandContract::unsupported("guest-agent", Effects::ReadOnly),
    CommandContract::object("volume create", Effects::NonIdempotent, VOLUME_ACTION),
    CommandContract::list(
        "volume list",
        Effects::ReadOnly,
        VOLUME_LIST,
        "volumes",
        VOLUME_ITEM,
    ),
    CommandContract::object("volume get", Effects::ReadOnly, VOLUME_ACTION),
    CommandContract::object("volume delete", Effects::Idempotent, NAMED_ACTION),
    CommandContract::object("secret create", Effects::NonIdempotent, SECRET_ACTION),
    CommandContract::list(
        "secret list",
        Effects::ReadOnly,
        SECRET_LIST,
        "secrets",
        SECRET_ITEM,
    ),
    CommandContract::object("secret get", Effects::ReadOnly, SECRET_ACTION),
    CommandContract::object("secret reveal", Effects::ReadOnly, SECRET_ACTION),
    CommandContract::object("secret rotate", Effects::NonIdempotent, SECRET_ACTION),
    CommandContract::object("secret delete", Effects::Idempotent, SECRET_DELETE),
    CommandContract::unsupported("shell", Effects::NonIdempotent),
    CommandContract::object("logs", Effects::ReadOnly, LOGS_OUTPUT),
    CommandContract::object("wait", Effects::ReadOnly, WAIT_OUTPUT),
    CommandContract::object("version", Effects::ReadOnly, VERSION_OUTPUT),
    CommandContract::object("config check", Effects::ReadOnly, CONFIG_CHECK_OUTPUT),
    CommandContract::object("profile list", Effects::ReadOnly, PROFILE_LIST),
    CommandContract::object("context add", Effects::Idempotent, CONTEXT_ADD),
    CommandContract::list(
        "context list",
        Effects::ReadOnly,
        CONTEXT_LIST,
        "contexts",
        CONTEXT_ITEM,
    ),
    CommandContract::object("context use", Effects::Idempotent, NAMED_ACTION),
    CommandContract::object("context remove", Effects::Idempotent, NAMED_ACTION),
    CommandContract::object("context show", Effects::ReadOnly, CONTEXT_SHOW),
    CommandContract::self_describing("schema", Effects::ReadOnly),
    CommandContract::object("capabilities", Effects::ReadOnly, CAPABILITIES_OUTPUT),
    CommandContract::unsupported("setup storage", Effects::Idempotent),
    CommandContract::object("doctor", Effects::ReadOnly, DOCTOR_OUTPUT),
    CommandContract::object("bundle freeze", Effects::Idempotent, BUNDLE_OUTPUT),
    CommandContract::object("bundle verify", Effects::ReadOnly, BUNDLE_OUTPUT),
    CommandContract::unsupported("completions", Effects::ReadOnly),
];

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};
    use husker_core::BootKind;
    use husker_vmm::VmmKind;

    use super::{Cli, Commands};

    /// The whole numbers a help text mentions, so a default of 30 is not
    /// satisfied by a 300 elsewhere in the sentence.
    fn numbers_in(help: &str) -> Vec<u64> {
        help.split(|c: char| !c.is_ascii_digit())
            .filter(|digits| !digits.is_empty())
            .map(|digits| digits.parse().unwrap())
            .collect()
    }

    fn help_of(command: &clap::Command, arg: &str) -> String {
        command
            .get_arguments()
            .find(|a| a.get_id() == arg)
            .unwrap_or_else(|| panic!("`{}` has no `{arg}` argument", command.get_name()))
            .get_help()
            .unwrap_or_else(|| panic!("`{}` {arg} has no help", command.get_name()))
            .to_string()
    }

    /// Every default the daemon applies to a timeout flag is named in that
    /// flag's help, for every boot mode, so a changed default or a new boot
    /// mode cannot leave the help describing a wait the daemon no longer uses.
    /// Every command that talks to the guest agent carries the connect flag.
    #[test]
    fn timeout_help_names_every_default_the_daemon_applies() {
        let root = Cli::command();

        for name in ["exec", "cp", "shell"] {
            let command = root.find_subcommand(name).unwrap();
            let connect = numbers_in(&help_of(command, "connect_timeout"));
            for kind in BootKind::ALL {
                let secs = husker_api::resolve_exec_connect_timeout(None, kind).as_secs();
                assert!(
                    connect.contains(&secs),
                    "{name} --connect-timeout help omits the {kind:?} default of {secs}s: {connect:?}"
                );
            }
            let max = husker_api::MAX_EXEC_CONNECT_TIMEOUT_SECS;
            assert!(
                connect.contains(&max),
                "{name} --connect-timeout help omits the {max}s ceiling: {connect:?}"
            );
        }

        let exec = root.find_subcommand("exec").unwrap();
        let run = numbers_in(&help_of(exec, "timeout"));
        let default = crate::config::default_exec_timeout_secs();
        let max = crate::config::default_exec_timeout_max_secs();
        assert!(
            run.contains(&default),
            "exec --timeout help omits the daemon default of {default}s: {run:?}"
        );
        assert!(
            run.contains(&max),
            "exec --timeout help omits the default ceiling of {max}s: {run:?}"
        );

        let wait = numbers_in(&help_of(root.find_subcommand("wait").unwrap(), "timeout"));
        for kind in BootKind::ALL {
            let secs = husker_core::default_ready_timeout(kind).as_secs();
            assert!(
                wait.contains(&secs),
                "wait --timeout help omits the {kind:?} default of {secs}s: {wait:?}"
            );
        }
    }

    /// The `--vmm` value a parsed `run` or `job` carries.
    fn parsed_vmm(args: &[&str]) -> Option<String> {
        let cli = Cli::try_parse_from(args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        match cli.command {
            Commands::Run { vmm, .. } | Commands::Job { vmm, .. } => vmm,
            _ => panic!("{args:?} parsed as a command without --vmm"),
        }
    }

    /// `--vmm` takes every spelling the daemon takes, so an alias that works
    /// in `HUSKER_VMM` or a profile is not refused by the parser before the
    /// daemon sees it. The value stays as typed; the daemon canonicalizes it.
    #[test]
    fn vmm_accepts_the_aliases_the_daemon_accepts() {
        for kind in VmmKind::ALL {
            for name in [kind.as_str()]
                .into_iter()
                .chain(kind.aliases().iter().copied())
            {
                assert_eq!(
                    parsed_vmm(&["husker", "run", "--vmm", name]).as_deref(),
                    Some(name)
                );
                assert_eq!(
                    parsed_vmm(&["husker", "job", "--vmm", name, "--", "true"]).as_deref(),
                    Some(name)
                );
            }
        }
        let refused = match Cli::try_parse_from(["husker", "run", "--vmm", "xen"]) {
            Ok(_) => panic!("an unknown backend parsed"),
            Err(error) => error,
        };
        assert_eq!(refused.kind(), clap::error::ErrorKind::InvalidValue);
    }

    /// The aliases are accepted, not advertised: the possible values, which
    /// the help and the schema both list, are the canonical names only.
    #[test]
    fn vmm_advertises_only_the_canonical_backend_names() {
        let root = Cli::command();
        for name in ["run", "job"] {
            let command = root.find_subcommand(name).unwrap();
            let vmm = command
                .get_arguments()
                .find(|a| a.get_id() == "vmm")
                .unwrap_or_else(|| panic!("`{name}` has no `vmm` argument"));
            let advertised: Vec<String> = vmm
                .get_possible_values()
                .iter()
                .map(|value| value.get_name().to_string())
                .collect();
            assert_eq!(advertised, VmmKind::ALL.map(VmmKind::as_str), "{name}");

            let help = command.clone().render_long_help().to_string();
            let listed = help
                .lines()
                .find(|line| line.contains("possible values: firecracker"))
                .unwrap_or_else(|| panic!("`{name}` help lists no --vmm values:\n{help}"));
            assert!(
                listed
                    .trim_end()
                    .ends_with("[possible values: firecracker, qemu]"),
                "{name} help advertises more than the canonical names: {listed}"
            );
        }
    }
}
