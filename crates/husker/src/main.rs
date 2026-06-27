use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use husker::{
    default_data_dir, default_images_base_url, default_initrd_path, default_kernel_path,
    default_rootfs_path,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

#[derive(Parser)]
#[command(
    name = "husker",
    about = "An open source microVM manager. Run `husker schema` for machine-readable API introspection.",
    version
)]
struct Cli {
    /// Path to config file
    #[arg(long)]
    config: Option<PathBuf>,

    /// Daemon API address (for client commands).
    ///
    /// Accepts http://host:port or ssh://[user@]host[:port] to reach a remote
    /// daemon over an SSH tunnel (reuses your ssh config/keys; no exposed port).
    /// Driving a Linux daemon this way unlocks Firecracker-only operations
    /// (fork, suspend, OCI import) from a macOS host. Overrides any selected
    /// context. Defaults to the current context, else http://127.0.0.1:7777.
    #[arg(long, env = "HUSKER_API_URL")]
    api_url: Option<String>,

    /// Use a saved context (see `husker context`) as the daemon target.
    /// Overridden by --api-url. Defaults to the current context.
    #[arg(long, short = 'c', env = "HUSKER_CONTEXT", global = true)]
    context: Option<String>,

    /// Bearer token for authenticated API access.
    #[arg(long)]
    api_token: Option<String>,

    /// Output format for command responses.
    #[arg(long, short = 'o', value_enum, default_value_t = OutputFormat::Auto, global = true)]
    output: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    /// Auto-detect: JSON when stdout is not a TTY, text when it is
    Auto,
    /// Human-readable text
    Text,
    /// Machine-readable JSON
    Json,
}

fn resolve_format(fmt: OutputFormat) -> OutputFormat {
    match fmt {
        OutputFormat::Auto => {
            if std::io::IsTerminal::is_terminal(&std::io::stdout()) {
                OutputFormat::Text
            } else {
                OutputFormat::Json
            }
        }
        other => other,
    }
}

#[derive(Subcommand)]
enum Commands {
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
        #[arg(long)]
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

        /// Resize the cloud-image disk before boot, e.g. 10G (cloud-image only)
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

        /// Attach a named persistent volume as the second disk (/dev/vdb)
        #[arg(long)]
        volume: Option<String>,

        /// Bind-mount a host directory into the guest over virtiofs as host:guest[:ro]
        /// (repeatable; QEMU only - pass --vmm qemu)
        #[arg(long)]
        mount: Vec<String>,

        /// Network mode: nat (default, husker-managed NAT) or bridged (attach VM to the
        /// configured lan_bridge; cloud-image only, Linux only)
        #[arg(long, value_parser = ["nat", "bridged"])]
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
        #[arg(long)]
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

        /// Resize the cloud-image disk before boot, e.g. 10G (cloud-image only)
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

        /// Attach a named persistent volume as the second disk (/dev/vdb)
        #[arg(long)]
        volume: Option<String>,

        /// Bind-mount a host directory into the guest over virtiofs as host:guest[:ro]
        /// (repeatable; QEMU only - pass --vmm qemu)
        #[arg(long)]
        mount: Vec<String>,

        /// Network mode: nat (default, husker-managed NAT) or bridged (attach VM to the
        /// configured lan_bridge; cloud-image only, Linux only)
        #[arg(long, value_parser = ["nat", "bridged"])]
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

        /// Copy a path (file or dir, relative to the synced tree) back to the host
        /// after the command, at the same relative location. Repeatable.
        /// Requires --sync-cwd. Build artifacts you do not name never come back.
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
        #[arg(long, value_parser = parse_octal_mode)]
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
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Validate the configuration file
    Check,
}

#[derive(Subcommand)]
enum ContextAction {
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
enum PortForwardAction {
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
enum HostGroupAction {
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
    },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum ServiceAction {
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
        #[arg(long)]
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
        /// Resize the cloud-image disk before boot, e.g. 10G (cloud-image only)
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
    },
}

#[derive(Subcommand)]
enum PoolAction {
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
        #[arg(long)]
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
    },
}

#[derive(Subcommand)]
enum SnapshotAction {
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
        /// Number of vCPUs
        #[arg(long, default_value_t = 1)]
        cpus: u32,
        /// Memory in MiB
        #[arg(long, default_value_t = 128)]
        memory: u32,
    },
    /// Delete a snapshot by name
    Delete {
        /// Snapshot name
        name: String,
    },
}

#[derive(Subcommand)]
enum ImageAction {
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
enum VolumeAction {
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
    },
}

#[derive(Subcommand)]
enum SecretAction {
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
    },
}

#[derive(Debug, Deserialize)]
struct Config {
    #[cfg(feature = "linux-net")]
    #[serde(default = "default_firecracker_bin")]
    firecracker_bin: PathBuf,
    #[cfg(feature = "linux-net")]
    #[serde(default)]
    vmm: VmmSelection,
    #[cfg(all(feature = "linux-net", target_os = "linux"))]
    #[serde(default = "default_qemu_bin")]
    qemu_bin: PathBuf,
    #[cfg(all(feature = "linux-net", target_os = "linux"))]
    #[serde(default = "default_ovmf_code")]
    ovmf_code: PathBuf,
    #[cfg(all(feature = "linux-net", target_os = "linux"))]
    #[serde(default = "default_ovmf_vars")]
    ovmf_vars: PathBuf,
    #[serde(default = "default_data_dir")]
    data_dir: PathBuf,
    #[serde(default = "husker::default_kernel_path")]
    default_kernel: PathBuf,
    #[serde(default = "husker::default_rootfs_path")]
    default_rootfs: PathBuf,
    #[serde(default = "husker::default_initrd_some")]
    default_initrd: Option<PathBuf>,
    /// Default disk size for cloud-image VMs when --disk-size is omitted
    /// (human units, e.g. "10G"). None leaves the image's own size.
    #[serde(default)]
    default_disk_size: Option<String>,
    #[serde(default = "husker::default_images_base_url")]
    images_base_url: String,
    #[serde(default)]
    api_token: Option<String>,
    #[serde(default = "default_api_max_request_bytes")]
    api_max_request_bytes: usize,
    #[serde(default = "default_api_max_file_read_bytes")]
    api_max_file_read_bytes: usize,
    #[serde(default = "default_api_max_file_write_bytes")]
    api_max_file_write_bytes: usize,
    #[serde(default = "default_api_sensitive_rate_limit_per_minute")]
    api_sensitive_rate_limit_per_minute: u32,
    #[serde(default)]
    allowed_read_paths: Vec<String>,
    #[serde(default)]
    allowed_write_paths: Vec<String>,
    #[serde(default)]
    allowed_mount_host_paths: Vec<String>,
    #[serde(default = "default_exec_timeout_secs")]
    exec_timeout_secs: u64,
    #[serde(default = "default_exec_timeout_max_secs")]
    exec_timeout_max_secs: u64,
    #[serde(default)]
    exec_allowlist: Vec<String>,
    #[serde(default)]
    exec_denylist: Vec<String>,
    #[serde(default)]
    exec_env_allowlist: Vec<String>,
    #[serde(default = "default_service_reconcile_interval")]
    service_reconcile_interval_secs: u64,
    #[serde(default = "default_true")]
    service_reconcile_enabled: bool,
    #[cfg(feature = "linux-net")]
    #[serde(default = "default_host_interface")]
    host_interface: String,
    #[cfg(feature = "linux-net")]
    #[serde(default = "default_bridge_name")]
    bridge_name: String,
    #[cfg(feature = "linux-net")]
    #[serde(default = "default_bridge_subnet")]
    bridge_subnet: String,
    #[cfg(feature = "linux-net")]
    #[serde(default = "default_dns_servers")]
    dns_servers: Vec<String>,
    /// Starting CID for vsock and TAP-name allocation (`husker<cid>`). Two
    /// co-located daemons must use distinct non-overlapping bases so their CID
    /// and TAP-name spaces are disjoint. Default 3 (no separation; suitable
    /// for a single-daemon setup).
    #[cfg(feature = "linux-net")]
    #[serde(default = "default_cid_base")]
    cid_base: u32,
    /// Host bridge device to attach bridged-mode VMs to (Linux only).
    /// The bridge must be pre-created by the administrator; husker only
    /// enslaves the VM's TAP to it. Unset means bridged mode is unavailable.
    #[cfg(all(feature = "linux-net", target_os = "linux"))]
    #[serde(default)]
    lan_bridge: Option<String>,
    #[serde(default)]
    profiles: std::collections::HashMap<String, Profile>,
}

/// Named VM preset, selectable with `--profile <name>` on run/job. Every key
/// is optional; explicit CLI flags always win over profile values.
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    cloud_image: Option<PathBuf>,
    rootfs: Option<PathBuf>,
    kernel: Option<PathBuf>,
    initrd: Option<PathBuf>,
    cpus: Option<u32>,
    memory: Option<u32>,
    disk_size: Option<String>,
    #[serde(default)]
    ssh_keys: Vec<PathBuf>,
    vmm: Option<String>,
    #[serde(default)]
    env: Vec<String>,
    balloon: Option<bool>,
    volume: Option<String>,
    #[serde(default)]
    mounts: Vec<String>,
    network: Option<String>,
}

/// Expand a leading `~/` against $HOME (profile ssh_keys convenience).
fn expand_tilde(path: &Path) -> PathBuf {
    if let Ok(rest) = path.strip_prefix("~")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    path.to_path_buf()
}

/// Read `KEY=VALUE` lines from each env file into `KEY=VALUE` strings, matching
/// the format of repeated `-e/--env` flags. Blank lines and `#` comments are
/// skipped, a leading `export ` is tolerated, and the key is trimmed. A line
/// without `=` is an error so a malformed file fails loudly rather than silently
/// dropping a secret. Values are taken verbatim (no quote stripping or
/// interpolation), matching `docker --env-file`.
fn load_env_files(paths: &[PathBuf]) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    for path in paths {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading env file {}", path.display()))?;
        for (idx, raw) in content.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("export ").unwrap_or(line);
            let (key, value) = line.split_once('=').ok_or_else(|| {
                anyhow::anyhow!(
                    "{}:{}: expected KEY=VALUE, got `{raw}`",
                    path.display(),
                    idx + 1
                )
            })?;
            let key = key.trim();
            if key.is_empty() {
                anyhow::bail!("{}:{}: empty key in `{raw}`", path.display(), idx + 1);
            }
            out.push(format!("{key}={value}"));
        }
    }
    Ok(out)
}

/// Combine `--env-file` contents with `-e/--env` flags. File entries come first
/// so an explicit `-e` overrides the same key in a file (consumers resolve env
/// last-wins).
fn merge_env(env_files: &[PathBuf], env_flags: Vec<String>) -> anyhow::Result<Vec<String>> {
    let mut merged = load_env_files(env_files)?;
    merged.extend(env_flags);
    Ok(merged)
}

/// Best-effort boot-failure hint for a VM that never became ready: the tail of
/// its guest serial console plus a pointer to the full log, so a `job` that
/// times out waiting for boot is diagnosable without the user knowing to reach
/// for `husker logs`. Returns a string with a leading newline (or a shorter
/// pointer if the console is empty or unreachable).
async fn serial_boot_hint(
    client: &reqwest::Client,
    api_url: &str,
    api_token: Option<&str>,
    name: &str,
) -> String {
    let url = format!("{api_url}/v1/vms/{name}/logs?source=serial&tail=20");
    let body = match with_api_auth(client.get(&url), api_token).send().await {
        Ok(resp) if resp.status().is_success() => resp.text().await.unwrap_or_default(),
        _ => String::new(),
    };
    let tail = body.trim_end();
    if tail.is_empty() {
        return format!(
            "\nhint: the guest serial console has no output yet; \
             run `husker logs --source serial {name}` to inspect it"
        );
    }
    let module_hint = husker_core::kernel_module_mismatch_hint(tail)
        .map(|h| format!("\nhint: {h}"))
        .unwrap_or_default();
    format!(
        "\n--- guest serial console (tail) ---\n{tail}\n\
         hint: run `husker logs --source serial {name}` for the full guest console{module_hint}"
    )
}

/// Parse a `--add-host name:ip` value into `(hostname, ip)`. The split is on the
/// FIRST `:` so IPv6 addresses (which contain colons) work
/// (`db:2001:db8::1` -> `("db", "2001:db8::1")`); the IP must parse.
fn parse_add_host(spec: &str) -> anyhow::Result<(String, String)> {
    let (host, ip) = spec
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("--add-host expects name:ip, got `{spec}`"))?;
    let host = host.trim();
    let ip = ip.trim();
    if host.is_empty() {
        anyhow::bail!("--add-host has an empty hostname in `{spec}`");
    }
    ip.parse::<std::net::IpAddr>()
        .map_err(|_| anyhow::anyhow!("--add-host `{spec}` has an invalid IP `{ip}`"))?;
    Ok((host.to_string(), ip.to_string()))
}

/// Parse a `--secret` value into `(env_var_name, secret_name)`. Accepts bare
/// `NAME` (the secret is exposed under its own name) or `ENVVAR=secret-name`
/// (renamed). The split is on the first `=`.
fn parse_secret_ref(spec: &str) -> anyhow::Result<(String, String)> {
    match spec.split_once('=') {
        Some((env_var, name)) => {
            let env_var = env_var.trim();
            let name = name.trim();
            if env_var.is_empty() || name.is_empty() {
                anyhow::bail!("--secret expects NAME or ENVVAR=secret-name, got `{spec}`");
            }
            Ok((env_var.to_string(), name.to_string()))
        }
        None => {
            let name = spec.trim();
            if name.is_empty() {
                anyhow::bail!("--secret expects a secret name");
            }
            Ok((name.to_string(), name.to_string()))
        }
    }
}

/// Build the `secret_env` request map (env-var name -> stored secret name) from
/// repeated `--secret` flags. The daemon resolves each name to its value; the
/// CLI never sees plaintext.
fn build_secret_env(
    specs: &[String],
) -> anyhow::Result<serde_json::Map<String, serde_json::Value>> {
    let mut map = serde_json::Map::new();
    for spec in specs {
        let (env_var, name) = parse_secret_ref(spec)?;
        map.insert(env_var, serde_json::Value::String(name));
    }
    Ok(map)
}

/// Validate `--dns` values as IP addresses, returning them unchanged.
fn validate_dns(dns: &[String]) -> anyhow::Result<()> {
    for d in dns {
        d.parse::<std::net::IpAddr>()
            .map_err(|_| anyhow::anyhow!("--dns `{d}` is not a valid IP address"))?;
    }
    Ok(())
}

/// `/etc/resolv.conf` contents for the given nameservers (one per line).
fn render_resolv_conf(dns: &[String]) -> String {
    dns.iter().map(|s| format!("nameserver {s}\n")).collect()
}

/// Merge `host -> ip` entries into existing `/etc/hosts` content, appending any
/// pair not already present (idempotent). Returns the new file content.
fn merge_etc_hosts(existing: &str, additions: &[(String, String)]) -> String {
    let mut out = existing.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    for (host, ip) in additions {
        let already = existing.lines().any(|l| {
            let mut toks = l.split_whitespace();
            toks.next() == Some(ip.as_str()) && toks.any(|t| t == host)
        });
        if !already {
            out.push_str(&format!("{ip}\t{host}\n"));
        }
    }
    out
}

/// Apply per-VM DNS and host entries by writing `/etc/resolv.conf` (replacing it
/// with `--dns` nameservers) and merging `--add-host` entries into `/etc/hosts`,
/// both via the guest file API. Scoped to this VM only - no daemon-wide change.
async fn apply_dns_hosts(
    client: &reqwest::Client,
    api_url: &str,
    api_token: Option<&str>,
    name: &str,
    dns: &[String],
    add_host: &[(String, String)],
) -> anyhow::Result<()> {
    if !dns.is_empty() {
        write_guest_file(
            client,
            api_url,
            api_token,
            name,
            "/etc/resolv.conf",
            render_resolv_conf(dns).as_bytes(),
        )
        .await?;
    }
    if !add_host.is_empty() {
        let existing = read_guest_file_or_empty(client, api_url, api_token, name, "/etc/hosts")
            .await
            .unwrap_or_default();
        let merged = merge_etc_hosts(&existing, add_host);
        write_guest_file(
            client,
            api_url,
            api_token,
            name,
            "/etc/hosts",
            merged.as_bytes(),
        )
        .await?;
    }
    Ok(())
}

/// Poll a VM's `/ready` endpoint until it reports ready or the deadline passes.
/// Returns `Ok(true)` when ready, `Ok(false)` on timeout, and `Err` if the VM is
/// gone or the daemon errors.
async fn wait_for_vm_ready(
    client: &reqwest::Client,
    api_url: &str,
    api_token: Option<&str>,
    name: &str,
    timeout: std::time::Duration,
) -> anyhow::Result<bool> {
    let ready_url = format!("{api_url}/v1/vms/{name}/ready");
    let deadline = std::time::Instant::now() + timeout;
    let mut backoff = std::time::Duration::from_millis(200);
    loop {
        let resp = api_request(with_api_auth(client.get(&ready_url), api_token)).await?;
        if !resp.status().is_success() {
            let msg = api_error(resp, &format!("VM '{name}'")).await;
            anyhow::bail!("{}", msg.message);
        }
        let rdy: serde_json::Value = resp.json().await?;
        if rdy.get("ready").and_then(|r| r.as_bool()).unwrap_or(false) {
            return Ok(true);
        }
        if std::time::Instant::now() + backoff >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(std::time::Duration::from_secs(2));
    }
}

/// Write `data` to `path` inside a VM via the guest file API.
async fn write_guest_file(
    client: &reqwest::Client,
    api_url: &str,
    api_token: Option<&str>,
    name: &str,
    path: &str,
    data: &[u8],
) -> anyhow::Result<()> {
    let body = serde_json::json!({
        "path": path,
        "data": husker_agent_proto::base64_encode(data),
    });
    let resp = api_request(
        with_api_auth(
            client.post(format!("{api_url}/v1/vms/{name}/files/write")),
            api_token,
        )
        .json(&body),
    )
    .await?;
    if !resp.status().is_success() {
        let msg = api_error(resp, &format!("VM '{name}'")).await;
        anyhow::bail!("writing {path}: {}", msg.message);
    }
    Ok(())
}

/// Read `path` from a VM via the guest file API, returning an empty string if the
/// file does not exist yet (so a fresh `/etc/hosts` merges cleanly).
async fn read_guest_file_or_empty(
    client: &reqwest::Client,
    api_url: &str,
    api_token: Option<&str>,
    name: &str,
    path: &str,
) -> anyhow::Result<String> {
    let resp = api_request(
        with_api_auth(
            client.post(format!("{api_url}/v1/vms/{name}/files/read")),
            api_token,
        )
        .json(&serde_json::json!({ "path": path })),
    )
    .await?;
    if !resp.status().is_success() {
        return Ok(String::new());
    }
    let result: serde_json::Value = resp.json().await?;
    let b64 = result["data"].as_str().unwrap_or("");
    let bytes = husker_agent_proto::base64_decode(b64)
        .map_err(|e| anyhow::anyhow!("invalid base64 from server: {e}"))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Flags shared by `run` and `job` that describe the VM to create.
#[derive(Debug, Default)]
struct VmRequestArgs {
    rootfs: Option<PathBuf>,
    kernel: Option<PathBuf>,
    initrd: Option<PathBuf>,
    cpus: Option<u32>,
    memory: Option<u32>,
    vmm: Option<String>,
    cloud_image: Option<PathBuf>,
    disk_size: Option<String>,
    ssh_key: Vec<PathBuf>,
    env: Vec<String>,
    balloon: bool,
    volume: Option<String>,
    mount: Vec<String>,
    network: Option<String>,
}

/// Fill unset fields from a profile: explicit CLI values always win;
/// list fields use the profile only when the CLI provided none.
/// For bool fields (balloon), the profile fills only when the CLI flag is false
/// (since false is the default/unset state; true is always an explicit opt-in).
fn apply_profile(args: &mut VmRequestArgs, p: &Profile) {
    args.cloud_image = args.cloud_image.take().or_else(|| p.cloud_image.clone());
    args.rootfs = args.rootfs.take().or_else(|| p.rootfs.clone());
    args.kernel = args.kernel.take().or_else(|| p.kernel.clone());
    args.initrd = args.initrd.take().or_else(|| p.initrd.clone());
    args.cpus = args.cpus.or(p.cpus);
    args.memory = args.memory.or(p.memory);
    args.disk_size = args.disk_size.take().or_else(|| p.disk_size.clone());
    args.vmm = args.vmm.take().or_else(|| p.vmm.clone());
    if args.ssh_key.is_empty() {
        args.ssh_key = p.ssh_keys.iter().map(|k| expand_tilde(k)).collect();
    }
    if args.env.is_empty() {
        args.env = p.env.clone();
    }
    if !args.balloon {
        args.balloon = p.balloon.unwrap_or(false);
    }
    args.volume = args.volume.take().or_else(|| p.volume.clone());
    if args.mount.is_empty() {
        args.mount = p.mounts.clone();
    }
    args.network = args.network.take().or_else(|| p.network.clone());
}

#[cfg(feature = "linux-net")]
fn default_firecracker_bin() -> PathBuf {
    PathBuf::from("firecracker")
}

#[cfg(feature = "linux-net")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum VmmSelection {
    #[default]
    Firecracker,
    #[cfg(target_os = "linux")]
    Qemu,
}

#[cfg(feature = "linux-net")]
impl VmmSelection {
    fn from_env_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "firecracker" | "fc" => Some(Self::Firecracker),
            #[cfg(target_os = "linux")]
            "qemu" | "kvm" => Some(Self::Qemu),
            _ => None,
        }
    }
}

#[cfg(all(feature = "linux-net", target_os = "linux"))]
fn default_qemu_bin() -> PathBuf {
    PathBuf::from("qemu-system-x86_64")
}

#[cfg(all(feature = "linux-net", target_os = "linux"))]
fn default_ovmf_code() -> PathBuf {
    PathBuf::from("/usr/share/OVMF/OVMF_CODE_4M.fd")
}

#[cfg(all(feature = "linux-net", target_os = "linux"))]
fn default_ovmf_vars() -> PathBuf {
    PathBuf::from("/usr/share/OVMF/OVMF_VARS_4M.fd")
}

fn default_api_max_request_bytes() -> usize {
    2 * 1024 * 1024
}

fn default_api_max_file_read_bytes() -> usize {
    1024 * 1024
}

fn default_api_max_file_write_bytes() -> usize {
    1024 * 1024
}

fn default_api_sensitive_rate_limit_per_minute() -> u32 {
    120
}

fn default_exec_timeout_secs() -> u64 {
    30
}

fn default_exec_timeout_max_secs() -> u64 {
    3600
}

fn default_service_reconcile_interval() -> u64 {
    15
}

fn default_true() -> bool {
    true
}

#[cfg(feature = "linux-net")]
fn default_host_interface() -> String {
    "eth0".into()
}

#[cfg(feature = "linux-net")]
fn default_bridge_name() -> String {
    "husker0".into()
}

#[cfg(feature = "linux-net")]
fn default_bridge_subnet() -> String {
    "172.20.0.0/24".into()
}

#[cfg(feature = "linux-net")]
fn default_dns_servers() -> Vec<String> {
    vec!["8.8.8.8".into(), "1.1.1.1".into()]
}

#[cfg(feature = "linux-net")]
fn default_cid_base() -> u32 {
    3
}

/// Extract a clean error message from an API error response.
///
/// Handles JSON error bodies, plain text, and empty responses gracefully
/// so the CLI never dumps raw stack traces at the user.
/// Exit codes husker returns for its own failures. `exec` and `shell` instead
/// pass through the guest command's exit code. Documented in `husker schema`.
mod exit_code {
    pub const GENERAL: i32 = 1;
    pub const NOT_FOUND: i32 = 2;
    pub const CONFLICT: i32 = 3;
    pub const DENIED: i32 = 4;
    pub const DAEMON_UNREACHABLE: i32 = 5;
    /// Destructive command attempted without confirmation (no TTY, no --yes).
    pub const CONFIRMATION_REQUIRED: i32 = 6;
}

/// A failure to surface to the user: a human-readable `message`, an optional
/// machine-readable `code` (the daemon's stable error code), the process
/// exit code to return, and an optional actionable hint. `String`/`&str`
/// convert in as a generic error.
struct ApiFailure {
    message: String,
    code: Option<String>,
    exit_code: i32,
    hint: Option<String>,
}

impl From<String> for ApiFailure {
    fn from(message: String) -> Self {
        Self {
            message,
            code: None,
            exit_code: exit_code::GENERAL,
            hint: None,
        }
    }
}

impl From<&str> for ApiFailure {
    fn from(message: &str) -> Self {
        message.to_string().into()
    }
}

/// Marker attached to connection failures so the top-level handler can map them
/// to `exit_code::DAEMON_UNREACHABLE`.
#[derive(Debug)]
struct DaemonUnreachable;

impl std::fmt::Display for DaemonUnreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "daemon unreachable")
    }
}

impl std::error::Error for DaemonUnreachable {}

/// Build an `ApiFailure` from a non-success API response: derive the exit code
/// from the HTTP status, capture the daemon's stable `code`, and the message.
async fn api_error(resp: reqwest::Response, subject: &str) -> ApiFailure {
    let status = resp.status();
    let exit_code = match status.as_u16() {
        404 => exit_code::NOT_FOUND,
        409 => exit_code::CONFLICT,
        401 | 403 => exit_code::DENIED,
        _ => exit_code::GENERAL,
    };
    let mut code = None;
    let message = match resp.text().await {
        Ok(body) if !body.is_empty() => match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(json) => {
                code = json["code"].as_str().map(String::from);
                if let Some(msg) = json["message"].as_str() {
                    match json["hint"].as_str() {
                        Some(hint) => format!("{msg} (hint: {hint})"),
                        None => msg.to_string(),
                    }
                } else if let Some(msg) = json["error"].as_str() {
                    msg.to_string()
                } else {
                    body
                }
            }
            Err(_) => body,
        },
        _ => match status.as_u16() {
            404 => format!("{subject} not found"),
            409 => format!("{subject} already exists"),
            _ => format!("{subject}: {status}"),
        },
    };
    ApiFailure {
        message,
        code,
        exit_code,
        hint: None,
    }
}

/// Stores the effective daemon URL for use in connection error messages.
/// Set once at CLI startup so `api_request` can mention the URL without
/// threading it through every call site.
static DAEMON_URL: OnceLock<String> = OnceLock::new();

fn set_daemon_url(url: &str) {
    let _ = DAEMON_URL.set(url.to_string());
}

/// Send a request to the daemon API and return the response.
///
/// Wraps connection errors with a hint about whether the daemon is running,
/// naming the URL so users running a daemon on a non-default port can
/// correct their `--api-url`/`HUSKER_API_URL` setting.
async fn api_request(request: reqwest::RequestBuilder) -> Result<reqwest::Response> {
    request.send().await.map_err(|e| {
        if e.is_connect() {
            let url = DAEMON_URL.get().map(String::as_str).unwrap_or("the daemon");
            anyhow::Error::new(DaemonUnreachable).context(format!(
                "cannot connect to daemon at {url}\n\
                 hint: start it with `husker daemon`, or point at a running daemon via --api-url / HUSKER_API_URL"
            ))
        } else {
            anyhow::anyhow!("{e}")
        }
    })
}

fn with_api_auth(
    request: reqwest::RequestBuilder,
    api_token: Option<&str>,
) -> reqwest::RequestBuilder {
    if let Some(token) = api_token {
        request.bearer_auth(token)
    } else {
        request
    }
}

fn resolve_api_token(cli_api_token: Option<String>, config_path: Option<&Path>) -> Option<String> {
    cli_api_token.or_else(|| load_config(config_path).api_token)
}

fn render_output<T: Serialize>(format: OutputFormat, value: &T, text: impl AsRef<str>) -> String {
    if resolve_format(format) == OutputFormat::Json {
        serde_json::to_string_pretty(value).expect("json serialization should succeed")
    } else {
        text.as_ref().to_string()
    }
}

/// Emit a clispec v0.2 structured error envelope as a single JSON line.
/// The kind is derived from the ApiFailure code when available; falls back to
/// a generic kind derived from the exit code.
fn render_error_envelope(kind: &str, message: &str, hint: Option<&str>) -> String {
    let mut inner = serde_json::Map::new();
    inner.insert("kind".into(), serde_json::Value::from(kind));
    inner.insert("message".into(), serde_json::Value::from(message));
    if let Some(h) = hint {
        inner.insert("hint".into(), serde_json::Value::from(h));
    }
    let mut outer = serde_json::Map::new();
    outer.insert("error".into(), serde_json::Value::Object(inner));
    serde_json::Value::Object(outer).to_string()
}

fn exit_code_to_kind(exit_code: i32) -> &'static str {
    match exit_code {
        exit_code::NOT_FOUND => "not_found",
        exit_code::CONFLICT => "conflict",
        exit_code::DENIED => "permission_denied",
        exit_code::DAEMON_UNREACHABLE => "daemon_unreachable",
        exit_code::CONFIRMATION_REQUIRED => "confirmation_required",
        _ => "error",
    }
}

fn print_output<T: Serialize>(format: OutputFormat, value: &T, text: impl AsRef<str>) {
    println!("{}", render_output(format, value, text));
}

fn exit_with_error(format: OutputFormat, error: impl Into<ApiFailure>) -> ! {
    let err = error.into();
    let kind = err
        .code
        .as_deref()
        .unwrap_or_else(|| exit_code_to_kind(err.exit_code));
    // The structured error envelope is always written to stderr as the last line.
    // Human-readable text mode also puts errors on stderr (no stdout pollution).
    let structured = render_error_envelope(kind, &err.message, err.hint.as_deref());
    if resolve_format(format) == OutputFormat::Json {
        eprintln!("{structured}");
    } else {
        eprintln!("Error: {}", &err.message);
        eprintln!("{structured}");
    }
    std::process::exit(err.exit_code);
}

/// Gate a destructive command on confirmation: a no-op when `yes` is set;
/// otherwise prompt when stdin is a TTY, or refuse (exit
/// `CONFIRMATION_REQUIRED`) when it is not. Shared by `destroy` and
/// `image delete` so destructive commands behave consistently.
fn require_confirmation(prompt: &str, yes: bool, format: OutputFormat) {
    use std::io::IsTerminal;
    if yes {
        return;
    }
    if std::io::stdin().is_terminal() {
        eprint!("{prompt} [y/N] ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer).ok();
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            eprintln!("Aborted.");
            std::process::exit(0);
        }
    } else {
        exit_with_error(
            format,
            ApiFailure {
                message: format!("{prompt} requires confirmation"),
                code: Some("confirmation_required".into()),
                exit_code: exit_code::CONFIRMATION_REQUIRED,
                hint: Some("Re-run with --yes to confirm.".into()),
            },
        );
    }
}

/// Build the machine-readable CLI contract emitted by `husker schema`.
/// Conforms to The CLI Spec v0.2 (https://clispec.dev/schema/v0.2.json):
/// `global_args` is an array, `commands` is an array, `errors` is an array.
fn build_cli_schema() -> serde_json::Value {
    use clap::CommandFactory;
    let root = Cli::command();
    let mut commands: Vec<serde_json::Value> = Vec::new();
    for sub in root.get_subcommands() {
        collect_schema_command(sub, &[], &mut commands);
    }
    // Sort so read-only commands appear before mutating ones, with `list`
    // first (the canonical list command that consumers use for introspection),
    // then other read-only commands, then mutating commands.
    commands.sort_by(|a, b| {
        let priority = |v: &serde_json::Value| -> u8 {
            let name = v.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let mutating = v.get("mutating").and_then(|m| m.as_bool());
            match (name, mutating) {
                ("list", _) => 0,
                (_, Some(false)) => 1,
                (_, Some(true)) => 3,
                _ => 2,
            }
        };
        priority(a).cmp(&priority(b))
    });
    serde_json::json!({
        "clispec": "0.2",
        "name": "husker",
        "version": env!("CARGO_PKG_VERSION"),
        "description": root.get_about().map(|s| s.to_string()).unwrap_or_default(),
        "global_args": schema_global_args(&root),
        "commands": commands,
        "errors": [
            {
                "kind": "error",
                "exit_code": 1,
                "retryable": false,
                "description": "General client or server error"
            },
            {
                "kind": "not_found",
                "exit_code": 2,
                "retryable": false,
                "description": "VM, image, snapshot, volume, or secret not found"
            },
            {
                "kind": "conflict",
                "exit_code": 3,
                "retryable": false,
                "description": "Resource already exists or is in an incompatible state"
            },
            {
                "kind": "permission_denied",
                "exit_code": 4,
                "retryable": false,
                "description": "Authentication or authorization failure"
            },
            {
                "kind": "daemon_unreachable",
                "exit_code": 5,
                "retryable": true,
                "description": "Cannot connect to the husker daemon"
            },
            {
                "kind": "confirmation_required",
                "exit_code": 6,
                "retryable": false,
                "description": "Destructive command attempted without confirmation; re-run with --yes"
            }
        ]
    })
}

/// Build a clap arg into the clispec `arg` shape.
fn clap_arg_to_schema(a: &clap::Arg) -> serde_json::Value {
    let id = a.get_id().as_str();
    let flag_name = if let Some(long) = a.get_long() {
        format!("--{long}")
    } else {
        id.to_string()
    };
    let type_str = match a.get_action() {
        clap::ArgAction::SetTrue | clap::ArgAction::SetFalse | clap::ArgAction::Count => "boolean",
        clap::ArgAction::Append => "string[]",
        _ => {
            // Heuristic: detect integer args by looking at default values or
            // known numeric arg names.
            if matches!(
                id,
                "limit"
                    | "offset"
                    | "amount_mib"
                    | "cpus"
                    | "memory"
                    | "desired_instances"
                    | "timeout"
                    | "tail"
                    | "host_port"
                    | "guest_port"
                    | "vcpus"
            ) {
                "integer"
            } else {
                "string"
            }
        }
    };
    let mut o = serde_json::Map::new();
    o.insert("name".into(), serde_json::Value::from(flag_name));
    o.insert("type".into(), serde_json::Value::from(type_str));
    o.insert(
        "required".into(),
        serde_json::Value::from(a.is_required_set()),
    );
    if let Some(help) = a.get_help() {
        o.insert(
            "description".into(),
            serde_json::Value::from(help.to_string()),
        );
    }
    if let Some(vals) = a.get_possible_values().first() {
        let _ = vals; // ensure no dead-code warning; enum population below
        let enums: Vec<serde_json::Value> = a
            .get_possible_values()
            .iter()
            .map(|v| serde_json::Value::from(v.get_name()))
            .collect();
        if !enums.is_empty() {
            o.insert("enum".into(), serde_json::Value::Array(enums));
        }
    }
    serde_json::Value::Object(o)
}

/// Recursively collect clap subcommands into a clispec commands array.
/// Groups (commands that only hold subcommands) collect their own positional
/// args and pass them down to leaves, which combine inherited + own args.
/// `prefix` is the space-joined path of parent command names for annotation
/// lookups, e.g. "service" when processing children of the `service` group.
fn collect_schema_command(
    cmd: &clap::Command,
    parent_args: &[serde_json::Value],
    out: &mut Vec<serde_json::Value>,
) {
    collect_schema_command_inner(cmd, parent_args, "", out);
}

fn collect_schema_command_inner(
    cmd: &clap::Command,
    parent_args: &[serde_json::Value],
    prefix: &str,
    out: &mut Vec<serde_json::Value>,
) {
    let name = cmd.get_name();
    if name == "help" {
        return;
    }
    let full_path = if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix} {name}")
    };

    let own_args: Vec<serde_json::Value> = cmd
        .get_arguments()
        .filter(|a| {
            let id = a.get_id().as_str();
            id != "help" && !a.is_global_set()
        })
        .map(clap_arg_to_schema)
        .collect();

    let subs: Vec<&clap::Command> = cmd
        .get_subcommands()
        .filter(|s| s.get_name() != "help")
        .collect();

    if subs.is_empty() {
        // Leaf command: emit it with combined args.
        let mut args = parent_args.to_vec();
        args.extend(own_args);

        let (mutating, output_field_names) = schema_command_annotations(&full_path);
        let output_fields: Vec<serde_json::Value> = output_field_names
            .iter()
            .map(|f| serde_json::json!({"name": f, "type": "string"}))
            .collect();

        out.push(serde_json::json!({
            "name": name,
            "description": cmd.get_about().map(|s| s.to_string()).unwrap_or_default(),
            "mutating": mutating,
            "args": args,
            "output_fields": output_fields,
        }));
    } else {
        // Group command: recurse, passing own positional args downward.
        let mut child_args = parent_args.to_vec();
        child_args.extend(own_args);

        let mut subcommands: Vec<serde_json::Value> = Vec::new();
        for sub in subs {
            collect_schema_command_inner(sub, &child_args, &full_path, &mut subcommands);
        }
        out.push(serde_json::json!({
            "name": name,
            "description": cmd.get_about().map(|s| s.to_string()).unwrap_or_default(),
            "subcommands": subcommands,
        }));
    }
}

/// Global args accepted by every command, derived from the root command.
/// Returns a v0.2-compliant array of arg objects.
fn schema_global_args(root: &clap::Command) -> Vec<serde_json::Value> {
    root.get_arguments()
        .filter(|a| {
            let id = a.get_id().as_str();
            id != "help" && id != "version"
        })
        .map(clap_arg_to_schema)
        .collect()
}

/// Manual annotations clap cannot derive: whether a command mutates state, and
/// the fields its JSON output emits. Read-only commands are listed explicitly;
/// everything else is treated as mutating. `output_fields` are provided for the
/// core commands and left empty for the rest.
fn schema_command_annotations(path: &str) -> (bool, Vec<&'static str>) {
    let read_only = matches!(
        path,
        "list"
            | "info"
            | "logs"
            | "wait"
            | "version"
            | "schema"
            | "config check"
            | "port-forward list"
            | "host-group list"
            | "host-group get"
            | "service list"
            | "service get"
            | "pool list"
            | "pool get"
            | "snapshot list"
            | "snapshot get"
            | "image list"
            | "image get"
            | "volume list"
            | "volume get"
            | "secret list"
            | "secret get"
            | "secret reveal"
            | "context list"
            | "context show"
    );
    let output_fields: Vec<&'static str> = match path {
        "balloon" => vec!["status", "action", "vm", "amount_mib"],
        "run" => vec!["status", "action", "vm", "userdata_queued"],
        "job" => vec!["status", "action", "vm", "exit_code", "stdout", "stderr"],
        "list" => vec![
            "name",
            "state",
            "vcpu_count",
            "mem_size_mib",
            "guest_ip",
            "vmm",
        ],
        "info" => vec![
            "name",
            "state",
            "vcpu_count",
            "mem_size_mib",
            "guest_ip",
            "host_ip",
            "userdata_status",
            "volume",
            "id",
            "vmm",
            "boot_mode",
            "kernel_path",
            "rootfs_path",
            "network",
        ],
        "wait" => vec!["status", "action", "vm", "ready"],
        "fork" => vec!["status", "action", "source", "vm", "guest_ip"],
        "stop" | "pause" | "resume" | "suspend" | "destroy" => vec!["status", "action", "vm"],
        "exec" => vec!["exit_code", "stdout", "stderr"],
        "version" => vec!["client_version", "server_version"],
        "service create" | "service scale" => vec!["status", "action", "service", "outcome"],
        "service delete" => vec!["status", "action", "name", "outcome"],
        "service get" => vec!["status", "action", "service", "instances"],
        "service list" => vec!["status", "action", "services"],
        "pool create" | "pool get" => vec!["status", "action", "pool"],
        "pool list" => vec!["status", "action", "pools"],
        "pool checkout" => vec!["status", "action", "vm"],
        "pool delete" => vec!["status", "action", "name"],
        "volume create" | "volume get" => vec!["status", "action", "volume"],
        "volume delete" => vec!["status", "action", "name"],
        "volume list" => vec!["status", "action", "volumes"],
        "context list" => vec!["contexts"],
        "context show" => vec!["current", "api_url"],
        "context add" => vec!["status", "action", "name", "api_url"],
        "context use" | "context remove" => vec!["status", "action", "name"],
        _ => vec![],
    };
    (!read_only, output_fields)
}

/// Derive a default catalog image name from an OCI reference: the last path
/// component with its tag, sanitized (e.g. `alpine:3.20` -> `alpine-3.20`,
/// `ghcr.io/o/img:v1` -> `img-v1`).
fn oci_default_image_name(reference: &str) -> String {
    let last = reference.rsplit('/').next().unwrap_or(reference);
    let name: String = last
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    // Cap the slug well under the catalog's 64-char resource-name limit, so a
    // digest reference (`repo@sha256:<64 hex>`) still yields a valid name.
    let capped: String = name.trim_matches('-').chars().take(48).collect();
    let trimmed = capped.trim_matches('-');
    if trimmed.is_empty() {
        "oci-image".to_string()
    } else {
        trimmed.to_string()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            #[cfg(feature = "linux-net")]
            firecracker_bin: default_firecracker_bin(),
            #[cfg(feature = "linux-net")]
            vmm: VmmSelection::default(),
            #[cfg(all(feature = "linux-net", target_os = "linux"))]
            qemu_bin: default_qemu_bin(),
            #[cfg(all(feature = "linux-net", target_os = "linux"))]
            ovmf_code: default_ovmf_code(),
            #[cfg(all(feature = "linux-net", target_os = "linux"))]
            ovmf_vars: default_ovmf_vars(),
            data_dir: default_data_dir(),
            default_kernel: default_kernel_path(),
            default_rootfs: default_rootfs_path(),
            default_initrd: Some(default_initrd_path()),
            default_disk_size: None,
            images_base_url: default_images_base_url(),
            api_token: None,
            api_max_request_bytes: default_api_max_request_bytes(),
            api_max_file_read_bytes: default_api_max_file_read_bytes(),
            api_max_file_write_bytes: default_api_max_file_write_bytes(),
            api_sensitive_rate_limit_per_minute: default_api_sensitive_rate_limit_per_minute(),
            allowed_read_paths: Vec::new(),
            allowed_write_paths: Vec::new(),
            allowed_mount_host_paths: Vec::new(),
            exec_timeout_secs: default_exec_timeout_secs(),
            exec_timeout_max_secs: default_exec_timeout_max_secs(),
            exec_allowlist: Vec::new(),
            exec_denylist: Vec::new(),
            exec_env_allowlist: Vec::new(),
            service_reconcile_interval_secs: default_service_reconcile_interval(),
            service_reconcile_enabled: default_true(),
            #[cfg(feature = "linux-net")]
            host_interface: default_host_interface(),
            #[cfg(feature = "linux-net")]
            bridge_name: default_bridge_name(),
            #[cfg(feature = "linux-net")]
            bridge_subnet: default_bridge_subnet(),
            #[cfg(feature = "linux-net")]
            dns_servers: default_dns_servers(),
            #[cfg(feature = "linux-net")]
            cid_base: default_cid_base(),
            #[cfg(all(feature = "linux-net", target_os = "linux"))]
            lan_bridge: None,
            profiles: Default::default(),
        }
    }
}

/// Resolve profile + defaults + guards into the create-VM JSON body.
/// Shared by `run` and `job`. Exits the process (via exit_with_error) on
/// user errors, matching the existing run-handler behavior.
fn build_vm_request_body(
    name: &str,
    mut args: VmRequestArgs,
    profile: Option<&str>,
    config: &Config,
    output: OutputFormat,
) -> anyhow::Result<serde_json::Value> {
    if let Some(p) = profile {
        match config.profiles.get(p) {
            Some(prof) => apply_profile(&mut args, prof),
            None => {
                let mut names: Vec<&String> = config.profiles.keys().collect();
                names.sort();
                let list = if names.is_empty() {
                    "none defined".to_string()
                } else {
                    names
                        .iter()
                        .map(|n| n.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                exit_with_error(output, format!("unknown profile '{p}' (available: {list})"));
            }
        }
    }

    if args.disk_size.is_some() && args.cloud_image.is_none() {
        exit_with_error(output, "--disk-size requires --cloud-image".to_string());
    }
    if !args.ssh_key.is_empty() && args.cloud_image.is_none() {
        exit_with_error(output, "--ssh-key requires --cloud-image".to_string());
    }

    let balloon = args.balloon;

    let env_pairs: Vec<(String, String)> = args
        .env
        .iter()
        .filter_map(|s| {
            let (k, v) = s.split_once('=')?;
            Some((k.to_string(), v.to_string()))
        })
        .collect();

    let mut body = serde_json::json!({
        "name": name,
        "vcpu_count": args.cpus.unwrap_or(1),
        "mem_size_mib": args.memory.unwrap_or(128),
        "env": env_pairs,
    });

    if let Some(ref vmm_kind) = args.vmm {
        body["vmm"] = serde_json::json!(vmm_kind);
    }

    if let Some(ref img) = args.cloud_image.clone() {
        body["cloud_image"] = serde_json::json!(img);
        let disk_size_source = if args.disk_size.is_some() {
            "--disk-size"
        } else {
            "config default_disk_size"
        };
        if let Some(ref size) = args.disk_size.clone().or(config.default_disk_size.clone()) {
            let bytes = husker::parse_disk_size(size)
                .map_err(|e| anyhow::anyhow!("{disk_size_source}: {e}"))?;
            body["disk_size"] = serde_json::json!(bytes);
        }
        if !args.ssh_key.is_empty() {
            let mut keys: Vec<String> = Vec::new();
            for path in &args.ssh_key {
                let content = std::fs::read_to_string(path)
                    .with_context(|| format!("reading SSH public key {}", path.display()))?;
                let parsed = husker::parse_ssh_public_keys(&content)
                    .map_err(|e| anyhow::anyhow!("--ssh-key {}: {e}", path.display()))?;
                keys.extend(parsed);
            }
            body["ssh_authorized_keys"] = serde_json::json!(keys);
        }
        if output == OutputFormat::Text {
            eprintln!("Using: cloud-image={}", img.display());
        }
    } else {
        // Only include kernel/rootfs/initrd in the request when the user explicitly
        // provided them. When omitted, the daemon resolves defaults from its own
        // config, ensuring the paths exist on the daemon host rather than the client.
        let explicit_rootfs = args
            .rootfs
            .map(|path| husker::resolve_rootfs_arg(path, &config.data_dir));
        let explicit_kernel = args.kernel;
        let explicit_initrd = args.initrd;

        // When paths are omitted and the local defaults don't exist, emit a hint
        // so users on a fresh local install know to run `husker images pull`.
        // This is advisory only; the daemon may have its own defaults even if the
        // client's data dir is empty (e.g. a remote daemon over ssh://).
        // Emitted unconditionally to stderr since it is always human-facing.
        if explicit_kernel.is_none() && !config.default_kernel.exists() {
            eprintln!(
                "Default kernel not found at {}.\n\
                 Run `husker images pull` to fetch it, or pass --kernel explicitly.",
                config.default_kernel.display()
            );
        }
        if explicit_rootfs.is_none() && !config.default_rootfs.exists() {
            eprintln!(
                "Default rootfs not found at {}.\n\
                 Run `husker images pull` to fetch it, or pass a rootfs path explicitly.",
                config.default_rootfs.display()
            );
        }

        if output == OutputFormat::Text {
            let kernel_str = explicit_kernel
                .as_ref()
                .map(|p: &std::path::PathBuf| p.display().to_string())
                .unwrap_or_else(|| "(daemon default)".to_string());
            let rootfs_str = explicit_rootfs
                .as_ref()
                .map(|p: &std::path::PathBuf| p.display().to_string())
                .unwrap_or_else(|| "(daemon default)".to_string());
            let initrd_str = explicit_initrd
                .as_ref()
                .map(|p: &std::path::PathBuf| p.display().to_string())
                .unwrap_or_else(|| "(daemon default)".to_string());
            eprintln!("Using: kernel={kernel_str} rootfs={rootfs_str} initrd={initrd_str}",);
        }
        if let Some(ref rootfs) = explicit_rootfs {
            body["rootfs_path"] = serde_json::json!(rootfs);
        }
        if let Some(ref kernel) = explicit_kernel {
            body["kernel_path"] = serde_json::json!(kernel);
        }
        if let Some(ref initrd) = explicit_initrd {
            body["initrd_path"] = serde_json::json!(initrd);
        }
    }

    if balloon {
        body["balloon"] = serde_json::json!(true);
    }

    if let Some(ref vol) = args.volume {
        body["volume"] = serde_json::json!(vol);
    }

    if !args.mount.is_empty() {
        body["mounts"] = serde_json::json!(args.mount);
    }

    if let Some(ref net) = args.network {
        body["network"] = serde_json::json!(net);
    }

    Ok(body)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("husker=info".parse().expect("static directive")),
        )
        .init();

    // Use try_parse so clap parse errors go through our structured-error
    // envelope instead of clap's plain-text error printer.
    // Help and version display are let through unchanged (they print and exit 0).
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            use clap::error::ErrorKind;
            if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                // Let clap print help/version normally and exit 0.
                e.exit();
            }
            // For genuine parse errors, emit human-readable text then the
            // structured envelope as the last line of stderr.
            let output = resolve_format(OutputFormat::Auto);
            let msg = e.render().to_string();
            if output == OutputFormat::Json {
                let structured = render_error_envelope("invalid_usage", &msg, None);
                eprintln!("{structured}");
            } else {
                eprint!("{msg}");
                let structured = render_error_envelope("invalid_usage", &msg, None);
                eprintln!("{structured}");
            }
            // Use the exit code clap computed (normally 2 for usage errors).
            std::process::exit(e.exit_code());
        }
    };
    let output = resolve_format(cli.output);
    if let Err(e) = run(cli).await {
        // A connection failure carries the DaemonUnreachable marker; everything
        // else is a generic client error. API errors (not-found/conflict/denied)
        // exit earlier via exit_with_error with their own codes. Rendered in the
        // requested format so `--output json` callers always get parseable errors.
        let (code, error_kind) = if e.chain().any(|cause| cause.is::<DaemonUnreachable>()) {
            (exit_code::DAEMON_UNREACHABLE, "daemon_unreachable")
        } else {
            (exit_code::GENERAL, "error")
        };
        let message = format!("{e:#}");
        let structured = render_error_envelope(error_kind, &message, None);
        if output == OutputFormat::Json {
            eprintln!("{structured}");
        } else {
            eprintln!("Error: {message}");
            eprintln!("{structured}");
        }
        std::process::exit(code);
    }
}

async fn run(cli: Cli) -> Result<()> {
    let Cli {
        config: config_path,
        api_url,
        context,
        api_token: cli_api_token,
        output: raw_output,
        command,
    } = cli;
    // Resolve Auto -> Json/Text once based on stdout TTY state, so all
    // downstream branches can compare directly without re-calling resolve_format.
    let output = resolve_format(raw_output);

    // Context management is local-only; handle it before resolving a daemon URL.
    if let Commands::Context { action } = command {
        return context_command(action, output);
    }

    // Resolve the daemon target: explicit --api-url/HUSKER_API_URL, else the
    // selected/current saved context, else the local default.
    let api_url =
        resolve_effective_api_url(api_url.as_deref(), context.as_deref(), &load_contexts())?;

    // ssh:// transport: open an SSH local-forward tunnel to a remote daemon and
    // rewrite api_url to the local end. The guard keeps the ssh process alive for
    // the whole command and tears it down on return. `husker daemon` starts a
    // local server and never tunnels, even if the current context is ssh://.
    let _ssh_tunnel: Option<SshTunnel>;
    let api_url = if api_url.starts_with("ssh://") && !matches!(command, Commands::Daemon { .. }) {
        let tunnel = SshTunnel::establish(&api_url).await?;
        let local = tunnel.local_url();
        _ssh_tunnel = Some(tunnel);
        local
    } else {
        _ssh_tunnel = None;
        api_url
    };
    set_daemon_url(&api_url);

    match command {
        Commands::Daemon {
            listen,
            allow_remote,
        } => {
            validate_daemon_bind(listen, allow_remote)?;
            let mut config = load_config(config_path.as_deref());
            if let Some(token) = cli_api_token.clone() {
                config.api_token = Some(token);
            }
            start_daemon(config, listen).await
        }
        Commands::Run {
            rootfs,
            name,
            pool,
            kernel,
            initrd,
            cpus,
            memory,
            userdata,
            env,
            env_file,
            dns,
            add_host,
            vmm,
            cloud_image,
            disk_size,
            ssh_key,
            balloon,
            volume,
            mount,
            net,
            profile,
        } => {
            let config = load_config(config_path.as_deref());
            let api_token = cli_api_token.clone().or_else(|| config.api_token.clone());

            let name =
                name.unwrap_or_else(|| format!("vm-{}", &uuid::Uuid::new_v4().to_string()[..8]));

            let env = merge_env(&env_file, env)?;
            // Validate DNS/host overrides before creating the VM.
            validate_dns(&dns)?;
            let add_host = add_host
                .iter()
                .map(|s| parse_add_host(s))
                .collect::<anyhow::Result<Vec<_>>>()?;

            let client = reqwest::Client::new();
            let resp = if let Some(pool) = pool {
                // Draw a fresh VM from a hot pool: fork its template into `name`.
                // The pool's template defines the image and resources, so the
                // boot/config flags do not apply - reject them rather than
                // silently ignore them.
                if rootfs.is_some()
                    || kernel.is_some()
                    || initrd.is_some()
                    || cpus.is_some()
                    || memory.is_some()
                    || vmm.is_some()
                    || cloud_image.is_some()
                    || disk_size.is_some()
                    || volume.is_some()
                    || net.is_some()
                    || profile.is_some()
                    || balloon
                    || userdata.is_some()
                    || !ssh_key.is_empty()
                    || !env.is_empty()
                    || !dns.is_empty()
                    || !add_host.is_empty()
                {
                    exit_with_error(
                        output,
                        format!(
                            "--pool cannot be combined with rootfs/boot/config flags \
                             (pool '{pool}' defines the VM); pass only --name"
                        ),
                    );
                }
                api_request(
                    with_api_auth(
                        client.post(format!("{api_url}/v1/pools/{pool}/checkout")),
                        api_token.as_deref(),
                    )
                    .json(&serde_json::json!({ "vm_name": &name })),
                )
                .await?
            } else {
                let args = VmRequestArgs {
                    rootfs,
                    kernel,
                    initrd,
                    cpus,
                    memory,
                    vmm,
                    cloud_image,
                    disk_size,
                    ssh_key,
                    env,
                    balloon,
                    volume,
                    mount,
                    network: net,
                };
                let mut body =
                    build_vm_request_body(&name, args, profile.as_deref(), &config, output)?;

                if let Some(ref userdata_path) = userdata {
                    let script = std::fs::read_to_string(userdata_path).with_context(|| {
                        format!("reading userdata script {}", userdata_path.display())
                    })?;
                    body["userdata"] = serde_json::json!(script);
                }

                #[cfg(all(target_os = "linux", feature = "linux-net"))]
                if needs_firecracker_preflight(&body) {
                    ensure_firecracker(&config).await?;
                }

                api_request(
                    with_api_auth(
                        client.post(format!("{api_url}/v1/vms")),
                        api_token.as_deref(),
                    )
                    .json(&body),
                )
                .await?
            };

            if !resp.status().is_success() {
                let mut full = api_error(resp, &format!("VM '{name}'")).await;
                if full.message.contains("already exists") {
                    full.message.push_str(&format!(
                        " (hint: if it is suspended, resume it with `husker resume {name}`; otherwise stop or destroy it first with `husker destroy {name}`)"
                    ));
                }
                exit_with_error(output, full);
            }

            let vm: serde_json::Value = resp.json().await?;
            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "run",
                        "vm": vm,
                        "userdata_queued": userdata.is_some(),
                    }),
                    "",
                );
            } else {
                println!("Created VM: {}", vm["name"].as_str().unwrap_or("-"));
                println!("  ID:    {}", vm["id"].as_str().unwrap_or("-"));
                println!("  State: {}", vm["state"].as_str().unwrap_or("-"));
                println!("  CPUs:  {}", vm["vcpu_count"]);
                println!("  RAM:   {} MiB", vm["mem_size_mib"]);

                if userdata.is_some() {
                    println!("  Userdata script queued (check status with `husker info {name}`)");
                }
            }

            // Apply per-VM DNS / host overrides once the agent is reachable. Only
            // waits for readiness when these flags are set, so a plain `run` stays
            // non-blocking.
            if !dns.is_empty() || !add_host.is_empty() {
                let ready_timeout = if vm.get("boot_mode").and_then(|b| b.as_str()) == Some("uefi")
                {
                    husker_core::UEFI_READY_TIMEOUT_SECS
                } else {
                    husker_core::DEFAULT_READY_TIMEOUT_SECS
                };
                let ready = wait_for_vm_ready(
                    &client,
                    &api_url,
                    api_token.as_deref(),
                    &name,
                    std::time::Duration::from_secs(ready_timeout),
                )
                .await?;
                if !ready {
                    let hint =
                        serial_boot_hint(&client, &api_url, api_token.as_deref(), &name).await;
                    anyhow::bail!(
                        "VM '{name}' did not become ready to apply --dns/--add-host{hint}"
                    );
                }
                apply_dns_hosts(
                    &client,
                    &api_url,
                    api_token.as_deref(),
                    &name,
                    &dns,
                    &add_host,
                )
                .await?;
                if output == OutputFormat::Text {
                    println!("  Applied per-VM DNS/host overrides");
                }
            }
            Ok(())
        }
        Commands::List {
            limit,
            offset,
            fields,
        } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            let client = reqwest::Client::new();
            let mut url = format!("{api_url}/v1/vms?limit={limit}&offset={offset}");
            if let Some(ref f) = fields {
                url.push_str(&format!("&fields={}", f));
            }
            // When the daemon is unreachable, return an empty list so agents and
            // scripts get a valid, paginatable response instead of a hard error.
            // A diagnostic message goes to stderr.
            let resp_result =
                api_request(with_api_auth(client.get(&url), api_token.as_deref())).await;
            let vms: Vec<serde_json::Value> = match resp_result {
                Err(ref e) if e.chain().any(|c| c.is::<DaemonUnreachable>()) => {
                    eprintln!(
                        "daemon not reachable; showing empty list (start with `husker daemon`)"
                    );
                    vec![]
                }
                Err(e) => return Err(e),
                Ok(resp) => {
                    if !resp.status().is_success() {
                        let msg = api_error(resp, "listing VMs").await;
                        exit_with_error(output, msg);
                    }
                    resp.json().await?
                }
            };
            let total = vms.len();
            let fmt = resolve_format(output);
            if fmt == OutputFormat::Json {
                // Apply field filtering when --fields is specified.
                let filtered: Vec<serde_json::Value> = if let Some(ref f) = fields {
                    let field_names: Vec<&str> = f.split(',').map(str::trim).collect();
                    vms.iter()
                        .map(|vm| {
                            let mut obj = serde_json::Map::new();
                            for name in &field_names {
                                if let Some(v) = vm.get(*name) {
                                    obj.insert((*name).to_string(), v.clone());
                                }
                            }
                            serde_json::Value::Object(obj)
                        })
                        .collect()
                } else {
                    vms.clone()
                };
                print_output(
                    output,
                    &serde_json::json!({
                        "items": filtered,
                        "total": total,
                        "limit": limit,
                        "offset": offset,
                    }),
                    "",
                );
            } else if vms.is_empty() {
                println!("No VMs found");
            } else {
                println!(
                    "{:<20} {:<12} {:>4}   {:<10} {:<16}",
                    "NAME", "STATE", "CPUS", "MEMORY", "GUEST IP"
                );
                for vm in &vms {
                    println!(
                        "{:<20} {:<12} {:>4}   {:>4} MiB   {:<16}",
                        vm["name"].as_str().unwrap_or("-"),
                        vm["state"].as_str().unwrap_or("-"),
                        vm["vcpu_count"],
                        vm["mem_size_mib"],
                        vm["guest_ip"].as_str().unwrap_or("-"),
                    );
                }
            }
            Ok(())
        }
        Commands::Info { name } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            let client = reqwest::Client::new();
            let resp = api_request(with_api_auth(
                client.get(format!("{api_url}/v1/vms/{name}")),
                api_token.as_deref(),
            ))
            .await?;

            if !resp.status().is_success() {
                let msg = api_error(resp, &format!("VM '{name}'")).await;
                exit_with_error(output, msg);
            }

            let vm: serde_json::Value = resp.json().await?;
            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "info",
                        "vm": vm,
                    }),
                    "",
                );
            } else {
                let s = |key: &str| vm[key].as_str().unwrap_or("-").to_string();
                println!("Name:      {}", s("name"));
                println!("State:     {}", s("state"));
                println!("vCPUs:     {}", vm["vcpu_count"]);
                println!("Memory:    {} MiB", vm["mem_size_mib"]);
                println!("Backend:   {}", s("vmm"));
                println!("Boot:      {}", s("boot_mode"));
                println!("Network:   {}", s("network"));
                let kernel = vm["kernel_path"].as_str().unwrap_or("");
                if !kernel.is_empty() {
                    println!("Kernel:    {kernel}");
                }
                let rootfs = vm["rootfs_path"].as_str().unwrap_or("");
                if !rootfs.is_empty() {
                    println!("Rootfs:    {rootfs}");
                }
                if let Some(ip) = vm["guest_ip"].as_str() {
                    println!("Guest IP:  {ip}");
                }
                if let Some(ip) = vm["host_ip"].as_str() {
                    println!("Host IP:   {ip}");
                }
                if let Some(status) = vm["userdata_status"].as_str() {
                    println!("Userdata:  {status}");
                }
                if let Some(vol) = vm["volume"].as_str() {
                    println!("Volume:    {vol}");
                }
                println!("ID:        {}", s("id"));
            }
            Ok(())
        }
        Commands::Stop { name } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            let client = reqwest::Client::new();
            let resp = api_request(with_api_auth(
                client.post(format!("{api_url}/v1/vms/{name}/stop")),
                api_token.as_deref(),
            ))
            .await?;

            if resp.status().is_success() {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "stop",
                        "vm": name,
                    }),
                    format!("Stopped VM: {name}"),
                );
            } else {
                let mut msg = api_error(resp, &format!("VM '{name}'")).await;
                if msg.message.contains("stopped") {
                    msg.message.push_str(" (hint: VM is already stopped)");
                }
                exit_with_error(output, msg);
            }
            Ok(())
        }
        Commands::Pause { name } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            let client = reqwest::Client::new();
            let resp = api_request(with_api_auth(
                client.post(format!("{api_url}/v1/vms/{name}/pause")),
                api_token.as_deref(),
            ))
            .await?;

            if resp.status().is_success() {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "pause",
                        "vm": name,
                    }),
                    format!("Paused VM: {name}"),
                );
            } else {
                let mut msg = api_error(resp, &format!("VM '{name}'")).await;
                if msg.message.contains("stopped") {
                    msg.message
                        .push_str(" (hint: start the VM first with `husker run`)");
                }
                exit_with_error(output, msg);
            }
            Ok(())
        }
        Commands::Resume { name } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            let client = reqwest::Client::new();
            let resp = api_request(with_api_auth(
                client.post(format!("{api_url}/v1/vms/{name}/resume")),
                api_token.as_deref(),
            ))
            .await?;

            if resp.status().is_success() {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "resume",
                        "vm": name,
                    }),
                    format!("Resumed VM: {name}"),
                );
            } else {
                let mut msg = api_error(resp, &format!("VM '{name}'")).await;
                if msg.message.contains("stopped") {
                    msg.message
                        .push_str(" (hint: start the VM first with `husker run`)");
                } else if msg.message.contains("running") {
                    msg.message
                        .push_str(" (hint: VM is already running, nothing to resume)");
                }
                exit_with_error(output, msg);
            }
            Ok(())
        }
        Commands::Suspend { name } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            preflight_capability(&api_url, api_token.as_deref(), "snapshot").await?;
            let client = reqwest::Client::new();
            let resp = api_request(with_api_auth(
                client.post(format!("{api_url}/v1/vms/{name}/suspend")),
                api_token.as_deref(),
            ))
            .await?;

            if resp.status().is_success() {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "suspend",
                        "vm": name,
                    }),
                    format!("Suspended VM: {name}"),
                );
            } else {
                let mut msg = api_error(resp, &format!("VM '{name}'")).await;
                if msg.message.contains("stopped") {
                    msg.message
                        .push_str(" (hint: VM must be running to suspend)");
                }
                exit_with_error(output, msg);
            }
            Ok(())
        }
        Commands::Fork { source, fork_name } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            preflight_capability(&api_url, api_token.as_deref(), "fork").await?;
            let client = reqwest::Client::new();
            let resp = api_request(with_api_auth(
                client
                    .post(format!("{api_url}/v1/vms/{source}/fork"))
                    .json(&serde_json::json!({ "fork_name": fork_name })),
                api_token.as_deref(),
            ))
            .await?;

            if resp.status().is_success() {
                let body: serde_json::Value = resp
                    .json()
                    .await
                    .unwrap_or_else(|_| serde_json::json!({ "name": fork_name }));
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "fork",
                        "source": source,
                        "vm": fork_name,
                        "guest_ip": body.get("guest_ip"),
                    }),
                    format!("Forked '{source}' -> '{fork_name}'"),
                );
            } else {
                let msg = api_error(resp, &format!("VM '{source}'")).await;
                exit_with_error(output, msg);
            }
            Ok(())
        }
        Commands::Destroy { name, yes } => {
            require_confirmation(&format!("Destroy VM '{name}'?"), yes, output);

            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            let client = reqwest::Client::new();
            let resp = api_request(with_api_auth(
                client.delete(format!("{api_url}/v1/vms/{name}")),
                api_token.as_deref(),
            ))
            .await?;

            if resp.status().is_success() {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "destroy",
                        "vm": name,
                    }),
                    format!("Destroyed VM: {name}"),
                );
            } else {
                let msg = api_error(resp, &format!("VM '{name}'")).await;
                exit_with_error(output, msg);
            }
            Ok(())
        }
        Commands::Balloon { name, amount_mib } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            let client = reqwest::Client::new();
            let body = serde_json::json!({ "amount_mib": amount_mib });
            let resp = api_request(
                with_api_auth(
                    client.put(format!("{api_url}/v1/vms/{name}/balloon")),
                    api_token.as_deref(),
                )
                .json(&body),
            )
            .await?;

            if resp.status().is_success() {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "balloon",
                        "vm": name,
                        "amount_mib": amount_mib,
                    }),
                    format!("Balloon set: {name} -> {amount_mib} MiB"),
                );
            } else {
                let msg = api_error(resp, &format!("VM '{name}'")).await;
                exit_with_error(output, msg);
            }
            Ok(())
        }
        Commands::Exec {
            name,
            workdir,
            env,
            env_file,
            secret,
            connect_timeout,
            timeout,
            command,
        } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            let (cmd, args) = command.split_first().context("command required after --")?;
            let env = merge_env(&env_file, env)?;
            let secret_env = build_secret_env(&secret)?;

            let mut body = serde_json::json!({
                "command": cmd,
                "args": args,
            });
            if let Some(ref wd) = workdir {
                body["working_dir"] = serde_json::json!(wd);
            }
            let env_map: serde_json::Map<String, serde_json::Value> = env
                .iter()
                .filter_map(|s| s.split_once('='))
                .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
                .collect();
            if !env_map.is_empty() {
                body["env"] = serde_json::Value::Object(env_map);
            }
            if !secret_env.is_empty() {
                body["secret_env"] = serde_json::Value::Object(secret_env);
            }
            if let Some(secs) = connect_timeout {
                body["connect_timeout_secs"] = serde_json::json!(secs);
            }
            if let Some(secs) = timeout {
                body["timeout_secs"] = serde_json::json!(secs);
            }

            let client = reqwest::Client::new();
            let resp = api_request(
                with_api_auth(
                    client.post(format!("{api_url}/v1/vms/{name}/exec")),
                    api_token.as_deref(),
                )
                .json(&body),
            )
            .await?;

            if !resp.status().is_success() {
                let msg = api_error(resp, &format!("VM '{name}'")).await;
                exit_with_error(output, msg);
            }

            let result: serde_json::Value = resp.json().await?;
            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "exec",
                        "vm": name,
                        "result": result,
                    }),
                    "",
                );
            } else {
                let stdout = result["stdout"].as_str().unwrap_or("");
                let stderr = result["stderr"].as_str().unwrap_or("");
                if !stdout.is_empty() {
                    print!("{stdout}");
                }
                if !stderr.is_empty() {
                    eprint!("{stderr}");
                }
            }
            let exit_code = result["exit_code"].as_i64().unwrap_or(1) as i32;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            Ok(())
        }
        Commands::Job {
            rootfs,
            name,
            pool,
            kernel,
            initrd,
            cpus,
            memory,
            env,
            env_file,
            secret,
            dns,
            add_host,
            vmm,
            cloud_image,
            disk_size,
            ssh_key,
            balloon,
            volume,
            mount,
            net,
            profile,
            timeout,
            keep,
            sync_cwd,
            out,
            write_back,
            command,
        } => {
            let config = load_config(config_path.as_deref());
            let api_token = cli_api_token.clone().or_else(|| config.api_token.clone());
            let name =
                name.unwrap_or_else(|| format!("job-{}", &uuid::Uuid::new_v4().to_string()[..8]));
            let env = merge_env(&env_file, env)?;
            let secret_env = build_secret_env(&secret)?;
            // Validate DNS/host overrides before booting a VM.
            validate_dns(&dns)?;
            let add_host = add_host
                .iter()
                .map(|s| parse_add_host(s))
                .collect::<anyhow::Result<Vec<_>>>()?;

            // An empty command runs the image's default entrypoint (resolved by
            // the guest agent). That is meaningless with --sync-cwd, which wraps
            // an explicit command to run in the synced tree - reject it before
            // booting a VM.
            if command.is_empty() && sync_cwd {
                exit_with_error(
                    output,
                    "--sync-cwd needs a command after `--`; the image default is \
                     only used without --sync-cwd",
                );
            }

            // With --pool the job's VM is forked from the pool's template, so there
            // is no create body and the image/boot flags do not apply (env/secret
            // still go to the exec). Otherwise build the create body (env goes to
            // the EXEC request, not the body; pass empty to the builder).
            let body = if let Some(ref pool) = pool {
                if rootfs.is_some()
                    || kernel.is_some()
                    || initrd.is_some()
                    || cpus.is_some()
                    || memory.is_some()
                    || vmm.is_some()
                    || cloud_image.is_some()
                    || disk_size.is_some()
                    || volume.is_some()
                    || net.is_some()
                    || profile.is_some()
                    || balloon
                    || !ssh_key.is_empty()
                {
                    exit_with_error(
                        output,
                        format!(
                            "--pool cannot be combined with rootfs/boot flags (pool '{pool}' \
                             defines the VM image); pass only --name and the command"
                        ),
                    );
                }
                None
            } else {
                let args = VmRequestArgs {
                    rootfs,
                    kernel,
                    initrd,
                    cpus,
                    memory,
                    vmm,
                    cloud_image,
                    disk_size,
                    ssh_key,
                    env: Vec::new(),
                    balloon,
                    volume,
                    mount,
                    network: net,
                };
                Some(build_vm_request_body(
                    &name,
                    args,
                    profile.as_deref(),
                    &config,
                    output,
                )?)
            };

            let client = reqwest::Client::new();

            // Best-effort cleanup: fire-and-forget DELETE so the VM is not left behind.
            let do_cleanup = {
                let client = client.clone();
                let api_url = api_url.clone();
                let api_token = api_token.clone();
                let name = name.clone();
                move || {
                    let client = client.clone();
                    let api_url = api_url.clone();
                    let api_token = api_token.clone();
                    let name = name.clone();
                    async move {
                        let _ = with_api_auth(
                            client.delete(format!("{api_url}/v1/vms/{name}")),
                            api_token.as_deref(),
                        )
                        .send()
                        .await;
                    }
                }
            };

            let work = async {
                // 1. Create the VM: fork it from the pool, or boot from the body.
                let resp = if let Some(ref pool) = pool {
                    api_request(
                        with_api_auth(
                            client.post(format!("{api_url}/v1/pools/{pool}/checkout")),
                            api_token.as_deref(),
                        )
                        .json(&serde_json::json!({ "vm_name": &name })),
                    )
                    .await?
                } else {
                    api_request(
                        with_api_auth(
                            client.post(format!("{api_url}/v1/vms")),
                            api_token.as_deref(),
                        )
                        .json(body.as_ref().expect("non-pool job builds a create body")),
                    )
                    .await?
                };
                if !resp.status().is_success() {
                    let msg = api_error(resp, &format!("VM '{name}'")).await;
                    exit_with_error(output, msg);
                }
                if output == OutputFormat::Text {
                    eprintln!("[job] vm {name} created, waiting for agent...");
                }

                // Old-daemon warning: if the requested timeout exceeds the historical
                // 30-second exec default, check the daemon version. Daemons older than
                // 0.4.2 ignore timeout_secs and cap execution at exec_timeout_secs.
                if timeout > 30 {
                    let health_client = reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(2))
                        .build()
                        .unwrap_or_default();
                    if let Ok(resp) = health_client
                        .get(format!("{api_url}/v1/health"))
                        .send()
                        .await
                        && resp.status().is_success()
                        && let Ok(health) = resp.json::<serde_json::Value>().await
                        && let Some(ver_str) = health["version"].as_str()
                    {
                        let parts: Vec<u64> =
                            ver_str.split('.').filter_map(|p| p.parse().ok()).collect();
                        if let [major, minor, patch] = parts.as_slice()
                            && (*major, *minor, *patch) < (0, 4, 2)
                        {
                            eprintln!(
                                "[job] warning: daemon {ver_str} does not support \
                                 --timeout; execution will be capped at the daemon's \
                                 exec_timeout_secs setting"
                            );
                        }
                    }
                }

                // 2. Boot-mode-aware readiness wait (mirrors Commands::Wait logic).
                let info_url = format!("{api_url}/v1/vms/{name}");
                let resp =
                    api_request(with_api_auth(client.get(&info_url), api_token.as_deref())).await?;
                if !resp.status().is_success() {
                    let msg = api_error(resp, &format!("VM '{name}'")).await;
                    anyhow::bail!("{}", msg.message);
                }
                let vm: serde_json::Value = resp.json().await?;
                let ready_timeout = if vm.get("boot_mode").and_then(|b| b.as_str()) == Some("uefi")
                {
                    husker_core::UEFI_READY_TIMEOUT_SECS
                } else {
                    husker_core::DEFAULT_READY_TIMEOUT_SECS
                };
                let ready_url = format!("{api_url}/v1/vms/{name}/ready");
                let deadline =
                    std::time::Instant::now() + std::time::Duration::from_secs(ready_timeout);
                let mut backoff = std::time::Duration::from_millis(200);
                loop {
                    let resp =
                        api_request(with_api_auth(client.get(&ready_url), api_token.as_deref()))
                            .await?;
                    if !resp.status().is_success() {
                        let msg = api_error(resp, &format!("VM '{name}'")).await;
                        anyhow::bail!("{}", msg.message);
                    }
                    let rdy: serde_json::Value = resp.json().await?;
                    if rdy.get("ready").and_then(|r| r.as_bool()).unwrap_or(false) {
                        break;
                    }
                    if std::time::Instant::now() + backoff >= deadline {
                        let hint =
                            serial_boot_hint(&client, &api_url, api_token.as_deref(), &name).await;
                        anyhow::bail!("timed out waiting for VM '{name}' to become ready{hint}");
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(std::time::Duration::from_secs(2));
                }

                // 2.4 Apply per-VM DNS / host overrides before running the command.
                apply_dns_hosts(
                    &client,
                    &api_url,
                    api_token.as_deref(),
                    &name,
                    &dns,
                    &add_host,
                )
                .await?;

                // 2.5 Optionally sync the working tree into the VM (git-aware, clean-room):
                // upload a tar.gz of the cwd and wrap the command to extract and run it
                // inside the guest. The host filesystem is never modified unless the
                // command's results are explicitly pulled back (--out / --write-back).
                let mut retrieve_paths: Vec<PathBuf> = Vec::new();
                let mut sync_cwd_dir: Option<PathBuf> = None;
                let (exec_command, exec_args): (String, Vec<String>) = if sync_cwd {
                    let cwd = std::env::current_dir()
                        .context("resolving current directory for --sync-cwd")?;
                    if output == OutputFormat::Text {
                        eprintln!("[job] syncing working tree from {}", cwd.display());
                    }
                    let archive = build_sync_archive(&cwd)?;
                    let encoded = husker_agent_proto::base64_encode(&archive);
                    let write_resp = api_request(
                        with_api_auth(
                            client.post(format!("{api_url}/v1/vms/{name}/files/write")),
                            api_token.as_deref(),
                        )
                        .json(&serde_json::json!({
                            "path": SYNC_ARCHIVE_GUEST_PATH,
                            "data": encoded,
                        })),
                    )
                    .await?;
                    if !write_resp.status().is_success() {
                        let msg = api_error(write_resp, &format!("VM '{name}'")).await;
                        anyhow::bail!("{}", msg.message);
                    }
                    // --write-back returns the synced files as the command left them
                    // (modifications only; new build artifacts are never pulled back).
                    if write_back {
                        retrieve_paths.extend(collect_sync_paths(&cwd)?);
                    }
                    // --out returns the named paths (files or dirs).
                    retrieve_paths.extend(out.iter().cloned());
                    retrieve_paths.sort();
                    retrieve_paths.dedup();
                    sync_cwd_dir = Some(cwd);
                    wrap_sync_command(
                        SYNC_ARCHIVE_GUEST_PATH,
                        SYNC_WORKDIR,
                        &command,
                        SYNC_OUTPUT_GUEST_PATH,
                        &retrieve_paths,
                    )
                } else if command.is_empty() {
                    // Run the image's default entrypoint + cmd: an empty command
                    // tells the guest agent to resolve it from the OCI config.
                    (String::new(), Vec::new())
                } else {
                    (command[0].clone(), command[1..].to_vec())
                };

                // 3. Run the command via exec.
                if output == OutputFormat::Text {
                    eprintln!("[job] running command");
                }
                let env_map: std::collections::HashMap<String, String> = env
                    .iter()
                    .filter_map(|s| {
                        let (k, v) = s.split_once('=')?;
                        Some((k.to_string(), v.to_string()))
                    })
                    .collect();
                let mut exec_body = serde_json::json!({
                    "command": exec_command,
                    "args": exec_args,
                    "env": env_map,
                    "timeout_secs": timeout,
                });
                if !secret_env.is_empty() {
                    exec_body["secret_env"] = serde_json::Value::Object(secret_env.clone());
                }
                let resp = api_request(
                    with_api_auth(
                        client.post(format!("{api_url}/v1/vms/{name}/exec")),
                        api_token.as_deref(),
                    )
                    .json(&exec_body),
                )
                .await?;
                if !resp.status().is_success() {
                    let msg = api_error(resp, &format!("VM '{name}'")).await;
                    anyhow::bail!("{}", msg.message);
                }
                let result: serde_json::Value = resp.json().await?;

                // 3.5 Pull requested results back to the host (--out / --write-back).
                if let Some(cwd) = &sync_cwd_dir
                    && !retrieve_paths.is_empty()
                {
                    let read_resp = api_request(
                        with_api_auth(
                            client.post(format!("{api_url}/v1/vms/{name}/files/read")),
                            api_token.as_deref(),
                        )
                        .json(&serde_json::json!({ "path": SYNC_OUTPUT_GUEST_PATH })),
                    )
                    .await?;
                    if read_resp.status().is_success() {
                        let body: serde_json::Value = read_resp.json().await?;
                        if let Some(b64) = body["data"].as_str()
                            && let Ok(bytes) = husker_agent_proto::base64_decode(b64)
                            && !bytes.is_empty()
                        {
                            let written = extract_archive_over(&bytes, cwd)?;
                            if output == OutputFormat::Text {
                                if written.is_empty() {
                                    eprintln!("[job] nothing matched --out/--write-back");
                                } else {
                                    eprintln!("[job] retrieved {} file(s) to host:", written.len());
                                    for f in &written {
                                        eprintln!("  {f}");
                                    }
                                }
                            }
                        }
                    }
                    // A missing output archive means the command produced none of the
                    // requested paths; that is not an error.
                }
                Ok::<serde_json::Value, anyhow::Error>(result)
            };

            // Ctrl-C destroys the VM (unless --keep) and exits 130.
            let result = tokio::select! {
                r = work => r,
                _ = tokio::signal::ctrl_c() => {
                    if !keep {
                        eprintln!("[job] interrupted, destroying {name}");
                        do_cleanup().await;
                    } else {
                        eprintln!("[job] interrupted, keeping {name}");
                    }
                    std::process::exit(130);
                }
            };

            match result {
                Ok(result) => {
                    let exit_code = result["exit_code"].as_i64().unwrap_or(1);
                    if output == OutputFormat::Json {
                        print_output(
                            output,
                            &serde_json::json!({
                                "status": "ok",
                                "action": "job",
                                "vm": name,
                                "exit_code": exit_code,
                                "stdout": result["stdout"],
                                "stderr": result["stderr"],
                            }),
                            "",
                        );
                    } else {
                        print!("{}", result["stdout"].as_str().unwrap_or(""));
                        eprint!("{}", result["stderr"].as_str().unwrap_or(""));
                    }
                    if keep {
                        if output == OutputFormat::Text {
                            eprintln!(
                                "[job] exit code {exit_code}, keeping {name} \
                                 (husker shell {name} / husker destroy {name})"
                            );
                        }
                    } else {
                        if output == OutputFormat::Text {
                            eprintln!("[job] exit code {exit_code}, destroying vm");
                        }
                        do_cleanup().await;
                    }
                    // Exit 127 in a synced sandbox almost always means the command
                    // isn't in the (minimal) default image. Point at the fix.
                    if sync_cwd && exit_code == 127 && output == OutputFormat::Text {
                        eprintln!(
                            "[job] hint: exit 127 usually means the command was not found in the \
                             sandbox image. The default image is minimal (no language toolchains); \
                             run against an image that includes your toolchain (pass a rootfs path \
                             or --cloud-image, e.g. a Docker image brought in with \
                             `husker image import-oci`)."
                        );
                    }
                    if exit_code != 0 {
                        std::process::exit(exit_code.clamp(1, 255) as i32);
                    }
                    Ok(())
                }
                Err(e) => {
                    if keep {
                        eprintln!("[job] failed, keeping {name}: {e}");
                    } else {
                        do_cleanup().await;
                    }
                    exit_with_error(output, e.to_string());
                }
            }
        }
        Commands::Cp { source, dest, mode } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            let src = parse_cp_path(&source);
            let dst = parse_cp_path(&dest);

            match (src, dst) {
                (CpPath::Local(local), CpPath::Vm { name, path }) => {
                    let data = std::fs::read(&local)
                        .with_context(|| format!("reading {}", local.display()))?;
                    let encoded = husker_agent_proto::base64_encode(&data);

                    let mut body = serde_json::json!({
                        "path": path,
                        "data": encoded,
                    });
                    if let Some(m) = mode {
                        body["mode"] = serde_json::json!(m);
                    }

                    let client = reqwest::Client::new();
                    let resp = api_request(
                        with_api_auth(
                            client.post(format!("{api_url}/v1/vms/{name}/files/write")),
                            api_token.as_deref(),
                        )
                        .json(&body),
                    )
                    .await?;

                    if resp.status().is_success() {
                        let result: serde_json::Value = resp.json().await?;
                        let bytes = result["bytes_written"].as_u64().unwrap_or(0);
                        print_output(
                            output,
                            &serde_json::json!({
                                "status": "ok",
                                "action": "cp",
                                "direction": "to_vm",
                                "vm": name,
                                "path": path,
                                "bytes": bytes,
                            }),
                            format!("{bytes} bytes copied to {name}:{path}"),
                        );
                    } else {
                        let msg = api_error(resp, &format!("VM '{name}'")).await;
                        exit_with_error(output, msg);
                    }
                }
                (CpPath::Vm { name, path }, CpPath::Local(local)) => {
                    let client = reqwest::Client::new();
                    let resp = api_request(
                        with_api_auth(
                            client.post(format!("{api_url}/v1/vms/{name}/files/read")),
                            api_token.as_deref(),
                        )
                        .json(&serde_json::json!({ "path": path })),
                    )
                    .await?;

                    if resp.status().is_success() {
                        let result: serde_json::Value = resp.json().await?;
                        let b64 = result["data"].as_str().unwrap_or("");
                        let data = husker_agent_proto::base64_decode(b64)
                            .map_err(|e| anyhow::anyhow!("invalid base64 from server: {e}"))?;
                        std::fs::write(&local, &data)
                            .with_context(|| format!("writing {}", local.display()))?;
                        print_output(
                            output,
                            &serde_json::json!({
                                "status": "ok",
                                "action": "cp",
                                "direction": "from_vm",
                                "vm": name,
                                "path": path,
                                "bytes": data.len(),
                                "destination": local,
                            }),
                            format!("{} bytes copied from {name}:{path}", data.len()),
                        );
                    } else {
                        let msg = api_error(resp, &format!("VM '{name}'")).await;
                        exit_with_error(output, msg);
                    }
                }
                (CpPath::Local(_), CpPath::Local(_)) => {
                    anyhow::bail!(
                        "both source and destination are local paths; prefix one with vmname:"
                    );
                }
                (CpPath::Vm { .. }, CpPath::Vm { .. }) => {
                    anyhow::bail!("VM-to-VM copy is not supported; copy to local first");
                }
            }
            Ok(())
        }
        Commands::PortForward { name, action } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            port_forward(api_url, api_token, name, action, output).await
        }
        Commands::HostGroup { action } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            host_group_command(api_url, api_token, action, output).await
        }
        Commands::Pool { action } => {
            let config = load_config(config_path.as_deref());
            let api_token = cli_api_token.clone().or_else(|| config.api_token.clone());
            pool_command(api_url, api_token, action, output, config).await
        }
        Commands::Service { action } => {
            let config = load_config(config_path.as_deref());
            let api_token = cli_api_token.clone().or_else(|| config.api_token.clone());
            service_command(api_url, api_token, action, output, config).await
        }
        Commands::Snapshot { action } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            snapshot_command(api_url, api_token, action, output).await
        }
        Commands::Image { action } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            image_command(api_url, api_token, action, output).await
        }
        Commands::Volume { action } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            volume_command(api_url, api_token, action, output).await
        }
        Commands::Secret { action } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            secret_command(api_url, api_token, action, output).await
        }
        Commands::Logs {
            name,
            follow,
            tail,
            userdata,
            source,
        } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            // Effective source: explicit --source wins; else --userdata maps to
            // "userdata"; else serial. Warn if both --source and --userdata given.
            if source.is_some() && userdata {
                eprintln!("warning: --source overrides --userdata");
            }
            let effective = source.unwrap_or_else(|| {
                if userdata {
                    "userdata".into()
                } else {
                    "serial".into()
                }
            });
            // Only the live serial console is followable.
            let follow = follow && effective == "serial";
            let mut url = format!("{api_url}/v1/vms/{name}/logs");
            let mut params = Vec::new();
            params.push(format!("source={effective}"));
            if follow {
                params.push("follow=true".to_string());
            }
            if let Some(n) = tail {
                params.push(format!("tail={n}"));
            }
            if !params.is_empty() {
                url.push('?');
                url.push_str(&params.join("&"));
            }

            let client = reqwest::Client::new();
            let resp = api_request(with_api_auth(client.get(&url), api_token.as_deref())).await?;

            if !resp.status().is_success() {
                let msg = api_error(resp, &format!("VM '{name}'")).await;
                exit_with_error(output, msg);
            }

            if follow {
                if output == OutputFormat::Json {
                    exit_with_error(
                        output,
                        "json output is not supported with --follow for streaming logs",
                    );
                }
                use tokio::io::AsyncWriteExt;
                let mut stream = resp.bytes_stream();
                let mut stdout = tokio::io::stdout();
                use futures_util::StreamExt;
                while let Some(chunk) = stream.next().await {
                    match chunk {
                        Ok(bytes) => {
                            stdout.write_all(&bytes).await?;
                            stdout.flush().await?;
                        }
                        Err(e) => {
                            exit_with_error(output, format!("error reading stream: {e}"));
                        }
                    }
                }
            } else {
                let body = resp.text().await?;
                if output == OutputFormat::Json {
                    print_output(
                        output,
                        &serde_json::json!({
                            "status": "ok",
                            "action": "logs",
                            "vm": name,
                            "follow": false,
                            "tail": tail,
                            "logs": body,
                        }),
                        "",
                    );
                } else {
                    print!("{body}");
                }
            }
            Ok(())
        }
        Commands::Wait { name, timeout } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            let client = reqwest::Client::new();
            let timeout = match timeout {
                Some(t) => t,
                None => {
                    // Boot-mode-aware default: UEFI/cloud VMs boot much slower
                    // than direct-kernel microVMs.
                    let info_url = format!("{api_url}/v1/vms/{name}");
                    let resp =
                        api_request(with_api_auth(client.get(&info_url), api_token.as_deref()))
                            .await?;
                    if !resp.status().is_success() {
                        let msg = api_error(resp, &format!("VM '{name}'")).await;
                        exit_with_error(output, msg);
                    }
                    let vm: serde_json::Value = resp.json().await?;
                    if vm.get("boot_mode").and_then(|b| b.as_str()) == Some("uefi") {
                        husker_core::UEFI_READY_TIMEOUT_SECS
                    } else {
                        husker_core::DEFAULT_READY_TIMEOUT_SECS
                    }
                }
            };
            let url = format!("{api_url}/v1/vms/{name}/ready");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout);
            let mut backoff = std::time::Duration::from_millis(200);
            loop {
                let resp =
                    api_request(with_api_auth(client.get(&url), api_token.as_deref())).await?;
                if !resp.status().is_success() {
                    let msg = api_error(resp, &format!("VM '{name}'")).await;
                    exit_with_error(output, msg);
                }
                let body: serde_json::Value = resp.json().await?;
                if body.get("ready").and_then(|r| r.as_bool()).unwrap_or(false) {
                    print_output(
                        output,
                        &serde_json::json!({"status":"ok","action":"wait","vm":name,"ready":true}),
                        format!("{name} is ready"),
                    );
                    break;
                }
                if std::time::Instant::now() + backoff >= deadline {
                    exit_with_error(
                        output,
                        format!("timed out waiting for VM '{name}' to become ready"),
                    );
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(std::time::Duration::from_secs(2));
            }
            Ok(())
        }
        Commands::Shell { name, command } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            run_shell(
                api_url,
                config_path,
                name,
                command,
                api_token.as_deref(),
                output,
            )
            .await
        }
        Commands::Version => {
            let mut daemon_info: Option<serde_json::Value> = None;

            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(2))
                .build()?;
            if let Ok(resp) = client.get(format!("{api_url}/v1/health")).send().await
                && resp.status().is_success()
                && let Ok(health) = resp.json::<serde_json::Value>().await
            {
                let version = health["version"].as_str().unwrap_or("unknown");
                let total = health["vms"]["total"].as_u64().unwrap_or(0);
                let running = health["vms"]["running"].as_u64().unwrap_or(0);
                daemon_info = Some(serde_json::json!({
                    "version": version,
                    "vms_total": total,
                    "vms_running": running,
                }));
            }

            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "version",
                        "client_version": env!("CARGO_PKG_VERSION"),
                        "daemon": daemon_info,
                    }),
                    "",
                );
            } else {
                println!("husker {}", env!("CARGO_PKG_VERSION"));
                if let Some(daemon) = daemon_info {
                    println!(
                        "daemon {} ({} VMs, {} running)",
                        daemon["version"].as_str().unwrap_or("unknown"),
                        daemon["vms_total"].as_u64().unwrap_or(0),
                        daemon["vms_running"].as_u64().unwrap_or(0)
                    );
                }
            }
            Ok(())
        }
        Commands::Config { action } => match action {
            ConfigAction::Check => {
                if output == OutputFormat::Json {
                    exit_with_error(
                        output,
                        "`husker config check` does not yet support --output json",
                    );
                }
                check_config(config_path.as_deref())
            }
        },
        Commands::Context { .. } => {
            unreachable!("Context is handled before daemon-target resolution in run()")
        }
        Commands::Schema => {
            println!(
                "{}",
                serde_json::to_string_pretty(&build_cli_schema()).expect("schema serializes")
            );
            Ok(())
        }
    }
}

/// Handle `husker context` subcommands: manage saved daemon targets in
/// `~/.config/husker/contexts.toml`. Purely local; never contacts a daemon.
fn context_command(action: ContextAction, output: OutputFormat) -> Result<()> {
    let mut contexts = load_contexts();
    match action {
        ContextAction::Add { name, url } => {
            contexts.contexts.insert(
                name.clone(),
                ContextEntry {
                    api_url: url.clone(),
                },
            );
            // First context added becomes current for convenience.
            if contexts.current.is_none() {
                contexts.current = Some(name.clone());
            }
            save_contexts(&contexts)?;
            print_output(
                output,
                &serde_json::json!({ "status": "ok", "action": "context-add", "name": name, "api_url": url }),
                format!("Added context '{name}' -> {url}"),
            );
        }
        ContextAction::List => {
            let items: Vec<serde_json::Value> = contexts
                .contexts
                .iter()
                .map(|(name, e)| {
                    serde_json::json!({
                        "name": name,
                        "api_url": e.api_url,
                        "current": contexts.current.as_deref() == Some(name.as_str()),
                    })
                })
                .collect();
            if output == OutputFormat::Json {
                print_output(output, &serde_json::json!({ "contexts": items }), "");
            } else if items.is_empty() {
                println!("No contexts. Add one: husker context add <name> <url>");
            } else {
                for (name, e) in &contexts.contexts {
                    let marker = if contexts.current.as_deref() == Some(name.as_str()) {
                        "*"
                    } else {
                        " "
                    };
                    println!("{marker} {name}\t{}", e.api_url);
                }
            }
        }
        ContextAction::Use { name } => {
            if !contexts.contexts.contains_key(&name) {
                exit_with_error(
                    output,
                    ApiFailure {
                        message: format!(
                            "unknown context '{name}' (list with `husker context list`)"
                        ),
                        code: Some("not_found".into()),
                        exit_code: exit_code::NOT_FOUND,
                        hint: None,
                    },
                );
            }
            contexts.current = Some(name.clone());
            save_contexts(&contexts)?;
            print_output(
                output,
                &serde_json::json!({ "status": "ok", "action": "context-use", "name": name }),
                format!("Switched to context '{name}'"),
            );
        }
        ContextAction::Remove { name } => {
            if contexts.contexts.remove(&name).is_none() {
                exit_with_error(
                    output,
                    ApiFailure {
                        message: format!("unknown context '{name}'"),
                        code: Some("not_found".into()),
                        exit_code: exit_code::NOT_FOUND,
                        hint: None,
                    },
                );
            }
            if contexts.current.as_deref() == Some(name.as_str()) {
                contexts.current = None;
            }
            save_contexts(&contexts)?;
            print_output(
                output,
                &serde_json::json!({ "status": "ok", "action": "context-remove", "name": name }),
                format!("Removed context '{name}'"),
            );
        }
        ContextAction::Show => match contexts.current.as_deref() {
            Some(name) => {
                let url = contexts
                    .contexts
                    .get(name)
                    .map(|e| e.api_url.as_str())
                    .unwrap_or("(missing)");
                print_output(
                    output,
                    &serde_json::json!({ "current": name, "api_url": url }),
                    format!("{name}\t{url}"),
                );
            }
            None => {
                print_output(
                    output,
                    &serde_json::json!({ "current": serde_json::Value::Null }),
                    "No current context (using http://127.0.0.1:7777)",
                );
            }
        },
    }
    Ok(())
}

fn validate_daemon_bind(listen: SocketAddr, allow_remote: bool) -> Result<()> {
    if !listen.ip().is_loopback() && !allow_remote {
        anyhow::bail!(
            "refusing to bind daemon to non-loopback address {listen} without \
             --allow-remote"
        );
    }
    Ok(())
}

async fn port_forward(
    api_url: String,
    api_token: Option<String>,
    name: String,
    action: PortForwardAction,
    output: OutputFormat,
) -> Result<()> {
    let client = reqwest::Client::new();
    match action {
        PortForwardAction::Add {
            host_port,
            guest_port,
            bind,
        } => {
            let mut payload = serde_json::json!({
                "host_port": host_port,
                "guest_port": guest_port,
            });
            if let Some(bind) = &bind {
                payload["bind_addr"] = serde_json::json!(bind);
            }
            let resp = api_request(
                with_api_auth(
                    client.post(format!("{api_url}/v1/vms/{name}/ports")),
                    api_token.as_deref(),
                )
                .json(&payload),
            )
            .await?;
            if resp.status().is_success() {
                // Read the effective values from the response: the bound host
                // port (the daemon may pick one when 0 is requested) and the
                // effective bind address.
                let pf: serde_json::Value =
                    resp.json().await.unwrap_or_else(|_| serde_json::json!({}));
                let bound = pf
                    .get("host_port")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(host_port as u64);
                let bind = pf.get("bind_addr").and_then(|v| v.as_str());
                let target = match bind {
                    Some(b) => format!("{b}:{bound}"),
                    None => bound.to_string(),
                };
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "port-forward-add",
                        "vm": name,
                        "host_port": bound,
                        "guest_port": guest_port,
                        "bind_addr": bind,
                    }),
                    format!("Port forward added: {target} -> {name}:{guest_port}"),
                );
            } else {
                let msg = api_error(resp, &format!("VM '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        PortForwardAction::Remove { host_port } => {
            let resp = api_request(with_api_auth(
                client.delete(format!("{api_url}/v1/vms/{name}/ports/{host_port}")),
                api_token.as_deref(),
            ))
            .await?;
            if resp.status().is_success() {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "port-forward-remove",
                        "vm": name,
                        "host_port": host_port,
                    }),
                    format!("Port forward removed: {host_port}"),
                );
            } else {
                let msg = api_error(resp, &format!("port forward {host_port}")).await;
                exit_with_error(output, msg);
            }
        }
        PortForwardAction::List => {
            let resp = api_request(with_api_auth(
                client.get(format!("{api_url}/v1/vms/{name}/ports")),
                api_token.as_deref(),
            ))
            .await?;
            if !resp.status().is_success() {
                let msg = api_error(resp, &format!("VM '{name}'")).await;
                exit_with_error(output, msg);
            }

            let forwards: Vec<serde_json::Value> = resp.json().await?;
            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "port-forward-list",
                        "vm": name,
                        "forwards": forwards,
                    }),
                    "",
                );
            } else if forwards.is_empty() {
                println!("No port forwards for {name}");
            } else {
                println!(
                    "{:<12} {:<12} {:<10} {:<16}",
                    "HOST PORT", "GUEST PORT", "PROTOCOL", "BIND"
                );
                for pf in &forwards {
                    println!(
                        "{:<12} {:<12} {:<10} {:<16}",
                        pf["host_port"],
                        pf["guest_port"],
                        pf["protocol"].as_str().unwrap_or("tcp"),
                        pf["bind_addr"].as_str().unwrap_or("-"),
                    );
                }
            }
        }
    }
    Ok(())
}

async fn host_group_command(
    api_url: String,
    api_token: Option<String>,
    action: HostGroupAction,
    output: OutputFormat,
) -> Result<()> {
    let client = reqwest::Client::new();
    match action {
        HostGroupAction::Create { name, description } => {
            let mut body = serde_json::json!({
                "name": &name,
            });
            if let Some(desc) = description.as_deref() {
                body["description"] = serde_json::json!(desc);
            }

            let resp = api_request(
                with_api_auth(
                    client.post(format!("{api_url}/v1/host-groups")),
                    api_token.as_deref(),
                )
                .json(&body),
            )
            .await?;

            if resp.status().is_success() {
                let group: serde_json::Value = resp.json().await?;
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "host-group-create",
                        "host_group": group,
                    }),
                    format!(
                        "Created host group: {}",
                        group["name"].as_str().unwrap_or("-")
                    ),
                );
            } else {
                let msg = api_error(resp, &format!("host group '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        HostGroupAction::List => {
            let resp = api_request(with_api_auth(
                client.get(format!("{api_url}/v1/host-groups")),
                api_token.as_deref(),
            ))
            .await?;

            if !resp.status().is_success() {
                let msg = api_error(resp, "listing host groups").await;
                exit_with_error(output, msg);
            }

            let groups: Vec<serde_json::Value> = resp.json().await?;
            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "host-group-list",
                        "host_groups": groups,
                    }),
                    "",
                );
            } else if groups.is_empty() {
                println!("No host groups found");
            } else {
                println!("{:<24} DESCRIPTION", "NAME");
                for group in &groups {
                    println!(
                        "{:<24} {}",
                        group["name"].as_str().unwrap_or("-"),
                        group["description"].as_str().unwrap_or("-"),
                    );
                }
            }
        }
        HostGroupAction::Get { name } => {
            let resp = api_request(with_api_auth(
                client.get(format!("{api_url}/v1/host-groups/{name}")),
                api_token.as_deref(),
            ))
            .await?;

            if !resp.status().is_success() {
                let msg = api_error(resp, &format!("host group '{name}'")).await;
                exit_with_error(output, msg);
            }

            let group: serde_json::Value = resp.json().await?;
            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "host-group-get",
                        "host_group": group,
                    }),
                    "",
                );
            } else {
                let s = |key: &str| group[key].as_str().unwrap_or("-");
                println!("Name:         {}", s("name"));
                println!(
                    "Description:  {}",
                    group["description"].as_str().unwrap_or("-")
                );
                println!("ID:           {}", s("id"));
                println!("Created:      {}", s("created_at"));
                println!("Updated:      {}", s("updated_at"));
            }
        }
        HostGroupAction::Delete { name } => {
            let resp = api_request(with_api_auth(
                client.delete(format!("{api_url}/v1/host-groups/{name}")),
                api_token.as_deref(),
            ))
            .await?;

            if resp.status().is_success() {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "host-group-delete",
                        "host_group": &name,
                    }),
                    format!("Deleted host group: {name}"),
                );
            } else {
                let msg = api_error(resp, &format!("host group '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
    }
    Ok(())
}

async fn pool_command(
    api_url: String,
    api_token: Option<String>,
    action: PoolAction,
    output: OutputFormat,
    config: Config,
) -> Result<()> {
    let client = reqwest::Client::new();
    match action {
        PoolAction::Create {
            name,
            rootfs,
            kernel,
            initrd,
            vcpus,
            memory,
        } => {
            let mut body = serde_json::json!({ "name": &name });
            if let Some(path) = rootfs {
                body["rootfs_path"] =
                    serde_json::json!(husker::resolve_rootfs_arg(path, &config.data_dir));
            }
            if let Some(k) = kernel {
                body["kernel_path"] = serde_json::json!(k);
            }
            if let Some(i) = initrd {
                body["initrd_path"] = serde_json::json!(i);
            }
            if let Some(n) = vcpus {
                body["vcpu_count"] = serde_json::json!(n);
            }
            if let Some(m) = memory {
                body["mem_size_mib"] = serde_json::json!(m);
            }
            let resp = api_request(
                with_api_auth(
                    client.post(format!("{api_url}/v1/pools")),
                    api_token.as_deref(),
                )
                .json(&body),
            )
            .await?;
            if resp.status().is_success() {
                let pool: serde_json::Value = resp.json().await?;
                if output == OutputFormat::Text {
                    println!("Created pool {}", pool["name"].as_str().unwrap_or("-"));
                } else {
                    print_output(
                        output,
                        &serde_json::json!({"status":"ok","action":"pool-create","pool":pool}),
                        "",
                    );
                }
            } else {
                let msg = api_error(resp, &format!("pool '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        PoolAction::List => {
            let resp = api_request(with_api_auth(
                client.get(format!("{api_url}/v1/pools")),
                api_token.as_deref(),
            ))
            .await?;
            if !resp.status().is_success() {
                let msg = api_error(resp, "listing pools").await;
                exit_with_error(output, msg);
            }
            let pools: Vec<serde_json::Value> = resp.json().await?;
            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({"status":"ok","action":"pool-list","pools":pools}),
                    "",
                );
            } else if pools.is_empty() {
                println!("No pools found");
            } else {
                println!("{:<20} {:<44} {:>8}", "NAME", "ROOTFS", "MEMORY");
                for p in &pools {
                    let mem = p["mem_size_mib"]
                        .as_u64()
                        .map(|m| format!("{m}M"))
                        .unwrap_or_else(|| "-".to_string());
                    println!(
                        "{:<20} {:<44} {:>8}",
                        p["name"].as_str().unwrap_or("-"),
                        p["rootfs_path"].as_str().unwrap_or("-"),
                        mem,
                    );
                }
            }
        }
        PoolAction::Get { name } => {
            let resp = api_request(with_api_auth(
                client.get(format!("{api_url}/v1/pools/{name}")),
                api_token.as_deref(),
            ))
            .await?;
            if !resp.status().is_success() {
                let msg = api_error(resp, &format!("pool '{name}'")).await;
                exit_with_error(output, msg);
            }
            let pool: serde_json::Value = resp.json().await?;
            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({"status":"ok","action":"pool-get","pool":pool}),
                    "",
                );
            } else {
                let s = |key: &str| pool[key].as_str().unwrap_or("-").to_string();
                println!("Name:     {}", s("name"));
                println!("Rootfs:   {}", s("rootfs_path"));
                println!("Kernel:   {}", s("kernel_path"));
                println!("Template: {}", s("template_vm_id"));
                if let Some(m) = pool["mem_size_mib"].as_u64() {
                    println!("Memory:   {m}M");
                }
                if let Some(c) = pool["vcpu_count"].as_u64() {
                    println!("vCPUs:    {c}");
                }
            }
        }
        PoolAction::Checkout { name, vm_name } => {
            let body = serde_json::json!({ "vm_name": vm_name });
            let resp = api_request(
                with_api_auth(
                    client.post(format!("{api_url}/v1/pools/{name}/checkout")),
                    api_token.as_deref(),
                )
                .json(&body),
            )
            .await?;
            if resp.status().is_success() {
                let vm: serde_json::Value = resp.json().await?;
                if output == OutputFormat::Text {
                    println!(
                        "Checked out {} from pool {} ({})",
                        vm["name"].as_str().unwrap_or("-"),
                        name,
                        vm["guest_ip"].as_str().unwrap_or("-"),
                    );
                } else {
                    print_output(
                        output,
                        &serde_json::json!({"status":"ok","action":"pool-checkout","vm":vm}),
                        "",
                    );
                }
            } else {
                let msg = api_error(resp, &format!("pool '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        PoolAction::Delete { name } => {
            let resp = api_request(with_api_auth(
                client.delete(format!("{api_url}/v1/pools/{name}")),
                api_token.as_deref(),
            ))
            .await?;
            if resp.status().is_success() {
                if output == OutputFormat::Text {
                    println!("Deleted pool {name}");
                } else {
                    print_output(
                        output,
                        &serde_json::json!({"status":"ok","action":"pool-delete","name":name}),
                        "",
                    );
                }
            } else {
                let msg = api_error(resp, &format!("pool '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
    }
    Ok(())
}

async fn service_command(
    api_url: String,
    api_token: Option<String>,
    action: ServiceAction,
    output: OutputFormat,
    config: Config,
) -> Result<()> {
    let client = reqwest::Client::new();
    match action {
        ServiceAction::Create {
            name,
            host_group,
            desired_instances,
            image,
            rootfs,
            kernel,
            initrd,
            vcpus,
            memory,
            userdata,
            env,
            cloud_image,
            disk_size,
            balloon,
            volume,
        } => {
            // Rootfs/kernel resolution:
            //   When --cloud-image is given, rootfs and kernel are omitted from
            //   the request body (the core validates/boots via UEFI).
            //   Otherwise, the existing default-resolution path applies.
            let (rootfs_val, kernel_val) = if cloud_image.is_some() {
                // cloud-image path: kernel and rootfs are not required
                (None, None)
            } else {
                // Only include rootfs/kernel when the user explicitly provided them.
                // Rootfs resolution precedence:
                //   1. --rootfs given: resolve through catalog (same as `husker run`)
                //   2. --image given: treat the value as a rootfs reference (path or
                //      bare image name) and resolve through the same catalog lookup
                //   3. neither: omit; the daemon fills from its own configured default
                let explicit_rootfs = match rootfs {
                    Some(path) => Some(husker::resolve_rootfs_arg(path, &config.data_dir)),
                    None => image.as_ref().map(|img| {
                        husker::resolve_rootfs_arg(PathBuf::from(img), &config.data_dir)
                    }),
                };
                // kernel: use explicit if given, otherwise omit (daemon resolves)
                let explicit_kernel = kernel;
                (explicit_rootfs, explicit_kernel)
            };

            let env_pairs: Vec<(String, String)> = env
                .iter()
                .filter_map(|s| {
                    let (k, v) = s.split_once('=')?;
                    Some((k.to_string(), v.to_string()))
                })
                .collect();

            let mut body = serde_json::json!({
                "name": &name,
                "desired_instances": desired_instances,
                "env": env_pairs,
            });
            if let Some(ref rootfs) = rootfs_val {
                body["rootfs_path"] = serde_json::json!(rootfs);
            }
            if let Some(ref kernel) = kernel_val {
                body["kernel_path"] = serde_json::json!(kernel);
            }
            if let Some(group) = host_group.as_deref() {
                body["host_group"] = serde_json::json!(group);
            }
            if let Some(image_ref) = image.as_deref() {
                body["image"] = serde_json::json!(image_ref);
            }
            if let Some(ref initrd_path) = initrd {
                body["initrd_path"] = serde_json::json!(initrd_path);
            }
            // Initrd default is resolved by the daemon from its own config; omit here.
            if let Some(n) = vcpus {
                body["vcpu_count"] = serde_json::json!(n);
            }
            if let Some(m) = memory {
                body["mem_size_mib"] = serde_json::json!(m);
            }
            if let Some(ref userdata_path) = userdata {
                let script = std::fs::read_to_string(userdata_path).with_context(|| {
                    format!("reading userdata script {}", userdata_path.display())
                })?;
                body["userdata"] = serde_json::json!(script);
            }
            if let Some(ref ci) = cloud_image {
                body["cloud_image"] = serde_json::json!(ci);
                if let Some(ref size) = disk_size {
                    let bytes = husker::parse_disk_size(size)
                        .map_err(|e| anyhow::anyhow!("--disk-size: {e}"))?;
                    body["disk_size"] = serde_json::json!(bytes);
                }
            } else if disk_size.is_some() {
                exit_with_error(output, "--disk-size requires --cloud-image".to_string());
            }
            if balloon {
                body["balloon"] = serde_json::json!(true);
            }
            if let Some(ref vol) = volume {
                body["volume"] = serde_json::json!(vol);
            }

            let resp = api_request(
                with_api_auth(
                    client.post(format!("{api_url}/v1/services")),
                    api_token.as_deref(),
                )
                .json(&body),
            )
            .await?;

            if resp.status().is_success() {
                let body: serde_json::Value = resp.json().await?;
                let svc = &body["service"];
                if output == OutputFormat::Text {
                    println!(
                        "Created service {} ({}/{})",
                        svc["name"].as_str().unwrap_or("-"),
                        svc["current_instances"],
                        svc["desired_instances"]
                    );
                    if let Some(created) = body["outcome"]["created"].as_array()
                        && !created.is_empty()
                    {
                        let names: Vec<&str> = created.iter().filter_map(|v| v.as_str()).collect();
                        println!("  created: {}", names.join(", "));
                    }
                    if let Some(failed) = body["outcome"]["failed"].as_array()
                        && !failed.is_empty()
                    {
                        for f in failed {
                            eprintln!(
                                "  failed {}: {}",
                                f["instance"].as_str().unwrap_or("?"),
                                f["error"].as_str().unwrap_or("unknown error")
                            );
                        }
                    }
                } else {
                    print_output(
                        output,
                        &serde_json::json!({
                            "status": "ok",
                            "action": "service-create",
                            "service": svc,
                            "outcome": body["outcome"],
                        }),
                        "",
                    );
                }
            } else {
                let msg = api_error(resp, &format!("service '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        ServiceAction::List => {
            let resp = api_request(with_api_auth(
                client.get(format!("{api_url}/v1/services")),
                api_token.as_deref(),
            ))
            .await?;

            if !resp.status().is_success() {
                let msg = api_error(resp, "listing services").await;
                exit_with_error(output, msg);
            }

            let services: Vec<serde_json::Value> = resp.json().await?;
            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "service-list",
                        "services": services,
                    }),
                    "",
                );
            } else if services.is_empty() {
                println!("No services found");
            } else {
                println!(
                    "{:<20} {:>14}   {:<30} {:<36}",
                    "NAME", "RUNNING/DESIRED", "IMAGE", "HOST GROUP ID"
                );
                for service in &services {
                    let current = service["current_instances"]
                        .as_u64()
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "-".to_string());
                    let desired = service["desired_instances"]
                        .as_u64()
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "-".to_string());
                    println!(
                        "{:<20} {:>14}   {:<30} {:<36}",
                        service["name"].as_str().unwrap_or("-"),
                        format!("{current}/{desired}"),
                        service["image"].as_str().unwrap_or("-"),
                        service["host_group_id"].as_str().unwrap_or("-"),
                    );
                }
            }
        }
        ServiceAction::Get { name } => {
            let resp = api_request(with_api_auth(
                client.get(format!("{api_url}/v1/services/{name}")),
                api_token.as_deref(),
            ))
            .await?;

            if !resp.status().is_success() {
                let msg = api_error(resp, &format!("service '{name}'")).await;
                exit_with_error(output, msg);
            }

            let service: serde_json::Value = resp.json().await?;
            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "service-get",
                        "service": service,
                    }),
                    "",
                );
            } else {
                let s = |key: &str| service[key].as_str().unwrap_or("-");
                println!("Name:              {}", s("name"));
                println!("Desired instances: {}", service["desired_instances"]);
                println!("Current instances: {}", service["current_instances"]);
                println!(
                    "Image:             {}",
                    service["image"].as_str().unwrap_or("-")
                );
                if let Some(ci) = service["cloud_image"].as_str() {
                    println!("Cloud image:       {ci}");
                }
                if let Some(ds) = service["disk_size"].as_u64() {
                    println!("Disk size:         {ds}");
                }
                if service["balloon"].as_bool().unwrap_or(false) {
                    println!("Balloon:           true");
                }
                if let Some(vol) = service["volume"].as_str() {
                    println!("Volume:            {vol}");
                }
                println!(
                    "Host group ID:     {}",
                    service["host_group_id"].as_str().unwrap_or("-")
                );
                println!("ID:                {}", s("id"));
                println!("Created:           {}", s("created_at"));
                println!("Updated:           {}", s("updated_at"));
                if let Some(instances) = service["instances"].as_array()
                    && !instances.is_empty()
                {
                    println!("Instances:");
                    println!("  {:<24} {:>7}  STATE", "NAME", "ORDINAL");
                    for inst in instances {
                        println!(
                            "  {:<24} {:>7}  {}",
                            inst["name"].as_str().unwrap_or("-"),
                            inst["ordinal"],
                            inst["state"].as_str().unwrap_or("-"),
                        );
                    }
                }
            }
        }
        ServiceAction::Scale {
            name,
            desired_instances,
        } => {
            let resp = api_request(
                with_api_auth(
                    client.post(format!("{api_url}/v1/services/{name}/scale")),
                    api_token.as_deref(),
                )
                .json(&serde_json::json!({
                    "desired_instances": desired_instances,
                })),
            )
            .await?;

            if resp.status().is_success() {
                let body: serde_json::Value = resp.json().await?;
                let svc = &body["service"];
                if output == OutputFormat::Text {
                    println!(
                        "Scaled service {} to {} (current {})",
                        svc["name"].as_str().unwrap_or("-"),
                        svc["desired_instances"],
                        svc["current_instances"]
                    );
                    let created_count = body["outcome"]["created"]
                        .as_array()
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let destroyed_count = body["outcome"]["destroyed"]
                        .as_array()
                        .map(|a| a.len())
                        .unwrap_or(0);
                    if created_count > 0 || destroyed_count > 0 {
                        println!("  +{created_count} created, -{destroyed_count} destroyed");
                    }
                    if let Some(failed) = body["outcome"]["failed"].as_array()
                        && !failed.is_empty()
                    {
                        for f in failed {
                            eprintln!(
                                "  failed {}: {}",
                                f["instance"].as_str().unwrap_or("?"),
                                f["error"].as_str().unwrap_or("unknown error")
                            );
                        }
                    }
                } else {
                    print_output(
                        output,
                        &serde_json::json!({
                            "status": "ok",
                            "action": "service-scale",
                            "service": svc,
                            "outcome": body["outcome"],
                        }),
                        "",
                    );
                }
            } else {
                let msg = api_error(resp, &format!("service '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        ServiceAction::Delete { name } => {
            let resp = api_request(with_api_auth(
                client.delete(format!("{api_url}/v1/services/{name}")),
                api_token.as_deref(),
            ))
            .await?;

            if resp.status().is_success() {
                let body: serde_json::Value = resp.json().await?;
                if output == OutputFormat::Text {
                    println!("Deleted service {name}");
                    if let Some(destroyed) = body["outcome"]["destroyed"].as_array()
                        && !destroyed.is_empty()
                    {
                        let names: Vec<&str> =
                            destroyed.iter().filter_map(|v| v.as_str()).collect();
                        println!("  destroyed: {}", names.join(", "));
                    }
                } else {
                    print_output(
                        output,
                        &serde_json::json!({
                            "status": "ok",
                            "action": "service-delete",
                            "name": &name,
                            "outcome": body["outcome"],
                        }),
                        "",
                    );
                }
            } else {
                let msg = api_error(resp, &format!("service '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
    }
    Ok(())
}

async fn snapshot_command(
    api_url: String,
    api_token: Option<String>,
    action: SnapshotAction,
    output: OutputFormat,
) -> Result<()> {
    let client = reqwest::Client::new();
    match action {
        SnapshotAction::Create { name, vm } => {
            let resp = api_request(
                with_api_auth(
                    client.post(format!("{api_url}/v1/snapshots")),
                    api_token.as_deref(),
                )
                .json(&serde_json::json!({
                    "name": &name,
                    "vm": &vm,
                })),
            )
            .await?;

            if resp.status().is_success() {
                let snapshot: serde_json::Value = resp.json().await?;
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "snapshot-create",
                        "snapshot": snapshot,
                    }),
                    format!(
                        "Created snapshot {} from VM {}",
                        snapshot["name"].as_str().unwrap_or("-"),
                        snapshot["source_vm_name"].as_str().unwrap_or("-")
                    ),
                );
            } else {
                let msg = api_error(resp, &format!("snapshot '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        SnapshotAction::List => {
            let resp = api_request(with_api_auth(
                client.get(format!("{api_url}/v1/snapshots")),
                api_token.as_deref(),
            ))
            .await?;

            if !resp.status().is_success() {
                let msg = api_error(resp, "listing snapshots").await;
                exit_with_error(output, msg);
            }

            let snapshots: Vec<serde_json::Value> = resp.json().await?;
            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "snapshot-list",
                        "snapshots": snapshots,
                    }),
                    "",
                );
            } else if snapshots.is_empty() {
                println!("No snapshots found");
            } else {
                println!("{:<20} {:<20} FILE", "NAME", "SOURCE VM");
                for snapshot in &snapshots {
                    println!(
                        "{:<20} {:<20} {}",
                        snapshot["name"].as_str().unwrap_or("-"),
                        snapshot["source_vm_name"].as_str().unwrap_or("-"),
                        snapshot["file_path"].as_str().unwrap_or("-"),
                    );
                }
            }
        }
        SnapshotAction::Get { name } => {
            let resp = api_request(with_api_auth(
                client.get(format!("{api_url}/v1/snapshots/{name}")),
                api_token.as_deref(),
            ))
            .await?;

            if !resp.status().is_success() {
                let msg = api_error(resp, &format!("snapshot '{name}'")).await;
                exit_with_error(output, msg);
            }

            let snapshot: serde_json::Value = resp.json().await?;
            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "snapshot-get",
                        "snapshot": snapshot,
                    }),
                    "",
                );
            } else {
                println!("Name:       {}", snapshot["name"].as_str().unwrap_or("-"));
                println!(
                    "Source VM:  {}",
                    snapshot["source_vm_name"].as_str().unwrap_or("-")
                );
                println!(
                    "File:       {}",
                    snapshot["file_path"].as_str().unwrap_or("-")
                );
                println!(
                    "Created:    {}",
                    snapshot["created_at"].as_str().unwrap_or("-")
                );
            }
        }
        SnapshotAction::Restore {
            snapshot,
            name,
            kernel,
            initrd,
            cpus,
            memory,
        } => {
            let mut body = serde_json::json!({
                "name": &name,
                "kernel_path": &kernel,
                "vcpu_count": cpus,
                "mem_size_mib": memory,
            });
            if let Some(initrd_path) = initrd.as_ref() {
                body["initrd_path"] = serde_json::json!(initrd_path);
            }

            let resp = api_request(
                with_api_auth(
                    client.post(format!("{api_url}/v1/snapshots/{snapshot}/restore")),
                    api_token.as_deref(),
                )
                .json(&body),
            )
            .await?;

            if resp.status().is_success() {
                let vm: serde_json::Value = resp.json().await?;
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "snapshot-restore",
                        "snapshot": snapshot,
                        "vm": vm,
                    }),
                    format!(
                        "Restored snapshot {} into VM {}",
                        snapshot,
                        vm["name"].as_str().unwrap_or("-")
                    ),
                );
            } else {
                let msg = api_error(resp, &format!("snapshot '{snapshot}'")).await;
                exit_with_error(output, msg);
            }
        }
        SnapshotAction::Delete { name } => {
            let resp = api_request(with_api_auth(
                client.delete(format!("{api_url}/v1/snapshots/{name}")),
                api_token.as_deref(),
            ))
            .await?;

            if resp.status().is_success() {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "snapshot-delete",
                        "snapshot": &name,
                    }),
                    format!("Deleted snapshot: {name}"),
                );
            } else {
                let msg = api_error(resp, &format!("snapshot '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
    }
    Ok(())
}

async fn image_command(
    api_url: String,
    api_token: Option<String>,
    action: ImageAction,
    output: OutputFormat,
) -> Result<()> {
    let client = reqwest::Client::new();
    match action {
        ImageAction::Import {
            name,
            source,
            format,
            kind,
        } => {
            let mut body = serde_json::json!({
                "name": &name,
                "source_path": &source,
            });
            if let Some(image_format) = format.as_deref() {
                body["format"] = serde_json::json!(image_format);
            }
            if let Some(image_kind) = kind.as_deref() {
                body["kind"] = serde_json::json!(image_kind);
            }

            let resp = api_request(
                with_api_auth(
                    client.post(format!("{api_url}/v1/images")),
                    api_token.as_deref(),
                )
                .json(&body),
            )
            .await?;

            if resp.status().is_success() {
                let image: serde_json::Value = resp.json().await?;
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "image-import",
                        "image": image,
                    }),
                    format!("Imported image: {}", image["name"].as_str().unwrap_or("-")),
                );
            } else {
                let msg = api_error(resp, &format!("image '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        ImageAction::ImportOci { reference, name } => {
            preflight_capability(&api_url, api_token.as_deref(), "oci_import").await?;
            let name = name.unwrap_or_else(|| oci_default_image_name(&reference));
            let resp = api_request(
                with_api_auth(
                    client.post(format!("{api_url}/v1/images/import-oci")),
                    api_token.as_deref(),
                )
                .json(&serde_json::json!({ "name": &name, "reference": &reference })),
            )
            .await?;

            if resp.status().is_success() {
                let image: serde_json::Value = resp.json().await?;
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "image-import-oci",
                        "image": image,
                    }),
                    format!(
                        "Imported OCI image '{reference}' as '{}'",
                        image["name"].as_str().unwrap_or(&name)
                    ),
                );
            } else {
                let msg = api_error(resp, &format!("image '{reference}'")).await;
                exit_with_error(output, msg);
            }
        }
        ImageAction::List => {
            let resp = api_request(with_api_auth(
                client.get(format!("{api_url}/v1/images")),
                api_token.as_deref(),
            ))
            .await?;

            if !resp.status().is_success() {
                let msg = api_error(resp, "listing images").await;
                exit_with_error(output, msg);
            }

            let images: Vec<serde_json::Value> = resp.json().await?;
            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "image-list",
                        "images": images,
                    }),
                    "",
                );
            } else if images.is_empty() {
                println!("No images found");
            } else {
                println!(
                    "{:<20} {:<12} {:<8} {:>10}   FILE",
                    "NAME", "KIND", "FORMAT", "SIZE"
                );
                for image in &images {
                    println!(
                        "{:<20} {:<12} {:<8} {:>10}   {}",
                        image["name"].as_str().unwrap_or("-"),
                        image["kind"].as_str().unwrap_or("rootfs"),
                        image["format"].as_str().unwrap_or("-"),
                        image["size_bytes"].as_u64().unwrap_or(0),
                        image["file_path"].as_str().unwrap_or("-"),
                    );
                }
            }
        }
        ImageAction::Get { name } => {
            let resp = api_request(with_api_auth(
                client.get(format!("{api_url}/v1/images/{name}")),
                api_token.as_deref(),
            ))
            .await?;

            if !resp.status().is_success() {
                let msg = api_error(resp, &format!("image '{name}'")).await;
                exit_with_error(output, msg);
            }

            let image: serde_json::Value = resp.json().await?;
            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "image-get",
                        "image": image,
                    }),
                    "",
                );
            } else {
                let s = |key: &str| image[key].as_str().unwrap_or("-");
                println!("Name:        {}", s("name"));
                println!(
                    "Kind:        {}",
                    image["kind"].as_str().unwrap_or("rootfs")
                );
                println!("Format:      {}", s("format"));
                println!("Size bytes:  {}", image["size_bytes"].as_u64().unwrap_or(0));
                println!("Source path: {}", s("source_path"));
                println!("File path:   {}", s("file_path"));
                println!("Created:     {}", s("created_at"));
            }
        }
        ImageAction::Export { name, destination } => {
            let resp = api_request(
                with_api_auth(
                    client.post(format!("{api_url}/v1/images/{name}/export")),
                    api_token.as_deref(),
                )
                .json(&serde_json::json!({
                    "destination_path": &destination,
                })),
            )
            .await?;

            if resp.status().is_success() {
                let exported: serde_json::Value = resp.json().await?;
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "image-export",
                        "image": name,
                        "export": exported,
                    }),
                    format!(
                        "Exported image {} to {}",
                        name,
                        exported["destination_path"].as_str().unwrap_or("-")
                    ),
                );
            } else {
                let msg = api_error(resp, &format!("image '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        ImageAction::Delete { name, yes } => {
            require_confirmation(&format!("Delete image '{name}'?"), yes, output);
            let resp = api_request(with_api_auth(
                client.delete(format!("{api_url}/v1/images/{name}")),
                api_token.as_deref(),
            ))
            .await?;

            if resp.status().is_success() {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "image-delete",
                        "image": &name,
                    }),
                    format!("Deleted image: {name}"),
                );
            } else {
                let msg = api_error(resp, &format!("image '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        ImageAction::Pull { from, force } => {
            let config = load_config(None);
            let configured = from.unwrap_or(config.images_base_url.clone());
            let base_url = husker::images::resolve_download_base(&configured)
                .await
                .context("resolving images release URL")?;
            if base_url != configured {
                println!("Resolved {configured} -> {base_url}");
            }
            let manifest = husker::images::fetch_manifest(&base_url)
                .await
                .context("fetching SHA256SUMS manifest")?;

            let arch = std::env::consts::ARCH;
            let kernel_asset = format!("kernel-{arch}");
            let rootfs_asset = format!("rootfs-{arch}.ext4");
            let initrd_asset = format!("initramfs-{arch}.gz");

            let mut targets: Vec<(String, PathBuf)> = vec![
                (kernel_asset, config.default_kernel.clone()),
                (rootfs_asset, husker::default_rootfs_path()),
            ];
            if let Some(initrd_dest) = config.default_initrd.clone() {
                targets.push((initrd_asset, initrd_dest));
            }

            for (asset, dest) in targets {
                let sha = manifest.get(&asset).ok_or_else(|| {
                    anyhow::anyhow!("{asset} missing from manifest at {base_url}")
                })?;
                if dest.exists() && !force {
                    println!(
                        "Skipping {} (exists; pass --force to overwrite)",
                        dest.display()
                    );
                    continue;
                }
                let url = format!("{}/{}", base_url.trim_end_matches('/'), asset);
                println!("Downloading {url} -> {}", dest.display());
                husker::images::fetch_and_verify(husker::images::DownloadSpec {
                    url,
                    expected_sha256: sha.clone(),
                    dest: dest.clone(),
                })
                .await?;
                println!("Verified {}", dest.display());
            }

            print_output(
                output,
                &serde_json::json!({
                    "status": "ok",
                    "action": "image-pull",
                    "kernel": config.default_kernel,
                    "rootfs": husker::default_rootfs_path(),
                    "initrd": config.default_initrd,
                }),
                "Images pulled.",
            );
        }
    }
    Ok(())
}

async fn volume_command(
    api_url: String,
    api_token: Option<String>,
    action: VolumeAction,
    output: OutputFormat,
) -> Result<()> {
    let client = reqwest::Client::new();
    match action {
        VolumeAction::Create { name, size } => {
            let size_bytes =
                husker::parse_disk_size(&size).map_err(|e| anyhow::anyhow!("--size: {e}"))?;
            let body = serde_json::json!({
                "name": &name,
                "size_bytes": size_bytes,
            });

            let resp = api_request(
                with_api_auth(
                    client.post(format!("{api_url}/v1/volumes")),
                    api_token.as_deref(),
                )
                .json(&body),
            )
            .await?;

            if resp.status().is_success() {
                let volume: serde_json::Value = resp.json().await?;
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "volume-create",
                        "volume": volume,
                    }),
                    format!("Created volume: {}", volume["name"].as_str().unwrap_or("-")),
                );
            } else {
                let msg = api_error(resp, &format!("volume '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        VolumeAction::List => {
            let resp = api_request(with_api_auth(
                client.get(format!("{api_url}/v1/volumes")),
                api_token.as_deref(),
            ))
            .await?;

            if !resp.status().is_success() {
                let msg = api_error(resp, "listing volumes").await;
                exit_with_error(output, msg);
            }

            let volumes: Vec<serde_json::Value> = resp.json().await?;
            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "volume-list",
                        "volumes": volumes,
                    }),
                    "",
                );
            } else if volumes.is_empty() {
                println!("No volumes found");
            } else {
                println!("{:<20} {:>12}   FILE", "NAME", "SIZE");
                for vol in &volumes {
                    println!(
                        "{:<20} {:>12}   {}",
                        vol["name"].as_str().unwrap_or("-"),
                        vol["size_bytes"].as_u64().unwrap_or(0),
                        vol["file_path"].as_str().unwrap_or("-"),
                    );
                }
            }
        }
        VolumeAction::Get { name } => {
            let resp = api_request(with_api_auth(
                client.get(format!("{api_url}/v1/volumes/{name}")),
                api_token.as_deref(),
            ))
            .await?;
            if !resp.status().is_success() {
                let msg = api_error(resp, &format!("volume '{name}'")).await;
                exit_with_error(output, msg);
            }

            let volume: serde_json::Value = resp.json().await?;
            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "volume-get",
                        "volume": volume,
                    }),
                    "",
                );
            } else {
                println!("Name:     {}", volume["name"].as_str().unwrap_or("-"));
                println!("Size:     {}", volume["size_bytes"].as_u64().unwrap_or(0));
                println!("File:     {}", volume["file_path"].as_str().unwrap_or("-"));
                println!("Created:  {}", volume["created_at"].as_str().unwrap_or("-"));
            }
        }
        VolumeAction::Delete { name } => {
            let resp = api_request(with_api_auth(
                client.delete(format!("{api_url}/v1/volumes/{name}")),
                api_token.as_deref(),
            ))
            .await?;

            if resp.status().is_success() {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "volume-delete",
                        "name": &name,
                    }),
                    format!("Deleted volume: {name}"),
                );
            } else {
                let msg = api_error(resp, &format!("volume '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
    }
    Ok(())
}

async fn secret_command(
    api_url: String,
    api_token: Option<String>,
    action: SecretAction,
    output: OutputFormat,
) -> Result<()> {
    let client = reqwest::Client::new();
    match action {
        SecretAction::Create { name, value } => {
            let resp = api_request(
                with_api_auth(
                    client.post(format!("{api_url}/v1/secrets")),
                    api_token.as_deref(),
                )
                .json(&serde_json::json!({
                    "name": &name,
                    "value": &value,
                })),
            )
            .await?;

            if resp.status().is_success() {
                let secret: serde_json::Value = resp.json().await?;
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "secret-create",
                        "secret": secret,
                    }),
                    format!("Created secret: {}", secret["name"].as_str().unwrap_or("-")),
                );
            } else {
                let msg = api_error(resp, &format!("secret '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        SecretAction::List => {
            let resp = api_request(with_api_auth(
                client.get(format!("{api_url}/v1/secrets")),
                api_token.as_deref(),
            ))
            .await?;
            if !resp.status().is_success() {
                let msg = api_error(resp, "listing secrets").await;
                exit_with_error(output, msg);
            }

            let secrets: Vec<serde_json::Value> = resp.json().await?;
            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "secret-list",
                        "secrets": secrets,
                    }),
                    "",
                );
            } else if secrets.is_empty() {
                println!("No secrets found");
            } else {
                println!("{:<24} UPDATED", "NAME");
                for secret in &secrets {
                    println!(
                        "{:<24} {}",
                        secret["name"].as_str().unwrap_or("-"),
                        secret["updated_at"].as_str().unwrap_or("-"),
                    );
                }
            }
        }
        SecretAction::Get { name } => {
            let resp = api_request(with_api_auth(
                client.get(format!("{api_url}/v1/secrets/{name}")),
                api_token.as_deref(),
            ))
            .await?;
            if !resp.status().is_success() {
                let msg = api_error(resp, &format!("secret '{name}'")).await;
                exit_with_error(output, msg);
            }

            let secret: serde_json::Value = resp.json().await?;
            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "secret-get",
                        "secret": secret,
                    }),
                    "",
                );
            } else {
                println!("Name:     {}", secret["name"].as_str().unwrap_or("-"));
                println!("Created:  {}", secret["created_at"].as_str().unwrap_or("-"));
                println!("Updated:  {}", secret["updated_at"].as_str().unwrap_or("-"));
            }
        }
        SecretAction::Reveal { name } => {
            let resp = api_request(with_api_auth(
                client.get(format!("{api_url}/v1/secrets/{name}/reveal")),
                api_token.as_deref(),
            ))
            .await?;
            if !resp.status().is_success() {
                let msg = api_error(resp, &format!("secret '{name}'")).await;
                exit_with_error(output, msg);
            }

            let revealed: serde_json::Value = resp.json().await?;
            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "secret-reveal",
                        "secret": revealed,
                    }),
                    "",
                );
            } else {
                println!("{}", revealed["value"].as_str().unwrap_or(""));
            }
        }
        SecretAction::Rotate { name, value } => {
            let resp = api_request(
                with_api_auth(
                    client.post(format!("{api_url}/v1/secrets/{name}/rotate")),
                    api_token.as_deref(),
                )
                .json(&serde_json::json!({
                    "value": &value,
                })),
            )
            .await?;
            if resp.status().is_success() {
                let secret: serde_json::Value = resp.json().await?;
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "secret-rotate",
                        "secret": secret,
                    }),
                    format!("Rotated secret: {}", secret["name"].as_str().unwrap_or("-")),
                );
            } else {
                let msg = api_error(resp, &format!("secret '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        SecretAction::Delete { name } => {
            let resp = api_request(with_api_auth(
                client.delete(format!("{api_url}/v1/secrets/{name}")),
                api_token.as_deref(),
            ))
            .await?;
            if resp.status().is_success() {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "secret-delete",
                        "secret": &name,
                    }),
                    format!("Deleted secret: {name}"),
                );
            } else {
                let msg = api_error(resp, &format!("secret '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
    }
    Ok(())
}

use husker_api::{WsShellInput, WsShellOutput};

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Run an interactive shell session inside a VM.
///
/// On Linux, connects directly to the Firecracker vsock UDS proxy for lower
/// latency. Falls back to the WebSocket path if the vsock socket is missing.
/// On macOS, always uses the WebSocket path through the daemon.
#[cfg(feature = "linux-net")]
async fn run_shell(
    api_url: String,
    config_path: Option<PathBuf>,
    name: String,
    command: Option<String>,
    api_token: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    let client = reqwest::Client::new();
    let resp = api_request(with_api_auth(
        client.get(format!("{api_url}/v1/vms/{name}")),
        api_token,
    ))
    .await?;

    if !resp.status().is_success() {
        let err = api_error(resp, &format!("VM '{name}'")).await;
        exit_with_error(output, err);
    }

    let vm: serde_json::Value = resp.json().await?;
    let vm_id = vm["id"].as_str().context("missing VM id")?;

    let config = load_config(config_path.as_deref());
    let runtime_dir = config.data_dir.join("run");
    let vsock_path = runtime_dir.join(format!("{vm_id}.vsock"));

    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        eprintln!("Error: `husker shell` requires an interactive terminal");
        std::process::exit(1);
    }

    // Try direct vsock first (lower latency), fall back to WebSocket.
    if vsock_path.exists() {
        let mut conn =
            husker_core::AgentClient::connect(&vsock_path, husker_agent_proto::AGENT_VSOCK_PORT)
                .await
                .context("connecting to agent")?;

        let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));

        conn.shell_start(command.as_deref(), cols, rows)
            .await
            .context("starting shell")?;

        crossterm::terminal::enable_raw_mode().context("enabling raw mode")?;

        let result = run_shell_bridge(&mut conn).await;

        crossterm::terminal::disable_raw_mode().ok();
        println!();

        match result {
            Ok(exit_code) => std::process::exit(exit_code),
            Err(e) => {
                eprintln!("Shell error: {e}");
                std::process::exit(1);
            }
        }
    }

    // Direct vsock unavailable — use WebSocket through daemon.
    run_shell_ws(&api_url, &name, command.as_deref(), api_token, output).await
}

#[cfg(not(feature = "linux-net"))]
async fn run_shell(
    api_url: String,
    _config_path: Option<PathBuf>,
    name: String,
    command: Option<String>,
    api_token: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    run_shell_ws(&api_url, &name, command.as_deref(), api_token, output).await
}

/// WebSocket-based interactive shell, works on both Linux and macOS.
async fn run_shell_ws(
    api_url: &str,
    name: &str,
    command: Option<&str>,
    api_token: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    // Pre-check: verify VM is running before opening the WebSocket.
    let client = reqwest::Client::new();
    let resp = api_request(with_api_auth(
        client.get(format!("{api_url}/v1/vms/{name}")),
        api_token,
    ))
    .await?;
    if !resp.status().is_success() {
        let err = api_error(resp, &format!("VM '{name}'")).await;
        exit_with_error(output, err);
    }
    let vm: serde_json::Value = resp.json().await?;
    let state = vm["state"].as_str().unwrap_or("unknown");
    if state != "running" {
        let mut message = format!("VM '{name}' is {state}, expected running");
        if state == "stopped" {
            message.push_str(" (hint: start the VM first with `husker run`)");
        } else if state == "paused" {
            message.push_str(&format!(
                " (hint: resume the VM first with `husker resume {name}`)"
            ));
        }
        exit_with_error(
            output,
            ApiFailure {
                message,
                code: Some("vm_not_running".into()),
                exit_code: exit_code::CONFLICT,
                hint: None,
            },
        );
    }

    let ws_url = api_url
        .replacen("http://", "ws://", 1)
        .replacen("https://", "wss://", 1);
    let url = format!("{ws_url}/v1/vms/{name}/shell");

    let mut ws_request = url
        .into_client_request()
        .context("building websocket request")?;
    if let Some(token) = api_token {
        let value = format!("Bearer {token}");
        let header = tungstenite::http::HeaderValue::from_str(&value)
            .context("invalid API token for websocket auth header")?;
        ws_request
            .headers_mut()
            .insert(tungstenite::http::header::AUTHORIZATION, header);
    }

    let (ws_stream, _) = tokio_tungstenite::connect_async(ws_request)
        .await
        .context("connecting to daemon WebSocket")?;

    let (mut ws_sink, mut ws_recv) = ws_stream.split();

    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));

    let start_msg = serde_json::to_string(&WsShellInput::Start {
        command: command.map(String::from),
        cols,
        rows,
    })?;
    ws_sink
        .send(tungstenite::Message::Text(start_msg.into()))
        .await
        .context("sending start message")?;

    // Wait for Started response.
    let started = ws_recv.next().await.context("no response from server")?;
    match started {
        Ok(tungstenite::Message::Text(text)) => {
            let msg: WsShellOutput =
                serde_json::from_str(&text).context("invalid server message")?;
            match msg {
                WsShellOutput::Started => {}
                WsShellOutput::Error { message } => {
                    eprintln!("Error: {message}");
                    std::process::exit(1);
                }
                _ => {
                    eprintln!("Error: unexpected response from server");
                    std::process::exit(1);
                }
            }
        }
        Ok(_) => anyhow::bail!("unexpected message type from server"),
        Err(e) => anyhow::bail!("WebSocket error: {e}"),
    }

    crossterm::terminal::enable_raw_mode().context("enabling raw mode")?;

    let result = run_shell_ws_bridge(&mut ws_sink, &mut ws_recv).await;

    crossterm::terminal::disable_raw_mode().ok();
    println!();

    // Exit immediately — tokio's stdin reader holds a blocking thread that
    // prevents clean runtime shutdown. process::exit() is the standard pattern
    // for interactive CLI tools that use raw stdin.
    match result {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(e) => {
            eprintln!("Shell error: {e}");
            std::process::exit(1);
        }
    }
}

/// Bridge raw stdin/stdout to a WebSocket shell session.
///
/// Reads raw stdin bytes directly (preserving escape sequences as-is) and
/// detects terminal resizes via SIGWINCH. Handles SIGHUP for graceful shutdown.
async fn run_shell_ws_bridge(
    ws_sink: &mut futures_util::stream::SplitSink<WsStream, tungstenite::Message>,
    ws_recv: &mut futures_util::stream::SplitStream<WsStream>,
) -> Result<i32> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut stdin = tokio::io::stdin();
    let mut stdin_buf = vec![0u8; 1024];
    let mut sigwinch = signal(SignalKind::window_change()).context("registering SIGWINCH")?;
    let mut sighup = signal(SignalKind::hangup()).context("registering SIGHUP")?;

    loop {
        tokio::select! {
            result = stdin.read(&mut stdin_buf) => {
                match result {
                    Ok(0) => return Ok(0),
                    Ok(n) => {
                        let encoded = husker_agent_proto::base64_encode(&stdin_buf[..n]);
                        let msg = serde_json::to_string(&WsShellInput::Data { data: encoded })?;
                        ws_sink.send(tungstenite::Message::Text(msg.into())).await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            _ = sigwinch.recv() => {
                if let Ok((cols, rows)) = crossterm::terminal::size() {
                    let msg = serde_json::to_string(&WsShellInput::Resize { cols, rows })?;
                    ws_sink.send(tungstenite::Message::Text(msg.into())).await?;
                }
            }
            _ = sighup.recv() => {
                let _ = ws_sink.send(tungstenite::Message::Close(None)).await;
                return Ok(0);
            }
            ws_msg = ws_recv.next() => {
                match ws_msg {
                    Some(Ok(tungstenite::Message::Text(text))) => {
                        let msg: WsShellOutput = serde_json::from_str(&text)?;
                        match msg {
                            WsShellOutput::Data { data } => {
                                let bytes = husker_agent_proto::base64_decode(&data)
                                    .map_err(|e| anyhow::anyhow!("base64 decode: {e}"))?;
                                use std::io::Write;
                                std::io::stdout().write_all(&bytes)?;
                                std::io::stdout().flush()?;
                            }
                            WsShellOutput::Exit { exit_code } => {
                                return Ok(exit_code);
                            }
                            WsShellOutput::Error { message } => {
                                return Err(anyhow::anyhow!("agent error: {message}"));
                            }
                            WsShellOutput::Started => {}
                        }
                    }
                    Some(Ok(tungstenite::Message::Close(_))) | None => return Ok(0),
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(anyhow::anyhow!("WebSocket error: {e}")),
                }
            }
        }
    }
}

enum CpPath {
    Local(PathBuf),
    Vm { name: String, path: String },
}

fn parse_octal_mode(s: &str) -> Result<u32, String> {
    u32::from_str_radix(s, 8).map_err(|e| format!("invalid octal mode: {e}"))
}

fn parse_cp_path(s: &str) -> CpPath {
    if let Some(colon_pos) = s.find(':') {
        let name = &s[..colon_pos];
        let path = &s[colon_pos + 1..];
        if !name.is_empty() && !path.is_empty() {
            return CpPath::Vm {
                name: name.to_string(),
                path: path.to_string(),
            };
        }
    }
    CpPath::Local(PathBuf::from(s))
}

#[cfg(feature = "linux-net")]
async fn run_shell_bridge<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    conn: &mut husker_core::AgentConnection<S>,
) -> Result<i32> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut stdin = tokio::io::stdin();
    let mut stdin_buf = vec![0u8; 1024];
    let mut sigwinch = signal(SignalKind::window_change()).context("registering SIGWINCH")?;
    let mut sighup = signal(SignalKind::hangup()).context("registering SIGHUP")?;

    loop {
        tokio::select! {
            result = stdin.read(&mut stdin_buf) => {
                match result {
                    Ok(0) => return Ok(0),
                    Ok(n) => {
                        conn.shell_send(&stdin_buf[..n]).await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            _ = sigwinch.recv() => {
                if let Ok((cols, rows)) = crossterm::terminal::size() {
                    conn.shell_resize(cols, rows).await?;
                }
            }
            _ = sighup.recv() => {
                return Ok(0);
            }
            event = conn.shell_recv() => {
                match event? {
                    husker_core::ShellEvent::Data(data) => {
                        use std::io::Write;
                        std::io::stdout().write_all(&data)?;
                        std::io::stdout().flush()?;
                    }
                    husker_core::ShellEvent::Exit(code) => {
                        return Ok(code);
                    }
                }
            }
        }
    }
}

/// Resolve the config file path by checking (in order):
/// 1. Explicit path from --config flag
/// 2. `~/.config/husker/config.toml` (XDG user config)
/// 3. `/etc/husker/config.toml` (system config)
fn resolve_config_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_owned();
    }
    if let Some(home) = std::env::var_os("HOME") {
        let user_config = PathBuf::from(home).join(".config/husker/config.toml");
        if user_config.exists() {
            return user_config;
        }
    }
    PathBuf::from("/etc/husker/config.toml")
}

/// A saved daemon target: a name mapped to an API URL (http:// or ssh://).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ContextEntry {
    api_url: String,
}

/// Named daemon targets ("contexts") plus the currently selected one, persisted
/// to `~/.config/husker/contexts.toml`. Lets a host switch between, say, a local
/// Apple VZ daemon and a remote Linux Firecracker daemon without retyping URLs.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Contexts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    current: Option<String>,
    #[serde(default)]
    contexts: std::collections::BTreeMap<String, ContextEntry>,
}

/// Path to the contexts file (`HUSKER_CONTEXTS_FILE` overrides; used by tests).
fn contexts_path() -> PathBuf {
    if let Some(p) = std::env::var_os("HUSKER_CONTEXTS_FILE") {
        return PathBuf::from(p);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    home.join(".config/husker/contexts.toml")
}

/// Load saved contexts, or an empty set if the file is absent or unreadable.
fn load_contexts() -> Contexts {
    std::fs::read_to_string(contexts_path())
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default()
}

/// Persist contexts, creating the parent directory if needed.
fn save_contexts(contexts: &Contexts) -> Result<()> {
    let path = contexts_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let body = toml::to_string_pretty(contexts).context("serializing contexts")?;
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))
}

/// Resolve the daemon API URL to use. Precedence: an explicit `--api-url` /
/// `HUSKER_API_URL` always wins; otherwise an explicitly named context
/// (`--context`/`HUSKER_CONTEXT`); otherwise the saved current context; otherwise
/// the local default. An explicitly named context that does not exist is an error;
/// a stale `current` falls back to the default rather than bricking the CLI.
fn resolve_effective_api_url(
    explicit_api_url: Option<&str>,
    context_name: Option<&str>,
    contexts: &Contexts,
) -> Result<String> {
    const DEFAULT_API_URL: &str = "http://127.0.0.1:7777";
    if let Some(url) = explicit_api_url {
        return Ok(url.to_string());
    }
    if let Some(name) = context_name {
        let entry = contexts.contexts.get(name).ok_or_else(|| {
            anyhow::anyhow!("unknown context '{name}' (list with `husker context list`)")
        })?;
        return Ok(entry.api_url.clone());
    }
    if let Some(name) = contexts.current.as_deref()
        && let Some(entry) = contexts.contexts.get(name)
    {
        return Ok(entry.api_url.clone());
    }
    Ok(DEFAULT_API_URL.to_string())
}

/// Apply environment variable overrides to the configuration.
///
/// Environment variables take precedence over file-based config.
fn apply_env_overrides(config: &mut Config) {
    if let Ok(val) = std::env::var("HUSKER_DATA_DIR") {
        let new_data_dir = PathBuf::from(val);
        // Cascade the override to kernel/rootfs/initrd paths when they were
        // left at their defaults. Explicit TOML values (which do not match
        // the default-based paths) are preserved.
        let old_default_kernel = husker::default_kernel_path_for(&config.data_dir);
        let old_default_rootfs = husker::default_rootfs_path_for(&config.data_dir);
        let old_default_initrd = husker::default_initrd_path_for(&config.data_dir);
        if config.default_kernel == old_default_kernel {
            config.default_kernel = husker::default_kernel_path_for(&new_data_dir);
        }
        if config.default_rootfs == old_default_rootfs {
            config.default_rootfs = husker::default_rootfs_path_for(&new_data_dir);
        }
        if config.default_initrd.as_ref() == Some(&old_default_initrd) {
            config.default_initrd = Some(husker::default_initrd_path_for(&new_data_dir));
        }
        config.data_dir = new_data_dir;
    }
    if let Ok(val) = std::env::var("HUSKER_DEFAULT_KERNEL") {
        config.default_kernel = PathBuf::from(val);
    }
    if let Ok(val) = std::env::var("HUSKER_DEFAULT_ROOTFS") {
        config.default_rootfs = PathBuf::from(val);
    }
    if let Ok(val) = std::env::var("HUSKER_DEFAULT_INITRD") {
        config.default_initrd = Some(PathBuf::from(val));
    }
    if let Ok(val) = std::env::var("HUSKER_DEFAULT_DISK_SIZE") {
        config.default_disk_size = Some(val);
    }
    if let Ok(val) = std::env::var("HUSKER_IMAGES_BASE_URL") {
        config.images_base_url = val;
    }
    if let Ok(val) = std::env::var("HUSKER_API_TOKEN") {
        config.api_token = Some(val);
    }
    if let Ok(val) = std::env::var("HUSKER_API_MAX_REQUEST_BYTES")
        && let Ok(parsed) = val.parse::<usize>()
    {
        config.api_max_request_bytes = parsed;
    }
    if let Ok(val) = std::env::var("HUSKER_API_MAX_FILE_READ_BYTES")
        && let Ok(parsed) = val.parse::<usize>()
    {
        config.api_max_file_read_bytes = parsed;
    }
    if let Ok(val) = std::env::var("HUSKER_API_MAX_FILE_WRITE_BYTES")
        && let Ok(parsed) = val.parse::<usize>()
    {
        config.api_max_file_write_bytes = parsed;
    }
    if let Ok(val) = std::env::var("HUSKER_API_SENSITIVE_RATE_LIMIT_PER_MINUTE")
        && let Ok(parsed) = val.parse::<u32>()
    {
        config.api_sensitive_rate_limit_per_minute = parsed;
    }
    if let Ok(val) = std::env::var("HUSKER_ALLOWED_READ_PATHS") {
        config.allowed_read_paths = val
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Ok(val) = std::env::var("HUSKER_ALLOWED_WRITE_PATHS") {
        config.allowed_write_paths = val
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Ok(val) = std::env::var("HUSKER_ALLOWED_MOUNT_HOST_PATHS") {
        config.allowed_mount_host_paths = val
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Ok(val) = std::env::var("HUSKER_EXEC_TIMEOUT_SECS")
        && let Ok(parsed) = val.parse::<u64>()
    {
        config.exec_timeout_secs = parsed;
    }
    if let Ok(val) = std::env::var("HUSKER_EXEC_TIMEOUT_MAX_SECS")
        && let Ok(parsed) = val.parse::<u64>()
    {
        config.exec_timeout_max_secs = parsed;
    }
    if let Ok(val) = std::env::var("HUSKER_EXEC_ALLOWLIST") {
        config.exec_allowlist = val
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Ok(val) = std::env::var("HUSKER_EXEC_DENYLIST") {
        config.exec_denylist = val
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Ok(val) = std::env::var("HUSKER_EXEC_ENV_ALLOWLIST") {
        config.exec_env_allowlist = val
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Ok(val) = std::env::var("HUSKER_SERVICE_RECONCILE_INTERVAL")
        && let Ok(parsed) = val.parse::<u64>()
    {
        config.service_reconcile_interval_secs = parsed;
    }
    if let Ok(val) = std::env::var("HUSKER_SERVICE_RECONCILE_ENABLED") {
        config.service_reconcile_enabled = matches!(val.as_str(), "1" | "true" | "TRUE" | "yes");
    }
    #[cfg(feature = "linux-net")]
    {
        if let Ok(val) = std::env::var("HUSKER_FIRECRACKER_BIN") {
            config.firecracker_bin = PathBuf::from(val);
        }
        #[cfg(target_os = "linux")]
        if let Ok(val) = std::env::var("HUSKER_QEMU_BIN") {
            config.qemu_bin = PathBuf::from(val);
        }
        #[cfg(target_os = "linux")]
        if let Ok(val) = std::env::var("HUSKER_OVMF_CODE") {
            config.ovmf_code = PathBuf::from(val);
        }
        #[cfg(target_os = "linux")]
        if let Ok(val) = std::env::var("HUSKER_OVMF_VARS") {
            config.ovmf_vars = PathBuf::from(val);
        }
        if let Ok(val) = std::env::var("HUSKER_VMM") {
            match VmmSelection::from_env_str(&val) {
                Some(sel) => config.vmm = sel,
                None => tracing::warn!(
                    value = %val,
                    "HUSKER_VMM: unrecognised or unsupported backend on this platform, ignoring (valid: firecracker, qemu)"
                ),
            }
        }
        if let Ok(val) = std::env::var("HUSKER_HOST_INTERFACE") {
            config.host_interface = val;
        }
        if let Ok(val) = std::env::var("HUSKER_BRIDGE_NAME") {
            config.bridge_name = val;
        }
        if let Ok(val) = std::env::var("HUSKER_BRIDGE_SUBNET") {
            config.bridge_subnet = val;
        }
        if let Ok(val) = std::env::var("HUSKER_DNS_SERVERS") {
            config.dns_servers = val.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(val) = std::env::var("HUSKER_CID_BASE")
            && let Ok(parsed) = val.parse::<u32>()
        {
            config.cid_base = parsed;
        }
        #[cfg(target_os = "linux")]
        if let Ok(val) = std::env::var("HUSKER_LAN_BRIDGE") {
            config.lan_bridge = if val.is_empty() { None } else { Some(val) };
        }
    }
}

fn load_config(explicit_path: Option<&Path>) -> Config {
    let path = resolve_config_path(explicit_path);
    let mut config = match std::fs::read_to_string(&path) {
        Ok(contents) => toml::from_str(&contents).unwrap_or_else(|e| {
            eprintln!("Warning: invalid config file: {e}");
            Config::default()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
        Err(e) => {
            eprintln!(
                "Warning: could not read config file {}: {e}",
                path.display()
            );
            Config::default()
        }
    };
    apply_env_overrides(&mut config);
    config
}

/// Parse a CIDR string (e.g. "172.20.0.0/24") into base address and prefix length.
///
/// Validates that:
/// - The string contains a `/` separator
/// - The base address is a valid IPv4 address
/// - The prefix length is between 1 and 30 (inclusive)
/// - The base address is network-aligned (host bits are zero)
#[cfg(feature = "linux-net")]
fn parse_cidr(cidr: &str) -> Result<(std::net::Ipv4Addr, u8)> {
    let (base_str, prefix_str) = cidr.split_once('/').context("invalid CIDR: missing '/'")?;
    let base: std::net::Ipv4Addr = base_str.parse().context("invalid CIDR base address")?;
    let prefix_len: u8 = prefix_str.parse().context("invalid CIDR prefix length")?;
    anyhow::ensure!(
        (1..=30).contains(&prefix_len),
        "prefix length must be 1..=30 (got {prefix_len})"
    );

    // Verify the base address has no host bits set (is a proper network address).
    let base_u32 = u32::from(base);
    let host_mask = (1u32 << (32 - prefix_len)) - 1;
    anyhow::ensure!(
        base_u32 & host_mask == 0,
        "base address {base} is not network-aligned for /{prefix_len} \
         (did you mean {}/{}?)",
        std::net::Ipv4Addr::from(base_u32 & !host_mask),
        prefix_len,
    );

    Ok((base, prefix_len))
}

/// Whether a VM create request will boot via Firecracker and therefore needs
/// the client-side Firecracker binary preflight. Cloud-image and explicit
/// `--vmm qemu` requests are served by QEMU, where the preflight would block
/// hosts that have QEMU but no Firecracker installed.
#[cfg(all(target_os = "linux", feature = "linux-net"))]
fn needs_firecracker_preflight(body: &serde_json::Value) -> bool {
    body.get("cloud_image").is_none() && body["vmm"].as_str() != Some("qemu")
}

/// Ensure Firecracker is available. If the binary can't be found, auto-install
/// when `HUSKER_AUTO_INSTALL_FIRECRACKER=1` is set, prompt interactively on a
/// TTY, or bail with a hint otherwise.
#[cfg(all(target_os = "linux", feature = "linux-net"))]
async fn ensure_firecracker(config: &Config) -> anyhow::Result<PathBuf> {
    if let Some(p) = find_in_path(&config.firecracker_bin) {
        return Ok(p);
    }
    let data = &config.data_dir;
    let bin = data.join("bin/firecracker");
    if bin.exists() {
        return Ok(bin);
    }

    let env = std::env::var("HUSKER_AUTO_INSTALL_FIRECRACKER").ok();
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin())
        && std::io::IsTerminal::is_terminal(&std::io::stderr());
    let url = husker::firecracker::firecracker_download_url();

    let should_install = match decide_auto_install(env.as_deref(), is_tty) {
        AutoInstallDecision::Yes => true,
        AutoInstallDecision::No => false,
        AutoInstallDecision::Prompt => prompt_firecracker_install(&url)?,
    };

    if !should_install {
        anyhow::bail!(
            "firecracker not found on PATH. Install it, or re-run with HUSKER_AUTO_INSTALL_FIRECRACKER=1 to download {url}"
        );
    }
    let installed = husker::firecracker::install(data).await?;
    eprintln!("Installed firecracker to {}", installed.display());
    Ok(installed)
}

#[cfg(all(target_os = "linux", feature = "linux-net"))]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum AutoInstallDecision {
    Yes,
    No,
    Prompt,
}

#[cfg(all(target_os = "linux", feature = "linux-net"))]
fn decide_auto_install(env: Option<&str>, is_tty: bool) -> AutoInstallDecision {
    match env {
        Some("1") => AutoInstallDecision::Yes,
        _ if is_tty => AutoInstallDecision::Prompt,
        _ => AutoInstallDecision::No,
    }
}

#[cfg(all(target_os = "linux", feature = "linux-net"))]
fn prompt_firecracker_install(url: &str) -> anyhow::Result<bool> {
    use std::io::Write;
    eprintln!("firecracker not found on PATH.");
    eprintln!("husker can download a pinned release from:");
    eprintln!("  {url}");
    eprint!("Install it now? [Y/n] ");
    std::io::stderr().flush().ok();
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_lowercase();
    Ok(matches!(answer.as_str(), "" | "y" | "yes"))
}

#[cfg(all(test, target_os = "linux", feature = "linux-net"))]
mod auto_install_tests {
    use super::{AutoInstallDecision, decide_auto_install};

    #[test]
    fn env_one_always_installs() {
        assert_eq!(
            decide_auto_install(Some("1"), true),
            AutoInstallDecision::Yes
        );
        assert_eq!(
            decide_auto_install(Some("1"), false),
            AutoInstallDecision::Yes
        );
    }

    #[test]
    fn no_env_on_tty_prompts() {
        assert_eq!(decide_auto_install(None, true), AutoInstallDecision::Prompt);
        assert_eq!(
            decide_auto_install(Some(""), true),
            AutoInstallDecision::Prompt
        );
        assert_eq!(
            decide_auto_install(Some("0"), true),
            AutoInstallDecision::Prompt
        );
    }

    #[test]
    fn no_env_without_tty_bails() {
        assert_eq!(decide_auto_install(None, false), AutoInstallDecision::No);
        assert_eq!(
            decide_auto_install(Some(""), false),
            AutoInstallDecision::No
        );
        assert_eq!(
            decide_auto_install(Some("0"), false),
            AutoInstallDecision::No
        );
    }
}

/// Check if a binary name can be found in PATH.
#[cfg(feature = "linux-net")]
fn find_in_path(name: &Path) -> Option<PathBuf> {
    if name.is_absolute() {
        return name.is_file().then(|| name.to_path_buf());
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Validate the configuration file and report results.
fn check_config(explicit_path: Option<&Path>) -> Result<()> {
    let path = resolve_config_path(explicit_path);
    let mut all_ok = true;

    let config = match std::fs::read_to_string(&path) {
        Ok(contents) => {
            println!("Config: {}", path.display());
            match toml::from_str::<Config>(&contents) {
                Ok(config) => config,
                Err(e) => {
                    println!("  parse .............. FAIL ({e})");
                    std::process::exit(1);
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if explicit_path.is_some() {
                println!("Config: {} (not found)", path.display());
                println!("  config file .............. FAIL (not found)");
                std::process::exit(1);
            } else {
                println!("Config: (defaults, no config file found)");
                Config::default()
            }
        }
        Err(e) => {
            println!("Config: {}", path.display());
            println!("  config file .............. FAIL ({e})");
            std::process::exit(1);
        }
    };

    let dd_from_env = std::env::var("HUSKER_DATA_DIR").is_ok();
    let kernel_from_env = std::env::var("HUSKER_DEFAULT_KERNEL").is_ok();

    // data_dir
    let dd = &config.data_dir;
    let dd_env_hint = if dd_from_env {
        " (from HUSKER_DATA_DIR)"
    } else {
        ""
    };
    if dd.exists() {
        println!("  data_dir ({}) ... OK{dd_env_hint}", dd.display());
    } else {
        match std::fs::create_dir_all(dd) {
            Ok(()) => {
                println!(
                    "  data_dir ({}) ... OK (created){dd_env_hint}",
                    dd.display()
                );
            }
            Err(e) => {
                println!("  data_dir ({}) ... FAIL ({e}){dd_env_hint}", dd.display());
                all_ok = false;
            }
        }
    }

    // default_kernel
    let kernel = &config.default_kernel;
    let kernel_env_hint = if kernel_from_env {
        " (from HUSKER_DEFAULT_KERNEL)"
    } else {
        ""
    };
    if kernel.is_file() {
        println!(
            "  default_kernel ({}) ... OK{kernel_env_hint}",
            kernel.display()
        );
    } else if kernel.exists() {
        println!(
            "  default_kernel ({}) ... FAIL (not a regular file){kernel_env_hint}",
            kernel.display()
        );
        all_ok = false;
    } else {
        println!(
            "  default_kernel ({}) ... FAIL (not found){kernel_env_hint}",
            kernel.display()
        );
        all_ok = false;
    }

    // default_rootfs
    let rootfs = &config.default_rootfs;
    let rootfs_env_hint = if std::env::var("HUSKER_DEFAULT_ROOTFS").is_ok() {
        " (from HUSKER_DEFAULT_ROOTFS)"
    } else {
        ""
    };
    if rootfs.is_file() {
        println!(
            "  default_rootfs ({}) ... OK{rootfs_env_hint}",
            rootfs.display()
        );
    } else if rootfs.exists() {
        println!(
            "  default_rootfs ({}) ... FAIL (not a regular file){rootfs_env_hint}",
            rootfs.display()
        );
        all_ok = false;
    } else {
        println!(
            "  default_rootfs ({}) ... FAIL (not found){rootfs_env_hint}",
            rootfs.display()
        );
        all_ok = false;
    }

    // default_initrd (optional)
    if let Some(initrd) = &config.default_initrd {
        let initrd_env_hint = if std::env::var("HUSKER_DEFAULT_INITRD").is_ok() {
            " (from HUSKER_DEFAULT_INITRD)"
        } else {
            ""
        };
        if initrd.is_file() {
            println!(
                "  default_initrd ({}) ... OK{initrd_env_hint}",
                initrd.display()
            );
        } else if initrd.exists() {
            println!(
                "  default_initrd ({}) ... FAIL (not a regular file){initrd_env_hint}",
                initrd.display()
            );
            all_ok = false;
        } else {
            println!(
                "  default_initrd ({}) ... FAIL (not found){initrd_env_hint}",
                initrd.display()
            );
            all_ok = false;
        }
    }

    // images_base_url
    let url = &config.images_base_url;
    let base_url_env_hint = if std::env::var("HUSKER_IMAGES_BASE_URL").is_ok() {
        " [HUSKER_IMAGES_BASE_URL override]"
    } else {
        ""
    };
    match reqwest::Url::parse(url) {
        Ok(_) => println!("  images_base_url ({url}) ... OK{base_url_env_hint}"),
        Err(err) => println!("  images_base_url ({url}) ... FAIL ({err}){base_url_env_hint}"),
    }

    #[cfg(feature = "linux-net")]
    {
        let fc_from_env = std::env::var("HUSKER_FIRECRACKER_BIN").is_ok();
        let iface_from_env = std::env::var("HUSKER_HOST_INTERFACE").is_ok();
        let subnet_from_env = std::env::var("HUSKER_BRIDGE_SUBNET").is_ok();

        // firecracker_bin
        let fc = &config.firecracker_bin;
        let fc_env_hint = if fc_from_env {
            " (from HUSKER_FIRECRACKER_BIN)"
        } else {
            ""
        };
        match find_in_path(fc) {
            Some(resolved) => {
                if fc.is_absolute() {
                    println!("  firecracker_bin ({}) ... OK{fc_env_hint}", fc.display());
                } else {
                    println!(
                        "  firecracker_bin ({}) ... OK ({}){fc_env_hint}",
                        fc.display(),
                        resolved.display()
                    );
                }
            }
            None => {
                println!(
                    "  firecracker_bin ({}) ... FAIL (not found){fc_env_hint}",
                    fc.display()
                );
                all_ok = false;
            }
        }

        // QEMU backend prerequisites (only when vmm = "qemu" is selected).
        #[cfg(target_os = "linux")]
        if config.vmm == VmmSelection::Qemu {
            let qemu_env_hint = if std::env::var("HUSKER_QEMU_BIN").is_ok() {
                " (from HUSKER_QEMU_BIN)"
            } else {
                ""
            };
            let qb = &config.qemu_bin;
            match find_in_path(qb) {
                Some(resolved) => {
                    if qb.is_absolute() {
                        println!("  qemu_bin ({}) ... OK{qemu_env_hint}", qb.display());
                    } else {
                        println!(
                            "  qemu_bin ({}) ... OK ({}){qemu_env_hint}",
                            qb.display(),
                            resolved.display()
                        );
                    }
                }
                None => {
                    println!(
                        "  qemu_bin ({}) ... FAIL (not found){qemu_env_hint}",
                        qb.display()
                    );
                    all_ok = false;
                }
            }
            // QEMU needs hardware acceleration and the vsock host device.
            for (dev, hint) in [
                ("/dev/kvm", ""),
                ("/dev/vhost-vsock", " (load the vhost_vsock kernel module)"),
            ] {
                if std::path::Path::new(dev).exists() {
                    println!("  {dev} ... OK");
                } else {
                    println!("  {dev} ... FAIL (missing){hint}");
                    all_ok = false;
                }
            }
        }

        // host_interface
        let iface = &config.host_interface;
        let iface_env_hint = if iface_from_env {
            " (from HUSKER_HOST_INTERFACE)"
        } else {
            ""
        };
        let iface_path = PathBuf::from(format!("/sys/class/net/{iface}"));
        if iface_path.exists() {
            println!("  host_interface ({iface}) ... OK{iface_env_hint}");
        } else {
            println!("  host_interface ({iface}) ... FAIL (not found){iface_env_hint}");
            all_ok = false;
        }

        // bridge_subnet
        let subnet_env_hint = if subnet_from_env {
            " (from HUSKER_BRIDGE_SUBNET)"
        } else {
            ""
        };
        match parse_cidr(&config.bridge_subnet) {
            Ok(_) => println!(
                "  bridge_subnet ({}) ... OK{subnet_env_hint}",
                config.bridge_subnet
            ),
            Err(e) => {
                println!(
                    "  bridge_subnet ({}) ... FAIL ({e}){subnet_env_hint}",
                    config.bridge_subnet
                );
                all_ok = false;
            }
        }

        // lan_bridge (optional; when configured, the bridge must exist)
        #[cfg(target_os = "linux")]
        if let Some(ref bridge) = config.lan_bridge {
            let bridge_env_hint = if std::env::var("HUSKER_LAN_BRIDGE").is_ok() {
                " (from HUSKER_LAN_BRIDGE)"
            } else {
                ""
            };
            let ok = std::process::Command::new("ip")
                .args(["link", "show", bridge.as_str()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            if ok {
                println!("  lan_bridge ({bridge}) ... OK{bridge_env_hint}");
            } else {
                println!("  lan_bridge ({bridge}) ... FAIL (bridge not found){bridge_env_hint}");
                all_ok = false;
            }
        }
    }

    #[cfg(all(feature = "linux-net", target_os = "linux"))]
    {
        let hint = if std::env::var("HUSKER_OVMF_CODE").is_ok() {
            " (from HUSKER_OVMF_CODE)"
        } else {
            ""
        };
        if config.ovmf_code.exists() {
            println!("  ovmf_code ({}) ... OK{hint}", config.ovmf_code.display());
        } else {
            println!(
                "  ovmf_code ({}) ... MISSING (cloud-image boot unavailable){hint}",
                config.ovmf_code.display()
            );
        }
        let hint = if std::env::var("HUSKER_OVMF_VARS").is_ok() {
            " (from HUSKER_OVMF_VARS)"
        } else {
            ""
        };
        if config.ovmf_vars.exists() {
            println!("  ovmf_vars ({}) ... OK{hint}", config.ovmf_vars.display());
        } else {
            println!(
                "  ovmf_vars ({}) ... MISSING (cloud-image boot unavailable){hint}",
                config.ovmf_vars.display()
            );
        }
        match std::process::Command::new("qemu-img")
            .arg("--version")
            .output()
        {
            Ok(out) if out.status.success() => println!("  qemu-img ... OK"),
            _ => println!("  qemu-img ... MISSING (cloud-image disk resize unavailable)"),
        }
        match std::process::Command::new("mkfs.ext4")
            .arg("--version")
            .output()
        {
            Ok(out) if out.status.success() || !out.stderr.is_empty() => {
                println!("  mkfs.ext4 ... OK")
            }
            _ => println!("  mkfs.ext4 ... MISSING (volumes unavailable)"),
        }
    }
    #[cfg(target_os = "macos")]
    {
        let ok = std::process::Command::new("qemu-img")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if ok {
            println!("  qemu-img ... OK (cloud-image conversion available)");
        } else {
            println!("  qemu-img ... MISSING (cloud images need it: brew install qemu)");
        }
    }
    if let Some(ref size) = config.default_disk_size {
        match husker::parse_disk_size(size) {
            Ok(_) => println!("  default_disk_size ({size}) ... OK"),
            Err(e) => {
                println!("  default_disk_size ({size}) ... FAIL ({e})");
                all_ok = false;
            }
        }
    }

    if config.exec_timeout_max_secs < config.exec_timeout_secs {
        println!(
            "  exec_timeout_max_secs ({}) ... FAIL (must be >= exec_timeout_secs ({}))",
            config.exec_timeout_max_secs, config.exec_timeout_secs
        );
        all_ok = false;
    } else {
        println!(
            "  exec_timeout_max_secs ({}) ... OK",
            config.exec_timeout_max_secs
        );
    }

    let mut profile_names: Vec<&String> = config.profiles.keys().collect();
    profile_names.sort();
    for name in profile_names {
        let p = &config.profiles[name.as_str()];
        let mut problems: Vec<String> = Vec::new();
        for key in &p.ssh_keys {
            let expanded = expand_tilde(key);
            if !expanded.exists() {
                problems.push(format!("ssh key {} not found", expanded.display()));
            }
        }
        for path in [&p.rootfs, &p.kernel, &p.initrd].into_iter().flatten() {
            if !path.exists() {
                problems.push(format!("{} not found", path.display()));
            }
        }
        if let Some(ref size) = p.disk_size
            && let Err(e) = husker::parse_disk_size(size)
        {
            problems.push(format!("disk_size: {e}"));
        }
        if let Some(ref v) = p.vmm
            && !["firecracker", "qemu"].contains(&v.as_str())
        {
            problems.push(format!("unknown vmm '{v}'"));
        }
        for e in &p.env {
            if !e.contains('=') {
                problems.push(format!("env entry '{e}' is not KEY=VALUE"));
            }
        }
        if problems.is_empty() {
            println!("  profile {name} ... OK");
        } else {
            println!("  profile {name} ... FAIL ({})", problems.join("; "));
            all_ok = false;
        }
    }

    if all_ok {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

async fn start_daemon(config: Config, listen: SocketAddr) -> Result<()> {
    tracing::info!("starting husker daemon");

    // Resolve firecracker_bin to an absolute path before handing it to the
    // VMM backend. Auto-installed Firecracker lands at `{data_dir}/bin/firecracker`
    // which is not on PATH for most setups; look there when PATH lookup fails.
    #[cfg(all(target_os = "linux", feature = "linux-net"))]
    let config = {
        let mut config = config;
        if !config.firecracker_bin.is_absolute() && find_in_path(&config.firecracker_bin).is_none()
        {
            let candidate = config.data_dir.join("bin/firecracker");
            if candidate.is_file() {
                tracing::info!(path = %candidate.display(), "resolved firecracker_bin from data dir");
                config.firecracker_bin = candidate;
            }
        }
        config
    };

    let runtime_dir = config.data_dir.join("run");
    let db_path = config.data_dir.join("husker.db");
    let api_token = config.api_token.clone();
    let service_reconcile_enabled = config.service_reconcile_enabled;
    let service_reconcile_interval = config.service_reconcile_interval_secs;
    let api_policy = husker_api::ApiPolicy {
        max_request_bytes: config.api_max_request_bytes,
        max_file_read_bytes: config.api_max_file_read_bytes,
        max_file_write_bytes: config.api_max_file_write_bytes,
        sensitive_rate_limit_per_minute: config.api_sensitive_rate_limit_per_minute,
        allowed_read_paths: config.allowed_read_paths.clone(),
        allowed_write_paths: config.allowed_write_paths.clone(),
        allowed_mount_host_paths: config.allowed_mount_host_paths.clone(),
        exec_timeout_secs: config.exec_timeout_secs,
        exec_timeout_max_secs: config.exec_timeout_max_secs,
        exec_allowlist: config.exec_allowlist.clone(),
        exec_denylist: config.exec_denylist.clone(),
        exec_env_allowlist: config.exec_env_allowlist.clone(),
    };
    husker_api::set_policy(api_policy);

    std::fs::create_dir_all(&runtime_dir).context("creating runtime directory")?;
    std::fs::create_dir_all(config.data_dir.join("vms")).context("creating vms directory")?;

    let state = husker_state::StateStore::open(&db_path).context("opening state database")?;

    #[cfg(target_os = "linux")]
    {
        let reaped = husker_core::reap_orphaned_vmms(&state);
        if reaped > 0 {
            tracing::info!(reaped, "reaped orphaned VMM processes from a prior run");
        }
    }

    let stale_count = state
        .mark_stale_vms_stopped()
        .context("reconciling stale VM state")?;
    if stale_count > 0 {
        tracing::info!(stale_count, "marked stale VMs as stopped");
    }

    // macOS userspace port-forward proxies do not survive a daemon restart, so
    // every persisted forward is stale. Clear them so `list` reflects reality.
    #[cfg(not(feature = "linux-net"))]
    if let Err(e) = state.clear_all_port_forwards() {
        tracing::warn!(error = %e, "failed to clear stale port forwards on startup");
    }

    #[cfg(feature = "linux-net")]
    state
        .ensure_cid_base(config.cid_base)
        .context("applying cid_base")?;

    let storage = husker_storage::StorageConfig {
        data_dir: config.data_dir,
    };

    #[cfg(feature = "linux-net")]
    {
        let (base, prefix_len) = parse_cidr(&config.bridge_subnet)?;
        let ip_allocator = husker_net::IpAllocator::new(base, prefix_len);

        // The allocator is in-memory and starts empty on each restart. Rebuild
        // its state from persisted VMs so a new allocation cannot collide with an
        // IP still recorded for an existing VM, and so releasing such an IP on
        // destroy succeeds. IPs outside this subnet (e.g. bridged-mode VMs) are
        // rejected by reserve() and skipped.
        if let Ok(vms) = state.list_vms() {
            let mut reserved = 0usize;
            for vm in &vms {
                if let Some(ip) = vm
                    .guest_ip
                    .as_deref()
                    .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
                    && ip_allocator.reserve(ip).is_ok()
                {
                    reserved += 1;
                }
            }
            if reserved > 0 {
                tracing::info!(reserved, "seeded IP allocator from persisted VMs");
            }
        }

        // Clean up any stale bridge from a previous run
        let _ = husker_net::delete_bridge(&config.bridge_name).await;

        // With our own bridge removed, any host route still overlapping the
        // configured subnet is a foreign conflict: reject it now with guidance
        // rather than silently hijacking host traffic once NAT rules go in.
        husker_net::check_subnet_conflict(
            base,
            prefix_len,
            &config.bridge_subnet,
            &config.bridge_name,
        )
        .await
        .context("checking bridge subnet for conflicts")?;

        husker_net::create_bridge(&config.bridge_name, ip_allocator.gateway(), prefix_len)
            .await
            .context("creating bridge")?;

        husker_net::init_nat(
            &config.bridge_name,
            &config.bridge_subnet,
            &config.host_interface,
        )
        .await
        .context("initializing nftables")?;

        #[cfg(target_os = "linux")]
        let core = {
            let firecracker = husker_vmm::firecracker::FirecrackerBackend::new(
                &config.firecracker_bin,
                &runtime_dir,
            );
            let qemu = husker_vmm::qemu::QemuKvmBackend::new(&config.qemu_bin, &runtime_dir);
            let default_kind = match config.vmm {
                VmmSelection::Qemu => husker_vmm::VmmKind::Qemu,
                VmmSelection::Firecracker => husker_vmm::VmmKind::Firecracker,
            };
            let vmm = husker_vmm::LinuxDispatchBackend::new(firecracker, qemu, default_kind);
            if husker::agent_embedded() {
                tracing::info!("cloud-image support enabled (guest agent embedded)");
            } else {
                tracing::info!(
                    "cloud-image support disabled (no embedded agent; run make build-agent)"
                );
            }
            Arc::new(
                husker_core::HuskerCore::new(
                    vmm,
                    state,
                    ip_allocator,
                    storage,
                    config.bridge_name.clone(),
                    config.dns_servers,
                    runtime_dir.clone(),
                )
                .with_embedded_agent(husker::EMBEDDED_AGENT)
                .with_uefi_firmware(config.ovmf_code.clone(), config.ovmf_vars.clone())
                .with_lan_bridge(config.lan_bridge.clone())
                .with_default_vmm_kind(default_kind)
                .with_default_images(
                    Some(config.default_kernel.clone()),
                    Some(config.default_rootfs.clone()),
                    config.default_initrd.clone(),
                ),
            )
        };
        #[cfg(not(target_os = "linux"))]
        let core = {
            // linux-net without target_os=linux (not a real deployment target):
            // no QEMU/vsock available, so Firecracker only.
            let vmm = husker_vmm::firecracker::FirecrackerBackend::new(
                &config.firecracker_bin,
                &runtime_dir,
            );
            Arc::new(
                husker_core::HuskerCore::new(
                    vmm,
                    state,
                    ip_allocator,
                    storage,
                    config.bridge_name.clone(),
                    config.dns_servers,
                    runtime_dir.clone(),
                )
                .with_default_images(
                    Some(config.default_kernel.clone()),
                    Some(config.default_rootfs.clone()),
                    config.default_initrd.clone(),
                ),
            )
        };
        run_linux_daemon(
            core,
            listen,
            api_token.clone(),
            service_reconcile_enabled,
            service_reconcile_interval,
        )
        .await?;

        // Network cleanup after VM drain. If the process is killed
        // (SIGKILL, panic, OOM), the stale bridge cleanup at startup above
        // handles the next launch.
        let _ = husker_net::cleanup_nat(&config.bridge_name).await;
        let _ = husker_net::delete_bridge(&config.bridge_name).await;
        Ok(())
    }

    #[cfg(all(not(feature = "linux-net"), target_os = "macos"))]
    {
        let vmm = husker_vmm::apple_vz::AppleVzBackend::new(&runtime_dir);

        let core = Arc::new(
            husker_core::HuskerCore::new(vmm, state, storage, runtime_dir.clone())
                .with_embedded_agent(husker::EMBEDDED_AGENT)
                .with_default_images(
                    Some(config.default_kernel.clone()),
                    Some(config.default_rootfs.clone()),
                    config.default_initrd.clone(),
                ),
        );

        run_initial_service_reconcile(&core).await;
        spawn_service_reconcile_loop(
            Arc::clone(&core),
            service_reconcile_enabled,
            service_reconcile_interval,
        );
        spawn_log_rotation(Arc::clone(&core));
        husker_api::serve_with_auth(Arc::clone(&core), listen, api_token).await?;
        drain_vms_on_shutdown(&core).await;
        Ok(())
    }

    #[cfg(all(not(feature = "linux-net"), not(target_os = "macos")))]
    {
        // No networking stack available (no `linux-net` feature, not macOS).
        // The API server can still run; VM operations will fail at create time
        // because no networking is configured. Primarily used by CI drills.
        let vmm = husker_vmm::firecracker::FirecrackerBackend::new(
            PathBuf::from("firecracker"),
            &runtime_dir,
        );

        let core = Arc::new(
            husker_core::HuskerCore::new(vmm, state, storage, runtime_dir.clone())
                .with_embedded_agent(husker::EMBEDDED_AGENT)
                .with_default_images(
                    Some(config.default_kernel.clone()),
                    Some(config.default_rootfs.clone()),
                    config.default_initrd.clone(),
                ),
        );

        run_initial_service_reconcile(&core).await;
        spawn_service_reconcile_loop(
            Arc::clone(&core),
            service_reconcile_enabled,
            service_reconcile_interval,
        );
        spawn_log_rotation(Arc::clone(&core));
        husker_api::serve_with_auth(Arc::clone(&core), listen, api_token).await?;
        drain_vms_on_shutdown(&core).await;
        Ok(())
    }
}

/// Run an initial service reconcile for all services, then create the ordinal index.
/// Always run on daemon startup (independent of the periodic-loop setting).
async fn run_initial_service_reconcile<B: husker_vmm::VmmBackend + 'static>(
    core: &Arc<husker_core::HuskerCore<B>>,
) {
    // Recover any source rootfs left stranded by a fork that crashed mid-load,
    // BEFORE the suspend reconcile (which can leave VMs resumable): a later
    // resume must not open a stale symlink to a fork clone.
    let recovered_disks = core.recover_stranded_fork_rootfs();
    if recovered_disks > 0 {
        tracing::info!(
            recovered_disks,
            "recovered source rootfs disks stranded by interrupted forks"
        );
    }
    // Recover any VM interrupted mid-suspend on the previous run, so a VM whose
    // memory was freed before its state write is finished to "suspended"
    // (resumable) instead of being lost. Runs on every platform branch.
    match core.reconcile_suspended_vms().await {
        Ok(n) if n > 0 => tracing::info!(reconciled = n, "recovered interrupted suspends"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "failed to reconcile interrupted suspends"),
    }
    match core.list_services() {
        Ok(services) => {
            for svc in &services {
                let o = core.reconcile_service(svc).await;
                if !o.created.is_empty() || !o.destroyed.is_empty() || !o.failed.is_empty() {
                    tracing::info!(
                        service = %svc.name,
                        created = o.created.len(),
                        destroyed = o.destroyed.len(),
                        failed = o.failed.len(),
                        "startup service reconcile"
                    );
                }
            }
        }
        Err(e) => tracing::warn!(error = %e, "failed to list services for startup reconcile"),
    }
    if let Err(e) = core.create_service_ordinal_index() {
        tracing::warn!(error = %e, "failed to create service ordinal index");
    }
}

/// Run the shared post-core daemon logic for the Linux (linux-net) path.
///
/// Runs service reconcile, restores port-forward rules, spawns background loops,
/// serves the API, and drains VMs on shutdown.
#[cfg(feature = "linux-net")]
async fn run_linux_daemon<B: husker_vmm::VmmBackend + 'static>(
    core: std::sync::Arc<husker_core::HuskerCore<B>>,
    listen: std::net::SocketAddr,
    api_token: Option<String>,
    service_reconcile_enabled: bool,
    service_reconcile_interval: u64,
) -> Result<()> {
    run_initial_service_reconcile(&core).await;
    let restored = core.reconcile_port_forwards_from_state().await;
    if restored > 0 {
        tracing::info!(restored, "restored persisted port-forward nftables rules");
    }
    spawn_service_reconcile_loop(
        std::sync::Arc::clone(&core),
        service_reconcile_enabled,
        service_reconcile_interval,
    );
    spawn_log_rotation(std::sync::Arc::clone(&core));
    husker_api::serve_with_auth(std::sync::Arc::clone(&core), listen, api_token).await?;
    drain_vms_on_shutdown(&core).await;
    Ok(())
}

/// Spawn the periodic self-healing reconcile loop (only when enabled).
fn spawn_service_reconcile_loop<B: husker_vmm::VmmBackend + 'static>(
    core: Arc<husker_core::HuskerCore<B>>,
    enabled: bool,
    interval_secs: u64,
) {
    if !enabled {
        return;
    }
    let interval = std::time::Duration::from_secs(interval_secs.max(1));
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // consume the immediate first tick
        loop {
            ticker.tick().await;
            let services = match core.list_services() {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "reconcile loop: list_services failed");
                    continue;
                }
            };
            for svc in &services {
                let o = core.reconcile_service(svc).await;
                if !o.created.is_empty() || !o.destroyed.is_empty() || !o.failed.is_empty() {
                    tracing::info!(
                        service = %svc.name,
                        created = o.created.len(),
                        destroyed = o.destroyed.len(),
                        failed = o.failed.len(),
                        "reconcile loop"
                    );
                }
            }
            // Attempt to create the unique ordinal index after reconciling all
            // services. It is idempotent (CREATE UNIQUE INDEX IF NOT EXISTS) and
            // only fails while a duplicate ordinal still exists. Each tick's
            // reconcile removes duplicates, so a later tick will succeed.
            if let Err(e) = core.create_service_ordinal_index() {
                tracing::warn!(error = %e, "reconcile loop: failed to create ordinal index");
            }
        }
    });
}

/// Spawn a background task that rotates oversized serial logs every hour.
fn spawn_log_rotation<B: husker_vmm::VmmBackend + 'static>(core: Arc<husker_core::HuskerCore<B>>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        interval.tick().await; // first tick fires immediately, skip it
        loop {
            interval.tick().await;
            let count = core.rotate_serial_logs().await;
            if count > 0 {
                tracing::info!(count, "rotated serial logs");
            }
        }
    });
}

/// Drain all running/paused VMs with a 30-second timeout.
async fn drain_vms_on_shutdown<B: husker_vmm::VmmBackend>(core: &husker_core::HuskerCore<B>) {
    tracing::info!("shutting down, draining VMs");
    match tokio::time::timeout(std::time::Duration::from_secs(30), core.drain_vms()).await {
        Ok(count) => {
            if count > 0 {
                tracing::info!(count, "drained VMs on shutdown");
            }
        }
        Err(_) => {
            tracing::warn!("VM drain timed out after 30s");
        }
    }
}

/// Default guest path the working-tree archive is uploaded to for `--sync-cwd`.
const SYNC_ARCHIVE_GUEST_PATH: &str = "/tmp/.husker-sync.tgz";
/// Default guest directory the working tree is extracted into for `--sync-cwd`.
const SYNC_WORKDIR: &str = "/work";
/// Guest path the retrieval archive (`--out`/`--write-back`) is built at.
const SYNC_OUTPUT_GUEST_PATH: &str = "/tmp/.husker-out.tgz";

/// Collect the set of files to sync into a `--sync-cwd` sandbox, relative to `dir`.
///
/// In a git repository the list is git-aware: tracked plus untracked-but-not-ignored
/// files (so gitignored build dirs like `target/` are excluded by construction). Outside
/// a git repo it falls back to every file under `dir`, skipping any `.git` directory.
fn collect_sync_paths(dir: &Path) -> Result<Vec<PathBuf>> {
    if dir.join(".git").is_dir() {
        // git-aware: tracked (--cached) plus untracked-but-not-ignored (--others
        // --exclude-standard), so gitignored build dirs are excluded by construction.
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ])
            .output()
            .context("running git ls-files for --sync-cwd")?;
        if !out.status.success() {
            anyhow::bail!(
                "git ls-files failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let mut paths: Vec<PathBuf> = out
            .stdout
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| PathBuf::from(String::from_utf8_lossy(s).into_owned()))
            .collect();
        paths.sort();
        paths.dedup();
        Ok(paths)
    } else {
        let mut paths = Vec::new();
        collect_walk(dir, dir, &mut paths)?;
        paths.sort();
        Ok(paths)
    }
}

/// Recursively collect regular files under `dir` (relative to `root`), skipping `.git`.
fn collect_walk(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            if entry.file_name() == ".git" {
                continue;
            }
            collect_walk(root, &entry.path(), out)?;
        } else if file_type.is_file()
            && let Ok(rel) = entry.path().strip_prefix(root)
        {
            out.push(rel.to_path_buf());
        }
    }
    Ok(())
}

/// Build a gzip-compressed tar archive of the `--sync-cwd` file set rooted at `dir`.
fn build_sync_archive(dir: &Path) -> Result<Vec<u8>> {
    let paths = collect_sync_paths(dir)?;
    let enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(enc);
    for rel in &paths {
        builder
            .append_path_with_name(dir.join(rel), rel)
            .with_context(|| format!("adding {} to sync archive", rel.display()))?;
    }
    let enc = builder.into_inner().context("finalizing sync tar")?;
    enc.finish().context("finalizing sync gzip")
}

/// Single-quote a string for safe inclusion in a POSIX shell script, so a path
/// can never be reinterpreted as shell syntax (`'` becomes `'\''`).
fn shell_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Wrap a user command so the guest first extracts the uploaded archive into `workdir`
/// and runs the command there. Returns the `(command, args)` for the exec request.
///
/// The archive path and workdir are husker-controlled constants; the user command is
/// passed as argv (never interpolated into the shell script) so it cannot be reparsed.
///
/// When `retrieve_paths` is non-empty, the command is run (not `exec`-ed) so that
/// afterwards the named paths are packed into `output_path` for the host to pull
/// back; the user command's exit code is preserved. Packing is best-effort (paths
/// the command did not produce are skipped). Paths are single-quoted, so `--out`
/// values cannot inject shell. busybox-safe: no `tar -T`/`--null`.
fn wrap_sync_command(
    archive_guest_path: &str,
    workdir: &str,
    command: &[String],
    output_path: &str,
    retrieve_paths: &[PathBuf],
) -> (String, Vec<String>) {
    let setup = format!(
        "set -e; mkdir -p {workdir}; tar -xzf {archive_guest_path} -C {workdir}; \
         rm -f {archive_guest_path}; cd {workdir}; "
    );
    let script = if retrieve_paths.is_empty() {
        format!("{setup}exec \"$@\"")
    } else {
        // `./`-prefix each path so a leading `-` can never look like a tar option,
        // and single-quote so `--out` values cannot inject shell.
        let quoted = retrieve_paths
            .iter()
            .map(|p| shell_single_quote(&format!("./{}", p.to_string_lossy())))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "{setup}set +e; \"$@\"; __rc=$?; \
             tar -czf {output_path} {quoted} 2>/dev/null || true; \
             exit $__rc"
        )
    };
    let mut args = vec!["-c".to_string(), script, "husker-sync".to_string()];
    args.extend(command.iter().cloned());
    ("sh".to_string(), args)
}

/// Unpack a gzip+tar archive over `dst`, returning the relative paths written.
/// Entries that would escape `dst` (absolute paths, `..`) are skipped.
fn extract_archive_over(bytes: &[u8], dst: &Path) -> Result<Vec<String>> {
    let gz = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(gz);
    let mut written = Vec::new();
    for entry in archive.entries().context("reading retrieval archive")? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if path.is_absolute()
            || path
                .components()
                .any(|c| c == std::path::Component::ParentDir)
        {
            continue;
        }
        if entry.unpack_in(dst)? {
            // Only record regular files (directories are structural).
            if entry.header().entry_type().is_file() {
                written.push(path.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    Ok(written)
}

/// The husker daemon's default listen port, used as the remote end of an
/// `ssh://` tunnel.
const SSH_REMOTE_DAEMON_PORT: u16 = 7777;

/// A parsed `ssh://[user@]host[:sshport]` daemon target.
#[derive(Debug, PartialEq, Eq)]
struct SshTarget {
    user: Option<String>,
    host: String,
    ssh_port: Option<u16>,
}

/// Parse an `ssh://[user@]host[:sshport]` API URL into its parts.
fn parse_ssh_url(url: &str) -> Result<SshTarget> {
    let rest = url
        .strip_prefix("ssh://")
        .context("API URL must start with ssh://")?;
    let (user, hostport) = match rest.split_once('@') {
        Some((u, hp)) => {
            if u.is_empty() {
                anyhow::bail!("ssh:// URL has an empty user");
            }
            (Some(u.to_string()), hp)
        }
        None => (None, rest),
    };
    let (host, ssh_port) = match hostport.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .with_context(|| format!("invalid ssh port in ssh:// URL: {p}"))?;
            (h.to_string(), Some(port))
        }
        None => (hostport.to_string(), None),
    };
    if host.is_empty() {
        anyhow::bail!("ssh:// URL is missing a host");
    }
    Ok(SshTarget {
        user,
        host,
        ssh_port,
    })
}

/// Build the `ssh` argv for a `-L` local-forward tunnel from `local_port` to the
/// remote daemon's `remote_port` on its loopback.
///
/// `control_path` enables SSH connection multiplexing: the first invocation opens
/// a master connection at that socket and later invocations reuse it, skipping the
/// handshake so a repeated `husker ... ssh://...` dev loop stays fast.
fn ssh_tunnel_args(target: &SshTarget, local_port: u16, remote_port: u16) -> Vec<String> {
    // A dedicated foreground tunnel: `-N` (no remote command) keeps the ssh
    // process alive for exactly as long as the forward is needed, so the
    // SshTunnel guard can tear it down on drop. No ControlMaster/ControlPersist:
    // a persisted master backgrounds itself and exits the foreground process with
    // status 0, which wait_ready() cannot distinguish from a failed connection.
    // LogLevel=ERROR keeps ssh's banner/MOTD chatter off our streams.
    let mut args = vec![
        "-N".to_string(),
        "-o".to_string(),
        "ExitOnForwardFailure=yes".to_string(),
        "-o".to_string(),
        "ConnectTimeout=10".to_string(),
        "-o".to_string(),
        "LogLevel=ERROR".to_string(),
        "-L".to_string(),
        format!("127.0.0.1:{local_port}:127.0.0.1:{remote_port}"),
    ];
    if let Some(p) = target.ssh_port {
        args.push("-p".to_string());
        args.push(p.to_string());
    }
    args.push(match &target.user {
        Some(u) => format!("{u}@{}", target.host),
        None => target.host.clone(),
    });
    args
}

/// PID of the live `ssh` tunnel child (`0` = none), read by the atexit hook.
static SSH_TUNNEL_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// Record the ssh tunnel's pid and install the atexit teardown hook once.
fn register_ssh_tunnel_for_atexit(pid: i32) {
    SSH_TUNNEL_PID.store(pid, std::sync::atomic::Ordering::SeqCst);
    static REGISTER: std::sync::Once = std::sync::Once::new();
    REGISTER.call_once(|| unsafe {
        libc::atexit(kill_ssh_tunnel_atexit);
    });
}

/// atexit hook: SIGKILL the ssh tunnel child if one is still recorded. husker
/// exits most paths via `std::process::exit` (to skip tokio runtime shutdown),
/// which bypasses `SshTunnel`'s `Drop`. Without this, the orphaned `ssh -N` keeps
/// husker's inherited stderr open, so a piped/captured invocation hangs on a
/// never-closing pipe (and the tunnel + forwarded port leak). `SshTunnel::drop`
/// clears the pid first, so a clean exit never targets a reused pid here.
extern "C" fn kill_ssh_tunnel_atexit() {
    let pid = SSH_TUNNEL_PID.load(std::sync::atomic::Ordering::SeqCst);
    if pid > 0 {
        // Safety: kill(2) is async-signal-safe and valid from an atexit handler.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
}

/// A live SSH local-forward tunnel to a remote husker daemon. The `ssh` child is
/// killed on drop (`kill_on_drop`), so the tunnel lives exactly as long as this
/// guard is held. A `std::process::exit` bypasses that drop, so the tunnel pid is
/// also registered for an atexit teardown (see `register_ssh_tunnel_for_atexit`).
struct SshTunnel {
    child: tokio::process::Child,
    local_port: u16,
}

impl Drop for SshTunnel {
    fn drop(&mut self) {
        // Clear the atexit pid before the Child's kill_on_drop tears ssh down, so
        // the atexit hook cannot later SIGKILL a reused pid on a clean exit.
        SSH_TUNNEL_PID.store(0, std::sync::atomic::Ordering::SeqCst);
    }
}

impl SshTunnel {
    /// Open a tunnel for an `ssh://` URL and wait until it accepts connections.
    async fn establish(url: &str) -> Result<Self> {
        let target = parse_ssh_url(url)?;
        let local_port = reserve_local_port()?;
        let args = ssh_tunnel_args(&target, local_port, SSH_REMOTE_DAEMON_PORT);
        let mut cmd = tokio::process::Command::new("ssh");
        // The tunnel produces no application output; null its stdio so a login
        // banner/MOTD never corrupts husker's stdout and a prompt can't block on
        // stdin. ssh's own errors still reach the user's terminal via stderr.
        cmd.args(&args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .kill_on_drop(true);
        let child = cmd
            .spawn()
            .context("spawning ssh for the ssh:// tunnel (is the ssh client installed?)")?;
        if let Some(pid) = child.id() {
            register_ssh_tunnel_for_atexit(pid as i32);
        }
        let mut tunnel = SshTunnel { child, local_port };
        tunnel.wait_ready().await?;
        Ok(tunnel)
    }

    async fn wait_ready(&mut self) -> Result<()> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                anyhow::bail!(
                    "ssh tunnel exited before it was ready (status {status}); \
                     check that you can `ssh` to the host and the daemon listens on \
                     127.0.0.1:{SSH_REMOTE_DAEMON_PORT}"
                );
            }
            if tokio::net::TcpStream::connect(("127.0.0.1", self.local_port))
                .await
                .is_ok()
            {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                anyhow::bail!("timed out establishing the ssh:// tunnel to the daemon");
            }
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
    }

    fn local_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.local_port)
    }
}

/// Reserve an ephemeral loopback port by binding and immediately releasing it, so
/// `ssh -L` can claim it for the forward.
fn reserve_local_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .context("reserving a local port for the ssh:// tunnel")?;
    Ok(listener.local_addr()?.port())
}

/// Human-facing phrase describing what backend a capability requires.
fn capability_requirement(cap: &str) -> &'static str {
    match cap {
        "fork" | "snapshot" => "a Firecracker backend (Linux)",
        "oci_import" => "a Linux daemon",
        "port_forward" => {
            "a daemon with port forwarding (nftables on Linux, or the userspace proxy on macOS)"
        }
        "bridged_net" => "a Linux daemon with bridged networking (linux-net build)",
        _ => "a different backend",
    }
}

/// Decide whether a command requiring capability `cap` can run against the daemon
/// described by its `/v1/health` JSON. Returns an actionable error when the daemon
/// advertises that it lacks the capability. Stays permissive (Ok) when the daemon
/// is too old to advertise capabilities, so old daemons fall through to the
/// server's own rejection instead of being blocked by the client.
fn capability_gate(health: &serde_json::Value, cap: &str) -> Result<(), String> {
    let Some(caps) = health.get("capabilities") else {
        return Ok(());
    };
    match caps.get(cap).and_then(|v| v.as_bool()) {
        Some(false) => {
            let backend = health
                .get("backend")
                .and_then(|b| b.as_str())
                .unwrap_or("unknown");
            let need = capability_requirement(cap);
            Err(format!(
                "this operation needs {need}; the daemon at the current --api-url is '{backend}', \
                 which does not support it. Point --api-url at {need}, e.g. ssh://user@linux-host."
            ))
        }
        _ => Ok(()),
    }
}

/// Fetch `/v1/health` and fail fast if the daemon advertises that it lacks the
/// capability `cap`. Best-effort: an unreachable or unparseable health response,
/// or a daemon too old to advertise capabilities, falls through so the command
/// proceeds (and the server rejects it if truly unsupported).
async fn preflight_capability(api_url: &str, api_token: Option<&str>, cap: &str) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();
    let Ok(resp) = with_api_auth(client.get(format!("{api_url}/v1/health")), api_token)
        .send()
        .await
    else {
        return Ok(());
    };
    if !resp.status().is_success() {
        return Ok(());
    }
    let Ok(health) = resp.json::<serde_json::Value>().await else {
        return Ok(());
    };
    if let Err(msg) = capability_gate(&health, cap) {
        anyhow::bail!("{msg}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::ffi::OsString;
    use std::sync::{Mutex, OnceLock};

    #[test]
    fn env_file_parses_pairs_skips_comments_and_blanks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env");
        std::fs::write(
            &path,
            "# a comment\n\nFOO=bar\n  export BAZ=qux \nTOKEN=a=b=c\n  # indented comment\nPADDED_KEY =value\n",
        )
        .unwrap();

        let pairs = load_env_files(std::slice::from_ref(&path)).unwrap();
        assert_eq!(
            pairs,
            vec![
                "FOO=bar".to_string(),
                // `export ` prefix stripped, key trimmed; value verbatim.
                "BAZ=qux".to_string(),
                // value keeps its own `=` signs.
                "TOKEN=a=b=c".to_string(),
                // key whitespace is trimmed; the value after `=` is taken as-is.
                "PADDED_KEY=value".to_string(),
            ]
        );
    }

    #[test]
    fn env_file_rejects_a_line_without_equals() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env");
        std::fs::write(&path, "FOO=bar\nNOPE\n").unwrap();
        let err = load_env_files(std::slice::from_ref(&path)).unwrap_err();
        assert!(
            err.to_string().contains("expected KEY=VALUE"),
            "malformed line must fail loudly, got: {err}"
        );
    }

    #[test]
    fn merge_env_lets_explicit_flags_override_file_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env");
        std::fs::write(&path, "SHARED=from_file\nONLY_FILE=1\n").unwrap();
        // File entries come first so a later `-e` of the same key wins in a
        // last-wins consumer.
        let merged = merge_env(
            std::slice::from_ref(&path),
            vec!["SHARED=from_flag".to_string(), "ONLY_FLAG=2".to_string()],
        )
        .unwrap();
        assert_eq!(
            merged,
            vec![
                "SHARED=from_file".to_string(),
                "ONLY_FILE=1".to_string(),
                "SHARED=from_flag".to_string(),
                "ONLY_FLAG=2".to_string(),
            ]
        );
        // The effective value in a last-wins map is the flag's.
        let map: std::collections::HashMap<_, _> =
            merged.iter().filter_map(|s| s.split_once('=')).collect();
        assert_eq!(map["SHARED"], "from_flag");
    }

    #[test]
    fn parse_secret_ref_accepts_bare_name_and_rename() {
        // Bare NAME -> env var of the same name.
        assert_eq!(
            parse_secret_ref("api_token").unwrap(),
            ("api_token".to_string(), "api_token".to_string())
        );
        // ENVVAR=secret-name -> renamed; whitespace trimmed.
        assert_eq!(
            parse_secret_ref(" API_TOKEN = gh-pat ").unwrap(),
            ("API_TOKEN".to_string(), "gh-pat".to_string())
        );
        // Errors: empty value, empty side of the rename.
        assert!(parse_secret_ref("").is_err());
        assert!(parse_secret_ref("=gh-pat").is_err());
        assert!(parse_secret_ref("API_TOKEN=").is_err());
    }

    #[test]
    fn build_secret_env_maps_envvar_to_secret_name() {
        let map =
            build_secret_env(&["TOKEN".to_string(), "DB_PASS=db-password".to_string()]).unwrap();
        assert_eq!(map.get("TOKEN").unwrap(), "TOKEN");
        assert_eq!(map.get("DB_PASS").unwrap(), "db-password");
        // The map carries only names, never values.
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn parse_add_host_splits_on_first_colon_and_validates_ip() {
        assert_eq!(
            parse_add_host("registry.local:192.0.2.10").unwrap(),
            ("registry.local".to_string(), "192.0.2.10".to_string())
        );
        // IPv6 values contain colons; the split is on the first colon only.
        assert_eq!(
            parse_add_host("db:2001:db8::1").unwrap(),
            ("db".to_string(), "2001:db8::1".to_string())
        );
        // Surrounding whitespace is trimmed.
        assert_eq!(
            parse_add_host(" host : 192.0.2.1 ").unwrap(),
            ("host".to_string(), "192.0.2.1".to_string())
        );
        // Errors: no colon, empty host, non-IP value.
        assert!(parse_add_host("noip").is_err());
        assert!(parse_add_host(":192.0.2.1").is_err());
        assert!(parse_add_host("host:not-an-ip").is_err());
    }

    #[test]
    fn validate_dns_rejects_non_ip() {
        assert!(validate_dns(&["192.0.2.1".into(), "2001:db8::1".into()]).is_ok());
        assert!(validate_dns(&["not-an-ip".into()]).is_err());
    }

    #[test]
    fn render_resolv_conf_one_nameserver_per_line() {
        assert_eq!(
            render_resolv_conf(&["192.0.2.1".into(), "192.0.2.2".into()]),
            "nameserver 192.0.2.1\nnameserver 192.0.2.2\n"
        );
        assert_eq!(render_resolv_conf(&[]), "");
    }

    #[test]
    fn merge_etc_hosts_appends_idempotently() {
        let existing = "127.0.0.1\tlocalhost\n";
        let merged = merge_etc_hosts(existing, &[("registry.local".into(), "192.0.2.10".into())]);
        assert_eq!(merged, "127.0.0.1\tlocalhost\n192.0.2.10\tregistry.local\n");

        // Re-applying the same entry does not duplicate it.
        let again = merge_etc_hosts(&merged, &[("registry.local".into(), "192.0.2.10".into())]);
        assert_eq!(again, merged);

        // A file without a trailing newline gets one before the appended entry.
        let no_newline = "127.0.0.1\tlocalhost";
        let merged = merge_etc_hosts(no_newline, &[("h".into(), "192.0.2.5".into())]);
        assert_eq!(merged, "127.0.0.1\tlocalhost\n192.0.2.5\th\n");
    }

    #[test]
    fn port_forward_add_has_bind_flag() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let pf = cmd
            .find_subcommand("port-forward")
            .expect("port-forward subcommand");
        let add = pf.find_subcommand("add").expect("add subcommand");
        assert!(
            add.get_arguments().any(|a| a.get_id() == "bind"),
            "port-forward add must expose a --bind flag"
        );
    }

    fn run_git(dir: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("git must be available for sync-cwd tests");
        assert!(status.success(), "git {args:?} failed");
    }

    fn init_repo(root: &Path) {
        run_git(root, &["init", "-q"]);
        run_git(root, &["config", "user.email", "t@example.com"]);
        run_git(root, &["config", "user.name", "t"]);
    }

    #[test]
    fn collect_sync_paths_is_git_aware() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_repo(root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/main.rs"), "fn main(){}").unwrap();
        std::fs::write(root.join("Cargo.toml"), "name=\"x\"").unwrap();
        std::fs::write(root.join(".gitignore"), "target/\n").unwrap();
        std::fs::create_dir_all(root.join("target")).unwrap();
        std::fs::write(root.join("target/junk.bin"), "x".repeat(1024)).unwrap();
        run_git(root, &["add", "src/main.rs", "Cargo.toml", ".gitignore"]);
        // an untracked-but-not-ignored file (dirty working tree)
        std::fs::write(root.join("notes.txt"), "hi").unwrap();

        let paths = collect_sync_paths(root).unwrap();
        let set: std::collections::HashSet<String> = paths
            .iter()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .collect();

        assert!(set.contains("src/main.rs"), "tracked file synced: {set:?}");
        assert!(set.contains("Cargo.toml"), "tracked file synced: {set:?}");
        assert!(
            set.contains("notes.txt"),
            "untracked-not-ignored file synced: {set:?}"
        );
        assert!(
            !set.iter().any(|p| p.starts_with("target/")),
            "gitignored build dir excluded: {set:?}"
        );
    }

    #[test]
    fn collect_sync_paths_walks_non_git_dir() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::write(root.join("a/b.txt"), "x").unwrap();
        std::fs::write(root.join("top.txt"), "y").unwrap();

        let paths = collect_sync_paths(root).unwrap();
        let set: std::collections::HashSet<String> = paths
            .iter()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .collect();
        assert!(set.contains("a/b.txt"), "nested file collected: {set:?}");
        assert!(set.contains("top.txt"), "top-level file collected: {set:?}");
    }

    #[test]
    fn build_sync_archive_excludes_gitignored() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_repo(root);
        std::fs::write(root.join("a.txt"), "hello").unwrap();
        std::fs::write(root.join(".gitignore"), "ignored.txt\n").unwrap();
        std::fs::write(root.join("ignored.txt"), "secret").unwrap();
        run_git(root, &["add", "a.txt", ".gitignore"]);

        let bytes = build_sync_archive(root).unwrap();
        assert!(!bytes.is_empty(), "archive must not be empty");
        let gz = flate2::read::GzDecoder::new(&bytes[..]);
        let mut ar = tar::Archive::new(gz);
        let names: Vec<String> = ar
            .entries()
            .unwrap()
            .map(|e| {
                e.unwrap()
                    .path()
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
                    .to_string()
            })
            .collect();
        assert!(
            names.iter().any(|n| n == "a.txt"),
            "archive contains tracked file: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n == "ignored.txt"),
            "archive excludes gitignored file: {names:?}"
        );
    }

    #[test]
    fn wrap_sync_command_untars_and_execs_in_workdir() {
        let (cmd, args) = wrap_sync_command(
            "/tmp/.husker-sync.tgz",
            "/work",
            &["cargo".to_string(), "test".to_string()],
            "/tmp/.husker-out.tgz",
            &[],
        );
        assert_eq!(cmd, "sh");
        assert_eq!(args[0], "-c");
        let script = &args[1];
        assert!(
            script.contains("tar -xzf /tmp/.husker-sync.tgz -C /work"),
            "script untars archive into workdir: {script}"
        );
        assert!(
            script.contains("cd /work"),
            "script cds into workdir: {script}"
        );
        assert!(
            script.contains("exec \"$@\""),
            "no retrieval => exec form: {script}"
        );
        // the user command trails after the $0 placeholder, passed as argv (no interpolation)
        assert_eq!(
            &args[args.len() - 2..],
            &["cargo".to_string(), "test".to_string()]
        );
    }

    #[test]
    fn wrap_sync_command_retrieves_and_preserves_exit_code() {
        let (_cmd, args) = wrap_sync_command(
            "/tmp/.husker-sync.tgz",
            "/work",
            &["cargo".to_string(), "build".to_string()],
            "/tmp/.husker-out.tgz",
            &[PathBuf::from("target/release/app"), PathBuf::from("src")],
        );
        let script = &args[1];
        // The command is run (not exec-ed) so packing can follow it.
        assert!(
            !script.contains("exec \"$@\""),
            "retrieval form runs, not execs: {script}"
        );
        assert!(
            script.contains("\"$@\"; __rc=$?"),
            "captures the command exit code: {script}"
        );
        assert!(
            script.contains("tar -czf /tmp/.husker-out.tgz "),
            "packs the output archive: {script}"
        );
        assert!(
            script.contains("'./target/release/app'"),
            "quotes the requested path: {script}"
        );
        assert!(
            script.contains("'./src'"),
            "includes every requested path: {script}"
        );
        assert!(
            script.trim_end().ends_with("exit $__rc"),
            "exits with the command's code: {script}"
        );
    }

    #[test]
    fn shell_single_quote_neutralizes_metacharacters() {
        assert_eq!(shell_single_quote("a b"), "'a b'");
        // an embedded single quote is closed, escaped, and reopened
        assert_eq!(shell_single_quote("a'b"), "'a'\\''b'");
        // shell metacharacters stay literal inside single quotes
        assert_eq!(shell_single_quote("$(rm -rf /)"), "'$(rm -rf /)'");
    }

    #[test]
    fn extract_archive_over_writes_files_into_nested_dirs() {
        // The tar crate refuses to even build a `..` entry, and its unpack also
        // blocks traversal; combined with our explicit guard, extraction stays
        // confined to the target dir. Here we verify the happy path: nested files
        // land at their relative location and are reported.
        let mut buf = Vec::new();
        {
            let enc = flate2::write::GzEncoder::new(&mut buf, flate2::Compression::default());
            let mut b = tar::Builder::new(enc);
            let data = b"hello";
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "out/app.bin", &data[..]).unwrap();
            b.into_inner().unwrap().finish().unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let written = extract_archive_over(&buf, dir.path()).unwrap();
        assert!(
            written.contains(&"out/app.bin".to_string()),
            "reports the written file: {written:?}"
        );
        let extracted = dir.path().join("out/app.bin");
        assert!(extracted.exists(), "writes nested file into the target dir");
        assert_eq!(std::fs::read(&extracted).unwrap(), b"hello");
    }
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn env_mutex() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            // SAFETY: tests hold env mutex to serialize env mutation.
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.previous {
                // SAFETY: tests hold env mutex to serialize env mutation.
                unsafe { std::env::set_var(self.key, value) };
            } else {
                // SAFETY: tests hold env mutex to serialize env mutation.
                unsafe { std::env::remove_var(self.key) };
            }
        }
    }

    fn temp_test_dir(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("husker-tests-{name}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    async fn request_single_response(
        status: &str,
        content_type: &str,
        body: &str,
    ) -> reqwest::Response {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let status = status.to_string();
        let content_type = content_type.to_string();
        let body = body.to_string();
        let body_len = body.len();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 1024];
            let _ = stream.read(&mut req).await;
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n{body}"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        reqwest::get(format!("http://{addr}/")).await.unwrap()
    }

    #[test]
    fn parse_cp_path_local() {
        assert!(
            matches!(parse_cp_path("/tmp/file.txt"), CpPath::Local(p) if p == Path::new("/tmp/file.txt"))
        );
        assert!(
            matches!(parse_cp_path("relative.txt"), CpPath::Local(p) if p == Path::new("relative.txt"))
        );
        assert!(
            matches!(parse_cp_path("./dir/file"), CpPath::Local(p) if p == Path::new("./dir/file"))
        );
    }

    #[test]
    fn parse_cp_path_vm() {
        match parse_cp_path("myvm:/tmp/file.txt") {
            CpPath::Vm { name, path } => {
                assert_eq!(name, "myvm");
                assert_eq!(path, "/tmp/file.txt");
            }
            CpPath::Local(_) => panic!("expected Vm"),
        }
    }

    #[test]
    fn parse_cp_path_vm_relative_guest_path() {
        match parse_cp_path("myvm:relative/path") {
            CpPath::Vm { name, path } => {
                assert_eq!(name, "myvm");
                assert_eq!(path, "relative/path");
            }
            CpPath::Local(_) => panic!("expected Vm"),
        }
    }

    #[test]
    fn parse_cp_path_multiple_colons() {
        match parse_cp_path("myvm:/path:with:colons") {
            CpPath::Vm { name, path } => {
                assert_eq!(name, "myvm");
                assert_eq!(path, "/path:with:colons");
            }
            CpPath::Local(_) => panic!("expected Vm"),
        }
    }

    #[test]
    fn parse_cp_path_empty_name_is_local() {
        assert!(matches!(parse_cp_path(":/tmp/file"), CpPath::Local(_)));
    }

    #[test]
    fn parse_cp_path_empty_path_is_local() {
        assert!(matches!(parse_cp_path("vmname:"), CpPath::Local(_)));
    }

    #[test]
    fn octal_mode_parsing() {
        assert_eq!(parse_octal_mode("755").unwrap(), 0o755);
        assert_eq!(parse_octal_mode("644").unwrap(), 0o644);
        assert_eq!(parse_octal_mode("777").unwrap(), 0o777);
        assert_eq!(parse_octal_mode("400").unwrap(), 0o400);
    }

    #[test]
    fn octal_mode_invalid() {
        assert!(parse_octal_mode("999").is_err());
        assert!(parse_octal_mode("abc").is_err());
        assert!(parse_octal_mode("").is_err());
    }

    #[test]
    fn output_flag_defaults_to_auto() {
        let cli = Cli::try_parse_from(["husker", "list"]).expect("cli should parse");
        assert_eq!(cli.output, OutputFormat::Auto);
    }

    #[test]
    fn output_flag_accepts_json() {
        let cli = Cli::try_parse_from(["husker", "--output", "json", "list"])
            .expect("cli should parse with json output");
        assert_eq!(cli.output, OutputFormat::Json);
    }

    #[test]
    fn parse_host_group_create_command() {
        let cli = Cli::try_parse_from([
            "husker",
            "host-group",
            "create",
            "edge",
            "--description",
            "edge workers",
        ])
        .expect("host-group create should parse");
        match cli.command {
            Commands::HostGroup {
                action: HostGroupAction::Create { name, description },
            } => {
                assert_eq!(name, "edge");
                assert_eq!(description.as_deref(), Some("edge workers"));
            }
            _ => panic!("expected host-group create command"),
        }
    }

    #[test]
    fn parse_service_create_command_with_defaults() {
        let cli =
            Cli::try_parse_from(["husker", "service", "create", "api"]).expect("service parses");
        match cli.command {
            Commands::Service {
                action:
                    ServiceAction::Create {
                        name,
                        host_group,
                        desired_instances,
                        image,
                        rootfs,
                        kernel,
                        initrd,
                        vcpus,
                        memory,
                        userdata,
                        env,
                        cloud_image,
                        disk_size,
                        balloon,
                        volume,
                    },
            } => {
                assert_eq!(name, "api");
                assert!(host_group.is_none());
                assert_eq!(desired_instances, 1);
                assert!(image.is_none());
                assert!(rootfs.is_none());
                assert!(kernel.is_none());
                assert!(initrd.is_none());
                assert!(vcpus.is_none());
                assert!(memory.is_none());
                assert!(userdata.is_none());
                assert!(env.is_empty());
                assert!(cloud_image.is_none());
                assert!(disk_size.is_none());
                assert!(!balloon);
                assert!(volume.is_none());
            }
            _ => panic!("expected service create command"),
        }
    }

    #[test]
    fn parse_service_create_command_with_options() {
        let cli = Cli::try_parse_from([
            "husker",
            "service",
            "create",
            "api",
            "--host-group",
            "default",
            "--desired-instances",
            "3",
            "--image",
            "ghcr.io/acme/api:1.2.3",
        ])
        .expect("service with options parses");
        match cli.command {
            Commands::Service {
                action:
                    ServiceAction::Create {
                        name,
                        host_group,
                        desired_instances,
                        image,
                        rootfs,
                        kernel,
                        initrd,
                        vcpus,
                        memory,
                        userdata,
                        env,
                        cloud_image,
                        disk_size,
                        balloon,
                        volume,
                    },
            } => {
                assert_eq!(name, "api");
                assert_eq!(host_group.as_deref(), Some("default"));
                assert_eq!(desired_instances, 3);
                assert_eq!(image.as_deref(), Some("ghcr.io/acme/api:1.2.3"));
                assert!(rootfs.is_none());
                assert!(cloud_image.is_none());
                assert!(disk_size.is_none());
                assert!(!balloon);
                assert!(volume.is_none());
                assert!(kernel.is_none());
                assert!(initrd.is_none());
                assert!(vcpus.is_none());
                assert!(memory.is_none());
                assert!(userdata.is_none());
                assert!(env.is_empty());
            }
            _ => panic!("expected service create command"),
        }
    }

    #[test]
    fn parse_balloon_command() {
        let cli = Cli::try_parse_from(["husker", "balloon", "myvm", "128"])
            .expect("balloon command parses");
        match cli.command {
            Commands::Balloon { name, amount_mib } => {
                assert_eq!(name, "myvm");
                assert_eq!(amount_mib, 128);
            }
            _ => panic!("expected balloon command"),
        }
    }

    #[test]
    fn parse_run_with_balloon_flag() {
        let cli = Cli::try_parse_from([
            "husker",
            "run",
            "--cloud-image",
            "/tmp/ubuntu.qcow2",
            "--balloon",
        ])
        .expect("run --balloon parses");
        match cli.command {
            Commands::Run { balloon, .. } => {
                assert!(balloon, "balloon flag should be set");
            }
            _ => panic!("expected run command"),
        }
    }

    #[test]
    fn parse_run_without_balloon_flag_defaults_false() {
        let cli = Cli::try_parse_from(["husker", "run"]).expect("run without balloon parses");
        match cli.command {
            Commands::Run { balloon, .. } => {
                assert!(!balloon, "balloon should default to false");
            }
            _ => panic!("expected run command"),
        }
    }

    #[test]
    fn parse_job_with_balloon_flag() {
        let cli = Cli::try_parse_from([
            "husker",
            "job",
            "--cloud-image",
            "/tmp/ubuntu.qcow2",
            "--balloon",
            "--",
            "echo",
            "hi",
        ])
        .expect("job --balloon parses");
        match cli.command {
            Commands::Job { balloon, .. } => {
                assert!(balloon, "balloon flag should be set");
            }
            _ => panic!("expected job command"),
        }
    }

    #[test]
    fn parse_service_create_with_cloud_image_flags() {
        let cli = Cli::try_parse_from([
            "husker",
            "service",
            "create",
            "cloudsvc",
            "--cloud-image",
            "ubuntu-2404",
            "--disk-size",
            "20G",
            "--balloon",
            "--desired-instances",
            "2",
        ])
        .expect("service create with cloud flags parses");
        match cli.command {
            Commands::Service {
                action:
                    ServiceAction::Create {
                        name,
                        cloud_image,
                        disk_size,
                        balloon,
                        desired_instances,
                        ..
                    },
            } => {
                assert_eq!(name, "cloudsvc");
                assert_eq!(cloud_image.as_deref(), Some("ubuntu-2404"));
                assert_eq!(disk_size.as_deref(), Some("20G"));
                assert!(balloon);
                assert_eq!(desired_instances, 2);
            }
            _ => panic!("expected service create command"),
        }
    }

    #[test]
    fn apply_profile_balloon_false_uses_profile_value() {
        let mut args = VmRequestArgs {
            balloon: false,
            ..VmRequestArgs::default()
        };
        let p = Profile {
            balloon: Some(true),
            ..Profile::default()
        };
        apply_profile(&mut args, &p);
        assert!(
            args.balloon,
            "profile balloon=true should fill when CLI is false"
        );
    }

    #[test]
    fn apply_profile_balloon_true_not_overridden_by_profile() {
        let mut args = VmRequestArgs {
            balloon: true,
            ..VmRequestArgs::default()
        };
        let p = Profile {
            balloon: Some(false),
            ..Profile::default()
        };
        apply_profile(&mut args, &p);
        assert!(
            args.balloon,
            "CLI balloon=true should win over profile false"
        );
    }

    #[test]
    fn apply_profile_balloon_none_in_profile_leaves_false() {
        let mut args = VmRequestArgs {
            balloon: false,
            ..VmRequestArgs::default()
        };
        let p = Profile {
            balloon: None,
            ..Profile::default()
        };
        apply_profile(&mut args, &p);
        assert!(!args.balloon, "no profile balloon should leave false");
    }

    #[test]
    fn cli_schema_balloon_command_annotated() {
        let schema = build_cli_schema();
        let cmds = schema["commands"]
            .as_array()
            .expect("commands must be an array");
        let balloon =
            find_leaf_command(cmds, "balloon").expect("balloon command must exist in schema");
        assert!(balloon.is_object());
        assert_eq!(balloon["mutating"], true, "balloon is a mutating command");
        let fields = balloon["output_fields"].as_array().unwrap();
        let field_names: Vec<&str> = fields
            .iter()
            .filter_map(|f| f.get("name").and_then(|n| n.as_str()))
            .collect();
        assert!(field_names.contains(&"status"));
        assert!(field_names.contains(&"amount_mib"));
        assert!(field_names.contains(&"vm"));
    }

    #[test]
    fn parse_service_scale_command() {
        let cli =
            Cli::try_parse_from(["husker", "service", "scale", "api", "7"]).expect("service scale");
        match cli.command {
            Commands::Service {
                action:
                    ServiceAction::Scale {
                        name,
                        desired_instances,
                    },
            } => {
                assert_eq!(name, "api");
                assert_eq!(desired_instances, 7);
            }
            _ => panic!("expected service scale command"),
        }
    }

    #[test]
    fn parse_snapshot_create_command() {
        let cli = Cli::try_parse_from(["husker", "snapshot", "create", "snap-1", "--vm", "vm-a"])
            .expect("snapshot create parses");
        match cli.command {
            Commands::Snapshot {
                action: SnapshotAction::Create { name, vm },
            } => {
                assert_eq!(name, "snap-1");
                assert_eq!(vm, "vm-a");
            }
            _ => panic!("expected snapshot create command"),
        }
    }

    #[test]
    fn parse_snapshot_restore_command() {
        let cli = Cli::try_parse_from([
            "husker",
            "snapshot",
            "restore",
            "snap-1",
            "--name",
            "restored-vm",
            "--kernel",
            "/tmp/vmlinux",
            "--cpus",
            "2",
            "--memory",
            "256",
        ])
        .expect("snapshot restore parses");
        match cli.command {
            Commands::Snapshot {
                action:
                    SnapshotAction::Restore {
                        snapshot,
                        name,
                        kernel,
                        initrd,
                        cpus,
                        memory,
                    },
            } => {
                assert_eq!(snapshot, "snap-1");
                assert_eq!(name, "restored-vm");
                assert_eq!(kernel, PathBuf::from("/tmp/vmlinux"));
                assert!(initrd.is_none());
                assert_eq!(cpus, 2);
                assert_eq!(memory, 256);
            }
            _ => panic!("expected snapshot restore command"),
        }
    }

    #[test]
    fn oci_default_image_name_derivation() {
        assert_eq!(oci_default_image_name("alpine:3.20"), "alpine-3.20");
        assert_eq!(oci_default_image_name("ghcr.io/o/img:v1"), "img-v1");
        assert_eq!(oci_default_image_name("alpine"), "alpine");
        // A digest reference must stay within the 64-char catalog name limit.
        let digest = format!("alpine@sha256:{}", "a".repeat(64));
        let name = oci_default_image_name(&digest);
        assert!(name.len() <= 48, "name too long: {} chars", name.len());
        assert!(name.starts_with("alpine-sha256-a"));
    }

    #[test]
    fn parse_image_import_command() {
        let cli = Cli::try_parse_from([
            "husker",
            "image",
            "import",
            "ubuntu-base",
            "--source",
            "/tmp/source.ext4",
            "--format",
            "ext4",
        ])
        .expect("image import parses");
        match cli.command {
            Commands::Image {
                action:
                    ImageAction::Import {
                        name,
                        source,
                        format,
                        kind,
                    },
            } => {
                assert_eq!(name, "ubuntu-base");
                assert_eq!(source, PathBuf::from("/tmp/source.ext4"));
                assert_eq!(format.as_deref(), Some("ext4"));
                assert!(kind.is_none());
            }
            _ => panic!("expected image import command"),
        }
    }

    #[test]
    fn parse_image_export_command() {
        let cli = Cli::try_parse_from([
            "husker",
            "image",
            "export",
            "ubuntu-base",
            "--destination",
            "/tmp/exported.ext4",
        ])
        .expect("image export parses");
        match cli.command {
            Commands::Image {
                action: ImageAction::Export { name, destination },
            } => {
                assert_eq!(name, "ubuntu-base");
                assert_eq!(destination, PathBuf::from("/tmp/exported.ext4"));
            }
            _ => panic!("expected image export command"),
        }
    }

    #[test]
    fn parse_secret_create_command() {
        let cli = Cli::try_parse_from([
            "husker",
            "secret",
            "create",
            "db-password",
            "--value",
            "hunter2",
        ])
        .expect("secret create parses");
        match cli.command {
            Commands::Secret {
                action: SecretAction::Create { name, value },
            } => {
                assert_eq!(name, "db-password");
                assert_eq!(value, "hunter2");
            }
            _ => panic!("expected secret create command"),
        }
    }

    #[test]
    fn parse_secret_rotate_command() {
        let cli = Cli::try_parse_from([
            "husker",
            "secret",
            "rotate",
            "db-password",
            "--value",
            "new-value",
        ])
        .expect("secret rotate parses");
        match cli.command {
            Commands::Secret {
                action: SecretAction::Rotate { name, value },
            } => {
                assert_eq!(name, "db-password");
                assert_eq!(value, "new-value");
            }
            _ => panic!("expected secret rotate command"),
        }
    }

    #[test]
    fn render_output_json_is_machine_readable() {
        let rendered = render_output(
            OutputFormat::Json,
            &serde_json::json!({
                "status": "ok",
                "vm": "test-vm",
            }),
            "ignored",
        );
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["status"], "ok");
        assert_eq!(parsed["vm"], "test-vm");
    }

    #[test]
    fn render_error_envelope_has_stable_fields() {
        let rendered = render_error_envelope("error", "boom", None);
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["error"]["kind"], "error");
        assert_eq!(parsed["error"]["message"], "boom");
        assert!(parsed["error"].get("hint").is_none());
    }

    #[test]
    fn render_error_envelope_includes_hint_when_present() {
        let rendered = render_error_envelope("not_found", "vm missing", Some("check the name"));
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["error"]["kind"], "not_found");
        assert_eq!(parsed["error"]["message"], "vm missing");
        assert_eq!(parsed["error"]["hint"], "check the name");
    }

    #[test]
    fn render_error_envelope_is_single_line_json() {
        let rendered = render_error_envelope("conflict", "already exists", None);
        assert!(!rendered.contains('\n'), "envelope must be a single line");
        serde_json::from_str::<serde_json::Value>(&rendered).expect("envelope must be valid JSON");
    }

    /// Helper: find a leaf command by name in the schema commands array.
    /// Groups have a "subcommands" key; leaves have "mutating".
    fn find_leaf_command<'a>(
        commands: &'a [serde_json::Value],
        name: &str,
    ) -> Option<&'a serde_json::Value> {
        for cmd in commands {
            if let Some(subs) = cmd.get("subcommands") {
                if let Some(subs) = subs.as_array()
                    && let Some(found) = find_leaf_command(subs, name)
                {
                    return Some(found);
                }
            } else if cmd.get("name").and_then(|n| n.as_str()) == Some(name) {
                return Some(cmd);
            }
        }
        None
    }

    #[test]
    fn cli_schema_is_well_formed() {
        let schema = build_cli_schema();
        assert_eq!(schema["name"], "husker");
        assert!(schema["version"].as_str().is_some());

        // v0.2: errors is an array; find the not_found entry.
        let errors = schema["errors"]
            .as_array()
            .expect("errors must be an array");
        let not_found = errors
            .iter()
            .find(|e| e.get("kind").and_then(|k| k.as_str()) == Some("not_found"))
            .expect("not_found error entry must exist");
        assert_eq!(not_found["exit_code"], 2);

        // v0.2: commands is an array.
        let cmds = schema["commands"]
            .as_array()
            .expect("commands must be an array");
        assert!(!cmds.is_empty());

        // Leaf commands and nested subcommands are derived from clap.
        let run_cmd = find_leaf_command(cmds, "run").expect("run command must exist");
        assert!(run_cmd.is_object());
        let schema_cmd = find_leaf_command(cmds, "schema").expect("schema command must exist");
        assert!(schema_cmd.is_object());

        // Groups appear with subcommands; "image" is a group, "pull" is its leaf.
        let image_group = cmds.iter().find(|c| {
            c.get("name").and_then(|n| n.as_str()) == Some("image")
                && c.get("subcommands").is_some()
        });
        assert!(image_group.is_some(), "image group must be in commands");
        let pull_cmd = find_leaf_command(cmds, "pull").expect("image pull command must exist");
        assert!(pull_cmd.is_object());

        // Mutating annotations: writes are mutating, getters/lists are not.
        assert_eq!(run_cmd["mutating"], true);
        assert_eq!(pull_cmd["mutating"], true);
        let list_cmd = find_leaf_command(cmds, "list").expect("list command must exist");
        assert_eq!(list_cmd["mutating"], false);
        assert_eq!(schema_cmd["mutating"], false);

        // Args are derived from clap (run takes a positional rootfs).
        let run_args = run_cmd["args"].as_array().unwrap();
        assert!(run_args.iter().any(|a| a["name"] == "rootfs"));

        // Nested commands inherit their parent's arguments: `port-forward add`
        // requires the parent VM `name` as well as its own ports.
        let pf_add = find_leaf_command(cmds, "add").expect("port-forward add must exist");
        let pf_args = pf_add["args"].as_array().unwrap();
        assert!(pf_args.iter().any(|a| a["name"] == "name"));
        assert!(pf_args.iter().any(|a| a["name"] == "host_port"));

        // Output fields annotated for core commands.
        let list_fields = list_cmd["output_fields"].as_array().unwrap();
        assert!(list_fields.iter().any(|f| f["name"] == "guest_ip"));
    }

    #[cfg(all(target_os = "linux", feature = "linux-net"))]
    #[test]
    fn firecracker_preflight_only_for_firecracker_bound_requests() {
        use serde_json::json;
        assert!(needs_firecracker_preflight(&json!({"name": "a"})));
        assert!(needs_firecracker_preflight(
            &json!({"name": "a", "vmm": "firecracker"})
        ));
        assert!(!needs_firecracker_preflight(
            &json!({"name": "a", "vmm": "qemu"})
        ));
        assert!(!needs_firecracker_preflight(
            &json!({"name": "a", "cloud_image": "/img.qcow2"})
        ));
        assert!(!needs_firecracker_preflight(
            &json!({"name": "a", "vmm": "qemu", "cloud_image": "/img.qcow2"})
        ));
    }

    #[test]
    fn cli_schema_includes_volume_get() {
        let schema = build_cli_schema();
        let cmds = schema["commands"]
            .as_array()
            .expect("commands must be an array");

        // Find the volume group, then look for "get" within it.
        let volume_group = cmds
            .iter()
            .find(|c| {
                c.get("name").and_then(|n| n.as_str()) == Some("volume")
                    && c.get("subcommands").is_some()
            })
            .expect("volume group must exist");
        let vol_subs = volume_group["subcommands"]
            .as_array()
            .expect("volume must have subcommands");
        let vol_get = find_leaf_command(vol_subs, "get").expect("volume get leaf must exist");
        assert!(vol_get.is_object());
        assert_eq!(vol_get["mutating"], false);
        let fields = vol_get["output_fields"].as_array().unwrap();
        assert!(fields.iter().any(|f| f["name"] == "volume"));
        let args = vol_get["args"].as_array().unwrap();
        assert!(args.iter().any(|a| a["name"] == "name"));
    }

    #[test]
    fn schema_includes_mutating_suspend() {
        let schema = build_cli_schema();
        let cmds = schema["commands"]
            .as_array()
            .expect("commands must be an array");
        // suspend must be present as a leaf command
        let suspend =
            find_leaf_command(cmds, "suspend").expect("suspend command must exist in schema");
        assert!(suspend.is_object());
        // suspend is a state-changing operation and must be marked mutating
        assert_eq!(suspend["mutating"], true, "suspend must be mutating");
        // suspend shares the same output_fields shape as pause/resume/stop
        let fields = suspend["output_fields"].as_array().unwrap();
        let field_names: Vec<&str> = fields
            .iter()
            .filter_map(|f| f.get("name").and_then(|n| n.as_str()))
            .collect();
        assert!(field_names.contains(&"status"));
        assert!(field_names.contains(&"action"));
        assert!(field_names.contains(&"vm"));
    }

    #[test]
    fn with_api_auth_sets_bearer_header() {
        let request = with_api_auth(
            reqwest::Client::new().get("http://example.invalid"),
            Some("secret"),
        )
        .build()
        .unwrap();
        let auth = request
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .unwrap();
        assert_eq!(auth, "Bearer secret");
    }

    #[test]
    fn with_api_auth_without_token_does_not_set_header() {
        let request = with_api_auth(reqwest::Client::new().get("http://example.invalid"), None)
            .build()
            .unwrap();
        assert!(
            request
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .is_none()
        );
    }

    #[test]
    fn daemon_bind_loopback_allowed_without_flag() {
        let listen: SocketAddr = "127.0.0.1:7777".parse().unwrap();
        assert!(validate_daemon_bind(listen, false).is_ok());
    }

    #[test]
    fn daemon_bind_non_loopback_requires_allow_remote() {
        let listen: SocketAddr = "0.0.0.0:7777".parse().unwrap();
        assert!(validate_daemon_bind(listen, false).is_err());
        assert!(validate_daemon_bind(listen, true).is_ok());
    }

    #[test]
    fn env_override_data_dir() {
        let _guard = env_mutex().lock().unwrap();
        let _env = EnvVarGuard::set("HUSKER_DATA_DIR", "/tmp/husker-env-test");
        let config = load_config(None);
        assert_eq!(config.data_dir, PathBuf::from("/tmp/husker-env-test"));
    }

    #[test]
    fn env_override_data_dir_cascades_to_default_paths() {
        let _guard = env_mutex().lock().unwrap();
        let _env = EnvVarGuard::set("HUSKER_DATA_DIR", "/tmp/husker-cascade-test");
        let config = load_config(None);
        assert_eq!(
            config.default_kernel,
            husker::default_kernel_path_for(&PathBuf::from("/tmp/husker-cascade-test"))
        );
        assert_eq!(
            config.default_rootfs,
            husker::default_rootfs_path_for(&PathBuf::from("/tmp/husker-cascade-test"))
        );
        assert_eq!(
            config.default_initrd,
            Some(husker::default_initrd_path_for(&PathBuf::from(
                "/tmp/husker-cascade-test"
            )))
        );
    }

    #[test]
    fn env_override_data_dir_preserves_explicit_default_kernel() {
        let _guard = env_mutex().lock().unwrap();
        let _vars = [
            EnvVarGuard::set("HUSKER_DATA_DIR", "/tmp/husker-cascade-test-2"),
            EnvVarGuard::set("HUSKER_DEFAULT_KERNEL", "/custom/vmlinux"),
        ];
        let config = load_config(None);
        assert_eq!(config.default_kernel, PathBuf::from("/custom/vmlinux"));
        // rootfs still cascades (it wasn't explicitly overridden)
        assert_eq!(
            config.default_rootfs,
            husker::default_rootfs_path_for(&PathBuf::from("/tmp/husker-cascade-test-2"))
        );
    }

    #[test]
    fn env_override_default_kernel() {
        let _guard = env_mutex().lock().unwrap();
        let _env = EnvVarGuard::set("HUSKER_DEFAULT_KERNEL", "/tmp/custom-kernel");
        let config = load_config(None);
        assert_eq!(config.default_kernel, PathBuf::from("/tmp/custom-kernel"));
    }

    #[test]
    fn env_override_api_token() {
        let _guard = env_mutex().lock().unwrap();
        let _env = EnvVarGuard::set("HUSKER_API_TOKEN", "test-token");
        let config = load_config(None);
        assert_eq!(config.api_token.as_deref(), Some("test-token"));
    }

    #[cfg(feature = "linux-net")]
    #[test]
    fn env_override_dns_servers_comma_separated() {
        let _guard = env_mutex().lock().unwrap();
        let _env = EnvVarGuard::set("HUSKER_DNS_SERVERS", "1.1.1.1, 8.8.4.4, 9.9.9.9");
        let config = load_config(None);
        assert_eq!(config.dns_servers, vec!["1.1.1.1", "8.8.4.4", "9.9.9.9"]);
    }

    #[test]
    fn resolve_api_token_prefers_cli_token() {
        let config_dir = temp_test_dir("resolve-api-token-cli");
        let config_path = config_dir.join("config.toml");
        std::fs::write(&config_path, "api_token = \"from-config\"\n").unwrap();

        let resolved = resolve_api_token(Some("from-cli".to_string()), Some(&config_path));
        assert_eq!(resolved.as_deref(), Some("from-cli"));
    }

    #[test]
    fn resolve_api_token_uses_config_when_cli_missing() {
        let config_dir = temp_test_dir("resolve-api-token-config");
        let config_path = config_dir.join("config.toml");
        std::fs::write(&config_path, "api_token = \"from-config\"\n").unwrap();

        let resolved = resolve_api_token(None, Some(&config_path));
        assert_eq!(resolved.as_deref(), Some("from-config"));
    }

    #[test]
    fn resolve_api_token_returns_none_when_not_set() {
        let config_dir = temp_test_dir("resolve-api-token-none");
        let config_path = config_dir.join("config.toml");
        std::fs::write(&config_path, "data_dir = \"/tmp/husker\"\n").unwrap();

        let resolved = resolve_api_token(None, Some(&config_path));
        assert!(resolved.is_none());
    }

    #[test]
    fn resolve_config_path_prefers_explicit_path() {
        let explicit = PathBuf::from("/tmp/husker-explicit-config.toml");
        assert_eq!(resolve_config_path(Some(&explicit)), explicit);
    }

    #[test]
    fn resolve_config_path_prefers_home_config_when_present() {
        let _guard = env_mutex().lock().unwrap();
        let home = temp_test_dir("resolve-home");
        let config_path = home.join(".config/husker/config.toml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        std::fs::write(&config_path, "data_dir = \"/tmp/husker-home\"\n").unwrap();
        let _home_env = EnvVarGuard::set("HOME", home.to_string_lossy().as_ref());

        assert_eq!(resolve_config_path(None), config_path);
    }

    #[test]
    fn resolve_config_path_falls_back_to_system_config() {
        let _guard = env_mutex().lock().unwrap();
        let home = temp_test_dir("resolve-system-fallback");
        let _home_env = EnvVarGuard::set("HOME", home.to_string_lossy().as_ref());
        assert_eq!(
            resolve_config_path(None),
            PathBuf::from("/etc/husker/config.toml")
        );
    }

    #[test]
    fn apply_env_overrides_parses_limits_and_lists() {
        let _guard = env_mutex().lock().unwrap();
        let _vars = [
            EnvVarGuard::set("HUSKER_API_MAX_REQUEST_BYTES", "1000"),
            EnvVarGuard::set("HUSKER_API_MAX_FILE_READ_BYTES", "2000"),
            EnvVarGuard::set("HUSKER_API_MAX_FILE_WRITE_BYTES", "3000"),
            EnvVarGuard::set("HUSKER_API_SENSITIVE_RATE_LIMIT_PER_MINUTE", "17"),
            EnvVarGuard::set("HUSKER_ALLOWED_READ_PATHS", " /etc , /var/log ,,"),
            EnvVarGuard::set("HUSKER_ALLOWED_WRITE_PATHS", "/tmp,/var/tmp"),
            EnvVarGuard::set("HUSKER_EXEC_TIMEOUT_SECS", "45"),
            EnvVarGuard::set("HUSKER_EXEC_TIMEOUT_MAX_SECS", "7200"),
            EnvVarGuard::set("HUSKER_EXEC_ALLOWLIST", "echo,cat"),
            EnvVarGuard::set("HUSKER_EXEC_DENYLIST", "rm,reboot"),
            EnvVarGuard::set("HUSKER_EXEC_ENV_ALLOWLIST", "PATH,TERM"),
        ];
        let mut config = Config::default();
        apply_env_overrides(&mut config);
        assert_eq!(config.api_max_request_bytes, 1000);
        assert_eq!(config.api_max_file_read_bytes, 2000);
        assert_eq!(config.api_max_file_write_bytes, 3000);
        assert_eq!(config.api_sensitive_rate_limit_per_minute, 17);
        assert_eq!(config.allowed_read_paths, vec!["/etc", "/var/log"]);
        assert_eq!(config.allowed_write_paths, vec!["/tmp", "/var/tmp"]);
        assert_eq!(config.exec_timeout_secs, 45);
        assert_eq!(config.exec_timeout_max_secs, 7200);
        assert_eq!(config.exec_allowlist, vec!["echo", "cat"]);
        assert_eq!(config.exec_denylist, vec!["rm", "reboot"]);
        assert_eq!(config.exec_env_allowlist, vec!["PATH", "TERM"]);
    }

    #[cfg(feature = "linux-net")]
    #[test]
    fn apply_env_overrides_parses_linux_network_fields() {
        let _guard = env_mutex().lock().unwrap();
        let _vars = [
            EnvVarGuard::set("HUSKER_FIRECRACKER_BIN", "/usr/local/bin/firecracker"),
            EnvVarGuard::set("HUSKER_HOST_INTERFACE", "ens7"),
            EnvVarGuard::set("HUSKER_BRIDGE_NAME", "husker-test"),
            EnvVarGuard::set("HUSKER_BRIDGE_SUBNET", "10.10.0.0/24"),
            EnvVarGuard::set("HUSKER_DNS_SERVERS", "9.9.9.9, 8.8.8.8"),
        ];
        let mut config = Config::default();
        apply_env_overrides(&mut config);
        assert_eq!(
            config.firecracker_bin,
            PathBuf::from("/usr/local/bin/firecracker")
        );
        assert_eq!(config.host_interface, "ens7");
        assert_eq!(config.bridge_name, "husker-test");
        assert_eq!(config.bridge_subnet, "10.10.0.0/24");
        assert_eq!(config.dns_servers, vec!["9.9.9.9", "8.8.8.8"]);
    }

    #[test]
    fn apply_env_overrides_ignores_invalid_numeric_values() {
        let _guard = env_mutex().lock().unwrap();
        let _vars = [
            EnvVarGuard::set("HUSKER_API_MAX_REQUEST_BYTES", "not-a-number"),
            EnvVarGuard::set("HUSKER_EXEC_TIMEOUT_SECS", "oops"),
        ];
        let mut config = Config::default();
        let expected_req = config.api_max_request_bytes;
        let expected_timeout = config.exec_timeout_secs;
        apply_env_overrides(&mut config);
        assert_eq!(config.api_max_request_bytes, expected_req);
        assert_eq!(config.exec_timeout_secs, expected_timeout);
    }

    #[test]
    fn service_config_defaults() {
        let cfg: Config = toml::from_str("").unwrap();
        assert_eq!(cfg.service_reconcile_interval_secs, 15);
        assert!(cfg.service_reconcile_enabled);
    }

    #[test]
    fn env_override_service_reconcile_interval() {
        let _guard = env_mutex().lock().unwrap();
        let _env = EnvVarGuard::set("HUSKER_SERVICE_RECONCILE_INTERVAL", "60");
        let mut config = Config::default();
        apply_env_overrides(&mut config);
        assert_eq!(config.service_reconcile_interval_secs, 60);
    }

    #[test]
    fn env_override_service_reconcile_enabled_false() {
        let _guard = env_mutex().lock().unwrap();
        let _env = EnvVarGuard::set("HUSKER_SERVICE_RECONCILE_ENABLED", "0");
        let mut config = Config::default();
        apply_env_overrides(&mut config);
        assert!(!config.service_reconcile_enabled);
    }

    #[test]
    fn env_override_service_reconcile_enabled_true_variants() {
        let _guard = env_mutex().lock().unwrap();
        for val in &["1", "true", "TRUE", "yes"] {
            let _env = EnvVarGuard::set("HUSKER_SERVICE_RECONCILE_ENABLED", val);
            let mut config = Config::default();
            apply_env_overrides(&mut config);
            assert!(
                config.service_reconcile_enabled,
                "expected enabled=true for HUSKER_SERVICE_RECONCILE_ENABLED={val}"
            );
        }
    }

    #[test]
    fn env_override_service_reconcile_interval_ignores_invalid() {
        let _guard = env_mutex().lock().unwrap();
        let _env = EnvVarGuard::set("HUSKER_SERVICE_RECONCILE_INTERVAL", "not-a-number");
        let mut config = Config::default();
        apply_env_overrides(&mut config);
        assert_eq!(config.service_reconcile_interval_secs, 15);
    }

    #[tokio::test]
    async fn api_request_connect_error_has_actionable_hint() {
        set_daemon_url("http://127.0.0.1:9");
        let client = reqwest::Client::new();
        let err = api_request(client.get("http://127.0.0.1:9"))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("cannot connect to daemon at http://127.0.0.1:9"),
            "expected URL in error, got: {msg}"
        );
        assert!(
            msg.contains("HUSKER_API_URL"),
            "expected HUSKER_API_URL hint in error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn api_error_prefers_message_and_hint_fields() {
        let response = request_single_response(
            "400 Bad Request",
            "application/json",
            r#"{"message":"nope","hint":"try again"}"#,
        )
        .await;
        let message = api_error(response, "running VM").await.message;
        assert_eq!(message, "nope (hint: try again)");
    }

    #[tokio::test]
    async fn api_error_falls_back_to_error_field_for_json() {
        let response = request_single_response(
            "500 Internal Server Error",
            "application/json",
            r#"{"error":"backend exploded"}"#,
        )
        .await;
        let message = api_error(response, "running VM").await.message;
        assert_eq!(message, "backend exploded");
    }

    #[tokio::test]
    async fn api_error_uses_plain_text_body_when_available() {
        let response =
            request_single_response("502 Bad Gateway", "text/plain", "gateway timeout").await;
        let message = api_error(response, "running VM").await.message;
        assert_eq!(message, "gateway timeout");
    }

    #[tokio::test]
    async fn api_error_uses_subject_for_empty_404() {
        let response = request_single_response("404 Not Found", "text/plain", "").await;
        let failure = api_error(response, "VM 'demo'").await;
        assert_eq!(failure.message, "VM 'demo' not found");
        assert_eq!(failure.exit_code, exit_code::NOT_FOUND);
    }

    #[tokio::test]
    async fn api_error_maps_status_and_code_to_exit_code() {
        let conflict = api_error(
            request_single_response(
                "409 Conflict",
                "application/json",
                r#"{"code":"vm_exists"}"#,
            )
            .await,
            "vm",
        )
        .await;
        assert_eq!(conflict.exit_code, exit_code::CONFLICT);
        assert_eq!(conflict.code.as_deref(), Some("vm_exists"));

        let denied = api_error(
            request_single_response("403 Forbidden", "text/plain", "").await,
            "vm",
        )
        .await;
        assert_eq!(denied.exit_code, exit_code::DENIED);
    }

    #[tokio::test]
    async fn api_error_uses_subject_for_empty_409() {
        let response = request_single_response("409 Conflict", "text/plain", "").await;
        let message = api_error(response, "VM 'demo'").await.message;
        assert_eq!(message, "VM 'demo' already exists");
    }

    #[tokio::test]
    async fn api_error_uses_status_for_other_empty_errors() {
        let response = request_single_response("500 Internal Server Error", "text/plain", "").await;
        let message = api_error(response, "creating VM").await.message;
        assert_eq!(message, "creating VM: 500 Internal Server Error");
    }

    #[cfg(feature = "linux-net")]
    mod cidr_tests {
        use super::super::parse_cidr;
        use std::net::Ipv4Addr;

        #[test]
        fn valid_cidr() {
            let (base, prefix) = parse_cidr("172.20.0.0/24").unwrap();
            assert_eq!(base, Ipv4Addr::new(172, 20, 0, 0));
            assert_eq!(prefix, 24);
        }

        #[test]
        fn valid_cidr_slash_16() {
            let (base, prefix) = parse_cidr("10.0.0.0/16").unwrap();
            assert_eq!(base, Ipv4Addr::new(10, 0, 0, 0));
            assert_eq!(prefix, 16);
        }

        #[test]
        fn valid_cidr_slash_30() {
            let (base, prefix) = parse_cidr("10.0.0.0/30").unwrap();
            assert_eq!(base, Ipv4Addr::new(10, 0, 0, 0));
            assert_eq!(prefix, 30);
        }

        #[test]
        fn missing_slash() {
            let err = parse_cidr("172.20.0.0").unwrap_err();
            assert!(err.to_string().contains("missing '/'"));
        }

        #[test]
        fn invalid_base_address() {
            assert!(parse_cidr("not.an.ip/24").is_err());
        }

        #[test]
        fn invalid_prefix_not_number() {
            assert!(parse_cidr("172.20.0.0/abc").is_err());
        }

        #[test]
        fn prefix_too_large() {
            let err = parse_cidr("172.20.0.0/31").unwrap_err();
            assert!(err.to_string().contains("1..=30"));
        }

        #[test]
        fn prefix_zero() {
            let err = parse_cidr("0.0.0.0/0").unwrap_err();
            assert!(err.to_string().contains("1..=30"));
        }

        #[test]
        fn base_not_network_aligned() {
            let err = parse_cidr("172.20.0.5/24").unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("not network-aligned"), "got: {msg}");
            // Should suggest the correct network address
            assert!(msg.contains("172.20.0.0/24"), "got: {msg}");
        }

        #[test]
        fn base_not_aligned_slash_16() {
            let err = parse_cidr("10.0.1.0/16").unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("not network-aligned"), "got: {msg}");
            assert!(msg.contains("10.0.0.0/16"), "got: {msg}");
        }
    }

    #[cfg(all(feature = "linux-net", target_os = "linux"))]
    #[test]
    fn vmm_selection_parses() {
        assert_eq!(VmmSelection::from_env_str("qemu"), Some(VmmSelection::Qemu));
        assert_eq!(
            VmmSelection::from_env_str("FC"),
            Some(VmmSelection::Firecracker)
        );
        assert_eq!(VmmSelection::from_env_str("xen"), None);
        assert_eq!(VmmSelection::default(), VmmSelection::Firecracker);
    }

    fn sample_profile() -> Profile {
        Profile {
            cloud_image: Some(PathBuf::from("ubuntu-2404")),
            memory: Some(2048),
            cpus: Some(2),
            disk_size: Some("10G".into()),
            ..Profile::default()
        }
    }

    #[test]
    fn profile_fills_unset_flags_only() {
        let mut args = VmRequestArgs {
            memory: Some(4096), // explicit flag wins
            ..VmRequestArgs::default()
        };
        apply_profile(&mut args, &sample_profile());
        assert_eq!(args.memory, Some(4096));
        assert_eq!(args.cpus, Some(2));
        assert_eq!(args.cloud_image, Some(PathBuf::from("ubuntu-2404")));
        assert_eq!(args.disk_size.as_deref(), Some("10G"));
    }

    #[test]
    fn profile_ssh_keys_and_env_used_when_cli_empty() {
        let mut args = VmRequestArgs {
            ssh_key: vec![PathBuf::from("/cli/key.pub")],
            ..VmRequestArgs::default()
        };
        let p = Profile {
            ssh_keys: vec![PathBuf::from("/profile/key.pub")],
            env: vec!["A=1".into()],
            ..Profile::default()
        };
        apply_profile(&mut args, &p);
        assert_eq!(args.ssh_key, vec![PathBuf::from("/cli/key.pub")]); // CLI wins
        assert_eq!(args.env, vec!["A=1".to_string()]); // profile fills empty
    }

    #[test]
    fn profile_parses_from_toml_and_rejects_unknown_keys() {
        let cfg: Config =
            toml::from_str("[profiles.sandbox]\ncloud_image = \"ubuntu-2404\"\nmemory = 2048\n")
                .unwrap();
        assert_eq!(
            cfg.profiles["sandbox"].cloud_image,
            Some(PathBuf::from("ubuntu-2404"))
        );
        assert!(
            toml::from_str::<Config>("[profiles.bad]\nnope = 1\n").is_err(),
            "unknown profile keys must be rejected"
        );
    }

    #[test]
    fn expand_tilde_expands_home_prefix() {
        let home = std::env::var("HOME").unwrap();
        assert_eq!(
            expand_tilde(Path::new("~/x.pub")),
            PathBuf::from(format!("{home}/x.pub"))
        );
        assert_eq!(
            expand_tilde(Path::new("/abs/x.pub")),
            PathBuf::from("/abs/x.pub")
        );
    }

    #[test]
    fn job_command_is_optional_and_captures_trailing_args() {
        // No trailing command parses to an empty command (run the image default).
        let cli = Cli::try_parse_from(["husker", "job", "--cloud-image", "x"])
            .expect("job parses without a trailing command (runs the image default)");
        match cli.command {
            Commands::Job { command, .. } => assert!(
                command.is_empty(),
                "an omitted command is empty, not an error"
            ),
            _ => panic!("expected Job"),
        }

        // A trailing command is captured verbatim.
        let cli = Cli::try_parse_from([
            "husker",
            "job",
            "--cloud-image",
            "x",
            "--",
            "sh",
            "-c",
            "true",
        ])
        .expect("job parses with trailing command");
        match cli.command {
            Commands::Job {
                command,
                timeout,
                keep,
                ..
            } => {
                assert_eq!(command, vec!["sh", "-c", "true"]);
                assert_eq!(timeout, 3600);
                assert!(!keep);
            }
            _ => panic!("expected Job"),
        }
    }

    #[test]
    fn exec_timeout_flag_parses() {
        let cli = Cli::try_parse_from(["husker", "exec", "vm1", "--timeout", "600", "--", "true"])
            .expect("exec parses with --timeout");
        match cli.command {
            Commands::Exec { timeout, .. } => assert_eq!(timeout, Some(600)),
            _ => panic!("expected Exec"),
        }
    }

    #[test]
    fn run_net_nat_parses() {
        let cli = Cli::try_parse_from([
            "husker",
            "run",
            "--cloud-image",
            "ubuntu.qcow2",
            "--net",
            "nat",
        ])
        .expect("run --net nat parses");
        match cli.command {
            Commands::Run { net, .. } => assert_eq!(net.as_deref(), Some("nat")),
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn run_and_job_pool_parses() {
        let run = Cli::try_parse_from(["husker", "run", "--pool", "web", "--name", "r1"])
            .expect("run --pool parses");
        match run.command {
            Commands::Run { pool, name, .. } => {
                assert_eq!(pool.as_deref(), Some("web"));
                assert_eq!(name.as_deref(), Some("r1"));
            }
            _ => panic!("expected Run"),
        }
        let job = Cli::try_parse_from(["husker", "job", "--pool", "web", "--", "echo", "hi"])
            .expect("job --pool parses");
        match job.command {
            Commands::Job { pool, command, .. } => {
                assert_eq!(pool.as_deref(), Some("web"));
                assert_eq!(command, vec!["echo", "hi"]);
            }
            _ => panic!("expected Job"),
        }
    }

    #[test]
    fn run_net_bridged_parses() {
        let cli = Cli::try_parse_from([
            "husker",
            "run",
            "--cloud-image",
            "ubuntu.qcow2",
            "--net",
            "bridged",
        ])
        .expect("run --net bridged parses");
        match cli.command {
            Commands::Run { net, .. } => assert_eq!(net.as_deref(), Some("bridged")),
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn run_net_invalid_is_rejected() {
        assert!(
            Cli::try_parse_from(["husker", "run", "--net", "invalid"]).is_err(),
            "--net with invalid value should be rejected"
        );
    }

    fn ctx(url: &str) -> ContextEntry {
        ContextEntry {
            api_url: url.to_string(),
        }
    }

    #[test]
    fn resolve_api_url_explicit_wins_over_everything() {
        let mut c = Contexts {
            current: Some("linux".into()),
            ..Default::default()
        };
        c.contexts.insert("linux".into(), ctx("ssh://ubuntu@host"));
        let u =
            resolve_effective_api_url(Some("http://192.0.2.9:7777"), Some("linux"), &c).unwrap();
        assert_eq!(u, "http://192.0.2.9:7777");
    }

    #[test]
    fn resolve_api_url_named_context() {
        let mut c = Contexts::default();
        c.contexts.insert("linux".into(), ctx("ssh://ubuntu@host"));
        let u = resolve_effective_api_url(None, Some("linux"), &c).unwrap();
        assert_eq!(u, "ssh://ubuntu@host");
    }

    #[test]
    fn resolve_api_url_uses_current_when_no_flag() {
        let mut c = Contexts {
            current: Some("mac".into()),
            ..Default::default()
        };
        c.contexts
            .insert("mac".into(), ctx("http://127.0.0.1:7777"));
        let u = resolve_effective_api_url(None, None, &c).unwrap();
        assert_eq!(u, "http://127.0.0.1:7777");
    }

    #[test]
    fn resolve_api_url_defaults_to_localhost() {
        let u = resolve_effective_api_url(None, None, &Contexts::default()).unwrap();
        assert_eq!(u, "http://127.0.0.1:7777");
    }

    #[test]
    fn resolve_api_url_unknown_named_context_errors() {
        let err = resolve_effective_api_url(None, Some("nope"), &Contexts::default()).unwrap_err();
        assert!(
            err.to_string().contains("nope"),
            "names the bad context: {err}"
        );
    }

    #[test]
    fn resolve_api_url_stale_current_falls_back() {
        let c = Contexts {
            current: Some("ghost".into()),
            ..Default::default()
        };
        let u = resolve_effective_api_url(None, None, &c).unwrap();
        assert_eq!(u, "http://127.0.0.1:7777");
    }

    #[test]
    fn contexts_roundtrip_toml() {
        let mut c = Contexts {
            current: Some("linux".into()),
            ..Default::default()
        };
        c.contexts.insert("linux".into(), ctx("ssh://ubuntu@host"));
        c.contexts
            .insert("mac".into(), ctx("http://127.0.0.1:7777"));
        let s = toml::to_string_pretty(&c).unwrap();
        let back: Contexts = toml::from_str(&s).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn capability_gate_blocks_when_unsupported() {
        let health = serde_json::json!({
            "backend": "apple_vz",
            "capabilities": { "fork": false, "snapshot": false }
        });
        let err = capability_gate(&health, "fork").unwrap_err();
        assert!(err.contains("apple_vz"), "names the current backend: {err}");
        assert!(
            err.to_lowercase().contains("firecracker"),
            "names what is needed: {err}"
        );
    }

    #[test]
    fn capability_gate_allows_when_supported() {
        let health = serde_json::json!({
            "backend": "firecracker",
            "capabilities": { "fork": true }
        });
        assert!(capability_gate(&health, "fork").is_ok());
    }

    #[test]
    fn capability_gate_is_graceful_against_old_daemon() {
        // No capabilities field (daemon too old to advertise): do not block.
        let health = serde_json::json!({ "version": "0.4.4" });
        assert!(capability_gate(&health, "fork").is_ok());
    }

    #[test]
    fn parse_ssh_url_full() {
        let t = parse_ssh_url("ssh://ubuntu@192.0.2.5:2222").unwrap();
        assert_eq!(t.user.as_deref(), Some("ubuntu"));
        assert_eq!(t.host, "192.0.2.5");
        assert_eq!(t.ssh_port, Some(2222));
    }

    #[test]
    fn parse_ssh_url_host_only() {
        let t = parse_ssh_url("ssh://host.example").unwrap();
        assert_eq!(t.user, None);
        assert_eq!(t.host, "host.example");
        assert_eq!(t.ssh_port, None);
    }

    #[test]
    fn parse_ssh_url_user_no_port() {
        let t = parse_ssh_url("ssh://ubuntu@host").unwrap();
        assert_eq!(t.user.as_deref(), Some("ubuntu"));
        assert_eq!(t.host, "host");
        assert_eq!(t.ssh_port, None);
    }

    #[test]
    fn parse_ssh_url_rejects_non_ssh_and_empty_host() {
        assert!(parse_ssh_url("http://host").is_err());
        assert!(parse_ssh_url("ssh://").is_err());
    }

    #[test]
    fn ssh_tunnel_args_builds_local_forward() {
        let t = SshTarget {
            user: Some("ubuntu".into()),
            host: "192.0.2.5".into(),
            ssh_port: Some(2222),
        };
        let args = ssh_tunnel_args(&t, 15000, 7777);
        assert!(
            args.contains(&"-N".to_string()),
            "runs without a remote command"
        );
        assert!(
            args.windows(2)
                .any(|w| w[0] == "-L" && w[1] == "127.0.0.1:15000:127.0.0.1:7777"),
            "forwards local 15000 to remote daemon: {args:?}"
        );
        assert!(
            args.windows(2).any(|w| w[0] == "-p" && w[1] == "2222"),
            "passes the ssh port: {args:?}"
        );
        assert_eq!(args.last().unwrap(), "ubuntu@192.0.2.5");
    }

    #[test]
    fn ssh_tunnel_args_is_dedicated_foreground_tunnel() {
        // Regression: ControlPersist makes ssh background the master connection and
        // exit the foreground process with status 0 as soon as the forward is up.
        // wait_ready() treats any child exit as failure ("exited before it was
        // ready"), so a persisted tunnel is misreported even though the forward
        // works. The tunnel must be a dedicated foreground `ssh -N` that lives
        // exactly as long as the SshTunnel guard (killed on drop), with no shared
        // control master to leak across invocations.
        let t = SshTarget {
            user: None,
            host: "h".into(),
            ssh_port: None,
        };
        let args = ssh_tunnel_args(&t, 100, 7777);
        assert!(
            !args.iter().any(|a| a.starts_with("ControlPersist=")),
            "must not persist a backgrounded master: {args:?}"
        );
        assert!(
            !args.iter().any(|a| a == "ControlMaster=auto"),
            "must be self-contained (no shared master): {args:?}"
        );
    }

    #[test]
    fn ssh_tunnel_args_no_user_no_port() {
        let t = SshTarget {
            user: None,
            host: "h".into(),
            ssh_port: None,
        };
        let args = ssh_tunnel_args(&t, 100, 7777);
        assert_eq!(args.last().unwrap(), "h");
        assert!(
            !args.contains(&"-p".to_string()),
            "no -p when ssh_port absent"
        );
    }

    #[test]
    fn context_add_and_use_parse() {
        let cli = Cli::try_parse_from(["husker", "context", "add", "linux", "ssh://ubuntu@host"])
            .expect("context add parses");
        match cli.command {
            Commands::Context {
                action: ContextAction::Add { name, url },
            } => {
                assert_eq!(name, "linux");
                assert_eq!(url, "ssh://ubuntu@host");
            }
            _ => panic!("expected Context::Add"),
        }

        let cli = Cli::try_parse_from(["husker", "-c", "linux", "list"])
            .expect("global --context short flag parses");
        assert_eq!(cli.context.as_deref(), Some("linux"));
    }

    #[test]
    fn job_sync_cwd_flag_parses() {
        let cli = Cli::try_parse_from(["husker", "job", "--sync-cwd", "--", "cargo", "test"])
            .expect("job --sync-cwd parses");
        match cli.command {
            Commands::Job {
                sync_cwd, command, ..
            } => {
                assert!(sync_cwd, "--sync-cwd sets the flag");
                assert_eq!(command, vec!["cargo", "test"]);
            }
            _ => panic!("expected Job"),
        }
    }

    #[test]
    fn job_sync_cwd_defaults_false() {
        let cli = Cli::try_parse_from(["husker", "job", "--", "true"]).expect("job parses");
        match cli.command {
            Commands::Job { sync_cwd, .. } => assert!(!sync_cwd, "sync_cwd defaults off"),
            _ => panic!("expected Job"),
        }
    }

    #[test]
    fn job_net_bridged_parses() {
        let cli = Cli::try_parse_from([
            "husker",
            "job",
            "--cloud-image",
            "ubuntu.qcow2",
            "--net",
            "bridged",
            "--",
            "true",
        ])
        .expect("job --net bridged parses");
        match cli.command {
            Commands::Job { net, .. } => assert_eq!(net.as_deref(), Some("bridged")),
            _ => panic!("expected Job"),
        }
    }

    #[test]
    fn profile_network_fills_when_cli_unset() {
        let mut args = VmRequestArgs::default();
        let p = Profile {
            network: Some("bridged".into()),
            ..Profile::default()
        };
        apply_profile(&mut args, &p);
        assert_eq!(args.network.as_deref(), Some("bridged"));
    }

    #[test]
    fn profile_network_cli_wins_over_profile() {
        let mut args = VmRequestArgs {
            network: Some("nat".into()),
            ..VmRequestArgs::default()
        };
        let p = Profile {
            network: Some("bridged".into()),
            ..Profile::default()
        };
        apply_profile(&mut args, &p);
        assert_eq!(args.network.as_deref(), Some("nat"));
    }

    #[test]
    fn profile_network_parses_from_toml() {
        let cfg: Config = toml::from_str(
            "[profiles.bridged-svc]\ncloud_image = \"ubuntu.qcow2\"\nnetwork = \"bridged\"\n",
        )
        .unwrap();
        assert_eq!(
            cfg.profiles["bridged-svc"].network.as_deref(),
            Some("bridged")
        );
    }

    #[test]
    fn cli_parses_repeatable_mount() {
        let cli = Cli::try_parse_from([
            "husker", "job", "--mount", "/a:/x", "--mount", "/b:/y:ro", "--", "true",
        ])
        .unwrap();
        match cli.command {
            Commands::Job { mount, .. } => {
                assert_eq!(mount, vec!["/a:/x".to_string(), "/b:/y:ro".to_string()])
            }
            _ => panic!("expected Job"),
        }
    }

    #[test]
    fn profile_fills_mounts_when_cli_empty() {
        let mut args = VmRequestArgs {
            mount: vec![],
            ..VmRequestArgs::default()
        };
        let p = Profile {
            mounts: vec!["/a:/x".into()],
            ..Profile::default()
        };
        apply_profile(&mut args, &p);
        assert_eq!(args.mount, vec!["/a:/x".to_string()]);
    }

    #[test]
    fn request_body_includes_mounts() {
        let args = VmRequestArgs {
            mount: vec!["/a:/x".into()],
            ..VmRequestArgs::default()
        };
        let body = build_vm_request_body("vm", args, None, &Config::default(), OutputFormat::Json)
            .unwrap();
        assert_eq!(body["mounts"], serde_json::json!(["/a:/x"]));
    }

    #[test]
    fn request_body_omits_mounts_when_empty() {
        let args = VmRequestArgs {
            mount: vec![],
            ..VmRequestArgs::default()
        };
        let body = build_vm_request_body("vm", args, None, &Config::default(), OutputFormat::Json)
            .unwrap();
        assert!(body.get("mounts").is_none());
    }
}
