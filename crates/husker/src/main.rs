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
#[command(name = "husker", about = "An open source microVM manager", version)]
struct Cli {
    /// Path to config file
    #[arg(long)]
    config: Option<PathBuf>,

    /// Daemon API address (for client commands)
    #[arg(long, env = "HUSKER_API_URL", default_value = "http://127.0.0.1:7777")]
    api_url: String,

    /// Bearer token for authenticated API access.
    #[arg(long)]
    api_token: Option<String>,

    /// Output format for command responses.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
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
        /// Path to rootfs ext4 image (defaults to the configured default_rootfs)
        rootfs: Option<PathBuf>,

        /// VM name
        #[arg(long)]
        name: Option<String>,

        /// Path to kernel (vmlinux)
        #[arg(long)]
        kernel: Option<PathBuf>,

        /// Path to initrd/initramfs (auto-detected if not specified)
        #[arg(long)]
        initrd: Option<PathBuf>,

        /// Number of vCPUs
        #[arg(long, default_value = "1")]
        cpus: u32,

        /// Memory in MiB
        #[arg(long, default_value = "128")]
        memory: u32,

        /// Path to userdata script to execute after VM boots
        #[arg(long)]
        userdata: Option<PathBuf>,

        /// Environment variables for userdata script (KEY=VALUE)
        #[arg(long, short = 'e')]
        env: Vec<String>,
    },

    /// List running VMs
    #[command(alias = "ls")]
    List,

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

    /// Destroy a VM and clean up resources
    #[command(alias = "rm")]
    Destroy {
        /// VM name
        name: String,
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

        /// Seconds to wait for the guest agent to become reachable before failing
        #[arg(long)]
        connect_timeout: Option<u64>,

        /// Command and arguments (after --)
        #[arg(last = true, required = true)]
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
    },

    /// Print version information (client and daemon)
    Version,

    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigAction,
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
enum PortForwardAction {
    /// Add a port forward
    Add {
        /// Host port
        host_port: u16,
        /// Guest port
        guest_port: u16,
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
    #[cfg(feature = "linux-net")]
    #[serde(default = "default_qemu_bin")]
    qemu_bin: PathBuf,
    #[serde(default = "default_data_dir")]
    data_dir: PathBuf,
    #[serde(default = "husker::default_kernel_path")]
    default_kernel: PathBuf,
    #[serde(default = "husker::default_rootfs_path")]
    default_rootfs: PathBuf,
    #[serde(default = "husker::default_initrd_some")]
    default_initrd: Option<PathBuf>,
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
    #[serde(default = "default_exec_timeout_secs")]
    exec_timeout_secs: u64,
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
    Qemu,
}

#[cfg(feature = "linux-net")]
impl VmmSelection {
    fn from_env_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "firecracker" | "fc" => Some(Self::Firecracker),
            "qemu" | "kvm" => Some(Self::Qemu),
            _ => None,
        }
    }
}

#[cfg(feature = "linux-net")]
fn default_qemu_bin() -> PathBuf {
    PathBuf::from("qemu-system-x86_64")
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
}

/// A failure to surface to the user: a human-readable `message`, an optional
/// machine-readable `code` (the daemon's stable error code), and the process
/// exit code to return. `String`/`&str` convert in as a generic error.
struct ApiFailure {
    message: String,
    code: Option<String>,
    exit_code: i32,
}

impl From<String> for ApiFailure {
    fn from(message: String) -> Self {
        Self {
            message,
            code: None,
            exit_code: exit_code::GENERAL,
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
    if format == OutputFormat::Json {
        serde_json::to_string_pretty(value).expect("json serialization should succeed")
    } else {
        text.as_ref().to_string()
    }
}

fn render_error_output(format: OutputFormat, message: &str, code: Option<&str>) -> String {
    if format == OutputFormat::Json {
        let mut obj = serde_json::Map::new();
        obj.insert("status".into(), serde_json::Value::from("error"));
        obj.insert("error".into(), serde_json::Value::from(message));
        if let Some(c) = code {
            obj.insert("code".into(), serde_json::Value::from(c));
        }
        serde_json::Value::Object(obj).to_string()
    } else {
        format!("Error: {message}")
    }
}

fn print_output<T: Serialize>(format: OutputFormat, value: &T, text: impl AsRef<str>) {
    println!("{}", render_output(format, value, text));
}

fn exit_with_error(format: OutputFormat, error: impl Into<ApiFailure>) -> ! {
    let err = error.into();
    let rendered = render_error_output(format, &err.message, err.code.as_deref());
    if format == OutputFormat::Json {
        println!("{rendered}");
    } else {
        eprintln!("{rendered}");
    }
    std::process::exit(err.exit_code);
}

/// Build the machine-readable CLI contract emitted by `husker schema`, in the
/// clispec shape used across the rest of the CLI fleet. Command names and args
/// are derived from clap so they cannot drift; mutating flags and output fields
/// are annotated here.
fn build_cli_schema() -> serde_json::Value {
    use clap::CommandFactory;
    let root = Cli::command();
    let mut commands = serde_json::Map::new();
    for sub in root.get_subcommands() {
        collect_schema_command(sub, "", &[], &mut commands);
    }
    serde_json::json!({
        "name": "husker",
        "version": env!("CARGO_PKG_VERSION"),
        "description": root.get_about().map(|s| s.to_string()).unwrap_or_default(),
        "global_flags": schema_global_flags(&root),
        "exit_codes": {
            "0": "success",
            "1": "general error",
            "2": "not found (VM, image, snapshot, secret, ...)",
            "3": "conflict or invalid state (already exists, or wrong state for the operation)",
            "4": "permission denied (token auth or exec policy)",
            "5": "daemon unreachable",
        },
        "notes": [
            "exec and shell pass through the guest command's exit code instead of the codes above.",
            "Pass --output json for machine-readable output; --output text is the default.",
            "JSON errors carry a stable `code` field when the daemon provides one.",
        ],
        "commands": serde_json::Value::Object(commands),
    })
}

/// Recursively flatten a clap command into clispec entries keyed by the full
/// command path ("image pull"). Groups (commands that only hold subcommands)
/// are not emitted; their leaves are.
fn collect_schema_command(
    cmd: &clap::Command,
    prefix: &str,
    parent_args: &[serde_json::Value],
    out: &mut serde_json::Map<String, serde_json::Value>,
) {
    let name = cmd.get_name();
    if name == "help" {
        return;
    }
    let path = if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix} {name}")
    };

    // This command's own arguments. A group (e.g. `port-forward`) can define
    // arguments (a required VM `name`) that its leaves also require, so groups
    // pass theirs down and leaves combine inherited + own.
    let own_args: Vec<serde_json::Value> = cmd
        .get_arguments()
        .filter(|a| a.get_id() != "help" && !a.is_global_set())
        .map(|a| {
            let mut o = serde_json::Map::new();
            o.insert("name".into(), serde_json::Value::from(a.get_id().as_str()));
            if let Some(help) = a.get_help() {
                o.insert(
                    "description".into(),
                    serde_json::Value::from(help.to_string()),
                );
            }
            o.insert(
                "required".into(),
                serde_json::Value::from(a.is_required_set()),
            );
            if let Some(long) = a.get_long() {
                o.insert("flag".into(), serde_json::Value::from(format!("--{long}")));
            }
            serde_json::Value::Object(o)
        })
        .collect();

    let subs: Vec<&clap::Command> = cmd
        .get_subcommands()
        .filter(|s| s.get_name() != "help")
        .collect();

    if subs.is_empty() {
        let mut args = parent_args.to_vec();
        args.extend(own_args);
        let (mutating, output_fields) = schema_command_annotations(&path);
        out.insert(
            path,
            serde_json::json!({
                "description": cmd.get_about().map(|s| s.to_string()).unwrap_or_default(),
                "args": args,
                "mutating": mutating,
                "output_fields": output_fields,
            }),
        );
    } else {
        let mut child_args = parent_args.to_vec();
        child_args.extend(own_args);
        for sub in subs {
            collect_schema_command(sub, &path, &child_args, out);
        }
    }
}

/// Top-level (global) flags for the schema, derived from the root command.
fn schema_global_flags(root: &clap::Command) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    for a in root.get_arguments() {
        let id = a.get_id().as_str();
        if id == "help" || id == "version" {
            continue;
        }
        if let Some(long) = a.get_long() {
            let key = if matches!(
                a.get_action(),
                clap::ArgAction::Set | clap::ArgAction::Append
            ) {
                format!("--{long} <{}>", id.to_uppercase())
            } else {
                format!("--{long}")
            };
            let help = a.get_help().map(|h| h.to_string()).unwrap_or_default();
            m.insert(key, serde_json::Value::from(help));
        }
    }
    serde_json::Value::Object(m)
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
            | "version"
            | "schema"
            | "config check"
            | "port-forward list"
            | "host-group list"
            | "host-group get"
            | "service list"
            | "service get"
            | "snapshot list"
            | "snapshot get"
            | "image list"
            | "image get"
            | "secret list"
            | "secret get"
            | "secret reveal"
    );
    let output_fields: Vec<&'static str> = match path {
        "run" => vec!["status", "action", "vm", "userdata_queued"],
        "list" => vec!["name", "state", "vcpu_count", "mem_size_mib", "guest_ip"],
        "info" => vec![
            "name",
            "state",
            "vcpu_count",
            "mem_size_mib",
            "guest_ip",
            "host_ip",
            "userdata_status",
            "id",
        ],
        "stop" | "pause" | "resume" | "destroy" => vec!["status", "action", "vm"],
        "exec" => vec!["exit_code", "stdout", "stderr"],
        "version" => vec!["client_version", "server_version"],
        "service create" | "service scale" => vec!["status", "action", "service", "outcome"],
        "service delete" => vec!["status", "action", "name", "outcome"],
        "service get" => vec!["status", "action", "service", "instances"],
        "service list" => vec!["status", "action", "services"],
        _ => vec![],
    };
    (!read_only, output_fields)
}

impl Default for Config {
    fn default() -> Self {
        Self {
            #[cfg(feature = "linux-net")]
            firecracker_bin: default_firecracker_bin(),
            #[cfg(feature = "linux-net")]
            vmm: VmmSelection::default(),
            #[cfg(feature = "linux-net")]
            qemu_bin: default_qemu_bin(),
            data_dir: default_data_dir(),
            default_kernel: default_kernel_path(),
            default_rootfs: default_rootfs_path(),
            default_initrd: Some(default_initrd_path()),
            images_base_url: default_images_base_url(),
            api_token: None,
            api_max_request_bytes: default_api_max_request_bytes(),
            api_max_file_read_bytes: default_api_max_file_read_bytes(),
            api_max_file_write_bytes: default_api_max_file_write_bytes(),
            api_sensitive_rate_limit_per_minute: default_api_sensitive_rate_limit_per_minute(),
            allowed_read_paths: Vec::new(),
            allowed_write_paths: Vec::new(),
            exec_timeout_secs: default_exec_timeout_secs(),
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
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("husker=info".parse().expect("static directive")),
        )
        .init();

    let cli = Cli::parse();
    let output = cli.output;
    if let Err(e) = run(cli).await {
        // A connection failure carries the DaemonUnreachable marker; everything
        // else is a generic client error. API errors (not-found/conflict/denied)
        // exit earlier via exit_with_error with their own codes. Rendered in the
        // requested format so `--output json` callers always get parseable errors.
        let (code, error_code) = if e.chain().any(|cause| cause.is::<DaemonUnreachable>()) {
            (exit_code::DAEMON_UNREACHABLE, Some("daemon_unreachable"))
        } else {
            (exit_code::GENERAL, None)
        };
        let rendered = render_error_output(output, &format!("{e:#}"), error_code);
        if output == OutputFormat::Json {
            println!("{rendered}");
        } else {
            eprintln!("{rendered}");
        }
        std::process::exit(code);
    }
}

async fn run(cli: Cli) -> Result<()> {
    let Cli {
        config: config_path,
        api_url,
        api_token: cli_api_token,
        output,
        command,
    } = cli;
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
            kernel,
            initrd,
            cpus,
            memory,
            userdata,
            env,
        } => {
            let config = load_config(config_path.as_deref());
            let api_token = cli_api_token.clone().or_else(|| config.api_token.clone());

            let rootfs = match rootfs {
                Some(path) => husker::resolve_rootfs_arg(path, &config.data_dir),
                None => {
                    let default = config.default_rootfs.clone();
                    if !default.exists() {
                        eprintln!(
                            "Default rootfs not found at {}.\nRun `husker images pull` to fetch it, or pass a rootfs path explicitly.",
                            default.display()
                        );
                        exit_with_error(output, "default rootfs not available".to_string());
                    }
                    default
                }
            };

            let kernel = match kernel {
                Some(path) => path,
                None => {
                    let default = config.default_kernel.clone();
                    if !default.exists() {
                        eprintln!(
                            "Default kernel not found at {}.\nRun `husker images pull` to fetch it, or pass --kernel explicitly.",
                            default.display()
                        );
                        exit_with_error(output, "default kernel not available".to_string());
                    }
                    default
                }
            };

            let name =
                name.unwrap_or_else(|| format!("vm-{}", &uuid::Uuid::new_v4().to_string()[..8]));

            let env_pairs: Vec<(String, String)> = env
                .iter()
                .filter_map(|s| {
                    let (k, v) = s.split_once('=')?;
                    Some((k.to_string(), v.to_string()))
                })
                .collect();

            let mut body = serde_json::json!({
                "name": name,
                "kernel_path": kernel,
                "rootfs_path": rootfs,
                "vcpu_count": cpus,
                "mem_size_mib": memory,
                "env": env_pairs,
            });
            if let Some(ref initrd_path) = initrd {
                body["initrd_path"] = serde_json::json!(initrd_path);
            } else if let Some(ref default_initrd) = config.default_initrd
                && default_initrd.exists()
            {
                body["initrd_path"] = serde_json::json!(default_initrd);
            }
            if let Some(ref userdata_path) = userdata {
                let script = std::fs::read_to_string(userdata_path).with_context(|| {
                    format!("reading userdata script {}", userdata_path.display())
                })?;
                body["userdata"] = serde_json::json!(script);
            }

            if output == OutputFormat::Text {
                let initrd_str = body
                    .get("initrd_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(none)");
                eprintln!(
                    "Using: kernel={} rootfs={} initrd={}",
                    kernel.display(),
                    rootfs.display(),
                    initrd_str,
                );
            }

            #[cfg(all(target_os = "linux", feature = "linux-net"))]
            ensure_firecracker(&config).await?;

            let client = reqwest::Client::new();
            let resp = api_request(
                with_api_auth(
                    client.post(format!("{api_url}/v1/vms")),
                    api_token.as_deref(),
                )
                .json(&body),
            )
            .await?;

            if !resp.status().is_success() {
                let mut full = api_error(resp, &format!("VM '{name}'")).await;
                if full.message.contains("already exists") {
                    full.message.push_str(&format!(
                        " (hint: stop or destroy it first with `husker destroy {name}`)"
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
            Ok(())
        }
        Commands::List => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            let client = reqwest::Client::new();
            let resp = api_request(with_api_auth(
                client.get(format!("{api_url}/v1/vms")),
                api_token.as_deref(),
            ))
            .await?;

            if !resp.status().is_success() {
                let msg = api_error(resp, "listing VMs").await;
                exit_with_error(output, msg);
            }

            let vms: Vec<serde_json::Value> = resp.json().await?;
            if output == OutputFormat::Json {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "list",
                        "vms": vms,
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
                if let Some(ip) = vm["guest_ip"].as_str() {
                    println!("Guest IP:  {ip}");
                }
                if let Some(ip) = vm["host_ip"].as_str() {
                    println!("Host IP:   {ip}");
                }
                if let Some(status) = vm["userdata_status"].as_str() {
                    println!("Userdata:  {status}");
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
        Commands::Destroy { name } => {
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
        Commands::Exec {
            name,
            workdir,
            env,
            connect_timeout,
            command,
        } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            let (cmd, args) = command.split_first().context("command required after --")?;

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
            if let Some(secs) = connect_timeout {
                body["connect_timeout_secs"] = serde_json::json!(secs);
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
        Commands::Secret { action } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            secret_command(api_url, api_token, action, output).await
        }
        Commands::Logs {
            name,
            follow,
            tail,
            userdata,
        } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            // The userdata log is a static, already-captured file, so following
            // it is meaningless; ignore --follow when --userdata is set.
            let follow = follow && !userdata;
            let mut url = format!("{api_url}/v1/vms/{name}/logs");
            let mut params = Vec::new();
            if userdata {
                params.push("userdata=true".to_string());
            }
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
        Commands::Schema => {
            println!(
                "{}",
                serde_json::to_string_pretty(&build_cli_schema()).expect("schema serializes")
            );
            Ok(())
        }
    }
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

#[cfg(not(feature = "linux-net"))]
async fn port_forward(
    _api_url: String,
    _api_token: Option<String>,
    _name: String,
    _action: PortForwardAction,
    output: OutputFormat,
) -> Result<()> {
    let message = "port forwarding is not supported on this platform (requires Linux with Firecracker + nftables; macOS uses shared NAT without inbound host mapping)";
    exit_with_error(output, message);
}

#[cfg(feature = "linux-net")]
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
        } => {
            let resp = api_request(
                with_api_auth(
                    client.post(format!("{api_url}/v1/vms/{name}/ports")),
                    api_token.as_deref(),
                )
                .json(&serde_json::json!({
                    "host_port": host_port,
                    "guest_port": guest_port,
                })),
            )
            .await?;
            if resp.status().is_success() {
                print_output(
                    output,
                    &serde_json::json!({
                        "status": "ok",
                        "action": "port-forward-add",
                        "vm": name,
                        "host_port": host_port,
                        "guest_port": guest_port,
                    }),
                    format!("Port forward added: {host_port} -> {name}:{guest_port}"),
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
                    "{:<12} {:<12} {:<10}",
                    "HOST PORT", "GUEST PORT", "PROTOCOL"
                );
                for pf in &forwards {
                    println!(
                        "{:<12} {:<12} {:<10}",
                        pf["host_port"],
                        pf["guest_port"],
                        pf["protocol"].as_str().unwrap_or("tcp"),
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
        } => {
            // Rootfs resolution precedence:
            //   1. --rootfs given: resolve through catalog (same as `husker run`)
            //   2. --image given: treat the value as a rootfs reference (path or
            //      bare image name) and resolve through the same catalog lookup
            //   3. neither: fall back to the configured default_rootfs
            let rootfs = match rootfs {
                Some(path) => husker::resolve_rootfs_arg(path, &config.data_dir),
                None => match image.as_ref().map(PathBuf::from) {
                    Some(image_path) => husker::resolve_rootfs_arg(image_path, &config.data_dir),
                    None => {
                        let default = config.default_rootfs.clone();
                        if !default.exists() {
                            eprintln!(
                                "Default rootfs not found at {}.\nRun `husker images pull` to fetch it, or pass --rootfs or --image explicitly.",
                                default.display()
                            );
                            exit_with_error(output, "default rootfs not available".to_string());
                        }
                        default
                    }
                },
            };

            let kernel = match kernel {
                Some(path) => path,
                None => {
                    let default = config.default_kernel.clone();
                    if !default.exists() {
                        eprintln!(
                            "Default kernel not found at {}.\nRun `husker images pull` to fetch it, or pass --kernel explicitly.",
                            default.display()
                        );
                        exit_with_error(output, "default kernel not available".to_string());
                    }
                    default
                }
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
                "rootfs_path": rootfs,
                "kernel_path": kernel,
                "env": env_pairs,
            });
            if let Some(group) = host_group.as_deref() {
                body["host_group"] = serde_json::json!(group);
            }
            if let Some(image_ref) = image.as_deref() {
                body["image"] = serde_json::json!(image_ref);
            }
            if let Some(ref initrd_path) = initrd {
                body["initrd_path"] = serde_json::json!(initrd_path);
            } else if let Some(ref default_initrd) = config.default_initrd
                && default_initrd.exists()
            {
                body["initrd_path"] = serde_json::json!(default_initrd);
            }
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
        } => {
            let mut body = serde_json::json!({
                "name": &name,
                "source_path": &source,
            });
            if let Some(image_format) = format.as_deref() {
                body["format"] = serde_json::json!(image_format);
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
                println!("{:<20} {:<8} {:>10}   FILE", "NAME", "FORMAT", "SIZE");
                for image in &images {
                    println!(
                        "{:<20} {:<8} {:>10}   {}",
                        image["name"].as_str().unwrap_or("-"),
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
        ImageAction::Delete { name } => {
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
    if let Ok(val) = std::env::var("HUSKER_EXEC_TIMEOUT_SECS")
        && let Ok(parsed) = val.parse::<u64>()
    {
        config.exec_timeout_secs = parsed;
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
        if let Ok(val) = std::env::var("HUSKER_QEMU_BIN") {
            config.qemu_bin = PathBuf::from(val);
        }
        if let Ok(val) = std::env::var("HUSKER_VMM")
            && let Some(sel) = VmmSelection::from_env_str(&val)
        {
            config.vmm = sel;
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
        exec_timeout_secs: config.exec_timeout_secs,
        exec_allowlist: config.exec_allowlist.clone(),
        exec_denylist: config.exec_denylist.clone(),
        exec_env_allowlist: config.exec_env_allowlist.clone(),
    };
    husker_api::set_policy(api_policy);

    std::fs::create_dir_all(&runtime_dir).context("creating runtime directory")?;
    std::fs::create_dir_all(config.data_dir.join("vms")).context("creating vms directory")?;

    let state = husker_state::StateStore::open(&db_path).context("opening state database")?;

    let stale_count = state
        .mark_stale_vms_stopped()
        .context("reconciling stale VM state")?;
    if stale_count > 0 {
        tracing::info!(stale_count, "marked stale VMs as stopped");
    }

    let storage = husker_storage::StorageConfig {
        data_dir: config.data_dir,
    };

    #[cfg(feature = "linux-net")]
    {
        let (base, prefix_len) = parse_cidr(&config.bridge_subnet)?;
        let ip_allocator = husker_net::IpAllocator::new(base, prefix_len);

        // Clean up any stale bridge from a previous run
        let _ = husker_net::delete_bridge(&config.bridge_name).await;

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

        match config.vmm {
            VmmSelection::Qemu => {
                let vmm =
                    husker_vmm::qemu::QemuKvmBackend::new(&config.qemu_bin, &runtime_dir);
                let core = Arc::new(husker_core::HuskerCore::new(
                    vmm,
                    state,
                    ip_allocator,
                    storage,
                    config.bridge_name.clone(),
                    config.dns_servers,
                    runtime_dir.clone(),
                ));
                run_linux_daemon(
                    core,
                    listen,
                    api_token.clone(),
                    service_reconcile_enabled,
                    service_reconcile_interval,
                )
                .await?;
            }
            VmmSelection::Firecracker => {
                let vmm = husker_vmm::firecracker::FirecrackerBackend::new(
                    &config.firecracker_bin,
                    &runtime_dir,
                );
                let core = Arc::new(husker_core::HuskerCore::new(
                    vmm,
                    state,
                    ip_allocator,
                    storage,
                    config.bridge_name.clone(),
                    config.dns_servers,
                    runtime_dir.clone(),
                ));
                run_linux_daemon(
                    core,
                    listen,
                    api_token.clone(),
                    service_reconcile_enabled,
                    service_reconcile_interval,
                )
                .await?;
            }
        }

        // Network cleanup after VM drain. If the process is killed
        // (SIGKILL, panic, OOM), the stale bridge cleanup at startup above
        // handles the next launch.
        let _ = husker_net::cleanup_nat().await;
        let _ = husker_net::delete_bridge(&config.bridge_name).await;
        Ok(())
    }

    #[cfg(all(not(feature = "linux-net"), target_os = "macos"))]
    {
        let vmm = husker_vmm::apple_vz::AppleVzBackend::new(&runtime_dir);

        let core = Arc::new(husker_core::HuskerCore::new(
            vmm,
            state,
            storage,
            runtime_dir.clone(),
        ));

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

        let core = Arc::new(husker_core::HuskerCore::new(
            vmm,
            state,
            storage,
            runtime_dir.clone(),
        ));

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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::ffi::OsString;
    use std::sync::{Mutex, OnceLock};
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
    fn output_flag_defaults_to_text() {
        let cli = Cli::try_parse_from(["husker", "list"]).expect("cli should parse");
        assert_eq!(cli.output, OutputFormat::Text);
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
                    },
            } => {
                assert_eq!(name, "api");
                assert_eq!(host_group.as_deref(), Some("default"));
                assert_eq!(desired_instances, 3);
                assert_eq!(image.as_deref(), Some("ghcr.io/acme/api:1.2.3"));
                assert!(rootfs.is_none());
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
                    },
            } => {
                assert_eq!(name, "ubuntu-base");
                assert_eq!(source, PathBuf::from("/tmp/source.ext4"));
                assert_eq!(format.as_deref(), Some("ext4"));
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
    fn render_error_output_json_has_stable_fields() {
        let rendered = render_error_output(OutputFormat::Json, "boom", None);
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["status"], "error");
        assert_eq!(parsed["error"], "boom");
        assert!(parsed.get("code").is_none());
    }

    #[test]
    fn render_error_output_json_includes_code_when_present() {
        let rendered = render_error_output(OutputFormat::Json, "boom", Some("vm_not_found"));
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["status"], "error");
        assert_eq!(parsed["error"], "boom");
        assert_eq!(parsed["code"], "vm_not_found");
    }

    #[test]
    fn render_error_output_text_is_prefixed() {
        let rendered = render_error_output(OutputFormat::Text, "boom", None);
        assert_eq!(rendered, "Error: boom");
    }

    #[test]
    fn cli_schema_is_well_formed() {
        let schema = build_cli_schema();
        assert_eq!(schema["name"], "husker");
        assert!(schema["version"].as_str().is_some());
        assert!(
            schema["exit_codes"]["2"]
                .as_str()
                .unwrap()
                .contains("not found")
        );

        let cmds = &schema["commands"];
        // Leaf commands and nested subcommands are derived from clap.
        assert!(cmds["run"].is_object());
        assert!(cmds["image pull"].is_object());
        assert!(cmds["schema"].is_object());
        // Groups themselves are not emitted, only their leaves.
        assert!(cmds.get("image").is_none());

        // Mutating annotations: writes are mutating, getters/lists are not.
        assert_eq!(cmds["run"]["mutating"], true);
        assert_eq!(cmds["image pull"]["mutating"], true);
        assert_eq!(cmds["list"]["mutating"], false);
        assert_eq!(cmds["schema"]["mutating"], false);
        assert_eq!(cmds["secret get"]["mutating"], false);
        assert_eq!(cmds["snapshot get"]["mutating"], false);

        // Args are derived from clap (run takes a positional rootfs).
        let run_args = cmds["run"]["args"].as_array().unwrap();
        assert!(run_args.iter().any(|a| a["name"] == "rootfs"));

        // Nested commands inherit their parent's arguments: `port-forward add`
        // requires the parent VM `name` as well as its own ports.
        let pf_args = cmds["port-forward add"]["args"].as_array().unwrap();
        assert!(pf_args.iter().any(|a| a["name"] == "name"));
        assert!(pf_args.iter().any(|a| a["name"] == "host_port"));

        // Output fields annotated for core commands.
        let list_fields = cmds["list"]["output_fields"].as_array().unwrap();
        assert!(list_fields.contains(&serde_json::json!("guest_ip")));
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

    #[cfg(feature = "linux-net")]
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
}
