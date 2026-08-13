#[cfg(test)]
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

mod cli;
mod config;
mod daemon;
mod daemon_client;
mod guest_file;
mod job;
mod schema;
mod vm_creation;

use crate::cli::*;
use crate::config::*;
use crate::daemon::*;
use crate::daemon_client::{ApiFailure, DaemonClient, DaemonUnreachable};
use crate::guest_file::{GuestFile, read_guest_file};
use crate::schema::*;
use crate::vm_creation::{
    VmCreationIntent, VmRequestArgs, fetch_daemon_profiles, plan_vm_creation,
};
#[cfg(test)]
use crate::vm_creation::{apply_profile, daemon_to_profile, profile_to_daemon};

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

/// Fetch a diagnostics report from the daemon's `GET /v1/diagnostics` endpoint.
async fn fetch_diagnostics(
    daemon: &DaemonClient,
) -> anyhow::Result<husker_core::DiagnosticsReport> {
    let resp = daemon
        .send(daemon.get("/v1/diagnostics"))
        .await?
        .error_for_status()?;
    Ok(resp.json().await?)
}

/// True when the API URL targets the local daemon, so a local probe is valid
/// as a fallback when the daemon is not running.
fn is_local_api(api_url: &str) -> bool {
    api_url.contains("127.0.0.1") || api_url.contains("localhost") || api_url.contains("[::1]")
}

/// Whether the resolved target is genuinely the LOCAL host, not a remote daemon
/// reached over an SSH tunnel. An `ssh://` context is rewritten to a
/// `127.0.0.1:<port>` tunnel URL, so `is_local_api` alone would wrongly treat a
/// remote host as local; the tunnel flag disambiguates.
fn is_local_target(api_url: &str, via_ssh_tunnel: bool) -> bool {
    is_local_api(api_url) && !via_ssh_tunnel
}

/// Commands that act on THIS machine's filesystem rather than on the daemon, and
/// so cannot honour `--context`/`--api-url`. Returns the refusal message when the
/// command is host-local, `None` when it is safe against any target.
///
/// Without this, a host-local command run against a remote context reports success
/// while having written to the local machine, which is indistinguishable from
/// having done the remote work. Refusing is the only honest answer: the flag is
/// unsupported here, not silently ignored.
fn host_local_refusal(command: &Commands) -> Option<String> {
    match command {
        Commands::Setup {
            action: SetupAction::Storage { .. },
        } => Some("setup storage runs on the daemon host; ssh to it and run there".to_string()),
        Commands::Image {
            action: ImageAction::Pull { .. },
        } => Some(format!(
            "image pull downloads into THIS machine's husker data dir and cannot target a remote \
             context; ssh to the daemon host and run it there (destinations: {}, {})",
            load_config(None).default_kernel.display(),
            husker::default_rootfs_path().display(),
        )),
        _ => None,
    }
}

/// Map a diagnostics report to a process exit code: 1 on any hard failure,
/// 0 otherwise (warnings are reported but do not fail).
fn doctor_exit_code(report: &husker_core::DiagnosticsReport) -> i32 {
    if report.has_failure() {
        exit_code::GENERAL
    } else {
        0
    }
}

/// Render a diagnostics report as `[ok/warn/FAIL] name: message` lines (text)
/// or a JSON array (JSON format).
fn render_diagnostics(report: &husker_core::DiagnosticsReport, format: OutputFormat) {
    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(report).unwrap());
        return;
    }
    for c in &report.checks {
        let tag = match c.status {
            husker_core::CheckStatus::Ok => "ok  ",
            husker_core::CheckStatus::Warn => "warn",
            husker_core::CheckStatus::Fail => "FAIL",
        };
        println!("[{tag}] {}: {}", c.name, c.message);
    }
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
pub(crate) async fn serial_boot_hint(daemon: &DaemonClient, name: &str) -> String {
    let path = format!("/v1/vms/{name}/logs?source=serial&tail=20");
    let body = match daemon.try_send(daemon.get(path)).await {
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
pub(crate) async fn apply_dns_hosts(
    daemon: &DaemonClient,
    name: &str,
    dns: &[String],
    add_host: &[(String, String)],
) -> anyhow::Result<()> {
    if !dns.is_empty() {
        write_guest_file(
            daemon,
            name,
            "/etc/resolv.conf",
            render_resolv_conf(dns).as_bytes(),
        )
        .await?;
    }
    if !add_host.is_empty() {
        let existing = read_guest_file_or_empty(daemon, name, "/etc/hosts")
            .await
            .unwrap_or_default();
        let merged = merge_etc_hosts(&existing, add_host);
        write_guest_file(daemon, name, "/etc/hosts", merged.as_bytes()).await?;
    }
    Ok(())
}

/// Poll a VM's `/ready` endpoint until it reports ready or the deadline passes.
/// Returns `Ok(true)` when ready, `Ok(false)` on timeout, and `Err` if the VM is
/// gone or the daemon errors.
async fn wait_for_vm_ready(
    daemon: &DaemonClient,
    name: &str,
    timeout: std::time::Duration,
) -> anyhow::Result<bool> {
    let ready_path = format!("/v1/vms/{name}/ready");
    let deadline = std::time::Instant::now() + timeout;
    let mut backoff = std::time::Duration::from_millis(200);
    loop {
        let resp = daemon.send(daemon.get(&ready_path)).await?;
        if !resp.status().is_success() {
            let msg = daemon.error(resp, &format!("VM '{name}'")).await;
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
    daemon: &DaemonClient,
    name: &str,
    path: &str,
    data: &[u8],
) -> anyhow::Result<()> {
    let body = serde_json::json!({
        "path": path,
        "data": husker_agent_proto::base64_encode(data),
    });
    let resp = daemon
        .send(
            daemon
                .post(format!("/v1/vms/{name}/files/write"))
                .json(&body),
        )
        .await?;
    if !resp.status().is_success() {
        let msg = daemon.error(resp, &format!("VM '{name}'")).await;
        anyhow::bail!("writing {path}: {}", msg.message);
    }
    Ok(())
}

/// Read `path` from a VM via the guest file API, returning an empty string if the
/// file does not exist yet (so a fresh `/etc/hosts` merges cleanly).
async fn read_guest_file_or_empty(
    daemon: &DaemonClient,
    name: &str,
    path: &str,
) -> anyhow::Result<String> {
    let resp = daemon
        .send(
            daemon
                .post(format!("/v1/vms/{name}/files/read"))
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
        .kind
        .as_deref()
        .unwrap_or_else(|| exit_code_to_kind(err.exit_code));
    // The structured error envelope is always written to stderr as the last line.
    // Human-readable text mode also puts errors on stderr (no stdout pollution).
    let structured = render_error_envelope(kind, &err.message, err.hint.as_deref());
    if resolve_format(format) == OutputFormat::Json {
        eprintln!("{structured}");
    } else {
        eprintln!("Error: {}", err.message);
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
                kind: Some("confirmation_required".into()),
                exit_code: exit_code::CONFIRMATION_REQUIRED,
                hint: Some("Re-run with --yes to confirm.".into()),
            },
        );
    }
}

/// Bytes available to a non-privileged writer on the fs backing `path`.
fn available_bytes_for(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

/// Total apparent size of `path` (best-effort recursive sum; 0 if unreadable).
fn dir_usage_bytes(path: &Path) -> u64 {
    fn walk(p: &Path, acc: &mut u64) {
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                let Ok(ft) = e.file_type() else { continue };
                if ft.is_dir() {
                    walk(&e.path(), acc);
                } else if let Ok(m) = e.metadata() {
                    *acc += m.len();
                }
            }
        }
    }
    let mut acc = 0;
    walk(path, &mut acc);
    acc
}

/// Whether an executable is on PATH (with an execute bit).
fn which_on_path(name: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|d| {
                let p = d.join(name);
                std::fs::metadata(&p)
                    .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// The managed config file the migration script edits: the first existing of
/// the discovery order, else the system default.
fn config_path_or_default() -> PathBuf {
    let user = dirs_config_husker();
    if user.exists() {
        return user;
    }
    PathBuf::from("/etc/husker/config.toml")
}

/// `~/.config/husker/config.toml`.
fn dirs_config_husker() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join(".config/husker/config.toml")
}

/// Derive a default catalog image name from an OCI reference: the last path
/// component with its tag, sanitized (e.g. `alpine:3.20` -> `alpine-3.20`,
/// `ghcr.io/o/img:v1` -> `img-v1`).
///
/// An `oci://` prefix yields the same name as the bare reference: the scheme
/// ends in `/`, so the `rsplit` below already drops it. That matters because
/// `image list` reports `source_path` as `oci://<ref>` and users feed it back
/// to `import-oci`; it is enforced by
/// `oci_scheme_does_not_reach_the_default_image_name` rather than left to the
/// reader to re-derive.
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

/// Compatibility helper for focused body tests. Production commands use the
/// complete intent-to-plan seam; this keeps the existing request assertions on
/// the same resolver without recreating its policy in `main.rs`.
#[cfg(test)]
fn build_vm_request_body(
    name: &str,
    args: VmRequestArgs,
    profile: Option<&str>,
    profiles: &std::collections::HashMap<String, Profile>,
    origins: &std::collections::HashMap<String, ProfileOrigin>,
    config: &Config,
    output: OutputFormat,
) -> anyhow::Result<serde_json::Value> {
    let built =
        crate::vm_creation::build_vm_request(name, args, profile, profiles, origins, config, true)?;
    for diagnostic in &built.diagnostics {
        diagnostic.report(output);
    }
    Ok(serde_json::to_value(built.body)?)
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

    if matches!(&command, Commands::Schema) {
        println!(
            "{}",
            serde_json::to_string_pretty(&build_cli_schema()).expect("schema serializes")
        );
        return Ok(());
    }
    if matches!(&command, Commands::Capabilities) {
        let capabilities = serde_json::json!({
            "name": "husker",
            "version": env!("CARGO_PKG_VERSION"),
            "clispec": "0.3",
            "output": ["text", "json"],
            "features": ["schema", "pagination", "field selection", "offline introspection"]
        });
        if output == OutputFormat::Json {
            println!(
                "{}",
                serde_json::to_string_pretty(&capabilities).expect("capabilities serialize")
            );
        } else {
            println!(
                "husker {} - clispec 0.3; text/json output, pagination, field selection",
                env!("CARGO_PKG_VERSION")
            );
        }
        return Ok(());
    }

    // Context management is local-only; handle it before resolving a daemon URL.
    if let Commands::Context { action } = command {
        return context_command(action, output);
    }

    // Resolve the daemon target: explicit --api-url/HUSKER_API_URL, else the
    // selected/current saved context, else the local default.
    let api_url =
        resolve_effective_api_url(api_url.as_deref(), context.as_deref(), &load_contexts())?;

    // Host-local operations read and write THIS machine's data dir. Refuse a
    // remote/ssh context up front, before we open a tunnel or touch any local
    // path, so the error is clean and nothing is written to the wrong host.
    let targets_remote_host = api_url.starts_with("ssh://") || !is_local_api(&api_url);
    if targets_remote_host && let Some(msg) = host_local_refusal(&command) {
        exit_with_error(output, msg);
    }

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
    // Remote-over-ssh: the tunnel URL is localhost, so `is_local_api` would
    // misclassify it. This flag lets `is_local_target` treat it as remote.
    let via_ssh_tunnel = _ssh_tunnel.is_some();
    match command {
        Commands::Daemon {
            listen,
            allow_remote,
        } => {
            let mut config = load_config_strict(config_path.as_deref())?;
            if let Some(token) = cli_api_token.clone() {
                config.api_token = Some(token);
            }
            validate_daemon_bind(listen, allow_remote, config.api_token.is_some())?;
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
            idle,
            idle_timeout,
            suspend_ttl,
            no_auto_resume,
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

            let client = DaemonClient::new(&api_url, api_token.clone());
            let userdata_queued = userdata.is_some();
            let mut extra_pool_conflicts = Vec::new();
            if !dns.is_empty() {
                extra_pool_conflicts.push("--dns");
            }
            if !add_host.is_empty() {
                extra_pool_conflicts.push("--add-host");
            }
            let plan = match plan_vm_creation(
                &client,
                &config,
                VmCreationIntent {
                    name: name.clone(),
                    pool,
                    profile,
                    args: VmRequestArgs {
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
                        idle,
                        idle_timeout_secs: idle_timeout,
                        suspend_ttl_secs: suspend_ttl,
                        auto_resume: if no_auto_resume { Some(false) } else { None },
                        volume,
                        mount,
                        network: net,
                    },
                    userdata,
                    extra_pool_conflicts,
                },
                is_local_target(&api_url, via_ssh_tunnel),
            )
            .await
            {
                Ok(plan) => plan,
                Err(error) => exit_with_error(output, error.to_string()),
            };
            plan.report_diagnostics(output);
            let plan = plan.prepare(&config).await?;
            let resp = plan.execute(&client).await?;

            if !resp.status().is_success() {
                let mut full = client.error(resp, &format!("VM '{name}'")).await;
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
                        "userdata_queued": userdata_queued,
                    }),
                    "",
                );
            } else {
                println!("Created VM: {}", vm["name"].as_str().unwrap_or("-"));
                println!("  ID:    {}", vm["id"].as_str().unwrap_or("-"));
                println!("  State: {}", vm["state"].as_str().unwrap_or("-"));
                println!("  CPUs:  {}", vm["vcpu_count"]);
                println!("  RAM:   {} MiB", vm["mem_size_mib"]);

                if userdata_queued {
                    println!("  Userdata script queued (check status with `husker info {name}`)");
                }
            }

            // Apply per-VM DNS / host overrides once the agent is reachable. Only
            // waits for readiness when these flags are set, so a plain `run` stays
            // non-blocking.
            if !dns.is_empty() || !add_host.is_empty() {
                let boot_mode = vm
                    .get("boot_mode")
                    .and_then(|b| b.as_str())
                    .unwrap_or("direct");
                let ready = wait_for_vm_ready(
                    &client,
                    &name,
                    husker_core::default_ready_timeout(boot_mode),
                )
                .await?;
                if !ready {
                    let hint = serial_boot_hint(&client, &name).await;
                    anyhow::bail!(
                        "VM '{name}' did not become ready to apply --dns/--add-host{hint}"
                    );
                }
                apply_dns_hosts(&client, &name, &dns, &add_host).await?;
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
            let client = DaemonClient::new(&api_url, api_token.clone());
            let mut url = format!("/v1/vms?limit={limit}&offset={offset}");
            if let Some(ref f) = fields {
                url.push_str(&format!("&fields={}", f));
            }
            // When the daemon is unreachable, return an empty list so agents and
            // scripts get a valid, paginatable response instead of a hard error.
            // A diagnostic message goes to stderr.
            let resp_result = client.send(client.get(&url)).await;
            let mut daemon_reachable = true;
            let vms: Vec<serde_json::Value> = match resp_result {
                Err(ref e) if e.chain().any(|c| c.is::<DaemonUnreachable>()) => {
                    eprintln!(
                        "daemon not reachable; showing empty list (start with `husker daemon`)"
                    );
                    daemon_reachable = false;
                    vec![]
                }
                Err(e) => return Err(e),
                Ok(resp) => {
                    if !resp.status().is_success() {
                        let msg = client.error(resp, "listing VMs").await;
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
                        // false only when the daemon was unreachable, so callers can
                        // tell an outage (empty list) apart from a genuinely empty fleet.
                        "daemon_reachable": daemon_reachable,
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
            let client = DaemonClient::new(&api_url, api_token.clone());
            let resp = client.send(client.get(format!("/v1/vms/{name}"))).await?;

            if !resp.status().is_success() {
                let msg = client.error(resp, &format!("VM '{name}'")).await;
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
            let client = DaemonClient::new(&api_url, api_token.clone());
            let resp = client
                .send(client.post(format!("/v1/vms/{name}/stop")))
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
                let mut msg = client.error(resp, &format!("VM '{name}'")).await;
                if msg.message.contains("stopped") {
                    msg.message.push_str(" (hint: VM is already stopped)");
                }
                exit_with_error(output, msg);
            }
            Ok(())
        }
        Commands::Pause { name } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            let client = DaemonClient::new(&api_url, api_token.clone());
            let resp = client
                .send(client.post(format!("/v1/vms/{name}/pause")))
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
                let mut msg = client.error(resp, &format!("VM '{name}'")).await;
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
            let client = DaemonClient::new(&api_url, api_token.clone());
            let resp = client
                .send(client.post(format!("/v1/vms/{name}/resume")))
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
                let mut msg = client.error(resp, &format!("VM '{name}'")).await;
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
            let client = DaemonClient::new(&api_url, api_token.clone());
            let resp = client
                .send(client.post(format!("/v1/vms/{name}/suspend")))
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
                let mut msg = client.error(resp, &format!("VM '{name}'")).await;
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
            let client = DaemonClient::new(&api_url, api_token.clone());
            let resp = client
                .send(
                    client
                        .post(format!("/v1/vms/{source}/fork"))
                        .json(&serde_json::json!({ "fork_name": fork_name })),
                )
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
                let msg = client.error(resp, &format!("VM '{source}'")).await;
                exit_with_error(output, msg);
            }
            Ok(())
        }
        Commands::Destroy { name, yes } => {
            require_confirmation(&format!("Destroy VM '{name}'?"), yes, output);

            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            let client = DaemonClient::new(&api_url, api_token.clone());
            let resp = client
                .send(client.delete(format!("/v1/vms/{name}")))
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
                let msg = client.error(resp, &format!("VM '{name}'")).await;
                exit_with_error(output, msg);
            }
            Ok(())
        }
        Commands::Balloon { name, amount_mib } => {
            let api_token = resolve_api_token(cli_api_token.clone(), config_path.as_deref());
            let client = DaemonClient::new(&api_url, api_token.clone());
            let body = serde_json::json!({ "amount_mib": amount_mib });
            let resp = client
                .send(client.put(format!("/v1/vms/{name}/balloon")).json(&body))
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
                let msg = client.error(resp, &format!("VM '{name}'")).await;
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

            let client = DaemonClient::new(&api_url, api_token.clone());
            let resp = client
                .send(client.post(format!("/v1/vms/{name}/exec")).json(&body))
                .await?;

            if !resp.status().is_success() {
                let msg = client.error(resp, &format!("VM '{name}'")).await;
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
            idle,
            idle_timeout,
            suspend_ttl,
            no_auto_resume,
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

            let client = DaemonClient::new(&api_url, api_token.clone());
            let plan = match plan_vm_creation(
                &client,
                &config,
                VmCreationIntent {
                    name: name.clone(),
                    pool,
                    profile,
                    args: VmRequestArgs {
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
                        idle,
                        idle_timeout_secs: idle_timeout,
                        suspend_ttl_secs: suspend_ttl,
                        auto_resume: if no_auto_resume { Some(false) } else { None },
                        volume,
                        mount,
                        network: net,
                    },
                    userdata: None,
                    extra_pool_conflicts: Vec::new(),
                },
                is_local_target(&api_url, via_ssh_tunnel),
            )
            .await
            {
                Ok(plan) => plan,
                Err(error) => exit_with_error(output, error.to_string()),
            };
            plan.report_diagnostics(output);
            let plan = plan.prepare(&config).await?;

            let termination = job::run_job(job::JobRequest {
                daemon: &client,
                output,
                name: &name,
                creation: plan,
                keep,
                timeout,
                dns: &dns,
                add_host: &add_host,
                sync_cwd,
                write_back,
                out: &out,
                command: &command,
                env: &env,
                secret_env: &secret_env,
            })
            .await;

            match termination {
                job::JobTermination::Success => Ok(()),
                job::JobTermination::Exit(code) => std::process::exit(code),
                job::JobTermination::Failure(failure) => exit_with_error(output, failure),
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
                    let client = DaemonClient::new(&api_url, api_token.clone());

                    if data.len() > CP_CHUNK_BYTES {
                        // Large file: send it as a sequence of append-mode
                        // chunks instead of one request the daemon would
                        // reject outright. Before sending any chunk, confirm
                        // the connected guest agent is new enough to honor
                        // `append` - an older agent ignores it and truncates
                        // on every write, which would silently corrupt the
                        // destination to only the final chunk while cp still
                        // reported success.
                        let resp = client
                            .send(client.get(format!("/v1/vms/{name}/guest-info")))
                            .await?;
                        if !resp.status().is_success() {
                            let msg = client.error(resp, &format!("VM '{name}'")).await;
                            exit_with_error(output, msg);
                        }
                        let info: serde_json::Value = resp.json().await?;
                        let guest_protocol_version =
                            info["protocol_version"].as_u64().unwrap_or(0) as u32;
                        if let Err(msg) = check_append_capable(guest_protocol_version) {
                            exit_with_error(output, msg);
                        }

                        let mut bytes_copied = 0u64;
                        for (i, (start, end)) in cp_chunk_ranges(data.len(), CP_CHUNK_BYTES)
                            .into_iter()
                            .enumerate()
                        {
                            let chunk = &data[start..end];
                            let mut body = serde_json::json!({
                                "path": path,
                                "data": husker_agent_proto::base64_encode(chunk),
                                "append": i > 0,
                            });
                            if let Some(m) = mode {
                                body["mode"] = serde_json::json!(m);
                            }

                            let resp = client
                                .send(
                                    client
                                        .post(format!("/v1/vms/{name}/files/write"))
                                        .json(&body),
                                )
                                .await?;

                            if !resp.status().is_success() {
                                let msg = client.error(resp, &format!("VM '{name}'")).await;
                                exit_with_error(output, msg);
                            }
                            let result: serde_json::Value = resp.json().await?;
                            bytes_copied += result["bytes_written"].as_u64().unwrap_or(0);
                        }

                        print_output(
                            output,
                            &serde_json::json!({
                                "status": "ok",
                                "action": "cp",
                                "direction": "to_vm",
                                "vm": name,
                                "path": path,
                                "bytes": bytes_copied,
                            }),
                            format!("{bytes_copied} bytes copied to {name}:{path}"),
                        );
                    } else {
                        let encoded = husker_agent_proto::base64_encode(&data);

                        let mut body = serde_json::json!({
                            "path": path,
                            "data": encoded,
                        });
                        if let Some(m) = mode {
                            body["mode"] = serde_json::json!(m);
                        }

                        let resp = client
                            .send(
                                client
                                    .post(format!("/v1/vms/{name}/files/write"))
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
                            let msg = client.error(resp, &format!("VM '{name}'")).await;
                            exit_with_error(output, msg);
                        }
                    }
                }
                (CpPath::Vm { name, path }, CpPath::Local(local)) => {
                    // Reads in chunks when the file is larger than one response
                    // can carry, so the size of an artifact is not a reason it
                    // cannot be copied out.
                    let client = DaemonClient::new(&api_url, api_token.clone());
                    let data = match read_guest_file(&client, &name, &path).await? {
                        GuestFile::Read(data) => data,
                        GuestFile::Failed(failure) => exit_with_error(output, failure),
                    };
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
            let mut url = format!("/v1/vms/{name}/logs");
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

            let client = DaemonClient::new(&api_url, api_token.clone());
            let resp = client.send(client.get(&url)).await?;

            if !resp.status().is_success() {
                let msg = client.error(resp, &format!("VM '{name}'")).await;
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
            let client = DaemonClient::new(&api_url, api_token.clone());
            let timeout = match timeout {
                Some(t) => std::time::Duration::from_secs(t),
                None => {
                    // Boot-mode-aware default: UEFI/EFI cloud VMs boot much slower
                    // than direct-kernel microVMs.
                    let info_url = format!("/v1/vms/{name}");
                    let resp = client.send(client.get(&info_url)).await?;
                    if !resp.status().is_success() {
                        let msg = client.error(resp, &format!("VM '{name}'")).await;
                        exit_with_error(output, msg);
                    }
                    let vm: serde_json::Value = resp.json().await?;
                    let boot_mode = vm
                        .get("boot_mode")
                        .and_then(|b| b.as_str())
                        .unwrap_or("direct");
                    husker_core::default_ready_timeout(boot_mode)
                }
            };
            let url = format!("/v1/vms/{name}/ready");
            let deadline = std::time::Instant::now() + timeout;
            let mut backoff = std::time::Duration::from_millis(200);
            loop {
                let resp = client.send(client.get(&url)).await?;
                if !resp.status().is_success() {
                    let msg = client.error(resp, &format!("VM '{name}'")).await;
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

            let client = DaemonClient::with_timeout(
                &api_url,
                resolve_api_token(cli_api_token.clone(), config_path.as_deref()),
                std::time::Duration::from_secs(2),
            )?;
            if let Ok(resp) = client.try_send(client.get("/v1/health")).await
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
        Commands::Profile { action } => match action {
            ProfileAction::List => {
                let config = load_config(config_path.as_deref());
                let api_token = cli_api_token.clone().or_else(|| config.api_token.clone());
                let client = DaemonClient::with_timeout(
                    &api_url,
                    api_token,
                    std::time::Duration::from_secs(3),
                )?;
                let daemon_result = match fetch_daemon_profiles(&client).await {
                    Ok(o) => o,
                    Err(e) => exit_with_error(output, e.to_string()),
                };
                let daemon_offline = daemon_result.is_none();
                let daemon_profiles = daemon_result.unwrap_or_default();
                let (merged, profile_origins) = merge_profiles(daemon_profiles, &config.profiles);

                if output == OutputFormat::Json {
                    let json_merged: std::collections::HashMap<_, _> = merged
                        .iter()
                        .map(|(name, p)| {
                            let origin = if profile_origins.get(name) == Some(&ProfileOrigin::Local)
                            {
                                "local"
                            } else {
                                "daemon"
                            };
                            (
                                name.clone(),
                                serde_json::json!({
                                    "origin": origin,
                                    "cpus": p.cpus,
                                    "memory": p.memory,
                                    "rootfs": p.rootfs,
                                    "kernel": p.kernel,
                                    "cloud_image": p.cloud_image,
                                }),
                            )
                        })
                        .collect();
                    print_output(
                        output,
                        &serde_json::json!({
                            "status": "ok",
                            "action": "profile-list",
                            "profiles": json_merged,
                        }),
                        "",
                    );
                } else if merged.is_empty() {
                    println!("No profiles defined (daemon or local).");
                    println!(
                        "Add profiles to ~/.config/husker/config.toml or to the daemon config."
                    );
                } else {
                    let mut names: Vec<&String> = merged.keys().collect();
                    names.sort();
                    for name in names {
                        let p = &merged[name];
                        let origin = if config.profiles.contains_key(name) {
                            "local"
                        } else {
                            "daemon"
                        };
                        let mut parts = vec![format!("[{}]", origin)];
                        if let Some(n) = p.cpus {
                            parts.push(format!("cpus={n}"));
                        }
                        if let Some(m) = p.memory {
                            parts.push(format!("memory={m}MiB"));
                        }
                        if let Some(ref r) = p.rootfs {
                            parts.push(format!("rootfs={}", r.display()));
                        }
                        if let Some(ref c) = p.cloud_image {
                            parts.push(format!("cloud-image={}", c.display()));
                        }
                        println!("{:20}  {}", name, parts.join("  "));
                    }
                    if daemon_offline {
                        println!(
                            "\n(daemon profiles unavailable - offline or daemon does not support GET /v1/profiles)"
                        );
                    }
                }
                Ok(())
            }
        },
        Commands::Setup { action } => match action {
            SetupAction::Storage {
                state_dir,
                image_path,
                size,
                fs,
                persist,
                thin,
                out,
                yes,
            } => {
                use husker::storage_setup as ss;
                let config = load_config(config_path.as_deref());
                let data_dir = config.data_dir.clone();
                let images_dir = data_dir.join("images");
                let vms_dir = data_dir.join("vms");
                let reflink = husker_storage::probe_reflink(&images_dir, &vms_dir)
                    .unwrap_or(husker_storage::ReflinkStatus::FullCopy);
                let fs_enum = match fs {
                    SetupFsArg::Xfs => ss::SetupFs::Xfs,
                    SetupFsArg::Btrfs => ss::SetupFs::Btrfs,
                };
                let facts = ss::StorageSetupHostFacts {
                    reflink,
                    free_bytes: available_bytes_for(&data_dir).unwrap_or(0),
                    bulk_usage_bytes: dir_usage_bytes(&data_dir),
                    mkfs_available: which_on_path(match fs {
                        SetupFsArg::Xfs => "mkfs.xfs",
                        SetupFsArg::Btrfs => "mkfs.btrfs",
                    }),
                    rsync_available: which_on_path("rsync"),
                    is_local_context: is_local_target(&api_url, via_ssh_tunnel),
                };
                let opts = ss::StorageSetupOptions {
                    state_dir,
                    image_path,
                    size,
                    fs: fs_enum,
                    persist: match persist {
                        SetupPersistArg::Systemd => ss::SetupPersist::Systemd,
                        SetupPersistArg::Fstab => ss::SetupPersist::Fstab,
                    },
                    thin,
                };
                let config_file = config_path_or_default();
                let api_addr = api_url
                    .strip_prefix("http://")
                    .or_else(|| api_url.strip_prefix("https://"))
                    .unwrap_or(api_url.as_str())
                    .trim_end_matches('/');
                match ss::build_storage_setup_plan(&data_dir, &config_file, api_addr, opts, &facts)
                {
                    Ok(ss::SetupOutcome::AlreadyReflink) => {
                        println!(
                            "data dir already supports reflink (copy-on-write); no migration needed."
                        );
                    }
                    Ok(ss::SetupOutcome::Plan(plan)) => {
                        let script = ss::render_migration_script(&plan);
                        let unit = ss::render_systemd_mount_unit(&plan);
                        if let Some(dir) = out {
                            if let Err(e) = std::fs::create_dir_all(&dir) {
                                exit_with_error(
                                    output,
                                    format!("cannot create {}: {e}", dir.display()),
                                );
                            }
                            let script_path = dir.join("husker-setup-storage.sh");
                            let unit_path = dir.join("husker-storage.mount");
                            if !yes && (script_path.exists() || unit_path.exists()) {
                                require_confirmation(
                                    &format!("overwrite files in {}?", dir.display()),
                                    yes,
                                    output,
                                );
                            }
                            std::fs::write(&script_path, &script).unwrap_or_else(|e| {
                                exit_with_error(
                                    output,
                                    format!("cannot write {}: {e}", script_path.display()),
                                )
                            });
                            std::fs::write(&unit_path, &unit).unwrap_or_else(|e| {
                                exit_with_error(
                                    output,
                                    format!("cannot write {}: {e}", unit_path.display()),
                                )
                            });
                            println!(
                                "wrote {} and {}",
                                script_path.display(),
                                unit_path.display()
                            );
                            println!(
                                "review, then run as root on the daemon host: sudo bash {}",
                                script_path.display()
                            );
                        } else {
                            print!("{script}");
                        }
                    }
                    Err(e) => {
                        exit_with_error(output, e.to_string());
                    }
                }
                Ok(())
            }
        },
        Commands::Doctor => {
            let config = load_config(config_path.as_deref());
            let client = DaemonClient::with_timeout(
                &api_url,
                cli_api_token.clone().or_else(|| config.api_token.clone()),
                std::time::Duration::from_secs(3),
            )?;
            let report = match fetch_diagnostics(&client).await {
                Ok(r) => r,
                Err(_) if is_local_target(&api_url, via_ssh_tunnel) => {
                    // Daemon is not running locally: run the probe directly on the host.
                    eprintln!("(daemon not reachable; running local host probe)");
                    let storage = husker_storage::StorageConfig {
                        data_dir: config.data_dir.clone(),
                        state_dir: config.effective_state_dir(),
                    };
                    let storage_volume = config.storage_volume;
                    let embedded_agent = husker::EMBEDDED_AGENT;
                    // Resolve "auto" the same way the daemon does so the probe
                    // checks the interface NAT would actually pin.
                    #[cfg(feature = "linux-net")]
                    let host_interface =
                        Some(husker_net::resolve_host_interface(&config.host_interface).effective);
                    #[cfg(not(feature = "linux-net"))]
                    let host_interface: Option<String> = None;
                    match tokio::task::spawn_blocking(move || {
                        let input = husker_core::DiagnosticsInput {
                            storage: &storage,
                            storage_volume,
                            embedded_agent,
                            host_interface: host_interface.as_deref(),
                            resource_limits_requested: config.resource_limits,
                        };
                        husker_core::build_diagnostics(&input)
                    })
                    .await
                    {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("diagnostics probe failed: {e}");
                            husker_core::DiagnosticsReport { checks: Vec::new() }
                        }
                    }
                }
                Err(e) => {
                    exit_with_error(
                        output,
                        ApiFailure {
                            message: format!("daemon unreachable: {e}"),
                            kind: None,
                            exit_code: exit_code::DAEMON_UNREACHABLE,
                            hint: None,
                        },
                    );
                }
            };
            render_diagnostics(&report, output);
            let code = doctor_exit_code(&report);
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        Commands::Context { .. } => {
            unreachable!("Context is handled before daemon-target resolution in run()")
        }
        Commands::Schema => unreachable!("schema handled before target resolution"),
        Commands::Capabilities => {
            unreachable!("capabilities handled before target resolution")
        }
        Commands::Completions { shell } => {
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
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
                        kind: Some("not_found".into()),
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
                        kind: Some("not_found".into()),
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

async fn port_forward(
    api_url: String,
    api_token: Option<String>,
    name: String,
    action: PortForwardAction,
    output: OutputFormat,
) -> Result<()> {
    let client = DaemonClient::new(&api_url, api_token.clone());
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
            let resp = client
                .send(client.post(format!("/v1/vms/{name}/ports")).json(&payload))
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
                let msg = client.error(resp, &format!("VM '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        PortForwardAction::Remove { host_port } => {
            let resp = client
                .send(client.delete(format!("/v1/vms/{name}/ports/{host_port}")))
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
                let msg = client
                    .error(resp, &format!("port forward {host_port}"))
                    .await;
                exit_with_error(output, msg);
            }
        }
        PortForwardAction::List => {
            let resp = client
                .send(client.get(format!("/v1/vms/{name}/ports")))
                .await?;
            if !resp.status().is_success() {
                let msg = client.error(resp, &format!("VM '{name}'")).await;
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
    let client = DaemonClient::new(&api_url, api_token.clone());
    match action {
        HostGroupAction::Create { name, description } => {
            let mut body = serde_json::json!({
                "name": &name,
            });
            if let Some(desc) = description.as_deref() {
                body["description"] = serde_json::json!(desc);
            }

            let resp = client
                .send(client.post("/v1/host-groups").json(&body))
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
                let msg = client.error(resp, &format!("host group '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        HostGroupAction::List => {
            let resp = client.send(client.get("/v1/host-groups")).await?;

            if !resp.status().is_success() {
                let msg = client.error(resp, "listing host groups").await;
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
            let resp = client
                .send(client.get(format!("/v1/host-groups/{name}")))
                .await?;

            if !resp.status().is_success() {
                let msg = client.error(resp, &format!("host group '{name}'")).await;
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
        HostGroupAction::Delete { name, yes } => {
            require_confirmation(&format!("Delete host group '{name}'?"), yes, output);
            let resp = client
                .send(client.delete(format!("/v1/host-groups/{name}")))
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
                let msg = client.error(resp, &format!("host group '{name}'")).await;
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
    let client = DaemonClient::new(&api_url, api_token.clone());
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
            let resp = client.send(client.post("/v1/pools").json(&body)).await?;
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
                let msg = client.error(resp, &format!("pool '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        PoolAction::List => {
            let resp = client.send(client.get("/v1/pools")).await?;
            if !resp.status().is_success() {
                let msg = client.error(resp, "listing pools").await;
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
            let resp = client.send(client.get(format!("/v1/pools/{name}"))).await?;
            if !resp.status().is_success() {
                let msg = client.error(resp, &format!("pool '{name}'")).await;
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
            let resp = client
                .send(
                    client
                        .post(format!("/v1/pools/{name}/checkout"))
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
                let msg = client.error(resp, &format!("pool '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        PoolAction::Delete { name, yes } => {
            require_confirmation(
                &format!("Delete pool '{name}' and its template?"),
                yes,
                output,
            );
            let resp = client
                .send(client.delete(format!("/v1/pools/{name}")))
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
                let msg = client.error(resp, &format!("pool '{name}'")).await;
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
    let client = DaemonClient::new(&api_url, api_token.clone());
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
            }
            // Applies to cloud images (grown by cloud-init on first boot) and
            // plain rootfs images (resized offline by the daemon) alike.
            if let Some(ref size) = disk_size {
                let bytes = husker::parse_disk_size(size)
                    .map_err(|e| anyhow::anyhow!("--disk-size: {e}"))?;
                body["disk_size"] = serde_json::json!(bytes);
            }
            if balloon {
                body["balloon"] = serde_json::json!(true);
            }
            if let Some(ref vol) = volume {
                body["volume"] = serde_json::json!(vol);
            }

            let resp = client.send(client.post("/v1/services").json(&body)).await?;

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
                let msg = client.error(resp, &format!("service '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        ServiceAction::List => {
            let resp = client.send(client.get("/v1/services")).await?;

            if !resp.status().is_success() {
                let msg = client.error(resp, "listing services").await;
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
            let resp = client
                .send(client.get(format!("/v1/services/{name}")))
                .await?;

            if !resp.status().is_success() {
                let msg = client.error(resp, &format!("service '{name}'")).await;
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
            let resp =
                client
                    .send(client.post(format!("/v1/services/{name}/scale")).json(
                        &serde_json::json!({
                            "desired_instances": desired_instances,
                        }),
                    ))
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
                let msg = client.error(resp, &format!("service '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        ServiceAction::Delete { name, yes } => {
            require_confirmation(&format!("Delete service '{name}'?"), yes, output);
            let resp = client
                .send(client.delete(format!("/v1/services/{name}")))
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
                let msg = client.error(resp, &format!("service '{name}'")).await;
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
    let client = DaemonClient::new(&api_url, api_token.clone());
    match action {
        SnapshotAction::Create { name, vm } => {
            let resp = client
                .send(client.post("/v1/snapshots").json(&serde_json::json!({
                    "name": &name,
                    "vm": &vm,
                })))
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
                let msg = client.error(resp, &format!("snapshot '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        SnapshotAction::List => {
            let resp = client.send(client.get("/v1/snapshots")).await?;

            if !resp.status().is_success() {
                let msg = client.error(resp, "listing snapshots").await;
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
            let resp = client
                .send(client.get(format!("/v1/snapshots/{name}")))
                .await?;

            if !resp.status().is_success() {
                let msg = client.error(resp, &format!("snapshot '{name}'")).await;
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

            let resp = client
                .send(
                    client
                        .post(format!("/v1/snapshots/{snapshot}/restore"))
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
                let msg = client.error(resp, &format!("snapshot '{snapshot}'")).await;
                exit_with_error(output, msg);
            }
        }
        SnapshotAction::Delete { name, yes } => {
            require_confirmation(&format!("Delete snapshot '{name}'?"), yes, output);
            let resp = client
                .send(client.delete(format!("/v1/snapshots/{name}")))
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
                let msg = client.error(resp, &format!("snapshot '{name}'")).await;
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
    let client = DaemonClient::new(&api_url, api_token.clone());
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

            let resp = client.send(client.post("/v1/images").json(&body)).await?;

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
                let msg = client.error(resp, &format!("image '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        ImageAction::ImportOci { reference, name } => {
            preflight_capability(&api_url, api_token.as_deref(), "oci_import").await?;
            let name = name.unwrap_or_else(|| oci_default_image_name(&reference));
            let resp = client
                .send(
                    client
                        .post("/v1/images/import-oci")
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
                let msg = client.error(resp, &format!("image '{reference}'")).await;
                exit_with_error(output, msg);
            }
        }
        ImageAction::List => {
            let resp = client.send(client.get("/v1/images")).await?;

            if !resp.status().is_success() {
                let msg = client.error(resp, "listing images").await;
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
            let resp = client
                .send(client.get(format!("/v1/images/{name}")))
                .await?;

            if !resp.status().is_success() {
                let msg = client.error(resp, &format!("image '{name}'")).await;
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
            let resp =
                client
                    .send(client.post(format!("/v1/images/{name}/export")).json(
                        &serde_json::json!({
                            "destination_path": &destination,
                        }),
                    ))
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
                let msg = client.error(resp, &format!("image '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        ImageAction::Delete { name, yes } => {
            require_confirmation(&format!("Delete image '{name}'?"), yes, output);
            let resp = client
                .send(client.delete(format!("/v1/images/{name}")))
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
                let msg = client.error(resp, &format!("image '{name}'")).await;
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

            // The kernel and initramfs must come from the SAME image release: a
            // stale kernel paired with a freshly downloaded initramfs fails module
            // loading. So treat the asset set as all-or-nothing rather than skipping
            // per-file: only skip when every destination already exists, otherwise
            // (re)download all of them from this manifest so the set stays matched.
            let all_present = targets.iter().all(|(_, dest)| dest.exists());
            if all_present && !force {
                println!("All default images already present (pass --force to re-download).");
            } else {
                for (asset, dest) in &targets {
                    let sha = manifest.get(asset).ok_or_else(|| {
                        anyhow::anyhow!("{asset} missing from manifest at {base_url}")
                    })?;
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
    let client = DaemonClient::new(&api_url, api_token.clone());
    match action {
        VolumeAction::Create { name, size } => {
            let size_bytes =
                husker::parse_disk_size(&size).map_err(|e| anyhow::anyhow!("--size: {e}"))?;
            let body = serde_json::json!({
                "name": &name,
                "size_bytes": size_bytes,
            });

            let resp = client.send(client.post("/v1/volumes").json(&body)).await?;

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
                let msg = client.error(resp, &format!("volume '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        VolumeAction::List => {
            let resp = client.send(client.get("/v1/volumes")).await?;

            if !resp.status().is_success() {
                let msg = client.error(resp, "listing volumes").await;
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
            let resp = client
                .send(client.get(format!("/v1/volumes/{name}")))
                .await?;
            if !resp.status().is_success() {
                let msg = client.error(resp, &format!("volume '{name}'")).await;
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
        VolumeAction::Delete { name, yes } => {
            require_confirmation(
                &format!("Delete volume '{name}'? This destroys its persistent data."),
                yes,
                output,
            );
            let resp = client
                .send(client.delete(format!("/v1/volumes/{name}")))
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
                let msg = client.error(resp, &format!("volume '{name}'")).await;
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
    let client = DaemonClient::new(&api_url, api_token.clone());
    match action {
        SecretAction::Create { name, value } => {
            let resp = client
                .send(client.post("/v1/secrets").json(&serde_json::json!({
                    "name": &name,
                    "value": &value,
                })))
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
                let msg = client.error(resp, &format!("secret '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        SecretAction::List => {
            let resp = client.send(client.get("/v1/secrets")).await?;
            if !resp.status().is_success() {
                let msg = client.error(resp, "listing secrets").await;
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
            let resp = client
                .send(client.get(format!("/v1/secrets/{name}")))
                .await?;
            if !resp.status().is_success() {
                let msg = client.error(resp, &format!("secret '{name}'")).await;
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
            let resp = client
                .send(client.get(format!("/v1/secrets/{name}/reveal")))
                .await?;
            if !resp.status().is_success() {
                let msg = client.error(resp, &format!("secret '{name}'")).await;
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
            let resp =
                client
                    .send(client.post(format!("/v1/secrets/{name}/rotate")).json(
                        &serde_json::json!({
                            "value": &value,
                        }),
                    ))
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
                let msg = client.error(resp, &format!("secret '{name}'")).await;
                exit_with_error(output, msg);
            }
        }
        SecretAction::Delete { name, yes } => {
            require_confirmation(&format!("Delete secret '{name}'?"), yes, output);
            let resp = client
                .send(client.delete(format!("/v1/secrets/{name}")))
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
                let msg = client.error(resp, &format!("secret '{name}'")).await;
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
    let client = DaemonClient::new(&api_url, api_token.map(str::to_owned));
    let resp = client.send(client.get(format!("/v1/vms/{name}"))).await?;

    if !resp.status().is_success() {
        let err = client.error(resp, &format!("VM '{name}'")).await;
        exit_with_error(output, err);
    }

    let vm: serde_json::Value = resp.json().await?;
    let vm_id = vm["id"].as_str().context("missing VM id")?;

    let config = load_config(config_path.as_deref());
    let runtime_dir = config.effective_state_dir().join("run");
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
    let client = DaemonClient::new(api_url, api_token.map(str::to_owned));
    let resp = client.send(client.get(format!("/v1/vms/{name}"))).await?;
    if !resp.status().is_success() {
        let err = client.error(resp, &format!("VM '{name}'")).await;
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
                kind: Some("vm_not_running".into()),
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

/// Bytes per chunk when `cp` splits a local file for upload to a VM. The
/// daemon rejects a single write-file request whose decoded payload exceeds
/// `ApiPolicy::max_file_write_bytes` (1 MiB by default); that limit is not
/// currently exposed to clients through any endpoint or response, so this is
/// a fixed, conservative size comfortably under the default rather than a
/// value probed from the daemon. A file at or under this size is still sent
/// in a single request, unchanged from before chunking existed.
const CP_CHUNK_BYTES: usize = 512 * 1024;

/// Confirm a connected guest agent's reported protocol version supports
/// append-mode writes, which chunked `cp` relies on to send a large file as a
/// sequence of requests instead of one. An agent older than
/// [`husker_agent_proto::MIN_PROTOCOL_VERSION_FOR_APPEND`] has no code path
/// for append at all and always truncates on every write, so sending it a
/// chunked transfer would silently keep only the last chunk while the
/// command still reports success. Fail loudly instead: name the guest's
/// reported version and the version chunking requires, and say plainly that
/// the VM's image predates append support.
fn check_append_capable(guest_protocol_version: u32) -> Result<(), String> {
    let required = husker_agent_proto::MIN_PROTOCOL_VERSION_FOR_APPEND;
    if guest_protocol_version >= required {
        Ok(())
    } else {
        Err(format!(
            "cannot copy a file larger than {CP_CHUNK_BYTES} bytes to this VM: \
             the guest agent reports protocol version {guest_protocol_version}, \
             but chunked copy requires version {required} or newer. \
             The VM's image predates append support in husker-agent; \
             rebuild or re-import the image with a current husker-agent, \
             or copy a file at or under {CP_CHUNK_BYTES} bytes."
        ))
    }
}

/// Split a file of `total_len` bytes into `(start, end)` byte ranges of at
/// most `chunk_size` bytes each, covering the whole file with no gaps or
/// overlap. `chunk_size` must be greater than zero. A zero-length file
/// yields a single empty range `(0, 0)`, so a caller that always sends one
/// request per range still issues exactly one (empty) write for an empty
/// file, matching the non-chunked path.
fn cp_chunk_ranges(total_len: usize, chunk_size: usize) -> Vec<(usize, usize)> {
    debug_assert!(chunk_size > 0, "chunk_size must be greater than zero");
    if total_len == 0 {
        return vec![(0, 0)];
    }
    let mut ranges = Vec::with_capacity(total_len.div_ceil(chunk_size));
    let mut start = 0;
    while start < total_len {
        let end = (start + chunk_size).min(total_len);
        ranges.push((start, end));
        start = end;
    }
    ranges
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

        // host_interface: resolve exactly like the daemon will ("auto" follows
        // the default route) and fail on anything that breaks guest egress.
        let iface_env_hint = if iface_from_env {
            " (from HUSKER_HOST_INTERFACE)"
        } else {
            ""
        };
        let uplink = husker_net::resolve_host_interface(&config.host_interface);
        let shown = if uplink.source == husker_net::HostInterfaceSource::Configured {
            uplink.effective.clone()
        } else {
            format!("{} -> {}", config.host_interface, uplink.effective)
        };
        if uplink.warnings.is_empty() {
            println!("  host_interface ({shown}) ... OK{iface_env_hint}");
        } else {
            println!(
                "  host_interface ({shown}) ... FAIL ({}){iface_env_hint}",
                uplink.warnings.join("; ")
            );
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

/// Default guest path the working-tree archive is uploaded to for `--sync-cwd`.
pub(crate) const SYNC_ARCHIVE_GUEST_PATH: &str = "/tmp/.husker-sync.tgz";
/// Default guest directory the working tree is extracted into for `--sync-cwd`.
pub(crate) const SYNC_WORKDIR: &str = "/work";
/// Guest path the retrieval archive (`--out`/`--write-back`) is built at.
pub(crate) const SYNC_OUTPUT_GUEST_PATH: &str = "/tmp/.husker-out.tgz";
/// Guest path the retrieval manifest is written to: one line per requested
/// pattern that matched nothing, as its 1-based position in the request. The
/// file is created before any matching happens and truncated first, so the host
/// can tell "every pattern matched" (present and empty) from "the wrapper never
/// got this far" (absent) - two facts an absent archive alone conflates, and the
/// conflation is why an unretrievable artifact used to be reported as one the
/// command never produced. Positions rather than the patterns themselves because
/// a position is always digits: no quoting, no separator that a path could
/// contain.
pub(crate) const SYNC_MANIFEST_GUEST_PATH: &str = "/tmp/.husker-out.manifest";

/// Collect the set of files to sync into a `--sync-cwd` sandbox, relative to `dir`.
///
/// In a git repository the list is git-aware: tracked plus untracked-but-not-ignored
/// files (so gitignored build dirs like `target/` are excluded by construction). Outside
/// a git repo it falls back to every file under `dir`, skipping any `.git` directory.
pub(crate) fn collect_sync_paths(dir: &Path) -> Result<Vec<PathBuf>> {
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
pub(crate) fn build_sync_archive(dir: &Path) -> Result<Vec<u8>> {
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
/// the command did not produce are skipped). Each path may be a glob: patterns
/// are single-quoted (so `--out` values cannot inject shell) and then expanded
/// guest-side via unquoted word expansion - pathname expansion only, never
/// shell re-parsing - so they match files the command created. busybox-safe:
/// no arrays, no `tar -T`/`--null`.
///
/// Alongside the archive the guest writes `manifest_path`, listing the 1-based
/// position of every pattern that matched nothing. Which patterns went unmatched
/// is knowable only on the guest, where the expansion happens, and without it the
/// host can only observe that the archive is missing - true both when nothing
/// matched and when everything matched but the archive could not be transferred.
pub(crate) fn wrap_sync_command(
    archive_guest_path: &str,
    workdir: &str,
    command: &[String],
    output_path: &str,
    manifest_path: &str,
    retrieve_paths: &[PathBuf],
) -> (String, Vec<String>) {
    let setup = format!(
        "set -e; mkdir -p {workdir}; tar -xzf {archive_guest_path} -C {workdir}; \
         rm -f {archive_guest_path}; cd {workdir}; "
    );
    let script = if retrieve_paths.is_empty() {
        format!("{setup}exec \"$@\"")
    } else {
        // `./`-prefix each pattern so a leading `-` can never look like a tar
        // option, and single-quote so `--out` values cannot inject shell. The
        // guest loop re-expands each pattern UNQUOTED, which performs pathname
        // expansion (globbing) but never shell re-parsing; a pattern with no
        // matches stays literal and is dropped by the `-e` test. Matches
        // accumulate in the positional parameters (the user command has
        // already run, so `$@` is free to reuse), while `__i` counts patterns
        // and `__n` records whether the current one matched anything.
        //
        // `IFS` is emptied for that expansion, which disables field splitting
        // and leaves only globbing. Otherwise a pattern containing a space
        // ("build output/*.tgz") would be split into two words before it was
        // expanded, and both would fail to match a file that exists.
        let quoted = retrieve_paths
            .iter()
            .map(|p| shell_single_quote(&format!("./{}", p.to_string_lossy())))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "{setup}set +e; \"$@\"; __rc=$?; \
             set --; __i=0; : > {manifest_path}; __oifs=$IFS; IFS=; \
             for __p in {quoted}; do __i=$((__i+1)); __n=0; \
             for __m in $__p; do \
             if [ -e \"$__m\" ]; then set -- \"$@\" \"$__m\"; __n=1; fi; done; \
             if [ $__n -eq 0 ]; then printf '%s\\n' \"$__i\" >> {manifest_path}; fi; done; \
             IFS=$__oifs; \
             if [ $# -gt 0 ]; then tar -czf {output_path} \"$@\" 2>/dev/null || true; fi; \
             exit $__rc"
        )
    };
    let mut args = vec!["-c".to_string(), script, "husker-sync".to_string()];
    args.extend(command.iter().cloned());
    ("sh".to_string(), args)
}

/// Unpack a gzip+tar archive over `dst`, returning the relative paths written.
/// Entries that would escape `dst` (absolute paths, `..`) are skipped.
pub(crate) fn extract_archive_over(bytes: &[u8], dst: &Path) -> Result<Vec<String>> {
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
    let Ok(client) = DaemonClient::with_timeout(
        api_url,
        api_token.map(str::to_owned),
        std::time::Duration::from_secs(5),
    ) else {
        return Ok(());
    };
    let Ok(resp) = client.try_send(client.get("/v1/health")).await else {
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
            "/tmp/.husker-out.manifest",
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

    /// Runs the generated retrieval script through a real `sh`: globs must
    /// expand against files the command CREATED (they did not exist at sync
    /// time), non-matching patterns must be dropped rather than passed to tar
    /// as literals, the manifest must name exactly the pattern that matched
    /// nothing, and the command's exit code must survive.
    #[test]
    fn wrap_sync_command_expands_globs_guest_side() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("work");
        let archive = tmp.path().join("sync.tgz");
        let out = tmp.path().join("out.tgz");
        let manifest = tmp.path().join("out.manifest");

        // Minimal sync archive (one seed file) for the setup step to extract.
        let gz = flate2::write::GzEncoder::new(
            std::fs::File::create(&archive).unwrap(),
            flate2::Compression::fast(),
        );
        let mut builder = tar::Builder::new(gz);
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "seed.txt", std::io::empty())
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap();

        let (cmd, args) = wrap_sync_command(
            archive.to_str().unwrap(),
            workdir.to_str().unwrap(),
            &[
                "sh".to_string(),
                "-c".to_string(),
                "mkdir -p results && touch results/a.log results/b.log && exit 3".to_string(),
            ],
            out.to_str().unwrap(),
            manifest.to_str().unwrap(),
            &[PathBuf::from("results/*"), PathBuf::from("nope/*")],
        );
        let status = std::process::Command::new(cmd)
            .args(&args)
            // This script runs inside a Linux guest, whose tar writes only the
            // globbed files. A macOS host's bsdtar also emits a `._name`
            // AppleDouble entry per file to carry extended attributes, which
            // would appear in the archive as extra members. Disable that so the
            // harness archives what the guest would.
            .env("COPYFILE_DISABLE", "1")
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(3), "user command exit code preserved");

        let gz = flate2::read::GzDecoder::new(std::fs::File::open(&out).unwrap());
        let mut names: Vec<String> = tar::Archive::new(gz)
            .entries()
            .unwrap()
            .map(|e| {
                let p = e.unwrap().path().unwrap().to_string_lossy().into_owned();
                p.trim_start_matches("./").to_string()
            })
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec!["results/a.log".to_string(), "results/b.log".to_string()],
            "glob matched exactly the created files; 'nope/*' was dropped"
        );

        // Dropping a pattern silently is what made an unretrievable artifact
        // indistinguishable from one the command never wrote. The manifest
        // names the second pattern, and only the second: a manifest that
        // listed both (or neither) would let the host misreport which.
        assert_eq!(
            std::fs::read_to_string(&manifest).unwrap(),
            "2\n",
            "manifest names only the pattern that matched nothing, by position"
        );
    }

    /// A directory name with a space in it is an ordinary thing to build into,
    /// and the pattern naming it is one pattern. Splitting it on the space
    /// before globbing makes both halves match nothing, which now reports a
    /// file that exists as an output the command never wrote, and fails the job
    /// for it.
    #[test]
    fn wrap_sync_command_matches_a_pattern_containing_a_space() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("work");
        let archive = tmp.path().join("sync.tgz");
        let out = tmp.path().join("out.tgz");
        let manifest = tmp.path().join("out.manifest");

        let gz = flate2::write::GzEncoder::new(
            std::fs::File::create(&archive).unwrap(),
            flate2::Compression::fast(),
        );
        let mut builder = tar::Builder::new(gz);
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "seed.txt", std::io::empty())
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap();

        let (cmd, args) = wrap_sync_command(
            archive.to_str().unwrap(),
            workdir.to_str().unwrap(),
            &[
                "sh".to_string(),
                "-c".to_string(),
                "mkdir -p 'build output' && touch 'build output/app.tgz'".to_string(),
            ],
            out.to_str().unwrap(),
            manifest.to_str().unwrap(),
            &[PathBuf::from("build output/*.tgz")],
        );
        let status = std::process::Command::new(cmd)
            .args(&args)
            .env("COPYFILE_DISABLE", "1")
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(0));

        // Asserted before the archive is opened: a split pattern matches
        // nothing, and the manifest says which pattern that was, while a
        // missing archive only says something went unretrieved.
        assert_eq!(
            std::fs::read_to_string(&manifest).unwrap(),
            "",
            "a pattern that matched must not be reported as unmatched"
        );

        let gz = flate2::read::GzDecoder::new(std::fs::File::open(&out).unwrap());
        let names: Vec<String> = tar::Archive::new(gz)
            .entries()
            .unwrap()
            .map(|e| {
                let p = e.unwrap().path().unwrap().to_string_lossy().into_owned();
                p.trim_start_matches("./").to_string()
            })
            .collect();
        assert_eq!(
            names,
            vec!["build output/app.tgz".to_string()],
            "the space belongs to the pattern, not between two patterns"
        );
    }

    /// A retrieval where no pattern matches anything must not create the output
    /// archive, and must say so in the manifest. The manifest is the difference
    /// between "the guest produced nothing" and "the archive did not come back":
    /// without it the host sees only a missing archive and cannot tell which.
    #[test]
    fn wrap_sync_command_no_matches_produces_no_archive_but_a_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("work");
        let archive = tmp.path().join("sync.tgz");
        let out = tmp.path().join("out.tgz");
        let manifest = tmp.path().join("out.manifest");

        let gz = flate2::write::GzEncoder::new(
            std::fs::File::create(&archive).unwrap(),
            flate2::Compression::fast(),
        );
        let mut builder = tar::Builder::new(gz);
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "seed.txt", std::io::empty())
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap();

        let (cmd, args) = wrap_sync_command(
            archive.to_str().unwrap(),
            workdir.to_str().unwrap(),
            &["true".to_string()],
            out.to_str().unwrap(),
            manifest.to_str().unwrap(),
            &[PathBuf::from("missing/*")],
        );
        let status = std::process::Command::new(cmd)
            .args(&args)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(0));
        assert!(!out.exists(), "no output archive when nothing matched");
        assert_eq!(
            std::fs::read_to_string(&manifest).unwrap(),
            "1\n",
            "the manifest accounts for the pattern that matched nothing"
        );
    }

    /// The manifest exists and is empty when every pattern matched, so its
    /// presence proves the wrapper ran to completion and its emptiness proves
    /// nothing went unmatched. An absent manifest means neither, which is why
    /// it is truncated up front rather than only written when there is
    /// something to say.
    #[test]
    fn wrap_sync_command_writes_an_empty_manifest_when_everything_matched() {
        let tmp = tempfile::tempdir().unwrap();
        let workdir = tmp.path().join("work");
        let archive = tmp.path().join("sync.tgz");
        let out = tmp.path().join("out.tgz");
        let manifest = tmp.path().join("out.manifest");

        let gz = flate2::write::GzEncoder::new(
            std::fs::File::create(&archive).unwrap(),
            flate2::Compression::fast(),
        );
        let mut builder = tar::Builder::new(gz);
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "seed.txt", std::io::empty())
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap();

        // Pre-fill the manifest so a wrapper that appended without truncating
        // would leave the stale line behind and fail this test.
        std::fs::write(&manifest, "9\n").unwrap();

        let (cmd, args) = wrap_sync_command(
            archive.to_str().unwrap(),
            workdir.to_str().unwrap(),
            &[
                "sh".to_string(),
                "-c".to_string(),
                "touch made.txt".to_string(),
            ],
            out.to_str().unwrap(),
            manifest.to_str().unwrap(),
            &[PathBuf::from("made.txt")],
        );
        let status = std::process::Command::new(cmd)
            .args(&args)
            .env("COPYFILE_DISABLE", "1")
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(0));
        assert!(out.exists(), "the matched path is archived");
        assert_eq!(
            std::fs::read_to_string(&manifest).unwrap(),
            "",
            "an empty manifest means every pattern matched"
        );
    }

    #[test]
    fn wrap_sync_command_retrieves_and_preserves_exit_code() {
        let (_cmd, args) = wrap_sync_command(
            "/tmp/.husker-sync.tgz",
            "/work",
            &["cargo".to_string(), "build".to_string()],
            "/tmp/.husker-out.tgz",
            "/tmp/.husker-out.manifest",
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
    fn check_append_capable_accepts_current_and_newer_versions() {
        let required = husker_agent_proto::MIN_PROTOCOL_VERSION_FOR_APPEND;
        assert!(check_append_capable(required).is_ok());
        assert!(check_append_capable(required + 1).is_ok());
    }

    #[test]
    fn check_append_capable_refuses_legacy_agent_naming_both_versions() {
        let required = husker_agent_proto::MIN_PROTOCOL_VERSION_FOR_APPEND;
        let legacy_version = required.saturating_sub(1);
        let err = check_append_capable(legacy_version).unwrap_err();
        assert!(
            err.contains(&legacy_version.to_string()),
            "error must name the guest's reported version, got: {err}"
        );
        assert!(
            err.contains(&required.to_string()),
            "error must name the required version, got: {err}"
        );
        assert!(
            err.to_lowercase().contains("predates"),
            "error must say the image predates append support, got: {err}"
        );
    }

    #[test]
    fn check_append_capable_refuses_unversioned_legacy_agent() {
        // An agent built before protocol versioning existed reports 0
        // (`#[serde(default)]` on GuestInfoResponse.protocol_version).
        let err = check_append_capable(0).unwrap_err();
        assert!(
            err.contains('0'),
            "error must name reported version 0: {err}"
        );
    }

    #[test]
    fn cp_chunk_ranges_covers_whole_file_with_no_gaps_or_overlap() {
        let total_len = 25;
        let chunk_size = 7;
        let ranges = cp_chunk_ranges(total_len, chunk_size);

        // Boundary case: 25 is not an exact multiple of 7, so the last
        // range must be short rather than out of bounds or padded.
        assert_eq!(ranges, vec![(0, 7), (7, 14), (14, 21), (21, 25)]);

        // Every byte covered exactly once.
        let mut covered = vec![false; total_len];
        for (start, end) in &ranges {
            for b in covered.iter_mut().take(*end).skip(*start) {
                assert!(!*b, "byte covered more than once");
                *b = true;
            }
        }
        assert!(covered.iter().all(|&b| b), "every byte must be covered");
    }

    #[test]
    fn cp_chunk_ranges_exact_multiple_has_no_trailing_short_chunk() {
        let ranges = cp_chunk_ranges(21, 7);
        assert_eq!(ranges, vec![(0, 7), (7, 14), (14, 21)]);
    }

    #[test]
    fn cp_chunk_ranges_smaller_than_chunk_size_is_one_range() {
        assert_eq!(cp_chunk_ranges(3, 7), vec![(0, 3)]);
    }

    #[test]
    fn cp_chunk_ranges_empty_file_yields_one_empty_range() {
        assert_eq!(cp_chunk_ranges(0, 7), vec![(0, 0)]);
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
    fn apply_profile_fills_idle_policy_when_unset() {
        let mut args = VmRequestArgs::default();
        let p = Profile {
            idle_timeout_secs: Some(900),
            suspend_ttl_secs: Some(1800),
            auto_resume: Some(false),
            ..Profile::default()
        };
        apply_profile(&mut args, &p);
        assert_eq!(args.idle_timeout_secs, Some(900));
        assert_eq!(args.suspend_ttl_secs, Some(1800));
        assert_eq!(args.auto_resume, Some(false));

        // Explicit CLI value wins over profile.
        let mut args2 = VmRequestArgs {
            idle_timeout_secs: Some(60),
            ..VmRequestArgs::default()
        };
        apply_profile(&mut args2, &p);
        assert_eq!(args2.idle_timeout_secs, Some(60));
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
                assert_eq!(cpus, Some(2));
                assert_eq!(memory, Some(256));
            }
            _ => panic!("expected snapshot restore command"),
        }
    }

    #[test]
    fn parse_snapshot_restore_omits_cpus_memory_when_unspecified() {
        // When --cpus and --memory are absent, the parsed values are None so the
        // serialized body sends null, letting the daemon apply its configured default.
        let cli = Cli::try_parse_from([
            "husker",
            "snapshot",
            "restore",
            "snap-1",
            "--name",
            "restored-vm",
            "--kernel",
            "/tmp/vmlinux",
        ])
        .expect("snapshot restore without cpus/memory parses");
        match cli.command {
            Commands::Snapshot {
                action: SnapshotAction::Restore { cpus, memory, .. },
            } => {
                assert!(
                    cpus.is_none(),
                    "cpus must be None when --cpus is not passed, \
                     so the daemon default applies rather than forcing 1"
                );
                assert!(
                    memory.is_none(),
                    "memory must be None when --memory is not passed, \
                     so the daemon default applies rather than forcing 128 MiB"
                );
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
    fn oci_scheme_does_not_reach_the_default_image_name() {
        // `image list` reports `source_path` as `oci://<ref>`, and that value is
        // meant to be usable as-is against `import-oci`. Re-importing a reported
        // path must therefore land on the same catalog name as the bare
        // reference, or the round trip silently creates a second image.
        for bare in ["alpine:3.20", "ghcr.io/o/img:v1", "alpine"] {
            let prefixed = format!("oci://{bare}");
            assert_eq!(
                oci_default_image_name(&prefixed),
                oci_default_image_name(bare),
                "`{prefixed}` must name the same image as `{bare}`"
            );
        }
        // Spelled out, so the assertion above cannot pass by both sides being
        // equally wrong.
        assert_eq!(oci_default_image_name("oci://alpine:3.20"), "alpine-3.20");
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

    /// Find a command by its canonical full path.
    fn find_leaf_command<'a>(
        commands: &'a [serde_json::Value],
        name: &str,
    ) -> Option<&'a serde_json::Value> {
        commands
            .iter()
            .find(|command| command.get("name").and_then(|value| value.as_str()) == Some(name))
    }

    #[test]
    fn cli_schema_is_well_formed() {
        let schema = build_cli_schema();
        assert_eq!(schema["name"], "husker");
        assert!(schema["version"].as_str().is_some());

        // Errors are an array; find the not_found entry.
        let errors = schema["errors"]
            .as_array()
            .expect("errors must be an array");
        let not_found = errors
            .iter()
            .find(|e| e.get("kind").and_then(|k| k.as_str()) == Some("not_found"))
            .expect("not_found error entry must exist");
        assert_eq!(not_found["exit_code"], 2);

        // Commands are a flat array of canonical paths.
        let cmds = schema["commands"]
            .as_array()
            .expect("commands must be an array");
        assert!(!cmds.is_empty());

        // Leaf commands are derived from clap.
        let run_cmd = find_leaf_command(cmds, "run").expect("run command must exist");
        assert!(run_cmd.is_object());
        let schema_cmd = find_leaf_command(cmds, "schema").expect("schema command must exist");
        assert!(schema_cmd.is_object());

        assert!(
            cmds.iter()
                .all(|command| command.get("subcommands").is_none())
        );
        let pull_cmd =
            find_leaf_command(cmds, "image pull").expect("image pull command must exist");
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
        let pf_add =
            find_leaf_command(cmds, "port-forward add").expect("port-forward add must exist");
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

        let vol_get = find_leaf_command(cmds, "volume get").expect("volume get leaf must exist");
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
    fn daemon_bind_loopback_allowed_without_flag() {
        let listen: SocketAddr = "127.0.0.1:7777".parse().unwrap();
        // Loopback needs neither --allow-remote nor a token.
        assert!(validate_daemon_bind(listen, false, false).is_ok());
    }

    #[test]
    fn daemon_bind_non_loopback_requires_allow_remote() {
        let listen: SocketAddr = "0.0.0.0:7777".parse().unwrap();
        // Without --allow-remote, a non-loopback bind is refused regardless of token.
        assert!(validate_daemon_bind(listen, false, true).is_err());
    }

    #[test]
    fn daemon_bind_remote_requires_token() {
        let listen: SocketAddr = "0.0.0.0:7777".parse().unwrap();
        // --allow-remote alone is not enough: a token is mandatory for a remote bind.
        assert!(validate_daemon_bind(listen, true, false).is_err());
        // Remote bind with both the flag and a token is allowed.
        assert!(validate_daemon_bind(listen, true, true).is_ok());
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

    #[test]
    fn load_config_strict_rejects_invalid_toml() {
        // A present-but-unparseable config must be fatal for the daemon, not silently
        // replaced with insecure defaults (which would drop a configured api_token).
        let config_dir = temp_test_dir("load-config-strict-invalid");
        let config_path = config_dir.join("config.toml");
        std::fs::write(&config_path, "this is = = not valid toml\n").unwrap();
        let err = load_config_strict(Some(&config_path)).unwrap_err();
        assert!(
            err.to_string().contains("invalid config file"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn load_config_strict_rejects_missing_explicit_path() {
        let config_dir = temp_test_dir("load-config-strict-missing");
        let config_path = config_dir.join("does-not-exist.toml");
        assert!(load_config_strict(Some(&config_path)).is_err());
    }

    #[test]
    fn load_config_strict_accepts_valid_toml() {
        let _guard = env_mutex().lock().unwrap();
        let config_dir = temp_test_dir("load-config-strict-valid");
        let config_path = config_dir.join("config.toml");
        std::fs::write(&config_path, "api_token = \"from-config\"\n").unwrap();
        let config = load_config_strict(Some(&config_path)).expect("valid config parses");
        assert_eq!(config.api_token.as_deref(), Some("from-config"));
    }

    #[test]
    fn remove_orphan_clone_dirs_removes_only_unknown_dirs() {
        let root = temp_test_dir("orphan-clone-dirs");
        let vms_dir = root.join("vms");
        std::fs::create_dir_all(vms_dir.join("keep")).unwrap();
        std::fs::create_dir_all(vms_dir.join("orphan")).unwrap();
        std::fs::write(vms_dir.join("keep").join("rootfs.ext4"), b"x").unwrap();
        std::fs::write(vms_dir.join("orphan").join("rootfs.ext4"), b"x").unwrap();
        // A stray file (not a directory) must be left untouched.
        std::fs::write(vms_dir.join("SHA256SUMS"), b"x").unwrap();

        let mut known = std::collections::HashSet::new();
        known.insert("keep");

        let removed = remove_orphan_clone_dirs(&vms_dir, &known);
        assert_eq!(removed, 1, "exactly the one orphan dir should be removed");
        assert!(vms_dir.join("keep").exists(), "known VM dir must be kept");
        assert!(
            !vms_dir.join("orphan").exists(),
            "orphan clone dir must be removed"
        );
        assert!(
            vms_dir.join("SHA256SUMS").exists(),
            "non-directory entries must be left alone"
        );
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
    fn env_overrides_resource_limits() {
        let _guard = env_mutex().lock().unwrap();
        let _vars = [
            EnvVarGuard::set("HUSKER_RESOURCE_LIMITS", "true"),
            EnvVarGuard::set("HUSKER_MEMORY_OVERHEAD_MIB", "512"),
            EnvVarGuard::set("HUSKER_CPU_LIMIT", "true"),
        ];
        let mut cfg = Config::default();
        apply_env_overrides(&mut cfg);
        assert!(cfg.resource_limits);
        assert_eq!(cfg.memory_overhead_mib, 512);
        assert!(cfg.cpu_limit);
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

    #[test]
    fn idle_policy_config_parses_from_toml() {
        let toml = r#"
[idle_policy]
poll_interval_secs = 15
default_idle_timeout_secs = 600
default_suspend_ttl_secs = 3600
default_auto_resume = false
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.idle_policy.poll_interval_secs, 15);
        assert_eq!(cfg.idle_policy.default_suspend_ttl_secs, 3600);
        assert!(!cfg.idle_policy.default_auto_resume);
    }

    #[test]
    fn idle_policy_env_override_applies() {
        let _guard = env_mutex().lock().unwrap();
        let _env = EnvVarGuard::set("HUSKER_IDLE_POLL_INTERVAL_SECS", "42");
        let mut cfg = Config::default();
        apply_env_overrides(&mut cfg);
        assert_eq!(cfg.idle_policy.poll_interval_secs, 42);
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

    /// Parse a command line and report whether it is refused against a remote target.
    fn refusal_for(argv: &[&str]) -> Option<String> {
        let cli = Cli::try_parse_from(argv).expect("argv parses");
        host_local_refusal(&cli.command)
    }

    #[test]
    fn host_local_commands_are_refused_against_a_remote_target() {
        // `image pull` writes the kernel/initramfs/rootfs into the LOCAL data dir
        // with no daemon call at all, so a remote context could only ever produce a
        // successful-looking no-op against the host the user meant to update.
        let pull = refusal_for(&["husker", "image", "pull"]).expect("image pull is host-local");
        assert!(
            pull.contains("cannot target a remote context"),
            "the refusal must say the context is unsupported, not merely unusual: {pull}"
        );
        assert!(
            pull.contains("ssh to the daemon host"),
            "the refusal must name the way to actually do it: {pull}"
        );
        assert!(
            refusal_for(&["husker", "setup", "storage"]).is_some(),
            "setup storage inspects this machine's data dir and stays host-local"
        );

        // `image` carries the visible aliases `images` and `img`, and the
        // not-found hint in build_vm_request_body tells users to run
        // `husker images pull` specifically. A guard that only caught the
        // canonical spelling would leave the spelling husker itself suggests
        // writing to the wrong host.
        for alias in ["image", "images", "img"] {
            assert_eq!(
                refusal_for(&["husker", alias, "pull"]),
                Some(pull.clone()),
                "`husker {alias} pull` must be refused exactly like `image pull`"
            );
        }
    }

    #[test]
    fn daemon_commands_are_not_refused_against_a_remote_target() {
        // The negative control: these are the whole point of --context, so a guard
        // that refused them would be worse than the bug it replaces.
        for argv in [
            vec!["husker", "image", "list"],
            vec!["husker", "image", "import-oci", "python:3.12-alpine"],
            vec!["husker", "list"],
            vec!["husker", "exec", "vm1", "--", "true"],
        ] {
            assert!(
                refusal_for(&argv).is_none(),
                "{argv:?} talks to the daemon and must work against any context"
            );
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
        let body = build_vm_request_body(
            "vm",
            args,
            None,
            &Default::default(),
            &Default::default(),
            &Config::default(),
            OutputFormat::Json,
        )
        .unwrap();
        assert_eq!(body["mounts"], serde_json::json!(["/a:/x"]));
    }

    #[test]
    fn request_body_serializes_empty_mounts_from_typed_request() {
        let args = VmRequestArgs {
            mount: vec![],
            ..VmRequestArgs::default()
        };
        let body = build_vm_request_body(
            "vm",
            args,
            None,
            &Default::default(),
            &Default::default(),
            &Config::default(),
            OutputFormat::Json,
        )
        .unwrap();
        assert_eq!(body["mounts"], serde_json::json!([]));
    }

    // ── Feature 1: default resource resolution ─────────────────────────

    #[test]
    fn request_body_sends_null_vcpu_and_memory_when_unset() {
        // When no CLI flag or profile sets cpus/memory, the body sends null so the
        // daemon can apply its own defaults (daemon default > built-in 128/1).
        let args = VmRequestArgs::default();
        let body = build_vm_request_body(
            "vm",
            args,
            None,
            &Default::default(),
            &Default::default(),
            &Config::default(),
            OutputFormat::Json,
        )
        .unwrap();
        assert!(
            body["vcpu_count"].is_null(),
            "vcpu_count must be null when unset so the daemon default applies"
        );
        assert!(
            body["mem_size_mib"].is_null(),
            "mem_size_mib must be null when unset so the daemon default applies"
        );
    }

    #[test]
    fn request_body_sends_explicit_cli_cpus_and_memory() {
        // CLI flag wins: explicit values are preserved in the body.
        let args = VmRequestArgs {
            cpus: Some(8),
            memory: Some(4096),
            ..VmRequestArgs::default()
        };
        let body = build_vm_request_body(
            "vm",
            args,
            None,
            &Default::default(),
            &Default::default(),
            &Config::default(),
            OutputFormat::Json,
        )
        .unwrap();
        assert_eq!(body["vcpu_count"], serde_json::json!(8));
        assert_eq!(body["mem_size_mib"], serde_json::json!(4096));
    }

    #[test]
    fn profile_fills_cpus_and_memory_when_cli_unset() {
        // Profile wins over unset CLI: memory/cpus from profile reach the body.
        let mut profiles = std::collections::HashMap::new();
        profiles.insert(
            "rust".into(),
            Profile {
                cpus: Some(4),
                memory: Some(8192),
                ..Profile::default()
            },
        );
        let args = VmRequestArgs::default();
        let body = build_vm_request_body(
            "vm",
            args,
            Some("rust"),
            &profiles,
            &Default::default(),
            &Config::default(),
            OutputFormat::Json,
        )
        .unwrap();
        assert_eq!(body["vcpu_count"], serde_json::json!(4));
        assert_eq!(body["mem_size_mib"], serde_json::json!(8192));
    }

    #[test]
    fn cli_flag_wins_over_profile_cpus_and_memory() {
        // Explicit CLI flag overrides profile: body contains CLI value.
        let mut profiles = std::collections::HashMap::new();
        profiles.insert(
            "rust".into(),
            Profile {
                cpus: Some(4),
                memory: Some(8192),
                ..Profile::default()
            },
        );
        let args = VmRequestArgs {
            cpus: Some(2),
            memory: Some(512),
            ..VmRequestArgs::default()
        };
        let body = build_vm_request_body(
            "vm",
            args,
            Some("rust"),
            &profiles,
            &Default::default(),
            &Config::default(),
            OutputFormat::Json,
        )
        .unwrap();
        assert_eq!(body["vcpu_count"], serde_json::json!(2));
        assert_eq!(body["mem_size_mib"], serde_json::json!(512));
    }

    // ── Feature 2: profile merge logic ────────────────────────────────

    #[test]
    fn merge_profiles_local_wins_on_conflict() {
        let mut daemon = std::collections::HashMap::new();
        daemon.insert(
            "rust".into(),
            Profile {
                cpus: Some(4),
                memory: Some(8192),
                ..Profile::default()
            },
        );
        let mut local = std::collections::HashMap::new();
        local.insert(
            "rust".into(),
            Profile {
                cpus: Some(2),
                memory: Some(1024),
                ..Profile::default()
            },
        );
        let (merged, origins) = merge_profiles(daemon, &local);
        assert_eq!(merged["rust"].cpus, Some(2), "local cpus override daemon");
        assert_eq!(
            merged["rust"].memory,
            Some(1024),
            "local memory overrides daemon"
        );
        assert_eq!(
            origins["rust"],
            ProfileOrigin::Local,
            "local override of same-named daemon profile must be Local-origin"
        );
    }

    #[test]
    fn merge_profiles_daemon_only_profile_is_accessible() {
        let mut daemon = std::collections::HashMap::new();
        daemon.insert(
            "py".into(),
            Profile {
                cpus: Some(2),
                memory: Some(4096),
                ..Profile::default()
            },
        );
        let local: std::collections::HashMap<String, Profile> = Default::default();
        let (merged, origins) = merge_profiles(daemon, &local);
        assert!(
            merged.contains_key("py"),
            "daemon-only profile must be visible"
        );
        assert_eq!(merged["py"].cpus, Some(2));
        assert_eq!(
            origins["py"],
            ProfileOrigin::Daemon,
            "daemon-only profile must be Daemon-origin"
        );
    }

    #[test]
    fn merge_profiles_offline_falls_back_to_local() {
        // Empty daemon map (e.g. offline) merges cleanly; local profiles survive.
        let daemon: std::collections::HashMap<String, Profile> = Default::default();
        let mut local = std::collections::HashMap::new();
        local.insert(
            "dev".into(),
            Profile {
                cpus: Some(1),
                memory: Some(512),
                ..Profile::default()
            },
        );
        let (merged, origins) = merge_profiles(daemon, &local);
        assert!(
            merged.contains_key("dev"),
            "local profile must survive offline daemon"
        );
        assert_eq!(
            origins["dev"],
            ProfileOrigin::Local,
            "local-only profile must be Local-origin"
        );
    }

    // ── Issue 1: daemon profile rootfs path resolution ─────────────────

    #[test]
    fn daemon_profile_rootfs_not_resolved_against_client_data_dir() {
        // A bare rootfs name in a daemon profile (e.g. "alpine-x86_64.ext4") must
        // reach the daemon as-is. resolve_rootfs_arg would expand it to a
        // client-local absolute path the daemon cannot use if the client happens
        // to have a same-named file under its data_dir/images/.
        let mut profiles = std::collections::HashMap::new();
        profiles.insert(
            "py".into(),
            Profile {
                rootfs: Some(PathBuf::from("alpine-x86_64.ext4")),
                ..Profile::default()
            },
        );
        let mut origins = std::collections::HashMap::new();
        origins.insert("py".into(), ProfileOrigin::Daemon);

        let args = VmRequestArgs::default();
        let body = build_vm_request_body(
            "vm",
            args,
            Some("py"),
            &profiles,
            &origins,
            &Config::default(),
            OutputFormat::Json,
        )
        .unwrap();
        assert_eq!(
            body["rootfs_path"],
            serde_json::json!("alpine-x86_64.ext4"),
            "daemon profile rootfs must stay opaque and not be resolved against client data_dir"
        );
    }

    #[test]
    fn local_override_of_daemon_profile_rootfs_is_resolved_client_side() {
        // Regression for the name-membership bug: a LOCAL profile that overrides
        // a same-named daemon profile must be treated as Local-origin. Its rootfs
        // must go through resolve_rootfs_arg, not pass through opaque.
        // We use an absolute path so resolve_rootfs_arg returns it unchanged
        // (no data_dir expansion needed) and we can assert it is present.
        let mut profiles = std::collections::HashMap::new();
        profiles.insert(
            "rust".into(),
            Profile {
                rootfs: Some(PathBuf::from("/local/override/rootfs.ext4")),
                cpus: Some(4),
                ..Profile::default()
            },
        );
        // Local wins: origin is Local even though "rust" was also a daemon name.
        let mut origins = std::collections::HashMap::new();
        origins.insert("rust".into(), ProfileOrigin::Local);

        let args = VmRequestArgs::default();
        let body = build_vm_request_body(
            "vm",
            args,
            Some("rust"),
            &profiles,
            &origins,
            &Config::default(),
            OutputFormat::Json,
        )
        .unwrap();
        // The local-profile rootfs must appear in the body (resolved client-side).
        assert_eq!(
            body["rootfs_path"],
            serde_json::json!("/local/override/rootfs.ext4"),
            "local-origin profile rootfs must be resolved client-side, not passed through opaque"
        );
    }

    #[test]
    fn cli_explicit_rootfs_is_still_resolved_when_daemon_profile_is_active() {
        // When the user passes --rootfs explicitly on the CLI AND selects a daemon
        // profile, the explicitly-provided rootfs goes through resolve_rootfs_arg as
        // usual (it is a client-side path). Only rootfs values *filled by* a daemon
        // profile skip resolution.
        let mut profiles = std::collections::HashMap::new();
        profiles.insert(
            "py".into(),
            Profile {
                cpus: Some(2),
                ..Profile::default()
            },
        );
        let mut origins = std::collections::HashMap::new();
        origins.insert("py".into(), ProfileOrigin::Daemon);

        // Pass an explicit rootfs that doesn't exist; resolve_rootfs_arg returns it
        // unchanged when neither the path itself nor data_dir/images/<name> exists.
        let args = VmRequestArgs {
            rootfs: Some(PathBuf::from("/explicit/path/rootfs.ext4")),
            ..VmRequestArgs::default()
        };
        let body = build_vm_request_body(
            "vm",
            args,
            Some("py"),
            &profiles,
            &origins,
            &Config::default(),
            OutputFormat::Json,
        )
        .unwrap();
        // The CLI-explicit path should appear in the body (resolve returns it
        // unchanged since the file does not exist locally).
        assert_eq!(
            body["rootfs_path"],
            serde_json::json!("/explicit/path/rootfs.ext4"),
            "CLI-explicit rootfs must still be sent even when a daemon profile is selected"
        );
    }

    #[test]
    fn profile_to_daemon_and_back_roundtrip() {
        let p = Profile {
            cpus: Some(4),
            memory: Some(8192),
            rootfs: Some(PathBuf::from("rust")),
            env: vec!["RUST_LOG=debug".into()],
            ..Profile::default()
        };
        let d = profile_to_daemon(&p);
        assert_eq!(d.cpus, Some(4));
        assert_eq!(d.memory, Some(8192));
        assert_eq!(d.rootfs.as_deref(), Some("rust"));
        assert_eq!(d.env, vec!["RUST_LOG=debug"]);

        let p2 = daemon_to_profile(d);
        assert_eq!(p2.cpus, Some(4));
        assert_eq!(p2.memory, Some(8192));
        assert_eq!(p2.rootfs, Some(PathBuf::from("rust")));
    }

    // ── fetch_daemon_profiles error classification ────────────────────────

    /// Spin up a one-shot TCP server that returns a fixed HTTP response to the
    /// first connection, then return the base URL so callers can pass it to
    /// `fetch_daemon_profiles`.
    async fn profiles_server(status: &str, body: &str) -> String {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let status = status.to_string();
        let body = body.to_string();
        let body_len = body.len();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 1024];
            let _ = stream.read(&mut req).await;
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n{body}"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn fetch_daemon_profiles_surfaces_401_as_error() {
        let base_url = profiles_server("401 Unauthorized", "").await;
        let client = DaemonClient::new(base_url, None);
        let result = fetch_daemon_profiles(&client).await;
        assert!(
            result.is_err(),
            "401 from daemon profiles endpoint must surface as an error, not silent fallback"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("401") || msg.contains("rejected"),
            "error message should mention the rejection, got: {msg}"
        );
    }

    #[tokio::test]
    async fn fetch_daemon_profiles_surfaces_403_as_error() {
        let base_url = profiles_server("403 Forbidden", "").await;
        let client = DaemonClient::new(base_url, None);
        let result = fetch_daemon_profiles(&client).await;
        assert!(
            result.is_err(),
            "403 from daemon profiles endpoint must surface as an error, not silent fallback"
        );
    }

    #[tokio::test]
    async fn fetch_daemon_profiles_surfaces_500_as_error() {
        let base_url = profiles_server("500 Internal Server Error", "").await;
        let client = DaemonClient::new(base_url, None);
        let result = fetch_daemon_profiles(&client).await;
        assert!(
            result.is_err(),
            "5xx from daemon profiles endpoint must surface as an error, not silent fallback"
        );
    }

    #[tokio::test]
    async fn fetch_daemon_profiles_falls_back_silently_on_404() {
        let base_url = profiles_server("404 Not Found", "").await;
        let client = DaemonClient::new(base_url, None);
        let result = fetch_daemon_profiles(&client).await;
        assert!(
            result.is_ok(),
            "404 (old daemon without /v1/profiles) must fall back silently, not error"
        );
        assert!(
            result.unwrap().is_none(),
            "404 fallback must return None to distinguish from a reachable daemon with zero profiles"
        );
    }

    #[tokio::test]
    async fn fetch_daemon_profiles_falls_back_silently_on_connection_refused() {
        // Port 9 is the discard port; connections are refused on most systems.
        // The key property is that the address is not listening, so send() fails
        // at the connection layer rather than returning an HTTP response.
        let client = DaemonClient::with_timeout(
            "http://127.0.0.1:9",
            None,
            std::time::Duration::from_secs(2),
        )
        .unwrap();
        let result = fetch_daemon_profiles(&client).await;
        assert!(
            result.is_ok(),
            "connection-level failure must fall back silently, not error"
        );
        assert!(
            result.unwrap().is_none(),
            "connection-failure fallback must return None to distinguish from a reachable daemon with zero profiles"
        );
    }

    #[tokio::test]
    async fn fetch_daemon_profiles_returns_some_for_reachable_empty_daemon() {
        // A daemon that is reachable and returns 200 with an empty profiles map
        // must produce Ok(Some(empty map)), not Ok(None). This distinguishes
        // "daemon online, zero profiles" from "daemon offline / fell back".
        let base_url = profiles_server("200 OK", r#"{"profiles":{}}"#).await;
        let client = DaemonClient::new(base_url, None);
        let result = fetch_daemon_profiles(&client).await;
        assert!(result.is_ok(), "200 with empty profiles map must not error");
        let opt = result.unwrap();
        assert!(
            opt.is_some(),
            "reachable daemon returning empty profiles must yield Some(map), not None"
        );
        assert!(
            opt.unwrap().is_empty(),
            "the returned map should be empty when the daemon has no profiles"
        );
    }

    // ── schema_command_annotations: profile list ─────────────────────────

    #[test]
    fn schema_annotation_profile_list_is_non_mutating() {
        let (mutating, _fields) = schema_command_annotations("profile list");
        assert!(
            !mutating,
            "profile list is a read-only introspection command and must not be marked mutating"
        );
    }

    #[test]
    fn schema_annotation_profile_list_has_output_fields() {
        let (_mutating, fields) = schema_command_annotations("profile list");
        assert!(
            fields.contains(&"status"),
            "profile list output must include 'status'"
        );
        assert!(
            fields.contains(&"action"),
            "profile list output must include 'action'"
        );
        assert!(
            fields.contains(&"profiles"),
            "profile list output must include 'profiles'"
        );
    }

    #[test]
    fn effective_state_dir_defaults_to_data_dir() {
        let mut cfg = Config {
            data_dir: PathBuf::from("/var/lib/husker"),
            state_dir: None,
            ..Config::default()
        };
        assert_eq!(cfg.effective_state_dir(), PathBuf::from("/var/lib/husker"));
        cfg.state_dir = Some(PathBuf::from("/var/lib/husker-state"));
        assert_eq!(
            cfg.effective_state_dir(),
            PathBuf::from("/var/lib/husker-state")
        );
    }

    #[test]
    fn second_daemon_lock_acquisition_fails() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("husker.lock");
        let _held = acquire_daemon_lock(&lock).expect("first lock acquires");
        // A second exclusive non-blocking lock on the same path must fail.
        assert!(acquire_daemon_lock(&lock).is_err());
    }

    #[test]
    fn mount_guard_logic() {
        assert!(storage_mount_satisfied(false, false)); // flag off -> always ok
        assert!(storage_mount_satisfied(true, true)); // mounted -> ok
        assert!(!storage_mount_satisfied(true, false)); // flag on, not mounted -> refuse
    }

    #[test]
    fn is_local_target_excludes_ssh_tunnels() {
        // Genuinely local: a direct http URL to localhost, no tunnel.
        assert!(is_local_target("http://127.0.0.1:7777", false));
        assert!(is_local_target("http://localhost:7777", false));
        // Remote over ssh: the tunnel URL is localhost but the host is remote.
        assert!(!is_local_target("http://127.0.0.1:45321", true));
        // Remote http context (non-localhost) is never local.
        assert!(!is_local_target("http://192.0.2.5:7777", false));
    }

    #[test]
    fn doctor_exit_code_from_report() {
        use husker_core::{CheckResult, CheckStatus, DiagnosticsReport};
        let ok = DiagnosticsReport {
            checks: vec![CheckResult {
                name: "x".into(),
                status: CheckStatus::Warn,
                message: "m".into(),
            }],
        };
        assert_eq!(doctor_exit_code(&ok), 0); // warnings do not fail
        let bad = DiagnosticsReport {
            checks: vec![CheckResult {
                name: "x".into(),
                status: CheckStatus::Fail,
                message: "m".into(),
            }],
        };
        assert_eq!(doctor_exit_code(&bad), exit_code::GENERAL);
    }

    #[test]
    fn setup_storage_in_schema_is_read_only() {
        // build_cli_schema derives from clap; the annotation marks setup storage read-only.
        let (mutating, _fields) = schema_command_annotations("setup storage");
        assert!(
            !mutating,
            "setup storage only prints/writes files; must be read-only"
        );
    }
}
