//! `husker job` orchestration, split out of `main.rs` so its decision logic is
//! unit-testable and its execution path can be exercised end-to-end against a
//! stub daemon (see the tests below). The HTTP round-trips themselves are
//! covered by the `husker-api` integration tests; here we test the CLI's own
//! responsibility: issuing the right requests in the right order and turning
//! the responses into the right outcome.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::cli::OutputFormat;
use crate::{
    SYNC_ARCHIVE_GUEST_PATH, SYNC_OUTPUT_GUEST_PATH, SYNC_WORKDIR, api_error, api_request,
    apply_dns_hosts, build_sync_archive, collect_sync_paths, extract_archive_over,
    serial_boot_hint, with_api_auth, wrap_sync_command,
};

/// Which image/boot/idle flags were supplied. `--pool` forks the job's VM from
/// the pool's template, so none of these apply; the caller reports any that were
/// set as a conflict.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct PoolFlags {
    pub rootfs: bool,
    pub kernel: bool,
    pub initrd: bool,
    pub cpus: bool,
    pub memory: bool,
    pub vmm: bool,
    pub cloud_image: bool,
    pub disk_size: bool,
    pub volume: bool,
    pub net: bool,
    pub profile: bool,
    pub balloon: bool,
    pub ssh_key: bool,
    pub idle: bool,
    pub idle_timeout: bool,
    pub suspend_ttl: bool,
    pub no_auto_resume: bool,
}

/// Names of the flags in `flags` that conflict with `--pool`, in a stable order
/// for a deterministic error message. Empty when `--pool` was used correctly.
pub(crate) fn pool_conflicting_flags(flags: &PoolFlags) -> Vec<&'static str> {
    let mut conflicts = Vec::new();
    for (set, name) in [
        (flags.rootfs, "--rootfs"),
        (flags.kernel, "--kernel"),
        (flags.initrd, "--initrd"),
        (flags.cpus, "--cpus"),
        (flags.memory, "--memory"),
        (flags.vmm, "--vmm"),
        (flags.cloud_image, "--cloud-image"),
        (flags.disk_size, "--disk-size"),
        (flags.volume, "--volume"),
        (flags.net, "--net"),
        (flags.profile, "--profile"),
        (flags.balloon, "--balloon"),
        (flags.ssh_key, "--ssh-key"),
        (flags.idle, "--idle"),
        (flags.idle_timeout, "--idle-timeout"),
        (flags.suspend_ttl, "--suspend-ttl"),
        (flags.no_auto_resume, "--no-auto-resume"),
    ] {
        if set {
            conflicts.push(name);
        }
    }
    conflicts
}

/// Resolve the `(command, args)` to exec for a non-`--sync-cwd` job. An empty
/// command runs the image's default entrypoint (the guest agent resolves it
/// from the OCI config), represented as an empty command string.
pub(crate) fn resolve_exec_command(command: &[String]) -> (String, Vec<String>) {
    match command.split_first() {
        None => (String::new(), Vec::new()),
        Some((first, rest)) => (first.clone(), rest.to_vec()),
    }
}

/// Parse `KEY=VALUE` env entries into a map. Entries without a `=` are skipped;
/// the value keeps any further `=` (e.g. `A=b=c` -> `A` => `b=c`).
pub(crate) fn parse_env_map(env: &[String]) -> HashMap<String, String> {
    env.iter()
        .filter_map(|s| {
            s.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

/// Inputs for a single `husker job` run, bundled to keep `run_job`'s signature
/// manageable. Everything is borrowed from the caller's parsed CLI state.
pub(crate) struct JobRequest<'a> {
    pub client: &'a reqwest::Client,
    pub api_url: &'a str,
    pub api_token: Option<&'a str>,
    pub output: OutputFormat,
    pub name: &'a str,
    pub pool: Option<&'a str>,
    pub body: Option<&'a serde_json::Value>,
    pub timeout: u64,
    pub dns: &'a [String],
    pub add_host: &'a [(String, String)],
    pub sync_cwd: bool,
    pub write_back: bool,
    pub out: &'a [PathBuf],
    pub command: &'a [String],
    pub env: &'a [String],
    pub secret_env: &'a serde_json::Map<String, serde_json::Value>,
}

/// Orchestrate a one-shot job against the daemon: create the VM (pool checkout
/// or fresh boot), wait for readiness, apply DNS/host overrides, optionally sync
/// the working tree, exec the command, and pull back requested outputs. Returns
/// the raw exec result JSON (carrying `exit_code`/`stdout`/`stderr`); the caller
/// handles cleanup, printing, and the process exit code.
pub(crate) async fn run_job(req: JobRequest<'_>) -> Result<serde_json::Value> {
    let client = req.client;
    let api_url = req.api_url;
    let api_token = req.api_token;
    let output = req.output;
    let name = req.name;

    // 1. Create the VM: fork it from the pool, or boot from the body.
    let resp = if let Some(pool) = req.pool {
        api_request(
            with_api_auth(
                client.post(format!("{api_url}/v1/pools/{pool}/checkout")),
                api_token,
            )
            .json(&serde_json::json!({ "vm_name": name })),
        )
        .await?
    } else {
        api_request(
            with_api_auth(client.post(format!("{api_url}/v1/vms")), api_token)
                .json(req.body.expect("non-pool job builds a create body")),
        )
        .await?
    };
    if !resp.status().is_success() {
        let msg = api_error(resp, &format!("VM '{name}'")).await;
        anyhow::bail!("{}", msg.message);
    }
    if output == OutputFormat::Text {
        eprintln!("[job] vm {name} created, waiting for agent...");
    }

    // Old-daemon warning: if the requested timeout exceeds the historical
    // 30-second exec default, check the daemon version. Daemons older than
    // 0.4.2 ignore timeout_secs and cap execution at exec_timeout_secs.
    if req.timeout > 30 {
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
            let parts: Vec<u64> = ver_str.split('.').filter_map(|p| p.parse().ok()).collect();
            if let [major, minor, patch] = parts.as_slice()
                && (*major, *minor, *patch) < (0, 4, 2)
            {
                eprintln!(
                    "[job] warning: daemon {ver_str} does not support --timeout; execution \
                     will be capped at the daemon's exec_timeout_secs setting"
                );
            }
        }
    }

    // 2. Boot-mode-aware readiness wait (mirrors Commands::Wait logic).
    let info_url = format!("{api_url}/v1/vms/{name}");
    let resp = api_request(with_api_auth(client.get(&info_url), api_token)).await?;
    if !resp.status().is_success() {
        let msg = api_error(resp, &format!("VM '{name}'")).await;
        anyhow::bail!("{}", msg.message);
    }
    let vm: serde_json::Value = resp.json().await?;
    let boot_mode = vm
        .get("boot_mode")
        .and_then(|b| b.as_str())
        .unwrap_or("direct");
    let ready_url = format!("{api_url}/v1/vms/{name}/ready");
    let deadline = std::time::Instant::now() + husker_core::default_ready_timeout(boot_mode);
    let mut backoff = std::time::Duration::from_millis(200);
    loop {
        let resp = api_request(with_api_auth(client.get(&ready_url), api_token)).await?;
        if !resp.status().is_success() {
            let msg = api_error(resp, &format!("VM '{name}'")).await;
            anyhow::bail!("{}", msg.message);
        }
        let rdy: serde_json::Value = resp.json().await?;
        if rdy.get("ready").and_then(|r| r.as_bool()).unwrap_or(false) {
            break;
        }
        if std::time::Instant::now() + backoff >= deadline {
            let hint = serial_boot_hint(client, api_url, api_token, name).await;
            anyhow::bail!("timed out waiting for VM '{name}' to become ready{hint}");
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(std::time::Duration::from_secs(2));
    }

    // 2.4 Apply per-VM DNS / host overrides before running the command.
    apply_dns_hosts(client, api_url, api_token, name, req.dns, req.add_host).await?;

    // 2.5 Optionally sync the working tree into the VM (git-aware, clean-room):
    // upload a tar.gz of the cwd and wrap the command to extract and run it
    // inside the guest. The host filesystem is never modified unless the
    // command's results are explicitly pulled back (--out / --write-back).
    let mut retrieve_paths: Vec<PathBuf> = Vec::new();
    let mut sync_cwd_dir: Option<PathBuf> = None;
    let (exec_command, exec_args): (String, Vec<String>) = if req.sync_cwd {
        let cwd = std::env::current_dir().context("resolving current directory for --sync-cwd")?;
        if output == OutputFormat::Text {
            eprintln!("[job] syncing working tree from {}", cwd.display());
        }
        let archive = build_sync_archive(&cwd)?;
        let encoded = husker_agent_proto::base64_encode(&archive);
        let write_resp = api_request(
            with_api_auth(
                client.post(format!("{api_url}/v1/vms/{name}/files/write")),
                api_token,
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
        if req.write_back {
            retrieve_paths.extend(collect_sync_paths(&cwd)?);
        }
        // --out returns the named paths (files or dirs).
        retrieve_paths.extend(req.out.iter().cloned());
        retrieve_paths.sort();
        retrieve_paths.dedup();
        sync_cwd_dir = Some(cwd);
        wrap_sync_command(
            SYNC_ARCHIVE_GUEST_PATH,
            SYNC_WORKDIR,
            req.command,
            SYNC_OUTPUT_GUEST_PATH,
            &retrieve_paths,
        )
    } else {
        // Non-sync: split the trailing command into (cmd, args). An empty
        // command tells the guest agent to resolve the image's default
        // entrypoint + cmd from the OCI config.
        resolve_exec_command(req.command)
    };

    // 3. Run the command via exec.
    if output == OutputFormat::Text {
        eprintln!("[job] running command");
    }
    let env_map = parse_env_map(req.env);
    let mut exec_body = serde_json::json!({
        "command": exec_command,
        "args": exec_args,
        "env": env_map,
        "timeout_secs": req.timeout,
    });
    if !req.secret_env.is_empty() {
        exec_body["secret_env"] = serde_json::Value::Object(req.secret_env.clone());
    }
    let resp = api_request(
        with_api_auth(
            client.post(format!("{api_url}/v1/vms/{name}/exec")),
            api_token,
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
                api_token,
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
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_conflicts_empty_when_no_flags_set() {
        assert!(pool_conflicting_flags(&PoolFlags::default()).is_empty());
    }

    #[test]
    fn pool_conflicts_lists_each_set_flag_in_order() {
        let flags = PoolFlags {
            rootfs: true,
            memory: true,
            balloon: true,
            no_auto_resume: true,
            ..PoolFlags::default()
        };
        assert_eq!(
            pool_conflicting_flags(&flags),
            vec!["--rootfs", "--memory", "--balloon", "--no-auto-resume"]
        );
    }

    #[test]
    fn pool_conflicts_reports_every_flag() {
        // Every field true -> every flag name reported (guards against a field
        // being added to the struct but forgotten in the conflict list).
        let all = PoolFlags {
            rootfs: true,
            kernel: true,
            initrd: true,
            cpus: true,
            memory: true,
            vmm: true,
            cloud_image: true,
            disk_size: true,
            volume: true,
            net: true,
            profile: true,
            balloon: true,
            ssh_key: true,
            idle: true,
            idle_timeout: true,
            suspend_ttl: true,
            no_auto_resume: true,
        };
        assert_eq!(pool_conflicting_flags(&all).len(), 17);
    }

    #[test]
    fn resolve_exec_command_empty_runs_image_default() {
        assert_eq!(resolve_exec_command(&[]), (String::new(), Vec::new()));
    }

    #[test]
    fn resolve_exec_command_splits_command_and_args() {
        let cmd = vec!["ls".to_string(), "-la".to_string(), "/tmp".to_string()];
        assert_eq!(
            resolve_exec_command(&cmd),
            (
                "ls".to_string(),
                vec!["-la".to_string(), "/tmp".to_string()]
            )
        );
    }

    #[test]
    fn resolve_exec_command_single_element_has_no_args() {
        let cmd = vec!["whoami".to_string()];
        assert_eq!(
            resolve_exec_command(&cmd),
            ("whoami".to_string(), Vec::new())
        );
    }

    #[test]
    fn parse_env_map_parses_and_skips_malformed() {
        let env = vec![
            "PATH=/usr/bin".to_string(),
            "EMPTY=".to_string(),
            "no_equals".to_string(),
            "A=b=c".to_string(),
        ];
        let map = parse_env_map(&env);
        assert_eq!(map.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert_eq!(map.get("EMPTY").map(String::as_str), Some(""));
        assert_eq!(map.get("A").map(String::as_str), Some("b=c"));
        assert!(!map.contains_key("no_equals"));
        assert_eq!(map.len(), 3);
    }

    // --- Behavioural tests: run_job against a stub daemon ---------------------
    //
    // These exercise the real run_job orchestration (create -> ready -> exec)
    // over real HTTP against a tiny canned-response server. They test the CLI's
    // own responsibility - issuing the right requests in the right order and
    // turning responses into the right outcome. The daemon's behaviour behind
    // those endpoints is covered by the husker-api integration tests.

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::http::StatusCode;
    use axum::routing::{get, post};
    use axum::{Json, Router};

    /// Bind an axum app to an ephemeral port and return its base URL plus the
    /// serving task handle.
    async fn serve_stub(app: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), handle)
    }

    fn base_request<'a>(
        client: &'a reqwest::Client,
        api_url: &'a str,
        body: &'a serde_json::Value,
        command: &'a [String],
        secret_env: &'a serde_json::Map<String, serde_json::Value>,
    ) -> JobRequest<'a> {
        JobRequest {
            client,
            api_url,
            api_token: None,
            output: OutputFormat::Json,
            name: "job-x",
            pool: None,
            body: Some(body),
            timeout: 10,
            dns: &[],
            add_host: &[],
            sync_cwd: false,
            write_back: false,
            out: &[],
            command,
            env: &[],
            secret_env,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_job_creates_waits_execs_and_returns_result() {
        // Count the exec calls to prove the command actually ran.
        let execs = Arc::new(AtomicUsize::new(0));
        let execs_route = execs.clone();
        let app = Router::new()
            .route(
                "/v1/vms",
                post(|| async {
                    (
                        StatusCode::CREATED,
                        Json(serde_json::json!({"name": "job-x"})),
                    )
                }),
            )
            .route(
                "/v1/vms/{name}",
                get(|| async { Json(serde_json::json!({"boot_mode": "direct"})) }),
            )
            .route(
                "/v1/vms/{name}/ready",
                get(|| async { Json(serde_json::json!({"ready": true})) }),
            )
            .route(
                "/v1/vms/{name}/exec",
                post(move || {
                    let execs = execs_route.clone();
                    async move {
                        execs.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!({
                            "exit_code": 7,
                            "stdout": "hello\n",
                            "stderr": "warn\n",
                        }))
                    }
                }),
            );
        let (api_url, server) = serve_stub(app).await;

        let client = reqwest::Client::new();
        let body = serde_json::json!({ "name": "job-x" });
        let command = vec!["echo".to_string(), "hello".to_string()];
        let secret_env = serde_json::Map::new();
        let result = run_job(base_request(
            &client,
            &api_url,
            &body,
            &command,
            &secret_env,
        ))
        .await
        .expect("run_job should succeed against a healthy stub");

        assert_eq!(result["exit_code"].as_i64(), Some(7));
        assert_eq!(result["stdout"].as_str(), Some("hello\n"));
        assert_eq!(result["stderr"].as_str(), Some("warn\n"));
        assert_eq!(execs.load(Ordering::SeqCst), 1, "exec must be called once");
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_job_surfaces_a_create_failure_as_error() {
        // The daemon rejects the create; run_job must return an error (not exec).
        let execs = Arc::new(AtomicUsize::new(0));
        let execs_route = execs.clone();
        let app = Router::new()
            .route(
                "/v1/vms",
                post(|| async {
                    (
                        StatusCode::CONFLICT,
                        Json(serde_json::json!({"error": {"message": "name taken"}})),
                    )
                }),
            )
            .route(
                "/v1/vms/{name}/exec",
                post(move || {
                    let execs = execs_route.clone();
                    async move {
                        execs.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!({"exit_code": 0}))
                    }
                }),
            );
        let (api_url, server) = serve_stub(app).await;

        let client = reqwest::Client::new();
        let body = serde_json::json!({ "name": "job-x" });
        let command = vec!["true".to_string()];
        let secret_env = serde_json::Map::new();
        let err = run_job(base_request(
            &client,
            &api_url,
            &body,
            &command,
            &secret_env,
        ))
        .await
        .expect_err("a failed create must abort the job");

        assert!(
            err.to_string().contains("name taken"),
            "error should carry the daemon message, got: {err}"
        );
        assert_eq!(
            execs.load(Ordering::SeqCst),
            0,
            "exec must not run after a failed create"
        );
        server.abort();
    }
}
