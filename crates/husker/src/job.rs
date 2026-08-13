//! `husker job` orchestration, split out of `main.rs` so its decision logic is
//! unit-testable and its execution path can be exercised end-to-end against a
//! stub daemon (see the tests below). The HTTP round-trips themselves are
//! covered by the `husker-api` integration tests; here we test the CLI's own
//! responsibility: issuing the right requests in the right order and turning
//! the responses into the right outcome.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::cli::OutputFormat;
use crate::cli_contract::structured_output;
use crate::daemon_client::{ApiFailure, DaemonClient};
use crate::guest_file::{GuestFile, read_guest_file};
use crate::schema::exit_code;
use crate::vm_creation::PreparedVmCreationPlan;
use crate::{
    SYNC_ARCHIVE_GUEST_PATH, SYNC_MANIFEST_GUEST_PATH, SYNC_OUTPUT_GUEST_PATH, SYNC_WORKDIR,
    apply_dns_hosts, build_sync_archive, collect_sync_paths, extract_archive_over,
    serial_boot_hint, wrap_sync_command,
};

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

/// What `--out`/`--write-back` brought back from the guest.
///
/// The three outcomes are kept apart deliberately. "Files arrived", "the guest
/// genuinely produced none of the requested paths" and "the transfer failed" are
/// different facts with different fixes, and collapsing them into one empty list
/// is what let an artifact too large to transfer be reported as an artifact the
/// command never wrote - with an exit code of zero.
#[derive(Debug, Default)]
pub(crate) struct Retrieval {
    /// Paths written to the host, relative to the synced directory.
    pub files: Vec<String>,
    /// The `--out` patterns that matched nothing on the guest, as the user wrote
    /// them.
    pub unmatched_out: Vec<String>,
    /// Synced paths that `--write-back` found gone from the guest tree, meaning
    /// the command deleted or renamed them. A legitimate result, so reported
    /// rather than treated as a failure.
    pub unmatched_write_back: Vec<String>,
    /// Why the outputs could not be brought back. Distinct from an empty
    /// `files`: this says the question could not be answered, not that the
    /// answer was "none".
    pub error: Option<ApiFailure>,
}

impl Retrieval {
    /// The failure that should end the job, if any.
    ///
    /// A retrieval that could not be completed is one. So is an explicit `--out`
    /// that matched nothing: naming an output is asking for it, and a job that
    /// silently produces none of what it was asked for has not succeeded.
    /// `--write-back` matching nothing is not a failure - it means the command
    /// removed a file it was handed, which is a legitimate thing to do.
    pub(crate) fn failure(&self) -> Option<ApiFailure> {
        if let Some(err) = &self.error {
            return Some(err.clone());
        }
        if self.unmatched_out.is_empty() {
            return None;
        }
        Some(ApiFailure {
            message: format!(
                "--out matched nothing on the guest: {}",
                self.unmatched_out.join(", ")
            ),
            kind: Some("out_matched_nothing".to_string()),
            exit_code: exit_code::GENERAL,
            hint: Some(
                "--out patterns are relative to the synced working tree; a build that writes \
                 outside it (CARGO_TARGET_DIR on a --volume, an absolute output path) produces \
                 nothing for --out to match"
                    .to_string(),
            ),
        })
    }

    /// The retrieval as it appears in `--output json`, so a machine consumer
    /// sees exactly what a human does. `error` is null rather than absent when
    /// the retrieval worked, so the field's presence never has to be tested.
    pub(crate) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "files": self.files,
            "unmatched_out": self.unmatched_out,
            "unmatched_write_back": self.unmatched_write_back,
            "error": self.error.as_ref().map(|e| e.message.clone()),
        })
    }

    /// Report the retrieval on stderr for a human. The error is left out: the
    /// caller decides whether it ends the job (and gets the error envelope) or
    /// merely accompanies a command that had already failed, and printing it
    /// here would duplicate that.
    pub(crate) fn report_text(&self) {
        if self.files.is_empty() {
            if self.error.is_none() && self.unmatched_out.is_empty() {
                eprintln!("[job] retrieved no files (nothing requested held a regular file)");
            }
        } else {
            eprintln!("[job] retrieved {} file(s) to host:", self.files.len());
            for f in &self.files {
                eprintln!("  {f}");
            }
        }
        if !self.unmatched_write_back.is_empty() {
            eprintln!(
                "[job] --write-back: {} synced path(s) no longer in the guest tree: {}",
                self.unmatched_write_back.len(),
                self.unmatched_write_back.join(", ")
            );
        }
    }
}

/// Parse the guest retrieval manifest into zero-based indices into the request
/// list. The guest writes one 1-based position per line for each pattern that
/// matched nothing.
///
/// Blank lines and positions outside the request are dropped: a manifest that
/// disagrees with the request describes a guest running a different wrapper, and
/// guessing which pattern such a line meant would misname the one reported as
/// unmatched.
fn parse_unmatched_manifest(bytes: &[u8], pattern_count: usize) -> Vec<usize> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter_map(|line| line.trim().parse::<usize>().ok())
        .filter(|pos| (1..=pattern_count).contains(pos))
        .map(|pos| pos - 1)
        .collect()
}

/// Inputs for one complete `husker job` lifecycle. Everything is borrowed from
/// the caller's parsed CLI state; acquisition, execution, interruption, and
/// cleanup policy stay behind this module's interface.
pub(crate) struct JobRequest<'a> {
    pub daemon: &'a DaemonClient,
    pub output: OutputFormat,
    pub name: &'a str,
    pub creation: PreparedVmCreationPlan,
    pub keep: bool,
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

/// The only process decision exposed by the Job module. `main.rs` applies it;
/// all Job-specific precedence and cleanup decisions have already happened.
#[derive(Debug)]
pub(crate) enum JobTermination {
    Success,
    Exit(i32),
    Failure(ApiFailure),
}

#[derive(Debug, serde::Deserialize)]
struct JobExecution {
    #[serde(default = "default_job_exit_code")]
    exit_code: i64,
    #[serde(default)]
    stdout: String,
    #[serde(default)]
    stderr: String,
}

fn default_job_exit_code() -> i64 {
    1
}

/// Internal result of command execution, before keep/destroy and process-exit
/// policy are applied.
#[derive(Debug)]
struct JobOutcome {
    exec: JobExecution,
    /// The outcome of `--out`/`--write-back`, or `None` when the job requested
    /// no outputs. `None` and an empty [`Retrieval`] are different: nothing was
    /// asked for, versus nothing came back.
    retrieval: Option<Retrieval>,
}

/// Own one complete Job lifecycle. The outer process adapter receives only the
/// final termination decision; validation, acquisition tracking, interruption,
/// rendering, cleanup, and failure precedence remain local to this module.
pub(crate) async fn run_job(req: JobRequest<'_>) -> JobTermination {
    run_job_with_interrupt(req, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

async fn run_job_with_interrupt<F>(req: JobRequest<'_>, interrupt: F) -> JobTermination
where
    F: Future<Output = ()>,
{
    if let Err(failure) = validate_request(&req) {
        return JobTermination::Failure(failure);
    }

    tokio::pin!(interrupt);
    let create = create_job_vm(&req);
    tokio::pin!(create);
    tokio::select! {
        biased;
        result = &mut create => match result {
            Ok(()) => (),
            Err(error) => return JobTermination::Failure(ApiFailure::from_error(&error)),
        },
        _ = &mut interrupt => {
            eprintln!(
                "[job] interrupted before VM acquisition completed; no VM was destroyed"
            );
            return JobTermination::Exit(130);
        }
    }

    let execution = execute_created_job(&req);
    tokio::pin!(execution);
    let result = tokio::select! {
        result = &mut execution => result,
        _ = &mut interrupt => {
            if req.keep {
                eprintln!("[job] interrupted, keeping {}", req.name);
            } else {
                eprintln!("[job] interrupted, destroying {}", req.name);
                report_secondary_cleanup_failure(cleanup_vm(&req).await);
            }
            return JobTermination::Exit(130);
        }
    };

    match result {
        Ok(outcome) => finish_job(&req, outcome).await,
        Err(error) => {
            let failure = ApiFailure::from_error(&error);
            if req.keep {
                eprintln!("[job] failed, keeping {}: {}", req.name, failure.message);
            } else {
                report_secondary_cleanup_failure(cleanup_vm(&req).await);
            }
            JobTermination::Failure(failure)
        }
    }
}

fn validate_request(req: &JobRequest<'_>) -> std::result::Result<(), ApiFailure> {
    if req.sync_cwd && req.command.is_empty() {
        return Err(
            "--sync-cwd needs a command after `--`; the image default is only used without \
             --sync-cwd"
                .into(),
        );
    }
    Ok(())
}

async fn create_job_vm(req: &JobRequest<'_>) -> Result<()> {
    let daemon = req.daemon;
    let name = req.name;
    let resp = req.creation.execute(daemon).await?;
    if !resp.status().is_success() {
        return Err(daemon.error(resp, &format!("VM '{name}'")).await.into());
    }
    Ok(())
}

async fn execute_created_job(req: &JobRequest<'_>) -> Result<JobOutcome> {
    let daemon = req.daemon;
    let output = req.output;
    let name = req.name;

    if output == OutputFormat::Text {
        eprintln!("[job] vm {name} created, waiting for agent...");
    }

    // Old-daemon warning: if the requested timeout exceeds the historical
    // 30-second exec default, check the daemon version. Daemons older than
    // 0.4.2 ignore timeout_secs and cap execution at exec_timeout_secs.
    if req.timeout > 30
        && let Ok(resp) = daemon
            .try_send(
                daemon
                    .get("/v1/health")
                    .timeout(std::time::Duration::from_secs(2)),
            )
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

    // 2. Boot-mode-aware readiness wait (mirrors Commands::Wait logic).
    let info_path = format!("/v1/vms/{name}");
    let resp = daemon.send(daemon.get(&info_path)).await?;
    if !resp.status().is_success() {
        return Err(daemon.error(resp, &format!("VM '{name}'")).await.into());
    }
    let vm: serde_json::Value = resp.json().await?;
    let boot_mode = vm
        .get("boot_mode")
        .and_then(|b| b.as_str())
        .unwrap_or("direct");
    let ready_path = format!("/v1/vms/{name}/ready");
    let deadline = std::time::Instant::now() + husker_core::default_ready_timeout(boot_mode);
    let mut backoff = std::time::Duration::from_millis(200);
    loop {
        let resp = daemon.send(daemon.get(&ready_path)).await?;
        if !resp.status().is_success() {
            return Err(daemon.error(resp, &format!("VM '{name}'")).await.into());
        }
        let rdy: serde_json::Value = resp.json().await?;
        if rdy.get("ready").and_then(|r| r.as_bool()).unwrap_or(false) {
            break;
        }
        if std::time::Instant::now() + backoff >= deadline {
            let hint = serial_boot_hint(daemon, name).await;
            anyhow::bail!("timed out waiting for VM '{name}' to become ready{hint}");
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(std::time::Duration::from_secs(2));
    }

    // 2.4 Apply per-VM DNS / host overrides before running the command.
    apply_dns_hosts(daemon, name, req.dns, req.add_host).await?;

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
        let write_resp = daemon
            .send(
                daemon
                    .post(format!("/v1/vms/{name}/files/write"))
                    .json(&serde_json::json!({
                        "path": SYNC_ARCHIVE_GUEST_PATH,
                        "data": encoded,
                    })),
            )
            .await?;
        if !write_resp.status().is_success() {
            return Err(daemon
                .error(write_resp, &format!("VM '{name}'"))
                .await
                .into());
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
            SYNC_MANIFEST_GUEST_PATH,
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
    let resp = daemon
        .send(daemon.post(format!("/v1/vms/{name}/exec")).json(&exec_body))
        .await?;
    if !resp.status().is_success() {
        return Err(daemon.error(resp, &format!("VM '{name}'")).await.into());
    }
    let exec = resp.json().await?;

    // 3.5 Pull requested results back to the host (--out / --write-back).
    let mut retrieval = None;
    if let Some(cwd) = &sync_cwd_dir
        && !retrieve_paths.is_empty()
    {
        let r = retrieve_outputs(daemon, name, cwd, &retrieve_paths, req.out).await?;
        retrieval = Some(r);
    }
    Ok(JobOutcome { exec, retrieval })
}

async fn finish_job(req: &JobRequest<'_>, outcome: JobOutcome) -> JobTermination {
    let retrieval_failure = outcome.retrieval.as_ref().and_then(Retrieval::failure);
    let exit_code = outcome.exec.exit_code;
    let mut termination = if exit_code != 0 {
        if let Some(failure) = &retrieval_failure
            && req.output == OutputFormat::Text
        {
            eprintln!("[job] note: {}", failure.message);
        }
        JobTermination::Exit(exit_code.clamp(1, 255) as i32)
    } else if let Some(failure) = retrieval_failure.as_ref() {
        JobTermination::Failure(failure.clone())
    } else {
        JobTermination::Success
    };

    let cleanup_failure = if req.keep {
        None
    } else {
        cleanup_vm(req).await
    };
    if let Some(failure) = cleanup_failure.as_ref() {
        if matches!(&termination, JobTermination::Success) {
            termination = JobTermination::Failure(failure.clone());
        } else {
            report_secondary_cleanup_failure(Some(failure.clone()));
        }
    }

    render_outcome(
        req,
        &outcome,
        retrieval_failure.as_ref(),
        !matches!(&termination, JobTermination::Success),
    );

    if req.keep {
        if req.output == OutputFormat::Text {
            eprintln!(
                "[job] exit code {exit_code}, keeping {} \
                 (husker shell {} / husker destroy {})",
                req.name, req.name, req.name
            );
        }
    } else if cleanup_failure.is_none() && req.output == OutputFormat::Text {
        eprintln!("[job] exit code {exit_code}, destroyed vm");
    }

    if req.sync_cwd && exit_code == 127 && req.output == OutputFormat::Text {
        eprintln!(
            "[job] hint: exit 127 usually means the command was not found in the sandbox image. \
             The default image is minimal (no language toolchains); run against an image that \
             includes your toolchain (pass a rootfs path or --cloud-image, e.g. a Docker image \
             brought in with `husker image import-oci`)."
        );
    }

    termination
}

fn render_outcome(
    req: &JobRequest<'_>,
    outcome: &JobOutcome,
    retrieval_failure: Option<&ApiFailure>,
    lifecycle_failed: bool,
) {
    if req.output == OutputFormat::Json {
        let payload = structured_output(
            "job",
            &outcome_json(req.name, outcome, retrieval_failure, lifecycle_failed),
        )
        .expect("job output must match its CLI contract");
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).expect("job output must serialize")
        );
    } else {
        if let Some(retrieval) = &outcome.retrieval {
            retrieval.report_text();
        }
        print!("{}", outcome.exec.stdout);
        eprint!("{}", outcome.exec.stderr);
    }
}

fn outcome_json(
    name: &str,
    outcome: &JobOutcome,
    retrieval_failure: Option<&ApiFailure>,
    lifecycle_failed: bool,
) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "status": if lifecycle_failed || outcome.exec.exit_code != 0 || retrieval_failure.is_some() {
            "error"
        } else {
            "ok"
        },
        "action": "job",
        "vm": name,
        "exit_code": outcome.exec.exit_code,
        "stdout": outcome.exec.stdout,
        "stderr": outcome.exec.stderr,
    });
    if let Some(retrieval) = &outcome.retrieval {
        payload["retrieval"] = retrieval.to_json();
    }
    payload
}

async fn cleanup_vm(req: &JobRequest<'_>) -> Option<ApiFailure> {
    let response = match req
        .daemon
        .send(
            req.daemon
                .delete(format!("/v1/vms/{}", req.name))
                .timeout(std::time::Duration::from_secs(10)),
        )
        .await
    {
        Ok(response) => response,
        Err(error) => return Some(cleanup_failure(req.name, ApiFailure::from_error(&error))),
    };
    if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND {
        return None;
    }
    let failure = req
        .daemon
        .error(response, &format!("VM '{}'", req.name))
        .await;
    Some(cleanup_failure(req.name, failure))
}

fn cleanup_failure(name: &str, mut failure: ApiFailure) -> ApiFailure {
    failure.message = format!(
        "job finished but VM '{name}' could not be destroyed: {}",
        failure.message
    );
    if failure.kind.is_none() {
        failure.kind = Some("job_cleanup_failed".into());
    }
    failure
}

fn report_secondary_cleanup_failure(failure: Option<ApiFailure>) {
    if let Some(failure) = failure {
        eprintln!("[job] warning: {}", failure.message);
    }
}

/// Bring `--out`/`--write-back` results back from the guest and classify what
/// happened.
///
/// Two guest files are involved and both are needed. The manifest says which
/// requested patterns matched nothing - knowable only on the guest, where the
/// expansion happened. The archive holds what did match. Reading the manifest
/// first means an absent archive is never guessed at: either the manifest
/// accounts for every pattern, so there is genuinely nothing to fetch, or some
/// pattern matched and an archive that will not come back is a transfer failure
/// reported as one.
///
/// `retrieve_paths` is the merged, ordered request the guest was given (its
/// order defines the manifest positions); `out` is the subset the user named
/// explicitly, which is what distinguishes a missing artifact from a file the
/// command legitimately deleted.
async fn retrieve_outputs(
    daemon: &DaemonClient,
    name: &str,
    cwd: &std::path::Path,
    retrieve_paths: &[PathBuf],
    out: &[PathBuf],
) -> Result<Retrieval> {
    let manifest = match read_guest_file(daemon, name, SYNC_MANIFEST_GUEST_PATH).await? {
        GuestFile::Read(bytes) => bytes,
        GuestFile::Failed(failure) => {
            return Ok(Retrieval {
                error: Some(ApiFailure {
                    message: format!(
                        "could not read the retrieval manifest from VM '{name}': {}",
                        failure.message
                    ),
                    hint: Some(
                        "the sandbox writes it after the command finishes, so a command that \
                         replaces or kills the shell it runs in prevents both the manifest and \
                         the outputs from being produced"
                            .to_string(),
                    ),
                    ..failure
                }),
                ..Retrieval::default()
            });
        }
    };

    let out_set: std::collections::HashSet<&PathBuf> = out.iter().collect();
    let mut unmatched_out = Vec::new();
    let mut unmatched_write_back = Vec::new();
    for index in parse_unmatched_manifest(&manifest, retrieve_paths.len()) {
        let path = &retrieve_paths[index];
        let display = path.to_string_lossy().into_owned();
        if out_set.contains(path) {
            unmatched_out.push(display);
        } else {
            unmatched_write_back.push(display);
        }
    }

    // Every pattern accounted for as unmatched means the guest built no archive,
    // and asking for one would turn a correct "nothing matched" into a spurious
    // read failure.
    if unmatched_out.len() + unmatched_write_back.len() == retrieve_paths.len() {
        return Ok(Retrieval {
            unmatched_out,
            unmatched_write_back,
            ..Retrieval::default()
        });
    }

    let archive = match read_guest_file(daemon, name, SYNC_OUTPUT_GUEST_PATH).await? {
        GuestFile::Read(bytes) => bytes,
        GuestFile::Failed(failure) => {
            return Ok(Retrieval {
                unmatched_out,
                unmatched_write_back,
                error: Some(ApiFailure {
                    message: format!(
                        "the command produced outputs but they could not be copied back from \
                         VM '{name}': {}",
                        failure.message
                    ),
                    ..failure
                }),
                ..Retrieval::default()
            });
        }
    };

    Ok(Retrieval {
        files: extract_archive_over(&archive, cwd)?,
        unmatched_out,
        unmatched_write_back,
        error: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    use axum::response::IntoResponse;
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

    fn lifecycle_stub(
        exec_exit_code: i64,
        delete_status: StatusCode,
        deletes: Arc<AtomicUsize>,
    ) -> Router {
        Router::new()
            .route(
                "/v1/vms",
                post(|| async { (StatusCode::CREATED, Json(serde_json::json!({}))) }),
            )
            .route(
                "/v1/vms/{name}",
                get(|| async { Json(serde_json::json!({"boot_mode": "direct"})) }).delete(
                    move || {
                        let deletes = deletes.clone();
                        async move {
                            deletes.fetch_add(1, Ordering::SeqCst);
                            delete_status
                        }
                    },
                ),
            )
            .route(
                "/v1/vms/{name}/ready",
                get(|| async { Json(serde_json::json!({"ready": true})) }),
            )
            .route(
                "/v1/vms/{name}/exec",
                post(move || async move {
                    Json(serde_json::json!({
                        "exit_code": exec_exit_code,
                        "stdout": "",
                        "stderr": "",
                    }))
                }),
            )
    }

    fn base_request<'a>(
        daemon: &'a DaemonClient,
        body: &'a serde_json::Value,
        command: &'a [String],
        secret_env: &'a serde_json::Map<String, serde_json::Value>,
    ) -> JobRequest<'a> {
        JobRequest {
            daemon,
            output: OutputFormat::Json,
            name: "job-x",
            creation: PreparedVmCreationPlan::create_for_test(body.clone()),
            keep: false,
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

    #[test]
    fn lifecycle_validation_rejects_sync_without_a_command() {
        let client = DaemonClient::new("http://example.invalid", None);
        let body = serde_json::json!({ "name": "job-x" });
        let command = Vec::new();
        let secret_env = serde_json::Map::new();
        let mut request = base_request(&client, &body, &command, &secret_env);
        request.sync_cwd = true;

        let failure = validate_request(&request).unwrap_err();

        assert!(failure.message.contains("--sync-cwd needs a command"));
    }

    #[test]
    fn nonzero_command_is_rendered_as_error_status() {
        let outcome = JobOutcome {
            exec: JobExecution {
                exit_code: 7,
                stdout: "output".into(),
                stderr: "failure".into(),
            },
            retrieval: None,
        };

        let payload = outcome_json("job-x", &outcome, None, false);

        assert_eq!(payload["status"], "error");
        assert_eq!(payload["exit_code"], 7);
    }

    #[test]
    fn lifecycle_failure_is_rendered_as_error_status() {
        let outcome = JobOutcome {
            exec: JobExecution {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            },
            retrieval: None,
        };

        let payload = outcome_json("job-x", &outcome, None, true);

        assert_eq!(payload["status"], "error");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_job_creates_waits_execs_and_returns_result() {
        // Count the exec calls to prove the command actually ran.
        let execs = Arc::new(AtomicUsize::new(0));
        let execs_route = execs.clone();
        let deletes = Arc::new(AtomicUsize::new(0));
        let deletes_route = deletes.clone();
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
                get(|| async { Json(serde_json::json!({"boot_mode": "direct"})) }).delete(
                    move || {
                        let deletes = deletes_route.clone();
                        async move {
                            deletes.fetch_add(1, Ordering::SeqCst);
                            StatusCode::NO_CONTENT
                        }
                    },
                ),
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

        let client = DaemonClient::new(&api_url, None);
        let body = serde_json::json!({ "name": "job-x" });
        let command = vec!["echo".to_string(), "hello".to_string()];
        let secret_env = serde_json::Map::new();
        let termination = run_job(base_request(&client, &body, &command, &secret_env)).await;

        assert!(matches!(termination, JobTermination::Exit(7)));
        assert_eq!(execs.load(Ordering::SeqCst), 1, "exec must be called once");
        assert_eq!(
            deletes.load(Ordering::SeqCst),
            1,
            "an acquired Job VM must be destroyed exactly once"
        );
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_job_surfaces_a_create_failure_as_error() {
        // The daemon rejects the create; run_job must return an error (not exec).
        let execs = Arc::new(AtomicUsize::new(0));
        let execs_route = execs.clone();
        let deletes = Arc::new(AtomicUsize::new(0));
        let deletes_route = deletes.clone();
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
            )
            .route(
                "/v1/vms/{name}",
                axum::routing::delete(move || {
                    let deletes = deletes_route.clone();
                    async move {
                        deletes.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                }),
            );
        let (api_url, server) = serve_stub(app).await;

        let client = DaemonClient::new(&api_url, None);
        let body = serde_json::json!({ "name": "job-x" });
        let command = vec!["true".to_string()];
        let secret_env = serde_json::Map::new();
        let termination = run_job(base_request(&client, &body, &command, &secret_env)).await;

        let JobTermination::Failure(failure) = termination else {
            panic!("a failed create must fail the Job")
        };
        assert!(failure.message.contains("name taken"));
        assert_eq!(
            execs.load(Ordering::SeqCst),
            0,
            "exec must not run after a failed create"
        );
        assert_eq!(
            deletes.load(Ordering::SeqCst),
            0,
            "a create conflict must never delete the pre-existing VM"
        );
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn successful_job_fails_when_its_vm_cannot_be_cleaned_up() {
        let deletes = Arc::new(AtomicUsize::new(0));
        let (api_url, server) = serve_stub(lifecycle_stub(
            0,
            StatusCode::INTERNAL_SERVER_ERROR,
            deletes.clone(),
        ))
        .await;
        let client = DaemonClient::new(&api_url, None);
        let body = serde_json::json!({ "name": "job-x" });
        let command = vec!["true".to_string()];
        let secret_env = serde_json::Map::new();

        let termination = run_job(base_request(&client, &body, &command, &secret_env)).await;

        let JobTermination::Failure(failure) = termination else {
            panic!("cleanup failure must fail an otherwise successful Job")
        };
        assert_eq!(failure.kind.as_deref(), Some("job_cleanup_failed"));
        assert!(failure.message.contains("could not be destroyed"));
        assert_eq!(deletes.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn command_exit_code_wins_over_a_secondary_cleanup_failure() {
        let deletes = Arc::new(AtomicUsize::new(0));
        let (api_url, server) = serve_stub(lifecycle_stub(
            23,
            StatusCode::INTERNAL_SERVER_ERROR,
            deletes.clone(),
        ))
        .await;
        let client = DaemonClient::new(&api_url, None);
        let body = serde_json::json!({ "name": "job-x" });
        let command = vec!["false".to_string()];
        let secret_env = serde_json::Map::new();

        let termination = run_job(base_request(&client, &body, &command, &secret_env)).await;

        assert!(matches!(termination, JobTermination::Exit(23)));
        assert_eq!(deletes.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn keep_prevents_cleanup_after_success() {
        let deletes = Arc::new(AtomicUsize::new(0));
        let (api_url, server) =
            serve_stub(lifecycle_stub(0, StatusCode::NO_CONTENT, deletes.clone())).await;
        let client = DaemonClient::new(&api_url, None);
        let body = serde_json::json!({ "name": "job-x" });
        let command = vec!["true".to_string()];
        let secret_env = serde_json::Map::new();
        let mut request = base_request(&client, &body, &command, &secret_env);
        request.keep = true;

        let termination = run_job(request).await;

        assert!(matches!(termination, JobTermination::Success));
        assert_eq!(deletes.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn already_absent_vm_counts_as_successful_cleanup() {
        let deletes = Arc::new(AtomicUsize::new(0));
        let (api_url, server) =
            serve_stub(lifecycle_stub(0, StatusCode::NOT_FOUND, deletes.clone())).await;
        let client = DaemonClient::new(&api_url, None);
        let body = serde_json::json!({ "name": "job-x" });
        let command = vec!["true".to_string()];
        let secret_env = serde_json::Map::new();

        let termination = run_job(base_request(&client, &body, &command, &secret_env)).await;

        assert!(matches!(termination, JobTermination::Success));
        assert_eq!(deletes.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn interruption_after_acquisition_destroys_the_job_vm() {
        let deletes = Arc::new(AtomicUsize::new(0));
        let deletes_route = deletes.clone();
        let exec_started = Arc::new(tokio::sync::Notify::new());
        let exec_started_route = exec_started.clone();
        let app = Router::new()
            .route(
                "/v1/vms",
                post(|| async { (StatusCode::CREATED, Json(serde_json::json!({}))) }),
            )
            .route(
                "/v1/vms/{name}",
                get(|| async { Json(serde_json::json!({"boot_mode": "direct"})) }).delete(
                    move || {
                        let deletes = deletes_route.clone();
                        async move {
                            deletes.fetch_add(1, Ordering::SeqCst);
                            StatusCode::NO_CONTENT
                        }
                    },
                ),
            )
            .route(
                "/v1/vms/{name}/ready",
                get(|| async { Json(serde_json::json!({"ready": true})) }),
            )
            .route(
                "/v1/vms/{name}/exec",
                post(move || {
                    let exec_started = exec_started_route.clone();
                    async move {
                        exec_started.notify_one();
                        std::future::pending::<Json<serde_json::Value>>().await
                    }
                }),
            );
        let (api_url, server) = serve_stub(app).await;
        let client = DaemonClient::new(&api_url, None);
        let body = serde_json::json!({ "name": "job-x" });
        let command = vec!["sleep".to_string(), "forever".to_string()];
        let secret_env = serde_json::Map::new();
        let request = base_request(&client, &body, &command, &secret_env);

        let termination = run_job_with_interrupt(request, exec_started.notified()).await;

        assert!(matches!(termination, JobTermination::Exit(130)));
        assert_eq!(deletes.load(Ordering::SeqCst), 1);
        server.abort();
    }

    // --- Retrieval: the three outcomes ---------------------------------------

    #[test]
    fn manifest_positions_become_indices_and_nonsense_is_dropped() {
        // 1-based positions in, 0-based indices out.
        assert_eq!(parse_unmatched_manifest(b"1\n3\n", 3), vec![0, 2]);
        // An empty manifest is the "everything matched" answer, not a parse
        // failure.
        assert_eq!(parse_unmatched_manifest(b"", 3), Vec::<usize>::new());
        assert_eq!(parse_unmatched_manifest(b"\n\n", 3), Vec::<usize>::new());
        // A position outside the request describes a guest running a different
        // wrapper; naming some pattern for it would misreport which one went
        // unmatched.
        assert_eq!(
            parse_unmatched_manifest(b"0\n4\n-1\nx\n", 3),
            Vec::<usize>::new()
        );
        assert_eq!(parse_unmatched_manifest(b" 2 \n", 3), vec![1]);
    }

    /// Bytes that do not compress, so an archive built from them stays above the
    /// daemon's single-response limit and the transfer genuinely has to chunk.
    fn incompressible(len: usize) -> Vec<u8> {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    fn tar_gz_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let enc = flate2::write::GzEncoder::new(&mut buf, flate2::Compression::default());
            let mut builder = tar::Builder::new(enc);
            for (name, data) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, name, *data).unwrap();
            }
            builder.into_inner().unwrap().finish().unwrap();
        }
        buf
    }

    /// A stub `files/read` serving a fixed set of guest files, honouring
    /// `offset`/`len` and refusing any response larger than `max_response` the
    /// way the daemon's `max_file_read_bytes` policy does. The cap is what makes
    /// these tests meaningful: a caller that asks for a whole large file gets
    /// 413, exactly as against a real daemon.
    fn guest_files_route(files: Vec<(String, Vec<u8>)>, max_response: usize) -> Router {
        Router::new().route(
            "/v1/vms/{name}/files/read",
            post(move |axum::extract::Json(req): axum::extract::Json<serde_json::Value>| {
                let files = files.clone();
                async move {
                    let path = req["path"].as_str().unwrap_or("").to_string();
                    let Some((_, content)) = files.iter().find(|(p, _)| *p == path) else {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({
                                "kind": "read_file_failed",
                                "message": format!("read failed: {path}: No such file or directory"),
                            })),
                        )
                            .into_response();
                    };
                    let offset = req["offset"].as_u64().unwrap_or(0) as usize;
                    let len = req["len"].as_u64().unwrap_or(u64::MAX) as usize;
                    let start = offset.min(content.len());
                    let end = start.saturating_add(len).min(content.len());
                    let slice = &content[start..end];
                    if slice.len() > max_response {
                        return (
                            StatusCode::PAYLOAD_TOO_LARGE,
                            Json(serde_json::json!({
                                "kind": "read_file_too_large",
                                "message": format!(
                                    "file exceeds max read size of {max_response} bytes"
                                ),
                            })),
                        )
                            .into_response();
                    }
                    Json(serde_json::json!({
                        "data": husker_agent_proto::base64_encode(slice),
                        "size": slice.len(),
                        "total_size": content.len(),
                    }))
                    .into_response()
                }
            }),
        )
    }

    /// The defect this whole change exists for: an artifact bigger than one read
    /// response used to be reported as "nothing matched --out", with exit code
    /// zero and no file on the host. The archive here is deliberately larger
    /// than the stub's response cap, so it can only arrive by chunking.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_artifact_larger_than_one_read_response_is_retrieved() {
        let payload = incompressible(2 * 1024 * 1024);
        let archive = tar_gz_of(&[("big.bin", &payload)]);
        assert!(
            archive.len() > 1024 * 1024,
            "the fixture must exceed one response, else it proves nothing: {} bytes",
            archive.len()
        );

        let (api_url, server) = serve_stub(guest_files_route(
            vec![
                (SYNC_MANIFEST_GUEST_PATH.to_string(), Vec::new()),
                (SYNC_OUTPUT_GUEST_PATH.to_string(), archive),
            ],
            1024 * 1024,
        ))
        .await;

        let dst = tempfile::tempdir().unwrap();
        let requested = vec![PathBuf::from("big.bin")];
        let client = DaemonClient::new(&api_url, None);
        let retrieval = retrieve_outputs(&client, "job-x", dst.path(), &requested, &requested)
            .await
            .expect("the stub daemon is reachable");

        assert!(
            retrieval.error.is_none(),
            "retrieval must succeed, got: {:?}",
            retrieval.error.map(|e| e.message)
        );
        assert_eq!(retrieval.files, vec!["big.bin".to_string()]);
        assert!(
            retrieval.failure().is_none(),
            "a retrieved artifact is not a failure"
        );
        assert_eq!(
            std::fs::read(dst.path().join("big.bin")).unwrap(),
            payload,
            "every byte of the artifact must reach the host, in order"
        );
        server.abort();
    }

    /// An archive the guest built but the host could not fetch is a transfer
    /// failure carrying the daemon's own words, not an absence. Reporting it as
    /// "nothing matched" is what made a broken transfer look like a build that
    /// produced nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_archive_that_cannot_be_fetched_fails_with_the_daemons_message() {
        // The manifest says every pattern matched, so an archive is expected;
        // it is absent from the stub, which answers the way the daemon does.
        let (api_url, server) = serve_stub(guest_files_route(
            vec![(SYNC_MANIFEST_GUEST_PATH.to_string(), Vec::new())],
            1024 * 1024,
        ))
        .await;

        let dst = tempfile::tempdir().unwrap();
        let requested = vec![PathBuf::from("dist/app")];
        let client = DaemonClient::new(&api_url, None);
        let retrieval = retrieve_outputs(&client, "job-x", dst.path(), &requested, &requested)
            .await
            .unwrap();

        let failure = retrieval
            .failure()
            .expect("a transfer that failed must fail the job");
        assert!(
            failure.message.contains("No such file or directory"),
            "the daemon's own message must survive, got: {}",
            failure.message
        );
        assert!(
            failure.message.contains("could not be copied back"),
            "and be framed as a transfer failure, got: {}",
            failure.message
        );
        assert!(
            retrieval.unmatched_out.is_empty(),
            "a failed transfer is not an unmatched pattern"
        );
        server.abort();
    }

    /// An `--out` the guest genuinely never produced: no error, but not a
    /// success either. The pattern is named, because "nothing matched" without
    /// saying which is the report that sent people looking in the wrong place.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unmatched_out_pattern_is_named_and_fails_the_job() {
        // Position 2 of the request went unmatched; position 1 matched.
        let archive = tar_gz_of(&[("src/main.rs", b"fn main() {}")]);
        let (api_url, server) = serve_stub(guest_files_route(
            vec![
                (SYNC_MANIFEST_GUEST_PATH.to_string(), b"2\n".to_vec()),
                (SYNC_OUTPUT_GUEST_PATH.to_string(), archive),
            ],
            1024 * 1024,
        ))
        .await;

        let dst = tempfile::tempdir().unwrap();
        let requested = vec![PathBuf::from("src/main.rs"), PathBuf::from("dist/*.whl")];
        let out = vec![PathBuf::from("dist/*.whl")];
        let client = DaemonClient::new(&api_url, None);
        let retrieval = retrieve_outputs(&client, "job-x", dst.path(), &requested, &out)
            .await
            .unwrap();

        assert_eq!(retrieval.unmatched_out, vec!["dist/*.whl".to_string()]);
        assert!(retrieval.unmatched_write_back.is_empty());
        assert_eq!(
            retrieval.files,
            vec!["src/main.rs".to_string()],
            "what did match is still retrieved"
        );
        let failure = retrieval
            .failure()
            .expect("an --out that matched nothing must fail the job");
        assert_eq!(failure.kind.as_deref(), Some("out_matched_nothing"));
        assert!(
            failure.message.contains("dist/*.whl"),
            "the failure must name the pattern, got: {}",
            failure.message
        );
        server.abort();
    }

    /// A `--write-back` path the command deleted is a legitimate result, so it
    /// is reported and does not fail the job. The same absence under `--out`
    /// does fail it: the difference is whether the user asked for that path by
    /// name.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_write_back_path_the_command_removed_is_reported_not_failed() {
        let archive = tar_gz_of(&[("kept.txt", b"still here")]);
        let (api_url, server) = serve_stub(guest_files_route(
            vec![
                (SYNC_MANIFEST_GUEST_PATH.to_string(), b"2\n".to_vec()),
                (SYNC_OUTPUT_GUEST_PATH.to_string(), archive),
            ],
            1024 * 1024,
        ))
        .await;

        let dst = tempfile::tempdir().unwrap();
        let requested = vec![PathBuf::from("kept.txt"), PathBuf::from("removed.txt")];
        let client = DaemonClient::new(&api_url, None);
        let retrieval = retrieve_outputs(
            &client,
            "job-x",
            dst.path(),
            &requested,
            // Neither path was named with --out: both came from --write-back.
            &[],
        )
        .await
        .unwrap();

        assert_eq!(
            retrieval.unmatched_write_back,
            vec!["removed.txt".to_string()]
        );
        assert!(retrieval.unmatched_out.is_empty());
        assert!(
            retrieval.failure().is_none(),
            "deleting a synced file is a legitimate result, not a job failure"
        );
        server.abort();
    }

    /// Every pattern unmatched means the guest built no archive at all. Asking
    /// for one anyway would turn a correct "nothing matched" into a spurious
    /// read failure, so no request is made.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn nothing_matched_does_not_go_looking_for_an_archive() {
        let (api_url, server) = serve_stub(guest_files_route(
            vec![(SYNC_MANIFEST_GUEST_PATH.to_string(), b"1\n2\n".to_vec())],
            1024 * 1024,
        ))
        .await;

        let dst = tempfile::tempdir().unwrap();
        let requested = vec![PathBuf::from("a"), PathBuf::from("b")];
        let client = DaemonClient::new(&api_url, None);
        let retrieval = retrieve_outputs(&client, "job-x", dst.path(), &requested, &requested)
            .await
            .unwrap();

        // The stub has no archive: had one been requested, this would be an
        // error rather than a clean pair of unmatched patterns.
        assert!(retrieval.error.is_none(), "no archive must be requested");
        assert_eq!(
            retrieval.unmatched_out,
            vec!["a".to_string(), "b".to_string()]
        );
        assert!(retrieval.files.is_empty());
        server.abort();
    }

    /// A manifest that cannot be read at all means the wrapper never finished,
    /// so nothing is known about what matched. That is a failure with a reason,
    /// not an empty result.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unreadable_manifest_is_a_failure_with_a_reason() {
        let (api_url, server) = serve_stub(guest_files_route(vec![], 1024 * 1024)).await;

        let dst = tempfile::tempdir().unwrap();
        let requested = vec![PathBuf::from("out/app")];
        let client = DaemonClient::new(&api_url, None);
        let retrieval = retrieve_outputs(&client, "job-x", dst.path(), &requested, &requested)
            .await
            .unwrap();

        let failure = retrieval
            .failure()
            .expect("an unknown outcome is a failure");
        assert!(
            failure.message.contains("retrieval manifest"),
            "got: {}",
            failure.message
        );
        assert!(
            failure.hint.is_some(),
            "the user needs to be told what prevents the manifest from being written"
        );
        server.abort();
    }
}
