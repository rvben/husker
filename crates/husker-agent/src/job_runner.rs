//! Guest-only trusted factory runner. The host must create a fresh disposable
//! VM, enforce its network/resources/deadline, and retain evidence before teardown.
use anyhow::{Result, ensure};
use husker_agent_proto::frozen_bundle::FrozenBundle;
use husker_agent_proto::job_spec::JobSpec;

/// Exclusions are permitted only for initially empty output/build directories.
/// An operator cannot accidentally exempt source files from mutation detection.
pub fn validate_bundle_policy(
    spec: &JobSpec,
    source: &FrozenBundle,
    acceptance: &FrozenBundle,
) -> Result<()> {
    spec.validate()?;
    ensure!(
        source.digest() == spec.source.digest
            && source.bytes().len() as u64 == spec.source.size_bytes,
        "source identity mismatch"
    );
    ensure!(
        acceptance.digest() == spec.acceptance.digest
            && acceptance.bytes().len() as u64 == spec.acceptance.size_bytes,
        "acceptance identity mismatch"
    );
    for directory in &spec.writable_directories {
        ensure!(
            !source.files().keys().any(|path| path == directory
                || path.starts_with(&format!("{directory}/"))
                || directory.starts_with(&format!("{path}/"))),
            "declared build/output directory overlaps frozen source"
        );
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn prepare(_job_id: &str, _spec_digest: &str) -> Result<()> {
    anyhow::bail!("factory staging requires a Linux guest; refusing host preparation")
}

#[cfg(not(target_os = "linux"))]
pub async fn run(_job_id: &str, _spec_digest: &str) -> Result<()> {
    anyhow::bail!("factory runner requires a Linux guest; refusing host execution")
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::job_process::build_job_process;
    use husker_agent_proto::job_result::{
        GuestJobManifest as Manifest, JobArtifactResult as ArtifactResult, JobCollectionStatus,
        JobCommandResult as CommandResult, JobOutcome, MAX_JOB_MANIFEST_BYTES,
    };
    use std::collections::BTreeSet;
    use std::ffi::CString;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::io::AsyncReadExt;

    const JOB_DIRECTORY: &str = "/run/husker-job";
    const MAX_FORWARDED_OUTPUT: usize = 4 * 1024 * 1024;

    fn protected_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == 0
                && metadata.nlink() == 1
                && metadata.mode() & 0o022 == 0,
            "input receipt must be a protected root-owned regular file"
        );
        ensure!(metadata.len() <= max_bytes, "input exceeds limit");
        let mut data = Vec::with_capacity(metadata.len() as usize);
        file.take(max_bytes + 1).read_to_end(&mut data)?;
        ensure!(
            data.len() as u64 == metadata.len(),
            "input changed during read"
        );
        Ok(data)
    }

    fn identity(job_id: &str, digest: &str) -> Result<Vec<u8>> {
        let parsed: uuid::Uuid = job_id.parse()?;
        ensure!(
            !parsed.is_nil() && parsed.to_string() == job_id,
            "job UUID must be canonical and nonnil"
        );
        ensure!(
            digest.len() == 71
                && digest.starts_with("sha256:")
                && digest[7..]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid specification digest"
        );
        Ok(serde_json::to_vec(
            &serde_json::json!({"job_id":job_id,"specification_digest":digest}),
        )?)
    }

    /// Trusted pre-execution staging. An existing directory is replayable only
    /// with its protected, synced identity receipt; partial creation is unknown.
    pub fn prepare(job_id: &str, digest: &str) -> Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "factory staging requires guest root"
        );
        let expected = identity(job_id, digest)?;
        match std::fs::DirBuilder::new().mode(0o700).create(JOB_DIRECTORY) {
            Ok(()) => {
                let mut receipt = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(Path::new(JOB_DIRECTORY).join("identity.json"))?;
                receipt.write_all(&expected)?;
                receipt.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let receipt = protected_file(&Path::new(JOB_DIRECTORY).join("identity.json"), 512)?;
                ensure!(
                    receipt == expected,
                    "staging identity changed or creation incomplete"
                );
            }
            Err(error) => return Err(error.into()),
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(JOB_DIRECTORY)?;
        let metadata = directory.metadata()?;
        ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o077 == 0,
            "staging directory is not protected root-owned storage"
        );
        directory.sync_all()?;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open("/run")?
            .sync_all()?;
        Ok(())
    }

    fn configure_frozen_tree(root: &Path, bundle: &FrozenBundle) -> Result<()> {
        let mut directories = BTreeSet::from([root.to_path_buf()]);
        for (path, entry) in bundle.files() {
            let full = root.join(path);
            let mut parent = full.parent();
            while let Some(path) = parent.filter(|path| path.starts_with(root)) {
                directories.insert(path.to_path_buf());
                parent = path.parent();
            }
            own(&full, 0, 0)?;
            std::fs::set_permissions(
                full,
                std::fs::Permissions::from_mode(if entry.executable { 0o555 } else { 0o444 }),
            )?;
        }
        for path in directories {
            own(&path, 0, 0)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o555))?;
        }
        Ok(())
    }
    fn own(path: &Path, uid: u32, gid: u32) -> Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let path = CString::new(path.as_os_str().as_bytes())?;
        ensure!(
            unsafe { libc::chown(path.as_ptr(), uid, gid) } == 0,
            "cannot assign workspace ownership: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
    fn require_deadline(spec: &JobSpec) -> Result<()> {
        ensure!(
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
                < spec.deadline.timestamp() as u64,
            "job hard deadline expired"
        );
        Ok(())
    }
    fn bound_error(error: &anyhow::Error) -> String {
        error.to_string().chars().take(128).collect()
    }

    async fn execute(
        spec: &JobSpec,
        index: usize,
        job_id: &str,
        forwarded: &mut usize,
    ) -> Result<CommandResult> {
        let initial_forwarded = *forwarded;
        let mut process = build_job_process(spec, index, job_id)?;
        let started = tokio::time::Instant::now();
        let mut child = process.command.spawn()?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("missing stdout"))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("missing stderr"))?;
        let mut out = [0u8; 8192];
        let mut err = [0u8; 8192];
        let mut out_open = true;
        let mut err_open = true;
        let mut tail = Vec::new();
        let mut captured = 0usize;
        let deadline = tokio::time::sleep(process.timeout);
        tokio::pin!(deadline);
        let mut terminal: Option<(Option<i32>, JobOutcome)> = None;
        let mut termination_confirmed = false;
        let mut termination_error = None;
        let mut drain_deadline = None;
        loop {
            if terminal.is_some() && !out_open && !err_open {
                break;
            }
            let (is_error, bytes): (bool, &[u8]) = tokio::select! {
                read = stdout.read(&mut out), if out_open => {
                    let len = read?; if len == 0 { out_open = false; continue; }
                    (false, &out[..len])
                }
                read = stderr.read(&mut err), if err_open => {
                    let len = read?; if len == 0 { err_open = false; continue; }
                    (true, &err[..len])
                }
                status = child.wait(), if terminal.is_none() => {
                    let status = status?;
                    terminal = Some((status.code().or_else(|| status.signal().map(|signal| 128 + signal)), if status.success() { JobOutcome::Completed } else { JobOutcome::CommandFailed }));
                    match process.containment.terminate_and_confirm().await {
                        Ok(()) => termination_confirmed = true,
                        Err(error) => termination_error = Some(bound_error(&error)),
                    }
                    drain_deadline = Some(tokio::time::Instant::now() + Duration::from_secs(2));
                    continue;
                }
                _ = &mut deadline, if terminal.is_none() => {
                    terminal = Some((None, JobOutcome::TimedOut));
                    match process.containment.terminate_and_confirm().await {
                        Ok(()) => termination_confirmed = true,
                        Err(error) => termination_error = Some(bound_error(&error)),
                    }
                    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
                    drain_deadline = Some(tokio::time::Instant::now() + Duration::from_secs(2));
                    continue;
                }
                _ = async {
                    match drain_deadline { Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending().await }
                }, if terminal.is_some() => break,
            };
            captured += bytes.len();
            tail.extend_from_slice(bytes);
            if tail.len() > 256 {
                tail.drain(..tail.len() - 256);
            }
            let retain = bytes
                .len()
                .min(MAX_FORWARDED_OUTPUT.saturating_sub(*forwarded));
            if retain > 0 {
                use tokio::io::AsyncWriteExt;
                let remaining = if terminal.is_some() {
                    drain_deadline
                        .expect("terminal drain deadline")
                        .saturating_duration_since(tokio::time::Instant::now())
                } else {
                    process.timeout.saturating_sub(started.elapsed())
                };
                if is_error {
                    tokio::time::timeout(
                        remaining,
                        tokio::io::stderr().write_all(&bytes[..retain]),
                    )
                    .await??;
                } else {
                    tokio::time::timeout(
                        remaining,
                        tokio::io::stdout().write_all(&bytes[..retain]),
                    )
                    .await??;
                }
                *forwarded += retain;
            }
        }
        let (exit_code, outcome) = terminal.expect("terminal before finishing capture");
        Ok(CommandResult {
            command_index: index,
            exit_code,
            outcome: if termination_confirmed {
                outcome
            } else {
                JobOutcome::InfrastructureFailed
            },
            duration_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            output: String::from_utf8_lossy(&tail).into_owned(),
            output_truncated: captured > tail.len(),
            logs_truncated: captured > *forwarded - initial_forwarded || out_open || err_open,
            termination_confirmed,
            termination_error,
        })
    }

    pub async fn run(job_id: &str, spec_digest: &str) -> Result<()> {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "factory runner must start as guest root"
        );
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(JOB_DIRECTORY)?;
        let metadata = directory.metadata()?;
        ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o077 == 0,
            "job input directory must be protected and root-owned"
        );
        ensure!(
            protected_file(&Path::new(JOB_DIRECTORY).join("identity.json"), 512)?
                == identity(job_id, spec_digest)?,
            "staged execution identity mismatch"
        );
        let spec: JobSpec = serde_json::from_slice(&protected_file(
            &PathBuf::from(JOB_DIRECTORY).join("spec.json"),
            64 * 1024,
        )?)?;
        ensure!(
            spec.digest()? == spec_digest,
            "execution specification digest mismatch"
        );
        require_deadline(&spec)?;
        let source = FrozenBundle::decode(
            protected_file(
                &PathBuf::from(JOB_DIRECTORY).join("source.tar"),
                spec.source.size_bytes,
            )?,
            &spec.source.digest,
            spec.source.size_bytes,
        )?;
        let acceptance = FrozenBundle::decode(
            protected_file(
                &PathBuf::from(JOB_DIRECTORY).join("acceptance.tar"),
                spec.acceptance.size_bytes,
            )?,
            &spec.acceptance.digest,
            spec.acceptance.size_bytes,
        )?;
        validate_bundle_policy(&spec, &source, &acceptance)?;
        // Admission tests every required kernel policy before exposing workspace
        // or starting ANY source. The probe has no spawned process.
        drop(build_job_process(&spec, 0, job_id)?);
        let root = File::open("/")?;
        // Refuse existing workspaces: one execution per fresh disposable guest.
        let workspace = source.extract_new_directory(&root, "workspace")?;
        let _acceptance = acceptance.extract_new_directory(&root, "acceptance")?;
        // Frozen source stays root-owned/read-only, including parent directories,
        // so checks cannot change and restore it between inventory observations.
        // Only explicit initially empty build/output directories are writable.
        configure_frozen_tree(Path::new("/workspace"), &source)?;
        configure_frozen_tree(Path::new("/acceptance"), &acceptance)?;
        for path in &spec.writable_directories {
            let destination = Path::new("/workspace").join(path);
            std::fs::create_dir_all(&destination)?;
            own(&destination, spec.uid, spec.gid)?;
            std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o755))?;
        }
        let mut manifest = Manifest {
            version: 1,
            job_id: job_id.parse()?,
            execution_specification_digest: spec_digest.into(),
            image: spec.image.clone(),
            source: spec.source.clone(),
            acceptance: spec.acceptance.clone(),
            commands: vec![],
            artifacts: vec![],
            source_changed: None,
            source_verification_error: None,
            collection_status: JobCollectionStatus::Complete,
            outcome: JobOutcome::Completed,
        };
        let mut forwarded = 0;
        for index in 0..spec.commands.len() {
            let result = match execute(&spec, index, job_id, &mut forwarded).await {
                Ok(result) => result,
                Err(error) => CommandResult {
                    command_index: index,
                    exit_code: None,
                    outcome: JobOutcome::InfrastructureFailed,
                    duration_ms: 0,
                    output: bound_error(&error),
                    output_truncated: false,
                    logs_truncated: true,
                    termination_confirmed: false,
                    termination_error: Some(bound_error(&error)),
                },
            };
            if result.outcome != JobOutcome::Completed {
                manifest.outcome = result.outcome;
            }
            let stop = !result.termination_confirmed
                || result.outcome == JobOutcome::TimedOut
                || result.outcome == JobOutcome::InfrastructureFailed;
            manifest.commands.push(result);
            if stop {
                break;
            }
        }
        if manifest.commands.iter().any(|result| result.logs_truncated) {
            manifest.collection_status = JobCollectionStatus::Truncated;
        }
        let all_terminated = manifest
            .commands
            .iter()
            .all(|result| result.termination_confirmed);
        let source_inventory = if all_terminated {
            FrozenBundle::freeze_directory_excluding(&workspace, &spec.writable_directories)
        } else {
            Err(husker_agent_proto::frozen_bundle::BundleError::Invalid(
                "termination unconfirmed; refusing evidence collection",
            ))
        };
        match source_inventory {
            Ok(final_source) => {
                let changed = final_source.digest() != spec.source.digest;
                manifest.source_changed = Some(changed);
                if changed {
                    manifest.outcome = JobOutcome::InfrastructureFailed;
                }
            }
            Err(error) => {
                manifest.source_verification_error =
                    Some(error.to_string().chars().take(128).collect());
                manifest.outcome = JobOutcome::InfrastructureFailed;
                manifest.collection_status = JobCollectionStatus::Failed;
            }
        }
        std::fs::create_dir(Path::new(JOB_DIRECTORY).join("artifacts"))?;
        std::fs::set_permissions(
            Path::new(JOB_DIRECTORY).join("artifacts"),
            std::fs::Permissions::from_mode(0o700),
        )?;
        for (index, declared) in spec.artifacts.iter().enumerate() {
            let collected = (|| -> Result<ArtifactResult> {
                require_deadline(&spec)?;
                ensure!(
                    all_terminated,
                    "termination unconfirmed; refusing artifact collection"
                );
                let artifact = husker_agent_proto::frozen_bundle::collect_declared_artifact(
                    &workspace,
                    &declared.path,
                    declared.max_bytes as usize,
                )?;
                let stored_name = format!("{index}.bin");
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(
                        Path::new(JOB_DIRECTORY)
                            .join("artifacts")
                            .join(&stored_name),
                    )?;
                file.write_all(&artifact.data)?;
                file.sync_all()?;
                Ok(ArtifactResult {
                    path: declared.path.clone(),
                    stored_name: Some(stored_name),
                    digest: Some(artifact.digest),
                    size_bytes: Some(artifact.data.len() as u64),
                    error: None,
                })
            })();
            match collected {
                Ok(result) => manifest.artifacts.push(result),
                Err(error) => {
                    manifest.artifacts.push(ArtifactResult {
                        path: declared.path.clone(),
                        stored_name: None,
                        digest: None,
                        size_bytes: None,
                        error: Some(bound_error(&error)),
                    });
                    manifest.collection_status = JobCollectionStatus::Failed;
                    manifest.outcome = JobOutcome::InfrastructureFailed;
                }
            }
        }
        if require_deadline(&spec).is_err() {
            manifest.outcome = JobOutcome::TimedOut;
        }
        let bytes = serde_json::to_vec(&manifest)?;
        ensure!(
            bytes.len() <= MAX_JOB_MANIFEST_BYTES,
            "result manifest exceeds retention limit"
        );
        Manifest::decode_for(&bytes, &spec, manifest.job_id)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(Path::new(JOB_DIRECTORY).join("result.json"))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        directory.sync_all()?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use linux::{prepare, run};
