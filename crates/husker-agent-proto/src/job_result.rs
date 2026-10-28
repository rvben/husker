//! Bounded guest evidence contract. A successful runner process is insufficient:
//! hosts must authenticate inputs, validate this manifest, and export artifacts.
use crate::job_spec::{JobBundle, JobSpec, JobSpecError, PreparedJobImage};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_JOB_MANIFEST_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobOutcome {
    Completed,
    CommandFailed,
    InfrastructureFailed,
    Cancelled,
    TimedOut,
    Interrupted,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobCollectionStatus {
    Complete,
    Truncated,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobCommandResult {
    pub command_index: usize,
    pub exit_code: Option<i32>,
    pub outcome: JobOutcome,
    pub duration_ms: u64,
    pub output: String,
    pub output_truncated: bool,
    pub logs_truncated: bool,
    pub termination_confirmed: bool,
    pub termination_error: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobArtifactResult {
    pub path: String,
    pub stored_name: Option<String>,
    pub digest: Option<String>,
    pub size_bytes: Option<u64>,
    pub error: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestJobManifest {
    pub version: u32,
    pub job_id: Uuid,
    pub execution_specification_digest: String,
    pub image: PreparedJobImage,
    pub source: JobBundle,
    pub acceptance: JobBundle,
    pub commands: Vec<JobCommandResult>,
    pub artifacts: Vec<JobArtifactResult>,
    pub source_changed: Option<bool>,
    pub source_verification_error: Option<String>,
    pub collection_status: JobCollectionStatus,
    pub outcome: JobOutcome,
}
impl GuestJobManifest {
    pub fn decode_for(bytes: &[u8], spec: &JobSpec, job_id: Uuid) -> Result<Self, JobSpecError> {
        if bytes.len() > MAX_JOB_MANIFEST_BYTES {
            return Err(JobSpecError("manifest exceeds 64 KiB"));
        }
        let result: Self =
            serde_json::from_slice(bytes).map_err(|_| JobSpecError("invalid guest manifest"))?;
        if result.version != 1
            || result.job_id != job_id
            || result.execution_specification_digest != spec.digest()?
            || result.image != spec.image
            || result.source != spec.source
            || result.acceptance != spec.acceptance
        {
            return Err(JobSpecError("guest result identity mismatch"));
        }
        if result.commands.is_empty() || result.commands.len() > spec.commands.len() {
            return Err(JobSpecError("invalid command result count"));
        }
        for (index, command) in result.commands.iter().enumerate() {
            if command.command_index != index || command.output.len() > 2048 {
                return Err(JobSpecError("invalid command result index or output bound"));
            }
            if command
                .termination_error
                .as_ref()
                .is_some_and(|error| error.len() > 2048)
                || (command.termination_confirmed && command.termination_error.is_some())
            {
                return Err(JobSpecError("inconsistent termination evidence"));
            }
            if command.outcome == JobOutcome::Completed
                && (command.exit_code != Some(0) || !command.termination_confirmed)
            {
                return Err(JobSpecError(
                    "completed command lacks successful confirmed termination",
                ));
            }
            if command.outcome == JobOutcome::CommandFailed
                && (command.exit_code.is_none_or(|code| code == 0)
                    || !command.termination_confirmed)
            {
                return Err(JobSpecError("command failure lacks confirmed nonzero exit"));
            }
        }
        if result.artifacts.len() != spec.artifacts.len() {
            return Err(JobSpecError("artifact declarations missing from result"));
        }
        for (index, (artifact, declaration)) in
            result.artifacts.iter().zip(&spec.artifacts).enumerate()
        {
            if artifact.path != declaration.path
                || artifact
                    .error
                    .as_ref()
                    .is_some_and(|error| error.len() > 2048)
            {
                return Err(JobSpecError("invalid artifact declaration or error bound"));
            }
            match &artifact.error {
                Some(_)
                    if artifact.digest.is_none()
                        && artifact.stored_name.is_none()
                        && artifact.size_bytes.is_none() => {}
                None if artifact.stored_name.as_deref()
                    == Some(format!("{index}.bin").as_str())
                    && artifact
                        .size_bytes
                        .is_some_and(|size| size <= declaration.max_bytes)
                    && artifact
                        .digest
                        .as_deref()
                        .is_some_and(super::job_spec::digest_valid) => {}
                _ => return Err(JobSpecError("inconsistent artifact receipt")),
            }
        }
        if result
            .source_verification_error
            .as_ref()
            .is_some_and(|error| error.len() > 2048)
        {
            return Err(JobSpecError("source verification error exceeds bound"));
        }
        if result.outcome == JobOutcome::Completed
            && (result.commands.len() != spec.commands.len()
                || result
                    .commands
                    .iter()
                    .any(|command| command.outcome != JobOutcome::Completed)
                || result.source_changed != Some(false)
                || result.source_verification_error.is_some()
                || result.collection_status == JobCollectionStatus::Failed
                || result
                    .artifacts
                    .iter()
                    .any(|artifact| artifact.error.is_some()))
        {
            return Err(JobSpecError(
                "completed result lacks successful execution and collection evidence",
            ));
        }
        // This validates receipts only. The host must still retrieve each file,
        // enforce total limits, compare its hash/size, and persist before cleanup.
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job_spec::{JobArtifact, JobCommand, JobCorrelation, JobNetwork, JobResources};
    use serde_json::{Value, json};

    const JOB_ID: Uuid = Uuid::from_u128(0x1234);

    fn sha(fill: char) -> String {
        format!("sha256:{}", fill.to_string().repeat(64))
    }

    fn spec() -> JobSpec {
        JobSpec {
            version: 1,
            image: PreparedJobImage {
                catalog_id: Uuid::from_u128(1),
                rootfs_digest: sha('a'),
                kernel_digest: sha('b'),
                initrd_digest: None,
            },
            source: JobBundle {
                digest: sha('c'),
                size_bytes: 1024,
            },
            acceptance: JobBundle {
                digest: sha('d'),
                size_bytes: 2048,
            },
            commands: vec![
                JobCommand {
                    argv: vec!["true".into()],
                    timeout_secs: 60,
                },
                JobCommand {
                    argv: vec!["true".into()],
                    timeout_secs: 60,
                },
            ],
            working_directory: "/workspace".into(),
            writable_directories: vec![],
            environment: Default::default(),
            uid: 1000,
            gid: 1000,
            resources: JobResources {
                vcpu_count: 2,
                mem_size_mib: 512,
                disk_size_bytes: 2 * 1024 * 1024 * 1024,
                pids_limit: 64,
            },
            network: JobNetwork::None {},
            deadline: chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
            artifacts: vec![
                JobArtifact {
                    path: "out/a.bin".into(),
                    max_bytes: 100,
                },
                JobArtifact {
                    path: "b.bin".into(),
                    max_bytes: 200,
                },
            ],
            correlation: JobCorrelation {
                job: "job".into(),
                stage: "stage".into(),
                round: 1,
            },
        }
    }

    fn command(index: usize, outcome: &str, exit_code: Option<i32>, confirmed: bool) -> Value {
        json!({
            "command_index": index,
            "exit_code": exit_code,
            "outcome": outcome,
            "duration_ms": 5,
            "output": "",
            "output_truncated": false,
            "logs_truncated": false,
            "termination_confirmed": confirmed,
            "termination_error": null,
        })
    }

    fn receipt(index: usize, path: &str, size: u64) -> Value {
        json!({
            "path": path,
            "stored_name": format!("{index}.bin"),
            "digest": sha('e'),
            "size_bytes": size,
            "error": null,
        })
    }

    fn failed_receipt(path: &str) -> Value {
        json!({
            "path": path,
            "stored_name": null,
            "digest": null,
            "size_bytes": null,
            "error": "missing",
        })
    }

    fn completed() -> Value {
        let spec = spec();
        json!({
            "version": 1,
            "job_id": JOB_ID,
            "execution_specification_digest": spec.digest().unwrap(),
            "image": spec.image,
            "source": spec.source,
            "acceptance": spec.acceptance,
            "commands": [
                command(0, "completed", Some(0), true),
                command(1, "completed", Some(0), true),
            ],
            "artifacts": [receipt(0, "out/a.bin", 100), receipt(1, "b.bin", 200)],
            "source_changed": false,
            "source_verification_error": null,
            "collection_status": "complete",
            "outcome": "completed",
        })
    }

    /// A non-completed result: the first command failed, so every check that
    /// completed results must pass is allowed to be unmet.
    fn failed() -> Value {
        let mut manifest = completed();
        manifest["commands"] = json!([command(0, "command_failed", Some(1), true)]);
        manifest["artifacts"] = json!([failed_receipt("out/a.bin"), failed_receipt("b.bin")]);
        manifest["source_changed"] = Value::Null;
        manifest["collection_status"] = json!("failed");
        manifest["outcome"] = json!("command_failed");
        manifest
    }

    fn decode(manifest: &Value) -> Result<GuestJobManifest, JobSpecError> {
        GuestJobManifest::decode_for(&serde_json::to_vec(manifest).unwrap(), &spec(), JOB_ID)
    }

    fn rejection(manifest: &Value) -> &'static str {
        match decode(manifest) {
            Err(error) => error.0,
            Ok(_) => panic!("manifest was accepted: {manifest}"),
        }
    }

    fn accepted(manifest: &Value) {
        if let Err(error) = decode(manifest) {
            panic!("manifest was rejected ({error}): {manifest}");
        }
    }

    #[test]
    fn manifest_limit_is_64_kib() {
        assert_eq!(MAX_JOB_MANIFEST_BYTES, 65_536);
    }

    #[test]
    fn well_formed_completed_and_failed_manifests_are_accepted() {
        accepted(&completed());
        accepted(&failed());
        let decoded = decode(&completed()).unwrap();
        assert_eq!(decoded.commands.len(), 2);
        assert_eq!(decoded.outcome, JobOutcome::Completed);
    }

    #[test]
    fn manifest_size_is_bounded_inclusively() {
        let body = serde_json::to_vec(&completed()).unwrap();
        let padded = |len: usize| {
            let mut bytes = body.clone();
            bytes.resize(len, b' ');
            bytes
        };
        let decode_bytes = |bytes: &[u8]| GuestJobManifest::decode_for(bytes, &spec(), JOB_ID);
        assert!(decode_bytes(&padded(MAX_JOB_MANIFEST_BYTES)).is_ok());
        assert_eq!(
            decode_bytes(&padded(MAX_JOB_MANIFEST_BYTES + 1))
                .unwrap_err()
                .0,
            "manifest exceeds 64 KiB"
        );
        assert_eq!(
            decode_bytes(b"not json").unwrap_err().0,
            "invalid guest manifest"
        );
    }

    #[test]
    fn each_identity_field_must_match_the_specification() {
        let mismatch = "guest result identity mismatch";
        let cases: [(&str, Value); 6] = [
            ("version", json!(2)),
            ("job_id", json!(Uuid::from_u128(0x9999))),
            ("execution_specification_digest", json!(sha('f'))),
            (
                "image",
                json!({
                    "catalog_id": Uuid::from_u128(1),
                    "rootfs_digest": sha('f'),
                    "kernel_digest": sha('b'),
                    "initrd_digest": null,
                }),
            ),
            ("source", json!({"digest": sha('f'), "size_bytes": 1024})),
            (
                "acceptance",
                json!({"digest": sha('d'), "size_bytes": 2049}),
            ),
        ];
        for (field, replacement) in cases {
            let mut manifest = completed();
            manifest[field] = replacement;
            assert_eq!(rejection(&manifest), mismatch, "{field}");
        }
    }

    #[test]
    fn command_count_must_be_between_one_and_the_declared_commands() {
        let message = "invalid command result count";
        let mut manifest = failed();
        manifest["commands"] = json!([]);
        assert_eq!(rejection(&manifest), message);

        manifest["commands"] = json!([
            command(0, "command_failed", Some(1), true),
            command(1, "command_failed", Some(1), true),
            command(2, "command_failed", Some(1), true),
        ]);
        assert_eq!(rejection(&manifest), message);

        // Fewer results than declared commands is legitimate after a failure.
        manifest["commands"] = json!([command(0, "command_failed", Some(1), true)]);
        accepted(&manifest);
        manifest["commands"] = json!([
            command(0, "completed", Some(0), true),
            command(1, "command_failed", Some(2), true),
        ]);
        accepted(&manifest);
    }

    #[test]
    fn command_index_and_output_bound_are_enforced() {
        let message = "invalid command result index or output bound";
        let mut manifest = failed();
        manifest["commands"] = json!([
            command(0, "completed", Some(0), true),
            command(0, "command_failed", Some(1), true),
        ]);
        assert_eq!(rejection(&manifest), message);

        let mut manifest = failed();
        manifest["commands"][0]["command_index"] = json!(1);
        assert_eq!(rejection(&manifest), message);

        let mut manifest = failed();
        manifest["commands"][0]["output"] = json!("x".repeat(2048));
        accepted(&manifest);
        manifest["commands"][0]["output"] = json!("x".repeat(2049));
        assert_eq!(rejection(&manifest), message);
    }

    #[test]
    fn termination_evidence_must_be_bounded_and_consistent() {
        let message = "inconsistent termination evidence";
        let interrupted = || {
            let mut manifest = failed();
            manifest["commands"] = json!([command(0, "interrupted", None, false)]);
            manifest["outcome"] = json!("interrupted");
            manifest
        };
        let mut manifest = interrupted();
        manifest["commands"][0]["termination_error"] = json!("x".repeat(2048));
        accepted(&manifest);
        manifest["commands"][0]["termination_error"] = json!("x".repeat(2049));
        assert_eq!(rejection(&manifest), message);

        let mut manifest = interrupted();
        manifest["commands"][0]["termination_error"] = json!("short");
        accepted(&manifest);
        manifest["commands"][0]["termination_confirmed"] = json!(true);
        assert_eq!(rejection(&manifest), message);

        // Confirmed termination without an error stays valid.
        let mut manifest = interrupted();
        manifest["commands"][0]["termination_confirmed"] = json!(true);
        accepted(&manifest);
    }

    #[test]
    fn completed_commands_need_exit_zero_and_confirmed_termination() {
        let message = "completed command lacks successful confirmed termination";
        for (exit_code, confirmed) in [(Some(1), true), (None, true), (Some(0), false)] {
            let mut manifest = failed();
            manifest["commands"] = json!([command(0, "completed", exit_code, confirmed)]);
            assert_eq!(rejection(&manifest), message, "{exit_code:?} {confirmed}");
        }
        let mut manifest = failed();
        manifest["commands"] = json!([command(0, "completed", Some(0), true)]);
        accepted(&manifest);
    }

    #[test]
    fn failed_commands_need_confirmed_nonzero_exit() {
        let message = "command failure lacks confirmed nonzero exit";
        for (exit_code, confirmed) in [(Some(0), true), (None, true), (Some(1), false)] {
            let mut manifest = failed();
            manifest["commands"] = json!([command(0, "command_failed", exit_code, confirmed)]);
            assert_eq!(rejection(&manifest), message, "{exit_code:?} {confirmed}");
        }
        for exit_code in [1, -1, 255] {
            let mut manifest = failed();
            manifest["commands"] = json!([command(0, "command_failed", Some(exit_code), true)]);
            accepted(&manifest);
        }
    }

    #[test]
    fn every_declared_artifact_needs_exactly_one_receipt() {
        let message = "artifact declarations missing from result";
        let mut manifest = failed();
        manifest["artifacts"] = json!([failed_receipt("out/a.bin")]);
        assert_eq!(rejection(&manifest), message);
        manifest["artifacts"] = json!([
            failed_receipt("out/a.bin"),
            failed_receipt("b.bin"),
            failed_receipt("b.bin"),
        ]);
        assert_eq!(rejection(&manifest), message);
    }

    #[test]
    fn artifact_paths_must_match_declarations_in_order() {
        let message = "invalid artifact declaration or error bound";
        let mut manifest = failed();
        manifest["artifacts"] = json!([failed_receipt("b.bin"), failed_receipt("out/a.bin")]);
        assert_eq!(rejection(&manifest), message);

        let mut manifest = failed();
        manifest["artifacts"][0]["error"] = json!("x".repeat(2048));
        accepted(&manifest);
        manifest["artifacts"][0]["error"] = json!("x".repeat(2049));
        assert_eq!(rejection(&manifest), message);
    }

    #[test]
    fn an_artifact_error_excludes_every_receipt_field() {
        let message = "inconsistent artifact receipt";
        for (field, value) in [
            ("digest", json!(sha('e'))),
            ("stored_name", json!("0.bin")),
            ("size_bytes", json!(1)),
        ] {
            let mut manifest = failed();
            manifest["artifacts"][0][field] = value;
            assert_eq!(rejection(&manifest), message, "{field}");
        }
    }

    #[test]
    fn a_receipt_without_error_needs_name_size_and_digest_within_bounds() {
        let message = "inconsistent artifact receipt";
        let with = |index: usize, field: &str, value: Value| {
            let mut manifest = failed();
            manifest["artifacts"] = json!([receipt(0, "out/a.bin", 100), receipt(1, "b.bin", 200)]);
            manifest["artifacts"][index][field] = value;
            manifest
        };
        accepted(&with(0, "size_bytes", json!(100)));
        accepted(&with(0, "size_bytes", json!(0)));
        accepted(&with(1, "size_bytes", json!(200)));
        let bad = [
            (0, "size_bytes", json!(101)),
            (1, "size_bytes", json!(201)),
            (0, "size_bytes", Value::Null),
            (0, "stored_name", Value::Null),
            (0, "stored_name", json!("1.bin")),
            (1, "stored_name", json!("0.bin")),
            (0, "stored_name", json!("0")),
            (0, "digest", Value::Null),
            (0, "digest", json!("sha256:abc")),
            (0, "digest", json!(sha('E'))),
        ];
        for (index, field, value) in bad {
            assert_eq!(
                rejection(&with(index, field, value.clone())),
                message,
                "{index} {field} {value}"
            );
        }
    }

    #[test]
    fn source_verification_error_is_bounded() {
        let mut manifest = failed();
        manifest["source_verification_error"] = json!("x".repeat(2048));
        accepted(&manifest);
        manifest["source_verification_error"] = json!("x".repeat(2049));
        assert_eq!(
            rejection(&manifest),
            "source verification error exceeds bound"
        );
    }

    #[test]
    fn a_completed_result_needs_evidence_of_every_stage() {
        let message = "completed result lacks successful execution and collection evidence";
        type Mutation = Box<dyn Fn(&mut Value)>;
        let cases: [(&str, Mutation); 7] = [
            (
                "fewer commands than declared",
                Box::new(|m| m["commands"] = json!([command(0, "completed", Some(0), true)])),
            ),
            (
                "a failed command",
                Box::new(|m| {
                    m["commands"][1] = command(1, "command_failed", Some(1), true);
                }),
            ),
            (
                "source changed",
                Box::new(|m| m["source_changed"] = json!(true)),
            ),
            (
                "source change unknown",
                Box::new(|m| m["source_changed"] = Value::Null),
            ),
            (
                "source verification error",
                Box::new(|m| m["source_verification_error"] = json!("unreadable")),
            ),
            (
                "failed collection",
                Box::new(|m| m["collection_status"] = json!("failed")),
            ),
            (
                "artifact error",
                Box::new(|m| m["artifacts"][1] = failed_receipt("b.bin")),
            ),
        ];
        for (name, mutate) in cases {
            let mut manifest = completed();
            mutate(&mut manifest);
            assert_eq!(rejection(&manifest), message, "{name}");
        }

        // The same evidence gaps are fine when the result does not claim completion.
        let mut manifest = completed();
        manifest["collection_status"] = json!("truncated");
        accepted(&manifest);
        for (field, value) in [
            ("source_changed", json!(true)),
            ("collection_status", json!("failed")),
        ] {
            let mut manifest = completed();
            manifest[field] = value;
            manifest["outcome"] = json!("unknown");
            accepted(&manifest);
        }
    }
}
