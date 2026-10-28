//! Versioned frozen inputs for the job orchestrator. Validation here describes
//! requests; it does not establish that a backend enforces the requested policy.
use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MAX_BUNDLE_BYTES: u64 = crate::frozen_bundle::MAX_BUNDLE_BYTES as u64;
pub const MAX_SPEC_BYTES: usize = 64 * 1024;
const MAX_COMMANDS: usize = 32;
const MAX_ARTIFACTS: usize = 16;

#[derive(Debug, thiserror::Error)]
#[error("invalid execution specification: {0}")]
pub struct JobSpecError(pub &'static str);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PreparedJobImage {
    pub catalog_id: Uuid,
    /// Lowercase sha256 identities, not mutable tags or host file paths.
    pub rootfs_digest: String,
    pub kernel_digest: String,
    pub initrd_digest: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JobBundle {
    /// Digest of the complete frozen tar bytes, including file modes.
    pub digest: String,
    pub size_bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JobResources {
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    pub disk_size_bytes: u64,
    pub pids_limit: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JobEgressRule {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum JobNetwork {
    None {},
    /// Linux host-enforced filtering only until Mac enforcement is proven.
    Filtered {
        rules: Vec<JobEgressRule>,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JobCommand {
    /// Operator-configured literal argv; no shell interpolation by Husker.
    pub argv: Vec<String>,
    pub timeout_secs: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JobArtifact {
    /// Relative to /workspace; no links or undeclared directories may be exported.
    pub path: String,
    pub max_bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JobCorrelation {
    pub job: String,
    pub stage: String,
    pub round: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JobSpec {
    pub version: u32,
    pub image: PreparedJobImage,
    pub source: JobBundle,
    pub acceptance: JobBundle,
    pub commands: Vec<JobCommand>,
    pub working_directory: String,
    /// Empty build/output directories excluded from the post-check source
    /// inventory. They must not contain any frozen source entry.
    #[serde(default)]
    pub writable_directories: Vec<String>,
    /// Only the check profile's non-secret environment vocabulary is accepted.
    /// The API must also enforce its operator allowlist before acceptance.
    pub environment: BTreeMap<String, String>,
    pub uid: u32,
    pub gid: u32,
    pub resources: JobResources,
    pub network: JobNetwork,
    /// Covers preparation, boot, transfers, execution and evidence collection.
    pub deadline: DateTime<Utc>,
    pub artifacts: Vec<JobArtifact>,
    pub correlation: JobCorrelation,
}

pub(crate) fn digest_valid(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn safe_relative(value: &str) -> bool {
    crate::frozen_bundle::safe_bundle_path(value)
}
fn printable(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn sort_json_keys(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(fields) => {
            for child in fields.values_mut() {
                sort_json_keys(child);
            }
            fields.sort_keys();
        }
        serde_json::Value::Array(values) => {
            for child in values {
                sort_json_keys(child);
            }
        }
        _ => {}
    }
}

impl JobSpec {
    /// Canonical v1 JSON uses recursively sorted keys, literal UTF-8, compact
    /// separators and integer fields. Hash these exact bytes with SHA-256.
    /// Structural validation is time-independent, so an expired identical
    /// replay can resolve its old identity. New acceptance enforces future time.
    pub fn canonical_json(&self) -> Result<String, JobSpecError> {
        self.validate()?;
        let mut value =
            serde_json::to_value(self).map_err(|_| JobSpecError("serialization failed"))?;
        sort_json_keys(&mut value);
        let json =
            serde_json::to_string(&value).map_err(|_| JobSpecError("serialization failed"))?;
        if json.len() > MAX_SPEC_BYTES {
            return Err(JobSpecError("specification exceeds 64 KiB"));
        }
        Ok(json)
    }
    pub fn digest(&self) -> Result<String, JobSpecError> {
        Ok(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(self.canonical_json()?.as_bytes()))
        ))
    }
    pub fn validate(&self) -> Result<(), JobSpecError> {
        if self.version != 1 {
            return Err(JobSpecError("unsupported contract version"));
        }
        if self.image.catalog_id.is_nil()
            || !digest_valid(&self.image.rootfs_digest)
            || !digest_valid(&self.image.kernel_digest)
            || self
                .image
                .initrd_digest
                .as_deref()
                .is_some_and(|d| !digest_valid(d))
        {
            return Err(JobSpecError(
                "immutable prepared image/kernel identities required",
            ));
        }
        for bundle in [&self.source, &self.acceptance] {
            if !digest_valid(&bundle.digest)
                || bundle.size_bytes == 0
                || bundle.size_bytes > MAX_BUNDLE_BYTES
            {
                return Err(JobSpecError("bundle identity or size invalid"));
            }
        }
        if self.uid < 1000 || self.gid < 1000 || self.uid == u32::MAX || self.gid == u32::MAX {
            return Err(JobSpecError("unprivileged numeric user and group required"));
        }
        if !(1..=32).contains(&self.resources.vcpu_count)
            || !(128..=65536).contains(&self.resources.mem_size_mib)
            || !(1024 * 1024 * 1024..=1024 * 1024 * 1024 * 1024)
                .contains(&self.resources.disk_size_bytes)
            || !(1..=512).contains(&self.resources.pids_limit)
        {
            return Err(JobSpecError(
                "explicit bounded CPU, memory, disk and process limits required",
            ));
        }
        if self.working_directory != "/workspace"
            && !self
                .working_directory
                .strip_prefix("/workspace/")
                .is_some_and(safe_relative)
        {
            return Err(JobSpecError("working directory must be inside /workspace"));
        }
        if self.writable_directories.len() > 16 {
            return Err(JobSpecError("at most 16 declared build/output directories"));
        }
        for (index, path) in self.writable_directories.iter().enumerate() {
            if !safe_relative(path)
                || self.writable_directories[..index].iter().any(|previous| {
                    previous == path
                        || previous.starts_with(&format!("{path}/"))
                        || path.starts_with(&format!("{previous}/"))
                })
            {
                return Err(JobSpecError(
                    "build/output directories must be safe and nonoverlapping",
                ));
            }
        }
        if self.commands.is_empty() || self.commands.len() > MAX_COMMANDS {
            return Err(JobSpecError("1–32 trusted command argv arrays required"));
        }
        for command in &self.commands {
            if command.argv.is_empty()
                || command.argv.len() > 128
                || command.argv[0].is_empty()
                || command
                    .argv
                    .iter()
                    .any(|arg| arg.len() > 4096 || arg.contains('\0'))
                || command.timeout_secs == 0
                || command.timeout_secs > 1200
            {
                return Err(JobSpecError(
                    "argv or command timeout invalid (maximum 20 minutes)",
                ));
            }
        }
        for (key, value) in &self.environment {
            if !matches!(
                key.as_str(),
                "PATH"
                    | "HOME"
                    | "LANG"
                    | "LC_ALL"
                    | "TZ"
                    | "TMPDIR"
                    | "RUSTUP_HOME"
                    | "CARGO_HOME"
                    | "CARGO_NET_OFFLINE"
                    | "RUSTFLAGS"
                    | "WERKT_ACCEPTANCE_DIR"
                    | "GIT_CONFIG_NOSYSTEM"
                    | "GIT_CONFIG_GLOBAL"
            ) || value.len() > 4096
                || value.contains('\0')
            {
                return Err(JobSpecError(
                    "environment is outside the non-secret check allowlist",
                ));
            }
        }
        if let JobNetwork::Filtered { rules } = &self.network
            && (rules.is_empty()
                || rules.len() > 32
                || rules.iter().any(|r| {
                    !printable(&r.host, 253)
                        || r.port == 0
                        || !matches!(r.protocol.as_str(), "tcp" | "udp")
                }))
        {
            return Err(JobSpecError(
                "filtered network requires 1–32 bounded explicit egress rules",
            ));
        }
        if self.deadline.timestamp() < 0 || self.deadline.timestamp_subsec_nanos() != 0 {
            return Err(JobSpecError(
                "deadline must be a nonnegative whole UTC second",
            ));
        }
        if self.artifacts.len() > MAX_ARTIFACTS {
            return Err(JobSpecError("at most 16 declared artifacts"));
        }
        let mut paths = std::collections::BTreeSet::new();
        let mut total = 0;
        for artifact in &self.artifacts {
            if !safe_relative(&artifact.path)
                || !paths.insert(&artifact.path)
                || artifact.max_bytes == 0
                || artifact.max_bytes > 4 * 1024 * 1024
            {
                return Err(JobSpecError(
                    "artifact must have a unique safe relative path and a bounded size",
                ));
            }
            total += artifact.max_bytes;
        }
        if total > 16 * 1024 * 1024 {
            return Err(JobSpecError("artifact budget exceeds 16 MiB"));
        }
        if !printable(&self.correlation.job, 128) || !printable(&self.correlation.stage, 64) {
            return Err(JobSpecError(
                "bounded non-secret job/stage correlation required",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct JobSubmission {
    pub idempotency_key: String,
    pub execution_specification_digest: String,
    pub specification: JobSpec,
}
impl JobSubmission {
    pub fn canonical_specification(&self) -> Result<String, JobSpecError> {
        if !printable(&self.idempotency_key, 128) {
            return Err(JobSpecError("bounded non-secret idempotency key required"));
        }
        let json = self.specification.canonical_json()?;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(json.as_bytes())));
        if self.execution_specification_digest != digest {
            return Err(JobSpecError("execution specification digest mismatch"));
        }
        Ok(json)
    }
}
