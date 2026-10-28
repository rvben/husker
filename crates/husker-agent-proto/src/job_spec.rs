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

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn hex64(c: char) -> String {
        format!("sha256:{}", c.to_string().repeat(64))
    }

    fn valid() -> JobSpec {
        JobSpec {
            version: 1,
            image: PreparedJobImage {
                catalog_id: Uuid::from_u128(7),
                rootfs_digest: hex64('a'),
                kernel_digest: hex64('b'),
                initrd_digest: None,
            },
            source: JobBundle {
                digest: hex64('c'),
                size_bytes: 10,
            },
            acceptance: JobBundle {
                digest: hex64('d'),
                size_bytes: 20,
            },
            commands: vec![JobCommand {
                argv: vec!["cargo".into(), "test".into()],
                timeout_secs: 60,
            }],
            working_directory: "/workspace".into(),
            writable_directories: vec![],
            environment: BTreeMap::new(),
            uid: 1000,
            gid: 1000,
            resources: JobResources {
                vcpu_count: 2,
                mem_size_mib: 512,
                disk_size_bytes: 2 * 1024 * MIB,
                pids_limit: 64,
            },
            network: JobNetwork::None {},
            deadline: DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
            artifacts: vec![],
            correlation: JobCorrelation {
                job: "job-1".into(),
                stage: "check".into(),
                round: 3,
            },
        }
    }

    fn rule(host: &str, port: u16, protocol: &str) -> JobEgressRule {
        JobEgressRule {
            host: host.into(),
            port,
            protocol: protocol.into(),
        }
    }

    fn filtered(rules: Vec<JobEgressRule>) -> JobNetwork {
        JobNetwork::Filtered { rules }
    }

    fn artifact(path: &str, max_bytes: u64) -> JobArtifact {
        JobArtifact {
            path: path.into(),
            max_bytes,
        }
    }

    fn command(argv: &[&str], timeout_secs: u64) -> JobCommand {
        JobCommand {
            argv: argv.iter().map(|a| (*a).to_string()).collect(),
            timeout_secs,
        }
    }

    fn dirs(count: usize) -> Vec<String> {
        (0..count).map(|i| format!("d{i}")).collect()
    }

    fn accepts(mutate: impl FnOnce(&mut JobSpec)) {
        let mut spec = valid();
        mutate(&mut spec);
        if let Err(e) = spec.validate() {
            panic!("expected acceptance, got: {e}");
        }
    }

    fn rejects(message: &str, mutate: impl FnOnce(&mut JobSpec)) {
        let mut spec = valid();
        mutate(&mut spec);
        match spec.validate() {
            Ok(()) => panic!("expected rejection with: {message}"),
            Err(e) => assert_eq!(e.0, message),
        }
    }

    #[test]
    fn spec_size_limit_is_64_kib() {
        assert_eq!(MAX_SPEC_BYTES, 65536);
    }

    #[test]
    fn digest_valid_requires_prefix_and_64_lowercase_hex() {
        assert!(digest_valid(&hex64('a')));
        assert!(digest_valid(&format!(
            "sha256:{}",
            "0123456789abcdef".repeat(4)
        )));
        assert!(!digest_valid(""));
        assert!(!digest_valid("sha256:"));
        assert!(!digest_valid(&"a".repeat(64)));
        assert!(!digest_valid(&format!("sha512:{}", "a".repeat(64))));
        assert!(!digest_valid(&format!("sha256:{}", "a".repeat(63))));
        assert!(!digest_valid(&format!("sha256:{}", "a".repeat(65))));
        assert!(!digest_valid(&format!("sha256:{}", "A".repeat(64))));
        assert!(!digest_valid(&format!("sha256:{}g", "a".repeat(63))));
        assert!(!digest_valid(&format!("sha256:{}`", "a".repeat(63))));
        assert!(!digest_valid(&format!("sha256:{}/", "a".repeat(63))));
        assert!(!digest_valid(&format!("sha256:{}:", "a".repeat(63))));
    }

    #[test]
    fn printable_bounds_length_and_rejects_control_characters() {
        assert!(printable("a", 4));
        assert!(printable("abcd", 4));
        assert!(!printable("", 4));
        assert!(!printable("abcde", 4));
        assert!(!printable("a\nb", 4));
        assert!(!printable("a\u{7f}", 4));
        assert!(!printable("\0", 4));
        assert!(printable("a b", 4));
    }

    #[test]
    fn safe_relative_accepts_plain_paths_and_rejects_traversal() {
        assert!(safe_relative("build"));
        assert!(safe_relative("a/b"));
        assert!(!safe_relative(""));
        assert!(!safe_relative("../x"));
        assert!(!safe_relative("/abs"));
        assert!(!safe_relative(".git"));
    }

    #[test]
    fn valid_spec_is_accepted() {
        valid().validate().unwrap();
    }

    #[test]
    fn version_must_be_one() {
        rejects("unsupported contract version", |s| s.version = 0);
        rejects("unsupported contract version", |s| s.version = 2);
    }

    #[test]
    fn image_identities_must_be_immutable() {
        const MSG: &str = "immutable prepared image/kernel identities required";
        rejects(MSG, |s| s.image.catalog_id = Uuid::nil());
        rejects(MSG, |s| s.image.rootfs_digest = "latest".into());
        rejects(MSG, |s| s.image.kernel_digest = "latest".into());
        rejects(MSG, |s| s.image.initrd_digest = Some("latest".into()));
        accepts(|s| s.image.initrd_digest = Some(hex64('e')));
        accepts(|s| s.image.initrd_digest = None);
    }

    #[test]
    fn bundle_identity_and_size_are_bounded() {
        const MSG: &str = "bundle identity or size invalid";
        let max = 32 * MIB;
        rejects(MSG, |s| s.source.digest = "bad".into());
        rejects(MSG, |s| s.source.size_bytes = 0);
        rejects(MSG, |s| s.source.size_bytes = max + 1);
        accepts(|s| s.source.size_bytes = 1);
        accepts(|s| s.source.size_bytes = max);
        rejects(MSG, |s| s.acceptance.digest = "bad".into());
        rejects(MSG, |s| s.acceptance.size_bytes = 0);
        rejects(MSG, |s| s.acceptance.size_bytes = max + 1);
        accepts(|s| s.acceptance.size_bytes = 1);
        accepts(|s| s.acceptance.size_bytes = max);
    }

    #[test]
    fn uid_and_gid_must_be_unprivileged_and_not_the_sentinel() {
        const MSG: &str = "unprivileged numeric user and group required";
        rejects(MSG, |s| s.uid = 0);
        rejects(MSG, |s| s.uid = 999);
        rejects(MSG, |s| s.uid = u32::MAX);
        rejects(MSG, |s| s.gid = 0);
        rejects(MSG, |s| s.gid = 999);
        rejects(MSG, |s| s.gid = u32::MAX);
        accepts(|s| s.uid = 1000);
        accepts(|s| s.gid = 1000);
        accepts(|s| {
            s.uid = u32::MAX - 1;
            s.gid = u32::MAX - 1;
        });
    }

    #[test]
    fn resource_limits_are_inclusive_ranges() {
        const MSG: &str = "explicit bounded CPU, memory, disk and process limits required";
        let gib = 1024 * MIB;
        let tib = 1024 * gib;
        rejects(MSG, |s| s.resources.vcpu_count = 0);
        accepts(|s| s.resources.vcpu_count = 1);
        accepts(|s| s.resources.vcpu_count = 32);
        rejects(MSG, |s| s.resources.vcpu_count = 33);

        rejects(MSG, |s| s.resources.mem_size_mib = 127);
        accepts(|s| s.resources.mem_size_mib = 128);
        accepts(|s| s.resources.mem_size_mib = 65536);
        rejects(MSG, |s| s.resources.mem_size_mib = 65537);

        rejects(MSG, |s| s.resources.disk_size_bytes = gib - 1);
        accepts(|s| s.resources.disk_size_bytes = gib);
        accepts(|s| s.resources.disk_size_bytes = tib);
        rejects(MSG, |s| s.resources.disk_size_bytes = tib + 1);

        rejects(MSG, |s| s.resources.pids_limit = 0);
        accepts(|s| s.resources.pids_limit = 1);
        accepts(|s| s.resources.pids_limit = 512);
        rejects(MSG, |s| s.resources.pids_limit = 513);
    }

    #[test]
    fn working_directory_must_be_workspace_or_a_safe_subpath() {
        const MSG: &str = "working directory must be inside /workspace";
        accepts(|s| s.working_directory = "/workspace".into());
        accepts(|s| s.working_directory = "/workspace/crates/app".into());
        rejects(MSG, |s| s.working_directory = String::new());
        rejects(MSG, |s| s.working_directory = "/".into());
        rejects(MSG, |s| s.working_directory = "/workspace/".into());
        rejects(MSG, |s| s.working_directory = "/workspacex".into());
        rejects(MSG, |s| s.working_directory = "/other".into());
        rejects(MSG, |s| s.working_directory = "workspace".into());
        rejects(MSG, |s| s.working_directory = "/workspace/../etc".into());
        rejects(MSG, |s| s.working_directory = "/workspace/.git".into());
    }

    #[test]
    fn at_most_16_writable_directories() {
        const MSG: &str = "at most 16 declared build/output directories";
        accepts(|s| s.writable_directories = dirs(0));
        accepts(|s| s.writable_directories = dirs(16));
        rejects(MSG, |s| s.writable_directories = dirs(17));
    }

    #[test]
    fn writable_directories_must_be_safe_and_nonoverlapping() {
        const MSG: &str = "build/output directories must be safe and nonoverlapping";
        let set = |paths: &[&str]| -> Vec<String> { paths.iter().map(|p| (*p).into()).collect() };
        accepts(|s| s.writable_directories = set(&["a", "b"]));
        accepts(|s| s.writable_directories = set(&["a", "ab"]));
        accepts(|s| s.writable_directories = set(&["ab", "a"]));
        accepts(|s| s.writable_directories = set(&["a/b", "a/c"]));
        rejects(MSG, |s| s.writable_directories = set(&["a", "a"]));
        rejects(MSG, |s| s.writable_directories = set(&["a", "a/b"]));
        rejects(MSG, |s| s.writable_directories = set(&["a/b", "a"]));
        rejects(MSG, |s| s.writable_directories = set(&["../x"]));
        rejects(MSG, |s| s.writable_directories = set(&["ok", "/abs"]));
        rejects(MSG, |s| s.writable_directories = set(&[""]));
    }

    #[test]
    fn command_count_is_between_1_and_32() {
        const MSG: &str = "1\u{2013}32 trusted command argv arrays required";
        let many = |n: usize| vec![command(&["true"], 1); n];
        rejects(MSG, |s| s.commands = vec![]);
        accepts(|s| s.commands = many(1));
        accepts(|s| s.commands = many(32));
        rejects(MSG, |s| s.commands = many(33));
    }

    #[test]
    fn command_argv_and_timeout_are_bounded() {
        const MSG: &str = "argv or command timeout invalid (maximum 20 minutes)";
        let with_argv = |argv: Vec<String>| JobCommand {
            argv,
            timeout_secs: 1,
        };
        rejects(MSG, |s| s.commands = vec![with_argv(vec![])]);
        rejects(MSG, |s| s.commands = vec![with_argv(vec![String::new()])]);
        accepts(|s| s.commands = vec![with_argv(vec!["x".into(); 128])]);
        rejects(MSG, |s| s.commands = vec![with_argv(vec!["x".into(); 129])]);
        accepts(|s| s.commands = vec![with_argv(vec!["x".into(), "a".repeat(4096)])]);
        rejects(MSG, |s| {
            s.commands = vec![with_argv(vec!["x".into(), "a".repeat(4097)])]
        });
        rejects(MSG, |s| {
            s.commands = vec![with_argv(vec!["a".repeat(4097)])]
        });
        rejects(MSG, |s| {
            s.commands = vec![with_argv(vec!["x".into(), "a\0b".into()])]
        });
        rejects(MSG, |s| s.commands = vec![with_argv(vec!["a\0".into()])]);
        rejects(MSG, |s| s.commands = vec![command(&["x"], 0)]);
        accepts(|s| s.commands = vec![command(&["x"], 1)]);
        accepts(|s| s.commands = vec![command(&["x"], 1200)]);
        rejects(MSG, |s| s.commands = vec![command(&["x"], 1201)]);
        rejects(MSG, |s| {
            s.commands = vec![command(&["ok"], 1), command(&["x"], 0)]
        });
    }

    #[test]
    fn environment_is_limited_to_the_non_secret_allowlist() {
        const MSG: &str = "environment is outside the non-secret check allowlist";
        let allowed = [
            "PATH",
            "HOME",
            "LANG",
            "LC_ALL",
            "TZ",
            "TMPDIR",
            "RUSTUP_HOME",
            "CARGO_HOME",
            "CARGO_NET_OFFLINE",
            "RUSTFLAGS",
            "WERKT_ACCEPTANCE_DIR",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_CONFIG_GLOBAL",
        ];
        accepts(|s| {
            s.environment = allowed.iter().map(|k| ((*k).into(), "v".into())).collect();
        });
        for key in ["SECRET", "path", "AWS_SECRET_ACCESS_KEY", "", "PATH2"] {
            rejects(MSG, |s| {
                s.environment.insert(key.into(), "v".into());
            });
        }
        accepts(|s| {
            s.environment.insert("PATH".into(), "a".repeat(4096));
        });
        rejects(MSG, |s| {
            s.environment.insert("PATH".into(), "a".repeat(4097));
        });
        rejects(MSG, |s| {
            s.environment.insert("PATH".into(), "a\0b".into());
        });
    }

    #[test]
    fn filtered_network_requires_bounded_explicit_rules() {
        const MSG: &str = "filtered network requires 1\u{2013}32 bounded explicit egress rules";
        let ok = || rule("example.test", 443, "tcp");
        accepts(|s| s.network = JobNetwork::None {});
        accepts(|s| s.network = filtered(vec![ok()]));
        accepts(|s| s.network = filtered(vec![ok(); 32]));
        rejects(MSG, |s| s.network = filtered(vec![]));
        rejects(MSG, |s| s.network = filtered(vec![ok(); 33]));
        accepts(|s| s.network = filtered(vec![rule("a", 1, "udp")]));
        accepts(|s| s.network = filtered(vec![rule("a", 65535, "tcp")]));
        accepts(|s| s.network = filtered(vec![rule(&"h".repeat(253), 1, "tcp")]));
        rejects(MSG, |s| {
            s.network = filtered(vec![rule(&"h".repeat(254), 1, "tcp")])
        });
        rejects(MSG, |s| s.network = filtered(vec![rule("", 1, "tcp")]));
        rejects(MSG, |s| s.network = filtered(vec![rule("a\nb", 1, "tcp")]));
        rejects(MSG, |s| s.network = filtered(vec![rule("a", 0, "tcp")]));
        rejects(MSG, |s| s.network = filtered(vec![rule("a", 1, "icmp")]));
        rejects(MSG, |s| s.network = filtered(vec![rule("a", 1, "TCP")]));
        rejects(MSG, |s| s.network = filtered(vec![rule("a", 1, "")]));
        rejects(MSG, |s| {
            s.network = filtered(vec![ok(), rule("", 1, "tcp")])
        });
        rejects(MSG, |s| {
            s.network = filtered(vec![ok(), rule("a", 0, "tcp")])
        });
        rejects(MSG, |s| {
            s.network = filtered(vec![ok(), rule("a", 1, "sctp")])
        });
    }

    #[test]
    fn deadline_must_be_a_nonnegative_whole_second() {
        const MSG: &str = "deadline must be a nonnegative whole UTC second";
        accepts(|s| s.deadline = DateTime::from_timestamp(0, 0).unwrap());
        accepts(|s| s.deadline = DateTime::from_timestamp(1, 0).unwrap());
        rejects(MSG, |s| {
            s.deadline = DateTime::from_timestamp(-1, 0).unwrap()
        });
        rejects(MSG, |s| {
            s.deadline = DateTime::from_timestamp(1_800_000_000, 1).unwrap()
        });
        rejects(MSG, |s| {
            s.deadline = DateTime::from_timestamp(1_800_000_000, 999_999_999).unwrap()
        });
    }

    #[test]
    fn at_most_16_artifacts() {
        const MSG: &str = "at most 16 declared artifacts";
        let many = |n: usize| (0..n).map(|i| artifact(&format!("o{i}"), 1)).collect();
        accepts(|s| s.artifacts = many(16));
        rejects(MSG, |s| s.artifacts = many(17));
    }

    #[test]
    fn artifacts_need_unique_safe_paths_and_bounded_sizes() {
        const MSG: &str = "artifact must have a unique safe relative path and a bounded size";
        accepts(|s| s.artifacts = vec![artifact("out/a.txt", 1)]);
        accepts(|s| s.artifacts = vec![artifact("a", 4 * MIB)]);
        rejects(MSG, |s| s.artifacts = vec![artifact("a", 0)]);
        rejects(MSG, |s| s.artifacts = vec![artifact("a", 4 * MIB + 1)]);
        rejects(MSG, |s| s.artifacts = vec![artifact("../a", 1)]);
        rejects(MSG, |s| s.artifacts = vec![artifact("", 1)]);
        rejects(MSG, |s| {
            s.artifacts = vec![artifact("a", 1), artifact("a", 1)]
        });
        accepts(|s| s.artifacts = vec![artifact("a", 1), artifact("b", 1)]);
        rejects(MSG, |s| {
            s.artifacts = vec![artifact("a", 1), artifact("b", 0)]
        });
    }

    #[test]
    fn artifact_budget_is_16_mib_in_total() {
        const MSG: &str = "artifact budget exceeds 16 MiB";
        let four = |extra: Option<u64>| {
            let mut list: Vec<JobArtifact> = (0..4)
                .map(|i| artifact(&format!("big{i}"), 4 * MIB))
                .collect();
            if let Some(bytes) = extra {
                list.push(artifact("extra", bytes));
            }
            list
        };
        accepts(|s| s.artifacts = four(None));
        rejects(MSG, |s| s.artifacts = four(Some(1)));
        rejects(MSG, |s| s.artifacts = four(Some(4 * MIB)));
    }

    #[test]
    fn correlation_is_bounded_and_printable() {
        const MSG: &str = "bounded non-secret job/stage correlation required";
        accepts(|s| s.correlation.job = "j".repeat(128));
        rejects(MSG, |s| s.correlation.job = "j".repeat(129));
        rejects(MSG, |s| s.correlation.job = String::new());
        rejects(MSG, |s| s.correlation.job = "a\tb".into());
        accepts(|s| s.correlation.stage = "s".repeat(64));
        rejects(MSG, |s| s.correlation.stage = "s".repeat(65));
        rejects(MSG, |s| s.correlation.stage = String::new());
        rejects(MSG, |s| s.correlation.stage = "a\nb".into());
    }

    const CANONICAL: &str = concat!(
        r#"{"acceptance":{"digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","size_bytes":20},"#,
        r#""artifacts":[{"max_bytes":5,"path":"out/r.txt"}],"#,
        r#""commands":[{"argv":["cargo","t\"q\\ é\n"],"timeout_secs":60}],"#,
        r#""correlation":{"job":"job-1","round":3,"stage":"check"},"#,
        r#""deadline":"2027-01-15T08:00:00Z","environment":{"HOME":"/h","PATH":"/p"},"gid":1001,"#,
        r#""image":{"catalog_id":"00000000-0000-0000-0000-000000000007","initrd_digest":null,"#,
        r#""kernel_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","#,
        r#""rootfs_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"#,
        r#""network":{"mode":"filtered","rules":[{"host":"example.test","port":443,"protocol":"tcp"}]},"#,
        r#""resources":{"disk_size_bytes":2147483648,"mem_size_mib":512,"pids_limit":64,"vcpu_count":2},"#,
        r#""source":{"digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size_bytes":10},"#,
        r#""uid":1000,"version":1,"working_directory":"/workspace/app","writable_directories":["build"]}"#,
    );

    fn canonical_fixture() -> JobSpec {
        let mut spec = valid();
        spec.commands = vec![command(&["cargo", "t\"q\\ é\n"], 60)];
        spec.working_directory = "/workspace/app".into();
        spec.writable_directories = vec!["build".into()];
        spec.environment =
            BTreeMap::from([("PATH".into(), "/p".into()), ("HOME".into(), "/h".into())]);
        spec.gid = 1001;
        spec.network = filtered(vec![rule("example.test", 443, "tcp")]);
        spec.deadline = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        spec.artifacts = vec![artifact("out/r.txt", 5)];
        spec
    }

    #[test]
    fn canonical_json_is_sorted_compact_utf8() {
        assert_eq!(canonical_fixture().canonical_json().unwrap(), CANONICAL);
    }

    #[test]
    fn canonical_json_sorts_keys_inside_arrays_and_the_network_tag() {
        let mut spec = canonical_fixture();
        spec.network = JobNetwork::None {};
        let json = spec.canonical_json().unwrap();
        assert!(json.contains(r#""network":{"mode":"none"}"#));
        assert!(json.contains(r#""commands":[{"argv":"#));
    }

    #[test]
    fn sort_json_keys_orders_nested_objects_and_objects_in_arrays() {
        let mut value: serde_json::Value = serde_json::from_str(
            r#"{"z":1,"a":{"y":[{"d":1,"b":2},3],"x":{"q":1,"p":2}},"m":[[{"k":1,"j":2}]]}"#,
        )
        .unwrap();
        sort_json_keys(&mut value);
        assert_eq!(
            serde_json::to_string(&value).unwrap(),
            r#"{"a":{"x":{"p":2,"q":1},"y":[{"b":2,"d":1},3]},"m":[[{"j":2,"k":1}]],"z":1}"#
        );
    }

    #[test]
    fn digest_is_sha256_of_the_canonical_bytes() {
        let expected = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(CANONICAL.as_bytes()))
        );
        assert_eq!(canonical_fixture().digest().unwrap(), expected);
        assert_eq!(expected.len(), "sha256:".len() + 64);
    }

    #[test]
    fn invalid_specs_have_no_canonical_form_or_digest() {
        let mut spec = valid();
        spec.version = 2;
        assert!(spec.canonical_json().is_err());
        assert!(spec.digest().is_err());
    }

    fn serialized_len(spec: &JobSpec) -> usize {
        serde_json::to_string(&serde_json::to_value(spec).unwrap())
            .unwrap()
            .len()
    }

    fn spec_with_serialized_len(target: usize) -> JobSpec {
        let build = |tail: usize| {
            let mut argv = vec!["x".to_string()];
            argv.extend(std::iter::repeat_n("a".repeat(4000), 16));
            argv.push("b".repeat(tail));
            let mut spec = valid();
            spec.commands = vec![JobCommand {
                argv,
                timeout_secs: 1,
            }];
            spec
        };
        let probe = serialized_len(&build(1000));
        let tail = (1000 + target).checked_sub(probe).unwrap();
        assert!(tail <= 4096);
        let spec = build(tail);
        assert_eq!(serialized_len(&spec), target);
        spec
    }

    #[test]
    fn canonical_json_accepts_exactly_64_kib_and_rejects_one_more() {
        let at_limit = spec_with_serialized_len(65536);
        assert_eq!(at_limit.canonical_json().unwrap().len(), 65536);
        let over = spec_with_serialized_len(65537);
        let err = over.canonical_json().unwrap_err();
        assert_eq!(err.0, "specification exceeds 64 KiB");
        assert!(over.digest().is_err());
    }

    fn submission(spec: JobSpec) -> JobSubmission {
        let digest = spec.digest().unwrap();
        JobSubmission {
            idempotency_key: "key-1".into(),
            execution_specification_digest: digest,
            specification: spec,
        }
    }

    #[test]
    fn submission_returns_the_canonical_specification_when_digest_matches() {
        let sub = submission(canonical_fixture());
        assert_eq!(sub.canonical_specification().unwrap(), CANONICAL);
    }

    #[test]
    fn submission_rejects_a_mismatched_digest() {
        let mut sub = submission(canonical_fixture());
        sub.execution_specification_digest = hex64('0');
        assert_eq!(
            sub.canonical_specification().unwrap_err().0,
            "execution specification digest mismatch"
        );
        let mut sub = submission(canonical_fixture());
        sub.execution_specification_digest = String::new();
        assert!(sub.canonical_specification().is_err());
    }

    #[test]
    fn submission_idempotency_key_is_bounded_and_printable() {
        const MSG: &str = "bounded non-secret idempotency key required";
        let with_key = |key: String| {
            let mut sub = submission(valid());
            sub.idempotency_key = key;
            sub.canonical_specification()
        };
        assert!(with_key("k".into()).is_ok());
        assert!(with_key("k".repeat(128)).is_ok());
        assert_eq!(with_key("k".repeat(129)).unwrap_err().0, MSG);
        assert_eq!(with_key(String::new()).unwrap_err().0, MSG);
        assert_eq!(with_key("a\nb".into()).unwrap_err().0, MSG);
    }

    #[test]
    fn submission_propagates_specification_errors() {
        let mut sub = submission(valid());
        sub.specification.version = 9;
        assert_eq!(
            sub.canonical_specification().unwrap_err().0,
            "unsupported contract version"
        );
    }
}
