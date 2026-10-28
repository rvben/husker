use chrono::{TimeZone, Utc};
use husker_core::job_spec::*;
use serde_json::json;
use uuid::Uuid;

fn sha(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}
fn spec() -> JobSpec {
    JobSpec {
        version: 1,
        image: PreparedJobImage {
            catalog_id: Uuid::new_v4(),
            rootfs_digest: sha('a'),
            kernel_digest: sha('b'),
            initrd_digest: None,
        },
        source: JobBundle {
            digest: sha('c'),
            size_bytes: 4096,
        },
        acceptance: JobBundle {
            digest: sha('d'),
            size_bytes: 4096,
        },
        commands: vec![JobCommand {
            argv: vec!["cargo".into(), "test".into(), "--offline".into()],
            timeout_secs: 1200,
        }],
        working_directory: "/workspace".into(),
        writable_directories: vec!["target".into(), "results".into()],
        environment: [
            ("HOME".into(), "/tmp".into()),
            ("CARGO_NET_OFFLINE".into(), "true".into()),
        ]
        .into(),
        uid: 1001,
        gid: 1001,
        resources: JobResources {
            vcpu_count: 2,
            mem_size_mib: 4096,
            disk_size_bytes: 20 * 1024 * 1024 * 1024,
            pids_limit: 128,
        },
        network: JobNetwork::None {},
        deadline: Utc.timestamp_opt(2_000_000_000, 0).unwrap(),
        artifacts: vec![JobArtifact {
            path: "results/check.json".into(),
            max_bytes: 4096,
        }],
        correlation: JobCorrelation {
            job: "job-1".into(),
            stage: "candidate".into(),
            round: 1,
        },
    }
}

#[test]
fn identity_binds_every_execution_input_and_environment_order_is_canonical() {
    let original = spec();
    let digest = original.digest().unwrap();
    let submission = JobSubmission {
        idempotency_key: "stage/1".into(),
        execution_specification_digest: digest.clone(),
        specification: original.clone(),
    };
    assert_eq!(
        submission.canonical_specification().unwrap(),
        original.canonical_json().unwrap()
    );
    let mut changes = Vec::new();
    macro_rules! changed {
        ($field:ident, $value:expr) => {{
            let mut s = original.clone();
            s.$field = $value;
            changes.push(s);
        }};
    }
    changed!(
        image,
        PreparedJobImage {
            rootfs_digest: sha('e'),
            ..original.image.clone()
        }
    );
    changed!(
        image,
        PreparedJobImage {
            kernel_digest: sha('e'),
            ..original.image.clone()
        }
    );
    changed!(
        image,
        PreparedJobImage {
            initrd_digest: Some(sha('e')),
            ..original.image.clone()
        }
    );
    changed!(
        source,
        JobBundle {
            digest: sha('e'),
            ..original.source.clone()
        }
    );
    changed!(
        acceptance,
        JobBundle {
            digest: sha('e'),
            ..original.acceptance.clone()
        }
    );
    changed!(
        commands,
        vec![JobCommand {
            argv: vec!["true".into()],
            timeout_secs: 600
        }]
    );
    changed!(working_directory, "/workspace/subdirectory".into());
    changed!(writable_directories, vec!["other-build-output".into()]);
    changed!(environment, [("HOME".into(), "/tmp/other".into())].into());
    changed!(
        resources,
        JobResources {
            mem_size_mib: 2048,
            ..original.resources.clone()
        }
    );
    changed!(uid, 1002);
    changed!(gid, 1002);
    changed!(
        network,
        JobNetwork::Filtered {
            rules: vec![JobEgressRule {
                host: "example.com".into(),
                port: 443,
                protocol: "tcp".into()
            }]
        }
    );
    changed!(deadline, original.deadline + chrono::Duration::seconds(1));
    changed!(artifacts, vec![]);
    changed!(
        correlation,
        JobCorrelation {
            round: 2,
            ..original.correlation.clone()
        }
    );
    for changed in changes {
        assert_ne!(changed.digest().unwrap(), digest);
        let changed_submission = JobSubmission {
            specification: changed,
            ..submission.clone()
        };
        assert!(changed_submission.canonical_specification().is_err());
    }
    let json = original.canonical_json().unwrap();
    assert!(
        json.starts_with("{\"acceptance\":"),
        "top-level keys must be sorted for non-Rust clients"
    );
    let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
    value["environment"] = json!({"CARGO_NET_OFFLINE":"true","HOME":"/tmp"});
    let decoded: JobSpec = serde_json::from_value(value).unwrap();
    assert_eq!(decoded.canonical_json().unwrap(), json);
}

#[test]
fn unknown_policy_fields_and_versions_fail_closed_in_every_nested_object() {
    let original = spec();
    let base = serde_json::to_value(original).unwrap();
    for field in [
        "image",
        "source",
        "acceptance",
        "resources",
        "environment",
        "correlation",
    ] {
        let mut value = base.clone();
        value[field]["unsupported_security_policy"] = json!("enforce");
        let parsed = serde_json::from_value::<JobSpec>(value);
        assert!(
            parsed.is_err() || parsed.unwrap().validate().is_err(),
            "{field}"
        );
    }
    let mut value = base.clone();
    value["commands"][0]["shell_interpolation"] = json!(true);
    assert!(serde_json::from_value::<JobSpec>(value).is_err());
    let mut value = base.clone();
    value["network"] = json!({"mode":"none", "allow_host":true});
    assert!(serde_json::from_value::<JobSpec>(value).is_err());
    let mut value = base.clone();
    value["network"] = json!({"mode":"filtered", "rules":[{"host":"example.com","port":443,"protocol":"tcp","allow_private":true}]});
    assert!(serde_json::from_value::<JobSpec>(value).is_err());
    let mut value = base.clone();
    value["network"] = json!({"mode":"nat"});
    assert!(serde_json::from_value::<JobSpec>(value).is_err());
    let mut value = base;
    value["version"] = json!(2);
    assert!(
        serde_json::from_value::<JobSpec>(value)
            .unwrap()
            .validate()
            .is_err()
    );
}

#[test]
fn unsafe_paths_privileged_users_secrets_and_unbounded_commands_are_rejected() {
    for path in [
        "/etc/passwd",
        "/workspace/../etc",
        "/workspace/.git",
        "/workspace/./ok",
        "/workspace//ok",
        "/workspace/a\\b",
    ] {
        let mut s = spec();
        s.working_directory = path.into();
        assert!(s.validate().is_err(), "{path}");
    }
    for path in [
        "../outside",
        "/root/secret",
        ".ssh/key",
        "a/.codex/auth",
        "a//b",
        "a/./b",
        "a/../b",
    ] {
        let mut s = spec();
        s.artifacts[0].path = path.into();
        assert!(s.validate().is_err(), "{path}");
    }
    for uid in [0, 999, u32::MAX] {
        let mut s = spec();
        s.uid = uid;
        assert!(s.validate().is_err());
    }
    for name in [
        "HUSKER_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "SSH_AUTH_SOCK",
        "AWS_SECRET_ACCESS_KEY",
        "LD_PRELOAD",
    ] {
        let mut s = spec();
        s.environment.insert(name.into(), "synthetic".into());
        assert!(s.validate().is_err(), "{name}");
    }
    let mut s = spec();
    s.commands[0].timeout_secs = 1201;
    assert!(s.validate().is_err());
    let mut s = spec();
    s.resources.pids_limit = 0;
    assert!(s.validate().is_err());
    let mut s = spec();
    s.resources.mem_size_mib = 65537;
    assert!(s.validate().is_err());
    let mut s = spec();
    s.resources.disk_size_bytes = 0;
    assert!(s.validate().is_err());
    let mut s = spec();
    s.commands[0].argv[0] = "evil\0command".into();
    assert!(s.validate().is_err());
    let mut s = spec();
    s.commands.clear();
    assert!(s.validate().is_err());
    let mut s = spec();
    s.image.rootfs_digest = "ubuntu:latest".into();
    assert!(s.validate().is_err());
    let mut s = spec();
    s.source.digest = sha('A');
    assert!(s.validate().is_err());
    let mut s = spec();
    s.artifacts.push(s.artifacts[0].clone());
    assert!(s.validate().is_err());
    let mut s = spec();
    s.deadline += chrono::Duration::nanoseconds(1);
    assert!(s.validate().is_err());
}

#[test]
fn python_rust_share_unicode_canonical_specification_identity() {
    let spec: JobSpec =
        serde_json::from_str(include_str!("../../../tests/fixtures/job_spec_v1.json")).unwrap();
    assert_eq!(
        spec.digest().unwrap(),
        include_str!("../../../tests/fixtures/job_spec_v1.sha256").trim()
    );
}
