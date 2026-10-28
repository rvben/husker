use husker_agent::job_runner::validate_bundle_policy;
use husker_agent_proto::frozen_bundle::{BundleFile, FrozenBundle};
use husker_agent_proto::job_spec::JobSpec;
use serde_json::json;
use std::collections::BTreeMap;

#[test]
fn factory_supervisor_cannot_be_started_as_an_ordinary_host_process() {
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_husker-agent"))
        .arg("--factory-supervisor")
        .output()
        .unwrap();
    assert!(!result.status.success());
    let diagnostic = String::from_utf8_lossy(&result.stderr);
    assert!(
        diagnostic.contains("factory supervisor requires"),
        "{diagnostic}"
    );
}

fn inputs() -> (JobSpec, FrozenBundle, FrozenBundle) {
    let source = FrozenBundle::from_files(BTreeMap::from([(
        "src/main.rs".into(),
        BundleFile {
            data: b"fn main() {}".to_vec(),
            executable: false,
        },
    )]))
    .unwrap();
    let acceptance = FrozenBundle::from_files(BTreeMap::new()).unwrap();
    let spec = serde_json::from_value(json!({
        "version": 1,
        "image": {"catalog_id": "10000000-0000-0000-0000-000000000000", "rootfs_digest": format!("sha256:{}", "a".repeat(64)), "kernel_digest": format!("sha256:{}", "b".repeat(64)), "initrd_digest": null},
        "source": {"digest": source.digest(), "size_bytes": source.bytes().len()},
        "acceptance": {"digest": acceptance.digest(), "size_bytes": acceptance.bytes().len()},
        "commands": [{"argv": ["true"], "timeout_secs": 30}],
        "working_directory": "/workspace", "writable_directories": ["target", "results"],
        "environment": {}, "uid": 1000, "gid": 1000,
        "resources": {"vcpu_count": 1, "mem_size_mib": 512, "disk_size_bytes": 2 * 1024_u64.pow(3), "pids_limit": 128},
        "network": {"mode": "none"}, "deadline": "2033-05-18T03:33:20Z", "artifacts": [],
        "correlation": {"job": "synthetic", "stage": "baseline", "round": 0}
    })).unwrap();
    (spec, source, acceptance)
}

#[test]
fn exclusions_cannot_hide_frozen_source_and_bind_the_spec_digest() {
    let (spec, source, acceptance) = inputs();
    validate_bundle_policy(&spec, &source, &acceptance).unwrap();
    let mut changed = spec.clone();
    changed.writable_directories = vec!["src".into()];
    assert!(validate_bundle_policy(&changed, &source, &acceptance).is_err());
    assert_ne!(changed.digest().unwrap(), spec.digest().unwrap());
    changed.writable_directories = vec!["src/main.rs/child".into()];
    assert!(validate_bundle_policy(&changed, &source, &acceptance).is_err());
    changed.writable_directories = vec!["target".into(), "target/cache".into()];
    assert!(changed.validate().is_err());
    changed.writable_directories = vec![".ssh".into()];
    assert!(changed.validate().is_err());
    let wrong = FrozenBundle::from_files(BTreeMap::new()).unwrap();
    assert!(validate_bundle_policy(&spec, &wrong, &acceptance).is_err());
}

#[test]
fn source_inventory_ignores_only_declared_initially_empty_build_trees() {
    let (spec, source, _) = inputs();
    let temp = tempfile::tempdir().unwrap();
    let root = source
        .extract_new_directory(&std::fs::File::open(temp.path()).unwrap(), "workspace")
        .unwrap();
    let workspace = temp.path().join("workspace");
    std::fs::create_dir(workspace.join("target")).unwrap();
    std::fs::write(workspace.join("target/generated"), b"build output").unwrap();
    assert_eq!(
        FrozenBundle::freeze_directory_excluding(&root, &spec.writable_directories)
            .unwrap()
            .digest(),
        source.digest()
    );
    std::fs::write(workspace.join("src/new.rs"), b"new code").unwrap();
    assert_ne!(
        FrozenBundle::freeze_directory_excluding(&root, &spec.writable_directories)
            .unwrap()
            .digest(),
        source.digest()
    );
    std::fs::remove_file(workspace.join("src/new.rs")).unwrap();
    std::fs::write(workspace.join("src/main.rs"), b"changed code").unwrap();
    assert_ne!(
        FrozenBundle::freeze_directory_excluding(&root, &spec.writable_directories)
            .unwrap()
            .digest(),
        source.digest()
    );
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn unsupported_platform_cannot_run_even_a_trusted_command() {
    let (spec, _, _) = inputs();
    assert!(
        husker_agent::job_process::build_job_process(
            &spec,
            0,
            "10000000-0000-0000-0000-000000000000"
        )
        .is_err()
    );
    let error = husker_agent::job_runner::run(
        "10000000-0000-0000-0000-000000000000",
        &spec.digest().unwrap(),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("refusing host execution"));
    let error = husker_agent::job_runner::prepare(
        "10000000-0000-0000-0000-000000000000",
        &spec.digest().unwrap(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("refusing host preparation"));
}

#[test]
fn guest_manifest_identity_and_missing_evidence_cannot_become_success() {
    use husker_agent_proto::job_result::GuestJobManifest;
    let (spec, _, _) = inputs();
    let id = spec.image.catalog_id;
    let good = json!({
        "version": 1, "job_id": id, "execution_specification_digest": spec.digest().unwrap(),
        "image": spec.image, "source": spec.source, "acceptance": spec.acceptance,
        "commands": [{"command_index": 0, "exit_code": 0, "outcome": "completed",
            "duration_ms": 1, "output": "ok", "output_truncated": false,
            "logs_truncated": false, "termination_confirmed": true}],
        "artifacts": [], "source_changed": false, "source_verification_error": null,
        "collection_status": "complete", "outcome": "completed"
    });
    GuestJobManifest::decode_for(&serde_json::to_vec(&good).unwrap(), &spec, id).unwrap();
    for (pointer, value) in [
        ("/job_id", json!("20000000-0000-0000-0000-000000000000")),
        ("/version", json!(2)),
        ("/commands", json!([])),
        ("/commands/0/command_index", json!(1)),
        ("/commands/0/exit_code", json!(1)),
        ("/commands/0/termination_confirmed", json!(false)),
        ("/source_changed", json!(true)),
        ("/source_changed", json!(null)),
        ("/source_verification_error", json!("collection failed")),
        ("/collection_status", json!("failed")),
        ("/outcome", json!("unsupported_outcome")),
        (
            "/image/kernel_digest",
            json!(format!("sha256:{}", "f".repeat(64))),
        ),
        ("/commands/0/output", json!("x".repeat(2049))),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(
            GuestJobManifest::decode_for(&serde_json::to_vec(&bad).unwrap(), &spec, id).is_err(),
            "{pointer}"
        );
    }
    let mut bad = good.clone();
    bad["ignored_security_field"] = json!(true);
    assert!(GuestJobManifest::decode_for(&serde_json::to_vec(&bad).unwrap(), &spec, id).is_err());
    assert!(GuestJobManifest::decode_for(&vec![b' '; 65537], &spec, id).is_err());
}

#[test]
fn artifact_receipt_has_declared_path_limit_and_fixed_storage_identity() {
    use husker_agent_proto::job_result::GuestJobManifest;
    let (mut spec, _, _) = inputs();
    spec.artifacts =
        serde_json::from_value(json!([{"path": "results/check.json", "max_bytes": 4}])).unwrap();
    let id = spec.image.catalog_id;
    let good = json!({
        "version": 1, "job_id": id, "execution_specification_digest": spec.digest().unwrap(),
        "image": spec.image, "source": spec.source, "acceptance": spec.acceptance,
        "commands": [{"command_index": 0, "exit_code": 0, "outcome": "completed",
            "duration_ms": 1, "output": "", "output_truncated": false,
            "logs_truncated": false, "termination_confirmed": true}],
        "artifacts": [{"path": "results/check.json", "stored_name": "0.bin", "digest": format!("sha256:{}", "a".repeat(64)), "size_bytes": 4, "error": null}],
        "source_changed": false, "source_verification_error": null,
        "collection_status": "complete", "outcome": "completed"
    });
    GuestJobManifest::decode_for(&serde_json::to_vec(&good).unwrap(), &spec, id).unwrap();
    for (pointer, value) in [
        ("/artifacts", json!([])),
        ("/artifacts/0/path", json!("other")),
        ("/artifacts/0/stored_name", json!("../escape")),
        ("/artifacts/0/size_bytes", json!(5)),
        ("/artifacts/0/digest", json!("mutable-tag")),
        ("/artifacts/0/error", json!("missing")),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(
            GuestJobManifest::decode_for(&serde_json::to_vec(&bad).unwrap(), &spec, id).is_err(),
            "{pointer}"
        );
    }
    let mut failed = good;
    failed["outcome"] = json!("infrastructure_failed");
    failed["collection_status"] = json!("failed");
    failed["artifacts"][0] = json!({"path": "results/check.json", "stored_name": null, "digest": null, "size_bytes": null, "error": "missing"});
    GuestJobManifest::decode_for(&serde_json::to_vec(&failed).unwrap(), &spec, id).unwrap();
}
