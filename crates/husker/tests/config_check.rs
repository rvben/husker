use std::fs;

use assert_cmd::Command;

fn valid_config_fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let kernel = dir.path().join("vmlinux");
    let rootfs = dir.path().join("rootfs.ext4");
    fs::write(&kernel, b"kernel").unwrap();
    fs::write(&rootfs, b"rootfs").unwrap();
    // These tests are about config validation, so every path the check reads
    // has to come from the fixture. Left to the default, `firecracker_bin`
    // resolves against the host's PATH and the same config passes on a
    // provisioned machine and fails on a bare one. The key is ignored on
    // builds without `linux-net`, where the check does not exist.
    let firecracker = dir.path().join("firecracker");
    fs::write(&firecracker, b"vmm").unwrap();
    let config = dir.path().join("config.toml");
    fs::write(
        &config,
        format!(
            "data_dir = {:?}\ndefault_kernel = {:?}\ndefault_rootfs = {:?}\nfirecracker_bin = {:?}\nimages_base_url = \"https://example.invalid/images\"\n",
            dir.path().join("data"),
            kernel,
            rootfs,
            firecracker,
        ),
    )
    .unwrap();
    (dir, config)
}

#[test]
fn config_check_json_is_one_typed_success_document() {
    let (_dir, config) = valid_config_fixture();
    let output = Command::cargo_bin("husker")
        .unwrap()
        .args([
            "--config",
            config.to_str().unwrap(),
            "--output",
            "json",
            "config",
            "check",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "ok");
    assert_eq!(report["source"], "file");
    assert!(
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| { check["name"] == "default_kernel" && check["status"] == "ok" })
    );
}

#[test]
fn config_check_json_reports_parse_failure_without_mixed_prose() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("broken.toml");
    fs::write(&config, "this is = = invalid\n").unwrap();
    let output = Command::cargo_bin("husker")
        .unwrap()
        .args([
            "--config",
            config.to_str().unwrap(),
            "--output",
            "json",
            "config",
            "check",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "error");
    assert_eq!(report["checks"][0]["name"], "config_file");
    assert_eq!(report["checks"][0]["status"], "fail");
}

/// The initrd path husker derives for itself points at a file that only exists
/// once a kernel has been downloaded. `vm_lifecycle` drops it when it is absent
/// and boots without one, so `config check` must not call a fresh install
/// broken.
#[test]
fn a_derived_initrd_that_was_never_downloaded_is_not_a_failure() {
    let (dir, config) = valid_config_fixture();
    let fresh_machine = dir.path().join("never-downloaded");
    let output = Command::cargo_bin("husker")
        .unwrap()
        .env("HOME", &fresh_machine)
        .env("XDG_DATA_HOME", &fresh_machine)
        .args([
            "--config",
            config.to_str().unwrap(),
            "--output",
            "json",
            "config",
            "check",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "ok");
    let initrd = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["name"] == "default_initrd")
        .unwrap();
    assert_eq!(initrd["status"], "warn");
}

/// An initrd the operator named by hand is a different fact from one husker
/// guessed: they asked for it, and it is not there.
#[test]
fn an_explicitly_configured_initrd_that_is_missing_still_fails() {
    let (dir, config) = valid_config_fixture();
    let missing = dir.path().join("asked-for-this.gz");
    let output = Command::cargo_bin("husker")
        .unwrap()
        .env("HUSKER_DEFAULT_INITRD", &missing)
        .args([
            "--config",
            config.to_str().unwrap(),
            "--output",
            "json",
            "config",
            "check",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "error");
    let initrd = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["name"] == "default_initrd")
        .unwrap();
    assert_eq!(initrd["status"], "fail");
}

#[test]
fn config_check_validates_the_effective_environment_override() {
    let (dir, config) = valid_config_fixture();
    let override_kernel = dir.path().join("override-vmlinux");
    fs::write(&override_kernel, b"override").unwrap();
    let output = Command::cargo_bin("husker")
        .unwrap()
        .env("HUSKER_DEFAULT_KERNEL", &override_kernel)
        .args([
            "--config",
            config.to_str().unwrap(),
            "--output",
            "json",
            "config",
            "check",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let kernel = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["name"] == "default_kernel")
        .unwrap();
    assert!(
        kernel["message"]
            .as_str()
            .unwrap()
            .ends_with("override-vmlinux")
    );
}
