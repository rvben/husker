use std::fs;

use assert_cmd::Command;

fn valid_config_fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let kernel = dir.path().join("vmlinux");
    let rootfs = dir.path().join("rootfs.ext4");
    fs::write(&kernel, b"kernel").unwrap();
    fs::write(&rootfs, b"rootfs").unwrap();
    let config = dir.path().join("config.toml");
    fs::write(
        &config,
        format!(
            "data_dir = {:?}\ndefault_kernel = {:?}\ndefault_rootfs = {:?}\nimages_base_url = \"https://example.invalid/images\"\n",
            dir.path().join("data"),
            kernel,
            rootfs,
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
