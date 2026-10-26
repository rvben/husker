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
///
/// The fixture leaves `default_initrd` unset, so it derives from the data dir.
/// `HUSKER_DATA_DIR` pins that to the fresh directory: as root the platform
/// default is `/var/lib/husker`, where a provisioned host has a real initramfs.
#[test]
fn a_derived_initrd_that_was_never_downloaded_is_not_a_failure() {
    let (dir, config) = valid_config_fixture();
    let fresh_machine = dir.path().join("never-downloaded");
    let output = Command::cargo_bin("husker")
        .unwrap()
        .env("HOME", &fresh_machine)
        .env("XDG_DATA_HOME", &fresh_machine)
        .env("HUSKER_DATA_DIR", &fresh_machine)
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
    let checks = report["checks"].as_array().unwrap();
    let find = |name: &str| checks.iter().find(|check| check["name"] == name).unwrap();
    let initrd = find("default_initrd");
    assert_eq!(initrd["status"], "warn");
    // The derived initrd followed the data directory, so the variable that
    // moved it is named; the kernel the file names explicitly stayed put and
    // is attributed to the file.
    assert_eq!(initrd["env_override"], "HUSKER_DATA_DIR", "{initrd}");
    let kernel = find("default_kernel");
    assert!(kernel.get("env_override").is_none(), "{kernel}");
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
    assert_eq!(kernel["env_override"], "HUSKER_DEFAULT_KERNEL", "{kernel}");

    // The text rendering names the same variable on the same check.
    let text = Command::cargo_bin("husker")
        .unwrap()
        .env("HUSKER_DEFAULT_KERNEL", &override_kernel)
        .args([
            "--config",
            config.to_str().unwrap(),
            "--output",
            "text",
            "config",
            "check",
        ])
        .output()
        .unwrap();
    assert!(text.status.success());
    let stdout = String::from_utf8_lossy(&text.stdout);
    let line = stdout
        .lines()
        .find(|line| line.starts_with("[ok  ] default_kernel: "))
        .unwrap_or_else(|| panic!("{stdout}"));
    assert!(
        line.ends_with("override-vmlinux (from HUSKER_DEFAULT_KERNEL)"),
        "{line}"
    );
}

/// The two output modes are renderings of one report, so a configuration the
/// daemon would refuse fails in both. The text mode once exited 0 on an
/// invalid `images_base_url` while JSON reported `error`.
#[test]
fn an_invalid_images_base_url_fails_in_both_output_modes() {
    let (_dir, config) = valid_config_fixture();
    let contents = fs::read_to_string(&config)
        .unwrap()
        .replace("https://example.invalid/images", "not a url");
    fs::write(&config, contents).unwrap();

    let json = Command::cargo_bin("husker")
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
    assert_eq!(json.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report["status"], "error");
    let url = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["name"] == "images_base_url")
        .unwrap();
    assert_eq!(url["status"], "fail", "{url}");

    let text = Command::cargo_bin("husker")
        .unwrap()
        .args([
            "--config",
            config.to_str().unwrap(),
            "--output",
            "text",
            "config",
            "check",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert_eq!(text.status.code(), Some(1), "{stdout}");
    assert!(
        stdout
            .lines()
            .any(|line| line.starts_with("[FAIL] images_base_url: not a url: ")),
        "{stdout}"
    );
}

/// Every check in the JSON report is a line of the text report, in the same
/// order and with the same words, so a reader of either sees the same
/// findings.
#[test]
fn the_text_report_lists_the_same_checks_as_the_json_report() {
    let (_dir, config) = valid_config_fixture();
    let run = |format: &str| {
        let output = Command::cargo_bin("husker")
            .unwrap()
            // One override in effect, so the attribution is part of the parity.
            .env("HUSKER_IMAGES_BASE_URL", "https://example.invalid/images")
            .args([
                "--config",
                config.to_str().unwrap(),
                "--output",
                format,
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
        String::from_utf8(output.stdout).unwrap()
    };
    let report: serde_json::Value = serde_json::from_str(&run("json")).unwrap();
    let text = run("text");
    let mut lines = text.lines();
    assert_eq!(
        lines.next().unwrap(),
        format!("Config: {}", config.display())
    );
    let expected: Vec<String> = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|check| {
            let tag = match check["status"].as_str().unwrap() {
                "ok" => "ok  ",
                "warn" => "warn",
                "fail" => "FAIL",
                other => panic!("unknown status {other}"),
            };
            let mut line = format!(
                "[{tag}] {}: {}",
                check["name"].as_str().unwrap(),
                check["message"].as_str().unwrap()
            );
            if let Some(var) = check["env_override"].as_str() {
                line.push_str(&format!(" (from {var})"));
            }
            line
        })
        .collect();
    assert!(!expected.is_empty());
    assert_eq!(lines.collect::<Vec<_>>(), expected, "{text}");
}

/// A host tool is found the way the daemon finds it, by name in PATH, not by
/// running it: the version flags differ between tools (`mkfs.ext4 --version`
/// exits 1 on every host that has it), which once reported a present tool as
/// missing in one output mode and present in the other.
#[cfg(any(all(feature = "linux-net", target_os = "linux"), target_os = "macos"))]
#[test]
fn a_host_tool_is_found_in_path_without_being_run() {
    let (dir, config) = valid_config_fixture();
    let tools = dir.path().join("tools");
    fs::create_dir(&tools).unwrap();
    let names: &[&str] = if cfg!(target_os = "macos") {
        &["qemu-img"]
    } else {
        &["qemu-img", "mkfs.ext4"]
    };
    for name in names {
        // Not executable: running it would fail, finding it succeeds.
        fs::write(tools.join(name), b"#!/bin/sh\nexit 1\n").unwrap();
    }
    let empty = dir.path().join("empty");
    fs::create_dir(&empty).unwrap();

    let run = |path: &std::path::Path| {
        let output = Command::cargo_bin("husker")
            .unwrap()
            .env("PATH", path)
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
        serde_json::from_slice::<serde_json::Value>(&output.stdout)
            .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stdout)))
    };
    let found = run(&tools);
    let missing = run(&empty);
    for name in names {
        let check = |report: &serde_json::Value| {
            report["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|check| check["name"] == *name)
                .cloned()
                .unwrap_or_else(|| panic!("{report}"))
        };
        let present = check(&found);
        assert_eq!(present["status"], "ok", "{present}");
        assert_eq!(present["message"], tools.join(name).to_str().unwrap());
        let absent = check(&missing);
        assert_eq!(absent["status"], "warn", "{absent}");
        assert!(
            absent["message"]
                .as_str()
                .unwrap()
                .starts_with("not found; "),
            "{absent}"
        );
    }
}

/// The daemon keeps the file's backend when `HUSKER_VMM` names an unknown
/// one, so the check reports the ignored override rather than crediting it.
/// The config loader also logs the ignored value, and that log line belongs
/// on stderr as plain text: stdout is the JSON document, parsed whole, and
/// stderr is not a terminal here.
#[cfg(all(feature = "linux-net", target_os = "linux"))]
#[test]
fn an_unknown_vmm_override_is_reported_as_ignored() {
    let (_dir, config) = valid_config_fixture();
    let output = Command::cargo_bin("husker")
        .unwrap()
        .env("HUSKER_VMM", "xen")
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
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("stdout is not one JSON document ({error}):\n{stdout}"));
    let vmm = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["name"] == "vmm")
        .unwrap();
    assert_eq!(vmm["status"], "warn", "{vmm}");
    let message = vmm["message"].as_str().unwrap();
    assert!(
        message.starts_with("firecracker; HUSKER_VMM=xen is ignored: "),
        "{message}"
    );
    assert!(vmm.get("env_override").is_none(), "{vmm}");
    assert!(
        stderr.contains("HUSKER_VMM"),
        "the ignored override must be logged on stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains('\u{1b}'),
        "a captured log must carry no escape codes:\n{stderr:?}"
    );
}

/// `husker schema` declares `config check` as a typed object, so a pipe gets
/// that document without an explicit `--output json`.
#[test]
fn config_check_emits_the_json_report_when_stdout_is_not_a_terminal() {
    let (_dir, config) = valid_config_fixture();
    let output = Command::cargo_bin("husker")
        .unwrap()
        .env_remove("HUSKER_DATA_DIR")
        .args(["--config", config.to_str().unwrap(), "config", "check"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("piped config check output must be one JSON document");
    assert_eq!(report["status"], "ok");
}

/// `config check` is read-only: a data directory that does not exist yet is
/// reported, not created, in both output modes.
#[test]
fn config_check_reports_a_missing_data_dir_without_creating_it() {
    let (dir, config) = valid_config_fixture();
    let data_dir = dir.path().join("data");
    assert!(!data_dir.exists());

    let json = Command::cargo_bin("husker")
        .unwrap()
        .env_remove("HUSKER_DATA_DIR")
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
    assert!(json.status.success());
    assert!(
        !data_dir.exists(),
        "config check --output json created {}",
        data_dir.display()
    );
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report["status"], "ok");
    let check = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["name"] == "data_dir")
        .unwrap();
    assert_eq!(check["status"], "warn");
    assert!(
        check["message"]
            .as_str()
            .unwrap()
            .contains("not created yet"),
        "{check}"
    );

    let text = Command::cargo_bin("husker")
        .unwrap()
        .env_remove("HUSKER_DATA_DIR")
        .args([
            "--config",
            config.to_str().unwrap(),
            "--output",
            "text",
            "config",
            "check",
        ])
        .output()
        .unwrap();
    assert!(text.status.success());
    assert!(
        !data_dir.exists(),
        "config check --output text created {}",
        data_dir.display()
    );
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(
        stdout.contains("data_dir") && stdout.contains("not created yet"),
        "{stdout}"
    );
}

/// A data_dir path that exists as a file is the failure the daemon would hit
/// on start, so the check reports it as one.
#[test]
fn config_check_fails_when_the_data_dir_path_is_a_file() {
    let (dir, config) = valid_config_fixture();
    fs::write(dir.path().join("data"), b"not a directory").unwrap();
    let output = Command::cargo_bin("husker")
        .unwrap()
        .env_remove("HUSKER_DATA_DIR")
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
    let check = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["name"] == "data_dir")
        .unwrap();
    assert_eq!(check["status"], "fail");
    assert!(
        check["message"]
            .as_str()
            .unwrap()
            .ends_with("not a directory"),
        "{check}"
    );
}

/// A profile's `vmm` is checked against the same backend table the daemon
/// parses with, so an alias the daemon accepts passes and an unknown name
/// fails naming every backend that would have been accepted.
#[test]
fn config_check_validates_a_profile_vmm_against_the_backend_table() {
    let (_dir, config) = valid_config_fixture();
    let mut contents = fs::read_to_string(&config).unwrap();
    contents.push_str("\n[profiles.alias]\nvmm = \"kvm\"\n\n[profiles.unknown]\nvmm = \"xen\"\n");
    fs::write(&config, contents).unwrap();
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
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "error");
    let checks = report["checks"].as_array().unwrap();
    let find = |name: &str| checks.iter().find(|check| check["name"] == name).unwrap();
    assert_eq!(find("profile.alias")["status"], "ok", "{report}");
    let unknown = find("profile.unknown");
    assert_eq!(unknown["status"], "fail", "{report}");
    let message = unknown["message"].as_str().unwrap();
    assert!(message.contains("unknown vmm 'xen'"), "{message}");
    assert!(message.contains("firecracker, qemu"), "{message}");
}

/// A profile's `rootfs` is judged the way `run --profile` resolves it: an
/// existing path or a pulled image under `<data_dir>/images` is a file, a
/// path-shaped value that does not exist is a failure, and a bare name or an
/// OCI reference is the daemon's to resolve against its image catalog, so it
/// is reported rather than failed as a missing file.
#[test]
fn a_profile_rootfs_is_judged_the_way_run_resolves_it() {
    let (dir, config) = valid_config_fixture();
    let images = dir.path().join("data").join("images");
    fs::create_dir_all(&images).unwrap();
    fs::write(images.join("pulled.ext4"), b"rootfs").unwrap();
    let mut contents = fs::read_to_string(&config).unwrap();
    contents.push_str(
        "\n[profiles.catalog]\nrootfs = \"rust\"\n\n[profiles.oci]\nrootfs = \"python:3.12-alpine\"\n\n[profiles.pulled]\nrootfs = \"pulled.ext4\"\n\n[profiles.typo]\nrootfs = \"/srv/images/missing.ext4\"\n",
    );
    fs::write(&config, contents).unwrap();
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
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "error");
    let checks = report["checks"].as_array().unwrap();
    let find = |name: &str| checks.iter().find(|check| check["name"] == name).unwrap();
    let catalog = find("profile.catalog");
    assert_eq!(catalog["status"], "ok", "{report}");
    assert_eq!(
        catalog["message"],
        "valid; rootfs rust is a catalog image or OCI reference, resolved by the daemon"
    );
    let oci = find("profile.oci");
    assert_eq!(oci["status"], "ok", "{report}");
    assert_eq!(
        oci["message"],
        "valid; rootfs python:3.12-alpine is a catalog image or OCI reference, resolved by the daemon"
    );
    let pulled = find("profile.pulled");
    assert_eq!(pulled["status"], "ok", "{report}");
    assert_eq!(pulled["message"], "valid");
    let typo = find("profile.typo");
    assert_eq!(typo["status"], "fail", "{report}");
    assert_eq!(typo["message"], "rootfs /srv/images/missing.ext4 not found");
}
