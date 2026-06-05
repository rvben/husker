use assert_cmd::Command;

#[test]
fn run_without_rootfs_and_no_default_hints_pull() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cmd = Command::cargo_bin("husker").unwrap();
    cmd.env("HUSKER_DATA_DIR", tmp.path())
        .env("HOME", tmp.path())
        .arg("run");
    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("husker images pull"),
        "stderr did not hint at `husker images pull`:\n{stderr}"
    );
}

// The firecracker pre-check only exists when `linux-net` is compiled in;
// the `--no-default-features` build skips it and reaches the daemon-connection
// path instead.
#[cfg(all(target_os = "linux", feature = "linux-net"))]
#[test]
fn run_with_missing_firecracker_hints_env_var() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cmd = Command::cargo_bin("husker").unwrap();
    cmd.env("PATH", "/nonexistent")
        .env("HOME", tmp.path())
        .env("HUSKER_DATA_DIR", tmp.path())
        .arg("run")
        .arg("--kernel")
        .arg("/tmp/x")
        .arg("/tmp/y");
    let out = cmd.output().unwrap();
    assert!(
        !out.status.success(),
        "expected non-zero exit, got {:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("HUSKER_AUTO_INSTALL_FIRECRACKER"),
        "stderr did not hint at the install env var:\n{stderr}"
    );
}
