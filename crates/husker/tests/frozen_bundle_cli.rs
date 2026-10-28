//! Local CLI contract: no daemon, no overwrite, no accidental credential copy.
use assert_cmd::cargo::cargo_bin_cmd;
use std::fs;

fn husker() -> assert_cmd::Command {
    let mut command = cargo_bin_cmd!("husker");
    command
        .env_remove("HUSKER_API_URL")
        .env_remove("HUSKER_CONTEXT");
    command
}

#[test]
fn local_freeze_verify_and_changed_identity() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let output = temp.path().join("source.tar");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("file"), [0, 255]).unwrap();
    fs::write(source.join(".env"), "synthetic credential").unwrap();
    let result = husker()
        .args(["--output", "json", "bundle", "freeze"])
        .arg(&source)
        .arg(&output)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(result["file_count"], 1);
    assert_eq!(result["version"], 1);
    let digest = result["digest"].as_str().unwrap();
    let size = result["size_bytes"].as_u64().unwrap().to_string();
    husker()
        .args(["--output", "json", "bundle", "verify"])
        .arg(&output)
        .args(["--digest", digest, "--size", &size])
        .assert()
        .success();
    let original = fs::read(&output).unwrap();
    husker()
        .args(["bundle", "freeze"])
        .arg(&source)
        .arg(&output)
        .assert()
        .failure();
    assert_eq!(fs::read(&output).unwrap(), original);
    let mut changed = original;
    changed[512] ^= 1;
    fs::write(&output, changed).unwrap();
    husker()
        .args(["bundle", "verify"])
        .arg(&output)
        .args(["--digest", digest, "--size", &size])
        .assert()
        .failure();
}

#[test]
fn refuses_destination_inside_source_and_explicit_remote_context() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("bundle.tar");
    husker()
        .args(["bundle", "freeze"])
        .arg(temp.path())
        .arg(&output)
        .assert()
        .failure();
    assert!(!output.exists());
    husker()
        .args(["--api-url", "ssh://invalid.invalid", "bundle", "freeze"])
        .arg(temp.path())
        .arg(temp.path().join("unused"))
        .assert()
        .failure();
    assert!(!temp.path().join("unused").exists());
}
