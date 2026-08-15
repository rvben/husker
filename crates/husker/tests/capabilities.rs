use assert_cmd::Command;

#[test]
fn capabilities_report_the_embedded_agent_build_fact() {
    let output = Command::cargo_bin("husker")
        .unwrap()
        .args(["--output", "json", "capabilities"])
        .output()
        .expect("husker capabilities should run");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());

    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("capabilities should emit valid JSON");
    assert_eq!(
        document["embedded_agent"].as_bool(),
        Some(husker::agent_embedded()),
        "capabilities must describe the artifact that emitted them"
    );
}

#[test]
fn capabilities_remain_offline_safe() {
    Command::cargo_bin("husker")
        .unwrap()
        .args(["--api-url", "ssh://", "--output", "json", "capabilities"])
        .assert()
        .success();
}
